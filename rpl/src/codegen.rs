//! AST -> bytecode, combined with type checking in a single pass (there's
//! nothing a separate type-check pass would learn that emission doesn't
//! already need to know, so keeping them together avoids re-deriving field
//! resolution twice). `check.rs` handles the one thing this pass doesn't
//! need: the termination/reachability structure of the statement tree.

use std::net::IpAddr;

use crate::ast::{BinOp, Expr, ExprKind, Policy, Postfix, Stmt, StmtKind, UnaryOp};
use crate::schema::{self, FieldInfo, FieldType};
use crate::symbols::Symbols;
use crate::vm::{CommunityValue, CompiledPolicy, Op, MAX_STACK_DEPTH};
use crate::CompileError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Int,
    Bool,
    Prefix,
    Ip,
    Enum(&'static str),
}

pub fn compile(policy: &Policy, symbols: &Symbols) -> Result<CompiledPolicy, CompileError> {
    let mut cg = Codegen {
        code: Vec::new(),
        depth: 0,
        max_depth: 0,
        symbols,
    };
    cg.compile_stmts(policy)?;
    if cg.max_depth > MAX_STACK_DEPTH {
        return Err(CompileError::new(
            policy.first().map_or(1, |s| s.line),
            "policy expression is too deeply nested to compile",
        ));
    }
    Ok(CompiledPolicy {
        code: cg.code,
        max_stack_depth: cg.max_depth,
    })
}

struct Codegen<'a> {
    code: Vec<Op>,
    depth: usize,
    max_depth: usize,
    symbols: &'a Symbols<'a>,
}

impl Codegen<'_> {
    fn emit(&mut self, op: Op, delta: isize) -> usize {
        let idx = self.code.len();
        self.code.push(op);
        self.depth = self.depth.saturating_add_signed(delta);
        self.max_depth = self.max_depth.max(self.depth);
        idx
    }

    fn patch_jump(&mut self, idx: usize) {
        let target = self.code.len();
        match &mut self.code[idx] {
            Op::JumpIfFalse(t) | Op::Jump(t) => *t = target,
            other => unreachable!("patch_jump called on {other:?}"),
        }
    }

    fn compile_stmts(&mut self, stmts: &[Stmt]) -> Result<(), CompileError> {
        for stmt in stmts {
            self.compile_stmt(stmt)?;
        }
        Ok(())
    }

    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompileError> {
        match &stmt.kind {
            StmtKind::Accept => {
                self.emit(Op::Accept, 0);
            }
            StmtKind::Reject => {
                self.emit(Op::Reject, 0);
            }
            StmtKind::Set(target, value) => {
                let info = resolve_settable_field(target)?;
                let value_ty = self.compile_expr(value)?;
                expect_ty(value_ty, Ty::Int, value.line)?;
                self.emit(Op::SetField(info.id), -1);
            }
            StmtKind::CommunityAdd(target, value) => {
                let info = resolve_settable_field(target)?;
                for val in self.community_values_for(info.ty, value)? {
                    self.emit(Op::CommunityAdd(info.id, val), 0);
                }
            }
            StmtKind::CommunityRemove(target, value) => {
                let info = resolve_settable_field(target)?;
                for val in self.community_values_for(info.ty, value)? {
                    self.emit(Op::CommunityRemove(info.id, val), 0);
                }
            }
            StmtKind::CommunityClear(target) => {
                let info = resolve_settable_field(target)?;
                if !is_community_list(info.ty) {
                    return Err(CompileError::new(
                        target.line,
                        "'.clear()' is only valid on a community-list field",
                    ));
                }
                self.emit(Op::CommunityClear(info.id), 0);
            }
            StmtKind::If {
                branches,
                else_body,
            } => self.compile_if(branches, else_body.as_ref())?,
        }
        Ok(())
    }

    fn compile_if(
        &mut self,
        branches: &[(Expr, Vec<Stmt>)],
        else_body: Option<&Vec<Stmt>>,
    ) -> Result<(), CompileError> {
        let mut end_jumps = Vec::new();
        let mut prev_jf: Option<usize> = None;

        for (cond, body) in branches {
            if let Some(jf) = prev_jf.take() {
                self.patch_jump(jf);
            }
            let cond_ty = self.compile_expr(cond)?;
            expect_ty(cond_ty, Ty::Bool, cond.line)?;
            let jf = self.emit(Op::JumpIfFalse(0), -1);
            self.compile_stmts(body)?;
            if !body_halts(body) {
                end_jumps.push(self.emit(Op::Jump(0), 0));
            }
            prev_jf = Some(jf);
        }

        match else_body {
            Some(else_body) => {
                if let Some(jf) = prev_jf.take() {
                    self.patch_jump(jf);
                }
                self.compile_stmts(else_body)?;
            }
            None => {
                if let Some(jf) = prev_jf.take() {
                    self.patch_jump(jf);
                }
            }
        }

        for j in end_jumps {
            self.patch_jump(j);
        }
        Ok(())
    }

    fn compile_expr(&mut self, expr: &Expr) -> Result<Ty, CompileError> {
        match &expr.kind {
            ExprKind::IntLit(n) => {
                self.emit(Op::LoadConstInt(*n), 1);
                Ok(Ty::Int)
            }
            ExprKind::PrefixLit(p) => {
                self.emit(Op::LoadConstPrefix(*p), 1);
                Ok(Ty::Prefix)
            }
            ExprKind::IpLit(a) => {
                self.emit(Op::LoadConstIp(*a), 1);
                Ok(Ty::Ip)
            }
            ExprKind::EnumLit(name, variant) => {
                let (enum_name, discriminant) = resolve_enum_literal(name, variant, expr.line)?;
                self.emit(Op::LoadConstEnum(discriminant), 1);
                Ok(Ty::Enum(enum_name))
            }
            ExprKind::ColonLit(_) => Err(CompileError::new(
                expr.line,
                "a colon-separated literal is only valid as an argument to '.contains(..)', '.add(..)', or '.remove(..)'",
            )),
            ExprKind::Ident(name) => Err(CompileError::new(
                expr.line,
                format!(
                    "'{name}' is only valid as an argument to '.contains(..)', '.add(..)', '.remove(..)', or as the right-hand side of 'in'"
                ),
            )),
            ExprKind::This(segments) => self.compile_field_access(segments, expr.line),
            ExprKind::Unary(UnaryOp::Not, inner) => {
                let ty = self.compile_expr(inner)?;
                expect_ty(ty, Ty::Bool, inner.line)?;
                self.emit(Op::Not, 0);
                Ok(Ty::Bool)
            }
            ExprKind::Binary(op, lhs, rhs) => self.compile_binary(*op, lhs, rhs, expr.line),
        }
    }

    fn compile_binary(
        &mut self,
        op: BinOp,
        lhs: &Expr,
        rhs: &Expr,
        line: usize,
    ) -> Result<Ty, CompileError> {
        match op {
            BinOp::And | BinOp::Or => {
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Bool, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Bool, rhs.line)?;
                self.emit(if op == BinOp::And { Op::And } else { Op::Or }, -1);
                Ok(Ty::Bool)
            }
            BinOp::Add | BinOp::Sub => {
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Int, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Int, rhs.line)?;
                self.emit(if op == BinOp::Add { Op::Add } else { Op::Sub }, -1);
                Ok(Ty::Int)
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Int, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Int, rhs.line)?;
                let cmp_op = match op {
                    BinOp::Lt => Op::CmpLt,
                    BinOp::Le => Op::CmpLe,
                    BinOp::Gt => Op::CmpGt,
                    BinOp::Ge => Op::CmpGe,
                    _ => unreachable!(),
                };
                self.emit(cmp_op, -1);
                Ok(Ty::Bool)
            }
            BinOp::Eq | BinOp::Ne => {
                let lt = self.compile_expr(lhs)?;
                let rt = self.compile_expr(rhs)?;
                if lt != rt {
                    return Err(CompileError::new(
                        line,
                        format!("cannot compare {lt:?} with {rt:?}"),
                    ));
                }
                self.emit(
                    if op == BinOp::Eq {
                        Op::CmpEq
                    } else {
                        Op::CmpNe
                    },
                    -1,
                );
                Ok(Ty::Bool)
            }
            BinOp::In => {
                if let ExprKind::Ident(name) = &rhs.kind {
                    let Some((_, entries)) = self
                        .symbols
                        .prefix_lists
                        .iter()
                        .find(|(n, _)| *n == name.as_str())
                    else {
                        return Err(CompileError::new(
                            rhs.line,
                            format!("undefined prefix-list '{name}'"),
                        ));
                    };
                    let entries = entries.to_vec();
                    let lt = self.compile_expr(lhs)?;
                    expect_ty(lt, Ty::Prefix, lhs.line)?;
                    self.emit(Op::PrefixInList(entries), 0);
                    return Ok(Ty::Bool);
                }
                let lt = self.compile_expr(lhs)?;
                expect_ty(lt, Ty::Prefix, lhs.line)?;
                let rt = self.compile_expr(rhs)?;
                expect_ty(rt, Ty::Prefix, rhs.line)?;
                self.emit(Op::PrefixIn, -1);
                Ok(Ty::Bool)
            }
        }
    }

    fn compile_field_access(
        &mut self,
        segments: &[Postfix],
        line: usize,
    ) -> Result<Ty, CompileError> {
        if segments.is_empty() {
            return Err(CompileError::new(line, "'this' cannot be used by itself"));
        }
        let mut names = Vec::new();
        for seg in segments {
            match seg {
                Postfix::Field(n) => names.push(n.clone()),
                Postfix::Call(..) => break,
            }
        }
        let Some((info, consumed)) = schema::resolve_field(&names) else {
            return Err(CompileError::new(
                line,
                format!("unknown field 'this.{}'", names.join(".")),
            ));
        };
        let leftover = &segments[consumed..];
        if leftover.is_empty() {
            return self.compile_plain_field(info, line);
        }
        if leftover.len() > 1 {
            return Err(CompileError::new(
                line,
                "unsupported field access: at most one property or method may follow a field",
            ));
        }
        match &leftover[0] {
            Postfix::Field(name) if name == "length" => self.compile_field_len(info, line),
            Postfix::Field(other) => Err(CompileError::new(
                line,
                format!("unknown property '.{other}'"),
            )),
            Postfix::Call(name, args) if name == "contains" => {
                self.compile_contains(info, args, line)
            }
            Postfix::Call(other, _) => Err(CompileError::new(
                line,
                format!("unknown method '.{other}(..)'"),
            )),
        }
    }

    fn compile_plain_field(
        &mut self,
        info: &'static FieldInfo,
        line: usize,
    ) -> Result<Ty, CompileError> {
        match info.ty {
            FieldType::Int => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Int)
            }
            FieldType::Bool => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Bool)
            }
            FieldType::Prefix => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Prefix)
            }
            FieldType::Enum(name) => {
                self.emit(Op::LoadField(info.id), 1);
                Ok(Ty::Enum(name))
            }
            FieldType::OptionalInt | FieldType::OptionalIp => Err(CompileError::new(
                line,
                "this field may be unset and can't be read directly yet (only 'set' is supported)",
            )),
            FieldType::ListInt
            | FieldType::ListIp
            | FieldType::ListCommunity
            | FieldType::ListExtCommunity
            | FieldType::ListLargeCommunity => Err(CompileError::new(
                line,
                "this field is a list — use '.length' or '.contains(...)'",
            )),
        }
    }

    fn compile_field_len(
        &mut self,
        info: &'static FieldInfo,
        line: usize,
    ) -> Result<Ty, CompileError> {
        match info.ty {
            FieldType::Prefix
            | FieldType::ListInt
            | FieldType::ListIp
            | FieldType::ListCommunity
            | FieldType::ListExtCommunity
            | FieldType::ListLargeCommunity => {
                self.emit(Op::FieldLen(info.id), 1);
                Ok(Ty::Int)
            }
            _ => Err(CompileError::new(
                line,
                "'.length' is only valid on a prefix or list field",
            )),
        }
    }

    fn compile_contains(
        &mut self,
        info: &'static FieldInfo,
        args: &[Expr],
        line: usize,
    ) -> Result<Ty, CompileError> {
        if args.len() != 1 {
            return Err(CompileError::new(
                line,
                "'.contains(..)' takes exactly one argument",
            ));
        }
        match info.ty {
            FieldType::ListInt => {
                let ExprKind::IntLit(n) = args[0].kind else {
                    return Err(CompileError::new(
                        args[0].line,
                        "'.contains(..)' on this field requires an integer literal",
                    ));
                };
                let n = u32::try_from(n).map_err(|_| {
                    CompileError::new(args[0].line, "AS number literal out of range")
                })?;
                self.emit(Op::ListContainsInt(info.id, n), 1);
                Ok(Ty::Bool)
            }
            FieldType::ListIp => {
                let ExprKind::IpLit(IpAddr::V4(addr)) = args[0].kind else {
                    return Err(CompileError::new(
                        args[0].line,
                        "'.contains(..)' on this field requires an IPv4 address literal",
                    ));
                };
                self.emit(Op::ListContainsIp(info.id, addr), 1);
                Ok(Ty::Bool)
            }
            FieldType::ListCommunity
            | FieldType::ListExtCommunity
            | FieldType::ListLargeCommunity => {
                let vals = self.community_values_for(info.ty, &args[0])?;
                let Some((first, rest)) = vals.split_first() else {
                    return Err(CompileError::new(
                        args[0].line,
                        "community group has no members",
                    ));
                };
                self.emit(Op::ListContainsCommunity(info.id, *first), 1);
                for val in rest {
                    self.emit(Op::ListContainsCommunity(info.id, *val), 1);
                    self.emit(Op::Or, -1);
                }
                Ok(Ty::Bool)
            }
            _ => Err(CompileError::new(
                line,
                "'.contains(..)' is only valid on a list field",
            )),
        }
    }

    /// Resolves a `.contains(..)`/`.add(..)`/`.remove(..)` argument against
    /// the target field's community kind, expanding a `community-alias`/
    /// `community-group` reference into its member value(s) — one value for
    /// a plain literal or an alias, one per member for a group (flat, no
    /// nesting). The caller reduces multiple values with `Op::Or` for
    /// `.contains`, or emits one `CommunityAdd`/`CommunityRemove` per value.
    fn community_values_for(
        &self,
        ty: FieldType,
        expr: &Expr,
    ) -> Result<Vec<CommunityValue>, CompileError> {
        let ExprKind::Ident(name) = &expr.kind else {
            return Ok(vec![community_value_for(ty, expr)?]);
        };
        if let Some((_, parts)) = self
            .symbols
            .aliases
            .iter()
            .find(|(n, _)| *n == name.as_str())
        {
            return Ok(vec![community_value_from_parts(ty, parts, expr.line)?]);
        }
        if let Some((_, members)) = self
            .symbols
            .groups
            .iter()
            .find(|(n, _)| *n == name.as_str())
        {
            return members
                .iter()
                .map(|parts| community_value_from_parts(ty, parts, expr.line))
                .collect();
        }
        Err(CompileError::new(
            expr.line,
            format!("undefined community alias or group '{name}'"),
        ))
    }
}

fn is_community_list(ty: FieldType) -> bool {
    matches!(
        ty,
        FieldType::ListCommunity | FieldType::ListExtCommunity | FieldType::ListLargeCommunity
    )
}

/// Validates and packs a `.contains(..)`/`.add(..)`/`.remove(..)` argument
/// against the target field's community kind. Shared by all three call
/// sites so arity/range checking lives in one place.
fn community_value_for(ty: FieldType, expr: &Expr) -> Result<CommunityValue, CompileError> {
    let ExprKind::ColonLit(parts) = &expr.kind else {
        return Err(CompileError::new(
            expr.line,
            "this argument requires a colon-separated community literal, e.g. 65000:100",
        ));
    };
    community_value_from_parts(ty, parts, expr.line)
}

/// The packing logic `community_value_for` applies to an inline `ColonLit`'s
/// parts, factored out so a resolved `community-alias`/`community-group`
/// member's already-flattened parts (see `Codegen::community_values_for`)
/// reuse the exact same arity/range checking.
fn community_value_from_parts(
    ty: FieldType,
    parts: &[i64],
    line: usize,
) -> Result<CommunityValue, CompileError> {
    let range_err = || CompileError::new(line, "community literal part out of range");
    match ty {
        FieldType::ListCommunity => {
            let [aa, nn] = parts else {
                return Err(CompileError::new(
                    line,
                    "a standard community literal takes exactly two parts, e.g. 65000:100",
                ));
            };
            let aa = u16::try_from(*aa).map_err(|_| range_err())?;
            let nn = u16::try_from(*nn).map_err(|_| range_err())?;
            Ok(CommunityValue::Standard(
                (u32::from(aa) << 16) | u32::from(nn),
            ))
        }
        FieldType::ListExtCommunity => {
            let [ty_octet, subtype, value] = parts else {
                return Err(CompileError::new(
                    line,
                    "an extended community literal takes exactly three parts, e.g. 0:2:100",
                ));
            };
            let ty_octet = u8::try_from(*ty_octet).map_err(|_| range_err())?;
            let subtype = u8::try_from(*subtype).map_err(|_| range_err())?;
            let value = u64::try_from(*value)
                .ok()
                .filter(|v| *v < (1u64 << 48))
                .ok_or_else(range_err)?;
            let packed = (u64::from(ty_octet) << 56) | (u64::from(subtype) << 48) | value;
            Ok(CommunityValue::Extended(packed))
        }
        FieldType::ListLargeCommunity => {
            let [ga, l1, l2] = parts else {
                return Err(CompileError::new(
                    line,
                    "a large community literal takes exactly three parts, e.g. 65000:1:1",
                ));
            };
            let ga = u32::try_from(*ga).map_err(|_| range_err())?;
            let l1 = u32::try_from(*l1).map_err(|_| range_err())?;
            let l2 = u32::try_from(*l2).map_err(|_| range_err())?;
            Ok(CommunityValue::Large(ga, l1, l2))
        }
        _ => Err(CompileError::new(
            line,
            "'.add'/'.remove' is only valid on a community-list field",
        )),
    }
}

fn expect_ty(got: Ty, want: Ty, line: usize) -> Result<(), CompileError> {
    if got == want {
        Ok(())
    } else {
        Err(CompileError::new(
            line,
            format!("expected {want:?}, found {got:?}"),
        ))
    }
}

fn body_halts(body: &[Stmt]) -> bool {
    matches!(
        body.last().map(|s| &s.kind),
        Some(StmtKind::Accept | StmtKind::Reject)
    )
}

fn resolve_settable_field(expr: &Expr) -> Result<&'static FieldInfo, CompileError> {
    let ExprKind::This(segments) = &expr.kind else {
        return Err(CompileError::new(
            expr.line,
            "assignment target must be a 'this' field",
        ));
    };
    let mut names = Vec::with_capacity(segments.len());
    for seg in segments {
        match seg {
            Postfix::Field(n) => names.push(n.clone()),
            Postfix::Call(..) => {
                return Err(CompileError::new(
                    expr.line,
                    "assignment target cannot include a method call",
                ))
            }
        }
    }
    let Some((info, consumed)) = schema::resolve_field(&names) else {
        return Err(CompileError::new(
            expr.line,
            format!("unknown field 'this.{}'", names.join(".")),
        ));
    };
    if consumed != names.len() {
        return Err(CompileError::new(
            expr.line,
            "assignment target must name a field exactly, with no suffix",
        ));
    }
    if !info.mutable {
        return Err(CompileError::new(
            expr.line,
            format!("field 'this.{}' is not settable", names.join(".")),
        ));
    }
    Ok(info)
}

fn resolve_enum_literal(
    name: &str,
    variant: &str,
    line: usize,
) -> Result<(&'static str, u8), CompileError> {
    match (name, variant) {
        ("origin", "igp") => Ok(("origin", 0)),
        ("origin", "egp") => Ok(("origin", 1)),
        ("origin", "incomplete") => Ok(("origin", 2)),
        _ => Err(CompileError::new(
            line,
            format!("unknown enum literal '{name}.{variant}'"),
        )),
    }
}

#[cfg(test)]
// Community/ASN values are conventionally written and read in decimal
// (`65000:100`, matching this language's own literal syntax) — hex/binary
// notation would make these test fixtures harder to read, not easier.
#[allow(clippy::decimal_bitwise_operands, clippy::identity_op)]
mod tests {
    use super::*;
    use crate::lexer::lex;
    use crate::parser::parse;
    use crate::schema::FieldId;
    use crate::symbols::PrefixListEntry;
    use crate::vm::{self, BgpInput, Input, Origin, Verdict};
    use std::net::Ipv4Addr;

    fn compile_src(src: &str) -> CompiledPolicy {
        compile_src_with(src, &Symbols::EMPTY)
    }

    fn compile_err(src: &str) -> CompileError {
        compile_err_with(src, &Symbols::EMPTY)
    }

    fn compile_src_with(src: &str, symbols: &Symbols) -> CompiledPolicy {
        let tokens = lex(src).unwrap();
        let policy = parse(&tokens).unwrap();
        crate::check::check_termination(&policy).unwrap();
        compile(&policy, symbols).unwrap()
    }

    fn compile_err_with(src: &str, symbols: &Symbols) -> CompileError {
        let tokens = lex(src).unwrap();
        let policy = parse(&tokens).unwrap();
        crate::check::check_termination(&policy).unwrap();
        compile(&policy, symbols).unwrap_err()
    }

    fn default_input(prefix: &str) -> (ipnet::IpNet, Vec<u32>, Vec<Ipv4Addr>) {
        (prefix.parse().unwrap(), Vec::new(), Vec::new())
    }

    fn make_input<'a>(
        prefix: ipnet::IpNet,
        as_path: &'a [u32],
        local_pref: u32,
        med: Option<u32>,
        cluster_list: &'a [Ipv4Addr],
    ) -> Input<'a> {
        Input {
            prefix,
            bgp: BgpInput {
                origin: Origin::Igp,
                as_path,
                local_pref,
                med,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
            },
        }
    }

    fn make_community_input<'a>(
        prefix: ipnet::IpNet,
        communities: &'a [u32],
        extended_communities: &'a [u64],
        large_communities: &'a [(u32, u32, u32)],
    ) -> Input<'a> {
        Input {
            prefix,
            bgp: BgpInput {
                origin: Origin::Igp,
                as_path: &[],
                local_pref: 100,
                med: None,
                next_hop: None,
                learned_via_ibgp: false,
                router_id: None,
                originator_id: None,
                cluster_list: &[],
                communities,
                extended_communities,
                large_communities,
            },
        }
    }

    #[test]
    fn worked_example_matches_plan() {
        let policy = compile_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        assert_eq!(
            policy.code,
            vec![
                Op::LoadField(FieldId::BgpLocalPref),
                Op::LoadConstInt(100),
                Op::CmpLt,
                Op::JumpIfFalse(5),
                Op::Reject,
                Op::Accept,
            ]
        );
    }

    #[test]
    fn reject_branch_runs_for_low_local_pref() {
        let policy = compile_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 50, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);
    }

    #[test]
    fn accept_branch_runs_for_high_local_pref() {
        let policy = compile_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 200, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 200,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn set_mutates_local_pref_before_accept() {
        let policy = compile_src(
            "if this.prefix in 203.0.113.0/16:\n    set this.bgp.local_pref = 150\n    accept\nelse:\n    reject\n",
        );
        let (prefix, as_path, cluster) = default_input("203.0.113.0/24");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 150,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn set_med_wraps_in_some() {
        let policy = compile_src(
            "if this.bgp.as_path.contains(65010):\n    set this.bgp.med = 50\n    accept\nelse:\n    accept\n",
        );
        let (prefix, _, cluster) = default_input("198.51.100.0/24");
        let as_path = vec![65010, 65020];
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: Some(50),
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn as_path_length_and_reject() {
        let policy =
            compile_src("if this.bgp.as_path.length > 2:\n    reject\nelse:\n    accept\n");
        let (prefix, _, cluster) = default_input("10.0.0.0/8");
        let long_path = vec![1, 2, 3, 4];
        let input = make_input(prefix, &long_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);
    }

    #[test]
    fn prefix_length_range() {
        let policy = compile_src(
            "if this.prefix in 203.0.113.0/16 and this.prefix.length <= 24:\n    accept\nelse:\n    reject\n",
        );
        let (prefix, as_path, cluster) = default_input("203.0.113.0/20");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn origin_enum_comparison() {
        let policy =
            compile_src("if this.bgp.origin == origin.igp:\n    accept\nelse:\n    reject\n");
        let (prefix, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn cluster_list_contains() {
        let policy = compile_src(
            "if this.bgp.cluster_list.contains(1.2.3.4):\n    reject\nelse:\n    accept\n",
        );
        let (prefix, as_path, _) = default_input("10.0.0.0/8");
        let cluster = vec![Ipv4Addr::new(1, 2, 3, 4)];
        let input = make_input(prefix, &as_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);
    }

    #[test]
    fn standard_community_contains_true_and_false() {
        let policy = compile_src(
            "if this.bgp.communities.contains(65000:100):\n    reject\nelse:\n    accept\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let present = make_community_input(prefix, &[(65000 << 16) | 100], &[], &[]);
        assert_eq!(vm::run(&policy, &present), Verdict::Reject);
        let absent = make_community_input(prefix, &[(65000 << 16) | 200], &[], &[]);
        assert_eq!(
            vm::run(&policy, &absent),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 200],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn community_add_then_contains_sees_own_write() {
        let policy = compile_src(
            "this.bgp.communities.add(65000:100)\nif this.bgp.communities.contains(65000:100):\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 100],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn community_remove_drops_matching_value() {
        let policy = compile_src("this.bgp.communities.remove(65000:100)\naccept\n");
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(
            prefix,
            &[(65000 << 16) | 100, (65000 << 16) | 200],
            &[],
            &[],
        );
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 200],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn community_clear_empties_length() {
        let policy = compile_src(
            "this.bgp.communities.clear()\nif this.bgp.communities.length == 0:\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[(65000 << 16) | 100], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn extended_community_contains() {
        let policy = compile_src(
            "if this.bgp.extended_communities.contains(0:2:100):\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let packed = (0u64 << 56) | (2u64 << 48) | 100u64;
        let extended = [packed];
        let input = make_community_input(prefix, &[], &extended, &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: vec![packed],
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn large_community_add_then_length() {
        let policy = compile_src(
            "this.bgp.large_communities.add(65000:1:1)\nif this.bgp.large_communities.length == 1:\n    accept\nelse:\n    reject\n",
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: vec![(65000, 1, 1)],
            }
        );
    }

    #[test]
    fn community_literal_wrong_arity_is_a_compile_error() {
        let err = compile_err(
            "if this.bgp.communities.contains(65000:100:1):\n    accept\nelse:\n    reject\n",
        );
        assert!(err.to_string().contains("exactly two parts"));
    }

    #[test]
    fn community_literal_out_of_range_is_a_compile_error() {
        let err = compile_err(
            "if this.bgp.communities.contains(999999:100):\n    accept\nelse:\n    reject\n",
        );
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn adding_to_immutable_list_field_is_a_compile_error() {
        let err = compile_err("this.bgp.as_path.add(65000:100)\naccept\n");
        assert!(err.to_string().contains("not settable"));
    }

    #[test]
    fn reading_optional_field_is_a_compile_error() {
        let err = compile_err("if this.bgp.med == 50:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("unset"));
    }

    #[test]
    fn reading_list_field_directly_is_a_compile_error() {
        let err = compile_err("if this.bgp.as_path == 5:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("list"));
    }

    #[test]
    fn setting_immutable_field_is_a_compile_error() {
        let err = compile_err("set this.bgp.origin = 1\naccept\n");
        assert!(err.to_string().contains("not settable"));
    }

    #[test]
    fn type_mismatch_in_comparison_is_a_compile_error() {
        let err =
            compile_err("if this.bgp.local_pref < this.prefix:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("expected Int"));
    }

    #[test]
    fn unknown_field_is_a_compile_error() {
        let err = compile_err("if this.bgp.nonexistent == 1:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn community_alias_resolves_in_contains() {
        let cust_a: &[i64] = &[65000, 100];
        let aliases: &[(&str, &[i64])] = &[("CUSTOMER_A", cust_a)];
        let symbols = Symbols {
            aliases,
            groups: &[],
            prefix_lists: &[],
        };
        let policy = compile_src_with(
            "if this.bgp.communities.contains(CUSTOMER_A):\n    reject\nelse:\n    accept\n",
            &symbols,
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let present = make_community_input(prefix, &[(65000 << 16) | 100], &[], &[]);
        assert_eq!(vm::run(&policy, &present), Verdict::Reject);
    }

    #[test]
    fn community_group_contains_matches_any_member() {
        let a: &[i64] = &[65000, 100];
        let b: &[i64] = &[65000, 200];
        let members: &[&[i64]] = &[a, b];
        let groups: &[(&str, &[&[i64]])] = &[("CUSTOMERS", members)];
        let symbols = Symbols {
            aliases: &[],
            groups,
            prefix_lists: &[],
        };
        let policy = compile_src_with(
            "if this.bgp.communities.contains(CUSTOMERS):\n    reject\nelse:\n    accept\n",
            &symbols,
        );
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let matches_second = make_community_input(prefix, &[(65000 << 16) | 200], &[], &[]);
        assert_eq!(vm::run(&policy, &matches_second), Verdict::Reject);
        let matches_neither = make_community_input(prefix, &[(65000 << 16) | 999], &[], &[]);
        assert_eq!(
            vm::run(&policy, &matches_neither),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 999],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn community_group_add_adds_every_member() {
        let a: &[i64] = &[65000, 100];
        let b: &[i64] = &[65000, 200];
        let members: &[&[i64]] = &[a, b];
        let groups: &[(&str, &[&[i64]])] = &[("CUSTOMERS", members)];
        let symbols = Symbols {
            aliases: &[],
            groups,
            prefix_lists: &[],
        };
        let policy = compile_src_with("this.bgp.communities.add(CUSTOMERS)\naccept\n", &symbols);
        let prefix: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        let input = make_community_input(prefix, &[], &[], &[]);
        assert_eq!(
            vm::run(&policy, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: vec![(65000 << 16) | 100, (65000 << 16) | 200],
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn undefined_community_alias_is_a_compile_error() {
        let err = compile_err(
            "if this.bgp.communities.contains(NOT_DEFINED):\n    accept\nelse:\n    reject\n",
        );
        assert!(err
            .to_string()
            .contains("undefined community alias or group"));
    }

    #[test]
    fn prefix_list_exact_match() {
        let entries: &[PrefixListEntry] = &[PrefixListEntry {
            cidr: "10.0.0.0/8".parse().unwrap(),
            range: None,
        }];
        let lists: &[(&str, &[PrefixListEntry])] = &[("BLOCKS", entries)];
        let symbols = Symbols {
            aliases: &[],
            groups: &[],
            prefix_lists: lists,
        };
        let policy = compile_src_with(
            "if this.prefix in BLOCKS:\n    reject\nelse:\n    accept\n",
            &symbols,
        );

        let (exact, as_path, cluster) = default_input("10.0.0.0/8");
        let input = make_input(exact, &as_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);

        let (more_specific, as_path2, cluster2) = default_input("10.0.0.0/24");
        let input2 = make_input(more_specific, &as_path2, 100, None, &cluster2);
        assert_eq!(
            vm::run(&policy, &input2),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn prefix_list_range_match() {
        let entries: &[PrefixListEntry] = &[PrefixListEntry {
            cidr: "10.0.0.0/8".parse().unwrap(),
            range: Some((24, 32)),
        }];
        let lists: &[(&str, &[PrefixListEntry])] = &[("BLOCKS", entries)];
        let symbols = Symbols {
            aliases: &[],
            groups: &[],
            prefix_lists: lists,
        };
        let policy = compile_src_with(
            "if this.prefix in BLOCKS:\n    reject\nelse:\n    accept\n",
            &symbols,
        );

        let (in_range, as_path, cluster) = default_input("10.0.0.0/24");
        let input = make_input(in_range, &as_path, 100, None, &cluster);
        assert_eq!(vm::run(&policy, &input), Verdict::Reject);

        let (too_short, as_path2, cluster2) = default_input("10.0.0.0/16");
        let input2 = make_input(too_short, &as_path2, 100, None, &cluster2);
        assert_eq!(
            vm::run(&policy, &input2),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
            }
        );
    }

    #[test]
    fn undefined_prefix_list_is_a_compile_error() {
        let err = compile_err("if this.prefix in BLOCKS:\n    accept\nelse:\n    reject\n");
        assert!(err.to_string().contains("undefined prefix-list"));
    }
}
