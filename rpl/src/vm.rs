use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::schema::FieldId;

/// Mirrors `nos_bgp::message::Origin`'s discriminants exactly (`Igp = 0`,
/// `Egp = 1`, `Incomplete = 2`) so `Value::Enum(u8)` round-trips without a
/// translation table. `nos-rpl` doesn't depend on `nos-bgp`, so this is its
/// own copy, not a shared type — see `Input`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    Int(i64),
    Bool(bool),
    Prefix(IpNet),
    Ip(IpAddr),
    Enum(u8),
}

/// One instruction. List-typed fields (`as_path`, `cluster_list`) are never
/// pushed onto the stack as a whole — `FieldLen`/`ListContains*` read
/// straight from the borrowed slice in `Input` and push only the scalar
/// result, so `Value` never needs a list variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    LoadField(FieldId),
    LoadConstInt(i64),
    LoadConstPrefix(IpNet),
    LoadConstIp(IpAddr),
    LoadConstEnum(u8),
    FieldLen(FieldId),
    ListContainsInt(FieldId, u32),
    ListContainsIp(FieldId, Ipv4Addr),
    Add,
    Sub,
    CmpEq,
    CmpNe,
    CmpLt,
    CmpLe,
    CmpGt,
    CmpGe,
    PrefixIn,
    And,
    Or,
    Not,
    JumpIfFalse(usize),
    Jump(usize),
    SetField(FieldId),
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub code: Vec<Op>,
    pub max_stack_depth: usize,
}

/// The route data a policy script can see, adapted from whatever the caller's
/// own route type is — `nos-rpl` has zero knowledge of `RibRoute` or any
/// other NOS-internal type, so a consumer (e.g. `nos-bgp`) writes a plain
/// conversion function into this shape rather than `nos-rpl` depending on it.
pub struct Input<'a> {
    pub prefix: IpNet,
    pub bgp: BgpInput<'a>,
}

pub struct BgpInput<'a> {
    pub origin: Origin,
    pub as_path: &'a [u32],
    pub local_pref: u32,
    pub med: Option<u32>,
    pub next_hop: Option<IpAddr>,
    pub learned_via_ibgp: bool,
    pub router_id: Option<Ipv4Addr>,
    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: &'a [Ipv4Addr],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept { local_pref: u32, med: Option<u32> },
    Reject,
}

/// Upper bound on a policy's compile-time-computed `max_stack_depth` —
/// `codegen::compile` refuses to produce a `CompiledPolicy` that would
/// exceed it. Policies have no calls and no loops, so real scripts sit at a
/// handful of stack slots; this is already generous headroom, chosen so
/// `run`'s stack can be a fixed-size array (zero heap allocation on the hot
/// path — this runs once per route, per peer, per update) rather than a
/// `Vec`.
pub const MAX_STACK_DEPTH: usize = 32;

/// Executes `policy` against `input`. `local_pref`/`med` start at `input`'s
/// own values and are only ever changed by a `SetField` the script actually
/// executes — reading `this.bgp.local_pref` after a `set` sees the updated
/// value, exactly like a normal imperative variable.
pub fn run(policy: &CompiledPolicy, input: &Input) -> Verdict {
    let mut stack = [Value::Int(0); MAX_STACK_DEPTH];
    let mut sp = 0usize;
    let mut cur_local_pref = input.bgp.local_pref;
    let mut cur_med = input.bgp.med;
    let mut pc = 0usize;

    macro_rules! push {
        ($v:expr) => {{
            stack[sp] = $v;
            sp += 1;
        }};
    }
    macro_rules! pop {
        () => {{
            sp -= 1;
            stack[sp]
        }};
    }

    loop {
        match &policy.code[pc] {
            Op::LoadField(id) => {
                let v = match id {
                    FieldId::Prefix => Value::Prefix(input.prefix),
                    FieldId::BgpOrigin => Value::Enum(input.bgp.origin as u8),
                    FieldId::BgpLocalPref => Value::Int(i64::from(cur_local_pref)),
                    FieldId::BgpLearnedViaIbgp => Value::Bool(input.bgp.learned_via_ibgp),
                    _ => unreachable!("check.rs rejects LoadField for {id:?}"),
                };
                push!(v);
            }
            Op::LoadConstInt(n) => push!(Value::Int(*n)),
            Op::LoadConstPrefix(p) => push!(Value::Prefix(*p)),
            Op::LoadConstIp(a) => push!(Value::Ip(*a)),
            Op::LoadConstEnum(e) => push!(Value::Enum(*e)),
            Op::FieldLen(id) => {
                let n = match id {
                    FieldId::Prefix => i64::from(input.prefix.prefix_len()),
                    FieldId::BgpAsPath => len_as_int(input.bgp.as_path.len()),
                    FieldId::BgpClusterList => len_as_int(input.bgp.cluster_list.len()),
                    _ => unreachable!("check.rs rejects FieldLen for {id:?}"),
                };
                push!(Value::Int(n));
            }
            Op::ListContainsInt(id, n) => {
                let found = match id {
                    FieldId::BgpAsPath => input.bgp.as_path.contains(n),
                    _ => unreachable!("check.rs rejects ListContainsInt for {id:?}"),
                };
                push!(Value::Bool(found));
            }
            Op::ListContainsIp(id, addr) => {
                let found = match id {
                    FieldId::BgpClusterList => input.bgp.cluster_list.contains(addr),
                    _ => unreachable!("check.rs rejects ListContainsIp for {id:?}"),
                };
                push!(Value::Bool(found));
            }
            Op::Add => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Int(a + b));
            }
            Op::Sub => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Int(a - b));
            }
            Op::CmpEq => {
                let b = pop!();
                let a = pop!();
                push!(Value::Bool(a == b));
            }
            Op::CmpNe => {
                let b = pop!();
                let a = pop!();
                push!(Value::Bool(a != b));
            }
            Op::CmpLt => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a < b));
            }
            Op::CmpLe => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a <= b));
            }
            Op::CmpGt => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a > b));
            }
            Op::CmpGe => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a >= b));
            }
            Op::PrefixIn => {
                let network = as_prefix(pop!());
                let candidate = as_prefix(pop!());
                push!(Value::Bool(network.contains(&candidate)));
            }
            Op::And => {
                let b = as_bool(pop!());
                let a = as_bool(pop!());
                push!(Value::Bool(a && b));
            }
            Op::Or => {
                let b = as_bool(pop!());
                let a = as_bool(pop!());
                push!(Value::Bool(a || b));
            }
            Op::Not => {
                let a = as_bool(pop!());
                push!(Value::Bool(!a));
            }
            Op::JumpIfFalse(target) => {
                if !as_bool(pop!()) {
                    pc = *target;
                    continue;
                }
            }
            Op::Jump(target) => {
                pc = *target;
                continue;
            }
            Op::SetField(id) => {
                let v = as_int(pop!());
                match id {
                    FieldId::BgpLocalPref => cur_local_pref = to_u32_saturating(v),
                    FieldId::BgpMed => cur_med = Some(to_u32_saturating(v)),
                    _ => unreachable!("check.rs rejects SetField for {id:?}"),
                }
            }
            Op::Accept => {
                return Verdict::Accept {
                    local_pref: cur_local_pref,
                    med: cur_med,
                }
            }
            Op::Reject => return Verdict::Reject,
        }
        pc += 1;
    }
}

fn len_as_int(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// `set this.bgp.local_pref = <expr>` carries a runtime-computed `i64`, not
/// always a literal, so out-of-range values can't be rejected at compile
/// time — clamp instead of wrapping, since a wrapped negative-to-huge value
/// would be a far more surprising outcome for a route attribute than a
/// clamped one.
fn to_u32_saturating(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(if v.is_negative() { 0 } else { u32::MAX })
}

fn as_int(v: Value) -> i64 {
    match v {
        Value::Int(n) => n,
        other => unreachable!("codegen.rs guarantees an Int here, got {other:?}"),
    }
}

fn as_bool(v: Value) -> bool {
    match v {
        Value::Bool(b) => b,
        other => unreachable!("codegen.rs guarantees a Bool here, got {other:?}"),
    }
}

fn as_prefix(v: Value) -> IpNet {
    match v {
        Value::Prefix(p) => p,
        other => unreachable!("codegen.rs guarantees a Prefix here, got {other:?}"),
    }
}
