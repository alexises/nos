use std::net::IpAddr;

use ipnet::IpNet;

/// One segment of a postfix chain off `this` — either a plain field/property
/// access (`.local_pref`, `.length`) or a method call (`.contains(65010)`).
/// The parser has no notion of the schema; `codegen.rs` is what decides
/// which prefix of a chain is a real field path and which trailing segment
/// (at most one, in v1) is a property/method suffix.
#[derive(Debug, Clone, PartialEq)]
pub enum Postfix {
    /// `.field` step.
    Field(String),
    /// `.name(args...)` method call.
    Call(String, Vec<Expr>),
}

/// Unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// Boolean negation (`not`).
    Not,
}

/// Binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `in` (membership/containment).
    In,
    /// `and`
    And,
    /// `or`
    Or,
}

/// Which extended-community-shaped value an [`ExprKind::ExtLit`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    /// `rt(..)`: a Route Target (RFC 4364 section 4.3.1).
    Rt,
    /// `soo(..)`: a Site of Origin (RFC 4364 section 7).
    Soo,
    /// `rd(..)`: a Route Distinguisher (RFC 4364 section 4.2).
    Rd,
}

/// Expression shape.
#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    /// Integer literal.
    IntLit(i64),
    /// `"^65001_"` — only valid as the argument to `.matches(..)` / `.remove_matching(..)`.
    StrLit(String),
    /// Prefix literal (`10.0.0.0/8`).
    PrefixLit(IpNet),
    /// IP address literal.
    IpLit(IpAddr),
    /// `rt(65000:2)` / `soo(10.0.0.1:7)` / `rd(65001:1)`, already encoded as
    /// the 8-octet value (the type octet in the high byte), the way
    /// `nos_proto::evpn_id::parse_rt`/`parse_rd` do.
    ExtLit(ExtKind, u64),
    /// `origin.igp` — an enum type name plus a variant name.
    EnumLit(String, String),
    /// `65000:100` / `3:2:900` — a colon-separated run of integer literals.
    /// Only valid as a direct argument to `.contains(..)`/`.add(..)`/
    /// `.remove(..)` on a community-list field; `codegen.rs` decides arity
    /// and packing from the target field's `FieldType`, not this node alone.
    ColonLit(Vec<i64>),
    /// A bare identifier not followed by `.` (so not an `EnumLit`) —
    /// referencing a `community-alias`/`community-group`/`prefix-list` by
    /// name. Only valid as a direct argument to `.contains(..)`/`.add(..)`/
    /// `.remove(..)`, or as the right-hand side of `in`; `codegen.rs`
    /// resolves it against the compile-time `Symbols` table.
    Ident(String),
    /// `this` followed by zero or more postfix segments.
    This(Vec<Postfix>),
    /// Unary operation.
    Unary(UnaryOp, Box<Expr>),
    /// Binary operation.
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

/// An expression with its source line.
#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    /// The expression's shape.
    pub kind: ExprKind,
    /// 1-based source line.
    pub line: usize,
}

/// Statement shape.
#[derive(Debug, Clone, PartialEq)]
pub enum StmtKind {
    /// `if`/`elif` branches (condition, body) in source order, plus an
    /// optional `else` body. `check.rs` is what requires `else_body` to be
    /// present (and every branch to terminate) for this to be a valid
    /// terminal statement — the parser accepts a missing `else` as an
    /// ordinary (non-terminating) statement.
    If {
        /// `(condition, body)` pairs in source order.
        branches: Vec<(Expr, Vec<Stmt>)>,
        /// Optional `else` body.
        else_body: Option<Vec<Stmt>>,
    },
    /// `set <field> = <expr>`.
    Set(Expr, Expr),
    /// `set this.bgp.local_pref += <expr>` / `-= <expr>` — the bool is
    /// `true` for `-=`.
    SetRelative(Expr, bool, Expr),
    /// `this.bgp.communities.add(65000:100)` — adds one value to a settable
    /// community-list field.
    CommunityAdd(Expr, Expr),
    /// `this.bgp.communities.remove(65000:100)` — removes one value, if
    /// present, from a settable community-list field.
    CommunityRemove(Expr, Expr),
    /// `this.bgp.communities.remove_matching("^65000:")` — removes every
    /// value whose rendered text matches the regex (target, string literal).
    CommunityRemoveMatching(Expr, Expr),
    /// `this.bgp.as_path.prepend(65000[, 3])` — the args are the ASN and an
    /// optional repeat count.
    AsPathPrepend(Expr, Vec<Expr>),
    /// `this.bgp.communities.clear()` — empties a settable community-list
    /// field.
    CommunityClear(Expr),
    /// `accept` (terminal).
    Accept,
    /// `reject` (terminal).
    Reject,
    /// `call NAME`: runs another stored policy inline, then continues here
    /// (the callee's `accept` returns; its `reject` rejects the route).
    Call(String),
}

/// A statement with its source line.
#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    /// The statement's shape.
    pub kind: StmtKind,
    /// 1-based source line.
    pub line: usize,
}

/// A whole policy: its top-level statements.
pub type Policy = Vec<Stmt>;
