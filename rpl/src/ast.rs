use std::net::IpAddr;

use ipnet::IpNet;

/// One segment of a postfix chain off `this` — either a plain field/property
/// access (`.local_pref`, `.length`) or a method call (`.contains(65010)`).
/// The parser has no notion of the schema; `codegen.rs` is what decides
/// which prefix of a chain is a real field path and which trailing segment
/// (at most one, in v1) is a property/method suffix.
#[derive(Debug, Clone, PartialEq)]
pub enum Postfix {
    Field(String),
    Call(String, Vec<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    IntLit(i64),
    PrefixLit(IpNet),
    IpLit(IpAddr),
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
    Unary(UnaryOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StmtKind {
    /// `if`/`elif` branches (condition, body) in source order, plus an
    /// optional `else` body. `check.rs` is what requires `else_body` to be
    /// present (and every branch to terminate) for this to be a valid
    /// terminal statement — the parser accepts a missing `else` as an
    /// ordinary (non-terminating) statement.
    If {
        branches: Vec<(Expr, Vec<Stmt>)>,
        else_body: Option<Vec<Stmt>>,
    },
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
    /// `this.bgp.communities.clear()` — empties a settable community-list
    /// field.
    CommunityClear(Expr),
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub line: usize,
}

pub type Policy = Vec<Stmt>;
