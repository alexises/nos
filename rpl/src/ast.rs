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
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub line: usize,
}

pub type Policy = Vec<Stmt>;
