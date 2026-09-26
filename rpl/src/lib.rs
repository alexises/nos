//! `nos-rpl` — the Routing Policy Language compiler and VM. Zero
//! NOS-internal dependencies, like `nos-tcp-auth`: it's a plain library
//! consumed by `nos-proto` (commit-time validation of `PolicyDefinition`
//! source) and `nos-bgp` (compiling, caching, and executing policies against
//! real routes). See root `CLAUDE.md`'s "Routing policy language (RPL)"
//! section for the language and architecture this implements.

pub mod ast;
mod check;
mod codegen;
mod lexer;
mod parser;
pub mod schema;
mod symbols;
pub mod vm;

pub use symbols::{PrefixListEntry, Symbols};
pub use vm::{
    AsPathRegexes, BgpInput, CompiledPolicy, Edits, Input, NextHopSet, Op, Origin, Value, Verdict,
};

use std::fmt;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub line: usize,
    pub message: String,
}

impl CompileError {
    pub(crate) fn new(line: usize, message: impl Into<String>) -> Self {
        CompileError {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for CompileError {}

/// Compiles RPL source into bytecode: lex -> parse -> termination/
/// reachability check -> type-checked codegen. Called both by
/// `nos-config` (commit-time validation of `PolicyDefinition.source`,
/// discarding the result) and `nos-bgp` (which caches and runs it).
/// `symbols` resolves any bare-identifier reference to a `community-alias`/
/// `community-group`/`prefix-list` object — pass `&Symbols::EMPTY` when none
/// are in scope.
pub fn compile(src: &str, symbols: &Symbols) -> Result<CompiledPolicy, CompileError> {
    let tokens = lexer::lex(src)?;
    let policy = parser::parse(&tokens)?;
    check::check_termination(&policy)?;
    codegen::compile(&policy, symbols)
}

/// Parses a bare colon-separated community literal (`"65000:100"` ->
/// `Some(vec![65000, 100])`), the exact grammar `parse_atom` accepts inline
/// in a script for `.contains(..)`/`.add(..)`/`.remove(..)`. Returns `None`
/// if `s` isn't exactly that shape (extra tokens, wrong token kinds, empty)
/// — reuses the real lexer so this never drifts from the script grammar.
/// Used by `nos-proto` to validate a stored `CommunityAlias.value` (and a
/// `CommunityGroup` member that isn't an alias name) without duplicating
/// RPL's literal grammar. Arity (2 parts for standard, 3 for extended/large)
/// is intentionally not checked here — it's ambiguous until the value is
/// referenced from a specific field inside a script, exactly like an inline
/// `ColonLit` today.
pub fn parse_colon_literal(s: &str) -> Option<Vec<i64>> {
    let tokens = lexer::lex(s).ok()?;
    let mut iter = tokens.iter().map(|t| &t.token);
    let lexer::Token::Int(first) = iter.next()? else {
        return None;
    };
    let mut parts = vec![*first];
    loop {
        match iter.next()? {
            lexer::Token::Colon => {
                let lexer::Token::Int(n) = iter.next()? else {
                    return None;
                };
                parts.push(*n);
            }
            lexer::Token::Newline => break,
            _ => return None,
        }
    }
    matches!(iter.next(), Some(lexer::Token::Eof)).then_some(parts)
}

/// The two reserved system policies every consumer resolves the same way —
/// see root `CLAUDE.md`'s "Built-in system policies". Not stored as
/// `PolicyDefinition` config entries: nothing to edit, nothing to delete.
pub static ACCEPT_ALL: LazyLock<CompiledPolicy> =
    LazyLock::new(|| compile("accept\n", &Symbols::EMPTY).expect("accept-all must compile"));
pub static DENY_ALL: LazyLock<CompiledPolicy> =
    LazyLock::new(|| compile("reject\n", &Symbols::EMPTY).expect("deny-all must compile"));

/// The two reserved policy names — see `ACCEPT_ALL`/`DENY_ALL`.
pub const ACCEPT_ALL_NAME: &str = "accept-all";
pub const DENY_ALL_NAME: &str = "deny-all";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_all_always_accepts() {
        let input = Input {
            prefix: "10.0.0.0/8".parse().unwrap(),
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
                peer: None,
                peer_as: 0,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
            },
        };
        assert_eq!(
            vm::run(&ACCEPT_ALL, &input),
            Verdict::Accept {
                local_pref: 100,
                med: None,
                communities: Vec::new(),
                extended_communities: Vec::new(),
                large_communities: Vec::new(),
                edits: Edits::default(),
            }
        );
    }

    #[test]
    fn deny_all_always_rejects() {
        let input = Input {
            prefix: "10.0.0.0/8".parse().unwrap(),
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
                peer: None,
                peer_as: 0,
                communities: &[],
                extended_communities: &[],
                large_communities: &[],
            },
        };
        assert_eq!(vm::run(&DENY_ALL, &input), Verdict::Reject);
    }

    #[test]
    fn compile_rejects_syntax_error() {
        assert!(compile("if this.prefix in :\n    accept\n", &Symbols::EMPTY).is_err());
    }

    #[test]
    fn compile_error_display_includes_line() {
        let err = compile(
            "if this.bgp.nonexistent == 1:\n    accept\nelse:\n    reject\n",
            &Symbols::EMPTY,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("line 1:"));
    }

    #[test]
    fn parse_colon_literal_accepts_two_and_three_part() {
        assert_eq!(parse_colon_literal("65000:100"), Some(vec![65000, 100]));
        assert_eq!(parse_colon_literal("65000:1:2"), Some(vec![65000, 1, 2]));
    }

    #[test]
    fn parse_colon_literal_rejects_non_literal_text() {
        assert_eq!(parse_colon_literal(""), None);
        assert_eq!(parse_colon_literal("not-a-literal"), None);
        assert_eq!(parse_colon_literal("65000:100 extra"), None);
        assert_eq!(parse_colon_literal("10.0.0.0/8"), None);
    }
}
