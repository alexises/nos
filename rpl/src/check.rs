//! The compile-time "every path terminates" rule: a structural reachability
//! pass over the statement tree, not dataflow analysis. Type checking lives
//! in `codegen.rs` (a single combined type-check-and-emit pass), since it
//! needs no information this pass produces.

use crate::ast::{Stmt, StmtKind};
use crate::CompileError;

pub fn check_termination(stmts: &[Stmt]) -> Result<(), CompileError> {
    check_reachable(stmts)?;
    if !terminates(stmts) {
        let line = stmts.last().map_or(1, |s| s.line);
        return Err(CompileError::new(
            line,
            "policy does not terminate on every path: end with accept/reject, or an 'if' with an 'else' where every branch terminates",
        ));
    }
    Ok(())
}

fn terminates(stmts: &[Stmt]) -> bool {
    stmts.last().is_some_and(stmt_terminates)
}

fn stmt_terminates(stmt: &Stmt) -> bool {
    match &stmt.kind {
        StmtKind::Accept | StmtKind::Reject => true,
        StmtKind::Set(..)
        | StmtKind::CommunityAdd(..)
        | StmtKind::CommunityRemove(..)
        | StmtKind::CommunityClear(..) => false,
        StmtKind::If {
            branches,
            else_body,
        } => {
            let Some(else_body) = else_body else {
                return false;
            };
            branches.iter().all(|(_, body)| terminates(body)) && terminates(else_body)
        }
    }
}

/// Flags any statement that appears after one that already terminates its
/// enclosing block — a hard error, not a warning, so the language never has
/// an ambiguous "accepts twice" script.
fn check_reachable(stmts: &[Stmt]) -> Result<(), CompileError> {
    for (i, stmt) in stmts.iter().enumerate() {
        if i + 1 < stmts.len() && stmt_terminates(stmt) {
            let next = &stmts[i + 1];
            return Err(CompileError::new(
                next.line,
                "unreachable statement: every path above this point already terminated",
            ));
        }
        if let StmtKind::If {
            branches,
            else_body,
        } = &stmt.kind
        {
            for (_, body) in branches {
                check_reachable(body)?;
            }
            if let Some(else_body) = else_body {
                check_reachable(else_body)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;
    use crate::parser::parse;

    fn check_src(src: &str) -> Result<(), CompileError> {
        check_termination(&parse(&lex(src).unwrap()).unwrap())
    }

    #[test]
    fn bare_accept_terminates() {
        check_src("accept\n").unwrap();
    }

    #[test]
    fn if_else_both_terminal_passes() {
        check_src("if this.prefix in 10.0.0.0/8:\n    reject\nelse:\n    accept\n").unwrap();
    }

    #[test]
    fn if_with_no_else_fails() {
        let err = check_src("if this.bgp.as_path.contains(65535):\n    reject\n").unwrap_err();
        assert!(err.to_string().contains("does not terminate"));
    }

    #[test]
    fn if_else_missing_terminal_in_else_fails() {
        let src =
            "if this.prefix in 10.0.0.0/8:\n    reject\nelse:\n    set this.bgp.local_pref = 50\n";
        assert!(check_src(src).is_err());
    }

    #[test]
    fn dead_code_after_terminal_fails() {
        let src = "if this.prefix in 10.0.0.0/8:\n    accept\nelse:\n    reject\naccept\n";
        let err = check_src(src).unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn set_then_terminal_passes() {
        check_src("set this.bgp.local_pref = 150\naccept\n").unwrap();
    }

    #[test]
    fn nested_if_all_branches_terminal_passes() {
        let src = "if this.prefix in 10.0.0.0/8:\n    if this.bgp.local_pref < 50:\n        reject\n    else:\n        accept\nelse:\n    reject\n";
        check_src(src).unwrap();
    }

    #[test]
    fn community_add_then_terminal_passes() {
        check_src("this.bgp.communities.add(65000:100)\naccept\n").unwrap();
    }

    #[test]
    fn bare_community_add_with_no_terminal_fails() {
        let err = check_src("this.bgp.communities.add(65000:100)\n").unwrap_err();
        assert!(err.to_string().contains("does not terminate"));
    }
}
