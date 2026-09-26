use crate::ast::{BinOp, Expr, ExprKind, Policy, Postfix, Stmt, StmtKind, UnaryOp};
use crate::lexer::{SpannedToken, Token};
use crate::CompileError;

struct Parser<'a> {
    tokens: &'a [SpannedToken],
    pos: usize,
}

pub fn parse(tokens: &[SpannedToken]) -> Result<Policy, CompileError> {
    let mut p = Parser { tokens, pos: 0 };
    let policy = p.parse_block_body()?;
    p.expect(&Token::Eof)?;
    Ok(policy)
}

impl Parser<'_> {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos].token
    }

    fn peek_at(&self, offset: usize) -> &Token {
        let idx = (self.pos + offset).min(self.tokens.len() - 1);
        &self.tokens[idx].token
    }

    fn line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].token.clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Token) -> Result<(), CompileError> {
        if self.peek() == want {
            self.advance();
            Ok(())
        } else {
            Err(CompileError::new(
                self.line(),
                format!("expected {want:?}, found {:?}", self.peek()),
            ))
        }
    }

    fn expect_ident(&mut self) -> Result<String, CompileError> {
        match self.advance() {
            Token::Ident(s) => Ok(s),
            other => Err(CompileError::new(
                self.line(),
                format!("expected identifier, found {other:?}"),
            )),
        }
    }

    /// A sequence of statements up to (not including) the token that ends
    /// the enclosing block (`Dedent`/`Eof`).
    fn parse_block_body(&mut self) -> Result<Vec<Stmt>, CompileError> {
        let mut stmts = Vec::new();
        while !matches!(self.peek(), Token::Dedent | Token::Eof) {
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    /// `":" NEWLINE INDENT <block> DEDENT`, shared by `if`/`elif`/`else`.
    fn parse_suite(&mut self) -> Result<Vec<Stmt>, CompileError> {
        self.expect(&Token::Colon)?;
        self.expect(&Token::Newline)?;
        self.expect(&Token::Indent)?;
        let body = self.parse_block_body()?;
        self.expect(&Token::Dedent)?;
        Ok(body)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, CompileError> {
        let line = self.line();
        let kind = match self.peek() {
            Token::If => self.parse_if()?,
            Token::Set => self.parse_set()?,
            Token::Ident(name) if name == "this" => self.parse_this_stmt()?,
            Token::Accept => {
                self.advance();
                self.expect(&Token::Newline)?;
                StmtKind::Accept
            }
            Token::Reject => {
                self.advance();
                self.expect(&Token::Newline)?;
                StmtKind::Reject
            }
            other => {
                return Err(CompileError::new(
                    line,
                    format!("expected a statement, found {other:?}"),
                ))
            }
        };
        Ok(Stmt { kind, line })
    }

    /// `this.<field>.add(..)` / `.remove(..)` / `.clear()` — parsed by
    /// reusing `parse_postfix` and then requiring the last segment to be
    /// exactly one of these three method calls.
    fn parse_this_stmt(&mut self) -> Result<StmtKind, CompileError> {
        let line = self.line();
        let expr = self.parse_postfix()?;
        let ExprKind::This(mut segments) = expr.kind else {
            unreachable!("parse_postfix always returns ExprKind::This for a 'this'-led atom");
        };
        let Some(Postfix::Call(name, mut args)) = segments.pop() else {
            return Err(CompileError::new(
                line,
                "expected a statement: 'set ... = ...' or 'this.<field>.add(..)'/'.remove(..)'/'.clear()'",
            ));
        };
        let target = Expr {
            kind: ExprKind::This(segments),
            line,
        };
        let kind = match (name.as_str(), args.len()) {
            ("add", 1) => StmtKind::CommunityAdd(target, args.remove(0)),
            ("remove", 1) => StmtKind::CommunityRemove(target, args.remove(0)),
            ("clear", 0) => StmtKind::CommunityClear(target),
            _ => {
                return Err(CompileError::new(
                    line,
                    format!("unknown statement '.{name}(..)'"),
                ))
            }
        };
        self.expect(&Token::Newline)?;
        Ok(kind)
    }

    fn parse_if(&mut self) -> Result<StmtKind, CompileError> {
        self.expect(&Token::If)?;
        let mut branches = Vec::new();
        let cond = self.parse_expr()?;
        let body = self.parse_suite()?;
        branches.push((cond, body));

        while matches!(self.peek(), Token::Elif) {
            self.advance();
            let cond = self.parse_expr()?;
            let body = self.parse_suite()?;
            branches.push((cond, body));
        }

        let else_body = if matches!(self.peek(), Token::Else) {
            self.advance();
            Some(self.parse_suite()?)
        } else {
            None
        };

        Ok(StmtKind::If {
            branches,
            else_body,
        })
    }

    fn parse_set(&mut self) -> Result<StmtKind, CompileError> {
        self.expect(&Token::Set)?;
        let target = self.parse_postfix()?;
        let relative = match self.peek() {
            Token::Plus => Some(false),
            Token::Minus => Some(true),
            _ => None,
        };
        if relative.is_some() {
            self.advance();
        }
        self.expect(&Token::Assign)?;
        let value = self.parse_expr()?;
        self.expect(&Token::Newline)?;
        Ok(match relative {
            Some(negate) => StmtKind::SetRelative(target, negate, value),
            None => StmtKind::Set(target, value),
        })
    }

    fn parse_expr(&mut self) -> Result<Expr, CompileError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Token::Or) {
            let line = self.line();
            self.advance();
            let rhs = self.parse_and()?;
            lhs = Expr {
                kind: ExprKind::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs)),
                line,
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek(), Token::And) {
            let line = self.line();
            self.advance();
            let rhs = self.parse_not()?;
            lhs = Expr {
                kind: ExprKind::Binary(BinOp::And, Box::new(lhs), Box::new(rhs)),
                line,
            };
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr, CompileError> {
        if matches!(self.peek(), Token::Not) {
            let line = self.line();
            self.advance();
            let inner = self.parse_not()?;
            Ok(Expr {
                kind: ExprKind::Unary(UnaryOp::Not, Box::new(inner)),
                line,
            })
        } else {
            self.parse_comparison()
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, CompileError> {
        let lhs = self.parse_sum()?;
        let line = self.line();
        let op = match self.peek() {
            Token::Eq => BinOp::Eq,
            Token::Ne => BinOp::Ne,
            Token::Lt => BinOp::Lt,
            Token::Le => BinOp::Le,
            Token::Gt => BinOp::Gt,
            Token::Ge => BinOp::Ge,
            Token::In => BinOp::In,
            _ => return Ok(lhs),
        };
        self.advance();
        let rhs = self.parse_sum()?;
        Ok(Expr {
            kind: ExprKind::Binary(op, Box::new(lhs), Box::new(rhs)),
            line,
        })
    }

    fn parse_sum(&mut self) -> Result<Expr, CompileError> {
        let mut lhs = self.parse_postfix()?;
        loop {
            let line = self.line();
            let op = match self.peek() {
                Token::Plus => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_postfix()?;
            lhs = Expr {
                kind: ExprKind::Binary(op, Box::new(lhs), Box::new(rhs)),
                line,
            };
        }
        Ok(lhs)
    }

    fn parse_postfix(&mut self) -> Result<Expr, CompileError> {
        let atom = self.parse_atom()?;
        let line = atom.line;
        let ExprKind::This(mut segments) = atom.kind else {
            return Ok(atom);
        };
        loop {
            if !matches!(self.peek(), Token::Dot) {
                break;
            }
            self.advance();
            let name = self.expect_ident()?;
            if matches!(self.peek(), Token::LParen) {
                self.advance();
                let mut args = Vec::new();
                if !matches!(self.peek(), Token::RParen) {
                    args.push(self.parse_expr()?);
                    while matches!(self.peek(), Token::Comma) {
                        self.advance();
                        args.push(self.parse_expr()?);
                    }
                }
                self.expect(&Token::RParen)?;
                segments.push(Postfix::Call(name, args));
            } else {
                segments.push(Postfix::Field(name));
            }
        }
        Ok(Expr {
            kind: ExprKind::This(segments),
            line,
        })
    }

    fn parse_atom(&mut self) -> Result<Expr, CompileError> {
        let line = self.line();
        let kind = match self.advance() {
            Token::Int(n) => {
                // `65000:100` / `3:2:900` — a colon-literal community value.
                // Only consume `Colon` here when it's immediately followed by
                // another `Int`, so the block-starting colon in `if cond:`
                // (always followed by `Newline`) is left untouched.
                let mut parts = vec![n];
                while matches!(self.peek(), Token::Colon)
                    && matches!(self.peek_at(1), Token::Int(_))
                {
                    self.advance(); // Colon
                    let Token::Int(next) = self.advance() else {
                        unreachable!("peek_at(1) just confirmed an Int");
                    };
                    parts.push(next);
                }
                if parts.len() == 1 {
                    ExprKind::IntLit(parts[0])
                } else {
                    ExprKind::ColonLit(parts)
                }
            }
            Token::Prefix(p) => ExprKind::PrefixLit(p),
            Token::IpAddr(a) => ExprKind::IpLit(a),
            Token::LParen => {
                let inner = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                return Ok(inner);
            }
            Token::Ident(name) if name == "this" => ExprKind::This(Vec::new()),
            Token::Ident(name) => {
                if matches!(self.peek(), Token::Dot) {
                    self.advance();
                    let variant = self.expect_ident()?;
                    ExprKind::EnumLit(name, variant)
                } else {
                    ExprKind::Ident(name)
                }
            }
            other => {
                return Err(CompileError::new(
                    line,
                    format!("expected an expression, found {other:?}"),
                ))
            }
        };
        Ok(Expr { kind, line })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn parse_src(src: &str) -> Policy {
        parse(&lex(src).unwrap()).unwrap()
    }

    #[test]
    fn accept_only() {
        let policy = parse_src("accept\n");
        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0].kind, StmtKind::Accept);
    }

    #[test]
    fn if_else_with_set() {
        let policy = parse_src(
            "if this.bgp.local_pref < 100:\n    set this.bgp.local_pref = 150\n    accept\nelse:\n    reject\n",
        );
        let StmtKind::If {
            branches,
            else_body,
        } = &policy[0].kind
        else {
            panic!("expected if");
        };
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].1.len(), 2);
        assert!(else_body.is_some());
    }

    #[test]
    fn field_access_and_method_call() {
        let policy =
            parse_src("if this.bgp.as_path.contains(65010):\n    reject\nelse:\n    accept\n");
        let StmtKind::If { branches, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        let ExprKind::This(segments) = &branches[0].0.kind else {
            panic!("expected this expr");
        };
        assert_eq!(
            segments,
            &vec![
                Postfix::Field("bgp".to_string()),
                Postfix::Field("as_path".to_string()),
                Postfix::Call(
                    "contains".to_string(),
                    vec![Expr {
                        kind: ExprKind::IntLit(65010),
                        line: 1
                    }]
                ),
            ]
        );
    }

    #[test]
    fn enum_literal() {
        let policy =
            parse_src("if this.bgp.origin == origin.igp:\n    accept\nelse:\n    reject\n");
        let StmtKind::If { branches, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        let ExprKind::Binary(BinOp::Eq, _, rhs) = &branches[0].0.kind else {
            panic!("expected ==");
        };
        assert_eq!(
            rhs.kind,
            ExprKind::EnumLit("origin".to_string(), "igp".to_string())
        );
    }

    #[test]
    fn missing_else_parses_as_non_terminating_if() {
        let policy = parse_src("if this.prefix in 10.0.0.0/8:\n    reject\n");
        let StmtKind::If { else_body, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        assert!(else_body.is_none());
    }

    #[test]
    fn colon_literal_parses_as_colon_lit() {
        let policy = parse_src("this.bgp.communities.add(65000:100)\naccept\n");
        let StmtKind::CommunityAdd(_, value) = &policy[0].kind else {
            panic!("expected CommunityAdd");
        };
        assert_eq!(value.kind, ExprKind::ColonLit(vec![65000, 100]));
    }

    #[test]
    fn three_part_colon_literal() {
        let policy = parse_src("this.bgp.large_communities.add(65000:1:2)\naccept\n");
        let StmtKind::CommunityAdd(_, value) = &policy[0].kind else {
            panic!("expected CommunityAdd");
        };
        assert_eq!(value.kind, ExprKind::ColonLit(vec![65000, 1, 2]));
    }

    #[test]
    fn block_colon_is_not_consumed_as_a_colon_literal() {
        let policy = parse_src("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        let StmtKind::If { branches, .. } = &policy[0].kind else {
            panic!("expected if");
        };
        let ExprKind::Binary(BinOp::Lt, _, rhs) = &branches[0].0.kind else {
            panic!("expected <");
        };
        assert_eq!(rhs.kind, ExprKind::IntLit(100));
    }

    #[test]
    fn community_remove_and_clear_parse() {
        let policy = parse_src(
            "this.bgp.communities.remove(65000:100)\nthis.bgp.communities.clear()\naccept\n",
        );
        assert!(matches!(policy[0].kind, StmtKind::CommunityRemove(..)));
        assert!(matches!(policy[1].kind, StmtKind::CommunityClear(..)));
    }
}
