use std::net::IpAddr;

use ipnet::IpNet;

use crate::CompileError;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Newline,
    Indent,
    Dedent,
    Ident(String),
    Int(i64),
    Str(String),
    Prefix(IpNet),
    IpAddr(IpAddr),
    If,
    Elif,
    Else,
    Set,
    Accept,
    Reject,
    And,
    Or,
    Not,
    In,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Assign,
    Colon,
    Dot,
    Comma,
    LParen,
    RParen,
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpannedToken {
    pub token: Token,
    pub line: usize,
}

/// Tokenizes `src` using Python-style significant indentation (a stack of
/// indent widths; `Indent`/`Dedent` are synthesized on width changes).
/// Blank lines and comment-only lines are skipped entirely — they never
/// affect the indent stack and never emit `Newline`. Tabs are rejected
/// outright rather than given an arbitrary width, since mixing tabs and
/// spaces is exactly the kind of silent-indentation-bug this format can't
/// afford to allow.
pub fn lex(src: &str) -> Result<Vec<SpannedToken>, CompileError> {
    let mut tokens = Vec::new();
    let mut indent_stack = vec![0usize];

    for (line_idx, raw_line) in src.lines().enumerate() {
        let line = line_idx + 1;
        let code = &raw_line[..code_end(raw_line)];
        if code.trim().is_empty() {
            continue;
        }
        if code.contains('\t') {
            return Err(CompileError::new(line, "tabs are not allowed; use spaces"));
        }
        let indent = code.len() - code.trim_start_matches(' ').len();
        let rest = code.trim_start_matches(' ');

        let current = *indent_stack.last().unwrap();
        if indent > current {
            indent_stack.push(indent);
            tokens.push(SpannedToken {
                token: Token::Indent,
                line,
            });
        } else if indent < current {
            while *indent_stack.last().unwrap() > indent {
                indent_stack.pop();
                tokens.push(SpannedToken {
                    token: Token::Dedent,
                    line,
                });
            }
            if *indent_stack.last().unwrap() != indent {
                return Err(CompileError::new(line, "inconsistent indentation"));
            }
        }

        lex_line(rest, line, &mut tokens)?;
        tokens.push(SpannedToken {
            token: Token::Newline,
            line,
        });
    }

    let last_line = src.lines().count().max(1);
    while indent_stack.len() > 1 {
        indent_stack.pop();
        tokens.push(SpannedToken {
            token: Token::Dedent,
            line: last_line,
        });
    }
    tokens.push(SpannedToken {
        token: Token::Eof,
        line: last_line,
    });
    Ok(tokens)
}

/// Byte index where the code on `line` ends: the first `#` outside a `"..."`
/// literal (strings have no escapes, like `lex_line`), else the line's end.
fn code_end(line: &str) -> usize {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return i,
            _ => {}
        }
    }
    line.len()
}

fn lex_line(line: &str, lineno: usize, out: &mut Vec<SpannedToken>) -> Result<(), CompileError> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == ' ' {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            // IPv4-dotted-decimal and prefix literals only in v1 — a bare
            // IPv6 literal's own colons would be ambiguous with the block
            // ':' that immediately follows one in real policy source (e.g.
            // `this.prefix in 2001:db8::/32:`), so it isn't supported here.
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c.is_ascii_digit() || c == '.' || c == '/' {
                    i += 1;
                } else {
                    break;
                }
            }
            let text = &line[start..i];
            out.push(SpannedToken {
                token: classify_numeric(text, lineno)?,
                line: lineno,
            });
            continue;
        }
        if c == '"' {
            let Some(len) = line[i + 1..].find('"') else {
                return Err(CompileError::new(lineno, "unterminated string literal"));
            };
            out.push(SpannedToken {
                token: Token::Str(line[i + 1..i + 1 + len].to_string()),
                line: lineno,
            });
            i += len + 2;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if c.is_ascii_alphanumeric() || c == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            let word = &line[start..i];
            out.push(SpannedToken {
                token: keyword_or_ident(word),
                line: lineno,
            });
            continue;
        }
        let (tok, width) = match c {
            '=' if bytes.get(i + 1) == Some(&b'=') => (Token::Eq, 2),
            '!' if bytes.get(i + 1) == Some(&b'=') => (Token::Ne, 2),
            '<' if bytes.get(i + 1) == Some(&b'=') => (Token::Le, 2),
            '>' if bytes.get(i + 1) == Some(&b'=') => (Token::Ge, 2),
            '<' => (Token::Lt, 1),
            '>' => (Token::Gt, 1),
            '=' => (Token::Assign, 1),
            '+' => (Token::Plus, 1),
            '-' => (Token::Minus, 1),
            ':' => (Token::Colon, 1),
            '.' => (Token::Dot, 1),
            ',' => (Token::Comma, 1),
            '(' => (Token::LParen, 1),
            ')' => (Token::RParen, 1),
            other => {
                return Err(CompileError::new(
                    lineno,
                    format!("unexpected character '{other}'"),
                ))
            }
        };
        out.push(SpannedToken {
            token: tok,
            line: lineno,
        });
        i += width;
    }
    Ok(())
}

fn keyword_or_ident(word: &str) -> Token {
    match word {
        "if" => Token::If,
        "elif" => Token::Elif,
        "else" => Token::Else,
        "set" => Token::Set,
        "accept" => Token::Accept,
        "reject" => Token::Reject,
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "in" => Token::In,
        _ => Token::Ident(word.to_string()),
    }
}

fn classify_numeric(text: &str, line: usize) -> Result<Token, CompileError> {
    if let Ok(n) = text.parse::<i64>() {
        return Ok(Token::Int(n));
    }
    if text.contains('/') {
        return text
            .parse::<IpNet>()
            .map(Token::Prefix)
            .map_err(|_| CompileError::new(line, format!("invalid prefix literal '{text}'")));
    }
    text.parse::<IpAddr>().map(Token::IpAddr).map_err(|_| {
        CompileError::new(line, format!("invalid numeric or address literal '{text}'"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens_of(src: &str) -> Vec<Token> {
        lex(src).unwrap().into_iter().map(|t| t.token).collect()
    }

    #[test]
    fn simple_accept() {
        assert_eq!(
            tokens_of("accept\n"),
            vec![Token::Accept, Token::Newline, Token::Eof]
        );
    }

    #[test]
    fn if_else_produces_indent_dedent() {
        let toks = tokens_of("if this.bgp.local_pref < 100:\n    reject\nelse:\n    accept\n");
        assert_eq!(
            toks,
            vec![
                Token::If,
                Token::Ident("this".to_string()),
                Token::Dot,
                Token::Ident("bgp".to_string()),
                Token::Dot,
                Token::Ident("local_pref".to_string()),
                Token::Lt,
                Token::Int(100),
                Token::Colon,
                Token::Newline,
                Token::Indent,
                Token::Reject,
                Token::Newline,
                Token::Dedent,
                Token::Else,
                Token::Colon,
                Token::Newline,
                Token::Indent,
                Token::Accept,
                Token::Newline,
                Token::Dedent,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        assert_eq!(
            tokens_of("# a comment\n\naccept # trailing\n"),
            vec![Token::Accept, Token::Newline, Token::Eof]
        );
    }

    #[test]
    fn hash_inside_string_is_literal() {
        let s = |t: &str| Token::Str(t.to_string());
        assert_eq!(
            tokens_of("\"^65001#\"\n"),
            vec![s("^65001#"), Token::Newline, Token::Eof]
        );
        assert_eq!(
            tokens_of("\"a#b\" # note\n"),
            vec![s("a#b"), Token::Newline, Token::Eof]
        );
        assert_eq!(
            tokens_of("\"#\"\n"),
            vec![s("#"), Token::Newline, Token::Eof]
        );
        assert_eq!(
            tokens_of("accept # \"quoted\" in comment\n"),
            vec![Token::Accept, Token::Newline, Token::Eof]
        );
        assert!(lex("\"abc # x\n").is_err());
    }

    #[test]
    fn prefix_and_ip_literals() {
        let toks = tokens_of("10.0.0.0/8\n192.0.2.1\n");
        assert_eq!(
            toks,
            vec![
                Token::Prefix("10.0.0.0/8".parse().unwrap()),
                Token::Newline,
                Token::IpAddr("192.0.2.1".parse().unwrap()),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tabs_are_rejected() {
        assert!(lex("\taccept\n").is_err());
    }

    #[test]
    fn inconsistent_indentation_is_rejected() {
        let src = "a:\n    b\n        c\n      d\n";
        assert!(lex(src).is_err());
    }
}
