//! Tab-completion, driven by `spec::COMMAND_SPECS` filtered to the current
//! `Mode`. Also the shared data source behind the live `?` key (see
//! `help_menu.rs`) — both read `Suggestion`s from the same completer, so
//! they always agree on what's valid to type next.

use nos_proto::{CommandDoc, Topic};
use reedline::{Completer, CompletionResult, Span, Suggestion};

use crate::session::Mode;
use crate::spec::{self, ArgKind, Doc, Token};

/// Tab-completion for the nos-cli grammar. Talks to `nos-configd` only
/// through the two injected closures below, so it never blocks on IPC
/// directly and stays testable without a real daemon.
pub struct NosCompleter {
    mode: Mode,
    /// Resolves a `Doc::FromConfig` topic to its text — production code
    /// wraps a cache-first, blocking-on-miss call to `client::describe`;
    /// tests supply canned docs.
    doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send>,
    /// Live BGP instance names for the current transaction, for
    /// `ArgKind::BgpInstanceName` slots — production code wraps a blocking
    /// call to `client::get_transaction`; tests supply a canned list.
    instance_name_source: Box<dyn FnMut() -> Vec<String> + Send>,
    /// Live peer-group names (flattened across every instance — see
    /// `main.rs`'s `completer_for`) for `ArgKind::BgpPeerGroupName` slots.
    peer_group_name_source: Box<dyn FnMut() -> Vec<String> + Send>,
}

impl NosCompleter {
    pub fn new(
        mode: Mode,
        doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send>,
        instance_name_source: Box<dyn FnMut() -> Vec<String> + Send>,
        peer_group_name_source: Box<dyn FnMut() -> Vec<String> + Send>,
    ) -> Self {
        Self {
            mode,
            doc_source,
            instance_name_source,
            peer_group_name_source,
        }
    }

    /// (summary, detail) for a spec's `Doc` — a single call regardless of
    /// which text ends up displayed, so the live `?` key's second press
    /// (switching to detail) never needs a fresh fetch: both strings were
    /// already cached in the `Suggestion` from the first press.
    fn doc_text_for(&mut self, doc: &Doc) -> (String, String) {
        match doc {
            Doc::Local { summary, detail } => ((*summary).to_string(), (*detail).to_string()),
            Doc::FromConfig(topic) => {
                let doc = (self.doc_source)(*topic);
                (doc.summary, doc.detail)
            }
        }
    }
}

/// One whitespace-delimited token in the buffer, with its start byte offset.
fn tokenize_with_offsets(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, ch) in line.char_indices() {
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                out.push((s, &line[s..i]));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push((s, &line[s..]));
    }
    out
}

impl Completer for NosCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> CompletionResult {
        let line = &line[..pos];
        let ends_with_whitespace = line.chars().next_back().is_none_or(char::is_whitespace);
        let tokens = tokenize_with_offsets(line);

        let (typed, partial_start, partial): (&[(usize, &str)], usize, &str) =
            if ends_with_whitespace || tokens.is_empty() {
                (&tokens, line.len(), "")
            } else {
                let (start, text) = tokens[tokens.len() - 1];
                (&tokens[..tokens.len() - 1], start, text)
            };

        let mut suggestions: Vec<Suggestion> = Vec::new();
        let specs: Vec<_> = spec::COMMAND_SPECS
            .iter()
            .filter(|s| spec::availability_matches(s.availability, &self.mode))
            .collect();

        for spec in specs {
            if typed.len() >= spec.tokens.len() {
                continue;
            }
            let matches_prefix =
                typed
                    .iter()
                    .zip(spec.tokens.iter())
                    .all(|(&(_, t), tok)| match tok {
                        Token::Literal(lit) => *lit == t,
                        Token::Arg(_) => !t.is_empty(),
                    });
            if !matches_prefix {
                continue;
            }

            match spec.tokens[typed.len()] {
                Token::Literal(lit) => {
                    if lit.starts_with(partial) && !suggestions.iter().any(|s| s.value == lit) {
                        let (summary, detail) = self.doc_text_for(&spec.doc);
                        suggestions.push(Suggestion {
                            value: lit.to_string(),
                            description: Some(summary),
                            // [usage, detail] — see `help_menu::HelpMenu::render_line`,
                            // which reads these to render the live `?` key's brief vs
                            // detailed views without a second fetch.
                            extra: Some(vec![spec.usage.to_string(), detail]),
                            span: Span::new(partial_start, line.len()),
                            append_whitespace: true,
                            ..Default::default()
                        });
                    }
                }
                Token::Arg(ArgKind::BgpInstanceName) => {
                    for name in (self.instance_name_source)() {
                        if name.starts_with(partial) && !suggestions.iter().any(|s| s.value == name)
                        {
                            suggestions.push(Suggestion {
                                value: name,
                                description: None,
                                span: Span::new(partial_start, line.len()),
                                append_whitespace: true,
                                ..Default::default()
                            });
                        }
                    }
                }
                Token::Arg(ArgKind::BgpPeerGroupName) => {
                    for name in (self.peer_group_name_source)() {
                        if name.starts_with(partial) && !suggestions.iter().any(|s| s.value == name)
                        {
                            suggestions.push(Suggestion {
                                value: name,
                                description: None,
                                span: Span::new(partial_start, line.len()),
                                append_whitespace: true,
                                ..Default::default()
                            });
                        }
                    }
                }
                Token::Arg(ArgKind::Plain) => {
                    // No way to complete an arbitrary value.
                }
            }
        }

        CompletionResult::fresh(suggestions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_source() -> Box<dyn FnMut(Topic) -> CommandDoc + Send> {
        Box::new(|topic| CommandDoc {
            topic,
            summary: format!("summary for {topic:?}"),
            detail: format!("detail for {topic:?}"),
        })
    }

    fn no_instances() -> Box<dyn FnMut() -> Vec<String> + Send> {
        Box::new(Vec::new)
    }

    fn no_peer_groups() -> Box<dyn FnMut() -> Vec<String> + Send> {
        Box::new(Vec::new)
    }

    fn values(result: &CompletionResult) -> Vec<String> {
        let mut v: Vec<String> = result
            .suggestions()
            .iter()
            .map(|s| s.value.clone())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn completes_top_level_keyword_in_operational_mode() {
        let mut completer = NosCompleter::new(
            Mode::Operational,
            doc_source(),
            no_instances(),
            no_peer_groups(),
        );
        let result = completer.complete("sh", 2);
        assert_eq!(values(&result), vec!["show".to_string()]);
    }

    #[test]
    fn hides_configuration_only_keywords_in_operational_mode() {
        let mut completer = NosCompleter::new(
            Mode::Operational,
            doc_source(),
            no_instances(),
            no_peer_groups(),
        );
        let result = completer.complete("com", 3);
        assert!(
            values(&result).is_empty(),
            "commit should not appear outside configuration mode"
        );
    }

    #[test]
    fn shows_configuration_only_keywords_in_configuration_mode() {
        let mode = Mode::Configuration {
            transaction: "t1".to_string(),
            path: crate::session::Path::Root,
            dirty: false,
        };
        let mut completer = NosCompleter::new(mode, doc_source(), no_instances(), no_peer_groups());
        let result = completer.complete("com", 3);
        assert_eq!(values(&result), vec!["commit".to_string()]);
    }

    #[test]
    fn completes_empty_buffer_with_top_level_keywords_only_operational() {
        let mut completer = NosCompleter::new(
            Mode::Operational,
            doc_source(),
            no_instances(),
            no_peer_groups(),
        );
        let result = completer.complete("", 0);
        let vals = values(&result);
        assert!(vals.contains(&"show".to_string()));
        assert!(vals.contains(&"save".to_string()));
        assert!(!vals.contains(&"commit".to_string()));
    }

    #[test]
    fn completes_bgp_instance_name_from_injected_source() {
        let mode = Mode::Configuration {
            transaction: "t1".to_string(),
            path: crate::session::Path::Root,
            dirty: false,
        };
        let names: Box<dyn FnMut() -> Vec<String> + Send> =
            Box::new(|| vec!["r1".to_string(), "r2".to_string(), "other".to_string()]);
        let mut completer = NosCompleter::new(mode, doc_source(), names, no_peer_groups());
        let result = completer.complete("edit bgp instance r", 19);
        assert_eq!(values(&result), vec!["r1".to_string(), "r2".to_string()]);
    }

    #[test]
    fn completes_bgp_peer_group_name_from_injected_source() {
        let mode = Mode::Configuration {
            transaction: "t1".to_string(),
            path: crate::session::Path::BgpInstance("r1".to_string()),
            dirty: false,
        };
        let groups: Box<dyn FnMut() -> Vec<String> + Send> =
            Box::new(|| vec!["pg1".to_string(), "pg2".to_string(), "other".to_string()]);
        let mut completer = NosCompleter::new(mode, doc_source(), no_instances(), groups);
        let result = completer.complete("edit peer-group p", 17);
        assert_eq!(values(&result), vec!["pg1".to_string(), "pg2".to_string()]);
    }

    #[test]
    fn extra_carries_usage_and_detail_for_help_menu() {
        let mut completer = NosCompleter::new(
            Mode::Operational,
            doc_source(),
            no_instances(),
            no_peer_groups(),
        );
        let result = completer.complete("show conf", 9);
        let suggestion = result
            .suggestions()
            .iter()
            .find(|s| s.value == "config")
            .expect("expected a 'config' suggestion");
        let extra = suggestion
            .extra
            .as_ref()
            .expect("expected usage+detail in extra");
        assert_eq!(extra[0], "show config");
        assert!(extra[1].contains("ShowRunningConfig"));
    }

    #[test]
    fn description_comes_from_injected_doc_source() {
        let mut completer = NosCompleter::new(
            Mode::Operational,
            doc_source(),
            no_instances(),
            no_peer_groups(),
        );
        let result = completer.complete("show config", 11);
        // Not a completion candidate (already fully typed) — use a partial instead.
        let result = if result.suggestions().is_empty() {
            completer.complete("show conf", 9)
        } else {
            result
        };
        let suggestion = result
            .suggestions()
            .iter()
            .find(|s| s.value == "config")
            .expect("expected a 'config' suggestion");
        assert!(suggestion
            .description
            .as_deref()
            .unwrap()
            .contains("ShowRunningConfig"));
    }
}
