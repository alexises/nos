//! `show config` / `show this`, generated from the same tree that parses
//! `set` (#116): the config's JSON is walked field by field through
//! `cli::root()` and written back in the CLI's own words, so a field the
//! grammar can enter is a field the output can show — no renderer names one.
//!
//! Layout: an indented hierarchy, each line the words relative to its parent
//! (`ospf instance o1` / `  router-id 1.1.1.1`). Only what is configured is
//! written: a field equal to its struct's `Default` is left out, which is also
//! what makes the output replayable (`cli/tests/render.rs` flattens it to
//! absolute `set` lines and feeds the grammar).
//!
//! A field the generic words can't spell (a keyed list inside an `Option`,
//! `ao-key …`) declares its own lines with `#[cli(render = …)]`; a secret
//! (`#[cli(secret)]`) is written as `<hidden>`.

use serde_json::Value;

use super::{field_spellings, root, variant_spellings, Field, Kind, Payload};

/// The text standing in for a secret's value.
pub const HIDDEN: &str = "<hidden>";

/// One output line: its depth and its words.
pub type Line = (usize, String);

/// The whole config.
pub fn render_root(config: &Value) -> Vec<Line> {
    let node = root();
    let mut out = Vec::new();
    object(
        node.fields,
        node.default.map(|d| d()).as_ref(),
        config,
        0,
        &mut out,
    );
    out
}

/// The object at `path` (REST segments), headed by its own words
/// (`bgp instance r1`) — `None` if nothing is there.
pub fn render_at(config: &Value, path: &[String]) -> Option<Vec<Line>> {
    let mut node = root();
    let mut value = config;
    let mut header = None;
    let mut segs = path.iter();
    while let Some(seg) = segs.next() {
        let f = node.fields.iter().find(|f| segment(f) == *seg)?;
        value = value.get(f.name)?;
        match (f.kind)() {
            Kind::List(elem) => {
                let Kind::Struct(n) = elem() else { return None };
                let key = n.fields.iter().find(|k| k.key)?;
                let want = segs.next()?;
                value = value
                    .as_array()?
                    .iter()
                    .find(|e| words(&(key.kind)(), &e[key.name]).first() == Some(want))?;
                header = Some(format!("{} {want}", name(f)));
                node = n;
            }
            Kind::Struct(n) => {
                header = Some(name(f));
                node = n;
            }
            _ => return None,
        }
    }
    let mut out = Vec::new();
    let depth = usize::from(header.is_some());
    if let Some(h) = header {
        out.push((0, h));
    }
    object(
        node.fields,
        node.default.map(|d| d()).as_ref(),
        value,
        depth,
        &mut out,
    );
    Some(out)
}

/// The lines as text, two spaces per depth.
pub fn indent(lines: &[Line]) -> String {
    lines
        .iter()
        .map(|(d, l)| format!("{:1$}{l}", "", d * 2))
        .collect::<Vec<_>>()
        .join("\n")
}

fn segment(f: &Field) -> String {
    let is_list = matches!((f.kind)(), Kind::List(_));
    crate::config_path::field_segment(f.name, is_list)
}

/// The canonical spelling of a field.
pub fn name(f: &Field) -> String {
    field_spellings(f).swap_remove(0)
}

/// A field that is never written: derived state, or the list key (it is in
/// its element's header).
fn skipped(f: &Field) -> bool {
    f.hidden || f.key
}

fn object(
    fields: &[Field],
    default: Option<&Value>,
    obj: &Value,
    depth: usize,
    out: &mut Vec<Line>,
) {
    for f in fields.iter().filter(|f| !skipped(f)) {
        let v = &obj[f.name];
        let unset = match default {
            Some(d) => d.get(f.name) == Some(v),
            None => {
                v.is_null() || *v == Value::Bool(false) || v.as_array().is_some_and(Vec::is_empty)
            }
        };
        if !unset {
            field(f, v, depth, out);
        }
    }
}

fn push(out: &mut Vec<Line>, depth: usize, text: String) {
    out.push((depth, text));
}

fn field(f: &Field, v: &Value, depth: usize, out: &mut Vec<Line>) {
    if f.secret {
        return out.push((depth, format!("{} {HIDDEN}", name(f))));
    }
    if let Some(render) = f.render {
        return out.extend(render(v).into_iter().map(|l| (depth, l)));
    }
    let kind = unwrap_option((f.kind)());
    match &kind {
        Kind::List(elem) => match elem() {
            Kind::Struct(n) if n.fields.iter().any(|k| k.key) => {
                for e in v.as_array().into_iter().flatten() {
                    let key = n.fields.iter().find(|k| k.key).expect("checked above");
                    push(
                        out,
                        depth,
                        format!(
                            "{} {}",
                            name(f),
                            words(&(key.kind)(), &e[key.name]).join(" ")
                        ),
                    );
                    object(n.fields, n.default.map(|d| d()).as_ref(), e, depth + 1, out);
                }
            }
            elem => {
                for e in v.as_array().into_iter().flatten() {
                    push(out, depth, join(name(f), words(&elem, e)));
                }
            }
        },
        // A plain struct is a section; an optional one is set in one line.
        Kind::Struct(n) if matches!((f.kind)(), Kind::Struct(_)) => {
            let mut inner = Vec::new();
            object(
                n.fields,
                n.default.map(|d| d()).as_ref(),
                v,
                depth + 1,
                &mut inner,
            );
            if !inner.is_empty() {
                push(out, depth, name(f));
                out.extend(inner);
            }
        }
        // Text over several lines (a policy's source) is a block, not a word.
        Kind::Str if v.as_str().is_some_and(|s| s.contains('\n')) => {
            push(out, depth, name(f));
            for l in v.as_str().into_iter().flat_map(str::lines) {
                out.push((depth + 1, l.to_string()));
            }
        }
        kind => push(out, depth, join(name(f), words(kind, v))),
    }
}

fn join(head: String, words: Vec<String>) -> String {
    std::iter::once(head)
        .chain(words)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn unwrap_option(kind: Kind) -> Kind {
    match kind {
        Kind::Option(inner) => unwrap_option(inner()),
        k => k,
    }
}

/// The words that spell a value of `kind` (what `set <field> …` takes).
pub fn words(kind: &Kind, v: &Value) -> Vec<String> {
    match kind {
        Kind::Option(_) if v.is_null() => Vec::new(),
        Kind::Option(inner) => words(&inner(), v),
        Kind::Str | Kind::Ipv4 | Kind::IpAddr | Kind::IpNet => {
            vec![v.as_str().unwrap_or_default().to_string()]
        }
        Kind::Uint(_) => vec![v.to_string()],
        Kind::Tuple(parts) => parts
            .iter()
            .zip(v.as_array().into_iter().flatten())
            .flat_map(|(p, e)| words(&p(), e))
            .collect(),
        // A bool is its word alone; a list is never one value.
        Kind::Bool | Kind::List(_) => Vec::new(),
        Kind::Struct(n) => struct_words(n.fields, n.default.map(|d| d()).as_ref(), v),
        Kind::Enum(variants) => {
            let (tag, payload) = match v {
                Value::String(s) => (s.as_str(), &Value::Null),
                Value::Object(o) => o
                    .iter()
                    .next()
                    .map_or(("", &Value::Null), |(k, p)| (k.as_str(), p)),
                _ => return Vec::new(),
            };
            let Some(var) = variants.iter().find(|x| x.name == tag) else {
                return Vec::new();
            };
            let word = variant_spellings(var).swap_remove(0);
            let rest = match var.payload {
                Payload::Unit => Vec::new(),
                Payload::Newtype(k) => words(&k(), payload),
                Payload::Struct(fields) => struct_words(fields, None, payload),
            };
            std::iter::once(word).chain(rest).collect()
        }
    }
}

/// `first-required-field-bare key value key value …` — the inverse of the
/// grammar's `fields_value`. Without a `Default` to compare to (an enum
/// payload) every required field is written.
fn struct_words(fields: &[Field], default: Option<&Value>, obj: &Value) -> Vec<String> {
    let optional = |f: &Field| matches!((f.kind)(), Kind::Option(_) | Kind::List(_) | Kind::Bool);
    let bare = fields.iter().find(|f| !optional(f)).map(|f| f.name);
    let (mut first, mut out) = (Vec::new(), Vec::new());
    for f in fields.iter().filter(|f| !f.hidden) {
        let v = &obj[f.name];
        let kind = (f.kind)();
        let shown = Some(f.name) == bare
            || match default {
                Some(d) => d.get(f.name) != Some(v),
                None => !optional(f) || !(v.is_null() || *v == Value::Bool(false)),
            };
        if !shown {
            continue;
        }
        let value = if f.secret {
            vec![HIDDEN.to_string()]
        } else {
            words(&kind, v)
        };
        if Some(f.name) == bare {
            first = value;
        } else if !matches!(kind, Kind::List(_)) {
            out.push(name(f));
            out.extend(value);
        }
    }
    first.extend(out);
    first
}
