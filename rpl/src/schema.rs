//! The fixed table of fields a policy script can read/write through `this`.
//! This is the one place a future capability (`this.static.*`,
//! `this.bgp.communities`) gets added — purely additive, no grammar/AST
//! change needed elsewhere. v1 has exactly one capability (`bgp`) plus the
//! always-present `prefix`, and both of `nos-rpl`'s attach points (BGP
//! import/export) guarantee the same set, so there's no per-attach-point
//! variation to model yet — see root `CLAUDE.md`'s "Explicitly out of
//! scope" for why a genuinely optional capability isn't built now.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    Prefix,
    BgpOrigin,
    BgpAsPath,
    BgpLocalPref,
    BgpMed,
    BgpNextHop,
    BgpLearnedViaIbgp,
    BgpRouterId,
    BgpOriginatorId,
    BgpClusterList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Int,
    Bool,
    Prefix,
    OptionalIp,
    OptionalInt,
    Enum(&'static str),
    ListInt,
    ListIp,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldInfo {
    pub id: FieldId,
    pub ty: FieldType,
    pub mutable: bool,
}

/// Every valid field path off `this`, keyed by its dotted segments (without
/// the leading `this`). `this.prefix` is `&["prefix"]`; `this.bgp.local_pref`
/// is `&["bgp", "local_pref"]`.
const FIELDS: &[(&[&str], FieldInfo)] = &[
    (
        &["prefix"],
        FieldInfo {
            id: FieldId::Prefix,
            ty: FieldType::Prefix,
            mutable: false,
        },
    ),
    (
        &["bgp", "origin"],
        FieldInfo {
            id: FieldId::BgpOrigin,
            ty: FieldType::Enum("origin"),
            mutable: false,
        },
    ),
    (
        &["bgp", "as_path"],
        FieldInfo {
            id: FieldId::BgpAsPath,
            ty: FieldType::ListInt,
            mutable: false,
        },
    ),
    (
        &["bgp", "local_pref"],
        FieldInfo {
            id: FieldId::BgpLocalPref,
            ty: FieldType::Int,
            mutable: true,
        },
    ),
    (
        &["bgp", "med"],
        FieldInfo {
            id: FieldId::BgpMed,
            ty: FieldType::OptionalInt,
            mutable: true,
        },
    ),
    (
        &["bgp", "next_hop"],
        FieldInfo {
            id: FieldId::BgpNextHop,
            ty: FieldType::OptionalIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "learned_via_ibgp"],
        FieldInfo {
            id: FieldId::BgpLearnedViaIbgp,
            ty: FieldType::Bool,
            mutable: false,
        },
    ),
    (
        &["bgp", "router_id"],
        FieldInfo {
            id: FieldId::BgpRouterId,
            ty: FieldType::OptionalIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "originator_id"],
        FieldInfo {
            id: FieldId::BgpOriginatorId,
            ty: FieldType::OptionalIp,
            mutable: false,
        },
    ),
    (
        &["bgp", "cluster_list"],
        FieldInfo {
            id: FieldId::BgpClusterList,
            ty: FieldType::ListIp,
            mutable: false,
        },
    ),
];

/// Looks up the longest field path that is a prefix of `segments`, returning
/// the matched field plus how many leading segments it consumed. The
/// remaining (unconsumed) segments, if any, are a suffix operation
/// (`.length`/`.contains(..)`) for `check.rs` to resolve separately.
pub fn resolve_field(segments: &[String]) -> Option<(&'static FieldInfo, usize)> {
    FIELDS
        .iter()
        .filter(|(path, _)| {
            path.len() <= segments.len() && path.iter().zip(segments.iter()).all(|(p, s)| p == s)
        })
        .map(|(path, info)| (info, path.len()))
        .max_by_key(|(_, len)| *len)
}
