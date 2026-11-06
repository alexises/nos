use ipnet::IpNet;

/// One `prefix-list` entry. `range: None` means exact match (this exact
/// prefix+length only); `Some((min, max))` means "contained within `cidr`,
/// with the candidate's own length in `[min, max]`" — deliberately different
/// from the existing `this.prefix in <cidr>` operator, which stays
/// containment/orlonger-based for a bare `cidr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixListEntry {
    /// Prefix to match.
    pub cidr: IpNet,
    /// Inclusive `(min, max)` bounds on the candidate's own prefix length; `None` means plain containment.
    pub range: Option<(u8, u8)>,
}

/// Compile-time lookup table for named `community-alias`/`community-group`/
/// `prefix-list` objects referenced by bare identifier from RPL source.
/// `nos-rpl` has zero NOS-internal dependencies, so the caller (`nos-proto`
/// at commit-time validation, `nos-bgp` at policy-cache resync) adapts its
/// own config types into this shape — same pattern as `Input`/`BgpInput`.
/// Group members are pre-flattened by the caller (an alias name resolved to
/// its parts, or an inline literal's own parts) — `nos-rpl` never resolves a
/// group member that is itself an alias name; groups are flat, not nested.
#[derive(Debug, Clone, Copy)]
pub struct Symbols<'a> {
    /// Named aliases: each a list of integer values.
    pub aliases: &'a [(&'a str, &'a [i64])],
    /// Named groups: each a list of flat integer lists (one per member).
    pub groups: &'a [(&'a str, &'a [&'a [i64]])],
    /// Named prefix lists.
    pub prefix_lists: &'a [(&'a str, &'a [PrefixListEntry])],
    /// Named as-path lists: each entry is one regex (see `Op::AsPathMatches`);
    /// a list matches if ANY entry does.
    pub as_path_lists: &'a [(&'a str, &'a [&'a str])],
    /// Stored policies callable with `call NAME`: `(name, RPL source)`.
    /// Sources, not compiled code: callees are inlined at codegen.
    pub policies: &'a [(&'a str, &'a str)],
}

impl Symbols<'_> {
    /// No aliases, groups or lists.
    pub const EMPTY: Symbols<'static> = Symbols {
        aliases: &[],
        groups: &[],
        prefix_lists: &[],
        as_path_lists: &[],
        policies: &[],
    };
}
