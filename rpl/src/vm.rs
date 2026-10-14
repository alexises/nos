use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::schema::FieldId;
use crate::symbols::PrefixListEntry;

/// One community value, tagged by kind so `Op::CommunityAdd`/`Remove`/
/// `ListContainsCommunity` know which of `Input`'s three community slices to
/// operate on without also carrying a redundant `FieldId` match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityValue {
    /// RFC 1997 standard community, packed `(AA << 16) | NN`.
    Standard(u32),
    /// RFC 4360 extended community, packed as its 8 raw wire bytes (one
    /// big-endian `u64`).
    Extended(u64),
    /// RFC 8092 large community: global admin, local data 1, local data 2.
    Large(u32, u32, u32),
}

/// Mirrors `nos_bgp::message::Origin`'s discriminants exactly (`Igp = 0`,
/// `Egp = 1`, `Incomplete = 2`) so `Value::Enum(u8)` round-trips without a
/// translation table. `nos-rpl` doesn't depend on `nos-bgp`, so this is its
/// own copy, not a shared type — see `Input`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// `IGP` (RFC 4271 ORIGIN 0).
    Igp = 0,
    /// `EGP` (RFC 4271 ORIGIN 1).
    Egp = 1,
    /// `INCOMPLETE` (RFC 4271 ORIGIN 2).
    Incomplete = 2,
}

/// RFC 6811 §2 origin validation state, `rpki.valid`/`rpki.invalid`/
/// `rpki.not_found` in a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationState {
    /// A covering VRP validates the origin AS.
    Valid = 0,
    /// A covering VRP exists but none matches.
    Invalid = 1,
    /// No covering VRP (the default).
    #[default]
    NotFound = 2,
}

/// A stack value of the interpreter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// Integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
    /// IP prefix.
    Prefix(IpNet),
    /// IP address.
    Ip(IpAddr),
    /// Enum variant discriminant (e.g. an [`Origin`]).
    Enum(u8),
}

/// Compiled as-path regexes, matched against the path rendered as
/// space-separated ASNs (`"65001 65002"`). `_` is the Cisco-style boundary
/// (start, end or a space), so `_65001_` matches the ASN 65001 anywhere.
#[derive(Debug, Clone)]
pub struct AsPathRegexes(Vec<regex::Regex>);

impl AsPathRegexes {
    /// Compiles each pattern; an invalid regex is the error string.
    pub fn new(patterns: &[&str]) -> Result<Self, String> {
        patterns
            .iter()
            .map(|p| {
                regex::Regex::new(&p.replace('_', "(?:^| |$)"))
                    .map_err(|e| format!("invalid as-path regex '{p}': {e}"))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    // ponytail: allocates the rendered path per evaluation, only for
    // scripts that use a regex; render lazily once per run if it shows up
    // in profiles.
    fn is_match(&self, as_path: &[u32]) -> bool {
        let text = as_path
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        self.0.iter().any(|re| re.is_match(&text))
    }
}

impl PartialEq for AsPathRegexes {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|(a, b)| a.as_str() == b.as_str())
    }
}
impl Eq for AsPathRegexes {}

/// One instruction. List-typed fields (`as_path`, `cluster_list`) are never
/// pushed onto the stack as a whole — `FieldLen`/`ListContains*` read
/// straight from the borrowed slice in `Input` and push only the scalar
/// result, so `Value` never needs a list variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Pushes a scalar field of the input.
    LoadField(FieldId),
    /// Pushes an integer constant.
    LoadConstInt(i64),
    /// Pushes a prefix constant.
    LoadConstPrefix(IpNet),
    /// Pushes an IP address constant.
    LoadConstIp(IpAddr),
    /// Pushes an enum discriminant constant.
    LoadConstEnum(u8),
    /// Pushes the length of a list field.
    FieldLen(FieldId),
    /// Pushes whether a list field contains the integer.
    ListContainsInt(FieldId, u32),
    /// Pushes whether a list field contains the IPv4 address.
    ListContainsIp(FieldId, Ipv4Addr),
    /// Pushes whether a community list contains the value.
    ListContainsCommunity(FieldId, CommunityValue),
    /// `this.bgp.as_path.matches(..)` / `this.bgp.as_path in LIST` — true if
    /// any regex matches the current path.
    AsPathMatches(AsPathRegexes),
    /// `this.bgp.as_path.prepend(asn, count)`.
    AsPathPrepend(u32, u8),
    /// `this.bgp.<field> == <ip literal>` on an optional-address field:
    /// false when the field is unset.
    OptIpEq(FieldId, IpAddr),
    /// Pops an `Enum` and sets `this.bgp.origin`.
    SetOrigin,
    /// Pops an `Ip` and sets `this.bgp.next_hop`.
    SetNextHop,
    /// `set this.bgp.next_hop = self`.
    SetNextHopSelf,
    /// Adds a community to a community-list field.
    CommunityAdd(FieldId, CommunityValue),
    /// Removes a community from a community-list field.
    CommunityRemove(FieldId, CommunityValue),
    /// Empties a community-list field.
    CommunityClear(FieldId),
    /// Pops two integers, pushes their sum.
    Add,
    /// Pops two integers, pushes their difference.
    Sub,
    /// Pops two values, pushes `==`.
    CmpEq,
    /// Pops two values, pushes `!=`.
    CmpNe,
    /// Pops two integers, pushes `<`.
    CmpLt,
    /// Pops two integers, pushes `<=`.
    CmpLe,
    /// Pops two integers, pushes `>`.
    CmpGt,
    /// Pops two integers, pushes `>=`.
    CmpGe,
    /// Pops a prefix literal and a prefix, pushes containment.
    PrefixIn,
    /// `this.prefix in SOME_PREFIX_LIST` — the entry list is resolved and
    /// compiled in at codegen time (not pushed as a runtime value), unlike
    /// `PrefixIn`'s plain-literal rhs. See `PrefixListEntry`'s doc comment
    /// for exact-vs-range matching.
    PrefixInList(Vec<PrefixListEntry>),
    /// Pops two booleans, pushes their conjunction.
    And,
    /// Pops two booleans, pushes their disjunction.
    Or,
    /// Pops a boolean, pushes its negation.
    Not,
    /// Pops a boolean; jumps to the instruction index when false.
    JumpIfFalse(usize),
    /// Jumps to the instruction index.
    Jump(usize),
    /// Pops a value and stores it in a mutable field.
    SetField(FieldId),
    /// Pops a signed delta and adds it (saturating) to a numeric field; an
    /// unset `med` counts as 0.
    AddField(FieldId),
    /// Ends evaluation accepting the route.
    Accept,
    /// Ends evaluation rejecting the route.
    Reject,
}

/// A compiled policy: bytecode plus the stack depth it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// The instructions.
    pub code: Vec<Op>,
    /// Maximum operand-stack depth any path reaches.
    pub max_stack_depth: usize,
}

impl CompiledPolicy {
    /// Whether the script reads `this.bgp.validation_state` — only such a
    /// policy's verdict can change when the RPKI VRP set does.
    pub fn reads_validation_state(&self) -> bool {
        self.code
            .contains(&Op::LoadField(FieldId::BgpValidationState))
    }
}

/// The route data a policy script can see, adapted from whatever the caller's
/// own route type is — `nos-rpl` has zero knowledge of `RibRoute` or any
/// other NOS-internal type, so a consumer (e.g. `nos-bgp`) writes a plain
/// conversion function into this shape rather than `nos-rpl` depending on it.
pub struct Input<'a> {
    /// The route's prefix.
    pub prefix: IpNet,
    /// BGP path attributes.
    pub bgp: BgpInput<'a>,
}

/// The BGP attributes a policy can read.
pub struct BgpInput<'a> {
    /// ORIGIN (RFC 4271 §5.1.1).
    pub origin: Origin,
    /// `AS_PATH` as a flat ASN list (RFC 4271 §5.1.2).
    pub as_path: &'a [u32],
    /// `LOCAL_PREF` (RFC 4271 §5.1.5).
    pub local_pref: u32,
    /// `MULTI_EXIT_DISC`, if present (RFC 4271 §5.1.4).
    pub med: Option<u32>,
    /// `NEXT_HOP`, if known (RFC 4271 §5.1.3).
    pub next_hop: Option<IpAddr>,
    /// Whether the route was learned over IBGP.
    pub learned_via_ibgp: bool,
    /// BGP identifier of the advertising peer, if known.
    pub router_id: Option<Ipv4Addr>,
    /// `ORIGINATOR_ID` (RFC 4456 §8), if present.
    pub originator_id: Option<Ipv4Addr>,
    /// `CLUSTER_LIST` (RFC 4456 §8).
    pub cluster_list: &'a [Ipv4Addr],
    /// The neighbor this route is being imported from / exported to; `None`
    /// (and `peer_as == 0`, never a real ASN) for a locally-redistributed
    /// route, which has no neighbor.
    pub peer: Option<IpAddr>,
    /// AS number of that neighbor (0 for a locally-redistributed route).
    pub peer_as: u32,
    /// Standard communities (RFC 1997), raw `AA:NN` values.
    pub communities: &'a [u32],
    /// Extended communities (RFC 4360), raw 8-octet values.
    pub extended_communities: &'a [u64],
    /// Large communities (RFC 8092), `(global, local1, local2)`.
    pub large_communities: &'a [(u32, u32, u32)],
    /// RFC 6811 origin validation state.
    pub validation_state: ValidationState,
}

/// Attribute rewrites beyond the always-carried ones on `Verdict::Accept`.
/// Every field is "unchanged" by default so a policy that never touches it
/// costs nothing (no allocation, and the consumer keeps its shared `Arc`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Edits {
    /// The full replacement `AS_PATH`, only if the script prepended.
    pub as_path: Option<Vec<u32>>,
    /// Replacement ORIGIN, if the script set it.
    pub origin: Option<Origin>,
    /// What the script did to the next hop.
    pub next_hop: NextHopSet,
}

/// What a policy did to the route's next hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NextHopSet {
    /// The script did not touch the next hop.
    #[default]
    Unchanged,
    /// `set this.bgp.next_hop = self`.
    SelfAddress,
    /// `set this.bgp.next_hop = <ip>`.
    Addr(IpAddr),
}

/// The outcome of running a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The route is accepted, with its (possibly rewritten) attributes.
    Accept {
        /// Final `LOCAL_PREF`.
        local_pref: u32,
        /// Final MED.
        med: Option<u32>,
        /// Final standard communities.
        communities: Vec<u32>,
        /// Final extended communities.
        extended_communities: Vec<u64>,
        /// Final large communities.
        large_communities: Vec<(u32, u32, u32)>,
        /// Further rewrites (AS path, origin, next hop).
        edits: Edits,
    },
    /// The route is rejected.
    Reject,
}

/// Upper bound on a policy's compile-time-computed `max_stack_depth` —
/// `codegen::compile` refuses to produce a `CompiledPolicy` that would
/// exceed it. Policies have no calls and no loops, so real scripts sit at a
/// handful of stack slots; this is already generous headroom, chosen so
/// `run`'s stack can be a fixed-size array (zero heap allocation on the hot
/// path — this runs once per route, per peer, per update) rather than a
/// `Vec`.
pub const MAX_STACK_DEPTH: usize = 32;

/// Executes `policy` against `input`. `local_pref`/`med` start at `input`'s
/// own values and are only ever changed by a `SetField` the script actually
/// executes — reading `this.bgp.local_pref` after a `set` sees the updated
/// value, exactly like a normal imperative variable. The three community
/// slices follow the same pattern via `Cow`, the one deliberate exception to
/// this module's "zero heap allocation on the hot path" stack — a
/// `CommunityAdd`/`Remove`/`Clear` needs to hand back an owned `Vec` through
/// `Verdict`, but `Cow::to_mut()` only clones on a script's first actual
/// write, and `Reject` never pays for it at all.
pub fn run(policy: &CompiledPolicy, input: &Input) -> Verdict {
    let mut stack = [Value::Int(0); MAX_STACK_DEPTH];
    let mut sp = 0usize;
    let mut cur_local_pref = input.bgp.local_pref;
    let mut cur_med = input.bgp.med;
    let mut cur_communities: Cow<[u32]> = Cow::Borrowed(input.bgp.communities);
    let mut cur_extended_communities: Cow<[u64]> = Cow::Borrowed(input.bgp.extended_communities);
    let mut cur_large_communities: Cow<[(u32, u32, u32)]> =
        Cow::Borrowed(input.bgp.large_communities);
    let mut cur_as_path: Cow<[u32]> = Cow::Borrowed(input.bgp.as_path);
    let mut cur_origin = input.bgp.origin;
    let mut next_hop_edit = NextHopSet::Unchanged;
    let mut pc = 0usize;

    macro_rules! push {
        ($v:expr) => {{
            stack[sp] = $v;
            sp += 1;
        }};
    }
    macro_rules! pop {
        () => {{
            sp -= 1;
            stack[sp]
        }};
    }

    loop {
        match &policy.code[pc] {
            Op::LoadField(id) => {
                let v = match id {
                    FieldId::Prefix => Value::Prefix(input.prefix),
                    FieldId::BgpOrigin => Value::Enum(cur_origin as u8),
                    FieldId::BgpPeerAs => Value::Int(i64::from(input.bgp.peer_as)),
                    FieldId::BgpLocalPref => Value::Int(i64::from(cur_local_pref)),
                    FieldId::BgpLearnedViaIbgp => Value::Bool(input.bgp.learned_via_ibgp),
                    FieldId::BgpValidationState => Value::Enum(input.bgp.validation_state as u8),
                    _ => unreachable!("check.rs rejects LoadField for {id:?}"),
                };
                push!(v);
            }
            Op::LoadConstInt(n) => push!(Value::Int(*n)),
            Op::LoadConstPrefix(p) => push!(Value::Prefix(*p)),
            Op::LoadConstIp(a) => push!(Value::Ip(*a)),
            Op::LoadConstEnum(e) => push!(Value::Enum(*e)),
            Op::FieldLen(id) => {
                let n = match id {
                    FieldId::Prefix => i64::from(input.prefix.prefix_len()),
                    FieldId::BgpAsPath => len_as_int(cur_as_path.len()),
                    FieldId::BgpClusterList => len_as_int(input.bgp.cluster_list.len()),
                    FieldId::BgpCommunities => len_as_int(cur_communities.len()),
                    FieldId::BgpExtCommunities => len_as_int(cur_extended_communities.len()),
                    FieldId::BgpLargeCommunities => len_as_int(cur_large_communities.len()),
                    _ => unreachable!("check.rs rejects FieldLen for {id:?}"),
                };
                push!(Value::Int(n));
            }
            Op::ListContainsInt(id, n) => {
                let found = match id {
                    FieldId::BgpAsPath => cur_as_path.contains(n),
                    _ => unreachable!("check.rs rejects ListContainsInt for {id:?}"),
                };
                push!(Value::Bool(found));
            }
            Op::ListContainsIp(id, addr) => {
                let found = match id {
                    FieldId::BgpClusterList => input.bgp.cluster_list.contains(addr),
                    _ => unreachable!("check.rs rejects ListContainsIp for {id:?}"),
                };
                push!(Value::Bool(found));
            }
            Op::ListContainsCommunity(id, val) => {
                let found = match (id, val) {
                    (FieldId::BgpCommunities, CommunityValue::Standard(n)) => {
                        cur_communities.contains(n)
                    }
                    (FieldId::BgpExtCommunities, CommunityValue::Extended(n)) => {
                        cur_extended_communities.contains(n)
                    }
                    (FieldId::BgpLargeCommunities, CommunityValue::Large(ga, l1, l2)) => {
                        cur_large_communities.contains(&(*ga, *l1, *l2))
                    }
                    _ => unreachable!("codegen.rs pairs FieldId/CommunityValue consistently"),
                };
                push!(Value::Bool(found));
            }
            Op::AsPathMatches(re) => push!(Value::Bool(re.is_match(&cur_as_path))),
            Op::AsPathPrepend(asn, count) => {
                cur_as_path
                    .to_mut()
                    .splice(0..0, std::iter::repeat_n(*asn, usize::from(*count)));
            }
            Op::OptIpEq(id, ip) => {
                let cur = match id {
                    FieldId::BgpNextHop => match next_hop_edit {
                        NextHopSet::Addr(a) => Some(a),
                        NextHopSet::SelfAddress => None,
                        NextHopSet::Unchanged => input.bgp.next_hop,
                    },
                    FieldId::BgpPeer => input.bgp.peer,
                    FieldId::BgpRouterId => input.bgp.router_id.map(IpAddr::V4),
                    FieldId::BgpOriginatorId => input.bgp.originator_id.map(IpAddr::V4),
                    _ => unreachable!("codegen.rs only emits OptIpEq for optional-ip fields"),
                };
                push!(Value::Bool(cur == Some(*ip)));
            }
            Op::SetOrigin => {
                cur_origin = match pop!() {
                    Value::Enum(0) => Origin::Igp,
                    Value::Enum(1) => Origin::Egp,
                    _ => Origin::Incomplete,
                };
            }
            Op::SetNextHop => match pop!() {
                Value::Ip(a) => next_hop_edit = NextHopSet::Addr(a),
                other => unreachable!("codegen.rs guarantees an Ip here, got {other:?}"),
            },
            Op::SetNextHopSelf => next_hop_edit = NextHopSet::SelfAddress,
            Op::Add => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Int(a + b));
            }
            Op::Sub => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Int(a - b));
            }
            Op::CmpEq => {
                let b = pop!();
                let a = pop!();
                push!(Value::Bool(a == b));
            }
            Op::CmpNe => {
                let b = pop!();
                let a = pop!();
                push!(Value::Bool(a != b));
            }
            Op::CmpLt => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a < b));
            }
            Op::CmpLe => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a <= b));
            }
            Op::CmpGt => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a > b));
            }
            Op::CmpGe => {
                let b = as_int(pop!());
                let a = as_int(pop!());
                push!(Value::Bool(a >= b));
            }
            Op::PrefixIn => {
                let network = as_prefix(pop!());
                let candidate = as_prefix(pop!());
                push!(Value::Bool(network.contains(&candidate)));
            }
            Op::PrefixInList(entries) => {
                let candidate = as_prefix(pop!());
                let found = entries.iter().any(|entry| match entry.range {
                    None => candidate == entry.cidr,
                    Some((min, max)) => {
                        entry.cidr.contains(&candidate)
                            && (min..=max).contains(&candidate.prefix_len())
                    }
                });
                push!(Value::Bool(found));
            }
            Op::And => {
                let b = as_bool(pop!());
                let a = as_bool(pop!());
                push!(Value::Bool(a && b));
            }
            Op::Or => {
                let b = as_bool(pop!());
                let a = as_bool(pop!());
                push!(Value::Bool(a || b));
            }
            Op::Not => {
                let a = as_bool(pop!());
                push!(Value::Bool(!a));
            }
            Op::JumpIfFalse(target) => {
                if !as_bool(pop!()) {
                    pc = *target;
                    continue;
                }
            }
            Op::Jump(target) => {
                pc = *target;
                continue;
            }
            Op::SetField(id) => {
                let v = as_int(pop!());
                match id {
                    FieldId::BgpLocalPref => cur_local_pref = to_u32_saturating(v),
                    FieldId::BgpMed => cur_med = Some(to_u32_saturating(v)),
                    _ => unreachable!("check.rs rejects SetField for {id:?}"),
                }
            }
            Op::AddField(id) => {
                let d = as_int(pop!());
                match id {
                    FieldId::BgpLocalPref => {
                        cur_local_pref = to_u32_saturating(i64::from(cur_local_pref) + d);
                    }
                    FieldId::BgpMed => {
                        cur_med = Some(to_u32_saturating(i64::from(cur_med.unwrap_or(0)) + d));
                    }
                    _ => unreachable!("check.rs rejects AddField for {id:?}"),
                }
            }
            Op::CommunityAdd(id, val) => match (id, val) {
                (FieldId::BgpCommunities, CommunityValue::Standard(n)) => {
                    let list = cur_communities.to_mut();
                    if !list.contains(n) {
                        list.push(*n);
                    }
                }
                (FieldId::BgpExtCommunities, CommunityValue::Extended(n)) => {
                    let list = cur_extended_communities.to_mut();
                    if !list.contains(n) {
                        list.push(*n);
                    }
                }
                (FieldId::BgpLargeCommunities, CommunityValue::Large(ga, l1, l2)) => {
                    let list = cur_large_communities.to_mut();
                    let v = (*ga, *l1, *l2);
                    if !list.contains(&v) {
                        list.push(v);
                    }
                }
                _ => unreachable!("codegen.rs pairs FieldId/CommunityValue consistently"),
            },
            Op::CommunityRemove(id, val) => match (id, val) {
                (FieldId::BgpCommunities, CommunityValue::Standard(n)) => {
                    cur_communities.to_mut().retain(|c| c != n);
                }
                (FieldId::BgpExtCommunities, CommunityValue::Extended(n)) => {
                    cur_extended_communities.to_mut().retain(|c| c != n);
                }
                (FieldId::BgpLargeCommunities, CommunityValue::Large(ga, l1, l2)) => {
                    let v = (*ga, *l1, *l2);
                    cur_large_communities.to_mut().retain(|c| *c != v);
                }
                _ => unreachable!("codegen.rs pairs FieldId/CommunityValue consistently"),
            },
            Op::CommunityClear(id) => match id {
                FieldId::BgpCommunities => cur_communities.to_mut().clear(),
                FieldId::BgpExtCommunities => cur_extended_communities.to_mut().clear(),
                FieldId::BgpLargeCommunities => cur_large_communities.to_mut().clear(),
                _ => unreachable!("check.rs/codegen.rs reject CommunityClear for {id:?}"),
            },
            Op::Accept => {
                return Verdict::Accept {
                    local_pref: cur_local_pref,
                    med: cur_med,
                    communities: cur_communities.into_owned(),
                    extended_communities: cur_extended_communities.into_owned(),
                    large_communities: cur_large_communities.into_owned(),
                    edits: Edits {
                        as_path: match cur_as_path {
                            Cow::Owned(v) => Some(v),
                            Cow::Borrowed(_) => None,
                        },
                        origin: (cur_origin != input.bgp.origin).then_some(cur_origin),
                        next_hop: next_hop_edit,
                    },
                }
            }
            Op::Reject => return Verdict::Reject,
        }
        pc += 1;
    }
}

fn len_as_int(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// `set this.bgp.local_pref = <expr>` carries a runtime-computed `i64`, not
/// always a literal, so out-of-range values can't be rejected at compile
/// time — clamp instead of wrapping, since a wrapped negative-to-huge value
/// would be a far more surprising outcome for a route attribute than a
/// clamped one.
fn to_u32_saturating(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(if v.is_negative() { 0 } else { u32::MAX })
}

fn as_int(v: Value) -> i64 {
    match v {
        Value::Int(n) => n,
        other => unreachable!("codegen.rs guarantees an Int here, got {other:?}"),
    }
}

fn as_bool(v: Value) -> bool {
    match v {
        Value::Bool(b) => b,
        other => unreachable!("codegen.rs guarantees a Bool here, got {other:?}"),
    }
}

fn as_prefix(v: Value) -> IpNet {
    match v {
        Value::Prefix(p) => p,
        other => unreachable!("codegen.rs guarantees a Prefix here, got {other:?}"),
    }
}
