use nos_proto::{CommandDoc, Topic};

/// The documentation `nos-config` serves in reply to `Request::Describe`.
/// This is the authoritative explanation of what an operation does — every
/// client shows this same text instead of keeping its own copy. Scoped to
/// one topic at a time (see `nos_proto::docs::Topic`), so a client only
/// pays for the docs it actually displays.
pub fn command_doc(topic: Topic) -> CommandDoc {
    let (summary, detail): (&str, &str) = match topic {
        Topic::ShowRunningConfig => (
            "Show the daemon's current running configuration.",
            "Returns the config that is actually in effect right now — the last one \
             successfully committed (via a transaction) or loaded from disk at startup. \
             This is unaffected by any in-progress, uncommitted transaction.",
        ),
        Topic::Save => (
            "Persist the running configuration to disk.",
            "Writes the current running config to the daemon's configured config file path \
             so it survives a daemon restart. Has no effect on any in-progress transaction, \
             and does not itself change what's running — only a committed transaction does \
             that.",
        ),
        Topic::OpenTransaction => (
            "Open or resume a named, server-held in-progress configuration.",
            "Creates a new named transaction — starting from either a blank config or a \
             clone of the current running config — or, if a transaction with that name \
             already exists, resumes its current in-progress state unchanged. Transactions \
             live entirely on the daemon, so they survive a client disconnecting and can be \
             resumed later from any connection.",
        ),
        Topic::GetTransaction => (
            "Show a named transaction's current in-progress configuration.",
            "Returns the full in-progress config held by a named transaction, including any \
             uncommitted edits applied so far. This never touches or reflects the running \
             config directly.",
        ),
        Topic::CommitTransaction => (
            "Validate and commit a named transaction.",
            "Validates the transaction's in-progress config; if valid, atomically replaces \
             the running config with it, broadcasts the change to every subscribed client, \
             and deletes the transaction. If validation fails, the transaction is left open, \
             unchanged, so it can be fixed and retried.",
        ),
        Topic::DiscardTransaction => (
            "Delete a named transaction without touching the running config.",
            "Permanently deletes the transaction's in-progress state from the daemon. The \
             running config is never affected by a discard — only a successful commit \
             changes it.",
        ),
        Topic::DiffTransaction => (
            "Show what a transaction changes relative to the running config.",
            "Compares the transaction's in-progress config against the current running \
             config and returns only what differs: fields added, removed, or changed. \
             Runs no validation — an invalid in-progress config can still be diffed.",
        ),
        Topic::EnsureBgpInstance => (
            "Create a BGP instance in the transaction if it doesn't already exist.",
            "Adds a new BGP instance with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the instance.",
        ),
        Topic::SetBgpInstanceAsn => (
            "Set a BGP instance's autonomous system number.",
            "Sets the ASN field on a BGP instance in the transaction's in-progress config. \
             Must be a valid, non-reserved 32-bit ASN; validity is checked at commit time, \
             not when the edit is applied.",
        ),
        Topic::SetBgpInstanceRouterId => (
            "Set a BGP instance's router ID.",
            "Sets the router-id field on a BGP instance in the transaction's in-progress \
             config. A router ID is a 32-bit identifier written in dotted-quad notation — \
             the same notation an IPv4 address uses, but it is not itself a routable \
             address and need not correspond to one. Validity is checked at commit time, \
             not when the edit is applied.",
        ),
        Topic::DeleteBgpInstance => (
            "Delete a BGP instance from the transaction.",
            "Removes a BGP instance and all of its fields from the transaction's \
             in-progress config. Only affects that transaction — the running config is \
             untouched until commit.",
        ),
        Topic::SetHostname => (
            "Set the configuration's hostname.",
            "Sets the top-level hostname field in the transaction's in-progress config. \
             Unlike BGP instance fields, hostname has no navigation context — it's a single \
             top-level scalar.",
        ),
        Topic::EnsureBgpPeerGroup => (
            "Create a peer-group in a BGP instance if it doesn't already exist.",
            "Adds a new peer-group with the given name to the named BGP instance's \
             peer-groups in the transaction's in-progress config, if none exists with that \
             name yet; if one already exists, this is a no-op. Does not itself set any \
             fields on the peer-group.",
        ),
        Topic::SetBgpPeerGroupRemoteAs => (
            "Set a peer-group's remote autonomous system number.",
            "Sets the remote-as field on a peer-group. Must be a valid, non-reserved 32-bit \
             ASN; validity is checked at commit time, not when the edit is applied.",
        ),
        Topic::SetBgpPeerGroupSourceAddress => (
            "Set a peer-group's transport source address.",
            "Sets the source-address field on a peer-group — referenced by interface name \
             (plus an optional label, for an interface with more than one address) rather \
             than a literal address, resolved by nos-bgpd at runtime. `source-address \
             loopback` refers to this instance's own loopback interface \
             (loopback-<routing-table>) without needing to spell out its name. This is \
             independent of which address families the group exchanges: the resolved \
             source address's family may still differ from an advertised address family \
             (RFC 8950 extended next-hop encoding), so source-address and address-family \
             are never cross-validated against each other.",
        ),
        Topic::ClearBgpPeerGroupSourceAddress => (
            "Clear a peer-group's transport source address.",
            "Unsets the source-address field on a peer-group, reverting to no explicit \
             transport source override.",
        ),
        Topic::AddBgpPeerGroupAddressFamily => (
            "Add an address family to a peer-group.",
            "Adds one AFI/SAFI (ipv4 or ipv6 unicast) to the set exchanged over this \
             peer-group's session. A no-op if it's already present. At least one address \
             family is required for the peer-group to be valid; checked at commit time.",
        ),
        Topic::RemoveBgpPeerGroupAddressFamily => (
            "Remove an address family from a peer-group.",
            "Removes one AFI/SAFI from the set exchanged over this peer-group's session. A \
             no-op if it's already absent. Removing the last remaining address family \
             leaves the peer-group invalid until another is added; checked at commit time.",
        ),
        Topic::DeleteBgpPeerGroup => (
            "Delete a peer-group from a BGP instance.",
            "Removes a peer-group and all of its fields from the named BGP instance in the \
             transaction's in-progress config. Any peer still referencing this peer-group \
             becomes invalid — checked at commit time, not when the peer-group is deleted.",
        ),
        Topic::SetBgpPeer => (
            "Associate a remote address with a peer-group.",
            "Creates the association between a remote address and a peer-group within a \
             BGP instance if it doesn't exist yet, or repoints it to a different peer-group \
             if it does. The referenced peer-group must exist for the config to be valid; \
             checked at commit time.",
        ),
        Topic::DeleteBgpPeer => (
            "Remove a peer's association to its peer-group.",
            "Deletes the remote-address-to-peer-group association from the named BGP \
             instance in the transaction's in-progress config.",
        ),
        Topic::EnsureRoutingTable => (
            "Create a routing table in the transaction if it doesn't already exist.",
            "Adds a new routing table with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself associate a BGP instance or a static routing instance.",
        ),
        Topic::SetRoutingTableBgpInstance => (
            "Associate a BGP instance with a routing table.",
            "Points a routing table at a BGP instance by name. The instance must exist, and \
             a given instance may be associated with at most one routing table at a time; \
             both are checked at commit time, not when the edit is applied.",
        ),
        Topic::ClearRoutingTableBgpInstance => (
            "Remove a routing table's BGP instance association.",
            "Unsets the bgp-instance field on a routing table, reverting to no explicit \
             association.",
        ),
        Topic::SetRoutingTableStaticRoutingInstance => (
            "Associate a static routing instance with a routing table.",
            "Points a routing table at a static routing instance by name. The instance must \
             exist, and a given static routing instance may be associated with at most one \
             routing table at a time; both are checked at commit time, not when the edit is \
             applied.",
        ),
        Topic::ClearRoutingTableStaticRoutingInstance => (
            "Remove a routing table's static routing instance association.",
            "Unsets the static-routing-instance field on a routing table, reverting to no \
             explicit association.",
        ),
        Topic::SetRoutingTableRedistribute => (
            "Redistribute this table's static routes into its associated BGP instance.",
            "Sets the redistribute field on a routing table (currently only 'from static to \
             bgp' is supported). Both bgp-instance and static-routing-instance must already be \
             set on the table for the rule to be valid — checked at commit time, not when the \
             rule is set. An optional trailing 'policy <name>' clause names an RPL policy (or \
             accept-all/deny-all) to filter redistributed routes through before they reach BGP; \
             omitted, redistribution stays unfiltered (accept-all), unlike a peer-group's \
             import-policy/export-policy, which default to deny-all.",
        ),
        Topic::ClearRoutingTableRedistribute => (
            "Clear this table's redistribution rule.",
            "Unsets the redistribute field on a routing table, reverting to no redistribution.",
        ),
        Topic::DeleteRoutingTable => (
            "Delete a routing table from the transaction.",
            "Removes a routing table from the transaction's in-progress config. This only \
             clears the table's own associations — it does not delete the BGP instance or \
             static routing instance it referenced.",
        ),
        Topic::EnsureStaticRoutingInstance => (
            "Create a static routing instance in the transaction if it doesn't already exist.",
            "Adds a new static routing instance with the given name to the transaction's \
             in-progress config if none exists with that name yet; if one already exists, \
             this is a no-op. A static routing instance carries no reference to any routing \
             table — only a routing table's static-routing-instance field names it.",
        ),
        Topic::DeleteStaticRoutingInstance => (
            "Delete a static routing instance from the transaction.",
            "Removes a static routing instance and all of its routes from the transaction's \
             in-progress config. Any routing table still referencing it by name becomes \
             invalid — checked at commit time, not when the static routing instance is \
             deleted.",
        ),
        Topic::SetStaticRoute => (
            "Add or repoint a static route.",
            "Creates a route for the given subnet within a static routing instance if it \
             doesn't exist, or repoints its gateway if it does. The gateway's address family \
             must match the subnet's, and a subnet must not repeat within the same instance; \
             both are checked at commit time. Only one gateway per subnet is supported — \
             ECMP is not modeled in this iteration.",
        ),
        Topic::DeleteStaticRoute => (
            "Remove a static route.",
            "Deletes the route for the given subnet from the named static routing instance \
             in the transaction's in-progress config.",
        ),
        Topic::EnsureInterface => (
            "Create an interface in the transaction if it doesn't already exist.",
            "Adds a new interface with the given name to the transaction's in-progress config \
             if none exists with that name yet; if one already exists, this is a no-op. Does \
             not itself set any addresses or a routing table.",
        ),
        Topic::AddInterfaceAddress => (
            "Add an IP address to an interface.",
            "Adds an address to the interface's address list if it isn't already present — a \
             no-op if it is. An interface may carry any number of addresses, including a mix \
             of IPv4 and IPv6; a given address must not repeat on the same interface, checked \
             at commit time.",
        ),
        Topic::RemoveInterfaceAddress => (
            "Remove an IP address from an interface.",
            "Removes an address from the interface's address list in the transaction's \
             in-progress config.",
        ),
        Topic::SetInterfaceRoutingTable => (
            "Associate a routing table with an interface.",
            "Points an interface at a routing table by name — the routing table doubles as \
             the interface's VRF assignment. The routing table must exist, checked at commit \
             time; unlike a routing table's own bgp-instance/static-routing-instance \
             associations, more than one interface may be associated with the same routing \
             table.",
        ),
        Topic::ClearInterfaceRoutingTable => (
            "Remove an interface's routing table association.",
            "Unsets the routing-table field on an interface, reverting to no explicit \
             association.",
        ),
        Topic::DeleteInterface => (
            "Delete an interface from the transaction.",
            "Removes an interface and all of its addresses from the transaction's in-progress \
             config. This only clears the interface's own configuration — it does not delete \
             the routing table it referenced.",
        ),
        Topic::SetBgpPeerGroupHoldTime => (
            "Set a peer-group's BGP hold-time.",
            "Sets the hold-time field on a peer-group — the value this router proposes in its \
             OPEN message. A value of 0 disables both the hold timer and keepalives entirely; \
             otherwise it must be at least 3 seconds (RFC 4271 §6.2). The value actually used \
             by a session is the lower of this and the peer's own proposed hold time. When \
             both hold-time and keepalive-interval are set, keepalive-interval must be less \
             than hold-time — checked at commit time, not when the edit is applied.",
        ),
        Topic::ClearBgpPeerGroupHoldTime => (
            "Clear a peer-group's BGP hold-time.",
            "Unsets the hold-time field on a peer-group, reverting to the default of 90 \
             seconds.",
        ),
        Topic::SetBgpPeerGroupKeepaliveInterval => (
            "Set a peer-group's BGP keepalive interval.",
            "Sets the keepalive-interval field on a peer-group — how often this router sends \
             KEEPALIVE messages on an established session. Must be strictly less than \
             hold-time whenever both are explicitly set (a hold-time of 0 disables keepalives \
             entirely, so no explicit keepalive-interval is valid alongside it); checked at \
             commit time, not when the edit is applied.",
        ),
        Topic::ClearBgpPeerGroupKeepaliveInterval => (
            "Clear a peer-group's BGP keepalive interval.",
            "Unsets the keepalive-interval field on a peer-group, reverting to the default of \
             one third of the negotiated hold time.",
        ),
        Topic::SetBgpPeerGroupConnectRetryTime => (
            "Set a peer-group's BGP connect-retry time.",
            "Sets the connect-retry-time field on a peer-group — how long this router waits \
             between outbound connection attempts to a peer in this group. Must be at least 1 \
             second; checked at commit time, not when the edit is applied.",
        ),
        Topic::ClearBgpPeerGroupConnectRetryTime => (
            "Clear a peer-group's BGP connect-retry time.",
            "Unsets the connect-retry-time field on a peer-group, reverting to the default of \
             120 seconds.",
        ),
        Topic::SetBgpPeerGroupMd5Auth => (
            "Set a peer-group's BGP MD5 password.",
            "Sets a single RFC 2385 TCP MD5 signature password on a peer-group's sessions, \
             replacing any TCP-AO keys that were set — the two mechanisms are mutually \
             exclusive, since the kernel accepts only one per socket. Stored clear-text, like \
             every other field in this config.",
        ),
        Topic::SetBgpPeerGroupAoKey => (
            "Set (or replace) one of a peer-group's TCP-AO keys.",
            "Adds one RFC 5925 TCP-AO key to a peer-group, identified by its send-id — adding a \
             key with a send-id that already exists replaces it in place. If the peer-group's \
             auth wasn't already TCP-AO (unset, or an MD5 password), this starts a fresh key \
             list containing just this key. Exactly one key across the whole list must be \
             marked current, and at most one may be marked rnext, for the peer-group to \
             validate at commit time — see set-bgp-peer-group-ao-current-key/rnext-key. Stored \
             clear-text, like every other field in this config.",
        ),
        Topic::RemoveBgpPeerGroupAoKey => (
            "Remove one of a peer-group's TCP-AO keys by send-id.",
            "Removes one TCP-AO key from a peer-group's key list by send-id; a no-op if the \
             peer-group's auth isn't TCP-AO or no key has that send-id. Does not clear the \
             peer-group's auth back to unset even if the list becomes empty — an empty TCP-AO \
             key list fails commit-time validation, so clear the auth explicitly instead if \
             that's the intent.",
        ),
        Topic::SetBgpPeerGroupAoCurrentKey => (
            "Mark one of a peer-group's TCP-AO keys as current.",
            "Marks the TCP-AO key with the given send-id as the current key — the one actively \
             signing outgoing segments — clearing that flag on every other key in the same \
             peer-group. Fails if the peer-group's auth isn't TCP-AO or no key has that \
             send-id.",
        ),
        Topic::SetBgpPeerGroupAoRnextKey => (
            "Mark one of a peer-group's TCP-AO keys as rnext.",
            "Marks the TCP-AO key with the given send-id as the rnext key — a hint requesting \
             the peer switch to it next, for key rotation without dropping the session — \
             clearing that flag on every other key in the same peer-group. Fails if the \
             peer-group's auth isn't TCP-AO or no key has that send-id.",
        ),
        Topic::ClearBgpPeerGroupAuth => (
            "Clear a peer-group's BGP session authentication.",
            "Unsets the auth field on a peer-group entirely, regardless of which mechanism \
             (MD5 password or TCP-AO keys) was set, reverting sessions to no transport \
             authentication.",
        ),
        Topic::SetBgpPeerGroupNextHop => (
            "Set a peer-group's advertised BGP next-hop mode.",
            "Sets the next-hop field on a peer-group to either 'self' (rewrite the NEXT_HOP \
             attribute to this router's own address on every advertisement — the standard \
             eBGP default) or 'unchanged' (preserve the next-hop the route already carries \
             — the standard iBGP default, avoiding the third-party-next-hop problem). \
             Overrides the mode this peer-group would otherwise default to based on whether \
             it's eBGP or iBGP (remote-as compared to the instance's own asn).",
        ),
        Topic::ClearBgpPeerGroupNextHop => (
            "Clear a peer-group's advertised BGP next-hop mode override.",
            "Unsets the next-hop field on a peer-group, reverting to the default: 'self' for \
             an eBGP peer-group, 'unchanged' for an iBGP one.",
        ),
        Topic::SetBgpPeerGroupRouteReflectorClient => (
            "Mark a peer-group as an RFC 4456 route-reflector client.",
            "Routes learned from any iBGP peer are reflected to this peer-group's sessions \
             (and routes learned from this peer-group are reflected to every other iBGP \
             peer), instead of being withheld by the usual iBGP split-horizon rule. Requires \
             an iBGP peer-group (remote-as equal to the instance's own asn) and is mutually \
             exclusive with route-server-client; both are checked at commit time.",
        ),
        Topic::ClearBgpPeerGroupRouteReflectorClient => (
            "Unmark a peer-group as a route-reflector client.",
            "Reverts this peer-group to the standard iBGP split-horizon rule: routes learned \
             from one iBGP peer are never re-advertised to another.",
        ),
        Topic::SetBgpPeerGroupRouteServerClient => (
            "Mark a peer-group as an RFC 7947 route-server client.",
            "This peer-group's own ASN is never prepended to AS_PATH when advertising to it, \
             and — via RFC 7911 ADD-PATH, if the peer negotiates it — it receives every other \
             route-server-client's path for a prefix, not just the one instance-wide elected \
             best path. Requires an eBGP peer-group (remote-as different from the instance's \
             own asn) and is mutually exclusive with route-reflector-client; both are checked \
             at commit time.",
        ),
        Topic::ClearBgpPeerGroupRouteServerClient => (
            "Unmark a peer-group as a route-server client.",
            "Reverts this peer-group to ordinary eBGP advertisement: the instance's own ASN \
             is prepended to AS_PATH as usual, and only the single elected best path is sent.",
        ),
        Topic::SetBgpInstanceClusterId => (
            "Set a BGP instance's RFC 4456 route-reflector cluster ID.",
            "Sets the cluster-id field on a BGP instance, written into the CLUSTER_LIST \
             attribute of every route this instance reflects. Only meaningful when at least \
             one peer-group has route-reflector-client set; multiple route reflectors serving \
             the same cluster should share the same cluster-id for correct loop detection.",
        ),
        Topic::ClearBgpInstanceClusterId => (
            "Clear a BGP instance's route-reflector cluster ID override.",
            "Unsets the cluster-id field, reverting to the default: this instance's own \
             router-id.",
        ),
        Topic::EnsureBroadcastDomain => (
            "Create a broadcast domain in the transaction if it doesn't already exist.",
            "Adds a new broadcast domain with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. A broadcast domain carries no fields beyond its name — only a switching \
             profile's members reference it.",
        ),
        Topic::DeleteBroadcastDomain => (
            "Delete a broadcast domain from the transaction.",
            "Removes a broadcast domain from the transaction's in-progress config. Any \
             switching profile still referencing it becomes invalid — checked at commit time, \
             not when the broadcast domain is deleted.",
        ),
        Topic::EnsureSwitchingProfile => (
            "Create a switching profile in the transaction if it doesn't already exist.",
            "Adds a new switching profile with the given name to the transaction's \
             in-progress config if none exists with that name yet; if one already exists, \
             this is a no-op. A switching profile is a trunk-style container — it maps \
             multiple broadcast domains to their dot1q tagging, added via a separate op.",
        ),
        Topic::AddSwitchingProfileMember => (
            "Add or retag a broadcast domain within a switching profile.",
            "Associates a broadcast domain with the given tag (a dot1q VLAN, or untagged) \
             within a switching profile — if the domain is already a member, its tag is \
             replaced. The referenced broadcast domain must exist, and no broadcast domain \
             may appear twice within the same profile; both are checked at commit time.",
        ),
        Topic::RemoveSwitchingProfileMember => (
            "Remove a broadcast domain from a switching profile.",
            "Removes the named broadcast domain's membership from the switching profile in \
             the transaction's in-progress config.",
        ),
        Topic::DeleteSwitchingProfile => (
            "Delete a switching profile from the transaction.",
            "Removes a switching profile and all of its broadcast-domain memberships from the \
             transaction's in-progress config.",
        ),
        Topic::SetInterfaceSwitchingProfile => (
            "Associate a switching profile with an interface.",
            "Points an interface at a switching profile by name, trunking it into one or more \
             broadcast domains. The switching profile must exist, checked at commit time. An \
             interface's routing-table and a switching profile with an untagged member are \
             mutually exclusive — the interface's physical link has only one master device — \
             also checked at commit time; a switching profile whose members are all tagged \
             (dot1q) never conflicts, since each is realized as its own independent \
             sub-interface.",
        ),
        Topic::ClearInterfaceSwitchingProfile => (
            "Remove an interface's switching-profile association.",
            "Unsets the switching-profile field on an interface, reverting to no explicit \
             association.",
        ),
    };
    CommandDoc {
        topic,
        summary: summary.to_string(),
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every topic a client might ever ask for, kept here (not in
    /// `nos-proto`) purely so this test can enumerate them — no client
    /// needs the full list, since `Request::Describe` is scoped to one
    /// topic at a time.
    const ALL_TOPICS: &[Topic] = &[
        Topic::ShowRunningConfig,
        Topic::Save,
        Topic::OpenTransaction,
        Topic::GetTransaction,
        Topic::CommitTransaction,
        Topic::DiscardTransaction,
        Topic::DiffTransaction,
        Topic::EnsureBgpInstance,
        Topic::SetBgpInstanceAsn,
        Topic::SetBgpInstanceRouterId,
        Topic::DeleteBgpInstance,
        Topic::SetHostname,
        Topic::EnsureBgpPeerGroup,
        Topic::SetBgpPeerGroupRemoteAs,
        Topic::SetBgpPeerGroupSourceAddress,
        Topic::ClearBgpPeerGroupSourceAddress,
        Topic::AddBgpPeerGroupAddressFamily,
        Topic::RemoveBgpPeerGroupAddressFamily,
        Topic::DeleteBgpPeerGroup,
        Topic::SetBgpPeer,
        Topic::DeleteBgpPeer,
        Topic::EnsureRoutingTable,
        Topic::SetRoutingTableBgpInstance,
        Topic::ClearRoutingTableBgpInstance,
        Topic::SetRoutingTableStaticRoutingInstance,
        Topic::ClearRoutingTableStaticRoutingInstance,
        Topic::SetRoutingTableRedistribute,
        Topic::ClearRoutingTableRedistribute,
        Topic::DeleteRoutingTable,
        Topic::EnsureStaticRoutingInstance,
        Topic::DeleteStaticRoutingInstance,
        Topic::SetStaticRoute,
        Topic::DeleteStaticRoute,
        Topic::EnsureInterface,
        Topic::AddInterfaceAddress,
        Topic::RemoveInterfaceAddress,
        Topic::SetInterfaceRoutingTable,
        Topic::ClearInterfaceRoutingTable,
        Topic::DeleteInterface,
        Topic::SetBgpPeerGroupHoldTime,
        Topic::ClearBgpPeerGroupHoldTime,
        Topic::SetBgpPeerGroupKeepaliveInterval,
        Topic::ClearBgpPeerGroupKeepaliveInterval,
        Topic::SetBgpPeerGroupConnectRetryTime,
        Topic::ClearBgpPeerGroupConnectRetryTime,
        Topic::SetBgpPeerGroupMd5Auth,
        Topic::SetBgpPeerGroupAoKey,
        Topic::RemoveBgpPeerGroupAoKey,
        Topic::SetBgpPeerGroupAoCurrentKey,
        Topic::SetBgpPeerGroupAoRnextKey,
        Topic::ClearBgpPeerGroupAuth,
        Topic::SetBgpPeerGroupNextHop,
        Topic::ClearBgpPeerGroupNextHop,
        Topic::SetBgpPeerGroupRouteReflectorClient,
        Topic::ClearBgpPeerGroupRouteReflectorClient,
        Topic::SetBgpPeerGroupRouteServerClient,
        Topic::ClearBgpPeerGroupRouteServerClient,
        Topic::SetBgpInstanceClusterId,
        Topic::ClearBgpInstanceClusterId,
        Topic::EnsureBroadcastDomain,
        Topic::DeleteBroadcastDomain,
        Topic::EnsureSwitchingProfile,
        Topic::AddSwitchingProfileMember,
        Topic::RemoveSwitchingProfileMember,
        Topic::DeleteSwitchingProfile,
        Topic::SetInterfaceSwitchingProfile,
        Topic::ClearInterfaceSwitchingProfile,
    ];

    #[test]
    fn every_topic_has_non_empty_doc() {
        for &topic in ALL_TOPICS {
            let doc = command_doc(topic);
            assert_eq!(doc.topic, topic);
            assert!(!doc.summary.is_empty(), "{topic:?} has empty summary");
            assert!(!doc.detail.is_empty(), "{topic:?} has empty detail");
        }
    }
}
