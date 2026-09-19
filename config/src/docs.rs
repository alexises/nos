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
            "Redistribute this table's static routes into its associated BGP or OSPF instance.",
            "Sets the redistribute field on a routing table ('from static to bgp' or 'from \
             static to ospf' — redistributing into OSPF makes this router a real RFC 2328 ASBR, \
             originating an AS-external-LSA per redistributed prefix). Both bgp-instance/\
             ospf-instance (matching the chosen target) and static-routing-instance must already \
             be set on the table for the rule to be valid — checked at commit time, not when the \
             rule is set. An optional trailing 'policy <name>' clause names an RPL policy (or \
             accept-all/deny-all) to filter redistributed routes through before they reach BGP/ \
             OSPF; omitted, redistribution stays unfiltered (accept-all), unlike a peer-group's \
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
             not itself set any addresses or a routing table. For a physical (non-loopback) \
             interface, L3 config lives on a subinterface addressed as '<name>.<tag>' — '.0' \
             for the untagged/native case, '.1'-'.4094' for a real 802.1q VLAN — rather than \
             directly on the interface; a loopback interface (name 'loopback-<table>') is the \
             one exception and keeps its addresses/routing-table flat, unchanged.",
        ),
        Topic::AddInterfaceAddress => (
            "Add an IP address to an interface.",
            "Adds an address to an interface's (or, for a physical interface, a subinterface's \
             — see 'edit interface') address list if it isn't already present — a no-op if it \
             is. Any number of addresses may be carried, including a mix of IPv4 and IPv6; a \
             given address must not repeat on the same interface/subinterface, checked at \
             commit time. Addressing a bare non-loopback interface name (no '.tag' suffix) \
             implicitly targets its tag-0 (untagged/native) subinterface.",
        ),
        Topic::RemoveInterfaceAddress => (
            "Remove an IP address from an interface.",
            "Removes an address from an interface's (or subinterface's) address list in the \
             transaction's in-progress config.",
        ),
        Topic::SetInterfaceRoutingTable => (
            "Associate a routing table with an interface.",
            "Points an interface — or, for a physical interface, one of its subinterfaces — at \
             a routing table by name, which doubles as its VRF assignment. The routing table \
             must exist, checked at commit time; unlike a routing table's own \
             bgp-instance/static-routing-instance associations, more than one \
             interface/subinterface may be associated with the same routing table. Addressing \
             a bare non-loopback interface name (no '.tag' suffix) implicitly targets its \
             tag-0 (untagged/native) subinterface.",
        ),
        Topic::ClearInterfaceRoutingTable => (
            "Remove an interface's routing table association.",
            "Unsets the routing-table field on an interface (or subinterface), reverting to no \
             explicit association.",
        ),
        Topic::SetInterfaceMtu => (
            "Set an interface's MTU.",
            "Sets the MTU (in bytes, 68-65535) on a physical or loopback interface — a \
             link-layer property of the interface itself, applying uniformly to every one of \
             its subinterfaces (a VLAN sub-link has no MTU of its own, unlike addresses/\
             routing-table). Always targets the physical interface even when navigated into one \
             of its subinterfaces.",
        ),
        Topic::ClearInterfaceMtu => (
            "Clear an interface's MTU.",
            "Unsets the mtu field on an interface, so `nos-interfaced` leaves whatever MTU the \
             kernel link already has untouched rather than forcing a default.",
        ),
        Topic::SetInterfaceLldpTransmit => (
            "Enable or disable LLDP transmit on an interface.",
            "`set` makes nos-lldpd periodically send IEEE 802.1AB LLDPDUs (chassis/port \
             identity, system name/description, capabilities) out this physical interface so \
             directly-connected neighbors can discover it; `delete` turns it off again, \
             sending a final shutdown LLDPDU so neighbors drop this system immediately. \
             Independent of lldp receive. Physical interfaces only — rejected on a loopback \
             at commit time.",
        ),
        Topic::SetInterfaceLldpReceive => (
            "Enable or disable LLDP receive on an interface.",
            "`set` makes nos-lldpd listen for neighbors' LLDPDUs on this physical interface \
             and record them, visible via `show lldp neighbors`; entries age out when their \
             advertised TTL lapses. `delete` turns it off and forgets this interface's \
             neighbors. Independent of lldp transmit. Physical interfaces only — rejected on \
             a loopback at commit time.",
        ),
        Topic::DeleteInterface => (
            "Delete an interface from the transaction.",
            "Removes an interface and all of its addresses/subinterfaces from the \
             transaction's in-progress config, or — when the name carries a '.tag' suffix — \
             just that one subinterface. This only clears the interface's own configuration — \
             it does not delete the routing table it referenced.",
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
             no-op. Does not itself set any addresses or a routing table — a switching \
             profile's members reference the domain for L2 membership, while its own \
             addresses/routing-table (set separately) make its bridge device an SVI (switch \
             virtual interface), a routed L3 attachment point for the domain as a whole.",
        ),
        Topic::DeleteBroadcastDomain => (
            "Delete a broadcast domain from the transaction.",
            "Removes a broadcast domain, along with any addresses/routing-table association it \
             carries, from the transaction's in-progress config. Any switching profile still \
             referencing it becomes invalid — checked at commit time, not when the broadcast \
             domain is deleted.",
        ),
        Topic::AddBroadcastDomainAddress => (
            "Add an IP address to a broadcast domain's SVI.",
            "Adds an address to a broadcast domain's own address list if it isn't already \
             present — a no-op if it is. Any number of addresses may be carried, including a \
             mix of IPv4 and IPv6; a given address must not repeat on the same domain, checked \
             at commit time. This addresses the domain's own bridge device (its SVI), not any \
             interface enslaved into it as an L2 member.",
        ),
        Topic::RemoveBroadcastDomainAddress => (
            "Remove an IP address from a broadcast domain's SVI.",
            "Removes an address from a broadcast domain's address list in the transaction's \
             in-progress config.",
        ),
        Topic::SetBroadcastDomainRoutingTable => (
            "Associate a routing table with a broadcast domain's SVI.",
            "Points a broadcast domain's own bridge device at a routing table by name, which \
             doubles as its VRF assignment. The routing table must exist, checked at commit \
             time; as with an interface, more than one broadcast domain (or interface) may be \
             associated with the same routing table.",
        ),
        Topic::ClearBroadcastDomainRoutingTable => (
            "Remove a broadcast domain's routing table association.",
            "Unsets the routing-table field on a broadcast domain, reverting to no explicit \
             association.",
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
             broadcast domains. The switching profile must exist, checked at commit time. A \
             tag claimed by one of the interface's own subinterfaces (an untagged/'.0' one \
             claims tag 0, a '.<n>' one claims tag n) and a tag claimed by a switching-profile \
             member (an untagged member claims tag 0, a dot1q member claims its tag) are \
             mutually exclusive on the same interface — each tag's link has only one master \
             device — checked at commit time.",
        ),
        Topic::ClearInterfaceSwitchingProfile => (
            "Remove an interface's switching-profile association.",
            "Unsets the switching-profile field on an interface, reverting to no explicit \
             association.",
        ),
        Topic::EnsurePortAggregate => (
            "Create a port aggregate in the transaction if it doesn't already exist.",
            "Adds a new Linux bonding device with the given name and mode to the transaction's \
             in-progress config if none exists with that name yet; if one already exists, this \
             is a no-op. An interface becomes a bonded member by pointing its own \
             port-aggregate field at this aggregate's name, the same way it points at a \
             switching profile for L2 trunking.",
        ),
        Topic::DeletePortAggregate => (
            "Delete a port aggregate from the transaction.",
            "Removes a port aggregate from the transaction's in-progress config. Any interface \
             still pointing at it as its port-aggregate becomes invalid — checked at commit \
             time, not when the aggregate is deleted.",
        ),
        Topic::SetPortAggregateMode => (
            "Set a port aggregate's bonding mode.",
            "Updates the mode field on the named port aggregate in the transaction's \
             in-progress config. The aggregate must already exist. `xor` enslaves every member \
             interface unconditionally, with no negotiation. `lacp` negotiates membership over \
             a real IEEE 802.1AX LACPDU exchange run by nos-lacpd — a member is only enslaved \
             once negotiation with the partner confirms it, and is released again if the \
             negotiation lapses.",
        ),
        Topic::SetPortAggregateLacpRate => (
            "Set how fast a port aggregate's LACP partner is asked to send LACPDUs.",
            "Updates the lacp-rate field on the named port aggregate in the transaction's \
             in-progress config. The aggregate must already exist. `slow` asks the partner for \
             an LACPDU every 30 seconds (a lost partner is noticed after 90); `fast` asks for one \
             every second (noticed after 3). Only meaningful for a `lacp`-mode aggregate. Each \
             end transmits at the rate the *other* end asks for, so both ends need `fast` for \
             fast detection in both directions.",
        ),
        Topic::SetInterfacePortAggregate => (
            "Associate an interface with a port aggregate as a bonded member.",
            "Points an interface at a port aggregate by name, making it a bonded member. The \
             port aggregate must exist, checked at commit time. A member interface must not \
             also carry a switching-profile association or any subinterfaces — like VRF/bridge \
             enslavement, bond enslavement claims the link's one Linux master device — checked \
             at commit time.",
        ),
        Topic::ClearInterfacePortAggregate => (
            "Remove an interface's port-aggregate association.",
            "Unsets the port-aggregate field on an interface, reverting to no explicit bonded \
             membership.",
        ),
        Topic::EnsureOspfInstance => (
            "Create an OSPF instance in the transaction if it doesn't already exist.",
            "Adds a new OSPF instance with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the instance.",
        ),
        Topic::SetOspfInstanceRouterId => (
            "Set an OSPF instance's router id.",
            "Updates the router-id field on the named OSPF instance in the transaction's \
             in-progress config. The instance must already exist.",
        ),
        Topic::DeleteOspfInstance => (
            "Delete an OSPF instance from the transaction.",
            "Removes the named OSPF instance from the transaction's in-progress config.",
        ),
        Topic::SetRoutingTableOspfInstance => (
            "Associate an OSPF instance with a routing table.",
            "Points a routing table at an OSPF instance by name (the VRF that instance \
             belongs to). The OSPF instance must exist, and at most one routing table may \
             claim a given instance at a time — both checked at commit time.",
        ),
        Topic::ClearRoutingTableOspfInstance => (
            "Remove a routing table's OSPF instance association.",
            "Unsets the ospf-instance field on a routing table, reverting to no explicit \
             association.",
        ),
        Topic::EnsureOspfArea => (
            "Create an OSPF area in the transaction if it doesn't already exist.",
            "Adds a new area with the given dotted-quad area id to the named OSPF instance's \
             area list if none exists with that id yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the area.",
        ),
        Topic::DeleteOspfArea => (
            "Delete an OSPF area from an instance.",
            "Removes the named area (and every profile nested under it) from the OSPF \
             instance's area list.",
        ),
        Topic::EnsureOspfProfile => (
            "Create an OSPF profile in the transaction if it doesn't already exist.",
            "Adds a new profile with the given name to the named area's profile list if none \
             exists with that name yet; if one already exists, this is a no-op. Profile names \
             are unique across the whole config, not just within their owning area, checked \
             at commit time.",
        ),
        Topic::DeleteOspfProfile => (
            "Delete an OSPF profile from an area.",
            "Removes the named profile from the area's profile list. Any interface, \
             subinterface, or broadcast domain still referencing it by name will fail \
             commit-time validation until repointed or cleared.",
        ),
        Topic::SetOspfProfileHelloInterval => (
            "Set an OSPF profile's Hello interval.",
            "Sets the hello-interval field on a profile — how often nos-ospfd sends Hello \
             packets on any link using it. When both hello-interval and dead-interval are set, \
             dead-interval must be strictly greater than hello-interval — checked at commit \
             time, not when the edit is applied.",
        ),
        Topic::ClearOspfProfileHelloInterval => (
            "Clear an OSPF profile's Hello interval.",
            "Unsets the hello-interval field on a profile, reverting to the default of 10 \
             seconds.",
        ),
        Topic::SetOspfProfileDeadInterval => (
            "Set an OSPF profile's router dead interval.",
            "Sets the dead-interval field on a profile — how long nos-ospfd waits without a \
             Hello from a neighbor before declaring it down. Must be strictly greater than \
             hello-interval whenever both are explicitly set — checked at commit time, not \
             when the edit is applied.",
        ),
        Topic::ClearOspfProfileDeadInterval => (
            "Clear an OSPF profile's router dead interval.",
            "Unsets the dead-interval field on a profile, reverting to the default of 40 \
             seconds.",
        ),
        Topic::SetOspfProfileCost => (
            "Set an OSPF profile's interface cost.",
            "Sets the cost field on a profile. This NOS has no SPF/LSDB yet, so this value has \
             no behavioral effect today — it's stored and validated (1-65535) as a \
             forward-declared placeholder for a future SPF phase.",
        ),
        Topic::ClearOspfProfileCost => (
            "Clear an OSPF profile's interface cost.",
            "Unsets the cost field on a profile. There is no default to revert to — the field \
             simply becomes unset again.",
        ),
        Topic::SetOspfProfilePriority => (
            "Set an OSPF profile's Router Priority.",
            "Sets the priority field on a profile — used by RFC 2328 §9.4 DR/BDR election on \
             a broadcast link (a priority of 0 makes a router ineligible to become DR/BDR); \
             sent on the wire, but functionally inert, on a point-to-point link.",
        ),
        Topic::ClearOspfProfilePriority => (
            "Clear an OSPF profile's Router Priority.",
            "Unsets the priority field on a profile, reverting to the default of 1.",
        ),
        Topic::SetOspfProfileMtu => (
            "Override the MTU OSPF believes this link has.",
            "Sets the mtu field on a profile — what this NOS advertises in the DBD packet's own \
             interface_mtu field and uses to size DBD pagination for every attach point using \
             this profile, independent of the interface's real kernel MTU (mirrors real OSPF \
             implementations' mtu-bytes-style override). Left unset, the attach point's real \
             interface MTU (queried from nos-interfaced) is used instead, falling back to 1500 \
             if unavailable.",
        ),
        Topic::ClearOspfProfileMtu => (
            "Clear an OSPF profile's MTU override.",
            "Unsets the mtu field on a profile, reverting to using the attach point's real \
             interface MTU.",
        ),
        Topic::SetOspfProfileNetworkType => (
            "Set an OSPF profile's network type.",
            "Sets the network-type field on a profile to point-to-point or broadcast, \
             overriding the default that would otherwise be derived from each attach point's \
             own kind (a subinterface defaults to point-to-point, a broadcast domain defaults \
             to broadcast). Never validated against the attach point's actual kind — this NOS \
             allows forcing either behavior on either kind of attach point, matching real OSPF.",
        ),
        Topic::ClearOspfProfileNetworkType => (
            "Clear an OSPF profile's network type override.",
            "Unsets the network-type field on a profile, reverting to the default derived \
             from each attach point's own kind.",
        ),
        Topic::SetOspfProfileSimpleAuth => (
            "Set an OSPF profile's simple password.",
            "Sets a single RFC 2328 Appendix D.2 plaintext password (up to 8 bytes) on a \
             profile's Hello/DBD/LSR/LSU/LSAck packets, replacing any crypto keys that were set \
             — the two mechanisms are mutually exclusive. Stored clear-text, like every other \
             field in this config.",
        ),
        Topic::SetOspfProfileCryptoKey => (
            "Set (or replace) one of an OSPF profile's cryptographic auth keys.",
            "Adds one RFC 2328 Appendix D.3 / RFC 5709 cryptographic auth key to a profile, \
             identified by its key-id and algorithm (md5, hmac-sha1, hmac-sha256, hmac-sha384, \
             or hmac-sha512) — adding a key with a key-id that already exists replaces it in \
             place. If the profile's auth wasn't already crypto (unset, or a simple password), \
             this starts a fresh key list containing just this key. Exactly one key across the \
             whole list must be marked current, for the profile to validate at commit time — \
             see set-ospf-profile-crypto-current-key. Stored clear-text, like every other field \
             in this config.",
        ),
        Topic::RemoveOspfProfileCryptoKey => (
            "Remove one of an OSPF profile's cryptographic auth keys by key-id.",
            "Removes one crypto key from a profile's key list by key-id; a no-op if the \
             profile's auth isn't crypto or no key has that key-id. Does not clear the \
             profile's auth back to unset even if the list becomes empty — an empty crypto key \
             list fails commit-time validation, so clear the auth explicitly instead if that's \
             the intent.",
        ),
        Topic::SetOspfProfileCryptoCurrentKey => (
            "Mark one of an OSPF profile's cryptographic auth keys as current.",
            "Marks the crypto key with the given key-id as the current key — the one actively \
             signing outgoing packets — clearing that flag on every other key in the same \
             profile. Every configured key, current or not, is still accepted on receive, \
             looked up by the wire's own key-id — this is what allows graceful key rotation. \
             Fails if the profile's auth isn't crypto or no key has that key-id.",
        ),
        Topic::ClearOspfProfileAuth => (
            "Clear an OSPF profile's authentication.",
            "Unsets the auth field on a profile entirely, regardless of which mechanism \
             (simple password or crypto keys) was set, reverting to RFC 2328 AuType 0 (no \
             authentication).",
        ),
        Topic::SetInterfaceOspfProfile => (
            "Associate an OSPF profile with an interface, subinterface, or broadcast domain.",
            "Points a loopback interface, a physical interface's subinterface, or a broadcast \
             domain's own SVI at an OSPF profile by name. The profile must exist, and the \
             same attach point must also have a routing-table set — OSPF has no meaning \
             without an L3/VRF context — both checked at commit time.",
        ),
        Topic::ClearInterfaceOspfProfile => (
            "Remove an OSPF profile association.",
            "Unsets the ospf field on an interface, subinterface, or broadcast domain, \
             reverting to no explicit association.",
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
        Topic::SetInterfaceMtu,
        Topic::ClearInterfaceMtu,
        Topic::SetInterfaceLldpTransmit,
        Topic::SetInterfaceLldpReceive,
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
        Topic::AddBroadcastDomainAddress,
        Topic::RemoveBroadcastDomainAddress,
        Topic::SetBroadcastDomainRoutingTable,
        Topic::ClearBroadcastDomainRoutingTable,
        Topic::EnsureSwitchingProfile,
        Topic::AddSwitchingProfileMember,
        Topic::RemoveSwitchingProfileMember,
        Topic::DeleteSwitchingProfile,
        Topic::SetInterfaceSwitchingProfile,
        Topic::ClearInterfaceSwitchingProfile,
        Topic::EnsurePortAggregate,
        Topic::DeletePortAggregate,
        Topic::SetPortAggregateMode,
        Topic::SetPortAggregateLacpRate,
        Topic::SetInterfacePortAggregate,
        Topic::ClearInterfacePortAggregate,
        Topic::EnsureOspfInstance,
        Topic::SetOspfInstanceRouterId,
        Topic::DeleteOspfInstance,
        Topic::SetRoutingTableOspfInstance,
        Topic::ClearRoutingTableOspfInstance,
        Topic::EnsureOspfArea,
        Topic::DeleteOspfArea,
        Topic::EnsureOspfProfile,
        Topic::DeleteOspfProfile,
        Topic::SetInterfaceOspfProfile,
        Topic::ClearInterfaceOspfProfile,
        Topic::SetOspfProfileHelloInterval,
        Topic::ClearOspfProfileHelloInterval,
        Topic::SetOspfProfileDeadInterval,
        Topic::ClearOspfProfileDeadInterval,
        Topic::SetOspfProfileCost,
        Topic::ClearOspfProfileCost,
        Topic::SetOspfProfilePriority,
        Topic::ClearOspfProfilePriority,
        Topic::SetOspfProfileMtu,
        Topic::ClearOspfProfileMtu,
        Topic::SetOspfProfileNetworkType,
        Topic::ClearOspfProfileNetworkType,
        Topic::SetOspfProfileSimpleAuth,
        Topic::SetOspfProfileCryptoKey,
        Topic::RemoveOspfProfileCryptoKey,
        Topic::SetOspfProfileCryptoCurrentKey,
        Topic::ClearOspfProfileAuth,
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
