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
        Topic::Hostname => (
            "Set the configuration's hostname.",
            "Sets the top-level hostname field in the transaction's in-progress config. \
             Unlike BGP instance fields, hostname has no navigation context — it's a single \
             top-level scalar.",
        ),
        Topic::User => (
            "Create or delete a local user.",
            "A local user may log in to the shell and to the REST API; every user is a full administrator. `delete` removes the user, and any certificate already issued to them is refused on its next use. A commit that would leave no user at all is refused.",
        ),
        Topic::UserPassword => (
            "Set a local user's password.",
            "Given in clear text; nos-configd stores only its argon2id hash, and setting the same password again keeps the existing hash, so it is not a change.",
        ),
        Topic::Lldp => (
            "System-wide LLDP settings.",
            "The LLDP timers and management address every LLDP-enabled interface advertises with; per-interface transmit/receive and destination are set on the interface itself.",
        ),
        Topic::LldpTxInterval => (
            "Set the system-wide LLDP transmit interval.",
            "Sets msgTxInterval — seconds between periodic LLDPDUs (1-3600, default 30). \
             The TTL advertised to neighbors is tx-hold × tx-interval and must fit in 16 bits \
             (65535 seconds). Applies to every LLDP-enabled interface; changing it restarts \
             each link (a shutdown LLDPDU, then a fresh advertisement). `delete` restores the \
             default.",
        ),
        Topic::LldpTxHold => (
            "Set the system-wide LLDP transmit hold multiplier.",
            "Sets msgTxHold (1-100, default 4): the TTL advertised to neighbors is this × \
             tx-interval, so a neighbor tolerates that many missed advertisements. Applies to \
             every LLDP-enabled interface. `delete` restores the default.",
        ),
        Topic::LldpManagementAddress => (
            "Add an LLDP management address.",
            "Adds an IPv4 or IPv6 unicast address to advertise, each in its own Management \
             Address TLV of every LLDPDU this system sends (at most 4), so neighbors can show \
             how to reach it. An address on an interface is sent with that interface's \
             ifIndex; any other is still advertised as configured. `delete` stops advertising \
             one.",
        ),
        Topic::Logging => (
            "Log export settings.",
            "Where nos-logd sends every log entry besides keeping it for `show log`.",
        ),
        Topic::LoggingSyslog => (
            "Create or delete a remote syslog collector.",
            "Every log entry at or above the collector's level is sent to it as an RFC 5424 \
             message, in addition to being kept for `show log`. Entries are dropped, never \
             queued, while a collector is unreachable. `delete` stops exporting to it.",
        ),
        Topic::SyslogAddress => (
            "Set a syslog collector's address.",
            "The collector's IPv4 or IPv6 unicast address (a name is not resolved: there is no \
             resolver inside a VRF).",
        ),
        Topic::SyslogPort => (
            "Set a syslog collector's port.",
            "Destination port, 1-65535. `delete` restores the default: 514 for udp, 601 for tcp.",
        ),
        Topic::SyslogTransport => (
            "Set a syslog collector's transport.",
            "`udp` (RFC 5426, one message per datagram, truncated to 1180 octets), `tcp` \
             (RFC 6587 octet-counted frames on one connection, reconnected every second while \
             it is down) or `tls` (RFC 5425: the same frames inside post-quantum TLS 1.3; \
             needs `tls trust-anchor` or `tls fingerprint`, default port 6514). `delete` \
             restores udp.",
        ),
        Topic::SyslogRoutingTable => (
            "Send syslog from inside a routing table's VRF.",
            "Names an existing routing table: the socket is scoped into its VRF, so a \
             collector reachable only through that table can be used. `delete` uses the \
             default network namespace.",
        ),
        Topic::SyslogLevel => (
            "Set a syslog collector's minimum severity.",
            "Entries below this level are not sent: error, warn, info, debug or trace (debug \
             and trace both map to syslog severity 7). `delete` restores info.",
        ),
        Topic::SyslogFacility => (
            "Set a syslog collector's facility.",
            "The facility of every message sent to it, local0 to local7. `delete` restores \
             local7.",
        ),
        Topic::SyslogTls => (
            "Configure how a TLS syslog collector is authenticated.",
            "Needed by (and only valid with) transport `tls`: set exactly one of `trust-anchor` \
             and `fingerprint`. nos presents no client certificate. `delete` removes the \
             whole block.",
        ),
        Topic::SyslogTlsTrustAnchor => (
            "Trust the collector's certificate through a CA (RFC 5425 §4.2.1).",
            "PEM CA certificate(s) the collector's certificate must chain to; its name is \
             checked against `tls server-name`, or against its IP address SANs by default. \
             Exclusive with `fingerprint`.",
        ),
        Topic::SyslogTlsFingerprint => (
            "Trust one collector certificate by its SHA-256 fingerprint (RFC 5425 §4.2.2).",
            "`SHA-256:` followed by 32 colon-separated hex octets, the hash of the collector's \
             own certificate. Exclusive with `trust-anchor`.",
        ),
        Topic::SyslogTlsServerName => (
            "Set the DNS name the collector's certificate must carry.",
            "Default: the collector's address is matched against the certificate's IP address \
             SANs. Not checked with `fingerprint`. `delete` restores the default.",
        ),
        Topic::SyslogTlsAllowTls12 => (
            "Also allow TLS 1.2 with classical key exchange, for collectors that need RFC 9662.",
            "Also allows TLS 1.2 with classical (non-post-quantum) ECDHE-AES-GCM suites, for \
             collectors that cannot do the post-quantum TLS 1.3 key exchange. TLS 1.3 stays \
             post-quantum only, but traffic sent over TLS 1.2 can be recorded now and \
             decrypted by a future quantum computer. A collector that offers TLS 1.3 without \
             X25519MLKEM768 must have TLS 1.3 turned off on that listener. Turn it on only \
             while such a collector cannot be upgraded; `delete` turns it off.",
        ),
        Topic::BgpInstance => (
            "Create a BGP instance in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new BGP instance with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the instance.",
                " ",
                "Delete a BGP instance from the transaction.",
            ),
        ),
        Topic::BgpInstanceAsn => (
            "Set a BGP instance's autonomous system number.",
            "Sets the ASN field on a BGP instance in the transaction's in-progress config. \
             Must be a valid, non-reserved 32-bit ASN; validity is checked at commit time, \
             not when the edit is applied.",
        ),
        Topic::BgpInstanceRouterId => (
            "Set a BGP instance's router ID.",
            "Sets the router-id field on a BGP instance in the transaction's in-progress \
             config. A router ID is a 32-bit identifier written in dotted-quad notation — \
             the same notation an IPv4 address uses, but it is not itself a routable \
             address and need not correspond to one. Validity is checked at commit time, \
             not when the edit is applied.",
        ),
        Topic::BgpInstanceClusterId => (
            "Set a BGP instance's RFC 4456 route-reflector cluster ID.",
            concat!(
                "Sets the cluster-id field on a BGP instance, written into the CLUSTER_LIST \
             attribute of every route this instance reflects. Only meaningful when at least \
             one peer-group has route-reflector-client set; multiple route reflectors serving \
             the same cluster should share the same cluster-id for correct loop detection.",
                " ",
                "Clear a BGP instance's route-reflector cluster ID override.",
            ),
        ),
        Topic::BgpInstanceMaximumPaths => (
            "Set how many equal BGP paths a prefix installs (multipath).",
            concat!(
                "Installs the best path plus every path that ties with it on local-pref, \
             AS_PATH length, origin, MED, peer type and IGP cost to the next hop, and \
             comes from the same neighbouring AS, up to this many next hops (1-64), as \
             one equal-cost kernel route. Only the best path is advertised to peers.",
                " ",
                "Clear it to install the best path alone.",
            ),
        ),
        Topic::BgpPeerGroup => (
            "Create a peer-group in a BGP instance if it doesn't already exist.",
            concat!(
                "Adds a new peer-group with the given name to the named BGP instance's \
             peer-groups in the transaction's in-progress config, if none exists with that \
             name yet; if one already exists, this is a no-op. Does not itself set any \
             fields on the peer-group.",
                " ",
                "Delete a peer-group from a BGP instance.",
            ),
        ),
        Topic::BgpPeerGroupRemoteAs => (
            "Set a peer-group's remote autonomous system number.",
            "Sets the remote-as field on a peer-group. Must be a valid, non-reserved 32-bit \
             ASN; validity is checked at commit time, not when the edit is applied.",
        ),
        Topic::BgpPeerGroupSourceAddress => (
            "Set a peer-group's transport source address.",
            concat!(
                "Sets the source-address field on a peer-group — referenced by interface name \
             (plus an optional label, for an interface with more than one address) rather \
             than a literal address, resolved by nos-bgpd at runtime. `source-address \
             loopback` refers to this instance's own loopback interface \
             (loopback-<routing-table>) without needing to spell out its name. This is \
             independent of which address families the group exchanges: the resolved \
             source address's family may still differ from an advertised address family \
             (RFC 8950 extended next-hop encoding), so source-address and address-family \
             are never cross-validated against each other.",
                " ",
                "Clear a peer-group's transport source address.",
            ),
        ),
        Topic::BgpPeerGroupAddressFamily => (
            "Add an address family to a peer-group.",
            concat!(
                "Adds one AFI/SAFI (ipv4 or ipv6 unicast, or l2vpn-evpn — RFC 7432 EVPN, which \
             is received and shown only for now) to the set exchanged over this \
             peer-group's session. A no-op if it's already present. At least one address \
             family is required for the peer-group to be valid; checked at commit time.",
                " ",
                "Remove an address family from a peer-group.",
            ),
        ),
        Topic::BgpPeerGroupHoldTime => (
            "Set a peer-group's BGP hold-time.",
            concat!(
                "Sets the hold-time field on a peer-group — the value this router proposes in its \
             OPEN message. A value of 0 disables both the hold timer and keepalives entirely; \
             otherwise it must be at least 3 seconds (RFC 4271 §6.2). The value actually used \
             by a session is the lower of this and the peer's own proposed hold time. When \
             both hold-time and keepalive-interval are set, keepalive-interval must be less \
             than hold-time — checked at commit time, not when the edit is applied.",
                " ",
                "Clear a peer-group's BGP hold-time.",
            ),
        ),
        Topic::BgpPeerGroupKeepaliveInterval => (
            "Set a peer-group's BGP keepalive interval.",
            concat!(
                "Sets the keepalive-interval field on a peer-group — how often this router sends \
             KEEPALIVE messages on an established session. Must be strictly less than \
             hold-time whenever both are explicitly set (a hold-time of 0 disables keepalives \
             entirely, so no explicit keepalive-interval is valid alongside it); checked at \
             commit time, not when the edit is applied.",
                " ",
                "Clear a peer-group's BGP keepalive interval.",
            ),
        ),
        Topic::BgpPeerGroupConnectRetryTime => (
            "Set a peer-group's BGP connect-retry time.",
            concat!(
                "Sets the connect-retry-time field on a peer-group — how long this router waits \
             between outbound connection attempts to a peer in this group. Must be at least 1 \
             second; checked at commit time, not when the edit is applied.",
                " ",
                "Clear a peer-group's BGP connect-retry time.",
            ),
        ),
        Topic::BgpPeerGroupMrai => (
            "Set a peer-group's BGP MinRouteAdvertisementInterval.",
            concat!(
                "Sets the mrai field on a peer-group (RFC 4271 §9.2.1.1) — advertisements to a peer \
             in this group are batched and sent at most once per this many seconds, and repeated \
             changes to one prefix within the interval collapse into the latest. Withdrawals are \
             never delayed. Unset or 0 sends every change immediately.",
                " ",
                "Clear a peer-group's BGP MinRouteAdvertisementInterval.",
            ),
        ),
        Topic::BgpPeerGroupRouteRefreshStaleTime => (
            "Set how long a peer-group's routes stay stale during an enhanced route refresh.",
            concat!(
                "Sets route-refresh-stale-time on a peer-group (RFC 7313 §4) — after a peer sends \
             a Beginning-of-Route-Refresh, its routes it hasn't re-announced are purged this many \
             seconds later even if its End-of-Route-Refresh never arrives. Unset defaults to 360 \
             seconds; 0 keeps stale routes until the End-of-Route-Refresh or the session ends.",
                " ",
                "Clear a peer-group's route refresh stale time (back to 360 seconds).",
            ),
        ),
        Topic::BgpPeerGroupLocalAs => (
            "Set the AS a peer-group's peers see instead of this instance's own.",
            concat!(
                "Sets local-as on an eBGP peer-group (`asn <n>`, optional `no-prepend` and `replace-as`; vendor local-as, no RFC) — the OPEN carries \
             this AS, routes sent to the peers get it prepended in front of this instance's own AS \
             (only it with replace-as), and routes received from them get it prepended to their \
             AS_PATH unless no-prepend is set. A route from these peers that already holds it is \
             dropped as a loop. Used to migrate a router to a new AS without reconfiguring every \
             neighbour at once.",
                " ",
                "Clear a peer-group's local-as (its peers see this instance's own AS again).",
            ),
        ),
        Topic::BgpPeerGroupAddPath => (
            "Set RFC 7911 ADD-PATH (several paths per prefix) for a peer-group.",
            concat!(
                "Sets ADD-PATH on a peer-group's ipv4/ipv6 unicast sessions (`receive`, `send` or \
             `both`; RFC 7911). `receive` keeps every path a peer sends for a prefix instead of \
             only the last one, so they all compete in best-path selection and can form multipath; \
             `send` advertises with path identifiers: a route-server client gets every other \
             source's path, any other peer the best `add-path-send-count` paths (2 by default). \
             What is used per family is what both \
             sides offer. A route-server client defaults to `both`, any other group to off. The \
             capability is in the OPEN, so a change restarts the group's sessions.",
                " ",
                "Clear a peer-group's ADD-PATH (back to off, or both for a route-server client).",
            ),
        ),
        Topic::BgpPeerGroupAddPathSendCount => (
            "Set how many paths per prefix a peer-group is sent over ADD-PATH.",
            concat!(
                "Sets how many paths per prefix (2-64) a peer-group's sessions are sent when \
             ADD-PATH send is negotiated: the best ones by the decision process, counted after the \
             group's own filtering (split horizon, export policy), so a refused path doesn't use \
             up a slot. Unset, a group gets 2 (the best path plus one backup), a route-server \
             client every path. Independent of the instance's maximum-paths, which only sets \
             what is installed: to let a receiver build the same multipath set, set this to at \
             least maximum-paths. Needs add-path send or both. A change restarts the group's \
             sessions.",
                " ",
                "Clear a peer-group's add-path-send-count (back to 2, or every path for a \
             route-server client).",
            ),
        ),
        Topic::BgpPeerGroupMaxHops => (
            "Set how many router hops away a peer-group's peers may be.",
            concat!(
                "Sets max-hops on a peer-group and enables the RFC 5082 Generalized TTL Security \
             Mechanism: sessions are sent with TTL/hop-limit 255 and packets arriving with a \
             lower value than 256 minus this number are dropped by the kernel. 1 means \
             directly connected; up to 254. Both ends must enable it. Unset disables it.",
                " ",
                "Clear a peer-group's max-hops.",
            ),
        ),
        Topic::BgpPeerGroupDamping => (
            "Enable route flap damping on a peer-group.",
            concat!(
                "Sets the damping block on an eBGP peer-group (RFC 2439; optional arguments `half-life <s>`, `reuse <n>`, `suppress <n>`, `max-suppress <s>` in any order): each withdrawal of a route \
             received from a peer in this group adds 1000 to that prefix's penalty (500 for an \
             attribute change), the penalty halves every half-life seconds, the route is \
             suppressed while it is at or above suppress and released once it decays below \
             reuse, and max-suppress caps how long a route can stay suppressed. Unset values \
             default to RFC 7196's recommendation (half-life 900, reuse 750, suppress 6000, \
             max-suppress 3600).",
                " ",
                "Disable route flap damping on a peer-group.",
            ),
        ),
        Topic::BgpPeerGroupAuth => (
            "A peer-group's BGP session authentication: an MD5 password or TCP-AO keys.",
            "Usually set with `md5-password` or `ao-key`. `delete auth` unsets the auth field on a peer-group entirely, regardless of which mechanism \
             (MD5 password or TCP-AO keys) was set, reverting sessions to no transport \
             authentication.",
        ),
        Topic::BgpPeerGroupMd5Password => (
            "Set a peer-group's BGP MD5 password.",
            "Sets a single RFC 2385 TCP MD5 signature password on a peer-group's sessions, \
             replacing any TCP-AO keys that were set — the two mechanisms are mutually \
             exclusive, since the kernel accepts only one per socket. Stored clear-text, like \
             every other field in this config.",
        ),
        Topic::BgpPeerGroupAoKey => (
            "Set (or replace) one of a peer-group's TCP-AO keys.",
            concat!(
                "Adds one RFC 5925 TCP-AO key to a peer-group, identified by its send-id — adding a \
             key with a send-id that already exists replaces it in place. If the peer-group's \
             auth wasn't already TCP-AO (unset, or an MD5 password), this starts a fresh key \
             list containing just this key. Exactly one key across the whole list must be \
             marked current, and at most one may be marked rnext, for the peer-group to \
             validate at commit time; send-ids and recv-ids must each be unique — see set-bgp-peer-group-ao-current-key/rnext-key. Stored \
             clear-text, like every other field in this config.",
                " ",
                "Remove one of a peer-group's TCP-AO keys by send-id.",
                " ",
                "Mark one of a peer-group's TCP-AO keys as current: the key a new connection \
             starts signing with. On an established session the peer's RNextKeyID decides \
             which key signs (RFC 5925 §7.5.2), so this never forces a switch.",
                " ",
                "Mark one of a peer-group's TCP-AO keys as rnext: the key this router asks the \
             peer to switch to. It takes effect on the live session without a reset.",
                " ",
                "`ao-key <send-id> exclude-options` makes that key's MAC skip TCP options \
             (RFC 5925 §5.2); `delete ao-key <send-id> exclude-options` clears it. Both \
             ends must agree.",
            ),
        ),
        Topic::BgpPeerGroupNextHop => (
            "Set a peer-group's advertised BGP next-hop mode.",
            concat!(
                "Sets the next-hop field on a peer-group to either 'self' (rewrite the NEXT_HOP \
             attribute to this router's own address on every advertisement — the standard \
             eBGP default) or 'unchanged' (preserve the next-hop the route already carries \
             — the standard iBGP default, avoiding the third-party-next-hop problem). \
             Overrides the mode this peer-group would otherwise default to based on whether \
             it's eBGP or iBGP (remote-as compared to the instance's own asn); a \
             route-server-client peer-group defaults to 'unchanged' (RFC 7947).",
                " ",
                "Clear a peer-group's advertised BGP next-hop mode override.",
            ),
        ),
        Topic::BgpPeerGroupRouteReflectorClient => (
            "Mark a peer-group as an RFC 4456 route-reflector client.",
            concat!(
                "Routes learned from any iBGP peer are reflected to this peer-group's sessions \
             (and routes learned from this peer-group are reflected to every other iBGP \
             peer), instead of being withheld by the usual iBGP split-horizon rule. Requires \
             an iBGP peer-group (remote-as equal to the instance's own asn) and is mutually \
             exclusive with route-server-client; both are checked at commit time.",
                " ",
                "Unmark a peer-group as a route-reflector client.",
            ),
        ),
        Topic::BgpPeerGroupRouteServerClient => (
            "Mark a peer-group as an RFC 7947 route-server client.",
            concat!(
                "This peer-group's own ASN is never prepended to AS_PATH when advertising to it, \
             and — via RFC 7911 ADD-PATH, if the peer negotiates it — it receives every other \
             route-server-client's path for a prefix, not just the one instance-wide elected \
             best path. Requires an eBGP peer-group (remote-as different from the instance's \
             own asn) and is mutually exclusive with route-reflector-client; both are checked \
             at commit time.",
                " ",
                "Unmark a peer-group as a route-server client.",
            ),
        ),
        Topic::BgpPeerGroupImportPolicy => (
            "Filter the routes this peer-group's peers send us through a routing policy.",
            "Names a policy-definition applied to every route received from this peer-group's peers before it enters the Loc-RIB. Unset, the direction defaults to the built-in deny-all: nothing is accepted. `accept-all` and `deny-all` are always available.",
        ),
        Topic::BgpPeerGroupExportPolicy => (
            "Filter the routes we advertise to this peer-group's peers through a routing policy.",
            "Names a policy-definition applied to every route before it is advertised to this peer-group's peers. Unset, the direction defaults to the built-in deny-all: nothing is advertised. `accept-all` and `deny-all` are always available.",
        ),
        Topic::BgpPeerGroupShutdown => (
            "Administratively shut every peer in a peer-group.",
            concat!(
                "Sets shutdown on a peer-group (RFC 4486): no session is opened or accepted for \
             any peer in it, and an established session is closed with a Cease / \
             Administrative Shutdown NOTIFICATION. An optional message (at most 255 bytes) is \
             sent to the peer as an RFC 9003 shutdown communication. A peer with its own \
             shutdown setting is unaffected by this one.",
                " ",
                "Bring a shut peer-group back up.",
            ),
        ),
        Topic::BgpPeer => (
            "Associate a remote address with a peer-group.",
            concat!(
                "Creates the association between a remote address and a peer-group within a \
             BGP instance if it doesn't exist yet, or repoints it to a different peer-group \
             if it does. The referenced peer-group must exist for the config to be valid; \
             checked at commit time.",
                " ",
                "Remove a peer's association to its peer-group.",
            ),
        ),
        Topic::BgpPeerShutdown => (
            "Administratively shut one BGP peer.",
            concat!(
                "Sets shutdown on a single peer (RFC 4486), overriding its peer-group: no session \
             is opened or accepted, and an established one is closed with a Cease / \
             Administrative Shutdown NOTIFICATION carrying the optional message (at most 255 \
             bytes, RFC 9003). The peer must already exist.",
                " ",
                "Bring a shut BGP peer back up.",
            ),
        ),
        Topic::RoutingTable => (
            "Create a routing table in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new routing table with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself associate a BGP instance or a static routing instance.",
                " ",
                "Delete a routing table from the transaction.",
            ),
        ),
        Topic::RoutingTableBgpInstance => (
            "Associate a BGP instance with a routing table.",
            concat!(
                "Points a routing table at a BGP instance by name. The instance must exist, and \
             a given instance may be associated with at most one routing table at a time; \
             both are checked at commit time, not when the edit is applied.",
                " ",
                "Remove a routing table's BGP instance association.",
            ),
        ),
        Topic::RoutingTableStaticRoutingInstance => (
            "Associate a static routing instance with a routing table.",
            concat!(
                "Points a routing table at a static routing instance by name. The instance must \
             exist, and a given static routing instance may be associated with at most one \
             routing table at a time; both are checked at commit time, not when the edit is \
             applied.",
                " ",
                "Remove a routing table's static routing instance association.",
            ),
        ),
        Topic::RoutingTableOspfInstance => (
            "Associate an OSPF instance with a routing table.",
            concat!(
                "Points a routing table at an OSPF instance by name (the VRF that instance \
             belongs to). The OSPF instance must exist, and at most one routing table may \
             claim a given instance at a time — both checked at commit time.",
                " ",
                "Remove a routing table's OSPF instance association.",
            ),
        ),
        Topic::RoutingTableOspfv3Instance => (
            "Associate an OSPFv3 instance with a routing table.",
            "The OSPFv3 instance's routes are installed into this routing table (its VRF). An instance can be claimed by at most one routing table. `delete` removes the association.",
        ),
        Topic::RoutingTableRedistribute => (
            "Redistribute this table's static routes into its associated BGP or OSPF instance.",
            concat!(
                "Sets the redistribute field on a routing table ('from static to bgp' or 'from \
             static to ospf' — redistributing into OSPF makes this router a real RFC 2328 ASBR, \
             originating an AS-external-LSA per redistributed prefix). Both bgp-instance/\
             ospf-instance (matching the chosen target) and static-routing-instance must already \
             be set on the table for the rule to be valid — checked at commit time, not when the \
             rule is set. An optional trailing 'policy <name>' clause names an RPL policy (or \
             accept-all/deny-all) to filter redistributed routes through before they reach BGP/ \
             OSPF; omitted, redistribution stays unfiltered (accept-all), unlike a peer-group's \
             import-policy/export-policy, which default to deny-all.",
                " ",
                "Clear this table's redistribution rule.",
            ),
        ),
        Topic::RoutingTableRestApi => (
            "Serve the REST API on an address inside this routing table.",
            "Makes nos-watchdogd run nos-restd for this routing table, listening on the given address (and port, default 8080) inside the table's VRF over mutual TLS. `delete` stops it.",
        ),
        Topic::RoutingTableEvpn => (
            "Make this routing table an EVPN IP-VRF with an L3 VNI.",
            "nos-ribd creates a VXLAN device for the l3-vni on a bridge in the table's VRF, \
             originates every best route of the table as an EVPN Type-5 (IP prefix) route into \
             the underlay bgp-instance, and installs the Type-5 routes it receives with an \
             import route-target through the VXLAN. Needs an l3-vni, rd, an export \
             route-target, a vtep-source and a bgp-instance. `delete` removes it all.",
        ),
        Topic::RoutingTableEvpnL3Vni => (
            "Set the table's L3 VNI.",
            "1-16777215, unique across every routing table's l3-vni and every broadcast \
             domain's vni. Carried as the label of every Type-5 route; a received one must \
             carry the same value.",
        ),
        Topic::RoutingTableEvpnRd => (
            "Set the Route Distinguisher of the table's Type-5 routes.",
            "Written asn:nn or a.b.c.d:nn.",
        ),
        Topic::RoutingTableEvpnRouteTarget => (
            "Add an EVPN Route Target to the table's import or export list.",
            "`import`: a received Type-5 route is installed only if it carries one of these. \
             `export`: attached to every Type-5 route the table originates (at least one is \
             required). Written asn:nn or a.b.c.d:nn.",
        ),
        Topic::RoutingTableEvpnVtepSource => (
            "Set the address the table's VXLAN tunnels are sourced from.",
            "Names an interface (and optionally the label of one of its addresses) or \
             `loopback` — the loopback of the routing table owning the evpn bgp-instance. \
             Resolved at runtime by nos-ribd; it is the next hop of every Type-5 route the \
             table originates.",
        ),
        Topic::RoutingTableEvpnBgpInstance => (
            "Name the underlay BGP instance the table's Type-5 routes are exchanged over.",
            "Must exist and must not be the table's own bgp-instance: the routes are carried \
             by the instance of the underlay VRF, which needs `address-family l2vpn-evpn` on \
             its peer-groups.",
        ),
        Topic::StaticRoutingInstance => (
            "Create a static routing instance in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new static routing instance with the given name to the transaction's \
             in-progress config if none exists with that name yet; if one already exists, \
             this is a no-op. A static routing instance carries no reference to any routing \
             table — only a routing table's static-routing-instance field names it.",
                " ",
                "Delete a static routing instance from the transaction.",
            ),
        ),
        Topic::StaticRoute => (
            "Add or repoint a static route.",
            concat!(
                "Creates a route for the given subnet within a static routing instance if it \
             doesn't exist, or repoints its gateway if it does. The gateway's address family \
             must match the subnet's, and a subnet must not repeat within the same instance; \
             both are checked at commit time. Only one gateway per subnet is supported — \
             ECMP is not modeled in this iteration.",
                " ",
                "Remove a static route.",
            ),
        ),
        Topic::Interface => (
            "Create an interface in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new interface with the given name to the transaction's in-progress config \
             if none exists with that name yet; if one already exists, this is a no-op. Does \
             not itself set any addresses or a routing table. For a physical (non-loopback) \
             interface, L3 config lives on a subinterface addressed as '<name>.<tag>' — '.0' \
             for the untagged/native case, '.1'-'.4094' for a real 802.1q VLAN — rather than \
             directly on the interface; a loopback interface (name 'loopback-<table>') is the \
             one exception and keeps its addresses/routing-table flat, unchanged.",
                " ",
                "Delete an interface from the transaction.",
            ),
        ),
        Topic::InterfaceAddress => (
            "Add an IP address to an interface.",
            concat!(
                "Adds an address to an interface's (or, for a physical interface, a subinterface's \
             — see 'edit interface') address list if it isn't already present — a no-op if it \
             is. Any number of addresses may be carried, including a mix of IPv4 and IPv6; a \
             given address must not repeat on the same interface/subinterface, checked at \
             commit time. Addressing a bare non-loopback interface name (no '.tag' suffix) \
             implicitly targets its tag-0 (untagged/native) subinterface.",
                " ",
                "Remove an IP address from an interface.",
            ),
        ),
        Topic::InterfaceRoutingTable => (
            "Associate a routing table with an interface.",
            concat!(
                "Points an interface — or, for a physical interface, one of its subinterfaces — at \
             a routing table by name, which doubles as its VRF assignment. The routing table \
             must exist, checked at commit time; unlike a routing table's own \
             bgp-instance/static-routing-instance associations, more than one \
             interface/subinterface may be associated with the same routing table. Addressing \
             a bare non-loopback interface name (no '.tag' suffix) implicitly targets its \
             tag-0 (untagged/native) subinterface.",
                " ",
                "Remove an interface's routing table association.",
            ),
        ),
        Topic::InterfaceOspfProfile => (
            "Associate an OSPF profile with an interface, subinterface, or broadcast domain.",
            concat!(
                "Points a loopback interface, a physical interface's subinterface, or a broadcast \
             domain's own SVI at an OSPF profile by name. The profile must exist, and the \
             same attach point must also have a routing-table set — OSPF has no meaning \
             without an L3/VRF context — both checked at commit time.",
                " ",
                "Remove an OSPF profile association.",
            ),
        ),
        Topic::InterfaceOspfv3Profile => (
            "Run OSPFv3 on this attach point under a profile.",
            "Joins OSPFv3 (RFC 5340) on this interface, subinterface or broadcast domain with the named OSPFv3 profile's timers, cost and authentication. Needs a routing-table on the same attach point. `delete` leaves OSPFv3 there.",
        ),
        Topic::InterfaceSwitchingProfile => (
            "Associate a switching profile with an interface.",
            concat!(
                "Points an interface at a switching profile by name, trunking it into one or more \
             broadcast domains. The switching profile must exist, checked at commit time. A \
             tag claimed by one of the interface's own subinterfaces (an untagged/'.0' one \
             claims tag 0, a '.<n>' one claims tag n) and a tag claimed by a switching-profile \
             member (an untagged member claims tag 0, a dot1q member claims its tag) are \
             mutually exclusive on the same interface — each tag's link has only one master \
             device — checked at commit time.",
                " ",
                "Remove an interface's switching-profile association.",
            ),
        ),
        Topic::InterfacePortAggregate => (
            "Associate an interface with a port aggregate as a bonded member.",
            concat!(
                "Points an interface at a port aggregate by name, making it a bonded member. The \
             port aggregate must exist, checked at commit time. A member interface must not \
             also carry a switching-profile association or any subinterfaces — like VRF/bridge \
             enslavement, bond enslavement claims the link's one Linux master device — checked \
             at commit time.",
                " ",
                "Remove an interface's port-aggregate association.",
            ),
        ),
        Topic::InterfaceMtu => (
            "Set an interface's MTU.",
            concat!(
                "Sets the MTU (in bytes, 68-65535) on a physical or loopback interface — a \
             link-layer property of the interface itself, applying uniformly to every one of \
             its subinterfaces (a VLAN sub-link has no MTU of its own, unlike addresses/\
             routing-table), so set it on the parent interface or port aggregate, not \
             inside a subinterface. Unset means 1500, enforced on the link.",
                " ",
                "Clear an interface's MTU: `delete` puts the link back to 1500.",
            ),
        ),
        Topic::InterfaceLldpTransmit => (
            "Enable or disable LLDP transmit on an interface.",
            "`set` makes nos-lldpd periodically send IEEE 802.1AB LLDPDUs (chassis/port \
             identity, system name/description, capabilities) out this physical interface so \
             directly-connected neighbors can discover it; `delete` turns it off again, \
             sending a final shutdown LLDPDU so neighbors drop this system immediately. \
             Independent of lldp receive. Physical interfaces only — rejected on a loopback \
             at commit time.",
        ),
        Topic::InterfaceLldpReceive => (
            "Enable or disable LLDP receive on an interface.",
            "`set` makes nos-lldpd listen for neighbors' LLDPDUs on this physical interface \
             and record them, visible via `show lldp neighbors`; entries age out when their \
             advertised TTL lapses. `delete` turns it off and forgets this interface's \
             neighbors. Independent of lldp transmit. Physical interfaces only — rejected on \
             a loopback at commit time.",
        ),
        Topic::InterfaceLldpDestination => (
            "Set the LLDP destination group an interface uses.",
            "Chooses which IEEE 802.1AB multicast group this interface's LLDPDUs are sent to \
             and accepted from: nearest-bridge (01:80:C2:00:00:0E, the default — never \
             forwarded by any bridge), non-tpmr (…:03, the nearest non-TPMR bridge: relayed by TPMRs, stopped by \
             every other bridge) or \
             customer-bridge (…:00). Both ends of a link must use the same group, or neither \
             will ever see the other. `delete` restores nearest-bridge. Physical interfaces \
             only — rejected on a loopback at commit time.",
        ),
        Topic::Subinterface => (
            "Create or delete a subinterface: one 802.1q tag's L3 attach point.",
            "A physical interface or port aggregate carries its L3 config per tag: tag 0 is the untagged link, 1-4094 an 802.1q VLAN sub-interface. Each has its own addresses, routing-table and OSPF profiles. `delete` removes the subinterface and its config.",
        ),
        Topic::BroadcastDomain => (
            "Create a broadcast domain in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new broadcast domain with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself set any addresses or a routing table — a switching \
             profile's members reference the domain for L2 membership, while its own \
             addresses/routing-table (set separately) make its bridge device an SVI (switch \
             virtual interface), a routed L3 attachment point for the domain as a whole.",
                " ",
                "Delete a broadcast domain from the transaction.",
            ),
        ),
        Topic::BroadcastDomainAddress => (
            "Add an IP address to a broadcast domain's SVI.",
            concat!(
                "Adds an address to a broadcast domain's own address list if it isn't already \
             present — a no-op if it is. Any number of addresses may be carried, including a \
             mix of IPv4 and IPv6; a given address must not repeat on the same domain, checked \
             at commit time. This addresses the domain's own bridge device (its SVI), not any \
             interface enslaved into it as an L2 member.",
                " ",
                "Remove an IP address from a broadcast domain's SVI.",
            ),
        ),
        Topic::BroadcastDomainRoutingTable => (
            "Associate a routing table with a broadcast domain's SVI.",
            concat!(
                "Points a broadcast domain's own bridge device at a routing table by name, which \
             doubles as its VRF assignment. The routing table must exist, checked at commit \
             time; as with an interface, more than one broadcast domain (or interface) may be \
             associated with the same routing table.",
                " ",
                "Remove a broadcast domain's routing table association.",
            ),
        ),
        Topic::BroadcastDomainVni => (
            "Give a broadcast domain a VXLAN Network Identifier (EVPN).",
            "Setting a VNI (1-16777215) makes nos-watchdogd run a nos-fdbd for the domain, \
             which creates a VXLAN device enslaved into the domain's bridge and programs its \
             forwarding database. rd, route-target, vtep-source and redistribute all require \
             it. `delete` clears it, which stops nos-fdbd and removes the VXLAN device.",
        ),
        Topic::BroadcastDomainRd => (
            "Set a broadcast domain's EVPN Route Distinguisher.",
            "Written asn:nn or a.b.c.d:nn (with a 4-byte asn or an address, nn must fit 16 \
             bits). Carried on every EVPN route the domain originates. Requires a vni.",
        ),
        Topic::BroadcastDomainRouteTarget => (
            "Add an EVPN Route Target to a broadcast domain's import or export list.",
            "`import`: a received EVPN route is installed into the domain's forwarding \
             database only if it carries at least one of these. `export`: attached to every \
             EVPN route the domain originates. Written asn:nn or a.b.c.d:nn; adding one \
             already present is a no-op, and `delete` removes one. Requires a vni.",
        ),
        Topic::BroadcastDomainVtepSource => (
            "Set the address a broadcast domain's VXLAN tunnels are sourced from.",
            "Names an interface (and, when it carries several addresses, the label of the one \
             to use) or `loopback` — the loopback of the routing table owning the BGP \
             instance named by `redistribute`. Resolved at runtime by nos-fdbd, so a missing \
             address is retried rather than rejected at commit. It is also the next-hop of \
             every EVPN route the domain originates. Requires a vni.",
        ),
        Topic::BroadcastDomainMacRedistribute => (
            "Redistribute a broadcast domain's MAC addresses into a BGP instance (EVPN).",
            "`redistribute from mac to bgp <instance>`: nos-fdbd originates an EVPN Type-2 \
             (MAC advertisement) route per MAC learned locally on the domain's bridge and a \
             Type-3 (inclusive multicast) route for the domain, into the named BGP instance; \
             EVPN routes that instance receives with a matching import route-target are \
             installed into the domain's forwarding database. Requires a vni, an rd and a \
             vtep-source; the peer-group must have `address-family l2vpn-evpn`.",
        ),
        Topic::BroadcastDomainArpRedistribute => (
            "Also originate a broadcast domain's ARP/ND neighbours as EVPN MAC+IP routes.",
            "`redistribute from arp to bgp <instance>`: every IPv4 ARP / IPv6 ND neighbour \
             (link-local addresses excluded) on the domain's bridge is originated as an EVPN \
             Type-2 route carrying both its MAC and IP. The instance must be the one named by \
             `redistribute from mac`. Received Type-2 routes with an IP are programmed as \
             kernel neighbours on the bridge.",
        ),
        Topic::BroadcastDomainConnectedRedistribute => (
            "Originate a broadcast domain's own (SVI) addresses as EVPN MAC+IP routes.",
            "`redistribute from connected to bgp <instance>`: each of the domain's own \
             `address`es (its SVI, link-local excluded) is originated as an EVPN Type-2 route \
             carrying the bridge's MAC and that IP. The instance must be the one named by \
             `redistribute from mac`.",
        ),
        Topic::BroadcastDomainNeighSuppress => (
            "Answer ARP/ND locally for EVPN-learned hosts (ARP/ND suppression).",
            "Sets neighbour suppression on the domain's VXLAN bridge port: an ARP request or \
             IPv6 neighbour solicitation for a host whose MAC+IP binding the bridge already \
             holds (every received EVPN Type-2 route with an IP is installed as one) is \
             answered by the bridge itself instead of being flooded over the fabric; an \
             unknown target still floods. Gratuitous ARP is no longer flooded to the VXLAN \
             port either, so remote hosts only learn a moved local IP once their cache \
             expires. Requires a vni. `delete` turns it off.",
        ),
        Topic::SwitchingProfile => (
            "Create a switching profile in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new switching profile with the given name to the transaction's \
             in-progress config if none exists with that name yet; if one already exists, \
             this is a no-op. A switching profile is a trunk-style container — it maps \
             multiple broadcast domains to their dot1q tagging, added via a separate op.",
                " ",
                "Delete a switching profile from the transaction.",
            ),
        ),
        Topic::SwitchingProfileMember => (
            "Add or retag a broadcast domain within a switching profile.",
            concat!(
                "Associates a broadcast domain with the given tag (a dot1q VLAN, or untagged) \
             within a switching profile — if the domain is already a member, its tag is \
             replaced. The referenced broadcast domain must exist, and no broadcast domain \
             may appear twice within the same profile; both are checked at commit time.",
                " ",
                "Remove a broadcast domain from a switching profile.",
            ),
        ),
        Topic::PortAggregate => (
            "Create a port aggregate in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new Linux bonding device with the given name and mode to the transaction's \
             in-progress config if none exists with that name yet; if one already exists, this \
             is a no-op. An interface becomes a bonded member by pointing its own \
             port-aggregate field at this aggregate's name, the same way it points at a \
             switching profile for L2 trunking.",
                " ",
                "Delete a port aggregate from the transaction.",
            ),
        ),
        Topic::PortAggregateMode => (
            "Set a port aggregate's bonding mode.",
            "Updates the mode field on the named port aggregate in the transaction's \
             in-progress config. The aggregate must already exist. `xor` enslaves every member \
             interface unconditionally, with no negotiation. `lacp` negotiates membership over \
             a real IEEE 802.1AX LACPDU exchange run by nos-lacpd — a member is only enslaved \
             once negotiation with the partner confirms it, and is released again if the \
             negotiation lapses.",
        ),
        Topic::PortAggregateLacpRate => (
            "Set how fast a port aggregate's LACP partner is asked to send LACPDUs.",
            "Updates the lacp-rate field on the named port aggregate in the transaction's \
             in-progress config. The aggregate must already exist. `slow` asks the partner for \
             an LACPDU every 30 seconds (a lost partner is noticed after 90); `fast` asks for one \
             every second (noticed after 3). Only meaningful for a `lacp`-mode aggregate. Each \
             end transmits at the rate the *other* end asks for, so both ends need `fast` for \
             fast detection in both directions.",
        ),
        Topic::PortAggregateEsi => (
            "Set the EVPN Ethernet Segment Identifier of a port aggregate.",
            "Sets the esi field on the named port aggregate: ten colon-separated hex bytes, not \
             all zero. Give the same value to the aggregate on every PE the customer device is \
             multi-homed to. nos-fdbd then advertises it in the Type-2 route of every MAC learned \
             on the aggregate, originates an Ethernet Segment (Type-4) route for it, and elects \
             one PE per broadcast domain as the Designated Forwarder for BUM traffic (the others \
             stop flooding to the aggregate). `delete` removes it. Two aggregates on one router \
             cannot share an ESI.",
        ),
        Topic::PortAggregateLacpSystemId => (
            "Override a port aggregate's LACP Actor System ID.",
            "Sets the MAC address nos-lacpd advertises as the Actor System ID for the named \
             `lacp`-mode aggregate, instead of the one derived from this machine's identity. Use \
             the same value on every PE of a multi-homed Ethernet Segment so the customer device \
             sees one partner and bundles its links across them. Must be a unicast MAC. `delete` \
             goes back to the derived id.",
        ),
        Topic::PortAggregateRedundancyMode => (
            "Set how the PEs sharing a port aggregate's Ethernet Segment divide the traffic.",
            "Sets the redundancy-mode of the named port aggregate: `all-active` (the default) lets \
             every PE forward unicast to the segment and only the Designated Forwarder flood BUM; \
             `single-active` lets only the Designated Forwarder forward anything, the other PEs \
             blocking the aggregate's bridge port outright. The mode is announced to the other PEs \
             in the per-ES Ethernet A-D route, and needs an `esi` (checked at commit time). The \
             blocked port keeps its carrier, so a single-active customer device needs end-to-end \
             failure detection (for example an ARP-monitored active-backup bond) to move over.",
        ),
        Topic::PortAggregateDfAlgorithm => (
            "Set the Designated Forwarder election algorithm of a port aggregate's Ethernet Segment.",
            "Sets the df-algorithm of the named port aggregate: `modulo` (the default, RFC 7432 \
             service carving) or `hrw` (RFC 8584 Highest Random Weight). The choice is advertised \
             in the segment's Type-4 route; HRW only takes effect when every PE on the segment \
             asks for it, otherwise every PE falls back to modulo. Needs an `esi` (checked at \
             commit time).",
        ),
        Topic::OspfInstance => (
            "Create an OSPF instance in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new OSPF instance with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the instance.",
                " ",
                "Delete an OSPF instance from the transaction.",
            ),
        ),
        Topic::OspfInstanceRouterId => (
            "Set an OSPF instance's router id.",
            "Updates the router-id field on the named OSPF instance in the transaction's \
             in-progress config. The instance must already exist.",
        ),
        Topic::OspfInstanceGracefulRestart => (
            "Announce an RFC 3623 graceful restart before a planned shutdown.",
            "On a planned shutdown the instance sends a Grace-LSA to every Full neighbor, which then keeps the adjacency and this router's routes for this many seconds (1-1800) while it restarts. `delete` turns it off. Helping a restarting neighbor needs no config.",
        ),
        Topic::OspfInstancePrefixSuppression => (
            "Hide transit-only networks (RFC 6860 prefix suppression).",
            "Leaves every point-to-point link's subnet out of this router's Router-LSA and gives the Network-LSA it originates as DR a /32 mask, so the rest of the area installs no route to those transit networks while still routing through them. Loopbacks are never hidden. The setting is instance-wide; enable it on every router attached to a network to hide it fully. `delete` turns it off.",
        ),
        Topic::OspfInstanceMaxMetricOnStartup => (
            "Advertise this router as a stub router for a while after it starts (RFC 6987).",
            "For this many seconds (5-86400) after nos-ospfd starts, every transit link in this router's Router-LSA costs 65535, so traffic avoids the router while its routes converge; its own prefixes stay reachable at their normal cost. Takes effect on the next start. Skipped after a graceful restart, whose helpers keep the old topology. `delete` turns it off, and ends a period that is still running.",
        ),
        Topic::OspfInstanceMaxMetricOnShutdown => (
            "Advertise this router as a stub router before it stops (RFC 6987).",
            "When nos-ospfd stops (not a graceful restart), it first advertises every transit link at cost 65535 and holds that for this many seconds (1-3) before withdrawing its LSAs, so traffic moves away before the router disappears. Skipped when its Router-LSA changed in the last 5 seconds. 3 seconds is what fits in nos-watchdogd's 10-second stop budget beside the withdrawal. `delete` turns it off.",
        ),
        Topic::OspfInstanceMaxMetricAdministrative => (
            "Advertise this router as a stub router until removed (RFC 6987).",
            "Every transit link in this router's Router-LSA costs 65535 while set, so traffic avoids the router whenever another path exists — for draining it before maintenance. Its own prefixes stay reachable, and neighbors stop using it as a loop-free alternate. `delete` turns it off.",
        ),
        Topic::OspfInstanceHostRouter => (
            "Make this router a host router that never carries transit traffic (RFC 8770).",
            "Sets the H-bit in this router's Router-LSA: routers that support RFC 8770 never route through it, only to it, once every router in the area advertises that support; its transit links also cost 65535, for routers that don't. Its own prefixes stay reachable, and it is never a loop-free alternate. Can't be combined with `redistribute … to ospf` on its routing table, since a host router is not an AS boundary router. `delete` turns it off.",
        ),
        Topic::OspfArea => (
            "Create an OSPF area in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new area with the given dotted-quad area id to the named OSPF instance's \
             area list if none exists with that id yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the area.",
                " ",
                "Delete an OSPF area from an instance.",
            ),
        ),
        Topic::OspfProfile => (
            "Create an OSPF profile in the transaction if it doesn't already exist.",
            concat!(
                "Adds a new profile with the given name to the named area's profile list if none \
             exists with that name yet; if one already exists, this is a no-op. Profile names \
             are unique across the whole config, not just within their owning area, checked \
             at commit time.",
                " ",
                "Delete an OSPF profile from an area.",
            ),
        ),
        Topic::OspfProfileHelloInterval => (
            "Set an OSPF profile's Hello interval.",
            concat!(
                "Sets the hello-interval field on a profile — how often nos-ospfd sends Hello \
             packets on any link using it. When both hello-interval and dead-interval are set, \
             dead-interval must be strictly greater than hello-interval — checked at commit \
             time, not when the edit is applied.",
                " ",
                "Clear an OSPF profile's Hello interval.",
            ),
        ),
        Topic::OspfProfileDeadInterval => (
            "Set an OSPF profile's router dead interval.",
            concat!(
                "Sets the dead-interval field on a profile — how long nos-ospfd waits without a \
             Hello from a neighbor before declaring it down. Must be strictly greater than \
             hello-interval whenever both are explicitly set — checked at commit time, not \
             when the edit is applied.",
                " ",
                "Clear an OSPF profile's router dead interval.",
            ),
        ),
        Topic::OspfProfileCost => (
            "Set an OSPF profile's interface cost.",
            concat!(
                "Sets the cost field on a profile. This NOS has no SPF/LSDB yet, so this value has \
             no behavioral effect today — it's stored and validated (1-65535) as a \
             forward-declared placeholder for a future SPF phase.",
                " ",
                "Clear an OSPF profile's interface cost.",
            ),
        ),
        Topic::OspfProfilePriority => (
            "Set an OSPF profile's Router Priority.",
            concat!(
                "Sets the priority field on a profile — used by RFC 2328 §9.4 DR/BDR election on \
             a broadcast link (a priority of 0 makes a router ineligible to become DR/BDR); \
             sent on the wire, but functionally inert, on a point-to-point link.",
                " ",
                "Clear an OSPF profile's Router Priority.",
            ),
        ),
        Topic::OspfProfileMtu => (
            "Override the MTU OSPF believes this link has.",
            concat!(
                "Sets the mtu field on a profile — what this NOS advertises in the DBD packet's own \
             interface_mtu field and uses to size DBD pagination for every attach point using \
             this profile, independent of the interface's real kernel MTU (mirrors real OSPF \
             implementations' mtu-bytes-style override). Left unset, the attach point's real \
             interface MTU (queried from nos-interfaced) is used instead, falling back to 1500 \
             if unavailable.",
                " ",
                "Clear an OSPF profile's MTU override.",
            ),
        ),
        Topic::OspfProfileNetworkType => (
            "Set an OSPF profile's network type.",
            concat!(
                "Sets the network-type field on a profile to point-to-point, broadcast or point-to-multipoint (RFC 2328 §9.5, OSPFv2 only), \
             overriding the default that would otherwise be derived from each attach point's \
             own kind (a subinterface defaults to point-to-point, a broadcast domain defaults \
             to broadcast). Never validated against the attach point's actual kind — this NOS \
             allows forcing either behavior on either kind of attach point, matching real OSPF.",
                " ",
                "Clear an OSPF profile's network type override.",
            ),
        ),
        Topic::OspfProfileExtendedSequenceNumbers => (
            "Enable or disable RFC 7474 extended cryptographic sequence numbers.",
            "Sets extended-sequence-numbers on a profile. When enabled, every attach point using \
             this profile signs with authentication type 3: a 64-bit sequence number (a boot \
             count persisted by nos-ospfd in the high 32 bits, a per-packet counter in the low \
             32) and a digest bound to the sender's IP address, so a captured packet cannot be \
             replayed after a router restart. Requires crypto auth with hmac-sha keys only (not \
             md5), and both ends of a link must enable it — type 3 and type 2 packets are not \
             accepted by each other.",
        ),
        Topic::OspfProfileAuth => (
            "An OSPF profile's authentication: a simple password or crypto keys.",
            "Usually set with `simple-password` or `crypto-key`. `delete auth` unsets the auth field on a profile entirely, regardless of which mechanism \
             (simple password or crypto keys) was set, reverting to RFC 2328 AuType 0 (no \
             authentication).",
        ),
        Topic::OspfProfileSimplePassword => (
            "Set an OSPF profile's simple password.",
            "Sets a single RFC 2328 Appendix D.2 plaintext password (up to 8 bytes) on a \
             profile's Hello/DBD/LSR/LSU/LSAck packets, replacing any crypto keys that were set \
             — the two mechanisms are mutually exclusive. Stored clear-text, like every other \
             field in this config.",
        ),
        Topic::OspfProfileCryptoKey => (
            "Set (or replace) one of an OSPF profile's cryptographic auth keys.",
            concat!(
                "Adds one RFC 2328 Appendix D.3 / RFC 5709 cryptographic auth key to a profile, \
             identified by its key-id and algorithm (md5, hmac-sha1, hmac-sha256, hmac-sha384, \
             or hmac-sha512) — adding a key with a key-id that already exists replaces it in \
             place. If the profile's auth wasn't already crypto (unset, or a simple password), \
             this starts a fresh key list containing just this key. Exactly one key across the \
             whole list must be marked current, for the profile to validate at commit time — \
             see set-ospf-profile-crypto-current-key. Stored clear-text, like every other field \
             in this config.",
                " ",
                "Remove one of an OSPF profile's cryptographic auth keys by key-id.",
                " ",
                "Mark one of an OSPF profile's cryptographic auth keys as current.",
            ),
        ),
        Topic::Ospfv3Instance => (
            "Create or delete an OSPFv3 instance.",
            "An OSPFv3 (RFC 5340) routing process; nos-watchdogd runs one nos-ospfv3d per instance. `edit` creates it if missing and navigates into it; `delete` removes it with its areas and profiles.",
        ),
        Topic::Ospfv3InstanceRouterId => (
            "Set an OSPFv3 instance's router-id.",
            "The dotted-quad identifier this OSPFv3 instance uses in its Hellos and LSAs; it must be unique across the OSPFv3 domain.",
        ),
        Topic::Ospfv3InstanceExtendedLsa => (
            "Originate RFC 8362 extended LSAs (Full mode).",
            "Makes the instance originate and use the RFC 8362 E-Router/E-Link/E-Intra-Area-Prefix LSAs instead of the legacy formats. Every router in the area must agree. `delete` returns to legacy LSAs.",
        ),
        Topic::Ospfv3InstanceGracefulRestart => (
            "Announce an RFC 5187 graceful restart before a planned shutdown.",
            "On a planned shutdown the instance sends a Grace-LSA to every Full neighbor, which then keeps the adjacency and this router's routes for this many seconds (1-1800) while it restarts. `delete` turns it off. Helping a restarting neighbor needs no config.",
        ),
        Topic::Ospfv3Area => (
            "Create or delete an OSPFv3 area.",
            "An area of an OSPFv3 instance, identified by a dotted-quad area-id. `edit` creates it if missing and navigates into it; `delete` removes it with its profiles.",
        ),
        Topic::Ospfv3Profile => (
            "Create or delete an OSPFv3 profile.",
            "A named set of OSPFv3 link settings (timers, cost, priority, network-type, mtu, authentication) that interfaces join with `ospfv3 <profile>`. Profile names are unique across every instance and area.",
        ),
        Topic::Ospfv3ProfileAuth => (
            "An OSPFv3 profile's RFC 7166 authentication-trailer keys.",
            "Set with `crypto-key`. `delete auth` removes every RFC 7166 authentication-trailer key from the profile, so its packets are sent and accepted without a trailer.",
        ),
        Topic::Ospfv3ProfileCryptoKey => (
            "Add, remove or select an RFC 7166 authentication-trailer key.",
            "`crypto-key <sa-id> <algorithm> <key>` adds or replaces a key (SA ID 1-65535, an HMAC-SHA algorithm; md5 is not allowed); `crypto-key <sa-id> current` makes it the key that signs outgoing packets; `delete crypto-key <sa-id>` removes it.",
        ),
        Topic::Ospfv3ProfileInstanceId => (
            "Set an OSPFv3 profile's instance id.",
            "The RFC 5340 Instance ID (0-31) this profile's links put in every packet header; packets carrying another Instance ID are dropped, so both ends of a link must agree. `delete instance-id` resets it to 0.",
        ),
        Topic::PolicyDefinition => (
            "Create or delete a routing policy.",
            "A named RPL script that BGP peer-groups and redistribution rules reference as their import, export or redistribution policy. `edit` creates it (empty) if missing and navigates into it, where its source is edited; `delete` removes it.",
        ),
        Topic::PolicyDefinitionSource => (
            "Set a routing policy's RPL source.",
            "The whole RPL script, compiled at commit time: a script that doesn't compile, or doesn't end every path with accept or reject, is refused.",
        ),
        Topic::CommunityAlias => (
            "Create or delete a community alias.",
            "A name for one BGP community literal that routing policies can use in place of the literal. `edit` creates it if missing; `delete` removes it.",
        ),
        Topic::CommunityAliasValue => (
            "Set the community a community alias stands for.",
            "A standard (AA:NN), extended (type:subtype:value) or large (ga:ld1:ld2) community literal.",
        ),
        Topic::CommunityGroup => (
            "Create or delete a community group.",
            "A named set of community aliases and/or literals: a policy's `.contains(group)` matches if any member matches, and `.add`/`.remove` apply to every member. `edit` creates it if missing; `delete` removes it.",
        ),
        Topic::CommunityGroupMember => (
            "Add or remove a member of a community group.",
            "A member is a community alias name or a community literal.",
        ),
        Topic::PrefixList => (
            "Create or delete a prefix list.",
            "A named set of prefix entries a policy matches with `this.prefix in <name>`. `edit` creates it if missing; `delete` removes it.",
        ),
        Topic::PrefixListEntry => (
            "Add or remove a prefix-list entry.",
            "A bare CIDR matches that exact prefix only. `range <min> <max>` matches any prefix inside the CIDR whose length is within [min, max]; `orlonger` is the CIDR's own length up to the maximum, and `upto <max>` its own length up to <max>.",
        ),
        Topic::AsPathList => (
            "Create or delete an AS-path list.",
            "A named set of AS-path regular expressions a policy matches with `this.bgp.as_path in <name>`: the route matches if any pattern does. `edit` creates it if missing; `delete` removes it.",
        ),
        Topic::AsPathListPattern => (
            "Add or remove an AS-path list pattern.",
            "A regular expression matched against the AS path rendered as space-separated ASNs, where `_` matches the start, the end, or a space.",
        ),
        Topic::BgpPeerGroupMaximumPrefix => (
            "Limit how many prefixes a peer-group's peers may send, per address family.",
            "Takes an address family (`ipv4`, `ipv6`, `l2vpn-evpn`) then `limit <n>` and optionally \
             `warning-only` and `restart-interval <s>` (RFC 4486). Prefixes are counted per peer \
             after the import policy. Over the limit the session is closed with Cease/Maximum \
             Number of Prefixes Reached and the peer stays down until `clear bgp <instance> <peer>`, \
             a shutdown and un-shutdown, or the restart interval elapses. The family must be one \
             the peer-group negotiates. Changing it restarts the peer-group's sessions. \
             `delete maximum-prefix <family>` removes that family's limit.",
        ),
        Topic::BgpPeerGroupMaximumPrefixLimit => (
            "Set the most prefixes a peer may send in this address family.",
            "At least 1. One more accepted prefix than this trips the limit.",
        ),
        Topic::BgpPeerGroupMaximumPrefixWarningOnly => (
            "Only log when the maximum-prefix limit is exceeded.",
            "Logs a warning each time a peer crosses the limit instead of closing the session.",
        ),
        Topic::BgpPeerGroupMaximumPrefixRestartInterval => (
            "Retry a peer held down by its maximum-prefix limit after this many seconds.",
            "0 (the default) keeps the peer down until `clear bgp <instance> <peer>` or a \
             shutdown and un-shutdown.",
        ),
        Topic::BgpInstanceGracefulRestart => (
            "Tune or turn off a BGP instance's graceful restart (RFC 4724, RFC 8538).",
            "On by default. A peer that advertises graceful restart keeps its routes in use \
             across a session reset: they are marked stale until it comes back within \
             restart-time (default 120s, also what we advertise) and sends End-of-RIB, or \
             stale-time (default 180s) passes after it returns. selection-deferral-time (default \
             360s) bounds how long a restarting instance waits for its peers' End-of-RIB. \
             `disable` turns it off: no capability is advertised and nothing is kept. Changing \
             it restarts the instance's sessions.",
        ),
        Topic::BgpInstanceConfederation => (
            "Make a BGP instance a member of an RFC 5065 confederation.",
            "Takes `identifier <asn>` and `peer <asn>` (repeatable). With an identifier, the \
             instance's asn is its member AS: peers whose remote-as is a confederation peer are \
             confederation-external (AS_CONFED_SEQUENCE prepended, next hop, MED and LOCAL_PREF \
             kept as for iBGP), and peers outside the confederation see only the identifier, in \
             their OPEN and in AS_PATH. Changing it restarts the instance's sessions.",
        ),
        Topic::BgpInstanceConfederationIdentifier => (
            "Set the AS a confederation shows to peers outside it.",
            concat!(
                "A valid asn (1..=4294967294), different from the instance's own asn (its member \
             AS). Setting it is what makes the instance a confederation member.",
                " ",
                "Leave the confederation; the instance's asn is its AS to everyone again.",
            ),
        ),
        Topic::BgpInstanceConfederationPeer => (
            "Add another member AS of the confederation.",
            concat!(
                "A peer-group whose remote-as is listed here is confederation-external rather than \
             external. Must differ from the instance's asn and from the confederation identifier.",
                " ",
                "Remove a member AS from the confederation's peer list.",
            ),
        ),
        Topic::BgpInstanceRpkiCache => (
            "Take RPKI origin validation data from an RPKI-to-Router cache.",
            concat!(
                "`rpki-cache <address>`, then `port <n>` / `preference <n>` on it: the instance's nos-bgpd \
             connects to the cache over RFC 8210 (falling back to version 0) inside the \
             instance's VRF, and validates every received route's origin AS against the VRPs it \
             serves (RFC 6811). Only one cache is used at a time: the lowest preference that \
             answers. Validation changes nothing by itself: an import policy reads \
             `this.bgp.validation_state` (`rpki.valid`, `rpki.invalid`, `rpki.not_found`).",
                " ",
                "Stop using this RPKI cache.",
            ),
        ),
        Topic::BgpInstanceRpkiCachePort => (
            "Set the RPKI cache's TCP port.",
            "Defaults to 323, the IANA rpki-rtr port.",
        ),
        Topic::BgpInstanceRpkiCachePreference => (
            "Set the RPKI cache's preference.",
            "Lower is preferred (RFC 8210 §10); defaults to 0. A cache is used only while every \
             more preferred one is unreachable.",
        ),
        Topic::BgpInstanceAggregate => (
            "Originate an aggregate route covering more specific BGP routes.",
            concat!(
                "`aggregate-address <prefix>`: while at least one more specific route is in the \
             instance's Loc-RIB, nos-bgpd originates the prefix itself (RFC 4271 §9.2.2.2) with \
             the worst ORIGIN of its contributors, an AGGREGATOR of this instance's asn and \
             router-id, and ATOMIC_AGGREGATE when contributors' AS paths are dropped. It's \
             withdrawn when the last contributor goes. No discard route is installed in the \
             kernel.",
                " ",
                "Stop originating this aggregate.",
            ),
        ),
        Topic::BgpInstanceAggregateAsSet => (
            "Keep the contributors' AS numbers in the aggregate's AS_PATH.",
            "The path becomes the contributors' common leading AS_SEQUENCE followed by one AS_SET \
             of every other ASN (RFC 4271 Appendix F.6), instead of an empty path with \
             ATOMIC_AGGREGATE. A peer whose ASN is in the set rejects the aggregate as a loop.",
        ),
        Topic::BgpInstanceAggregateSummaryOnly => (
            "Advertise only the aggregate, not its more specific routes.",
            "While the aggregate is active, every route it covers is withdrawn from (or never \
             sent to) every peer. They're still installed in the kernel.",
        ),
        Topic::OspfAreaType => (
            "Make an OSPF area a stub, totally-stubby or not-so-stubby area.",
            concat!(
                "Sets area-type to normal, stub, totally-stubby, nssa or nssa-no-summary (RFC \
             2328 §3.6, RFC 3101). A stub area carries no AS-external LSAs and its Hellos have \
             the E-bit clear; an area border router sends a default summary route into it \
             instead. A totally-stubby area gets only that default, no other summary. An NSSA \
             also carries no AS-external LSA, but a router in it may still redistribute: its \
             routes travel as Type-7 LSAs, which one area border router translates into \
             AS-external LSAs for the rest of the network. nssa-no-summary is an NSSA that \
             gets only a default summary. Every router on the area's links must agree, or they \
             won't form adjacencies — changing it restarts the area's links. The backbone \
             (0.0.0.0) can't be any of them.",
                " ",
                "Reset the area to normal.",
            ),
        ),
        Topic::OspfAreaStubDefaultCost => (
            "Set the cost of the default route an ABR sends into this stub area.",
            concat!(
                "Sets stub-default-cost (1-65535) — the metric of the 0.0.0.0/0 default this \
             router originates into the area when it is an area border router. Only allowed \
             on a stub area or an NSSA.",
                " ",
                "Clear it, back to 1.",
            ),
        ),
        Topic::OspfAreaRange => (
            "Summarize this area's prefixes into one range (RFC 2328 §3.5).",
            concat!(
                "Adds an address range to the area. As an area border router, every prefix of \
             this area that falls inside the range is no longer summarized on its own into the \
             other areas: the range itself is, as one summary whose metric is the largest \
             covered cost, and a discard route for it is installed locally. With \
             not-advertise, the covered prefixes are hidden from the other areas entirely.",
                " ",
                "Remove an address range.",
            ),
        ),
        Topic::OspfAreaNssaTranslateAlways => (
            "Always translate this NSSA's Type-7 routes, as its area border router.",
            concat!(
                "Sets nssa-translate-always: this router translates the NSSA's Type-7 LSAs into \
             AS-external LSAs whenever it is one of the area's border routers, instead of only \
             when elected translator (the border router with the highest router id, RFC 3101 \
             §3.1). Only allowed on an NSSA.",
                " ",
                "Go back to translating only when elected.",
            ),
        ),
        Topic::OspfAreaNssaDefaultOriginate => (
            "Send a default route into this NSSA, as its area border router.",
            concat!(
                "Sets nssa-default-originate: as one of the NSSA's border routers, this router \
             originates a 0.0.0.0/0 Type-7 LSA into it (RFC 3101 §2.7), at stub-default-cost. \
             It is never translated out of the area. Only allowed on an NSSA.",
                " ",
                "Stop originating it.",
            ),
        ),
        Topic::OspfAreaRangeAdvertise => (
            "Hide every prefix an OSPF area range covers from the other areas.",
            concat!(
                "Sets not-advertise on a range: nothing it covers is summarized into the other \
             areas, and no discard route is installed for it.",
                " ",
                "Advertise the range again, as one summary.",
            ),
        ),
        Topic::BgpClearPeer => (
            "Reset one BGP peer's session.",
            "Releases a peer held down by its maximum-prefix limit so it can reconnect. A peer \
             with an established session is closed with Cease/Administrative Reset (RFC 4486) \
             and reconnects. Changes no configuration.",
        ),
        Topic::BgpPeerGroupAnnounceRpkiState => (
            "Exchange RPKI origin validation state with a peer-group's iBGP peers (RFC 8097).",
            concat!(
                "Every route advertised to these peers carries its validation state (valid, \
             not-found, invalid) as a non-transitive extended community, and a route received \
             from them takes its state from that community while this instance has no RPKI \
             data of its own (no rpki-cache, none synced yet, or expired). Requires an iBGP \
             peer-group, checked at commit time. Changing it restarts the peer-group's sessions.",
                " ",
                "Stop exchanging RPKI validation state with the peer-group's peers.",
            ),
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

    #[test]
    fn every_topic_has_non_empty_doc() {
        for &topic in Topic::ALL {
            let doc = command_doc(topic);
            assert_eq!(doc.topic, topic);
            assert!(!doc.summary.is_empty(), "{topic:?} has empty summary");
            assert!(!doc.detail.is_empty(), "{topic:?} has empty detail");
        }
    }
}
