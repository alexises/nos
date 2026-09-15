# BGP-4 / IPv6 (MP-BGP) implementation status

Snapshot as of commit `0022cb7` (RFC 4271 §9.1.2.2 best-path). Tracks what's
built vs. missing so follow-up sessions can pick items off this list instead
of re-auditing the codebase. Update this file as items are implemented.

**Caveat:** `bgp/CLAUDE.md`'s "Scope" section is stale — it says UPDATE/RIB
integration is out of scope, but commits `81f5fb5`→`0022cb7` added exactly
that plus IPv6, auth, and full best-path. The code is authoritative, not
that doc (worth fixing `bgp/CLAUDE.md` too, separately).

## Implemented

- **Transport/FSM**: VRF-scoped TCP, active+passive per RFC 4271, states
  `OpenSent`/`OpenConfirm`/`Established` (Idle/Connect/Active live in the
  retry loop, not as FSM states). OPEN validation, hold-timer reset,
  keepalive=hold/3.
- **Messages**: OPEN/UPDATE/KEEPALIVE/NOTIFICATION/ROUTE_REFRESH (RFC 2918,
  both directions — see `bgp/CLAUDE.md`'s "Route refresh" section).
- **Capabilities**: 4-byte ASN, MultiProtocol AFI/SAFI, Extended Next-Hop
  (RFC 8950), Route-Refresh (RFC 2918, code 2). Nothing else (no Graceful
  Restart/ADD-PATH/ORF capabilities).
- **Path attributes**: ORIGIN, AS_PATH (flattened, no SET/SEQUENCE
  distinction), NEXT_HOP, MED, LOCAL_PREF, MP_REACH/UNREACH_NLRI.
- **AFI/SAFI**: unicast v4+v6 only, SAFI hardcoded to 1.
- **RIB/best-path**: full RFC 4271 §9.1.2.2 ten-step process, correct
  MED/eBGP-iBGP tiebreaks; IGP-metric step is a documented no-op (no IGP
  exists). Adj-RIB-In/Out per peer, iBGP split-horizon (no reflection by
  design), loop prevention, next-hop self/unchanged, static redistribution.
- **Collision resolution**: real RFC 4271 §6.8, router-ID based.
- **Session auth**: RFC 2385 MD5 + RFC 5925 TCP-AO with key rotation.
- **Config/CLI**: peer-group/peer/instance fields as expected; `show bgp
  brief`, `clear bgp <instance> <peer> soft-in`.

## Not implemented (confirmed zero hits)

- **Messages/monitoring**: BMP.
- **Attributes**: ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES, EXTENDED
  COMMUNITIES, LARGE COMMUNITIES, ORIGINATOR_ID/CLUSTER_LIST,
  AS4_PATH/AS4_AGGREGATOR (moot — always native 4-byte).
- **Capabilities**: Graceful Restart, ADD-PATH, ORF, dynamic capability
  negotiation.
- **AFI/SAFI**: VPNv4/VPNv6/MPLS L3VPN, multicast, FlowSpec, EVPN.
- **Policy**: AS confederations, route reflection (by design), route
  dampening, and **no policy engine at all** — no route-maps/prefix-lists/
  AS-path or community filters, no import/export filtering.
- **Operational**: MRAI batching (UPDATEs sent immediately), prefix limits,
  dynamic peer-groups, BFD, GTSM/`ebgp-multihop`, `local-as`,
  `allow-as-in`, RIB-inspection CLI command.

## Partial / stubbed (dead code worth knowing about)

- `BadMessageType`/`UnsupportedOptionalParameter`/`CeaseSubcode::Other`
  enum variants exist but nothing ever constructs them — unrecognized
  types/params are silently ignored, not rejected.
- UPDATE errors collapse RFC 4271's ~9 subcodes into one
  `MalformedAttributeList`.
- AS_PATH never preserves SET vs SEQUENCE (decode flattens, encode always
  emits SEQUENCE) — affects best-path fidelity and blocks confederation
  support later.

## Priority note

Biggest real-world gap is the **complete absence of any policy engine**
(no route-maps/prefix-lists/communities) — everything else (graceful
restart, ADD-PATH, VPN AFIs) is advanced/optional by comparison.
