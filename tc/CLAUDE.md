# nos-tc — hand-encoded Linux tc

A leaf crate (only `netlink-sys`, no NOS dependencies, like `nos-l2-socket`): the tc messages `netlink-packet-route` cannot build (`gact`, `skbedit`, `fw`, chains, action cookies, stats dumps), encoded by hand and sent on a plain `NETLINK_ROUTE` socket. Used by `nos-fdbd` (EVPN local bias), `nos-interfaced` (STP BPDU trap) and `nos-acld` (#541).

## API

- `Request`: `Clsact { ifindex }` (exclusive: tolerate `EEXIST`), `AddFilter(Filter)`, `DelFilter { .., prio, protocol, handle }` (`handle == 0` deletes the whole priority), `FlushChain` (`RTM_DELCHAIN`: every filter of the chain goes; `ENOENT` if it has none).
- `Filter { ifindex, hook, chain, prio, protocol, handle, kind, actions, replace }`:
  - `chain == 0` sends **no** `TCA_CHAIN`, so the fdb/interfaced messages stay byte-identical.
  - `replace` adds `NLM_F_REPLACE`: the same handle at the same chain/prio is swapped in place (one RCU swap).
  - `Protocol::Ip`/`Ipv6` also send `TCA_FLOWER_KEY_ETH_TYPE`: flower ignores every L3 key without it.
  - `Kind::Flower(FlowerKeys)` (all `None` = match-all; a keyless flower, not `matchall`, because only flower replaces in place) or `Kind::Fw { mask }`.
  - An exact port (`min == max`) uses the `TCP_*`/`UDP_*` key (needs `ip_proto` 6 or 17); a range uses `PORT_*_MIN/MAX` (the kernel wants min below max).
- `Action { kind, cookie }`: `Gact(Verdict)` or `Skbedit { mark, mask, verdict }`; `Verdict::GotoChain(n)` is `TC_ACT_GOTO_CHAIN | n`, `n < 2^28`. A cookie is at most 16 bytes.
- `encode` refuses (`InvalidInput`) what the kernel would reject less clearly: long cookie, chain ≥ 2^28, inverted range, exact port without tcp/udp, prefix too long.
- `send(&Request, tolerate)` and `dump(ifindex, hook, chain) -> Vec<FilterStats>` **block**: call them from `spawn_blocking`.
- `FilterStats`: one row per **action** (`chain, prio, handle, action, cookie, packets, bytes`); `TCA_STATS_PKT64` wins over the 32-bit `gnet_stats_basic` count. A missing chain dumps as an empty list.

## Priorities in use (chain 0, first match wins)

| Owner | Hook | Prio | What |
|---|---|---|---|
| `nos-fdbd` | VXLAN ingress | 1, 2 | `flower enc_src_ip` + `skbedit mark` (peers, catch-all) |
| `nos-fdbd` | segment port egress | 1, 2 | `fw` + `gact drop` (local bias, DF) |
| `nos-interfaced` | bridge port ingress | 1 | `flower dst_mac` + `gact drop`, protocol 802.2 |
| `nos-acld` (#541) | ingress/egress | 100 | keyless flower `goto chain` 1000/1001 |

- Nobody deletes the `clsact` qdisc: every owner only ensures it.
- Delete only your own priorities (or chains).

## Files

- `consts.rs`: uapi values, grouped by header; private (N2 of #545).
- `encode.rs` (pure): types, `encode`, `dump_request`. Tests in `encode_tests.rs`, including the golden bytes of the former fdb/interfaced encoders.
- `decode.rs` (pure): `ack`, `dump_part`. Tests in `decode_tests.rs`, including a captured kernel dump reply.
- `socket.rs`: the only I/O, a fresh socket per call.

## Adding a key or an action

1. The constant in `consts.rs`, under its header's group, value from the header (not memory).
2. A field on `FlowerKeys` (or an `ActionKind` variant), encoded in `flower`/`action`; validate in `check` if the kernel can refuse it.
3. A byte test in `encode_tests.rs`, and a case in `tests/kernel.rs` read back with `tc filter show`.

## Kernel test

- `unshare -Urn cargo test -p nos-tc --test kernel -- --ignored` (needs `ip`, `tc`).
- With `NOS_TC_CAPTURE=1 ... --nocapture` it prints `DUMP_REPLY <hex>`, the source of `decode_tests.rs`'s fixture.
