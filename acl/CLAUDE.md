# nos-acl — access lists on tc (`nos-acld`)

A single fixed process (like `nos-stpd`): every `acl in`/`acl out` on an `Interface`, `Subinterface` or `PortAggregate` becomes tc flower filters on that kernel device. Stateless: no conntrack (`established` is "ACK or RST set").

## Flow

- `reconcile.rs`: `SubscribeDiff` on `Acls`/`Interfaces`/`PortAggregates` is only a trigger; every diff (and a 10 s tick) re-fetches the config into a `plan::Plan`.
- `plan.rs` (pure): `Compiler` compiles each ACL once per change (logs `compiled acl acl= rules= filters= levels= shadowed=`, the e2e anchor); a failed compile keeps the last good one (fail closed). `attachments` lists every attach point as a `Device` (`Kernel(name)` or `Aggregate { name, tag }`).
- `link_client.rs`: `nos-interfaced`'s `SubscribeLinks` stream, reimplemented per crate. Until a snapshot with `observed: true` arrives nothing is applied (a `noop` interfaced never gives one).
- `engine.rs`: per (device, direction) holds `{ifindex, chain, compiled}`; a pass resolves devices (a bond through `LinkState.port_aggregate`, never by deriving `bond<id>`), detaches what is no longer wanted, installs what changed. Driver calls block: a pass runs on `spawn_blocking`, the engine moved in and out.
- `compile/` (pure): `compile(&Acl) -> Compiled { levels, default_action, rules, shadowed }`; one rule = one level today. `rule.rs` splits by family (prefix family, else `icmp` v4 / `icmpv6` v6, else both) and `established` into two filters (ACK, RST).
- `driver/`: `Driver` trait (`live_chain`, `install`, `switch`, `flush`, `detach`), `noop.rs` (records calls, tests), `linux.rs` (only `nos-tc` calls; coverage-excluded). Request building (`chain_requests`, `entry_request`, `live_from`) is pure, in `driver/mod.rs`.

## Kernel layout (details: `docs/architecture/linux-drivers.md`)

- Chain 0, prio `ACL_PRIO` 100, handle 1: keyless flower `goto chain` 1000/1001; its gact cookie is the live chain (read back on start).
- Rule `i`: prios `2i+1` (`ip`) and `2i+2` (`ipv6`): the kernel refuses two protocols at one prio. Defaults: one keyless filter per family after the rules. Cookies: rule index, `u32::MAX` for defaults (#543 reads them).
- Update = install idle chain, replace entry (`NLM_F_REPLACE`), flush old. Flush tolerates `ENOENT`/`EINVAL`.
- Never delete the `clsact` qdisc; stay off other owners' priorities (`tc/CLAUDE.md`).

## Rules that bite

- Fail closed: a crash leaves filters enforcing; on start the first link snapshot is swept (chain-0 dump per device and hook) and what a previous run left is adopted, then replaced or detached. A refused install flushes the idle chain and keeps the old one live; retried on the next pass.
- An attach point whose device is absent logs `acl pending interface= direction= acl= reason="absent"` once and applies when the link shows up. A device that disappears is dropped without driver calls (its qdisc went with it).
- The untagged (tag 0) subinterface is its parent's device: the commit refuses both setting one direction (`schema::acl::one_per_device`).
- `log` is not implemented (#544): one `warn!(acl, rule, "acl log not supported yet")` per compile.
- L4 keys never match non-first fragments (`ponytail:` in `compile/rule.rs`).
- No listen socket yet: `show acl` (#543) adds `--listen-socket` and `ServiceRef::Acl`; the watchdog passes none (`fixed_args(None, ..)`).

## Tests

- Unit: compile shapes, plan resolution, engine with `NoopDriver` (attach, A/B alternation, pending device, sweep, refused install, shutdown), request bytes via `nos-tc` types.
- Kernel: `unshare -Urn cargo test -p nos-acl --test kernel -- --ignored` (`tc` as the oracle; a foreign prio-1 filter survives).
- e2e: `cargo run -p nos-e2e -- acl` (group `drivers`): attach, `?before=` drops BGP, `?after=` restores it, detach.

Out of scope here: optimiser (#542), `show acl` and counters (#543), `log` (#544).
