# nos-rest — REST API daemon (`nos-restd`)

An HTTP+JSON management API for the whole system: every `nos-cli` `show` query and the full transaction/config-editing surface. One process per `RoutingTable` that has `rest-api` pinned to it, listening on **one configured address inside that table's VRF**. **There is no authentication** — the VRF and the pinned address are the only access boundary, so pin it to a management address.

## Pinning and supervision

`RoutingTable.rest_api: Option<RestApi { address, port }>` (`set routing-table <t> rest-api address <ip> [port <n>]`). `nos-watchdogd` runs `nos-restd --table <name>` for every table that has it set, via the same `instances::manage` as `nos-ribd`/`nos-bgpd`/`nos-ospfd`, with one addition: `Managed.claim_label`. The other families spawn a process per section; this one is *opt-in per table*, and a field flip on an existing table is a `Modified` diff (a no-op for the others), so the watchdog keys on the `rest-api` `FieldDiff` (`nos_proto::diff::routing_table::REST_API_LABEL`): a value other than `"unset"` spawns, `"unset"`/removal stops. It has no IPC query listener, so `Managed.endpoint` is `None` (no `--listen-socket`, no registry entry).

## Listening (`listen.rs`)

Every 1s tick — and immediately on a routing-table config diff — `Listener` compares what config *wants* (this table's `rest_api`) with what is *bound* and converges:

- the VRF name comes from the owning `nos-ribd` (`ServiceRef::RibTable` + `RibRequest::GetVrfName`), exactly like `nos-bgpd`; `None` means "not created yet" and is retried;
- the socket is bound to `address:port` (no wildcard) with `SO_BINDTODEVICE=<vrf>` (a per-crate copy of `nos-bgpd`'s `tcp::bind_listener`);
- an address that isn't configured on an interface in the VRF yet (`EADDRNOTAVAIL`) is a transient state, retried each tick and logged once per change (`rest api not listening yet: …`);
- a changed address/port, or a VRF that was deleted and recreated under the same name (its `nos-ribd` restarted — detected by the device's `ifindex` changing, since `SO_BINDTODEVICE` resolves the name once), drops and rebinds the listener;
- a `nos-configd` read failure keeps the current listener rather than tearing it down.

Log lines the e2e phase greps: `rest api listening table=… vrf=… address=… port=…`, `rest api stopped listening`, `rest api not listening yet: …`.

## Endpoints (`/v1`, see `api.rs`)

Show (GET, the daemon's own reply payload as JSON): `/config`, `/routes/{table}[/{addr}]`, `/interfaces[/{name}]`, `/port-aggregates[/{name}]`, `/lacp[/{name}]`, `/lldp/neighbors`, `/logs?source=&limit=`, `/logs/follow?source=&limit=` (`show log --follow` as Server-Sent Events: the backlog — trimmed to `limit` — then each new entry as an `event: log` whose data is the JSON `LogEntry`, until the client disconnects; the daemon-side `Tail` connection's write half is held open for the stream's lifetime), `/bgp/summary`, `/ospf/{neighbors,database}`, `/ospfv3/{neighbors,database}`. The router-wide ones (`bgp`/`ospf`/`ospfv3`) iterate the instances in the running config and report a per-instance `"not running"` instead of failing, like `nos-cli`. A daemon that isn't reachable is `503`. **Actions** (`clear.rs`, `POST`, change live state never config): `/bgp/{instance}/peer/{peer}/soft-in` = `clear bgp <instance> <peer> soft-in` — asks the live session for an RFC 2918 ROUTE-REFRESH; 404 if the peer isn't configured or has no `Established` session (the daemon doesn't distinguish the two), 503 if that instance's `nos-bgpd` isn't running.

**Transactions — the config tree is the URL tree:**

| | |
|---|---|
| `POST /transactions/<tx>?base=blank\|current` | open or resume (201 / 200) |
| `GET` / `PUT` / `DELETE /transactions/<tx>` | whole in-progress config / set the whole config / discard |
| `GET` / `PUT` / `DELETE /transactions/<tx>/<path>` | read / set / remove one subsection |
| `GET /transactions/<tx>/diff`, `POST …/commit` | diff vs running; validate + commit (422 on a validation error, transaction kept) |

`<path>` is e.g. `hostname`, `routing-table/rt1`, `bgp-instance/r1/peer-group/pg1`, `ospf-instance/o1/area/0.0.0.0/profile/p1`, `static-routing-instance/s1/route/10.1.0.0%2F16`. The grammar lives in `nos_proto::config_path` (segment = kebab-case field name, a list field is followed by the element's key; a `PUT` to a list element that doesn't exist appends it; the body's key must match the URL). `diff` and `commit` are static routes and therefore reserved first segments. The handlers split the **raw** URI path before percent-decoding, so a key containing `/` stays one segment. The server-side edit is one new `nos-configd` request, `Request::SetTransactionPath` — atomic under the transactions lock, all-or-nothing (the edited JSON must still deserialize as a `Config`), and, like every op, unvalidated until commit.

## OpenAPI (`openapi.rs`)

`GET /openapi.json`, browsable at `/swagger-ui/` (`utoipa-swagger-ui` with the `vendored` feature: assets are embedded in the binary, so there is no CDN dependency at runtime or GitHub download at build; it is pointed at the `/openapi.json` route rather than given a `utoipa` struct, so it shows the generated config-tree paths too). Show and transaction-root operations are `#[utoipa::path]`-annotated and registered with `routes!`, so the router and the spec can't disagree. The config-tree paths are **generated** by walking the `Config` schema (the router serves them all with one `{*path}` route) using `config_path::{field_segment, key_field}` — the same naming and key rules the server resolves paths with; the walker debug-asserts `field_matches` for every path it emits and tests check every parameter is declared and every `$ref` resolves. `nos-proto`'s `openapi` feature adds `ToSchema` derives (off unless `nos-rest` is built); `IpAddr`/`IpNet` fields carry `schema(value_type = String)`, and the recursive `SectionDiff.subsections` needs `schema(no_recursion)`. Adding a config section needs no OpenAPI work; adding a *show* endpoint needs a `#[utoipa::path]` and a `routes!` line.

## Testing

`tests/api.rs` drives the real router (via `tower::ServiceExt::oneshot`) against a **real** `nos-config` `ConfigStore` behind its own IPC server — so the path-set semantics tested are the shipped ones — plus a fake broker and fake `nos-ribd`. The listener itself needs `CAP_NET_RAW` and a VRF, so it is covered only by `tools/verify-e2e.sh rest`.
