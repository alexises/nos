# NOS user documentation

This is the operator's documentation for NOS: how to log in, configure the router and read its state back. You can do all of that from the interactive shell (`nos`) or from the REST API. The two are equivalent: whatever you can configure in one, you can configure in the other, and they share the same transactions.

It is written for network engineers who know BGP, OSPF, VLANs and VRFs, but not NOS. How NOS is built internally is documented in [`CLAUDE.md`](../CLAUDE.md), not here.

## Start here

Read these in order the first time:

1. **[Concepts](concepts.md)**: how configuration works (the running config, named transactions, commit, save), what a routing table is, users and login, and where the logs are. Everything else assumes this page.
2. **[The CLI](cli.md)**: logging in to the `nos` shell, operational vs configuration mode, navigating the config tree, the transaction commands, `help` / `?` / Tab, and every `show` command.
3. **[The REST API](api.md)**: enabling the API, getting a client certificate, the config tree as URLs, transactions with `ETag`/`If-Match`, errors, the live log stream, and the OpenAPI document.
4. **[CLI ↔ API mapping](cli-api-mapping.md)**: the REST equivalent of every CLI operation, how a `set` command becomes a URL, and one change done both ways.

## Reference material

- The OpenAPI 3 document for the REST API is checked in as [`openapi.json`](openapi.json). A running router serves the same document at `https://<address>:<port>/openapi.json`, and a browsable explorer at `https://<address>:<port>/swagger-ui/` (see [The REST API](api.md#the-openapi-document)).
- Every shell command has built-in help: type `help`, or press `?` while typing (see [The CLI](cli.md#getting-help-help--and-tab)).

`openapi.json` is regenerated from the code and checked by a test, so it always matches what `nos-restd` serves. After changing the API, run `make docs-fix` to update it.

## Per-protocol guides

Each protocol and feature gets its own page with four parts: what it is and what it's for; how to do the common operations, in both the CLI and REST; the features and how they behave; and a complete configuration reference with every field, its CLI command, its REST path, its type, default and validation rules.

These pages are being written as part of issue #107. The planned set:

- BGP: instances, peer-groups, timers, MRAI, damping, GTSM, MD5 and TCP-AO authentication, route reflection, route servers
- Routing policy: the RPL language, prefix lists, community aliases and groups, AS-path lists
- OSPFv2 and OSPFv3
- Routing tables, static routes and redistribution
- Interfaces, subinterfaces and loopbacks
- L2 switching: broadcast domains, switching profiles and SVIs
- Port aggregation and LACP
- LLDP
- EVPN/VXLAN, including multi-homing
- System: hostname, users, the REST API and logs

Until they are written, the configuration commands for each area are listed by `help` in configuration mode (see [The CLI](cli.md)). The REST paths are in [`openapi.json`](openapi.json).

## Conventions used in these pages

- Shell transcripts show the prompt the shell actually prints, such as `edge-1(doc2)>`. Type what follows the `>`.
- Placeholders are in angle brackets: `<name>`, `<table>`, `<cidr>`. Optional parts are in square brackets: `[port <port>]`. `a|b` means one of the two literal keywords.
- REST examples use `curl`, with these two shell variables set as shown in [The REST API](api.md#a-complete-session-with-curl):
  ```sh
  B=https://10.50.0.2:8080
  C="curl -sS --cacert rest-ca.crt --cert cert.pem --key key.pem"
  ```
- The outputs shown were captured from real routers running the `nos:local` image: the two-router lab `cargo run -p nos-e2e -- up` builds (router-a at 10.50.0.2, AS 65001, BGP-peered with router-b at 10.50.0.3, AS 65002). Timestamps, uptimes and certificate bytes will differ on your router.
