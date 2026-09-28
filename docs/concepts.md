# Concepts

This page explains the ideas the rest of the documentation relies on. It covers what runs on a NOS router, how configuration moves from an edit to the kernel, what a routing table is, and how users and certificates work. None of it is specific to the CLI or the REST API; both behave exactly as described here.

- [What runs on a router](#what-runs-on-a-router)
- [The configuration tree](#the-configuration-tree)
- [Running config, transactions and the saved file](#running-config-transactions-and-the-saved-file)
- [Named transactions](#named-transactions)
- [Validation](#validation)
- [Routing tables are VRFs](#routing-tables-are-vrfs)
- [Users and logging in](#users-and-logging-in)
- [Certificates and encryption](#certificates-and-encryption)
- [Logs](#logs)
- [Glossary](#glossary)

## What runs on a router

A NOS router is a set of cooperating processes, one per job, rather than one big routing daemon. You never start or stop them yourself. `nos-watchdogd` starts all of them, restarts any that crash, and starts or stops per-instance processes as your configuration changes. For example, committing a new BGP instance starts a new `nos-bgpd` for it; deleting the instance stops it.

| Process | How many | What it does |
|---|---|---|
| `nos-watchdogd` | 1 | Supervises every other process. It is also the internal certificate authority and the login service: it checks passwords and issues certificates. |
| `nos-configd` | 1 | Holds the configuration: the running config, every open transaction, and the saved file. Every change goes through it. |
| `nos-bgpd` | one per BGP instance | BGP sessions, route selection and advertisement for one instance. |
| `nos-ribd` | one per routing table | The routing table itself: picks the best route per prefix among connected, static, BGP and OSPF, and installs it into the kernel VRF it creates. |
| `nos-ospfd` / `nos-ospfv3d` | one per OSPF / OSPFv3 instance | Neighbour discovery, adjacencies, LSDB, SPF. |
| `nos-interfaced` | 1 | Applies interface configuration to the kernel: addresses, VRF membership, MTU, VLAN subinterfaces, bridges, bonds. |
| `nos-lacpd` | 1 | LACP negotiation for `lacp`-mode port aggregates. |
| `nos-lldpd` | 1 | LLDP transmit/receive on interfaces that enable it. |
| `nos-fdbd` | one per broadcast domain with a `vni` | The VXLAN device and forwarding database for one EVPN domain. |
| `nos-restd` | one per routing table with `rest-api` set | The REST API. It runs only where you enable it. |
| `nos-logd` | 1 | Collects log entries from every other process; `show log` and `/v1/logs` read from it. |

Two things follow from this design:

- **A problem in one instance stays in that instance.** If one BGP instance's process crashes, it is restarted on its own and other instances keep running. When `show bgp brief` finds an instance whose process is not up, it reports that instance as not running and still shows the others.
- **Configuration changes never need a restart.** Each process watches the configuration sections it cares about and adjusts itself when a commit changes them.

The shell (`nos`) and the REST API (`nos-restd`) are both just *clients*. They read the running config from `nos-configd`, edit transactions there, and query the other processes for operational state (`show …`). Neither holds state of its own. This is why the two are fully interchangeable. See [CLI ↔ API mapping](cli-api-mapping.md).

## The configuration tree

The whole router configuration is one tree. At the top are these sections; each section except `hostname` and `lldp` is a list of named objects:

| Section (CLI keyword / REST path segment) | What it holds |
|---|---|
| `hostname` | The router's name, shown in the shell prompt. Default `nos`. |
| `user` | Local users and their password hashes. |
| `routing-table` | Routing tables (VRFs), and what feeds each one: a BGP instance, an OSPF instance, an OSPFv3 instance, a static routing instance, redistribution, and the REST API. |
| `bgp-instance` | BGP instances (ASN, router-id), with their peer-groups and peers. |
| `ospf-instance`, `ospfv3-instance` | OSPF instances, with their areas and the interface profiles inside each area. |
| `static-routing-instance` | Named sets of static routes. |
| `interface` | Physical interfaces and loopbacks, with their subinterfaces, addresses and attachments. |
| `broadcast-domain`, `switching-profile` | L2 domains (bridges) and how interfaces are trunked into them. |
| `port-aggregate` | Bonds, static (`xor`) or negotiated (`lacp`). |
| `policy-definition`, `prefix-list`, `community-alias`, `community-group`, `as-path-list` | Routing policy: scripts, and the named lists the scripts refer to. |
| `lldp` | System-wide LLDP timers and management address. |

The CLI and the REST API name things the same way. In the CLI you write `routing-table rt1`; the REST API has the URL `…/routing-table/rt1`. Objects refer to each other **by name**: a routing table says `bgp-instance r1`, an interface says `routing-table rt1`. A reference to something that does not exist is rejected when you commit (see [Validation](#validation)).

`show config` in the shell prints the whole running tree. `GET /v1/config` returns it as JSON.

## Running config, transactions and the saved file

There are three copies of the configuration to keep in mind:

```
   edit (set / delete / PUT)        commit                 save
 ───────────────────────────► transaction ──────► running config ──────► /var/lib/nos/config.yaml
                              (named, held       (what every daemon      (loaded at startup)
                               in nos-configd)    applies, live)
```

- The **running config** is what the router is doing right now. The only way to change it is to commit a transaction.
- A **transaction** is a named working copy that you edit. Nothing you do inside a transaction has any effect on the router until you commit it.
- The **saved config**, `/var/lib/nos/config.yaml`, is what `nos-configd` loads at startup. **A commit does not save.** Committed changes are live immediately, but they are lost when the router restarts unless you run `save` in the shell afterwards. The REST API has no save operation (see [CLI ↔ API mapping](cli-api-mapping.md#operations-with-no-counterpart)).

A commit is **atomic**: the new running config replaces the old one in one step, and every process sees the whole change at once. You never get a half-applied set of edits.

## Named transactions

Transactions live in `nos-configd`, not in your shell session or HTTP connection. You refer to one by its name. This has some useful consequences:

- **Opening a transaction that already exists resumes it.** `configure lab` in the shell, or `POST /v1/transactions/lab` over REST, creates `lab` if it does not exist. If it does exist, you continue from its current state.
- **A dropped connection loses nothing.** Leave the shell, lose your SSH session, or kill the client, and the transaction stays on the router until someone commits or discards it.
- **The CLI and the REST API can work on the same transaction.** Start it in the shell, check it with a script over REST, and commit it from either. [CLI ↔ API mapping](cli-api-mapping.md#one-transaction-two-front-ends) shows this with real output.
- **You choose the starting point.** A new transaction starts as a copy of the running config (`current`, the default) or empty (`blank`). Starting blank and committing would replace the whole configuration, so use `blank` only when you really want to replace everything.

A transaction ends in one of two ways:

- **commit**: the transaction is validated. If it is valid, it becomes the running config and the transaction is deleted. If it is not, nothing changes and the transaction stays open so you can fix it.
- **discard** (`discard` or `abort` in the shell, `DELETE /v1/transactions/<name>` over REST): the transaction is deleted and the running config is untouched.

Every transaction has a **generation number**. It starts at 0 when the transaction is opened and increases by one with every edit. The REST API returns it as the `ETag` header. A client can send it back to say "apply this only if nobody else has edited the transaction since I last looked" (see [The REST API](api.md#concurrent-edits-etag-and-if-match)).

## Validation

An edit is refused on the spot only when the object it changes does not exist yet, for example `set` on a BGP instance nobody has created. Everything else is checked for the whole transaction when you commit. This lets you make changes in any order, for example making a routing table refer to a BGP instance before you create that instance, as long as the end result is consistent. The commit checks cover:

- values: ranges, address formats, names;
- references between objects (a routing table naming a BGP instance that does not exist);
- rules that span sections, for example an interface cannot both be in a routing table and be an untagged member of a switching profile, and at least one user must remain.

A failed commit reports every problem it found, each prefixed with its path in the tree:

```
edge-1(doc3)> commit
error: nos-configd reported an error: validation failed:
routing_tables[0].bgp_instance: referenced bgp instance does not exist
 (transaction left open — fix and retry)
```

The REST API returns the same text in a `422 Unprocessable Entity` response (see [The REST API](api.md#errors)). You can use `diff` (or `GET /v1/transactions/<name>/diff`) at any time, even on a transaction that would fail validation, to see what it changes.

## Routing tables are VRFs

A **routing table** in NOS is a Linux VRF. When you commit a routing table, its `nos-ribd` creates the kernel VRF device and routing table for it. Everything that deals in layer 3 refers to a routing table:

- `set routing-table rt1 bgp-instance r1` makes BGP instance `r1` feed its best routes into `rt1`. The BGP sessions of `r1` also run inside `rt1`'s VRF.
- `set routing-table rt1 ospf-instance o1`, `ospfv3-instance …` and `static-routing-instance …` do the same for OSPF, OSPFv3 and static routes.
- `set interface eth0 routing-table rt1` puts `eth0` (strictly, its untagged subinterface `eth0.0`) into the VRF. Its addresses then produce **connected** routes in `rt1`.
- `set routing-table rt1 rest-api address 10.50.0.2` starts the REST API inside `rt1`'s VRF, listening on that one address.

A BGP instance must be linked to a routing table to open any session at all. NOS has no implicit "default VRF": a BGP instance that no routing table refers to only logs an error. Each prefix in a routing table can have several candidate routes from different sources. `show route <table>` lists all of them, best first, and marks the selected one with `*`:

```
lab-1> show route rt1
10.50.0.0/24
  * via 10.50.0.2 [connected]
192.0.2.0/24
  * via 10.50.0.3 [static]
```

## Users and logging in

- Every local user is a full administrator. There are no roles or per-command permissions.
- Passwords are stored only as argon2id hashes. You enter a clear password (`set user alice password …`) and `nos-configd` hashes it as it is applied. `show config` shows only the user names.
- A commit that would leave no users at all is refused. On first boot, with no users configured, NOS creates `admin` with password `admin`. Add your own user, then delete or change `admin`.
- Both the shell and the REST API log in through `nos-watchdogd`, which checks the password against the running config. The shell allows 3 attempts, then exits. The REST API makes each failed attempt cost one second, and after 5 failures within 60 seconds it refuses further logins for that user for a while (HTTP 429).
- Deleting a user takes effect immediately, even for sessions that are already logged in. A REST client presenting that user's certificate is refused on its next request.

## Certificates and encryption

Every connection on the router is mutually authenticated TLS 1.3, with post-quantum key exchange (hybrid `X25519MLKEM768`). That includes connections between the NOS processes themselves, the shell's connections to them, and REST clients. There is no unencrypted fallback. `nos-watchdogd` is the certificate authority, and in practice it runs two:

| CA | Public certificate | Used for |
|---|---|---|
| internal CA | `/run/nos/pki/ca.crt` | Every process and the `nos` shell. Keys are ML-DSA-65. |
| REST CA | `/run/nos/pki/rest-ca.crt` | The REST API's server certificate and every REST client certificate. Keys are ECDSA P-256, so browsers and standard tools can use them. |

What this means for you:

- **Logging in gives you a certificate, not a session cookie.** The shell or REST client generates a key pair and sends the login request with the public key. The watchdog checks the password and returns a certificate for that key, naming the user (`nos://user/<name>`). The private key never leaves the client. The shell does all of this invisibly. REST clients do it once with `POST /v1/login` (see [The REST API](api.md#getting-a-client-certificate)).
- **User certificates are short-lived**: 8 hours by default (`nos-watchdogd --pki-user-lifetime`). The shell renews its own at half-life. A REST client renews with `POST /v1/renew`, which needs no password.
- **Trusting the REST API means copying `rest-ca.crt` from the router.** Copy it by some channel you already trust, such as `docker cp` or your provisioning system. NOS deliberately never serves it over the network: anyone able to intercept that download could also capture the login password.
- **The CAs are created fresh every time `nos-watchdogd` starts.** After a restart, copy `rest-ca.crt` again and log in again.

## Logs

Every NOS process sends its log entries to `nos-logd`, which keeps the most recent 10,000 on disk. Each entry has a timestamp, a level, a source, a target (the code module) and a message with fields. The source is the process name; per-instance processes add the instance name in brackets:

```
nos-watchdogd   nos-configd   nos-interfaced   nos-lacpd   nos-lldpd   nos-restd
nos-bgpd[r1]    nos-ribd[rt1]
```

`show log [<source>] [--follow]` in the shell, and `GET /v1/logs` / `GET /v1/logs/follow` over REST, read this buffer and can follow new entries as they arrive.

## Glossary

| Term | Meaning |
|---|---|
| running config | The configuration currently in effect. Only a commit changes it. |
| transaction | A named, server-held working copy of the configuration. See [Named transactions](#named-transactions). |
| generation | A transaction's edit counter. Over REST it is the `ETag`. |
| commit | Validate a transaction and make it the running config. |
| save | Write the running config to `/var/lib/nos/config.yaml`, so it survives a restart. |
| routing table | A Linux VRF plus the routes NOS computes for it. |
| instance | One BGP/OSPF/OSPFv3/static-routing configuration object. Each dynamic protocol instance runs as its own process. |
| attach point | Something a protocol profile or routing table is attached to: an interface's subinterface, a loopback, or a broadcast domain's own bridge (an SVI). |
| operational state | What the router is actually doing (sessions, neighbours, routes, MACs), as opposed to what is configured. Read with `show …` or `GET /v1/…`. |
