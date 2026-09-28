# The CLI (`nos`)

`nos` is the interactive shell. It is the main way people configure and inspect a NOS router. This page explains how to use it; the commands for each protocol are covered on the per-protocol pages.

- [Starting the shell and logging in](#starting-the-shell-and-logging-in)
- [The two modes](#the-two-modes)
- [A first configuration session](#a-first-configuration-session)
- [How configuration commands are built](#how-configuration-commands-are-built)
- [Navigating: `edit`, `up`, `top`](#navigating-edit-up-top)
- [Transaction commands](#transaction-commands)
- [Leaving the shell, and coming back](#leaving-the-shell-and-coming-back)
- [Getting help: `help`, `?` and Tab](#getting-help-help--and-tab)
- [Operational commands](#operational-commands)
- [Errors](#errors)

## Starting the shell and logging in

On a router started with `docker compose` from this repository:

```sh
docker compose run --rm cli          # the shell in its own container, sharing the router's /run/nos
docker exec -it nos-watchdog nos     # or: run it inside the router's own container
```

`nos` finds everything through the watchdog's socket (`--watchdog-socket`, default `/run/nos/watchdog.sock`). It trusts the internal CA certificate (`--pki-ca`, default `/run/nos/pki/ca.crt`). Both flags are needed only if you have moved those files.

The shell first asks for a user name and password:

```
login: e2e
password:
NOS interactive shell. Type 'help' for available commands, or press '?' at any point while typing.
edge-1>
```

The password is not echoed. After three wrong passwords the shell exits:

```
login incorrect
login: e2e
password:
login incorrect
Error: too many failed login attempts
```

If `nos-watchdogd` cannot be reached, the shell refuses to start: nothing works without a login. On a freshly installed router the only user is `admin`, password `admin`. See [Concepts: Users and logging in](concepts.md#users-and-logging-in).

## The two modes

The shell is in one of two modes, and the prompt shows which:

| Mode | Prompt | What you can do |
|---|---|---|
| operational | `edge-1>` | `show …` commands, `clear …`, `save`, and `configure` to enter configuration mode |
| configuration | `edge-1(doc2)>`, `edge-1(doc2/bgp:r1)>` | Everything above except `save` and `configure`, plus `edit`/`set`/`delete`, `show this`, `diff`, `commit`, `discard` |

`edge-1` is the router's `hostname`, so the prompt changes when a commit changes it. In configuration mode the part in parentheses is the transaction name, followed by where you are in the config tree (see [Navigating](#navigating-edit-up-top)).

Commands that belong to the other mode are refused:

```
lab-1> set hostname x
error: not in configuration mode — use 'configure <name>' first
```

## A first configuration session

This session changes the hostname and adds a static route to an existing static routing instance `s1`, which feeds routing table `rt1`:

```
edge-1> configure doc2
edge-1(doc2)> set hostname lab-1
edge-1(doc2)> edit static-routing-instance s1
edge-1(doc2/static-routing-instance:s1)> set route 198.51.100.0/24 gateway 10.50.0.3
edge-1(doc2/static-routing-instance:s1)> show this
static-routing-instance s1
  route 192.0.2.0/24: gateway 10.50.0.3
  route 198.51.100.0/24: gateway 10.50.0.3
edge-1(doc2/static-routing-instance:s1)> top
edge-1(doc2)> diff
- hostname: edge-1
+ hostname: lab-1
  static-routing-instance s1:
+   route 198.51.100.0/24:
+     gateway: 10.50.0.3
edge-1(doc2)> commit
transaction 'doc2' committed
lab-1> show route rt1 198.51.100.7
198.51.100.0/24
  * via 10.50.0.3 [static]
lab-1> save
configuration saved
```

Step by step:

1. `configure doc2` opens a transaction named `doc2`, starting as a copy of the running config.
2. `set` and `edit` change the transaction only. The router is not affected yet.
3. `show this` and `diff` let you check the result before it goes live.
4. `commit` validates the transaction and makes it the running config. The prompt now shows the new hostname, and the route is live straight away.
5. `save` writes the running config to disk so it survives a restart. A commit does not do this.

## How configuration commands are built

Three verbs change configuration:

| Verb | Meaning |
|---|---|
| `edit <object>` | Create the object if it does not exist, and move into it (see [Navigating](#navigating-edit-up-top)). |
| `set <object> <field> <value>` | Set a field, or add an element to a list, such as an address or a route. The object must already exist; create it with `edit` first. |
| `delete <object> [<field>]` | Remove an object, a list element, or a field. A removed field goes back to its default. |

Every `set`/`delete` command has two spellings:

- the **absolute** form names the whole path from the top of the tree, and works from anywhere in configuration mode:
  `set bgp instance r1 peer-group pg1 hold-time 30`
- the **relative** form leaves out the path you have already navigated into:
  `set hold-time 30` (while at `edge-1(doc3/bgp:r1/peer-group:pg1)>`)

The two are exactly equivalent. Use absolute forms in scripts and runbooks, since they don't depend on where the shell is; relative forms are shorter when typing.

Tokens must match exactly. There are no abbreviations and no case folding: `sh conf` or `SHOW CONFIG` is an unknown command. Values are passed through as typed and checked at commit.

Interfaces have one naming rule of their own: `<interface>.<tag>` names a VLAN subinterface, for example `edit interface eth0.100`. A plain `eth0` in an address or routing-table command means its untagged subinterface, `eth0.0`. Interface-level settings such as `mtu` and `switching-profile` apply to `eth0` itself.

## Navigating: `edit`, `up`, `top`

`edit` moves you into an object; the prompt shows the path:

```
lab-1(doc3)> edit bgp instance r1
lab-1(doc3/bgp:r1)> edit peer-group pg1
lab-1(doc3/bgp:r1/peer-group:pg1)> set keepalive-interval 10
lab-1(doc3/bgp:r1/peer-group:pg1)> show this
peer-group pg1: remote-as 65002, source-address unset, address-family [ipv4], hold-time 30, keepalive-interval 10, connect-retry-time 3, auth none, next-hop default (self, eBGP)
lab-1(doc3/bgp:r1/peer-group:pg1)> up
lab-1(doc3/bgp:r1)> up
lab-1(doc3)>
```

| Command | Effect |
|---|---|
| `edit <object>` | Create the object if needed, then move into it. |
| `up` | Go up one level. |
| `top` | Go straight back to the top of the transaction. |
| `show this` | Show the object you are in, or the whole transaction when you are at the top. |
| `delete` (on its own) | Delete the object you are in, and move to its parent. |

Where `edit` can go:

| Object | Nested objects |
|---|---|
| `bgp instance <name>` | `peer-group <group>` |
| `ospf instance <name>`, `ospfv3 instance <name>` | `area <area-id>`, then `profile <name>` |
| `interface <name>` | `interface <name>.<tag>` (a subinterface) |
| `routing-table`, `static-routing-instance`, `broadcast domain`, `switching-profile`, `port-aggregate`, `policy-definition`, `community-alias`, `community-group`, `as-path-list`, `prefix-list` | none |

## Transaction commands

| Command | Mode | What it does |
|---|---|---|
| `configure <name> [from blank\|current]` | operational | Open transaction `<name>`, or resume it if it already exists (the shell prints `resuming transaction '<name>'`). A new transaction starts from the running config (`current`, the default) or empty (`blank`). |
| `show this` | configuration | Show the current object, or the whole transaction. A transaction with edits is labelled `(uncommitted changes)`. |
| `diff` | configuration | Show what committing would change compared with the running config: `-` removed, `+` added, with unchanged enclosing sections shown for context. |
| `commit` | configuration | Validate and apply. If it succeeds you are back in operational mode. If it fails, the errors are printed and you stay in the transaction. |
| `discard`, `abort` | configuration | Delete the transaction. The running config is not touched. |
| `save` | operational | Write the running config to `/var/lib/nos/config.yaml`. |

A failed commit leaves everything as it was, so you can fix the problem and commit again:

```
lab-1(doc3)> set routing-table rt1 bgp-instance nope
lab-1(doc3)> commit
error: nos-configd reported an error: validation failed:
routing_tables[0].bgp_instance: referenced bgp instance does not exist
 (transaction left open — fix and retry)
lab-1(doc3)> diff
  bgp instance r1:
    peer-group pg1:
-     hold-time: default (90s)
+     hold-time: 30
-     keepalive-interval: default (hold-time / 3)
+     keepalive-interval: 10
  routing-table rt1:
-   bgp-instance: r1
+   bgp-instance: nope
lab-1(doc3)> discard
transaction 'doc3' discarded
```

## Leaving the shell, and coming back

`exit`, `quit` and `end` all do the same thing:

- In operational mode they leave the shell.
- In configuration mode they return to operational mode. If the transaction has uncommitted changes, the shell asks first:

```
lab-1(shared)> exit
Transaction 'shared' has uncommitted changes. [c]ommit / [d]iscard / [l]eave open (default): l
transaction 'shared' left open on the daemon — resume with 'configure shared'
```

Transactions are kept by the router, not by the shell. Ctrl-C, a closed terminal or a dropped connection therefore never loses one: it stays open. Log in again and `configure <same name>` to carry on:

```
lab-1> configure doc4
resuming transaction 'doc4'
lab-1(doc4)> show this
transaction 'doc4' (uncommitted changes):
hostname: draft
…
```

## Getting help: `help`, `?` and Tab

- **`help`** lists every command valid right now (in this mode, at this position in the tree), each with a one-line summary:
  ```
  lab-1> help
  Available commands:
    show config                                   Show the daemon's current running configuration.
    show route <table>                            Show every route in a routing table, best to worst per prefix.
    show route <table> <address>                  Look up the best route(s) for one destination address.
    …
    configure <name> [from blank|current]         Open or resume a named, server-held in-progress configuration.
  ```
- **`?`**, pressed at any point while typing, shows the commands that can complete what you have typed so far, with their syntax and summary. It does not submit the line. Press it a second time for the full description. Press Enter to close the list without running anything.
- **Tab** completes keywords. Where a command expects the name of an existing object (BGP instance, peer-group, routing table, interface, and so on), it also offers the names in your transaction.

The descriptions come from the router itself (`nos-configd`), so they match the version you are running.

Known gap: some commands work but are not yet listed by `help`, `?` or Tab. These are the routing-policy objects (`policy-definition`, `prefix-list`, `community-alias`, `community-group`, `as-path-list`), `import-policy`/`export-policy` on a peer-group, the damping parameters, and `redistribute … policy`. The per-protocol pages document them; issue #109 tracks adding them to the help.

## Operational commands

These work in both modes and never change anything, except `clear`. The REST equivalent of each is in [CLI ↔ API mapping](cli-api-mapping.md#operational-commands).

| Command | Shows |
|---|---|
| `show config` | The whole running config. |
| `show route <table>` | Every prefix in a routing table, with every candidate route best first; `*` marks the selected one. |
| `show route <table> <address>` | The longest-prefix match for one address. |
| `show interface [<name>]` | What `nos-interfaced` has actually applied: addresses, routing table, MTU, per subinterface. |
| `show port-aggregate [<name>]` | Bonds and their members. |
| `show lacp [<name>]` | LACP state per member port of each `lacp`-mode aggregate. |
| `show lldp neighbors` | Every LLDP neighbour heard, on every interface. |
| `show bgp brief` | One line per BGP peer across every instance: state, remote AS, uptime, negotiated hold time. |
| `show bgp evpn` | EVPN routes received from BGP peers. |
| `show ospf neigh`, `show ospfv3 neigh` | OSPF/OSPFv3 neighbours and their state. |
| `show ospf database`, `show ospfv3 database` | The LSA headers in each LSDB. |
| `show fdb <domain>` | An EVPN broadcast domain's MAC table and flood list. |
| `show log [<source>] [--follow]` | Collected log entries, all sources or just one (see [Concepts: Logs](concepts.md#logs)). With `--follow` it keeps printing new entries until Ctrl-C. |
| `clear bgp <instance> <peer> soft-in` | Ask a live BGP session to resend its routes (an RFC 2918 route refresh). Configuration is not changed. |

Examples from a running router:

```
lab-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:02:21 hold-time 90
lab-1> show interface
interface eth0: address [none], routing-table unset, switching-profile unset, mtu 1500
  subinterface 0: address [10.50.0.2/24], routing-table rt1
lab-1> show log nos-configd
2026-09-28T18:51:42.627Z  INFO nos-configd nos_config::persistence: loaded config from disk (path=/var/lib/nos/config.yaml)
2026-09-28T18:51:42.704Z  INFO nos-configd nos_config::server: config IPC server listening (listen=unix:/run/nos/config.sock)
…
```

When the process behind a `show` command is not running, for example an instance that was just deleted, the shell says so for that instance and still shows the rest.

## Errors

| Message | Meaning |
|---|---|
| `error: unknown command: '…' (type 'help' for a list)` | No command matches these exact tokens. Check spelling and argument count with `?`. |
| `error: not in configuration mode — use 'configure <name>' first` | You used a configuration command in operational mode. |
| `error: nos-configd reported an error: edit failed: bgp instance 'r7' not found` | `set` on an object that does not exist yet. Create it with `edit` first. |
| `error: nos-configd reported an error: validation failed: …` | The commit was refused. Each line gives the path in the tree and the reason. The transaction is still open. |
