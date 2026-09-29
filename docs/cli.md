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

`nos` needs no options on a standard router. It has two, `--watchdog-socket` (default `/run/nos/watchdog.sock`) and `--pki-ca` (default `/run/nos/pki/ca.crt`), for the case where those files have been moved.

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

If the router's login service cannot be reached, the shell refuses to start: nothing works without a login. On a freshly installed router the only user is `admin`, password `admin`. See [Concepts: Users and logging in](concepts.md#users-and-logging-in).

## The two modes

The shell is always in one of two modes, and the prompt shows which.

In **operational mode** the prompt is just the hostname, such as `edge-1>`. Here you look at the router with `show …`, act on live sessions with `clear …`, write the running config to disk with `save`, and enter configuration mode with `configure`.

In **configuration mode** the prompt adds the transaction name and your position in the config tree, such as `edge-1(doc2)>` or `edge-1(doc2/bgp-instance:r1)>`. Here you change the transaction with `edit`, `set` and `delete`, inspect it with `show this` and `diff`, and finish with `commit` or `discard`. The `show` commands still work; `save` and `configure` do not.

`edge-1` is the router's `hostname`, so the prompt changes when a commit changes it.

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

- `edit <object>` creates the object if it does not exist, and moves into it (see [Navigating](#navigating-edit-up-top)).
- `set <object> <field> <value>` sets a field, or adds an element to a list such as an address or a route. An object on the way that does not exist yet is created with its defaults, like `edit` would.
- `delete <object> [<field>]` removes an object, a list element or a field. A removed field goes back to its default.

Every `set`/`delete` command has two spellings:

- the **absolute** form names the whole path from the top of the tree, and works from anywhere in configuration mode:
  `set bgp instance r1 peer-group pg1 hold-time 30`
- the **relative** form leaves out the path you have already navigated into:
  `set hold-time 30` (while at `edge-1(doc3/bgp-instance:r1/peer-group:pg1)>`)

The two are exactly equivalent. Use absolute forms in scripts and runbooks, since they don't depend on where the shell is; relative forms are shorter when typing.

Tokens must match exactly. There are no abbreviations and no case folding: `sh conf` or `SHOW CONFIG` is an unknown command. Values are checked for their type when you type them (a number, an address, one of a field's options); everything else is checked at commit.

Every object and field also accepts its REST API spelling, so `set bgp-instance r1 asn 65001` is the same command as `set bgp instance r1 asn 65001`. `help`, `?` and Tab always show the shell spelling. The prompt shows your position in the REST spelling: `edge-1(doc3/bgp-instance:r1/peer-group:pg1)>`.

Interfaces have one naming rule of their own: `<interface>.<tag>` names a VLAN subinterface, for example `edit interface eth0.100`. A plain `eth0` in an address or routing-table command means its untagged subinterface, `eth0.0`. Interface-level settings such as `mtu` and `switching-profile` apply to `eth0` itself.

## Navigating: `edit`, `up`, `top`

`edit` moves you into an object; the prompt shows the path:

```
lab-1(doc3)> edit bgp instance r1
lab-1(doc3/bgp-instance:r1)> edit peer-group pg1
lab-1(doc3/bgp-instance:r1/peer-group:pg1)> set keepalive-interval 10
lab-1(doc3/bgp-instance:r1/peer-group:pg1)> show this
peer-group pg1: remote-as 65002, source-address unset, address-family [ipv4], hold-time 30, keepalive-interval 10, connect-retry-time 3, auth none, next-hop default (self, eBGP), import-policy default (deny-all), export-policy default (deny-all)
lab-1(doc3/bgp-instance:r1/peer-group:pg1)> up
lab-1(doc3/bgp-instance:r1)> up
lab-1(doc3)>
```

`up` goes back one level and `top` goes straight back to the top of the transaction. `show this` shows the object you are in, or the whole transaction when you are at the top. `delete` on its own deletes the object you are in and moves you to its parent.

Most objects are a single level deep. Three have objects nested inside them. A BGP instance contains peer-groups (`edit peer-group <group>`). An OSPF or OSPFv3 instance contains areas (`edit area <area-id>`), and each area contains interface profiles (`edit profile <name>`). A physical interface contains VLAN subinterfaces, which you reach as `edit interface <name>.<tag>`.

## Transaction commands

`configure <name>` opens the transaction `<name>`, or resumes it if it already exists; the shell then prints `resuming transaction '<name>'`. A new transaction starts as a copy of the running config. Add `from blank` to start it empty instead (`from current` is the default).

In the transaction, `show this` shows your current object or the whole transaction, labelled `(uncommitted changes)` once you have edited it. `diff` shows what a commit would change: `-` for removed lines, `+` for added ones, with the enclosing section names for context.

`commit` validates the transaction and applies it. If it succeeds, you are back in operational mode. If it fails, the errors are printed and you stay in the transaction. `discard` (or `abort`) deletes the transaction without touching the running config.

Back in operational mode, `save` writes the running config to `/var/lib/nos/config.yaml` so it survives a restart.

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
    configure <name>                              Open or resume a named, server-held in-progress configuration.
    configure <name> from blank                   Open or resume a named, server-held in-progress configuration.
  ```
  In configuration mode the list goes on with every `edit`, `set` and `delete` you can type from where you are, object by object, in the order of the config tree.
- **`?`**, pressed at any point while typing, shows what can come next after what you have typed so far, with its syntax and summary. It does not submit the line. Press it a second time for the full description. Press Enter to close the list without running anything.
- **Tab** completes keywords, a field's options (such as `next-hop self|unchanged`) and, where a command names an existing object (BGP instance, peer-group, routing table, interface, and so on), the names in your transaction.

The descriptions come from the router itself, so they always match the version you are running. Configuration commands are generated from the router's configuration schema, so every configuration field is always listed, documented and completed.

## Operational commands

These work in both modes. Only `clear` acts on anything, and it never changes configuration. The REST equivalent of each is in [CLI ↔ API mapping](cli-api-mapping.md#operational-commands).

- `show config`: the whole running config.
- `show route <table>`: every prefix in a routing table, with every candidate route best first; `*` marks the one in use. `show route <table> <address>` looks up the longest-prefix match for one address.
- `show interface [<name>]`: what is actually applied to each interface and subinterface: addresses, routing table, MTU.
- `show port-aggregate [<name>]` and `show lacp [<name>]`: bonds, their members, and LACP negotiation state.
- `show lldp neighbors`: every LLDP neighbour heard, on every interface.
- `show bgp brief`: one line per BGP peer across every instance, with state, remote AS, uptime and hold time. `show bgp evpn` lists received EVPN routes.
- `show ospf neigh` and `show ospf database`, and their `ospfv3` counterparts: neighbours and their state, and the LSA headers in each LSDB.
- `show fdb <domain>`: an EVPN broadcast domain's MAC table and flood list.
- `show log [<source>] [--follow]`: the router's log, all sources or just one (see [Concepts: Logs](concepts.md#logs)). With `--follow` it keeps printing new entries until Ctrl-C.
- `clear bgp <instance> <peer> soft-in`: ask a live BGP session to resend its routes (an RFC 2918 route refresh).

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

If one instance cannot answer, for example because it was just deleted, the shell says so for that instance and still shows the rest.

## Errors

- `error: unknown command: '…' (type 'help' for a list)`: no command matches these exact words. Check spelling and the number of arguments with `?`.
- `error: not in configuration mode — use 'configure <name>' first`: you used a configuration command in operational mode.
- `error: '…' is not a valid edit here (press ? to see what fits)`: no field or object matches these words, or a value has the wrong type, at your position or from the top of the tree. Type the start of the line and press `?`.
- `error: nos-configd reported an error: validation failed: …`: the commit was refused. Each line gives the place in the tree and the reason. The transaction is still open.
