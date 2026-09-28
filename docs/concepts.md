# Concepts

This page covers the handful of ideas you need before configuring a NOS router. They apply equally to the shell and the REST API.

- [The configuration tree](#the-configuration-tree)
- [Running config, transactions and the saved file](#running-config-transactions-and-the-saved-file)
- [Working with transactions](#working-with-transactions)
- [Validation](#validation)
- [Routing tables are VRFs](#routing-tables-are-vrfs)
- [Users and logging in](#users-and-logging-in)
- [Logs](#logs)

For how NOS is built internally, see [`CLAUDE.md`](../CLAUDE.md) at the root of the repository. You don't need it to operate a router.

## The configuration tree

The whole router configuration is one tree, and the shell and the REST API name its parts the same way. What the shell calls `routing-table rt1`, the REST API reaches at `…/routing-table/rt1`. At the top of the tree are these sections:

- `hostname`: the router's name, also shown in the shell prompt. It defaults to `nos`.
- `user`: the local users who may log in.
- `routing-table`: routing tables, and what feeds each of them (see [Routing tables are VRFs](#routing-tables-are-vrfs)).
- `bgp-instance`, `ospf-instance`, `ospfv3-instance`, `static-routing-instance`: the routing protocols and static routes.
- `interface`: physical interfaces and loopbacks, their VLAN subinterfaces and addresses.
- `broadcast-domain`, `switching-profile`, `port-aggregate`: L2 bridging, VLAN trunking and bonds.
- `policy-definition`, `prefix-list`, `community-alias`, `community-group`, `as-path-list`: routing policy.
- `lldp`: system-wide LLDP settings.

Objects refer to each other by name. A routing table says `bgp-instance r1`; an interface says `routing-table rt1`. Referring to something that does not exist is an error, reported when you commit.

To see the whole running tree, use `show config` in the shell or `GET /v1/config` over REST.

## Running config, transactions and the saved file

Three copies of the configuration matter:

```
   edit (set / delete / PUT)        commit                 save
 ───────────────────────────► transaction ──────► running config ──────► /var/lib/nos/config.yaml
```

The **running config** is what the router is doing right now. The only way to change it is to commit a transaction.

A **transaction** is a named working copy that you edit. Nothing you change in a transaction affects the router until you commit it. A commit is atomic: the whole set of changes goes live together, never half of it.

The **saved config** is the file the router loads when it starts. **Committing does not save.** Your changes are live as soon as you commit, but they are lost at the next restart unless you also run `save` in the shell. The REST API has no save operation (see [CLI ↔ API mapping](cli-api-mapping.md#operations-with-no-counterpart)).

## Working with transactions

You open a transaction by giving it a name: `configure lab` in the shell, or `POST /v1/transactions/lab` over REST. A new transaction starts as a copy of the running config. You can also start it empty (`from blank`, or `?base=blank`), but committing an empty transaction replaces the entire configuration, so do that only when you mean it.

Transactions are kept on the router, not in your shell session or HTTP connection. Opening a name that already exists resumes that transaction where it was left. So a closed terminal or a dropped connection loses nothing: log in again and open the same name. The CLI and the REST API can also work on the same transaction. You can start it in the shell and commit it from a script, as shown in [CLI ↔ API mapping](cli-api-mapping.md#one-transaction-two-front-ends).

A transaction ends in one of two ways. **Commit** validates it; if it is valid it becomes the running config and the transaction disappears, and if not, nothing changes and the transaction stays open for you to fix. **Discard** throws it away and leaves the running config untouched. Before either, `diff` shows exactly what a commit would change.

Each edit to a transaction increases its generation number. The REST API returns this number as an `ETag`, which a script can use to avoid overwriting someone else's edits (see [The REST API](api.md#concurrent-edits-etag-and-if-match)).

## Validation

An edit is refused on the spot only when it targets an object that does not exist yet. For example, `set bgp instance r7 asn 65007` fails until `r7` has been created with `edit`. Everything else is checked across the whole transaction when you commit: value ranges and formats, references between objects, and rules that span sections. One such rule: an interface cannot both belong to a routing table and be an untagged member of a switching profile. Another: at least one user must remain. Because checking happens at commit, you can make related changes in any order.

A refused commit lists every problem, each with its place in the tree, and leaves the transaction open:

```
edge-1(doc3)> commit
error: nos-configd reported an error: validation failed:
routing_tables[0].bgp_instance: referenced bgp instance does not exist
 (transaction left open — fix and retry)
```

Over REST, the same text comes back in a `422` response.

## Routing tables are VRFs

A routing table is a VRF. Everything that deals with layer 3 is attached to one, and NOS has no implicit default VRF: a BGP instance that no routing table refers to does not open any session.

- `set routing-table rt1 bgp-instance r1` runs BGP instance `r1` inside `rt1` and installs its best routes there. `ospf-instance`, `ospfv3-instance` and `static-routing-instance` do the same for OSPF, OSPFv3 and static routes.
- `set interface eth0 routing-table rt1` puts the interface (its untagged subinterface, `eth0.0`) into `rt1`. Its addresses then appear in the table as connected routes.
- `set routing-table rt1 rest-api address 10.50.0.2` turns on the REST API inside `rt1`, on that one address.

A prefix can have several candidate routes from different sources. `show route <table>` lists them all, best first, and marks the one in use with `*`:

```
lab-1> show route rt1
10.50.0.0/24
  * via 10.50.0.2 [connected]
192.0.2.0/24
  * via 10.50.0.3 [static]
```

## Users and logging in

Every local user is a full administrator; there are no roles. You set a password in clear (`set user alice password s3cret`, or the same over REST). The router stores only a hash, and `show config` shows only user names. A commit that would remove the last user is refused. A new router has one user, `admin`, with password `admin`. Add your own user, then change or remove `admin`.

The shell asks for your user name and password when it starts, and gives up after three wrong attempts. REST clients log in once with `POST /v1/login` and receive a client certificate, which they present on every later request. After five failed REST logins for one user within a minute, logins for that user are refused for a while. Certificates last 8 hours; the shell renews its own, and REST clients renew with `POST /v1/renew` (see [The REST API](api.md#getting-a-client-certificate)).

Deleting a user takes effect immediately, even for someone who is already logged in.

All connections are encrypted with TLS 1.3 and a post-quantum key exchange. For the REST API, a client must trust the router's REST certificate authority, `/run/nos/pki/rest-ca.crt`. Copy it from the router over a channel you already trust; it is never served over the network. It changes whenever the router restarts, so copy it again after a restart.

## Logs

The router keeps its most recent 10,000 log entries. Each entry names its source. Instance-specific sources carry the instance name in brackets, such as `nos-bgpd[r1]` for BGP instance `r1` or `nos-ribd[rt1]` for routing table `rt1`. General ones are named `nos-configd`, `nos-restd`, `nos-interfaced` and so on.

- In the shell, `show log` shows the buffer, `show log <source>` shows one source, and `--follow` keeps printing new entries.
- Over REST, use `GET /v1/logs` and `GET /v1/logs/follow` (see [The REST API](api.md#following-the-log-server-sent-events)).
