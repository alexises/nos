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
        Topic::EnsureBgpInstance => (
            "Create a BGP instance in the transaction if it doesn't already exist.",
            "Adds a new BGP instance with the given name to the transaction's in-progress \
             config if none exists with that name yet; if one already exists, this is a \
             no-op. Does not itself set any fields on the instance.",
        ),
        Topic::SetBgpInstanceAsn => (
            "Set a BGP instance's autonomous system number.",
            "Sets the ASN field on a BGP instance in the transaction's in-progress config. \
             Must be a valid, non-reserved 32-bit ASN; validity is checked at commit time, \
             not when the edit is applied.",
        ),
        Topic::SetBgpInstanceRouterId => (
            "Set a BGP instance's router ID.",
            "Sets the router-id field on a BGP instance in the transaction's in-progress \
             config. A router ID is a 32-bit identifier written in dotted-quad notation — \
             the same notation an IPv4 address uses, but it is not itself a routable \
             address and need not correspond to one. Validity is checked at commit time, \
             not when the edit is applied.",
        ),
        Topic::DeleteBgpInstance => (
            "Delete a BGP instance from the transaction.",
            "Removes a BGP instance and all of its fields from the transaction's \
             in-progress config. Only affects that transaction — the running config is \
             untouched until commit.",
        ),
        Topic::SetHostname => (
            "Set the configuration's hostname.",
            "Sets the top-level hostname field in the transaction's in-progress config. \
             Unlike BGP instance fields, hostname has no navigation context — it's a single \
             top-level scalar.",
        ),
        Topic::EnsureBgpPeerGroup => (
            "Create a peer-group in a BGP instance if it doesn't already exist.",
            "Adds a new peer-group with the given name to the named BGP instance's \
             peer-groups in the transaction's in-progress config, if none exists with that \
             name yet; if one already exists, this is a no-op. Does not itself set any \
             fields on the peer-group.",
        ),
        Topic::SetBgpPeerGroupRemoteAs => (
            "Set a peer-group's remote autonomous system number.",
            "Sets the remote-as field on a peer-group. Must be a valid, non-reserved 32-bit \
             ASN; validity is checked at commit time, not when the edit is applied.",
        ),
        Topic::SetBgpPeerGroupSourceAddress => (
            "Set a peer-group's transport source address.",
            "Sets the source-address field on a peer-group — the local address BGP uses to \
             establish sessions in this group. This is independent of which address \
             families the group exchanges: an IPv6 source-address may still carry IPv4 \
             unicast routes over the session (RFC 8950 extended next-hop encoding), so \
             source-address and address-family are never cross-validated against each \
             other.",
        ),
        Topic::ClearBgpPeerGroupSourceAddress => (
            "Clear a peer-group's transport source address.",
            "Unsets the source-address field on a peer-group, reverting to no explicit \
             transport source override.",
        ),
        Topic::AddBgpPeerGroupAddressFamily => (
            "Add an address family to a peer-group.",
            "Adds one AFI/SAFI (ipv4 or ipv6 unicast) to the set exchanged over this \
             peer-group's session. A no-op if it's already present. At least one address \
             family is required for the peer-group to be valid; checked at commit time.",
        ),
        Topic::RemoveBgpPeerGroupAddressFamily => (
            "Remove an address family from a peer-group.",
            "Removes one AFI/SAFI from the set exchanged over this peer-group's session. A \
             no-op if it's already absent. Removing the last remaining address family \
             leaves the peer-group invalid until another is added; checked at commit time.",
        ),
        Topic::DeleteBgpPeerGroup => (
            "Delete a peer-group from a BGP instance.",
            "Removes a peer-group and all of its fields from the named BGP instance in the \
             transaction's in-progress config. Any peer still referencing this peer-group \
             becomes invalid — checked at commit time, not when the peer-group is deleted.",
        ),
        Topic::SetBgpPeer => (
            "Associate a remote address with a peer-group.",
            "Creates the association between a remote address and a peer-group within a \
             BGP instance if it doesn't exist yet, or repoints it to a different peer-group \
             if it does. The referenced peer-group must exist for the config to be valid; \
             checked at commit time.",
        ),
        Topic::DeleteBgpPeer => (
            "Remove a peer's association to its peer-group.",
            "Deletes the remote-address-to-peer-group association from the named BGP \
             instance in the transaction's in-progress config.",
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
    const ALL_TOPICS: &[Topic] = &[
        Topic::ShowRunningConfig,
        Topic::Save,
        Topic::OpenTransaction,
        Topic::GetTransaction,
        Topic::CommitTransaction,
        Topic::DiscardTransaction,
        Topic::DiffTransaction,
        Topic::EnsureBgpInstance,
        Topic::SetBgpInstanceAsn,
        Topic::SetBgpInstanceRouterId,
        Topic::DeleteBgpInstance,
        Topic::SetHostname,
        Topic::EnsureBgpPeerGroup,
        Topic::SetBgpPeerGroupRemoteAs,
        Topic::SetBgpPeerGroupSourceAddress,
        Topic::ClearBgpPeerGroupSourceAddress,
        Topic::AddBgpPeerGroupAddressFamily,
        Topic::RemoveBgpPeerGroupAddressFamily,
        Topic::DeleteBgpPeerGroup,
        Topic::SetBgpPeer,
        Topic::DeleteBgpPeer,
    ];

    #[test]
    fn every_topic_has_non_empty_doc() {
        for &topic in ALL_TOPICS {
            let doc = command_doc(topic);
            assert_eq!(doc.topic, topic);
            assert!(!doc.summary.is_empty(), "{topic:?} has empty summary");
            assert!(!doc.detail.is_empty(), "{topic:?} has empty detail");
        }
    }
}
