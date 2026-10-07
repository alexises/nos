//! Kernel link-state table behind `InterfaceRequest::SubscribeLinks`.
//!
//! `LinkHub` is pure (no netlink): the Linux driver's watcher feeds it
//! decoded `RTM_NEWLINK`/`RTM_DELLINK` messages and dumps, the server calls
//! `watch()` per subscriber. Sends happen under the table lock, so a
//! subscriber's snapshot and its receiver can neither miss nor repeat an event.

use std::collections::BTreeMap;
use std::sync::Mutex;

use nos_proto::LinkState;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage, State};
use rtnetlink::packet_route::RouteNetlinkMessage;
use tokio::sync::broadcast;
use tracing::debug;

/// Production broadcast capacity; a slower subscriber gets a fresh snapshot.
pub const HUB_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    Changed(LinkState),
    Removed(String),
}

/// What `InterfaceDriver::watch_links` hands a subscriber. `rx: None` means
/// the driver never reports anything (noop): `observed` is then false.
pub struct LinkWatch {
    pub observed: bool,
    pub links: Vec<LinkState>,
    pub rx: Option<broadcast::Receiver<LinkEvent>>,
}

pub struct LinkHub {
    observed: bool,
    inner: Mutex<BTreeMap<String, LinkState>>,
    tx: broadcast::Sender<LinkEvent>,
}

impl LinkHub {
    pub fn new(capacity: usize) -> Self {
        Self {
            observed: true,
            inner: Mutex::new(BTreeMap::new()),
            tx: broadcast::channel(capacity).0,
        }
    }

    pub fn upsert(&self, link: LinkState) {
        let mut table = self.inner.lock().unwrap();
        if table.get(&link.name) == Some(&link) {
            return;
        }
        // A rename arrives as RTM_NEWLINK only: drop the old name.
        let stale: Vec<String> = table
            .values()
            .filter(|l| l.ifindex == link.ifindex && l.name != link.name)
            .map(|l| l.name.clone())
            .collect();
        for old in stale {
            table.remove(&old);
            debug!(name = %old, "link removed");
            let _ = self.tx.send(LinkEvent::Removed(old));
        }
        debug!(
            name = %link.name, ifindex = link.ifindex,
            admin_up = link.admin_up, carrier = link.carrier,
            "link state changed"
        );
        table.insert(link.name.clone(), link.clone());
        let _ = self.tx.send(LinkEvent::Changed(link));
    }

    pub fn remove(&self, name: &str) {
        let mut table = self.inner.lock().unwrap();
        if table.remove(name).is_some() {
            debug!(name = %name, "link removed");
            let _ = self.tx.send(LinkEvent::Removed(name.to_string()));
        }
    }

    /// A full dump: upsert each, drop every stored name not listed.
    pub fn replace_all(&self, links: Vec<LinkState>) {
        let keep: Vec<String> = links.iter().map(|l| l.name.clone()).collect();
        let gone: Vec<String> = {
            let table = self.inner.lock().unwrap();
            table
                .keys()
                .filter(|k| !keep.contains(k))
                .cloned()
                .collect()
        };
        for l in links {
            self.upsert(l);
        }
        for n in gone {
            self.remove(&n);
        }
    }

    pub fn watch(&self) -> LinkWatch {
        let table = self.inner.lock().unwrap();
        LinkWatch {
            observed: self.observed,
            links: table.values().cloned().collect(),
            rx: Some(self.tx.subscribe()),
        }
    }
}

pub enum Delta {
    Upsert(LinkState),
    Remove(String),
}

pub fn link_state(msg: &LinkMessage) -> Option<LinkState> {
    let name = msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(n) => Some(n.clone()),
        _ => None,
    })?;
    let oper = msg
        .attributes
        .iter()
        .find_map(|a| match a {
            LinkAttribute::OperState(s) => Some(*s),
            _ => None,
        })
        .unwrap_or(State::Unknown);
    Some(LinkState {
        name,
        ifindex: msg.header.index,
        admin_up: msg.header.flags.contains(LinkFlags::Up),
        carrier: msg.header.flags.contains(LinkFlags::LowerUp)
            && matches!(oper, State::Up | State::Unknown),
    })
}

pub fn decode(msg: NetlinkPayload<RouteNetlinkMessage>) -> Option<Delta> {
    match msg {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
            link_state(&m).map(Delta::Upsert)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(m)) => {
            link_state(&m).map(|l| Delta::Remove(l.name))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(name: Option<&str>, flags: LinkFlags, oper: Option<State>) -> LinkMessage {
        let mut m = LinkMessage::default();
        m.header.index = 7;
        m.header.flags = flags;
        if let Some(n) = name {
            m.attributes.push(LinkAttribute::IfName(n.into()));
        }
        if let Some(o) = oper {
            m.attributes.push(LinkAttribute::OperState(o));
        }
        m
    }

    fn l(name: &str, ifindex: u32, up: bool) -> LinkState {
        LinkState {
            name: name.into(),
            ifindex,
            admin_up: up,
            carrier: up,
        }
    }

    #[test]
    fn link_state_flags() {
        let up = LinkFlags::Up | LinkFlags::LowerUp;
        let s = link_state(&msg(Some("a"), up, Some(State::Up))).unwrap();
        assert!(s.admin_up && s.carrier && s.ifindex == 7);
        let s = link_state(&msg(Some("a"), LinkFlags::LowerUp, Some(State::Up))).unwrap();
        assert!(!s.admin_up && s.carrier);
        let s = link_state(&msg(Some("a"), LinkFlags::Up, Some(State::Up))).unwrap();
        assert!(s.admin_up && !s.carrier);
        let s = link_state(&msg(Some("a"), up, Some(State::Down))).unwrap();
        assert!(!s.carrier);
        assert!(
            link_state(&msg(Some("a"), up, Some(State::Unknown)))
                .unwrap()
                .carrier
        );
        assert!(link_state(&msg(Some("a"), up, None)).unwrap().carrier);
        assert!(link_state(&msg(None, up, None)).is_none());
    }

    #[test]
    fn decode_kinds() {
        let m = msg(Some("a"), LinkFlags::Up, None);
        let new = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m.clone()));
        assert!(matches!(decode(new), Some(Delta::Upsert(s)) if s.name == "a"));
        let del = NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(m));
        assert!(matches!(decode(del), Some(Delta::Remove(n)) if n == "a"));
        assert!(decode(NetlinkPayload::Noop).is_none());
    }

    #[test]
    fn hub_dedupes_changes_and_removes() {
        let hub = LinkHub::new(16);
        let mut rx = hub.watch().rx.unwrap();
        hub.upsert(l("a", 1, true));
        hub.upsert(l("a", 1, true));
        hub.upsert(l("a", 1, false));
        hub.remove("a");
        hub.remove("a");
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Changed(l("a", 1, true)));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Changed(l("a", 1, false)));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("a".into()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn hub_rename_removes_old_name() {
        let hub = LinkHub::new(16);
        hub.upsert(l("old", 3, true));
        let mut rx = hub.watch().rx.unwrap();
        hub.upsert(l("new", 3, true));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("old".into()));
        assert_eq!(
            rx.try_recv().unwrap(),
            LinkEvent::Changed(l("new", 3, true))
        );
        assert_eq!(hub.watch().links, vec![l("new", 3, true)]);
    }

    #[test]
    fn replace_all_emits_only_differences() {
        let hub = LinkHub::new(16);
        hub.replace_all(vec![l("a", 1, true), l("b", 2, true)]);
        let mut rx = hub.watch().rx.unwrap();
        hub.replace_all(vec![l("a", 1, true), l("c", 3, true)]);
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Changed(l("c", 3, true)));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Removed("b".into()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn watch_snapshot_then_later_events_only() {
        let hub = LinkHub::new(16);
        hub.upsert(l("a", 1, true));
        let w = hub.watch();
        assert!(w.observed);
        assert_eq!(w.links, vec![l("a", 1, true)]);
        let mut rx = w.rx.unwrap();
        assert!(rx.try_recv().is_err());
        hub.upsert(l("b", 2, true));
        assert_eq!(rx.try_recv().unwrap(), LinkEvent::Changed(l("b", 2, true)));
    }
}
