//! Generic netlink, only what `nos-acld`'s `log` needs (#544): resolving a
//! family (`CTRL_CMD_GETFAMILY`) and decoding psample's `PSAMPLE_CMD_SAMPLE`
//! multicasts. Pure; `socket.rs` does the I/O.

use std::io;

#[allow(clippy::wildcard_imports, reason = "the uapi constant table")]
use crate::consts::*;
use crate::decode::{attrs, bad, errno_of, find, u16_at, u32_at};
use crate::encode::{cstr, nla};

/// `struct nlmsghdr` + `struct genlmsghdr`.
const HEADER: usize = 16 + 4;

/// What `nos-acld` needs of the `psample` family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Psample {
    /// The family's netlink message type.
    pub family: u16,
    /// The `packets` multicast group.
    pub group: u32,
    /// The kernel knows `PSAMPLE_ATTR_USER_COOKIE` (Linux 6.11, with
    /// `act_sample` passing its action cookie): a sample names its filter.
    pub user_cookie: bool,
}

/// One sampled packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sample {
    /// The `act_sample` action's psample group.
    pub group: u32,
    pub in_ifindex: u32,
    pub out_ifindex: u32,
    /// The action's cookie, when the kernel passes it.
    pub cookie: Option<Vec<u8>>,
    /// The packet from its MAC header, truncated as the action says.
    pub data: Vec<u8>,
}

/// The `CTRL_CMD_GETFAMILY` request for `name`.
pub(crate) fn family_request(name: &str, seq: u32) -> Vec<u8> {
    let mut body = Vec::new();
    nla(&mut body, CTRL_ATTR_FAMILY_NAME, &cstr(name));
    let len = u32::try_from(HEADER + body.len()).unwrap();
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&GENL_ID_CTRL.to_ne_bytes());
    out.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    // genlmsghdr: cmd, version 1, reserved.
    out.extend_from_slice(&[CTRL_CMD_GETFAMILY, 1, 0, 0]);
    out.extend_from_slice(&body);
    out
}

/// Every netlink message of a received buffer.
fn messages(buf: &[u8]) -> io::Result<Vec<&[u8]>> {
    let mut v = Vec::new();
    let mut at = 0;
    while at + 16 <= buf.len() {
        let len = usize::try_from(u32_at(buf, at)).unwrap();
        if len < 16 || at + len > buf.len() {
            return Err(bad("truncated netlink message"));
        }
        v.push(&buf[at..at + len]);
        at += len.next_multiple_of(4);
    }
    Ok(v)
}

/// The reply to [`family_request`] for `psample`: an absent family is the
/// kernel's `ENOENT`, a family without the `packets` group `NotFound`.
pub(crate) fn psample_reply(buf: &[u8]) -> io::Result<Psample> {
    let msg = *messages(buf)?
        .first()
        .ok_or_else(|| bad("empty genl reply"))?;
    if u16_at(msg, 4) == NLMSG_ERROR {
        return Err(io::Error::from_raw_os_error(-errno_of(msg)?));
    }
    if msg.len() < HEADER {
        return Err(bad("short genl message"));
    }
    let a = attrs(&msg[HEADER..])?;
    let family = find(&a, CTRL_ATTR_FAMILY_ID)
        .filter(|v| v.len() >= 2)
        .map(|v| u16_at(v, 0))
        .ok_or_else(|| bad("no family id"))?;
    let max_attr = find(&a, CTRL_ATTR_MAXATTR)
        .filter(|v| v.len() >= 4)
        .map_or(0, |v| u32_at(v, 0));
    let mut group = None;
    for (_, g) in attrs(find(&a, CTRL_ATTR_MCAST_GROUPS).unwrap_or_default())? {
        let g = attrs(g)?;
        if find(&g, CTRL_ATTR_MCAST_GRP_NAME) == Some(b"packets\0") {
            group = find(&g, CTRL_ATTR_MCAST_GRP_ID)
                .filter(|v| v.len() >= 4)
                .map(|v| u32_at(v, 0));
        }
    }
    Ok(Psample {
        family,
        group: group.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no packets group"))?,
        user_cookie: max_attr >= u32::from(PSAMPLE_ATTR_USER_COOKIE),
    })
}

/// A `u16` or `u32` attribute (psample sends the ifindexes as `u16`).
fn uint(v: &[u8]) -> u32 {
    match v.len() {
        2 => u32::from(u16_at(v, 0)),
        4.. => u32_at(v, 0),
        _ => 0,
    }
}

/// The `PSAMPLE_CMD_SAMPLE` messages of family `family` in a buffer; others
/// (and unknown attributes) are skipped.
pub(crate) fn samples(buf: &[u8], family: u16) -> io::Result<Vec<Sample>> {
    let mut out = Vec::new();
    for msg in messages(buf)? {
        if u16_at(msg, 4) != family || msg.len() < HEADER || msg[16] != PSAMPLE_CMD_SAMPLE {
            continue;
        }
        let a = attrs(&msg[HEADER..])?;
        let get = |k| find(&a, k).map_or(0, uint);
        out.push(Sample {
            group: get(PSAMPLE_ATTR_SAMPLE_GROUP),
            in_ifindex: get(PSAMPLE_ATTR_IIFINDEX),
            out_ifindex: get(PSAMPLE_ATTR_OIFINDEX),
            cookie: find(&a, PSAMPLE_ATTR_USER_COOKIE).map(<[u8]>::to_vec),
            data: find(&a, PSAMPLE_ATTR_DATA).unwrap_or_default().to_vec(),
        });
    }
    Ok(out)
}

#[cfg(test)]
#[path = "genl_tests.rs"]
mod tests;
