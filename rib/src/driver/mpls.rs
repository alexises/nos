//! The kernel MPLS pieces of L3VPN (#581) that need no netlink socket: label
//! checks, the `AF_MPLS` pop route, reading a route's pushed labels back, and
//! the `net.mpls` sysctls (plain `/proc/sys` file I/O, no external command,
//! #228). `LinuxRibDriver` sends what these build; kept out of `linux.rs` so
//! it counts toward `COVERAGE_MIN`.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use rtnetlink::packet_route::route::{
    MplsLabel, RouteAddress, RouteAttribute, RouteLwTunnelEncap, RouteMessage, RouteMplsIpTunnel,
};
use rtnetlink::RouteMessageBuilder;

use super::DriverError;

/// What `RibDriver::sync_mpls` programs for a table with `vpn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mpls {
    /// The VRF's label: pop, then an IP lookup in the VRF.
    pub label: u32,
    /// The underlay table (`vpn.bgp_instance`'s): its interfaces receive the
    /// labelled packets, and an imported route's PE next hop leaves over one
    /// of them.
    pub underlay: Option<String>,
}

/// The largest 20-bit label; `net.mpls.platform_labels` tops out here too.
pub const MAX_LABEL: u32 = (1 << 20) - 1;

/// Labels 0-15 are reserved (RFC 3032 section 2.1): refused even though
/// config validation already does, defence in depth.
pub fn check_label(label: u32) -> Result<(), DriverError> {
    if (16..MAX_LABEL).contains(&label) {
        Ok(())
    } else {
        Err(DriverError::Other(format!(
            "mpls label {label} is outside 16..{MAX_LABEL}"
        )))
    }
}

/// A label stack as the kernel takes it: bottom-of-stack on the last entry
/// only, TTL and traffic class zero (it refuses anything else).
pub fn stack(labels: &[u32]) -> Vec<MplsLabel> {
    labels
        .iter()
        .enumerate()
        .map(|(i, &label)| MplsLabel {
            label,
            traffic_class: 0,
            bottom_of_stack: i + 1 == labels.len(),
            ttl: 0,
        })
        .collect()
}

/// `<label> dev <vrf>`: pop and look the payload up in the VRF's table. One
/// route serves IPv4 and IPv6 (the kernel reads the payload's version).
pub fn pop_route_msg(label: u32, vrf: u32) -> RouteMessage {
    RouteMessageBuilder::<MplsLabel>::new()
        .label(stack(&[label])[0])
        .output_interface(vrf)
        .build()
}

/// `(label, oif)` of a dumped `AF_MPLS` route.
pub fn pop_route_of(route: &RouteMessage) -> Option<(u32, Option<u32>)> {
    let label = route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Destination(RouteAddress::Mpls(l)) => Some(l.label),
        _ => None,
    })?;
    let oif = route.attributes.iter().find_map(|a| match a {
        RouteAttribute::Oif(i) => Some(*i),
        _ => None,
    });
    Some((label, oif))
}

/// The labels an IP route pushes (`RTA_ENCAP` of type MPLS), empty without.
pub fn labels_of(route: &RouteMessage) -> Vec<u32> {
    route
        .attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Encap(encaps) => encaps.iter().find_map(|e| match e {
                RouteLwTunnelEncap::Mpls(RouteMplsIpTunnel::Destination(l)) => {
                    Some(l.iter().map(|l| l.label).collect())
                }
                _ => None,
            }),
            _ => None,
        })
        .unwrap_or_default()
}

/// The `net.mpls` sysctls, under `root` (`/proc/sys`, a tempdir in tests).
/// Each is read first and written only when not already enough, so a value
/// the operator set (or the e2e helper did) is never rewritten.
#[derive(Debug, Clone)]
pub struct Sysctl {
    root: PathBuf,
}

impl Default for Sysctl {
    fn default() -> Self {
        Self::new("/proc/sys")
    }
}

impl Sysctl {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn mpls(&self) -> Result<PathBuf, DriverError> {
        let dir = self.root.join("net/mpls");
        if dir.is_dir() {
            Ok(dir)
        } else {
            Err(DriverError::Other(
                "MPLS is not available: load the mpls_router kernel module \
                 (mpls_iptunnel for labelled routes)"
                    .into(),
            ))
        }
    }

    /// `net.mpls.platform_labels` above `label`: grown to the next multiple
    /// of 1024 when short, never shrunk (that would delete routes).
    pub fn ensure_platform_labels(&self, label: u32) -> Result<(), DriverError> {
        let path = self.mpls()?.join("platform_labels");
        let current: u32 = read(&path)?.parse().unwrap_or(0);
        if current > label {
            return Ok(());
        }
        let want = (label + 1).next_multiple_of(1024).min(MAX_LABEL);
        write(&path, "net.mpls.platform_labels", want)
    }

    /// `net.mpls.conf.<ifname>.input = 1`. A device without an MPLS conf
    /// directory is skipped.
    pub fn ensure_input(&self, ifname: &str) -> Result<(), DriverError> {
        let path = self.mpls()?.join("conf").join(ifname).join("input");
        match std::fs::read_to_string(&path) {
            Ok(v) if v.trim() == "1" => Ok(()),
            Ok(_) => write(&path, &format!("net.mpls.conf.{ifname}.input"), 1),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DriverError::Registry(e)),
        }
    }
}

fn read(path: &Path) -> Result<String, DriverError> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn write(path: &Path, name: &str, value: u32) -> Result<(), DriverError> {
    std::fs::write(path, value.to_string()).map_err(|e| match e.kind() {
        ErrorKind::ReadOnlyFilesystem | ErrorKind::PermissionDenied => DriverError::Other(format!(
            "cannot write {name}={value}: set it on the host or with docker's --sysctl \
             (docker mounts /proc/sys read-only)"
        )),
        _ => DriverError::Other(format!("cannot write {name}={value}: {e}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn labels_are_checked_and_stacked_bottom_last() {
        assert!(check_label(15).is_err());
        assert!(check_label(MAX_LABEL).is_err());
        check_label(16).unwrap();
        let s = stack(&[100, 200]);
        assert_eq!(
            (
                s[0].label,
                s[0].bottom_of_stack,
                s[1].label,
                s[1].bottom_of_stack
            ),
            (100, false, 200, true)
        );
        assert_eq!((s[1].ttl, s[1].traffic_class), (0, 0));
    }

    #[test]
    fn pop_route_round_trips() {
        let m = pop_route_msg(1000, 7);
        assert_eq!(m.header.destination_prefix_length, 20);
        assert_eq!(pop_route_of(&m), Some((1000, Some(7))));
        assert_eq!(labels_of(&m), [] as [u32; 0]);
        assert_eq!(pop_route_of(&RouteMessage::default()), None);
    }

    #[test]
    fn pushed_labels_read_back_v4_and_v6() {
        for (dst, len, gw) in [
            ("10.1.0.0", 24, "10.0.0.2"),
            ("2001:db8:1::", 48, "2001:db8::2"),
        ] {
            let m = RouteMessageBuilder::<std::net::IpAddr>::new()
                .destination_prefix(dst.parse().unwrap(), len)
                .unwrap()
                .gateway(gw.parse().unwrap())
                .unwrap()
                .output_mpls(stack(&[2000]))
                .build();
            assert_eq!(labels_of(&m), vec![2000]);
        }
    }

    fn tree(platform: &str, inputs: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mpls = dir.path().join("net/mpls");
        std::fs::create_dir_all(&mpls).unwrap();
        std::fs::write(mpls.join("platform_labels"), platform).unwrap();
        for (ifname, v) in inputs {
            std::fs::create_dir_all(mpls.join("conf").join(ifname)).unwrap();
            std::fs::write(mpls.join("conf").join(ifname).join("input"), v).unwrap();
        }
        dir
    }

    fn get(dir: &tempfile::TempDir, rel: &str) -> String {
        std::fs::read_to_string(dir.path().join("net/mpls").join(rel)).unwrap()
    }

    #[test]
    fn a_missing_module_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let e = Sysctl::new(dir.path())
            .ensure_platform_labels(1000)
            .unwrap_err();
        assert!(e.to_string().contains("mpls_router"), "{e}");
        assert!(Sysctl::new(dir.path()).ensure_input("eth0").is_err());
        assert_eq!(Sysctl::default().root, PathBuf::from("/proc/sys"));
    }

    #[test]
    fn platform_labels_only_grow() {
        let t = tree("0\n", &[]);
        let s2 = Sysctl::new(t.path());
        s2.ensure_platform_labels(1000).unwrap();
        assert_eq!(get(&t, "platform_labels"), "1024");
        s2.ensure_platform_labels(1024).unwrap();
        assert_eq!(get(&t, "platform_labels"), "2048");
        s2.ensure_platform_labels(100).unwrap();
        assert_eq!(get(&t, "platform_labels"), "2048", "never shrinks");
        s2.ensure_platform_labels(MAX_LABEL - 1).unwrap();
        assert_eq!(get(&t, "platform_labels"), MAX_LABEL.to_string());
        // Enough already: left as the operator wrote it.
        let t = tree("1048575\n", &[]);
        Sysctl::new(t.path()).ensure_platform_labels(5000).unwrap();
        assert_eq!(get(&t, "platform_labels"), "1048575\n");
    }

    #[test]
    fn input_is_set_once_and_unknown_devices_skipped() {
        let t = tree("0", &[("eth0", "0\n"), ("eth1", "1\n")]);
        let s = Sysctl::new(t.path());
        s.ensure_input("eth0").unwrap();
        s.ensure_input("eth1").unwrap();
        s.ensure_input("nope").unwrap();
        assert_eq!(get(&t, "conf/eth0/input"), "1");
        assert_eq!(get(&t, "conf/eth1/input"), "1\n", "not rewritten");
    }

    #[test]
    fn an_unwritable_sysctl_says_where_to_set_it() {
        let t = tree("0", &[("eth0", "0")]);
        let files = [
            t.path().join("net/mpls/platform_labels"),
            t.path().join("net/mpls/conf/eth0/input"),
        ];
        for f in &files {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        // Root ignores file modes: nothing to assert then.
        if std::fs::OpenOptions::new()
            .write(true)
            .open(&files[0])
            .is_ok()
        {
            return;
        }
        let s = Sysctl::new(t.path());
        let e = s.ensure_platform_labels(1000).unwrap_err().to_string();
        assert!(
            e.contains("net.mpls.platform_labels=1024") && e.contains("--sysctl"),
            "{e}"
        );
        let e = s.ensure_input("eth0").unwrap_err().to_string();
        assert!(e.contains("net.mpls.conf.eth0.input=1"), "{e}");
    }
}
