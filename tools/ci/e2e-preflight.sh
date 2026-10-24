#!/bin/sh
# What a host needs before `nos-e2e` can pass (CI runs this too, see
# .github/workflows/verify-e2e.yml): every kernel module the routers'
# rtnetlink drivers create devices of (a container can't modprobe), and the
# file capabilities Dockerfile's `setcap` put on nos-ribd — an xattr an image
# export can drop, after which nos-ribd never creates the VRF and REST never
# binds (#97). Usage: IMAGE=nos:local tools/ci/e2e-preflight.sh
set -eu

IMAGE=${IMAGE:-nos:local}
SUDO=
[ "$(id -u)" -eq 0 ] || SUDO=sudo

# On ubuntu-24.04 azure runners vrf.ko (and the MPLS modules) ship in
# linux-modules-extra, which the runner image doesn't install.
if ! $SUDO modprobe -a vrf mpls_router mpls_iptunnel 2>/dev/null; then
    $SUDO apt-get install -y "linux-modules-extra-$(uname -r)" || true
fi
# vrf..ipip: rtnetlink drivers. cls_flower..sch_ingress: EVPN local bias
# (nos-fdbd, tc: flower/skbedit mark, fw/gact drop, clsact) and the STP BPDU
# trap (nos-interfaced: flower + gact drop on ingress). act_sample/psample:
# ACL `log` (nos-acld, #544); the acl phase's log step cannot pass without them.
# mpls_router/mpls_iptunnel: the L3VPN data plane (nos-ribd, vpn-dataplane);
# /proc/sys/net/mpls exists only in netns created after mpls_router loads.
mods="vrf dummy bonding vxlan 8021q bridge ipip cls_flower cls_fw act_skbedit act_gact sch_ingress act_sample psample mpls_router mpls_iptunnel"
# -a: without it every name after the first is a parameter of the first module.
# shellcheck disable=SC2086
$SUDO modprobe -a $mods || true
# Loaded modules have /sys/module/<m>; built-ins without parameters don't, but
# are listed in modules.builtin.
missing=
for m in $mods; do
    [ -d "/sys/module/$m" ] && continue
    grep -qE "/$m\.ko" "/lib/modules/$(uname -r)/modules.builtin" 2>/dev/null && continue
    missing="$missing $m"
done
if [ -n "$missing" ]; then
    echo "kernel modules missing on $(uname -r):$missing" >&2
    exit 1
fi
lsmod | grep -E 'vrf|dummy|bonding|vxlan|8021q|bridge|ipip|cls_|act_|sch_ingress|psample|mpls' || true
uname -r

# `docker cp` to a host path writes as the caller, who can't set the
# security.capability xattr — extract the stream inside a container instead
# (as root, with CAP_SETFCAP), then getcap the file on the host.
id=$(docker create "$IMAGE")
dir=$(mktemp -d)
docker cp "$id:/usr/local/bin/nos-ribd" - \
    | docker run --rm -i --user 0 -v "$dir:/out:z" --entrypoint tar "$IMAGE" \
        -x --xattrs --xattrs-include=security.capability -C /out
docker rm "$id" >/dev/null
caps=$(getcap "$dir/nos-ribd")
rm -rf "$dir"
echo "$caps"
case $caps in
    *cap_net_admin*) ;;
    *) echo "nos-ribd in $IMAGE lacks cap_net_admin — the image export dropped its file capabilities" >&2; exit 1 ;;
esac
