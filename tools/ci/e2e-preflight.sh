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

# On ubuntu-24.04 azure runners vrf.ko ships in linux-modules-extra, which
# the runner image doesn't install.
if ! $SUDO modprobe vrf 2>/dev/null; then
    $SUDO apt-get install -y "linux-modules-extra-$(uname -r)" || true
fi
$SUDO modprobe vrf dummy bonding vxlan 8021q bridge ipip || true
# EVPN local bias (nos-fdbd, tc): flower/skbedit mark, fw/gact drop, clsact;
# STP BPDU trap (nos-interfaced): flower + gact drop on ingress.
$SUDO modprobe cls_flower cls_fw act_skbedit act_gact sch_ingress || true
lsmod | grep -E 'vrf|dummy|bonding|vxlan|8021q|bridge|ipip|cls_|act_|sch_ingress' || true
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
