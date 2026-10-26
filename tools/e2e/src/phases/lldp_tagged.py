"""Sends router-a's eth1 two LLDPDUs from a fake neighbour: first one behind an
in-band 802.1Q tag (vlan 100; the veth moves it into skb metadata, so the bytes
nos-lldpd reads look untagged), then the same untagged as a control (#690).
Runs in router-b's netns.
"""
import socket
import struct


def tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


def pdu(port):
    return (
        tlv(1, b"\x07tagged")
        + tlv(2, b"\x07" + port)
        + tlv(3, struct.pack(">H", 120))
        + tlv(5, b"tagged")
        + tlv(0, b"")
    )


head = bytes.fromhex("0180c200000e" "020000deadbe")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth1", 0))
s.send(head + struct.pack(">HHH", 0x8100, 100, 0x88CC) + pdu(b"tagged-vlan"))
s.send(head + struct.pack(">H", 0x88CC) + pdu(b"untagged-ctl"))
