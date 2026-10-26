"""Floods eth2 with LLDPDUs (port id "race-eth2") for 40 s, as fast as it can.

Runs in router-b's netns; the frames cross the veth to router-a's *eth2*, where
no LLDP link runs. A socket opened on eth1 must never see them (#691).
"""
import socket
import struct
import time


def tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


pdu = (
    tlv(1, b"\x07race")
    + tlv(2, b"\x07race-eth2")
    + tlv(3, struct.pack(">H", 120))
    + tlv(5, b"race")
    + tlv(0, b"")
)
frame = bytes.fromhex("0180c200000e" "020000deadbe") + struct.pack(">H", 0x88CC) + pdu

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth2", 0))
deadline = time.time() + 40
while time.time() < deadline:
    for _ in range(200):
        s.send(frame)
