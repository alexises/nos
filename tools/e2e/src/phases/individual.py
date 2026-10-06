"""Plays a partner that treats eth2 as an Individual link (802.1AX Actor_State
.Aggregation clear): one LACPDU per second for 10s on eth2, fast timeout, in
sync, collecting and distributing, but not aggregatable.

Neither the kernel's bonding driver (always sets Aggregation) nor nos-lacpd
(ditto) can send that, hence a scripted speaker. Runs in router-b's netns,
whose own eth2 is out of the aggregate at that point.
"""
import socket
import struct
import time

mac = bytes.fromhex(open("/sys/class/net/eth2/address").read().strip().replace(":", ""))
dst = bytes.fromhex("0180c2000002")
# Activity | Timeout | Synchronization | Collecting | Distributing (no Aggregation)
STATE = 0x01 | 0x02 | 0x08 | 0x10 | 0x20


def info(tlv, prio, system, key, port, state):
    return struct.pack(">BBH6sHHHB3x", tlv, 20, prio, system, key, 0x8000, port, state)


pdu = bytes([1, 1])
pdu += info(1, 0x8000, bytes.fromhex("02000000" "0c01"), 9, 1, STATE)
pdu += info(2, 0x8000, bytes(6), 0, 0, 0)
pdu += bytes([3, 16]) + bytes(14) + bytes([0, 0])
pdu = pdu.ljust(110, b"\0")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8809))
s.bind(("eth2", 0x8809))
for _ in range(10):
    s.send(dst + mac + struct.pack(">H", 0x8809) + pdu)
    time.sleep(1)
