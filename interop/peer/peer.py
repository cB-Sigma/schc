# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# A driver for openschc (https://github.com/openschc/openschc, MIT) used as
# the reference peer of this module's interop tests. It runs openschc's own
# SCHCProtocol (compression, fragmentation sender and receiver) with a lower
# layer that writes every SCHC message it sends to standard output, and a
# scheduler on a virtual clock that the test moves on. No openschc code is
# copied here; this file only calls it.
#
# One JSON command per line on standard input; answers are lines starting
# with "PEER ", and each command ends with "PEER done".
#
#   {"cmd": "setup", "role": "device"|"core", "rules": [...], "mtu": bits}
#   {"cmd": "compress", "hex": "...", "layers": ["IPv6", "UDP", "CoAP"]}
#   {"cmd": "send", "hex": "..."}      compress, fragment if over the MTU
#   {"cmd": "recv", "hex": "..."}      a SCHC message from the other end
#   {"cmd": "tick", "seconds": n}      move the clock on, run what is due
#   {"cmd": "mtu", "bits": n}

import binascii
import json
import sys
import traceback

import gen_rulemanager
import protocol
from gen_parameters import T_POSITION_CORE, T_POSITION_DEVICE


def out(*parts):
    print("PEER " + " ".join(str(p) for p in parts), flush=True)


class Scheduler:
    """openschc's scheduler interface on a clock the test moves."""

    def __init__(self):
        self.clock = 0.0
        self.queue = []
        self.next_id = 0

    def get_clock(self):
        return self.clock

    def add_event(self, rel_time, callback, args, session_id=None):
        eid = self.next_id
        self.next_id += 1
        self.queue.append((self.clock + rel_time, eid, callback, args, session_id))
        return eid

    def cancel_event(self, event):
        for i, q in enumerate(self.queue):
            if q[1] == event:
                return self.queue.pop(i)
        return None

    def cancel_session(self, session_id=None):
        self.queue = [q for q in self.queue if q[4] != session_id]

    def run_due(self):
        while True:
            due = [q for q in self.queue if q[0] <= self.clock]
            if not due:
                return
            due.sort(key=lambda q: (q[0], q[1]))
            q = due[0]
            self.queue.remove(q)
            q[2](*q[3])


class System:
    def __init__(self):
        self.scheduler = Scheduler()

    def get_scheduler(self):
        return self.scheduler

    def log(self, name, message):
        pass


class Link:
    """The lower layer: every SCHC message sent is printed."""

    def __init__(self):
        self.protocol = None
        self.mtu = 400

    def _set_protocol(self, p):
        self.protocol = p

    def send_packet(self, packet, dest=None, transmit_callback=None):
        out("tx", binascii.hexlify(bytes(packet)).decode())
        if transmit_callback is not None:
            transmit_callback(1)

    def get_mtu_size(self):
        return self.mtu


state = {}


def setup(c):
    rm = gen_rulemanager.RuleManager()
    rm.Add(dev_info=c["rules"])
    role = T_POSITION_DEVICE if c.get("role", "device") == "device" else T_POSITION_CORE
    system = System()
    link = Link()
    p = protocol.SCHCProtocol(config={}, system=system, layer2=link, role=role,
                              unique_peer=True, verbose=False)
    p.set_rulemanager(rm)
    mtu = int(c.get("mtu", 400))
    link.mtu = mtu
    p.connectivity_manager.set_mtu(mtu)
    state.update(protocol=p, link=link, system=system, rm=rm)


def scapy4(c):
    """An IPv4 packet built by scapy, its checksums its own: for the
    IPv4, UDP-over-IPv4 and SCTP checksums of this module."""
    from scapy.all import IP, UDP, Raw
    from scapy.layers.sctp import SCTP, SCTPChunkData
    ip = IP(src=c["src"], dst=c["dst"], ttl=c.get("ttl", 64), id=c.get("id", 1), tos=c.get("tos", 0))
    data = bytes.fromhex(c["payload"])
    if c["l4"] == "udp":
        pkt = ip / UDP(sport=c["sport"], dport=c["dport"]) / Raw(data)
    else:
        pkt = ip / SCTP(sport=c["sport"], dport=c["dport"], tag=c["tag"]) / SCTPChunkData(data=data, tsn=7, stream_id=1, proto_id=0)
    out("scapy", bytes(pkt).hex())


def handle(c):
    cmd = c["cmd"]
    if cmd == "setup":
        setup(c)
        return
    if cmd == "scapy4":
        scapy4(c)
        return
    p = state["protocol"]
    sched = state["system"].scheduler
    if cmd == "mtu":
        state["link"].mtu = int(c["bits"])
        p.connectivity_manager.set_mtu(int(c["bits"]))
    elif cmd == "compress":
        raw = binascii.unhexlify(c["hex"])
        bb, _ = p._apply_compression(None, raw, c.get("layers"))
        if bb is None:
            out("compressed none")
        else:
            out("compressed", binascii.hexlify(bytes(bb.get_content())).decode(), bb.count_added_bits())
    elif cmd == "send":
        raw = binascii.unhexlify(c["hex"])
        p.schc_send(raw, parsing=c.get("layers"))
    elif cmd == "recv":
        res = p.schc_recv(binascii.unhexlify(c["hex"]))
        if isinstance(res, tuple) and len(res) == 2:
            pkt = res[1]
            if pkt is False:
                out("failed")
            elif pkt is not None:
                out("packet", binascii.hexlify(bytes(pkt)).decode())
    elif cmd == "tick":
        sched.clock += float(c["seconds"])
    else:
        out("error unknown command", cmd)
    sched.run_due()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line == "quit":
            break
        try:
            handle(json.loads(line))
        except Exception as e:  # report and go on: the test decides
            traceback.print_exc(file=sys.stdout)
            out("error", type(e).__name__, str(e).replace("\n", " "))
        out("done")


if __name__ == "__main__":
    main()
