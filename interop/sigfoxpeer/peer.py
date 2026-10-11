# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# A driver for schc-over-sigfox (https://github.com/schc-over-sigfox/
# schc-over-sigfox, MIT), the implementation of RFC 9442 by its authors,
# used as the reference peer of this module's Sigfox tests. It calls their
# Fragmenter, their SCHCReceiver and their message parsers; no code of
# theirs is copied here.
#
# One JSON command per line; answers are "PEER " lines, then "PEER done".
#
#   {"cmd": "fragment", "rule": "010", "hex": "..."}   their fragments
#   {"cmd": "recv", "hex": "...", "time": n}            to their receiver
#   {"cmd": "parse-ack", "hex": "..."}                  their reading of an ACK
#   {"cmd": "reset"}

import json
import shutil
import sys
import traceback

from Entities.Fragmenter import Fragmenter
from Entities.Reassembler import Reassembler
from Entities.Rule import Rule
from Entities.SCHCReceiver import SCHCReceiver
from Entities.exceptions import SenderAbortError, ReceiverAbortError
from Messages.CompoundACK import CompoundACK
from Messages.Fragment import Fragment
from db.JSONStorage import JSONStorage


def out(*parts):
    print("PEER " + " ".join(str(p) for p in parts), flush=True)


class MemoryStorage(JSONStorage):
    """Their JSON storage kept in memory: nothing to load or save."""

    def load(self):
        pass

    def save(self):
        pass


state = {}


def reset():
    state.clear()
    shutil.rmtree("/tmp/sd", ignore_errors=True)


def handle(c):
    cmd = c["cmd"]
    if cmd == "reset":
        reset()
    elif cmd == "fragment":
        shutil.rmtree("/tmp/sd", ignore_errors=True)
        f = Fragmenter(Rule(c["rule"]), fragment_dir="/tmp/sd")
        for frag in f.fragment(bytes.fromhex(c["hex"])):
            out("fragment", frag.to_hex())
    elif cmd == "recv":
        if "receiver" not in state:
            storage = MemoryStorage()
            state["storage"] = storage
            state["receiver"] = SCHCReceiver(Rule.from_hex(c["hex"]), storage)
        rx, storage = state["receiver"], state["storage"]
        fragment = Fragment.from_hex(c["hex"])
        try:
            ack = rx.schc_recv(fragment, int(c.get("time", 0)))
        except SenderAbortError:
            out("sender-abort")
            return
        except ReceiverAbortError:
            out("receiver-abort", rx.get_receiver_abort().to_hex())
            return
        if ack is not None:
            out("ack", ack.to_hex())
        if fragment.is_all_1() and ack is not None and ack.is_complete():
            frags = []
            for wdw in storage.list_nodes("fragments"):
                for frg in storage.list_nodes(f"fragments/{wdw}"):
                    frags.append(Fragment.from_hex(storage.read(f"fragments/{wdw}/{frg}")))
            out("packet", Reassembler(frags).reassemble().hex())
    elif cmd == "parse-fragment":
        out("fragment-rule", Fragment.from_hex(c["hex"]).HEADER.RULE_ID)
    elif cmd == "parse-ack":
        ack = CompoundACK.from_hex(c["hex"])
        out("parsed", "c=" + ack.HEADER.C, " ".join(f"{w}:{b}" for (w, b) in ack.TUPLES))
    else:
        out("error unknown command", cmd)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line == "quit":
            break
        try:
            handle(json.loads(line))
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            out("error", type(e).__name__, str(e).replace("\n", " "))
        out("done")


if __name__ == "__main__":
    main()
