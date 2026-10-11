// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cB-Sigma/schc"
)

// way is one direction of a fragmented transfer: which end openschc plays
// when it sends and when it receives.
type way struct {
	name              string
	dir               schc.Direction
	peerDir           string // openschc's FRDirection
	peerSends, peerRx string // openschc's role as sender, as receiver
}

var ways = []way{
	{"uplink", schc.Up, "UP", "device", "core"},
	{"downlink", schc.Down, "DW", "core", "device"},
}

// Covers: SIG-IPE-7301
func TestNoAckFromOpenschc(t *testing.T) {
	p := startPeer(t)
	for _, w := range ways {
		for _, n := range []int{40, 101, 250} {
			t.Run(fmt.Sprint(w.name, "-", n), func(t *testing.T) {
				p.setup(w.peerSends, peerFragRules("NoAck", w.peerDir), 200)
				rs, rule := ourFragRules(t, "NoAck", string(w.dir))
				raw := coapPacket(t, w.dir, n)
				if got := fromPeer(t, p, rs, rule, raw, nil); !bytes.Equal(got, raw) {
					t.Fatalf("got %x\nwant %x", got, raw)
				}
			})
		}
	}
}

// Covers: SIG-IPE-7301
func TestNoAckToOpenschc(t *testing.T) {
	p := startPeer(t)
	for _, w := range ways {
		for _, n := range []int{40, 101, 250} {
			t.Run(fmt.Sprint(w.name, "-", n), func(t *testing.T) {
				p.setup(w.peerRx, peerFragRules("NoAck", w.peerDir), 200)
				rs, rule := ourFragRules(t, "NoAck", string(w.dir))
				raw := coapPacket(t, w.dir, n)
				got := toPeer(t, p, rs, rule, raw, 200, nil)
				if len(got) != 1 || !bytes.Equal(got[0], raw) {
					t.Fatalf("openschc delivered %x\nwant %x", got, raw)
				}
			})
		}
	}
}

// Covers: SIG-IPE-7302
//
// The losses are of fragments whose tiles are all in one window. openschc
// resends a lone missing tile as an All-1 fragment in that tile's window
// (frag_send.py, FragmentAckOnError.send_frag, at commit 58293f71), which
// no receiver can place; see TestAckOnErrorOpenschcLoneTileResend.
func TestAckOnErrorFromOpenschc(t *testing.T) {
	p := startPeer(t)
	for _, w := range ways {
		for _, tc := range []struct {
			n    int
			drop map[int]bool
		}{
			{41, nil}, {101, nil}, {41, map[int]bool{1: true}}, {101, map[int]bool{1: true, 7: true}},
		} {
			t.Run(fmt.Sprintf("%s-%d-%v", w.name, tc.n, tc.drop), func(t *testing.T) {
				p.setup(w.peerSends, peerFragRules("AckOnError", w.peerDir), 120)
				rs, rule := ourFragRules(t, "AckOnError", string(w.dir))
				raw := coapPacket(t, w.dir, tc.n)
				if got := fromPeer(t, p, rs, rule, raw, tc.drop); !bytes.Equal(got, raw) {
					t.Fatalf("got %x\nwant %x", got, raw)
				}
			})
		}
	}
}

// Covers: SIG-IPE-7302
func TestAckOnErrorToOpenschc(t *testing.T) {
	p := startPeer(t)
	for _, w := range ways {
		for _, tc := range []struct {
			n    int
			drop map[int]bool
		}{
			{41, nil}, {101, nil}, {41, map[int]bool{1: true}}, {101, map[int]bool{2: true, 5: true}}, {101, map[int]bool{2: true}},
		} {
			n := tc.n
			if w.dir == schc.Down {
				// One byte less: the downlink residue with 41 or 101 bytes
				// ends in a 1-bit tile, which openschc's receiver cannot
				// take from any sender (TestAckOnErrorOpenschcToItself);
				// with 40 or 100 the last tile is 25 bits.
				n--
			}
			t.Run(fmt.Sprintf("%s-%d-%v", w.name, n, tc.drop), func(t *testing.T) {
				p.setup(w.peerRx, peerFragRules("AckOnError", w.peerDir), 120)
				rs, rule := ourFragRules(t, "AckOnError", string(w.dir))
				raw := coapPacket(t, w.dir, n)
				got := toPeer(t, p, rs, rule, raw, 120, tc.drop)
				if len(got) != 1 || !bytes.Equal(got[0], raw) {
					t.Fatalf("openschc delivered %x\nwant %x", got, raw)
				}
			})
		}
	}
}

// openschc does not implement ACK-Always (protocol.py raises
// NotImplementedError for both sessions at commit 58293f71), so that mode
// has no openschc peer; TestAckAlwaysOpenschcRefuses keeps that checked.
func TestAckAlwaysOpenschcRefuses(t *testing.T) {
	p := startPeer(t)
	p.setup("device", append(append([]any(nil), peerCoAPRules...),
		map[string]any{"RuleID": 2, "RuleIDLength": 3, "Fragmentation": map[string]any{
			"FRMode": "AckAlways", "FRDirection": "UP", "FRModeProfile": map[string]any{"dtagSize": 2, "FCNSize": 3}}}), 120)
	lines, errLine := p.try(map[string]any{"cmd": "send", "hex": fmt.Sprintf("%x", coapPacket(t, schc.Up, 41))})
	if errLine == "" {
		t.Fatalf("openschc sent ACK-Always fragments %q: it implements the mode now, add exchanges for it", lines)
	}
	t.Logf("openschc: %s", errLine)
}

// TestAckOnErrorOpenschcToItself relays openschc's ACK-on-Error fragments to
// a second openschc. For the downlink packets of these tests (last tile of
// 1 bit, sent as a short penultimate tile and a 9-bit last tile) openschc's
// receiver fails its own sender's transfer, as it fails ours: it reads a
// fragment's payload as whole tiles and takes up to 8 bits left over for
// padding (frag_recv.py, ReassemblerAckOnError.receive_frag, at commit
// 58293f71). The test records that, so TestAckOnErrorToOpenschc's downlink
// cases are not counted against this module; it fails once openschc
// reassembles them, to say they can be enabled.
func TestAckOnErrorOpenschcToItself(t *testing.T) {
	a, b := startPeer(t), startPeer(t)
	for _, w := range ways {
		t.Run(w.name, func(t *testing.T) {
			a.setup(w.peerSends, peerFragRules("AckOnError", w.peerDir), 120)
			b.setup(w.peerRx, peerFragRules("AckOnError", w.peerDir), 120)
			raw := coapPacket(t, w.dir, 41)
			toB := tx(t, a.do(map[string]any{"cmd": "send", "hex": fmt.Sprintf("%x", raw)}))
			var got [][]byte
			for round := 0; round < 12 && len(got) == 0; round++ {
				var toA [][]byte
				for _, m := range toB {
					lines := b.do(map[string]any{"cmd": "recv", "hex": fmt.Sprintf("%x", m)})
					got = append(got, packets(t, lines)...)
					toA = append(toA, tx(t, lines)...)
				}
				toB = nil
				for _, m := range toA {
					toB = append(toB, tx(t, a.do(map[string]any{"cmd": "recv", "hex": fmt.Sprintf("%x", m)}))...)
				}
				if len(toB) == 0 {
					lines, errLine := a.try(map[string]any{"cmd": "tick", "seconds": 160})
					if errLine != "" {
						// After MAX_ACK_REQUESTS openschc's sender fails on its
						// own Sender-Abort (an attribute it does not set).
						t.Logf("openschc sender: %s", errLine)
						break
					}
					toB = tx(t, lines)
				}
			}
			ok := len(got) == 1 && bytes.Equal(got[0], raw)
			switch {
			case w.dir == schc.Up && !ok:
				t.Fatalf("openschc to openschc, uplink: delivered %x", got)
			case w.dir == schc.Down && ok:
				t.Fatal("openschc now reassembles its own downlink transfer: enable the downlink cases of TestAckOnErrorToOpenschc")
			case w.dir == schc.Down:
				t.Log("openschc does not reassemble its own downlink transfer of this packet")
			}
		})
	}
}
