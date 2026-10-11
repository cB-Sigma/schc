// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// A 289-bit packet in 3-byte tiles ends with a 1-bit tile, which the
// sender puts in the All-1; the receiver used to take it for padding and
// fail the check with every tile in hand.
func TestAckOnErrorSubWordLastTile(t *testing.T) {
	r := testRule(t, `{"ruleId":9,"fragmentation":{"mode":"ack-on-error","wSize":2,"fcnSize":3,"tileBytes":3,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`)
	for _, n := range []int{289, 290, 295, 1, 7, 25} {
		pkt := packetOf(n, int64(n))
		s, err := NewSender(r, 8, 0, pkt)
		if err != nil {
			t.Fatal(err)
		}
		rv := NewReceiver(r, 8, 0, 0, time.Now())
		w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 144}
		w.run()
		got, ok := rv.Packet()
		if !ok || !s.Done() || s.Err() != nil {
			t.Fatalf("%d bits: delivered %v, sender %v\n%s", n, ok, s.Err(), strings.Join(w.trace, "\n"))
		}
		if !bytes.Equal(got.Slice(0, n).Bytes(), pkt.Bytes()) || got.Len()-n >= 8 {
			t.Fatalf("%d bits: wrong packet of %d bits", n, got.Len())
		}
	}
}

// RFC 9363's ACK-on-Error rule without tile-size: tiles fill their
// fragment, one per fragment, cut at the MTU the sender starts with;
// across loss the packet arrives or both ends give up. openschc's rule 2
// is such a rule.
func TestAckOnErrorTilesFillFragments(t *testing.T) {
	r := testRule(t, `{"ruleId":2,"ruleIdLength":3,"fragmentation":{"mode":"ack-on-error","dtagSize":2,"wSize":7,"fcnSize":3,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`)
	// An ACK before Start (no tiles cut yet) is ignored.
	early, _ := NewSender(r, 8, 1, packetOf(100, 1))
	ack := (&FragMsg{Kind: MsgAck, Rule: r, DTag: 1, Bitmap: make([]bool, 7)}).Encode(8)
	if out, err := early.Receive(time.Now(), ack, 64); out != nil || err != nil {
		t.Fatalf("%v %v", out, err)
	}
	for seed := int64(0); seed < 600; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		pkt := packetOf(1+rnd.Intn(1200*8), seed)
		s, err := NewSender(r, 8, 1, pkt)
		if err != nil {
			t.Fatal(err)
		}
		rv := NewReceiver(r, 8, 1, 0, time.Now())
		loss := 0.0
		if seed%2 == 1 {
			loss = rnd.Float64() * 0.3
		}
		mtu := 8 * (12 + rnd.Intn(60))
		w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: mtu,
			dropUp:   func(int, *FragMsg) bool { return rnd.Float64() < loss },
			dropDown: func(int, *FragMsg) bool { return rnd.Float64() < loss },
		}
		w.run()
		got, ok := rv.Packet()
		if ok && !bytes.Equal(got.Slice(0, min(pkt.Len(), got.Len())).Bytes(), pkt.Bytes()) {
			t.Fatalf("seed %d: wrong packet", seed)
		}
		if loss == 0 && (!ok || !s.Done() || s.Err() != nil) {
			t.Fatalf("seed %d (%d bits, MTU %d): %v / %v\n%s", seed, pkt.Len(), mtu, s.Err(), rv.Err(), strings.Join(w.trace, "\n"))
		}
		if loss == 0 {
			// One tile per fragment, the fragment full: the tile is the
			// MTU's whole bytes less the 15-bit header.
			if want := mtu/8*8 - 15; s.tiles[0].Len() != min(want, pkt.Len()) {
				t.Fatalf("seed %d: tile of %d bits for MTU %d", seed, s.tiles[0].Len(), mtu)
			}
		}
	}
}
