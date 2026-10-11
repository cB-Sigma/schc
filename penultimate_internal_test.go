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

// Covers: SIG-IPE-7305
//
// penultimateShort (RFC 8724 8.4.3.1): a last tile shorter than an L2 Word
// takes a word from the penultimate tile, so it travels in a regular
// fragment, and the receiver reads the fragment both ways and lets the RCS
// decide. openschc fragments every ACK-on-Error packet this way.
func TestAckOnErrorPenultimateShort(t *testing.T) {
	r := testRule(t, `{"ruleId":3,"ruleIdLength":3,"fragmentation":{"mode":"ack-on-error","dtagSize":2,"wSize":3,"fcnSize":3,"tileBits":32,"lastTile":"regular","penultimateShort":true,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`)
	for seed := int64(0); seed < 400; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		n := 40 + rnd.Intn(1400)
		pkt := packetOf(n, seed)
		s, err := NewSender(r, 8, 0, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if lt := s.tiles[len(s.tiles)-1]; n%32 != 0 && n%32 < 8 && (lt.Len() != n%32+8 || s.tiles[len(s.tiles)-2].Len() != 24) {
			t.Fatalf("%d bits: last tiles of %d and %d bits", n, s.tiles[len(s.tiles)-2].Len(), lt.Len())
		}
		rv := NewReceiver(r, 8, 0, 0, time.Now())
		loss := 0.0
		if seed%2 == 1 {
			loss = rnd.Float64() * 0.25
		}
		w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 120,
			dropUp: func(int, *FragMsg) bool { return rnd.Float64() < loss }}
		w.run()
		got, ok := rv.Packet()
		if loss == 0 && (!ok || s.Err() != nil) {
			t.Fatalf("seed %d, %d bits: delivered %v, sender %v\n%s", seed, n, ok, s.Err(), strings.Join(w.trace, "\n"))
		}
		if ok && (!bytes.Equal(got.Slice(0, n).Bytes(), pkt.Bytes()) || got.Len()-n >= 8) {
			t.Fatalf("seed %d, %d bits: wrong packet of %d bits", seed, n, got.Len())
		}
	}
}
