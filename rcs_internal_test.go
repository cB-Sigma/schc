// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// The built-in algorithms give the published check values of their CRC
// for "123456789" (CRC-32/ISO-HDLC CBF43926, CRC-32/ISCSI E3069283,
// CRC-16/IBM-SDLC 906E, CRC-8/SMBUS F4).
func TestRCSCheckValues(t *testing.T) {
	for name, want := range map[string]uint32{"crc32": 0xCBF43926, "crc32c": 0xE3069283, "crc16-hdlc": 0x906E, "crc8": 0xF4} {
		a, ok := LookupRCS(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if got := a.Sum([]byte("123456789")); got != want {
			t.Errorf("%s = %X, want %X", name, got, want)
		}
	}
}

// Every mode fragments and reassembles with every algorithm, across loss,
// and the All-1 carries an RCS of the algorithm's size.
func TestFragmentationWithEachRCS(t *testing.T) {
	if err := RegisterRCS(RCSAlgorithm{Name: "test-sum5", Bits: 5, Sum: func(b []byte) uint32 {
		var s uint32
		for _, c := range b {
			s += uint32(c)
		}
		return s
	}}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterRCS(RCSAlgorithm{Name: "crc32", Bits: 32, Sum: func([]byte) uint32 { return 0 }}); err == nil {
		t.Fatal("crc32 registered twice")
	}
	modes := []string{
		`"mode":"no-ack","fcnSize":1`,
		`"mode":"ack-always","wSize":1,"fcnSize":3,"retransmissionTimer":"1m","inactivityTimer":"1h"`,
		`"mode":"ack-on-error","wSize":2,"fcnSize":3,"tileBytes":3,"retransmissionTimer":"1m","inactivityTimer":"1h"`,
	}
	for _, alg := range []string{"crc32", "crc32c", "crc16-hdlc", "crc8", "test-sum5"} {
		for _, mode := range modes {
			r := testRule(t, fmt.Sprintf(`{"ruleId":9,"fragmentation":{%s,"rcs":%q}}`, mode, alg))
			a, _ := LookupRCS(alg)
			if r.Fragmentation.RCSSize != a.Bits {
				t.Fatalf("%s: rcsSize %d", alg, r.Fragmentation.RCSSize)
			}
			for seed := int64(0); seed < 40; seed++ {
				rnd := rand.New(rand.NewSource(seed))
				n := 1 + rnd.Intn(80*8)
				pkt := packetOf(n, seed)
				s, err := NewSender(r, 8, 0, pkt)
				if err != nil {
					t.Fatal(err)
				}
				rv := NewReceiver(r, 8, 0, 0, time.Now())
				loss := 0.0
				if r.Fragmentation.Mode != NoAck && seed%2 == 1 {
					loss = 0.2
				}
				w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 8 * (10 + rnd.Intn(20)),
					dropUp:   func(int, *FragMsg) bool { return rnd.Float64() < loss },
					dropDown: func(int, *FragMsg) bool { return rnd.Float64() < loss },
				}
				w.run()
				got, ok := rv.Packet()
				if ok && !bytes.Equal(got.Slice(0, min(pkt.Len(), got.Len())).Bytes(), pkt.Bytes()) {
					t.Fatalf("%s %s seed %d: wrong packet", alg, mode, seed)
				}
				if loss == 0 && !ok {
					t.Fatalf("%s %s seed %d: lossless transfer failed: %v / %v\n%s", alg, mode, seed, s.Err(), rv.Err(), strings.Join(w.trace, "\n"))
				}
			}
		}
	}
}

// A tile changed on the way fails the receiver's check (No-ACK, where
// nothing else would notice).
func TestRCSDetectsCorruption(t *testing.T) {
	for _, alg := range []string{"crc32", "crc16-hdlc", "crc8"} {
		r := testRule(t, fmt.Sprintf(`{"ruleId":9,"fragmentation":{"mode":"no-ack","fcnSize":1,"rcs":%q}}`, alg))
		pkt := packetOf(400, 1)
		s, _ := NewSender(r, 8, 0, pkt)
		frags, err := s.Start(time.Now(), 8*20)
		if err != nil {
			t.Fatal(err)
		}
		rv := NewReceiver(r, 8, 0, 0, time.Now())
		for i, f := range frags {
			if i == 1 {
				b := f.Bytes()
				b[3] ^= 0x10
				f = BitsOf(b, f.Len())
			}
			_, _ = rv.Receive(time.Now(), f)
		}
		if _, ok := rv.Packet(); ok || rv.Err() == nil {
			t.Fatalf("%s: a corrupted packet passed the check", alg)
		}
	}
}

func TestRCSRefusals(t *testing.T) {
	for _, js := range []string{
		`{"ruleId":9,"fragmentation":{"mode":"no-ack","fcnSize":1,"rcs":"md5"}}`,
		`{"ruleId":9,"fragmentation":{"mode":"no-ack","fcnSize":1,"rcs":"crc8","rcsSize":32}}`,
		`{"ruleId":9,"fragmentation":{"mode":"no-ack","fcnSize":1,"rcsSize":16}}`,
	} {
		if _, err := ParseRuleSet([]byte(`{"rules":[` + js + `]}`)); err == nil {
			t.Errorf("accepted %s", js)
		}
	}
	if err := RegisterRCS(RCSAlgorithm{Name: "x", Bits: 33, Sum: crc8}); err == nil {
		t.Error("a 33-bit RCS was registered")
	}
}
