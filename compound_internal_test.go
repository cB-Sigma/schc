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

// compoundRule: RuleID 20 (8 bits), T=0, M=2, N=3, WINDOW_SIZE 7, 16-bit
// tiles, the last tile in the All-1, CRC8 so that the All-1 with its tile
// fits the 40-bit MTU that carries one tile per fragment.
const compoundRule = `{"ruleId":20,"fragmentation":{"mode":"ack-on-error","wSize":2,"fcnSize":3,"windowSize":7,"tileBits":16,"lastTile":"all1","rcs":"crc8","compoundAck":true,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`

// RFC 9441 section 4, figures 7 and 8: 14 tiles, the fragments W=0 FCN=2
// and W=1 FCN=1 lost; one Compound ACK reports both windows, the sender
// resends both tiles, and (after its ACK REQ, which RFC 9441 allows and
// the figure leaves out) gets C=1.
func TestCompoundAckFigure7(t *testing.T) {
	r := testRule(t, compoundRule)
	pkt := packetOf(14*16, 9441)
	s, err := NewSender(r, 8, 0, pkt)
	if err != nil {
		t.Fatal(err)
	}
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 40,
		dropUp: func(n int, m *FragMsg) bool { return n == 5 || n == 13 }}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4
		-> W=0, FCN=3
		-> W=0, FCN=2 X
		-> W=0, FCN=1
		-> W=0, FCN=0
		-> W=1, FCN=6
		-> W=1, FCN=5
		-> W=1, FCN=4
		-> W=1, FCN=3
		-> W=1, FCN=2
		-> W=1, FCN=1 X
		-> W=1, FCN=All-1
		<- ACK W=0 C=0 1111011, W=1 1111101
		-> W=0, FCN=2
		-> W=1, FCN=1
		-> W=1, ACK REQ
		<- ACK W=1 C=1`)
	got, ok := rv.Packet()
	if !ok || !bytes.Equal(got.Slice(0, pkt.Len()).Bytes(), pkt.Bytes()) || !s.Done() || s.Err() != nil {
		t.Fatalf("delivered %v, sender %v", ok, s.Err())
	}
}

// Figure 8: the Compound ACK's bits. RuleID, W=00, C=0, 1111011, W=01,
// 1111101, then M=2 zero bits because 5 bits of padding were needed, and
// 3 bits of padding.
func TestCompoundAckFigure8Bits(t *testing.T) {
	r := testRule(t, compoundRule)
	ones := func(s string) []bool {
		var b []bool
		for _, c := range s {
			b = append(b, c == '1')
		}
		return b
	}
	m := &FragMsg{Kind: MsgAck, Rule: r, W: 0, Bitmap: ones("1111011"), More: []WindowBitmap{{W: 1, Bitmap: ones("1111101")}}}
	got := m.Encode(8)
	if want := "00010100" + "00" + "0" + "1111011" + "01" + "1111101" + "00" + "000"; got.String() != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	back, err := DecodeAtSender(r, got, 8)
	if err != nil || describe(back) != "ACK W=0 C=0 1111011, W=1 1111101" {
		t.Fatalf("decoded %s, %v", describe(back), err)
	}
	// The last bitmap compressed: 1111111 after W=2 at bit 20 is cut to
	// the word boundary, and nothing follows.
	m = &FragMsg{Kind: MsgAck, Rule: r, W: 0, Bitmap: ones("0111111"), More: []WindowBitmap{{W: 2, Bitmap: ones("1011111")}}}
	got = m.Encode(8)
	if want := "00010100" + "00" + "0" + "0111111" + "10" + "1011"; got.String() != want {
		t.Fatalf("compressed: got  %s\nwant %s", got, want)
	}
	back, _ = DecodeAtSender(r, got, 8)
	if describe(back) != "ACK W=0 C=0 0111111, W=2 1011111" {
		t.Fatalf("decoded %s", describe(back))
	}
	// Windows out of order or repeated: the ACK is discarded.
	bad := mustBits(t, "00010100"+"01"+"0"+"1111011"+"01"+"1111101"+"00"+"000")
	if _, err := DecodeAtSender(r, bad, 8); err == nil {
		t.Fatal("a repeated window was accepted")
	}
	// An RFC 8724 ACK reads the same under a compound rule.
	plain := testRule(t, strings.Replace(compoundRule, `"compoundAck":true`, `"compoundAck":false`, 1))
	one := (&FragMsg{Kind: MsgAck, Rule: plain, W: 1, Bitmap: ones("1011111")}).Encode(8)
	back, err = DecodeAtSender(r, one, 8)
	if err != nil || describe(back) != "ACK W=1 C=0 1011111" {
		t.Fatalf("plain ACK under a compound rule: %s %v", describe(back), err)
	}
}

// Under random loss the Compound ACK delivers the packet or both ends
// give up, as RFC 8724 ACK-on-Error does.
func TestCompoundAckRandomLoss(t *testing.T) {
	for _, js := range []string{
		compoundRule,
		strings.Replace(compoundRule, `"compoundAck":true`, `"compoundAck":true,"lastBitmapUncompressed":true`, 1),
	} {
		r := testRule(t, js)
		for seed := int64(0); seed < 150; seed++ {
			rnd := rand.New(rand.NewSource(seed))
			n := 1 + rnd.Intn(4*7*16)
			pkt := packetOf(n, seed)
			s, err := NewSender(r, 8, 0, pkt)
			if err != nil {
				t.Fatal(err)
			}
			rv := NewReceiver(r, 8, 0, 0, time.Now())
			loss := rnd.Float64() * 0.3
			w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 8 * (5 + rnd.Intn(20)),
				dropUp:   func(int, *FragMsg) bool { return rnd.Float64() < loss },
				dropDown: func(int, *FragMsg) bool { return rnd.Float64() < loss },
			}
			w.run()
			got, ok := rv.Packet()
			if ok && !bytes.Equal(got.Slice(0, min(pkt.Len(), got.Len())).Bytes(), pkt.Bytes()) {
				t.Fatalf("seed %d: wrong packet", seed)
			}
			if s.Done() && s.Err() == nil && !ok {
				t.Fatalf("seed %d: the sender succeeded but no packet\n%s", seed, strings.Join(w.trace, "\n"))
			}
		}
	}
	if _, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fragmentation":{"mode":"no-ack","fcnSize":1,"compoundAck":true}}]}`)); err == nil {
		t.Fatal("compoundAck accepted for no-ack")
	}
}
