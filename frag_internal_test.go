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

// wire runs a sender and a receiver against each other; drop decides
// which messages are lost (by their number in each direction) and trace
// records what went across, in the style of RFC 8724 appendix B.
type wire struct {
	t        *testing.T
	s        *Sender
	r        *Receiver
	now      time.Time
	mtu      int
	dropUp   func(n int, m *FragMsg) bool
	dropDown func(n int, m *FragMsg) bool
	nUp      int
	nDown    int
	trace    []string
}

func describe(m *FragMsg) string {
	switch m.Kind {
	case MsgFragment:
		return fmt.Sprintf("W=%d, FCN=%d", m.W, m.FCN)
	case MsgAll1:
		return fmt.Sprintf("W=%d, FCN=All-1", m.W)
	case MsgAckReq:
		return fmt.Sprintf("W=%d, ACK REQ", m.W)
	case MsgAck:
		if m.C {
			return fmt.Sprintf("ACK W=%d C=1", m.W)
		}
		var b strings.Builder
		for _, x := range m.Bitmap {
			if x {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		return fmt.Sprintf("ACK W=%d C=0 %s", m.W, b.String())
	}
	return m.Kind.String()
}

func (w *wire) toReceiver(msgs []Bits) {
	for _, b := range msgs {
		m, err := DecodeAtReceiver(w.s.r, b, 8)
		if err != nil {
			w.t.Fatalf("receiver cannot decode %s: %v", b, err)
		}
		w.nUp++
		lost := w.dropUp != nil && w.dropUp(w.nUp, m)
		tag := ""
		if lost {
			tag = " X"
		}
		w.trace = append(w.trace, "-> "+describe(m)+tag)
		if lost {
			continue
		}
		back, _ := w.r.Receive(w.now, b)
		w.toSender(back)
	}
}

func (w *wire) toSender(msgs []Bits) {
	for _, b := range msgs {
		m, err := DecodeAtSender(w.s.r, b, 8)
		if err != nil {
			w.t.Fatalf("sender cannot decode %s: %v", b, err)
		}
		w.nDown++
		lost := w.dropDown != nil && w.dropDown(w.nDown, m)
		tag := ""
		if lost {
			tag = " X"
		}
		w.trace = append(w.trace, "<- "+describe(m)+tag)
		if lost {
			continue
		}
		more, _ := w.s.Receive(w.now, b, w.mtu)
		w.toReceiver(more)
	}
}

func (w *wire) run() {
	out, err := w.s.Start(w.now, w.mtu)
	if err != nil {
		w.t.Fatal(err)
	}
	w.toReceiver(out)
	for i := 0; i < 50 && !w.s.Done(); i++ {
		w.now = w.now.Add(w.s.p.Retransmission.D() + time.Second)
		more, _ := w.s.Tick(w.now)
		w.toReceiver(more)
	}
}

func testRule(t *testing.T, js string) *Rule {
	t.Helper()
	rs, err := ParseRuleSet([]byte(`{"rules":[` + js + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return &rs.Rules[0]
}

func packetOf(nbits int, seed int64) Bits {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, (nbits+7)/8)
	r.Read(b)
	return BitsOf(b, nbits).Clone()
}

// eleven tiles of 16 bits with a 16-bit header (RuleID 8, W 1 or 2, FCN
// 3, padding to the word): one tile per fragment at this MTU.
const b11 = 11*16 - 3

func checkTrace(t *testing.T, got []string, want string) {
	t.Helper()
	w := strings.Split(strings.TrimSpace(want), "\n")
	for i := range w {
		w[i] = strings.TrimSpace(w[i])
	}
	if strings.Join(got, "\n") != strings.Join(w, "\n") {
		t.Fatalf("trace:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(w, "\n"))
	}
}

// RFC 8724 figure 29: No-ACK, 11 fragments, FCN 1 bit.
// Covers: SIG-IPE-3788
func TestNoAckFigure29(t *testing.T) {
	r := testRule(t, `{"ruleId":5,"fragmentation":{"mode":"no-ack","fcnSize":1}}`)
	// Regular fragments of 64 bits carry 55-bit tiles (header 9 bits); the
	// All-1 carries the last 20 bits after the 32-bit RCS.
	pkt := packetOf(10*55+20, 1)
	s, _ := NewSender(r, 8, 0, pkt)
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 64}
	w.run()
	if len(w.trace) != 11 || w.trace[10] != "-> W=0, FCN=All-1" || w.trace[0] != "-> W=0, FCN=0" {
		t.Fatalf("trace %v", w.trace)
	}
	got, ok := rv.Packet()
	if !ok || !bytes.Equal(got.Slice(0, pkt.Len()).Bytes(), pkt.Bytes()) {
		t.Fatalf("reassembly failed: %v", rv.Err())
	}
}

const aoeRule = `{"ruleId":6,"fragmentation":{"mode":"ack-on-error","wSize":1,"fcnSize":3,"windowSize":7,"tileBits":16,"lastTile":"all1","retransmissionTimer":"1m","inactivityTimer":"1h"}}`

// RFC 8724 figure 30: ACK-on-Error, 11 tiles, nothing lost.
// Covers: SIG-IPE-3790
func TestAckOnErrorFigure30(t *testing.T) {
	r := testRule(t, aoeRule)
	s, _ := NewSender(r, 8, 0, packetOf(11*16, 2))
	s.NextMTU = func() int { return 32 } // one 16-bit tile per fragment
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 64}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4
		-> W=0, FCN=3
		-> W=0, FCN=2
		-> W=0, FCN=1
		-> W=0, FCN=0
		-> W=1, FCN=6
		-> W=1, FCN=5
		-> W=1, FCN=4
		-> W=1, FCN=All-1
		<- ACK W=1 C=1`)
	if !s.Done() || s.Err() != nil {
		t.Fatal(s.Err())
	}
}

// RFC 8724 figure 31: ACK-on-Error, three fragments lost; the ACK for
// window 0 comes on the All-1 (this receiver does not acknowledge each
// window unless ackEveryWindow), with the figure's bitmaps.
// Covers: SIG-IPE-3790
func TestAckOnErrorFigure31(t *testing.T) {
	r := testRule(t, aoeRule)
	s, _ := NewSender(r, 8, 0, packetOf(11*16, 3))
	s.NextMTU = func() int { return 32 }
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 64,
		dropUp: func(n int, m *FragMsg) bool { return n == 3 || n == 5 || n == 10 }}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4 X
		-> W=0, FCN=3
		-> W=0, FCN=2 X
		-> W=0, FCN=1
		-> W=0, FCN=0
		-> W=1, FCN=6
		-> W=1, FCN=5
		-> W=1, FCN=4 X
		-> W=1, FCN=All-1
		<- ACK W=0 C=0 1101011
		-> W=0, FCN=4
		-> W=0, FCN=2
		-> W=1, ACK REQ
		<- ACK W=1 C=0 1100001
		-> W=1, FCN=4
		-> W=1, ACK REQ
		<- ACK W=1 C=1`)
	pkt, ok := rv.Packet()
	if !ok || !bytes.Equal(pkt.Slice(0, 11*16).Bytes(), packetOf(11*16, 3).Bytes()) {
		t.Fatal("packet not reassembled")
	}
}

const aaRule = `{"ruleId":7,"fragmentation":{"mode":"ack-always","wSize":1,"fcnSize":3,"windowSize":7,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`

// RFC 8724 figure 33: ACK-Always, 11 tiles, no loss.
// Covers: SIG-IPE-3789
func TestAckAlwaysFigure33(t *testing.T) {
	r := testRule(t, aaRule)
	// Header 12 bits: regular fragments of 32 bits carry 20-bit tiles; the
	// last 12 bits go in the All-1 (+32 RCS bits).
	s, _ := NewSender(r, 8, 0, packetOf(10*20+12, 4))
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 32}
	s.NextMTU = func() int {
		if s.pos >= 10*20 {
			return 64
		}
		return 32
	}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4
		-> W=0, FCN=3
		-> W=0, FCN=2
		-> W=0, FCN=1
		-> W=0, FCN=0
		<- ACK W=0 C=0 1111111
		-> W=1, FCN=6
		-> W=1, FCN=5
		-> W=1, FCN=4
		-> W=1, FCN=All-1
		<- ACK W=1 C=1`)
}

// RFC 8724 figure 34: ACK-Always with three lost fragments.
// Covers: SIG-IPE-3789
func TestAckAlwaysFigure34(t *testing.T) {
	r := testRule(t, aaRule)
	pkt := packetOf(10*20+12, 5)
	s, _ := NewSender(r, 8, 0, pkt)
	s.NextMTU = func() int {
		if s.pos >= 10*20 {
			return 64
		}
		return 32
	}
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 32,
		dropUp: func(n int, m *FragMsg) bool { return n == 3 || n == 5 || n == 12 }}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4 X
		-> W=0, FCN=3
		-> W=0, FCN=2 X
		-> W=0, FCN=1
		-> W=0, FCN=0
		<- ACK W=0 C=0 1101011
		-> W=0, FCN=4
		-> W=0, FCN=2
		<- ACK W=0 C=0 1111111
		-> W=1, FCN=6
		-> W=1, FCN=5
		-> W=1, FCN=4 X
		-> W=1, FCN=All-1
		<- ACK W=1 C=0 1100001
		-> W=1, FCN=4
		<- ACK W=1 C=1`)
	got, ok := rv.Packet()
	if !ok || !bytes.Equal(got.Slice(0, pkt.Len()).Bytes(), pkt.Bytes()) {
		t.Fatal("packet not reassembled")
	}
}

// RFC 8724 figures 36 and 37: six tiles, the final ACK or a resent
// fragment lost; the retransmission timer brings an ACK REQ. Figure 37
// draws the second bitmap 1111101, with a bit for tile 1, which was never
// sent (figure 35 leaves it 0 in the same position); we send 1111001
// (F-2103).
// Covers: SIG-IPE-3789
func TestAckAlwaysFigures36And37(t *testing.T) {
	r := testRule(t, aaRule)
	mk := func(seed int64) (*Sender, *Receiver, Bits) {
		pkt := packetOf(5*20+12, seed)
		s, _ := NewSender(r, 8, 0, pkt)
		s.NextMTU = func() int {
			if s.pos >= 5*20 {
				return 64
			}
			return 32
		}
		return s, NewReceiver(r, 8, 0, 0, time.Now()), pkt
	}
	s, rv, _ := mk(6)
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 32,
		dropUp:   func(n int, m *FragMsg) bool { return n >= 3 && n <= 5 },
		dropDown: func(n int, m *FragMsg) bool { return n == 2 }}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4 X
		-> W=0, FCN=3 X
		-> W=0, FCN=2 X
		-> W=0, FCN=All-1
		<- ACK W=0 C=0 1100001
		-> W=0, FCN=4
		-> W=0, FCN=3
		-> W=0, FCN=2
		<- ACK W=0 C=1 X
		-> W=0, ACK REQ
		<- ACK W=0 C=1`)
	s, rv, pkt := mk(7)
	w = &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 32,
		dropUp: func(n int, m *FragMsg) bool { return (n >= 3 && n <= 5) || n == 9 }}
	w.run()
	checkTrace(t, w.trace, `
		-> W=0, FCN=6
		-> W=0, FCN=5
		-> W=0, FCN=4 X
		-> W=0, FCN=3 X
		-> W=0, FCN=2 X
		-> W=0, FCN=All-1
		<- ACK W=0 C=0 1100001
		-> W=0, FCN=4
		-> W=0, FCN=3
		-> W=0, FCN=2 X
		-> W=0, ACK REQ
		<- ACK W=0 C=0 1111001
		-> W=0, FCN=2
		<- ACK W=0 C=1`)
	got, ok := rv.Packet()
	if !ok || !bytes.Equal(got.Slice(0, pkt.Len()).Bytes(), pkt.Bytes()) {
		t.Fatal("packet not reassembled")
	}
}

// RFC 9011 appendix A.2: a 282-byte-and-5-bit SCHC Packet goes up in
// fragments of 1, 23 and 5 tiles (FCN 62, 61, 38, MTUs 11, 231 and 242
// bytes), then an All-1 with the RCS only, answered by ACK W=0 C=1.
// Covers: SIG-IPE-3792
func TestLoRaWANUplinkExampleA2(t *testing.T) {
	rs := RuleSet{Rules: []Rule{LoRaWANUplinkRule(FPortUp, 10, false)}}
	if err := rs.Compile(); err != nil {
		t.Fatal(err)
	}
	r := &rs.Rules[0]
	pkt := packetOf(282*8+5, 8)
	s, err := NewSender(r, 8, 0, pkt)
	if err != nil {
		t.Fatal(err)
	}
	mtus := []int{11, 231, 242}
	s.NextMTU = func() int { m := mtus[0]; mtus = mtus[1:]; return 8 + 8*m }
	out, err := s.Start(time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("%d messages", len(out))
	}
	for i, want := range []struct {
		fcn, payloadBytes int
	}{{62, 11}, {61, 231}, {38, 44}, {63, 5}} {
		f, err := ToLoRaWAN(out[i])
		if err != nil {
			t.Fatal(err)
		}
		if f.FPort != 20 || int(f.Payload[0]&0x3F) != want.fcn || f.Payload[0]>>6 != 0 || len(f.Payload) != want.payloadBytes {
			t.Fatalf("message %d: FPort %d, W %d, FCN %d, %d bytes", i, f.FPort, f.Payload[0]>>6, f.Payload[0]&0x3F, len(f.Payload))
		}
	}
	rv := NewReceiver(r, 8, 0, 0, time.Now())
	var acks []Bits
	for _, m := range out {
		a, err := rv.Receive(time.Now(), m)
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, a...)
	}
	if len(acks) != 1 {
		t.Fatalf("%d ACKs", len(acks))
	}
	f, _ := ToLoRaWAN(acks[0])
	if f.FPort != 20 || !bytes.Equal(f.Payload, []byte{0x20}) {
		t.Fatalf("ACK is %d % x, want 20 20", f.FPort, f.Payload)
	}
	got, ok := rv.Packet()
	if !ok || !bytes.Equal(got.Slice(0, pkt.Len()).Bytes(), pkt.Bytes()) {
		t.Fatal("not reassembled")
	}
	if _, err := s.Receive(time.Now(), acks[0], 0); err != nil || !s.Done() {
		t.Fatal("sender not done")
	}
}

// RFC 9011 appendix A.3: a 130-byte-and-5-bit packet goes down in tiles of
// 50 bytes 6 bits, 48 bytes 6 bits and (in the All-1) 31 bytes 1 bit. The
// device's ACK after an All-0 is C=0 with bitmap 1 (5.6.3.5.1 note; the
// appendix draws C=1, which this sender also takes: F-2101).
// Covers: SIG-IPE-3793
func TestLoRaWANDownlinkExampleA3(t *testing.T) {
	rs := RuleSet{Rules: []Rule{LoRaWANDownlinkRule(FPortDown, ClassA, 0)}}
	if err := rs.Compile(); err != nil {
		t.Fatal(err)
	}
	r := &rs.Rules[0]
	pkt := packetOf(130*8+5, 9)
	for _, appendixC1 := range []bool{false, true} {
		s, _ := NewSender(r, 8, 0, pkt)
		mtus := []int{51, 49, 51}
		s.NextMTU = func() int { m := mtus[0]; mtus = mtus[1:]; return 8 + 8*m }
		rv := NewReceiver(r, 8, 0, 0, time.Now())
		msgs, _ := s.Start(time.Now(), 0)
		var sizes []int
		for step := 0; step < 3; step++ {
			if len(msgs) != 1 {
				t.Fatalf("step %d: %d messages", step, len(msgs))
			}
			f, _ := ToLoRaWAN(msgs[0])
			sizes = append(sizes, len(f.Payload))
			acks, err := rv.Receive(time.Now(), msgs[0])
			if err != nil || len(acks) != 1 {
				t.Fatalf("step %d: %v %d", step, err, len(acks))
			}
			a, _ := ToLoRaWAN(acks[0])
			w := byte(step & 1)
			want := []byte{w<<7 | 0x20} // C=0, bitmap 1
			if step == 2 {
				want = []byte{0x40} // W=0, C=1
			}
			if !bytes.Equal(a.Payload, want) {
				t.Fatalf("step %d: ACK % x, want % x", step, a.Payload, want)
			}
			if appendixC1 && step < 2 {
				acks[0] = FromLoRaWAN(FPortDown, []byte{w<<7 | 0x40})
			}
			msgs, err = s.Receive(time.Now(), acks[0], 0)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !s.Done() || s.Err() != nil {
			t.Fatalf("sender: %v", s.Err())
		}
		// Figure 34 labels the last payload 37 bytes, counting the FPort,
		// unlike figure 29's 51 (F-2102): the FRMPayload is 36 bytes.
		if fmt.Sprint(sizes) != "[51 49 36]" {
			t.Fatalf("payload sizes %v, want 51 49 36", sizes)
		}
		got, ok := rv.Packet()
		if !ok || !bytes.Equal(got.Slice(0, pkt.Len()).Bytes(), pkt.Bytes()) {
			t.Fatal("not reassembled")
		}
	}
}

// Property: every mode delivers random packets across random losses, or
// both ends give up; nothing else happens.
// Covers: SIG-IPE-3791
func TestFragmentationRandomLoss(t *testing.T) {
	rules := map[string]string{
		"no-ack":           `{"ruleId":1,"fragmentation":{"mode":"no-ack","fcnSize":1}}`,
		"ack-always":       aaRule,
		"ack-on-error":     aoeRule,
		"aoe-lorawan-like": `{"ruleId":20,"fragmentation":{"mode":"ack-on-error","wSize":2,"fcnSize":6,"windowSize":63,"tileBytes":10,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`,
		"aoe-every-window": `{"ruleId":20,"fragmentation":{"mode":"ack-on-error","wSize":2,"fcnSize":6,"windowSize":5,"tileBytes":3,"ackEveryWindow":true,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`,
		"aoe-regular-last": `{"ruleId":20,"fragmentation":{"mode":"ack-on-error","wSize":2,"fcnSize":3,"tileBytes":2,"lastTile":"regular","retransmissionTimer":"1m","inactivityTimer":"1h"}}`,
	}
	for name, js := range rules {
		r := testRule(t, js)
		for seed := int64(0); seed < 150; seed++ {
			rnd := rand.New(rand.NewSource(seed))
			n := 1 + rnd.Intn(600*8)
			if r.Fragmentation.Mode == AckOnError {
				n = min(n, (1<<uint(r.Fragmentation.WSize))*r.Fragmentation.WindowSize*r.Fragmentation.TileSize)
			}
			pkt := packetOf(n, seed)
			s, err := NewSender(r, 8, 0, pkt)
			if err != nil {
				t.Fatal(err)
			}
			rv := NewReceiver(r, 8, 0, 0, time.Now())
			loss := 0.0
			if r.Fragmentation.Mode != NoAck {
				loss = rnd.Float64() * 0.3
			}
			w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 8 * (18 + rnd.Intn(60)),
				dropUp:   func(int, *FragMsg) bool { return rnd.Float64() < loss },
				dropDown: func(int, *FragMsg) bool { return rnd.Float64() < loss },
			}
			w.run()
			got, ok := rv.Packet()
			if ok && !bytes.Equal(got.Slice(0, min(pkt.Len(), got.Len())).Bytes(), pkt.Bytes()) {
				t.Fatalf("%s seed %d: wrong packet delivered", name, seed)
			}
			if ok && got.Len()-pkt.Len() >= 8 {
				t.Fatalf("%s seed %d: %d extra bits", name, seed, got.Len()-pkt.Len())
			}
			if s.Done() && s.Err() == nil && !ok {
				t.Fatalf("%s seed %d: the sender succeeded but no packet\n%s", name, seed, strings.Join(w.trace, "\n"))
			}
			if loss == 0 && !ok {
				t.Fatalf("%s seed %d: lossless transfer failed: %v / %v\n%s", name, seed, s.Err(), rv.Err(), strings.Join(w.trace, "\n"))
			}
		}
	}
}

// Fuzz: decoding at either end never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	rs := RuleSet{Rules: []Rule{LoRaWANUplinkRule(20, 10, true), LoRaWANDownlinkRule(21, ClassA, 0)}}
	if err := rs.Compile(); err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{20, 0x3E, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	f.Add([]byte{21, 0x40})
	f.Fuzz(func(t *testing.T, b []byte) {
		msg := BytesOf(b)
		for i := range rs.Rules {
			r := &rs.Rules[i]
			_, _ = DecodeAtReceiver(r, msg, 8)
			_, _ = DecodeAtSender(r, msg, 8)
			rv := NewReceiver(r, 8, 0, 64, time.Now())
			_, _ = rv.Receive(time.Now(), msg)
		}
	})
}
