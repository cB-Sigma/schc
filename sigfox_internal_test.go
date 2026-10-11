// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func mustRule(r Rule, err error) Rule {
	if err != nil {
		panic(err)
	}
	return r
}

func compiled(t *testing.T, r Rule) *Rule {
	t.Helper()
	rs := &RuleSet{Rules: []Rule{r}}
	if err := rs.Compile(); err != nil {
		t.Fatal(err)
	}
	return &rs.Rules[0]
}

// sigfoxRun carries messages between a sender and a receiver as Sigfox
// does: messages that go down are padded to 8 bytes; drop loses messages
// sent up (fragments for an uplink rule, ACKs for a downlink one).
func sigfoxRun(t *testing.T, r *Rule, pkt Bits, drop func(n int) bool) (*Sender, *Receiver, []*FragMsg) {
	t.Helper()
	now := time.Unix(1_000_000, 0)
	s, err := NewSender(r, 8, 0, pkt)
	if err != nil {
		t.Fatal(err)
	}
	rv := NewReceiver(r, 8, 0, 0, now)
	mtu := SigfoxUplinkMTU
	down := r.Fragmentation.Direction == Down
	if down {
		mtu = SigfoxDownlinkMTU
	}
	frame := func(m Bits, isDown bool) Bits {
		if !isDown {
			if m.Len() > SigfoxUplinkMTU || m.Len()%8 != 0 {
				t.Fatalf("an uplink message of %d bits", m.Len())
			}
			return m
		}
		b, err := SigfoxDownlinkPayload(m)
		if err != nil {
			t.Fatal(err)
		}
		return BytesOf(b)
	}
	var log []*FragMsg
	toRx, err := s.Start(now, mtu)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for round := 0; round < 60; round++ {
		for _, m := range toRx {
			fm, err := DecodeAtReceiver(r, frame(m, down), 8)
			if err != nil {
				t.Fatalf("our fragment %s: %v", m, err)
			}
			log = append(log, fm)
			n++
			if !down && drop != nil && drop(n-1) {
				continue
			}
			acks, _ := rv.Receive(now, frame(m, down))
			for _, a := range acks {
				n++
				if down && drop != nil && drop(n-1) {
					continue
				}
				more, _ := s.Receive(now, frame(a, !down), mtu)
				toRx = append(toRx, more...)
			}
		}
		toRx = nil
		if s.Done() {
			break
		}
		now = now.Add(r.Fragmentation.Retransmission.D() + time.Second)
		toRx, _ = s.Tick(now)
	}
	return s, rv, log
}

// Covers: SIG-IPE-7306
func TestSigfoxUplinkAckOnError(t *testing.T) {
	for _, h := range []struct {
		name   string
		layout SigfoxHeader
		id     uint32
	}{{"single-byte", SigfoxSingleByte, 2}, {"two-byte-1", SigfoxTwoByte1, 0b111001}, {"two-byte-2", SigfoxTwoByte2, 0b11111101}} {
		r := compiled(t, mustRule(SigfoxUplinkRule(h.id, h.layout)))
		maxBytes := map[SigfoxHeader]int{SigfoxSingleByte: 300, SigfoxTwoByte1: 480, SigfoxTwoByte2: 2400}[h.layout]
		for seed := int64(0); seed < 120; seed++ {
			rnd := rand.New(rand.NewSource(seed))
			size := 1 + rnd.Intn(maxBytes)
			if seed < 4 {
				size = []int{maxBytes, 11, 10, 77}[seed]
			}
			pkt := packetOf(8*size, seed)
			loss := 0.0
			if seed%2 == 1 {
				loss = 0.2
			}
			s, rv, _ := sigfoxRun(t, r, pkt, func(int) bool { return rnd.Float64() < loss })
			got, ok := rv.Packet()
			if loss == 0 && (!ok || s.Err() != nil) {
				t.Fatalf("%s, %d bytes: delivered %v, sender %v, receiver %v", h.name, size, ok, s.Err(), rv.Err())
			}
			if ok && !bytes.Equal(got.Bytes(), pkt.Bytes()) {
				t.Fatalf("%s, %d bytes: got %d bits", h.name, size, got.Len())
			}
		}
	}
}

// Covers: SIG-IPE-7307
func TestSigfoxFormats(t *testing.T) {
	r := compiled(t, mustRule(SigfoxUplinkRule(2, SigfoxSingleByte)))
	// 2 tiles of 11 bytes and a last tile of 5 in the All-1: the All-1 is
	// the third fragment of window 0, so the count is 3.
	pkt := packetOf(8*27, 7)
	s, _ := NewSender(r, 8, 0, pkt)
	out, err := s.Start(time.Now(), SigfoxUplinkMTU)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[0].Len() != 96 || out[1].Len() != 96 {
		t.Fatalf("fragments %v", out)
	}
	// Regular: RuleID 010, W 00, FCN 110, then the 11-byte tile.
	if out[0].Bytes()[0] != 0b010_00_110 || !bytes.Equal(out[0].Bytes()[1:], pkt.Bytes()[:11]) {
		t.Fatalf("first fragment %x", out[0].Bytes())
	}
	// All-1: RuleID 010, W 00, FCN 111, RCS 011, five padding bits, tile.
	a := out[2].Bytes()
	if out[2].Len() != 16+40 || a[0] != 0b010_00_111 || a[1] != 0b011_00000 || !bytes.Equal(a[2:], pkt.Bytes()[22:]) {
		t.Fatalf("All-1 %08b", a)
	}
	// A Compound ACK for windows 0 and 1, padded to the 64-bit downlink:
	// RuleID 010, W 00, C 0, bitmap 1011111, W 01, bitmap 1100001, 00.
	ack := (&FragMsg{Kind: MsgAck, Rule: r, W: 0, Bitmap: bitsOf("1011111"),
		More: []WindowBitmap{{W: 1, Bitmap: bitsOf("1100001")}}}).Encode(8)
	frame, err := SigfoxDownlinkPayload(ack)
	if err != nil {
		t.Fatal(err)
	}
	want := "010" + "00" + "0" + "1011111" + "01" + "1100001" + "00"
	if got := BytesOf(frame).String(); got[:len(want)] != want || bytes.Count([]byte(got[len(want):]), []byte("1")) != 0 || len(got) != 64 {
		t.Fatalf("Compound ACK %s\nwant %s then zeros", got, want)
	}
	m, err := DecodeAtSender(r, BytesOf(frame), 8)
	if err != nil || m.W != 0 || len(m.More) != 1 || m.More[0].W != 1 || fmt.Sprint(m.More[0].Bitmap) != fmt.Sprint(bitsOf("1100001")) {
		t.Fatalf("decoded %+v %v", m, err)
	}
	// Sender-Abort: one byte, W 11, FCN 111.
	if sa := (&FragMsg{Kind: MsgSenderAbort, Rule: r}).Encode(8); sa.Len() != 8 || sa.Bytes()[0] != 0b010_11_111 {
		t.Fatalf("Sender-Abort %s", sa)
	}
}

func bitsOf(s string) []bool {
	out := make([]bool, len(s))
	for i := range s {
		out[i] = s[i] == '1'
	}
	return out
}

// Covers: SIG-IPE-7308
func TestSigfoxUplinkNoAck(t *testing.T) {
	r := compiled(t, mustRule(SigfoxUplinkNoAckRule(1)))
	for _, size := range []int{1, 10, 11, 12, 22, 100, 340} {
		pkt := packetOf(8*size, int64(size))
		s, rv, log := sigfoxRun(t, r, pkt, nil)
		got, ok := rv.Packet()
		if !ok || s.Err() != nil || !bytes.Equal(got.Bytes(), pkt.Bytes()) {
			t.Fatalf("%d bytes: %v %v %v", size, ok, s.Err(), rv.Err())
		}
		// FCN from the fragment count less one down to 1, then All-1.
		for i, m := range log[:len(log)-1] {
			if m.FCN != uint32(len(log)-1-i) || m.Payload.Len() != 88 {
				t.Fatalf("%d bytes: fragment %d FCN %d, %d bits", size, i, m.FCN, m.Payload.Len())
			}
		}
		if last := log[len(log)-1]; last.Kind != MsgAll1 || last.RCS != uint32(len(log))%32 {
			t.Fatalf("%d bytes: All-1 %+v", size, last)
		}
	}
	// A lost fragment fails the count.
	pkt := packetOf(8*100, 1)
	_, rv, _ := sigfoxRun(t, r, pkt, func(n int) bool { return n == 3 })
	if _, ok := rv.Packet(); ok {
		t.Fatal("a packet with a fragment lost passed the count")
	}
	if _, err := SigfoxUplinkNoAckRule(7); err == nil {
		t.Fatal("RuleID 7 is the two-byte prefix")
	}
}

// Covers: SIG-IPE-7309
func TestSigfoxDownlinkAckAlways(t *testing.T) {
	r := compiled(t, mustRule(SigfoxDownlinkRule(5)))
	for seed := int64(0); seed < 80; seed++ {
		rnd := rand.New(rand.NewSource(seed))
		size := 1 + rnd.Intn(31*7-1)
		pkt := packetOf(8*size, seed)
		loss := 0.0
		if seed%2 == 1 {
			loss = 0.2
		}
		s, rv, _ := sigfoxRun(t, r, pkt, func(int) bool { return rnd.Float64() < loss })
		got, ok := rv.Packet()
		if loss == 0 && (!ok || s.Err() != nil) {
			t.Fatalf("%d bytes: delivered %v, sender %v, receiver %v", size, ok, s.Err(), rv.Err())
		}
		// The All-1's padding to 8 bytes stays on the packet (RFC 9442
		// gives no way to tell it from the tile).
		if ok && !bytes.Equal(got.Bytes()[:size], pkt.Bytes()) {
			t.Fatalf("%d bytes: wrong packet", size)
		}
	}
	// More than one window does not fit a rule without W.
	if s, _, _ := sigfoxRun(t, r, packetOf(8*7*32, 1), nil); s.Err() == nil {
		t.Fatal("a packet of two windows went through a rule without W")
	}
}
