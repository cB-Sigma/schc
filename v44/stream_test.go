// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
)

func mustEncoder(t *testing.T, m Method, p Params) *Encoder {
	t.Helper()
	e, err := NewEncoder(m, p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustDecoder(t *testing.T, m Method, p Params) *Decoder {
	t.Helper()
	d, err := NewDecoder(m, p)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// textPacket is a packet of words from a small vocabulary, so that later
// packets repeat what earlier ones said.
func textPacket(rng *rand.Rand, n int) []byte {
	words := []string{"meter ", "reading ", "0.8.0 ", "voltage ", "230.1 ", "current ", "status OK ", "{\"id\":", "\"value\":", "}, "}
	var b []byte
	for len(b) < n {
		b = append(b, words[rng.Intn(len(words))]...)
	}
	return b[:n]
}

// B.2: a dictionary kept across packets compresses a run of similar
// packets better than the packet method, and the peer decoder follows,
// packet by packet.
func TestMultiPacketRoundTrip(t *testing.T) {
	for _, p := range []Params{{}, {Codewords: 256, History: 512}, {Codewords: 300, MaxString: 32, History: 600}} {
		rng := rand.New(rand.NewSource(int64(p.Codewords)))
		e := mustEncoder(t, MultiPacket, p)
		d := mustDecoder(t, MultiPacket, p)
		multi, single := 0, 0
		for i := 0; i < 200; i++ {
			pkt := textPacket(rng, 20+rng.Intn(400))
			if i%17 == 0 {
				pkt = make([]byte, rng.Intn(300))
				rng.Read(pkt) // incompressible
			}
			c, compressed := e.PacketOrRaw(pkt)
			back, err := d.Packet(c)
			if err != nil {
				t.Fatalf("%+v packet %d: %v", p, i, err)
			}
			if !bytes.Equal(back, pkt) {
				t.Fatalf("%+v packet %d (compressed %v): got %q\nwant %q", p, i, compressed, back, pkt)
			}
			s, _ := Compress(Params{Codewords: max(p.Codewords, 256), MaxString: p.MaxString}, pkt)
			multi, single = multi+len(c), single+len(s)
		}
		if multi >= single {
			t.Errorf("%+v: multi-packet %d octets, packet method %d", p, multi, single)
		}
		if p.Codewords == 256 && e.e.reinits == 0 {
			t.Errorf("no REINIT with N2 256 and N8 512")
		}
	}
}

// B.2.1: the history filling in the middle of a packet and the node-tree
// filling both bring REINIT, mid-packet, and the decoder follows.
func TestMultiPacketReinit(t *testing.T) {
	p := Params{Codewords: 256, History: 512}
	e := mustEncoder(t, MultiPacket, p)
	d := mustDecoder(t, MultiPacket, p)
	rng := rand.New(rand.NewSource(7))
	pkt := textPacket(rng, 1500) // three histories' worth
	c := e.Packet(pkt)
	if e.e.reinits < 2 {
		t.Fatalf("%d REINITs for 1500 characters in a 512-character history", e.e.reinits)
	}
	back, err := d.Packet(c)
	if err != nil || !bytes.Equal(back, pkt) {
		t.Fatalf("%v", err)
	}
	// A decoder with a smaller node-tree than the encoder's refuses
	// (codewords beyond its C1, 7.15).
	e = mustEncoder(t, MultiPacket, Params{Codewords: 1024})
	small := mustDecoder(t, MultiPacket, Params{Codewords: 256})
	if _, err := small.Packet(e.Packet(textPacket(rng, 3000))); err == nil {
		t.Fatal("a decoder with N2 256 took an N2 1024 stream")
	}
}

// A corrupted packet stops the decoder until a new one is made: the
// dictionaries of the two ends no longer agree.
func TestMultiPacketErrorIsSticky(t *testing.T) {
	e := mustEncoder(t, MultiPacket, Params{})
	d := mustDecoder(t, MultiPacket, Params{})
	c := e.Packet([]byte("hello hello hello"))
	bad := append([]byte{0xFF, 0xFF}, c...)
	if _, err := d.Packet(bad); err == nil {
		t.Fatal("garbage decoded")
	}
	if _, err := d.Packet(c); err == nil {
		t.Fatal("the decoder went on after an error")
	}
}

// The stream method: whatever the chunking of input and output and
// wherever the flushes fall, the decoder gives back the stream.
func TestStreamRoundTrip(t *testing.T) {
	for seed := int64(0); seed < 60; seed++ {
		rng := rand.New(rand.NewSource(seed))
		p := Params{}
		if seed%3 == 1 {
			p = Params{Codewords: 256, MaxString: 40, History: 512}
		}
		e := mustEncoder(t, Stream, p)
		d := mustDecoder(t, Stream, p)
		var in, wire, out []byte
		feed := func(b []byte) {
			wire = append(wire, b...)
			for len(wire) > 0 && rng.Intn(3) != 0 {
				n := 1 + rng.Intn(len(wire))
				got, err := d.Write(wire[:n])
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				out = append(out, got...)
				wire = wire[n:]
			}
		}
		for i := 0; i < 40; i++ {
			chunk := textPacket(rng, rng.Intn(200))
			if rng.Intn(5) == 0 {
				chunk = make([]byte, rng.Intn(100))
				rng.Read(chunk)
			}
			in = append(in, chunk...)
			feed(e.Write(chunk))
			if rng.Intn(4) == 0 {
				feed(e.Flush())
			}
		}
		feed(e.Flush())
		got, err := d.Write(wire)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got...)
		if !bytes.Equal(out, in) {
			t.Fatalf("seed %d: %d characters back of %d", seed, len(out), len(in))
		}
	}
}

// 6.5 and 7.14: transparent mode carries the characters as they are, with
// the ESCAPE (0, then +51 each time it occurs) followed by EID; ESCAPE ECM
// returns to compressed mode with new dictionaries. Auto switches by the
// test of 7.11.5.
func TestStreamTransparentMode(t *testing.T) {
	e := mustEncoder(t, Stream, Params{})
	d := mustDecoder(t, Stream, Params{})
	var wire []byte
	wire = append(wire, e.Write([]byte("compressed compressed compressed"))...)
	wire = append(wire, e.SetTransparent(true)...)
	raw := []byte{'a', 0, 'b', 51, 0, 102, 'c'}
	tr := e.Write(raw)
	// 0 is the ESCAPE: 0 EID; then the ESCAPE is 51: 51 EID; then 102.
	if want := []byte{'a', 0, 1, 'b', 51, 1, 0, 102, 1, 'c'}; !bytes.Equal(tr, want) {
		t.Fatalf("transparent octets % x, want % x", tr, want)
	}
	wire = append(wire, tr...)
	wire = append(wire, e.SetTransparent(false)...)
	wire = append(wire, e.Write([]byte(" and compressed again"))...)
	wire = append(wire, e.Flush()...)
	got, err := d.Write(wire)
	want := "compressed compressed compressed" + string(raw) + " and compressed again"
	if err != nil || string(got) != want {
		t.Fatalf("got %q, %v", got, err)
	}

	// Auto: random data goes transparent after its flush, text brings it
	// back.
	e = mustEncoder(t, Stream, Params{})
	e.Auto = true
	d = mustDecoder(t, Stream, Params{})
	rng := rand.New(rand.NewSource(1))
	var in, out []byte
	modes := map[bool]int{}
	for i := 0; i < 30; i++ {
		var chunk []byte
		if i%10 < 5 {
			chunk = make([]byte, 300)
			rng.Read(chunk)
		} else {
			chunk = textPacket(rng, 300)
		}
		in = append(in, chunk...)
		b := append(e.Write(chunk), e.Flush()...)
		modes[e.transparent]++
		got, err := d.Write(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got...)
	}
	if !bytes.Equal(in, out) || modes[true] == 0 || modes[false] == 0 {
		t.Fatalf("auto: back %v, modes %v", bytes.Equal(in, out), modes)
	}
}

// 7.4.2: parameters sent in parameter mode reach the peer decoder's
// OnParameters, in transparent mode.
func TestStreamParameterMode(t *testing.T) {
	e := mustEncoder(t, Stream, Params{})
	d := mustDecoder(t, Stream, Params{})
	var got []Parameter
	d.OnParameters = func(ps []Parameter) { got = ps }
	prop := Proposal{Transmit: true, Receive: true, TxCodewords: 2048, RxCodewords: 512, TxMaxString: 64}
	b, err := e.SendParameters(prop.Parameters())
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, e.Write([]byte{0, 0})...) // ESCAPE in data while transparent
	out, err := d.Write(b)
	if err != nil || !bytes.Equal(out, []byte{0, 0}) {
		t.Fatalf("out % x, %v", out, err)
	}
	back, err := ProposalOf(got)
	if err != nil || back != prop {
		t.Fatalf("parameters %+v, %v", back, err)
	}
}

// Appendix II.1 as a stream: the characters written and flushed give the
// octets of Table II.1, as the packet method does; the next character
// creates codeword 15, which the appendix's encoder made "sight-unseen"
// for the character after the FLUSH, on root C; the decoder creates it
// on the code after the FLUSH.
func TestStreamAppendixII1Continued(t *testing.T) {
	e := mustEncoder(t, Stream, DefaultParams())
	d := mustDecoder(t, Stream, DefaultParams())
	in := []byte("ABCDEXABCDEYABCDE\xffAC")
	got := append(e.Write(in), e.Flush()...)
	want, _ := hex.DecodeString("828486888AB009295B29F8176468" + "00")
	if !bytes.Equal(got, want) {
		t.Fatalf("stream octets %X, want %X", got, want)
	}
	if _, err := d.Write(got); err != nil {
		t.Fatal(err)
	}
	if d.d.c1 != 15 {
		t.Fatalf("decoder C1 = %d after the FLUSH, want 15", d.d.c1)
	}
	more := append(e.Write([]byte("Q")), e.Flush()...)
	n := e.e.nodes[15]
	if e.e.c1 != 16 || n.pos != 20 || n.length != 1 || e.e.root['C'] != 6 || e.e.nodes[6].side != 15 {
		t.Fatalf("codeword 15: %+v, C1 %d", n, e.e.c1)
	}
	out, err := d.Write(more)
	if err != nil || string(out) != "Q" || d.d.c1 != 16 {
		t.Fatalf("%q %v C1 %d", out, err, d.d.c1)
	}
	if s := d.d.strs[15]; s.last != 20 || s.length != 2 {
		t.Fatalf("decoder string 15: %+v, want CQ at 19-20", s)
	}
}

// Stream decoding of arbitrary input never panics and ends.
func FuzzStreamDecoder(f *testing.F) {
	e, _ := NewEncoder(Stream, Params{})
	f.Add(append(e.Write([]byte("hello hello hello")), e.Flush()...))
	f.Add([]byte{0x01, 'a', 0, 2, 0x43, 2, 4, 0, 0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, _ := NewDecoder(Stream, Params{Limit: 1 << 16})
		for len(b) > 0 {
			n := 1 + int(b[0])%7
			if n > len(b) {
				n = len(b)
			}
			if _, err := d.Write(b[:n]); err != nil {
				return
			}
			b = b[n:]
		}
	})
}

// Annex A, Table A.1: the XID user data subfield; 7.4 and annex B: the
// agreement.
func TestXIDAndAgreement(t *testing.T) {
	a := Proposal{Packet: true, MultiPacket: true, Transmit: true, Receive: true, TxCodewords: 2048, RxCodewords: 1024, TxMaxString: 255, RxMaxString: 100, TxHistory: 6144}
	x := a.MarshalXID()
	if !strings.HasPrefix(hex.EncodeToString(x), "ff4003563434"+"4101c0"+"420103"+"43020800"+"44020400") {
		t.Fatalf("XID % x", x)
	}
	back, err := ParseXID(x)
	if err != nil || back != a {
		t.Fatalf("%+v %v", back, err)
	}
	b := Proposal{Packet: true, Transmit: false, Receive: true, RxCodewords: 4096, TxCodewords: 512, RxMaxString: 64}
	ag, err := Agree(a, b)
	if err != nil {
		t.Fatal(err)
	}
	// a sends (b receives); b does not send.
	if !ag.TxOn || ag.RxOn || ag.Method != 0 {
		t.Fatalf("%+v", ag)
	}
	if ag.Tx.Codewords != 2048 || ag.Tx.MaxString != 64 || ag.Tx.History != 3*1024*2 {
		t.Fatalf("tx %+v", ag.Tx)
	}
	if ag.Rx.Codewords != 512 || ag.Rx.MaxString != 100 {
		t.Fatalf("rx %+v", ag.Rx)
	}
	if _, err := Agree(Proposal{TxCodewords: 100}, Proposal{}); err == nil {
		t.Fatal("N2 100 agreed")
	}
	if _, err := Agree(Proposal{Packet: true}, Proposal{}); err == nil {
		t.Fatal("a packet network agreed with a modem")
	}
	if ag, _ := Agree(Proposal{}, Proposal{}); ag.Method != Stream {
		t.Fatal("two modems do not use the stream method")
	}
	if _, err := ParseXID([]byte{0xFF, 0x40, 3, 'V', '4', '2'}); err == nil {
		t.Fatal("a V.42 bis set read as V.44")
	}
	if _, err := ParseXID([]byte{0xFF, 0x40, 3, 'V', '4', '4', 0x41, 1, 0x40}); err == nil {
		t.Fatal("PM = 01 accepted")
	}
}
