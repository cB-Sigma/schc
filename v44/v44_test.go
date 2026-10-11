// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// packBits packs a string of '0'/'1' in order of transmission into octets,
// first bit into bit 1 (6.6); spaces are ignored and the tail is padded
// with zeros.
func packBits(t *testing.T, s string) []byte {
	t.Helper()
	var w bitWriter
	for _, c := range strings.ReplaceAll(s, " ", "") {
		switch c {
		case '0':
			w.bit(0)
		case '1':
			w.bit(1)
		default:
			t.Fatalf("bad bit %q", c)
		}
	}
	w.align()
	return w.out
}

// lsb renders v as n bits, least significant first (order of transmission).
func lsb(v, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + v>>i&1))
	}
	return b.String()
}

// trace decodes src code by code, calling after(codes) after each code.
func trace(t *testing.T, p Params, src []byte, after func(d *decoder, codes int)) *decoder {
	t.Helper()
	d := newDecoder(p.withDefaults(), src)
	for codes := 1; !d.flushed; codes++ {
		if err := d.step(); err != nil {
			t.Fatalf("code %d: %v", codes, err)
		}
		after(d, codes)
	}
	return d
}

type wantNode struct{ cw, pos, length, down, side int }

func checkNodes(t *testing.T, e *encoder, want []wantNode, roots map[byte]int) {
	t.Helper()
	if e.c1 != firstCW+len(want) {
		t.Errorf("encoder C1 = %d, want %d", e.c1, firstCW+len(want))
	}
	for _, w := range want {
		if w.cw >= len(e.nodes) {
			t.Errorf("codeword %d not created", w.cw)
			continue
		}
		n := e.nodes[w.cw]
		if n.pos != w.pos || n.length != w.length || n.down != w.down || n.side != w.side {
			t.Errorf("codeword %d: position %d length %d down %d side %d, want %d %d %d %d", w.cw, n.pos, n.length, n.down, n.side, w.pos, w.length, w.down, w.side)
		}
	}
	for c := 0; c < 256; c++ {
		want, ok := roots[byte(c)]
		if !ok {
			want = -1
		}
		if e.root[c] != want {
			t.Errorf("root %#x down-index %d, want %d", c, e.root[c], want)
		}
	}
}

// Appendix II.1: "ABCDEXABCDEYABCDE FFH AC" gives exactly the octets of
// Table II.1, the encoder node-tree and root array of stage 11, and the
// decoder string collection and history at the end of every stage.
// Corrigendum 1 changes only the typesetting of FFH in the stage 10
// histories and the page layout, nothing a test can see.
//
// Covers: SIG-IPE-662
func TestAppendixII1(t *testing.T) {
	in := []byte("ABCDEXABCDEYABCDE\xffAC")
	want, _ := hex.DecodeString("828486888AB009295B29F8176468" + "00")
	p := DefaultParams()
	e := newEncoder(p, in)
	e.run()
	if !bytes.Equal(e.w.out, want) {
		t.Fatalf("compressed\n%X, want Table II.1\n%X", e.w.out, want)
	}
	// Stage 11's node-tree, less codeword 15: the appendix's encoder
	// appends the character after the final "C" before it arrives
	// ("sight-unseen"); ours creates a node only for a character that
	// exists, and the packet ends there. Codes transferred are the same.
	checkNodes(t, e, []wantNode{
		{4, 1, 1, 10, 14}, {5, 2, 1, -1, -1}, {6, 3, 1, -1, -1}, {7, 4, 1, -1, -1}, {8, 5, 1, -1, -1},
		{9, 6, 1, -1, -1}, {10, 8, 3, 12, -1}, {11, 12, 1, -1, -1}, {12, 17, 1, -1, -1}, {13, 18, 1, -1, -1},
		{14, 19, 1, -1, -1},
	}, map[byte]int{'A': 4, 'B': 5, 'C': 6, 'D': 7, 'E': 8, 'X': 9, 'Y': 11, 0xFF: 13})

	// Decoder: after the codes of each stage, the history length and the
	// whole string collection (codeword: last-character position, length).
	type stage struct {
		name    string
		codes   int
		history int
		strs    map[int]str
	}
	s2 := map[int]str{4: {1, 2}}
	s6 := map[int]str{4: {1, 2}, 5: {2, 2}, 6: {3, 2}, 7: {4, 2}, 8: {5, 2}}
	s7 := merge(s6, map[int]str{9: {6, 2}})
	s8 := merge(s7, map[int]str{10: {10, 5}})
	s9 := merge(s8, map[int]str{11: {12, 2}})
	s10 := merge(s9, map[int]str{12: {17, 6}})
	s11 := merge(s10, map[int]str{13: {18, 2}, 14: {19, 2}})
	stages := []stage{
		{"stage 1", 1, 1, map[int]str{}},
		{"stage 2", 2, 2, s2},
		{"stages 3-6", 6, 6, s6},
		{"stage 7", 7, 8, s7},
		{"stage 8b", 9, 12, s8},
		{"stage 9", 10, 17, s9},
		{"stage 10", 12, 18, s10},
		{"stage 11", 15, 20, s11},
	}
	next := 0
	d := trace(t, p, want, func(d *decoder, codes int) {
		if next < len(stages) && stages[next].codes == codes {
			st := stages[next]
			next++
			if len(d.out) != st.history {
				t.Errorf("%s: history %d characters, want %d", st.name, len(d.out), st.history)
			}
			if got := collection(d); !equalStrs(got, st.strs) {
				t.Errorf("%s: string collection %v, want %v", st.name, got, st.strs)
			}
		}
	})
	if next != len(stages) {
		t.Errorf("decoded %d stages of %d", next, len(stages))
	}
	if !bytes.Equal(d.out, in) {
		t.Errorf("decoded %q", d.out)
	}
	// "The decoder does not create codeword 15 until the code after the
	// FLUSH is received."
	if d.c1 != 15 {
		t.Errorf("decoder C1 = %d, want 15", d.c1)
	}
}

// Appendix II.2: "CCCCCCCCCCX" transfers ordinal C, codeword 4 (which the
// decoder has not created yet: 6.4.1 rule 4), string-extension length 7 and
// ordinal X. The appendix gives the codes, not octets; the expected octets
// here are those codes with the prefixes of Table 5 and the length coding
// of Table 3, then FLUSH.
//
// Covers: SIG-IPE-662
func TestAppendixII2(t *testing.T) {
	in := []byte("CCCCCCCCCCX")
	want := packBits(t, "0"+lsb('C', 7)+" 1"+lsb(4, 6)+" 01 0 00 0 "+lsb(2, 3)+" 0"+lsb('X', 7)+" 1"+lsb(ctlFLUSH, 6))
	p := DefaultParams()
	e := newEncoder(p, in)
	e.run()
	if !bytes.Equal(e.w.out, want) {
		t.Fatalf("compressed %X, want %X", e.w.out, want)
	}
	// Stage 5's node-tree less codeword 6 (the sight-unseen node after X).
	checkNodes(t, e, []wantNode{{4, 1, 1, 5, -1}, {5, 3, 7, -1, -1}}, map[byte]int{'C': 4})
	stages := map[int]struct {
		history int
		strs    map[int]str
	}{
		1: {1, map[int]str{}},
		2: {3, map[int]str{4: {1, 2}}},
		3: {10, map[int]str{4: {1, 2}, 5: {9, 9}}},
		4: {11, map[int]str{4: {1, 2}, 5: {9, 9}}},
	}
	d := trace(t, p, want, func(d *decoder, codes int) {
		if st, ok := stages[codes]; ok {
			if len(d.out) != st.history {
				t.Errorf("after code %d: history %d, want %d", codes, len(d.out), st.history)
			}
			if got := collection(d); !equalStrs(got, st.strs) {
				t.Errorf("after code %d: strings %v, want %v", codes, got, st.strs)
			}
		}
	})
	if !bytes.Equal(d.out, in) {
		t.Errorf("decoded %q", d.out)
	}
}

func merge(a, b map[int]str) map[int]str {
	out := map[int]str{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func collection(d *decoder) map[int]str {
	out := map[int]str{}
	for cw := firstCW; cw < d.c1; cw++ {
		out[cw] = d.strs[cw]
	}
	return out
}

func equalStrs(a, b map[int]str) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// 6.6.4 Table 6: codeword A with C2 = 11, ordinals B and C with C5 = 8,
// codeword D, string-extension length 8, ordinal E, then ETM and padding,
// land on exactly the bit positions of the table.
//
// Covers: SIG-IPE-662
func TestTransferExample(t *testing.T) {
	A, B, C, D, E := 0x5A5, 0xB7, 0x3C, 0x2D3, 0xC9
	e := newEncoder(DefaultParams(), nil)
	e.c2, e.c3, e.c5 = 11, 1<<11, 8
	e.w.bits(0, 2) // bits 1 and 2 of octet i belong to earlier codes
	e.codeword(A)
	e.ordinal(byte(B))
	e.ordinal(byte(C))
	e.codeword(D)
	e.extensionLength(8)
	e.ordinal(byte(E))
	e.control(ctlETM)
	e.w.align()
	sym := func(v int) func(int) string {
		return func(i int) string { return fmt.Sprint(v >> (i - 1) & 1) }
	}
	a, b, c, dd, ee := sym(A), sym(B), sym(C), sym(D), sym(E)
	// Rows of Table 6, bit 8 down to bit 1.
	rows := [][]string{
		{a(5), a(4), a(3), a(2), a(1), "1", "0", "0"},
		{"0", "0", a(11), a(10), a(9), a(8), a(7), a(6)},
		{b(8), b(7), b(6), b(5), b(4), b(3), b(2), b(1)},
		{c(7), c(6), c(5), c(4), c(3), c(2), c(1), "0"},
		{dd(6), dd(5), dd(4), dd(3), dd(2), dd(1), "1", c(8)},
		{"0", "1", "0", dd(11), dd(10), dd(9), dd(8), dd(7)},
		{ee(1), "0", "0", "1", "1", "0", "0", "0"},
		{"1", ee(8), ee(7), ee(6), ee(5), ee(4), ee(3), ee(2)},
		{"0", "0", "0", "0", "0", "0", "0", "0"},
		{"0", "0", "0", "0", "0", "0", "0", "0"},
	}
	var want []byte
	for _, r := range rows {
		var o byte
		for i, s := range r {
			if s == "1" {
				o |= 1 << (7 - i)
			}
		}
		want = append(want, o)
	}
	if !bytes.Equal(e.w.out, want) {
		t.Errorf("octets %X, want Table 6 %X", e.w.out, want)
	}
}

// Tables 3 and 4: every string-extension length reads back, for each N7
// width band, and lengths 1 to 12 have the bit patterns of Table 3.
//
// Covers: SIG-IPE-662
func TestExtensionLengths(t *testing.T) {
	table3 := map[int]string{1: "1", 2: "0 10", 3: "0 01", 4: "0 11", 5: "0 00 0 000", 6: "0 00 0 100",
		7: "0 00 0 010", 8: "0 00 0 110", 9: "0 00 0 001", 10: "0 00 0 101", 11: "0 00 0 011", 12: "0 00 0 111"}
	for k, bitsStr := range table3 {
		var w bitWriter
		w.writeExtension(k, 255)
		w.align()
		if want := packBits(t, bitsStr); !bytes.Equal(w.out, want) {
			t.Errorf("length %d: %X, want %X", k, w.out, want)
		}
	}
	for _, n7 := range []int{32, 46, 47, 78, 79, 142, 143, 255} {
		for k := 1; k <= n7-2 && k <= 253; k++ {
			var w bitWriter
			w.writeExtension(k, n7)
			w.align()
			d := newDecoder(Params{MaxString: n7}.withDefaults(), w.out)
			got, err := d.readExtension()
			if err != nil || got != k {
				t.Fatalf("N7 %d length %d: read %d, %v", n7, k, got, err)
			}
		}
	}
	if extensionBits(46) != 5 || extensionBits(47) != 6 || extensionBits(78) != 6 || extensionBits(79) != 7 ||
		extensionBits(142) != 7 || extensionBits(143) != 8 {
		t.Error("Table 4 bands")
	}
}

func roundTrip(t *testing.T, p Params, in []byte) []byte {
	t.Helper()
	c, err := Compress(p, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decompress(p, c)
	if err != nil {
		t.Fatalf("%d octets: %v", len(in), err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("%d octets did not round-trip (got %d)", len(in), len(out))
	}
	return c
}

// Round trips: empty input, all byte values, random data, text, long runs
// of one character, repeats longer than N7, and each N7 band.
//
// Covers: SIG-IPE-663
func TestRoundTrip(t *testing.T) {
	p := DefaultParams()
	// Empty: FLUSH alone ("1" then 1 in six bits), one octet.
	if c := roundTrip(t, p, nil); !bytes.Equal(c, []byte{0x03}) {
		t.Errorf("empty packet: %X, want 03", c)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	roundTrip(t, p, all)
	roundTrip(t, p, bytes.Repeat(all, 40))
	rng := rand.New(rand.NewSource(44))
	for _, n := range []int{1, 2, 3, 7, 64, 255, 256, 1000, 4096, 70000} {
		b := make([]byte, n)
		rng.Read(b)
		roundTrip(t, p, b)
	}
	text := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog; DLMS COSEM get-response ", 300))
	if c := roundTrip(t, p, text); len(c)*5 > len(text) {
		t.Errorf("text compressed to %d of %d", len(c), len(text))
	}
	run := bytes.Repeat([]byte{'C'}, 100000)
	if c := roundTrip(t, p, run); len(c) > 1000 {
		t.Errorf("a run of 100000 compressed to %d", len(c))
	}
	for _, n7 := range []int{32, 46, 47, 78, 79, 142, 143, 255} {
		q := Params{MaxString: n7}
		roundTrip(t, q, run[:5000])
		roundTrip(t, q, text)
		// Small alphabets make many long repeats and deep trees.
		b := make([]byte, 20000)
		for i := range b {
			b[i] = "ab"[rng.Intn(2)]
		}
		roundTrip(t, q, b)
	}
	// Structured: repeated records with a changing counter.
	var rec []byte
	for i := 0; i < 2000; i++ {
		rec = append(rec, 0x02, 0x03, 0x09, 0x0C, 0x07, 0xE2, byte(i>>8), byte(i), 0x06, 0, 1, byte(i*7), byte(i*13))
	}
	roundTrip(t, p, rec)
}

// Random inputs of every size up to 600, from several alphabets.
//
// Covers: SIG-IPE-663
func TestRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for n := 0; n <= 600; n++ {
		for _, alpha := range []int{1, 2, 3, 16, 256} {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(0x7E + rng.Intn(alpha)) // straddles 127: ordinal STEPUP
			}
			roundTrip(t, DefaultParams(), b)
			roundTrip(t, Params{Codewords: 256, MaxString: 32}, b)
		}
	}
}

// 7.11.2: codewords up to 63 go in 6 bits; 64 needs STEPUP first, and the
// codeword size then doubles its threshold each STEPUP, up to N1 (11 bits
// for 1525 codewords). 7.11.1: the ordinal size steps to 8 once.
//
// Covers: SIG-IPE-663
func TestStepup(t *testing.T) {
	e := newEncoder(DefaultParams(), nil)
	e.codeword(63)
	if e.c2 != 6 || len(e.w.out) != 0 || e.w.nacc != 7 {
		t.Fatalf("codeword 63: C2 %d, %d bits", e.c2, e.w.nacc)
	}
	e.codeword(64)
	// STEPUP ("1" + 2 in 6 bits) then "1" + 64 in 7 bits.
	e.w.align()
	want := packBits(t, "1"+lsb(63, 6)+" 1"+lsb(ctlSTEPUP, 6)+" 1"+lsb(64, 7))
	if !bytes.Equal(e.w.out, want) || e.c2 != 7 || e.c3 != 128 {
		t.Errorf("codeword 64: %X C2 %d C3 %d, want %X", e.w.out, e.c2, e.c3, want)
	}
	// Several steps at once: 300 from 6 bits needs three STEPUPs.
	e = newEncoder(DefaultParams(), nil)
	e.codeword(300)
	e.w.align()
	want = packBits(t, strings.Repeat("1"+lsb(ctlSTEPUP, 6)+" ", 1)+"1"+lsb(ctlSTEPUP, 7)+" 1"+lsb(ctlSTEPUP, 8)+" 1"+lsb(300, 9))
	if !bytes.Equal(e.w.out, want) || e.c2 != 9 {
		t.Errorf("codeword 300: %X C2 %d, want %X", e.w.out, e.c2, want)
	}
	if n := (Params{Codewords: 1525}).maxCodewordBits(); n != 11 {
		t.Errorf("N1 for 1525 codewords = %d", n)
	}
	if n := (Params{Codewords: 1024}).maxCodewordBits(); n != 10 {
		t.Errorf("N1 for 1024 codewords = %d", n)
	}
	// A packet big and varied enough to fill the node-tree reaches C2 = 11
	// and no further; the decoder follows every STEPUP.
	rng := rand.New(rand.NewSource(3))
	b := make([]byte, 30000)
	for i := range b {
		b[i] = byte('a' + rng.Intn(8))
	}
	e = newEncoder(DefaultParams(), b)
	e.run()
	if e.c2 != 11 || e.c1 != 1525 {
		t.Errorf("C2 %d C1 %d after a large packet, want 11 and 1525", e.c2, e.c1)
	}
	out, err := Decompress(DefaultParams(), e.w.out)
	if err != nil || !bytes.Equal(out, b) {
		t.Fatalf("large packet: %v", err)
	}
	// Ordinal STEPUP happens once, before the first ordinal above 127.
	e = newEncoder(DefaultParams(), nil)
	e.ordinal(0x80)
	e.ordinal(0x81)
	e.w.align()
	want = packBits(t, "1"+lsb(ctlSTEPUP, 6)+" 0"+lsb(0x80, 8)+" 0"+lsb(0x81, 8))
	if !bytes.Equal(e.w.out, want) {
		t.Errorf("ordinal STEPUP: %X, want %X", e.w.out, want)
	}
}

// B.1.1: once the last codeword is created the packet method creates no
// more, and matching and extension go on; with N2 = 256 the encoder stops
// at C1 = 256 and the decoder with the same N2 decodes it. A decoder with
// a smaller N2 than the encoder's refuses the packet (a codeword beyond
// its C1, 7.15), which is how mismatched settings show.
//
// Covers: SIG-IPE-663
func TestNodeTreeFull(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	b := make([]byte, 50000)
	for i := range b {
		b[i] = byte('0' + rng.Intn(10))
	}
	small := Params{Codewords: 256}
	e := newEncoder(small.withDefaults(), b)
	e.run()
	if e.c1 != 256 || e.c2 > 8 {
		t.Errorf("C1 %d C2 %d, want 256 and at most 8", e.c1, e.c2)
	}
	out, err := Decompress(small, e.w.out)
	if err != nil || !bytes.Equal(out, b) {
		t.Fatalf("N2 256: %v", err)
	}
	big, err := Compress(DefaultParams(), b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decompress(small, big); !errors.Is(err, ErrCorrupt) {
		t.Errorf("N2 1525 data decoded with N2 256: %v", err)
	}
}

// History full (7.11.4, 7.12, B.2.1): with N8 set, a longer packet is coded
// in runs of N8 characters separated by REINIT, and the decoder follows;
// a decoder with a smaller N8 than the encoder's refuses the packet.
//
// Covers: SIG-IPE-663
func TestHistoryFull(t *testing.T) {
	text := []byte(strings.Repeat("0123456789abcdef-meter-", 400)) // 9200 octets
	p := Params{History: 1000}
	c := roundTrip(t, p, text)
	reinits, base := 0, 0
	d := trace(t, p, c, func(d *decoder, _ int) {
		if d.base != base {
			reinits, base = reinits+1, d.base
		}
	})
	if reinits != len(text)/1000 {
		t.Errorf("%d REINITs, want %d", reinits, len(text)/1000)
	}
	if !bytes.Equal(d.out, text) {
		t.Error("decoded differently")
	}
	if _, err := Decompress(Params{History: 512}, c); !errors.Is(err, ErrCorrupt) {
		t.Errorf("N8 1000 data decoded with N8 512: %v", err)
	}
	// Without N8 the same packet has no REINIT and compresses better.
	if whole := roundTrip(t, DefaultParams(), text); len(whole) >= len(c) {
		t.Errorf("whole-packet history %d, N8 1000 %d", len(whole), len(c))
	}
}

// Malformed packets are refused with ErrCorrupt (7.15 and more), never
// with a panic; trailing octets after FLUSH are padding (RFC 3051 2.3).
//
// Covers: SIG-IPE-663
func TestDecoderErrors(t *testing.T) {
	p := DefaultParams()
	cases := map[string]string{
		"empty input":                     "",
		"no FLUSH":                        "0" + lsb('A', 7),
		"codeword beyond C1":              "1" + lsb(5, 6),
		"codeword C1 with nothing before": "1" + lsb(4, 6),
		"codeword C1 after an extension":  "0" + lsb('A', 7) + "0" + lsb('B', 7) + "1" + lsb(4, 6) + "01 1" + "1" + lsb(7, 6),
		"extension beyond N7":             "0" + lsb('A', 7) + "0" + lsb('A', 7) + "1" + lsb(4, 6) + "01 0 00 1 " + lsb(253, 8) + "1" + lsb(ctlFLUSH, 6),
		"ordinal STEPUP twice":            "1" + lsb(ctlSTEPUP, 6) + "0" + lsb(0x80, 8) + "1" + lsb(ctlSTEPUP, 6) + "0" + lsb(0x81, 8) + "1" + lsb(ctlFLUSH, 6),
		"codeword STEPUP beyond N1":       strings.Repeat("1"+lsb(ctlSTEPUP, 6), 1) + "1" + lsb(ctlSTEPUP, 7) + "1" + lsb(ctlSTEPUP, 8) + "1" + lsb(ctlSTEPUP, 9) + "1" + lsb(ctlSTEPUP, 10) + "1" + lsb(ctlSTEPUP, 11) + "1" + lsb(0, 12),
		"ETM inside a packet":             "0" + lsb('A', 7) + "1" + lsb(ctlETM, 6),
	}
	for name, bitsStr := range cases {
		in := packBits(t, bitsStr)
		if name == "no FLUSH" {
			// packBits pads with zeros, which read as more codes; cut the
			// input to whole codes instead.
			in = in[:len(bitsStr)/8]
		}
		if _, err := Decompress(p, in); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
	// Padding after FLUSH, including whole octets, is ignored.
	c := roundTrip(t, p, []byte("padding"))
	out, err := Decompress(p, append(c, 0xFF, 0x00, 0x12))
	if err != nil || string(out) != "padding" {
		t.Errorf("trailing octets: %q %v", out, err)
	}
	// Limit: a small packet that expands past the limit is refused.
	run, _ := Compress(p, bytes.Repeat([]byte{7}, 100000))
	if _, err := Decompress(Params{Limit: 1000}, run); !errors.Is(err, ErrLimit) {
		t.Errorf("limit: %v", err)
	}
	for _, bad := range []Params{{Codewords: 255}, {Codewords: 65536}, {MaxString: 31}, {MaxString: 256}, {History: 511}, {Limit: -1}} {
		if _, err := Compress(bad, nil); err == nil {
			t.Errorf("%+v accepted", bad)
		}
		if _, err := Decompress(bad, []byte{3}); err == nil {
			t.Errorf("%+v accepted by the decoder", bad)
		}
	}
}

// Annex B: a packet that does not compress goes as the ETM indicator in
// the first octet and the original octets; the decoder returns them.
//
// Covers: SIG-IPE-663
func TestUncompressedIndicator(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	b := make([]byte, 300)
	rng.Read(b)
	out, compressed, err := CompressOrRaw(DefaultParams(), b)
	if err != nil || compressed || out[0] != 0x01 || !bytes.Equal(out[1:], b) {
		t.Fatalf("random data: compressed %v, %X…, %v", compressed, out[:2], err)
	}
	if back, err := Decompress(DefaultParams(), out); err != nil || !bytes.Equal(back, b) {
		t.Errorf("raw packet: %v", err)
	}
	out, compressed, err = CompressOrRaw(DefaultParams(), bytes.Repeat([]byte("ab"), 100))
	if err != nil || !compressed || len(out) >= 50 {
		t.Errorf("repetitive data: compressed %v, %d octets, %v", compressed, len(out), err)
	}
}

// Size and time: 1 MiB of random data and 1 MiB of text each compress and
// decompress within a few seconds (race detector included), and random
// data grows by less than 15 %.
//
// Covers: SIG-IPE-663
func TestSizeAndTime(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	random := make([]byte, 1<<20)
	rng.Read(random)
	text := bytes.Repeat([]byte("IEC 62056-5-3 get-response with profile generic buffer, 0203 0900 1F29; "), (1<<20)/72)
	for name, b := range map[string][]byte{"random": random, "text": text} {
		start := time.Now()
		c := roundTrip(t, DefaultParams(), b)
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%s: %v for 1 MiB", name, d)
		}
		if name == "random" && len(c) > len(b)*115/100 {
			t.Errorf("random data grew to %d", len(c))
		}
		t.Logf("%s: %d → %d octets", name, len(b), len(c))
	}
}

// Informative: IEC 62056-5-3:2023 Table F.16 gives only the sizes of V.44
// compressed get-response APDUs, not their bytes or the V.44 parameters.
// The "compressed null-data and delta values (const)" APDU of Table F.14
// (24 hourly records, 167 octets) compresses with the B.1.2 defaults to 36
// octets, near the table's 34. The table's 33, 34 and 34 for 48, 96 and
// 168 records are not reachable by V.44 (a defect in that table; see
// PROVENANCE.md):
// each codeword or string extension covers at most N7 = 255 octets, so the
// 865 octets of repeats between 24 and 168 records need several more
// codes; ours grow by a few octets per 255.
//
// Covers: SIG-IPE-663
func TestTableF16Sizes(t *testing.T) {
	sizes := map[int]int{}
	for _, c := range []struct{ records, want int }{{24, 34}, {48, 33}, {96, 34}, {168, 34}} {
		apdu := []byte{0xC4, 0x01, 0x00, 0x00, 0x01}
		if c.records < 128 {
			apdu = append(apdu, byte(c.records))
		} else {
			apdu = append(apdu, 0x81, byte(c.records))
		}
		// First record: date-time 12-2-2018 00:00, 0, 100000.
		apdu = append(apdu, 0x02, 0x03, 0x09, 0x0C, 0x07, 0xE2, 0x02, 0x0C, 0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
			0x11, 0x00, 0x06, 0x00, 0x01, 0x86, 0xA0)
		for i := 1; i < c.records; i++ {
			apdu = append(apdu, 0x02, 0x03, 0x00, 0x00, 0x1F, 0x29)
		}
		if c.records == 24 && len(apdu) != 167 {
			t.Fatalf("Table F.14 APDU is %d octets, want 167", len(apdu))
		}
		comp := roundTrip(t, DefaultParams(), apdu)
		sizes[c.records] = len(comp)
		t.Logf("%d records: %d octets → %d (Table F.16: %d)", c.records, len(apdu), len(comp), c.want)
	}
	if d := sizes[24] - 34; d < -4 || d > 4 {
		t.Errorf("24 records: %d octets, Table F.16 says 34", sizes[24])
	}
	// Growth stays near the bound of a few octets per 255 repeated octets.
	if g := sizes[168] - sizes[24]; g < 4 || g > 16 {
		t.Errorf("168 records grew by %d octets over 24", g)
	}
}
