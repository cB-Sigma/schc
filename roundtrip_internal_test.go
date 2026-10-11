// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

const wrapperRules = `{"rules":[
 {"ruleId":1,"fields":[
  {"fid":"wrapper.version","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
  {"fid":"wrapper.devWPort","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
  {"fid":"wrapper.appWPort","fl":16,"tv":[16,32,48,64,80,96,102,1],"mo":"match-mapping","cda":"mapping-sent"},
  {"fid":"wrapper.length","fl":16,"mo":"ignore","cda":"compute"}]},
 {"ruleId":2,"fields":[
  {"fid":"wrapper.version","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
  {"fid":"wrapper.devWPort","fl":16,"tv":0,"mo":"msb(8)","cda":"lsb"},
  {"fid":"wrapper.appWPort","fl":16,"mo":"ignore","cda":"value-sent"},
  {"fid":"wrapper.length","fl":16,"mo":"ignore","cda":"compute"}]},
 {"ruleId":22,"kind":"no-compression"}]}`

func wpdu(src, dst uint16, apdu []byte) []byte {
	b := make([]byte, 8, 8+len(apdu))
	binary.BigEndian.PutUint16(b[0:], 1)
	binary.BigEndian.PutUint16(b[2:], src)
	binary.BigEndian.PutUint16(b[4:], dst)
	binary.BigEndian.PutUint16(b[6:], uint16(len(apdu)))
	return append(b, apdu...)
}

// Property: any wrapper frame (or any bytes at all) comes back unchanged
// through compression, zero padding and decompression, both ways.
// Covers: SIG-IPE-3784
func TestWrapperRoundTrip(t *testing.T) {
	rs, err := ParseRuleSet([]byte(wrapperRules))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := ParseStack("wrapper")
	rnd := rand.New(rand.NewSource(1))
	used := map[uint32]int{}
	for i := 0; i < 3000; i++ {
		apdu := make([]byte, rnd.Intn(300))
		rnd.Read(apdu)
		dir := Up
		if i%2 == 1 {
			dir = Down
		}
		dev := uint16(1)
		if rnd.Intn(4) == 0 {
			dev = uint16(rnd.Intn(300))
		}
		app := []uint16{16, 32, 48, 64, 80, 96, 102, 1, 4242}[rnd.Intn(9)]
		src, dst := dev, app
		if dir == Down {
			src, dst = app, dev
		}
		raw := wpdu(src, dst, apdu)
		switch rnd.Intn(10) {
		case 0:
			raw[7] ^= 1 // a length that disagrees
		case 1:
			raw = raw[:rnd.Intn(len(raw)+1)] // not a whole frame
		}
		msg, r, err := rs.Compress(st, raw, dir, Context{})
		if err != nil {
			t.Fatal(err)
		}
		used[r.ID]++
		msg.Pad(8)
		back, _, err := rs.Decompress(st, msg, dir, Context{})
		if err != nil {
			t.Fatalf("rule %d: %v", r.ID, err)
		}
		if !bytes.Equal(back, raw) {
			t.Fatalf("rule %d changed % x into % x", r.ID, raw, back)
		}
	}
	if used[1] == 0 || used[2] == 0 || used[22] == 0 {
		t.Fatalf("rules used %v", used)
	}
}

// Fuzz: decompression of arbitrary messages never panics, and whatever it
// accepts recompresses to a message that decompresses the same.
func FuzzDecompress(f *testing.F) {
	rs, err := ParseRuleSet([]byte(wrapperRules))
	if err != nil {
		f.Fatal(err)
	}
	st, _ := ParseStack("wrapper")
	f.Add([]byte{1 << 5, 0xC0, 0x01})
	f.Add([]byte{22, 1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		raw, _, err := rs.Decompress(st, BytesOf(b), Up, Context{})
		if err != nil {
			return
		}
		msg, _, err := rs.Compress(st, raw, Up, Context{})
		if err != nil {
			t.Fatal(err)
		}
		msg.Pad(8)
		again, _, err := rs.Decompress(st, msg, Up, Context{})
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("% x → % x → % x (%v)", b, raw, again, err)
		}
	})
}
