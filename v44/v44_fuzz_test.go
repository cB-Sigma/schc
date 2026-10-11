// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import (
	"bytes"
	"errors"
	"testing"
)

// The decoder refuses malformed input with an error, never panics, never
// loops, and never returns more than the limit.
//
// Covers: SIG-IPE-663
func FuzzDecompress(f *testing.F) {
	for _, s := range [][]byte{
		{}, {0x03}, {0x01, 'a'}, {0x82, 0x84, 0x86, 0x88, 0x8A, 0xB0, 0x09, 0x29, 0x5B, 0x29, 0xF8, 0x17, 0x64, 0x68, 0x00},
		{0xFF, 0xFF, 0xFF}, {0x05, 0x05}, {0x55, 0xAA, 0x55, 0xAA},
	} {
		f.Add(s, uint16(0), uint8(0))
	}
	if c, err := Compress(DefaultParams(), bytes.Repeat([]byte("abcab"), 200)); err == nil {
		f.Add(c, uint16(0), uint8(0))
	}
	f.Fuzz(func(t *testing.T, in []byte, n2 uint16, n7 uint8) {
		p := Params{Codewords: 256 + int(n2)%(65536-256), MaxString: 32 + int(n7)%224, Limit: 1 << 16}
		out, err := Decompress(p, in)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrLimit) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		if len(out) > p.Limit {
			t.Fatalf("%d octets over the limit", len(out))
		}
	})
}

// Whatever goes in comes back out, for any parameters.
//
// Covers: SIG-IPE-663
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("ABCDEXABCDEYABCDE\xffAC"), uint16(1525-256), uint8(255-32), uint16(0))
	f.Add([]byte("CCCCCCCCCCX"), uint16(0), uint8(0), uint16(1))
	f.Fuzz(func(t *testing.T, in []byte, n2 uint16, n7 uint8, n8 uint16) {
		p := Params{Codewords: 256 + int(n2)%(65536-256), MaxString: 32 + int(n7)%224}
		if n8 != 0 {
			p.History = 512 + int(n8)%4096
		}
		c, err := Compress(p, in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := Decompress(p, c)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("round trip failed: %v", err)
		}
	})
}
