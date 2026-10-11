// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Covers: SIG-IPE-7307
//
// A Compound ACK as the RFC 9442 authors' receiver sends it (captured from
// schc-over-sigfox at commit 1ec0b723): RuleID 010, windows 0, 1 and 2
// with tiles missing, the 00 that ends the list, zeros to 64 bits.
func TestSigfoxCompoundAckFromReference(t *testing.T) {
	r := compiled(t, mustRule(SigfoxUplinkRule(2, SigfoxSingleByte)))
	b, _ := hex.DecodeString("43badede00000000")
	m, err := DecodeAtSender(r, BytesOf(b), 8)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%d %s", m.W, bitString(m.Bitmap))
	for _, w := range m.More {
		got += fmt.Sprintf(", %d %s", w.W, bitString(w.Bitmap))
	}
	if want := "0 1110111, 1 0110111, 2 1101111"; m.C || got != want {
		t.Fatalf("read %q, want %q", got, want)
	}
}

func bitString(bm []bool) string {
	s := make([]byte, len(bm))
	for i, b := range bm {
		s[i] = '0'
		if b {
			s[i] = '1'
		}
	}
	return string(s)
}
