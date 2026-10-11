// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/cB-Sigma/schc"
)

// TestSigfoxReferenceTwoByteParse records why TestSigfoxToReference runs
// the single-byte layout only: the reference's fragment parser
// (Messages/Fragment.py, Fragment.from_hex, at commit 1ec0b723) hands the
// fragment's bit string to Rule.from_hex, which expects hexadecimal, so a
// fragment of a 6- or 8-bit RuleID is read under a wrong rule. Its own
// fragments of those layouts reach our receiver fine
// (TestSigfoxFromReference). The test fails once the reference reads the
// RuleID right, to say the two-byte layouts can join the test.
func TestSigfoxReferenceTwoByteParse(t *testing.T) {
	p := startImage(t, sigfoxRI)
	for _, l := range sigfoxLayouts[1:] {
		r := sigfoxRule(t, l.id, l.layout)
		s, err := schc.NewSender(r, 8, 0, schc.BytesOf(make([]byte, 40)))
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Start(time.Now(), schc.SigfoxUplinkMTU)
		if err != nil {
			t.Fatal(err)
		}
		got := lineArg(t, p.do(map[string]any{"cmd": "parse-fragment", "hex": hex.EncodeToString(out[0].Bytes())}), "fragment-rule")
		if len(got) != 1 {
			t.Fatalf("%s: %q", l.name, got)
		}
		if got[0] == l.bits {
			t.Fatalf("%s: the reference now reads RuleID %s right: add the layout to TestSigfoxToReference", l.name, l.bits)
		}
		t.Logf("%s: the reference reads RuleID %s as %s", l.name, l.bits, got[0])
	}
}
