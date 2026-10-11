// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// coapWithToken is a CON GET with Message ID 0x1234, the token tok (TKL and
// its extension as RFC 8974 2.1 writes them), Uri-Path "t" and payload "x".
func coapWithToken(tok []byte) []byte {
	n := len(tok)
	var nib byte
	var ext []byte
	switch {
	case n < 13:
		nib = byte(n)
	case n < 269:
		nib, ext = 13, []byte{byte(n - 13)}
	default:
		nib, ext = 14, []byte{byte((n - 269) >> 8), byte(n - 269)}
	}
	out := []byte{0x40 | nib, 0x01, 0x12, 0x34}
	out = append(out, ext...)
	out = append(out, tok...)
	return append(out, 0xB1, 't', 0xFF, 'x')
}

// Covers: SIG-IPE-7310
//
// RFC 8974 extended token lengths: the TKL nibble and its extension are
// one field of 4, 12 or 20 bits (draft-ietf-schc-8824-update 4.3), the
// token's length function "tkl" reads all of it, and messages with tokens
// of 9 to 12, 13 to 268 and 269 bytes and more compress and come back.
func TestCoAPExtendedTokenLength(t *testing.T) {
	rs, err := ParseRuleSet([]byte(`{"rules":[
	 {"ruleId":1,"fields":[
	  {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	  {"fid":"coap.type","fl":2,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"coap.tkl","fl":12,"tv":"d07","mo":"equal","cda":"not-sent"},
	  {"fid":"coap.code","fl":8,"tv":1,"mo":"equal","cda":"not-sent"},
	  {"fid":"coap.mid","fl":16,"mo":"ignore","cda":"value-sent"},
	  {"fid":"coap.token","var":"tkl","mo":"ignore","cda":"value-sent"},
	  {"fid":"coap.uriPath","var":"bytes","tv":"t","mo":"equal","cda":"not-sent"}]},
	 {"ruleId":2,"fields":[
	  {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	  {"fid":"coap.type","fl":2,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"coap.tkl","var":"bits","mo":"ignore","cda":"value-sent"},
	  {"fid":"coap.code","fl":8,"tv":1,"mo":"equal","cda":"not-sent"},
	  {"fid":"coap.mid","fl":16,"mo":"ignore","cda":"value-sent"},
	  {"fid":"coap.token","var":"tkl","mo":"ignore","cda":"value-sent"},
	  {"fid":"coap.uriPath","var":"bytes","tv":"t","mo":"equal","cda":"not-sent"}]},
	 {"ruleId":3,"kind":"no-compression"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := ParseStack("coap")
	for _, tc := range []struct {
		n    int
		rule uint32
		bits int // residue after the RuleID, before the payload
	}{
		{1, 2, 4 + 4 + 16 + 8}, {8, 2, 4 + 4 + 16 + 64}, {12, 2, 4 + 4 + 16 + 96},
		{20, 1, 16 + 160}, {13, 2, 4 + 12 + 16 + 104}, {268, 2, 4 + 12 + 16 + 268*8},
		{269, 2, 12 + 20 + 16 + 269*8}, {1000, 2, 12 + 20 + 16 + 8000},
	} {
		tok := bytes.Repeat([]byte{0xA5}, tc.n)
		for i := range tok {
			tok[i] ^= byte(i)
		}
		msg := coapWithToken(tok)
		p, err := st.Parse(msg, Up)
		if err != nil {
			t.Fatalf("%d-byte token: %v", tc.n, err)
		}
		if v, _ := fieldValue(p, FCoAPTKL); v.Len() != map[bool]int{true: 4, false: map[bool]int{true: 12, false: 20}[tc.n < 269]}[tc.n < 13] {
			t.Fatalf("%d-byte token: TKL field of %d bits", tc.n, v.Len())
		}
		c, r, err := rs.Compress(st, msg, Up, Context{})
		if err != nil {
			t.Fatal(err)
		}
		if r.ID != tc.rule || c.Len() != 8+tc.bits+8 {
			t.Fatalf("%d-byte token: rule %d, %d bits, want rule %d and %d", tc.n, r.ID, c.Len(), tc.rule, 8+tc.bits+8)
		}
		back, _, err := rs.Decompress(st, c, Up, Context{})
		if err != nil || !bytes.Equal(back, msg) {
			t.Fatalf("%d-byte token: %x %v\nwant %x", tc.n, back, err, msg)
		}
	}
	// TKL 15 is a message format error: the packet goes uncompressed.
	bad, _ := hex.DecodeString("4f011234")
	if _, r, _ := rs.Compress(st, bad, Up, Context{}); r.ID != 3 {
		t.Fatalf("TKL 15 compressed by rule %d", r.ID)
	}
	// A TKL of 13 that the message is too short for.
	short, _ := hex.DecodeString("4d01123405aabb")
	if _, err := st.Parse(short, Up); err == nil {
		t.Fatal("a truncated extended token parsed")
	}
}
