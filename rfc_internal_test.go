// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustBits(t *testing.T, s string) Bits {
	t.Helper()
	b, err := ParseBits(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-3796
func TestCMACRFC4493Vectors(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	for _, c := range []struct{ msg, mac string }{
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
	} {
		got, err := cmacAES128(key, mustHex(t, c.msg))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.mac {
			t.Errorf("CMAC(%s) = %x, want %s", c.msg, got, c.mac)
		}
	}
}

// RFC 9011 figure 6: the Dev IID from AppSKey and DevEUI.
// Covers: SIG-IPE-3795
func TestLoRaWANIIDFigure6(t *testing.T) {
	iid, err := LoRaWANIID(mustHex(t, "00AABBCCDDEEFF00AABBCCDDEEFFAABB"), mustHex(t, "1122334455667788"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ToUpper(hex.EncodeToString(iid)); got != "4E822D9775B26499" {
		t.Fatalf("IID %s, want 4E822D9775B26499", got)
	}
}

// RFC 8724 8.3.2.1 figures 16 to 19: bitmap compression cuts trailing ones
// up to an L2 Word boundary of the whole message.
// Covers: SIG-IPE-3787
func TestBitmapCompressionFigures(t *testing.T) {
	bm := func(s string) []bool {
		var out []bool
		for _, c := range s {
			out = append(out, c == '1')
		}
		return out
	}
	// Figure 16/17: header ending 3 bits before a word boundary, 17-bit
	// bitmap 1 0 then fifteen ones: only 101 is sent, nothing padded.
	h := mustBits(t, "10110")
	compressBitmap(&h, bm("10111111111111111"), 8)
	if h.String() != "10110"+"101" {
		t.Fatalf("figure 17: %s", h)
	}
	// Figure 18: 1010111 with the header one bit before a boundary; the
	// bitmap cannot be cut and is padded.
	h = mustBits(t, "1011011")
	compressBitmap(&h, bm("1010111"), 8)
	if h.String() != "1011011"+"1010111"+"00" {
		t.Fatalf("figure 18: %s", h)
	}
	// Figure 19: 1111111 after the same header: one bit sent.
	h = mustBits(t, "1011011")
	compressBitmap(&h, bm("1111111"), 8)
	if h.String() != "1011011"+"1" {
		t.Fatalf("figure 19: %s", h)
	}
}

// RFC 9011 5.6.2.3 note: with the uplink rule (header 11 bits, WINDOW_SIZE
// 63) the compressed bitmap is 5, 13, …, 61, 62 or 63 bits, and a 63-bit one
// takes 6 bits of padding.
// Covers: SIG-IPE-3794
func TestLoRaWANCompressedBitmapSizes(t *testing.T) {
	r := LoRaWANUplinkRule(FPortUp, 10, false)
	rs := RuleSet{Rules: []Rule{r}}
	if err := rs.Compile(); err != nil {
		t.Fatal(err)
	}
	sizes := map[int]bool{}
	for zero := 0; zero < 63; zero++ {
		b := make([]bool, 63)
		for i := range b {
			b[i] = i != zero
		}
		msg := (&FragMsg{Kind: MsgAck, Rule: &rs.Rules[0], Bitmap: b}).Encode(8)
		sizes[msg.Len()-11] = true
		back, err := DecodeAtSender(&rs.Rules[0], msg, 8)
		if err != nil || back.C {
			t.Fatal(err)
		}
		for i := range b {
			if back.Bitmap[i] != b[i] {
				t.Fatalf("bitmap with tile %d missing did not survive: %v", zero, back.Bitmap)
			}
		}
	}
	for s := range sizes {
		ok := map[int]bool{5: true, 13: true, 21: true, 29: true, 37: true, 45: true, 53: true, 61: true, 69: true}
		if !ok[s] {
			t.Errorf("compressed bitmap plus padding of %d bits", s)
		}
	}
	// Figure 10: C=1 ACK is RuleID, W=00, C=1, five zero bits.
	ack := (&FragMsg{Kind: MsgAck, Rule: &rs.Rules[0], C: true}).Encode(8)
	if !bytes.Equal(ack.Bytes(), []byte{20, 0x20}) {
		t.Fatalf("ACK C=1 is % x", ack.Bytes())
	}
	// Figure 12: Receiver-Abort is W=11, C=1, 11111, then FFh.
	ra := (&FragMsg{Kind: MsgReceiverAbort, Rule: &rs.Rules[0]}).Encode(8)
	if !bytes.Equal(ra.Bytes(), []byte{20, 0xFF, 0xFF}) {
		t.Fatalf("Receiver-Abort is % x", ra.Bytes())
	}
	if m, err := DecodeAtSender(&rs.Rules[0], ra, 8); err != nil || m.Kind != MsgReceiverAbort {
		t.Fatalf("Receiver-Abort decoded as %v, %v", m, err)
	}
	// Figure 13: ACK REQ is W then six zero bits.
	req := (&FragMsg{Kind: MsgAckReq, Rule: &rs.Rules[0], W: 2}).Encode(8)
	if !bytes.Equal(req.Bytes(), []byte{20, 0x80}) {
		t.Fatalf("ACK REQ is % x", req.Bytes())
	}
	if m, err := DecodeAtReceiver(&rs.Rules[0], req, 8); err != nil || m.Kind != MsgAckReq || m.W != 2 {
		t.Fatalf("ACK REQ decoded as %+v, %v", m, err)
	}
}

// RFC 8724 7.4.2: variable-length residue sizes on 4, 12 or 28 bits.
// Covers: SIG-IPE-3785
func TestVariableLengthSize(t *testing.T) {
	for _, c := range []struct{ n, bits int }{{0, 4}, {14, 4}, {15, 12}, {254, 12}, {255, 28}, {4000, 28}} {
		var b Bits
		if !appendSize(&b, c.n, "bits") || b.Len() != c.bits {
			t.Fatalf("size %d took %d bits", c.n, b.Len())
		}
		got, err := readSize(&reader{x: b}, "bits")
		if err != nil || got != c.n {
			t.Fatalf("size %d read back as %d (%v)", c.n, got, err)
		}
	}
}

// appendixARules are RFC 8724 figures 26 to 28 in our JSON (alpha, beta,
// gamma chosen as 2001:db8:a::/64, …:b::, …:c::).
const appendixARules = `{"rules":[
 {"ruleId":0,"kind":"no-compression"},
 {"ruleId":1,"fields":[
  {"fid":"ipv6.version","fl":4,"tv":6,"mo":"ignore","cda":"not-sent"},
  {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute-*"},
  {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.hopLimit","fl":8,"tv":255,"mo":"ignore","cda":"not-sent"},
  {"fid":"ipv6.devPrefix","fl":64,"tv":"fe80::/64","mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.devIID","fl":64,"mo":"ignore","cda":"DevIID"},
  {"fid":"ipv6.appPrefix","fl":64,"tv":"fe80::/64","mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.appIID","fl":64,"tv":"::1","mo":"equal","cda":"not-sent"},
  {"fid":"udp.devPort","fl":16,"tv":123,"mo":"equal","cda":"not-sent"},
  {"fid":"udp.appPort","fl":16,"tv":124,"mo":"equal","cda":"not-sent"},
  {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute-*"},
  {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute-*"}]},
 {"ruleId":2,"fields":[
  {"fid":"ipv6.version","fl":4,"tv":6,"mo":"ignore","cda":"not-sent"},
  {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute-*"},
  {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.hopLimit","fl":8,"tv":255,"mo":"ignore","cda":"not-sent"},
  {"fid":"ipv6.devPrefix","fl":64,"tv":["2001:db8:a::/64","fe80::/64"],"mo":"match-mapping","cda":"mapping-sent"},
  {"fid":"ipv6.devIID","fl":64,"mo":"ignore","cda":"DevIID"},
  {"fid":"ipv6.appPrefix","fl":64,"tv":["2001:db8:b::/64","2001:db8:a::/64","fe80::/64"],"mo":"match-mapping","cda":"mapping-sent"},
  {"fid":"ipv6.appIID","fl":64,"tv":"::1000","mo":"equal","cda":"not-sent"},
  {"fid":"udp.devPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
  {"fid":"udp.appPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
  {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute-*"},
  {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute-*"}]},
 {"ruleId":3,"fields":[
  {"fid":"ipv6.version","fl":4,"tv":6,"mo":"ignore","cda":"not-sent"},
  {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute-*"},
  {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.hopLimit","fl":8,"di":"up","tv":255,"mo":"ignore","cda":"not-sent"},
  {"fid":"ipv6.hopLimit","fl":8,"di":"dw","mo":"ignore","cda":"value-sent"},
  {"fid":"ipv6.devPrefix","fl":64,"tv":"2001:db8:a::/64","mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.devIID","fl":64,"mo":"ignore","cda":"DevIID"},
  {"fid":"ipv6.appPrefix","fl":64,"tv":"2001:db8:c::/64","mo":"equal","cda":"not-sent"},
  {"fid":"ipv6.appIID","fl":64,"tv":"::1000","mo":"equal","cda":"not-sent"},
  {"fid":"udp.devPort","fl":16,"tv":8720,"mo":"msb(12)","cda":"lsb"},
  {"fid":"udp.appPort","fl":16,"tv":8720,"mo":"msb(12)","cda":"lsb"},
  {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute-*"},
  {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute-*"}]}]}`

// ipv6UDP builds an IPv6/UDP packet from dev to app (up) or app to dev.
func ipv6UDP(t *testing.T, dir Direction, devPrefix, devIID, appPrefix, appIID string, devPort, appPort uint16, hop byte, payload []byte) []byte {
	t.Helper()
	vals := map[string]Bits{
		FIPv6Version: Uint(6, 4), FIPv6TrafficClass: Uint(0, 8), FIPv6FlowLabel: Uint(0, 20),
		FIPv6NextHeader: Uint(17, 8), FIPv6HopLimit: Uint(uint64(hop), 8),
		FUDPDevPort: Uint(uint64(devPort), 16), FUDPAppPort: Uint(uint64(appPort), 16),
	}
	for fid, s := range map[string]string{FIPv6DevPrefix: devPrefix, FIPv6DevIID: devIID, FIPv6AppPrefix: appPrefix, FIPv6AppIID: appIID} {
		v, err := ipv6Value(s, 64)
		if err != nil {
			t.Fatal(err)
		}
		vals[fid] = v
	}
	raw, err := Stack{"ipv6", "udp"}.Build(vals, payload, dir)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// RFC 8724 appendix A: the three flows compress under rules 1, 2 and 3 to
// the residues of the figures' Sent column, and decompress back.
// Covers: SIG-IPE-3783
func TestAppendixACompression(t *testing.T) {
	rs, err := ParseRuleSet([]byte(appendixARules))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := ParseStack("ipv6/udp")
	devIID := mustHex(t, "0200000000000042")
	ctx := Context{DevIID: devIID}
	payload := []byte("coap-message")
	for _, c := range []struct {
		name    string
		dir     Direction
		raw     []byte
		rule    uint32
		residue int
	}{
		{"management", Up, ipv6UDP(t, Up, "fe80::/64", "::200:0:0:42", "fe80::/64", "::1", 123, 124, 255, payload), 1, 0},
		{"measurement", Up, ipv6UDP(t, Up, "2001:db8:a::/64", "::200:0:0:42", "2001:db8:b::/64", "::1000", 5683, 5683, 255, payload), 2, 3},
		{"legacy up", Up, ipv6UDP(t, Up, "2001:db8:a::/64", "::200:0:0:42", "2001:db8:c::/64", "::1000", 8725, 8721, 255, payload), 3, 8},
		{"legacy down", Down, ipv6UDP(t, Down, "2001:db8:a::/64", "::200:0:0:42", "2001:db8:c::/64", "::1000", 8725, 8721, 61, payload), 3, 16},
		{"no rule", Up, ipv6UDP(t, Up, "2001:db8:9::/64", "::200:0:0:42", "fe80::/64", "::1", 1, 2, 255, payload), 0, -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, r, err := rs.Compress(st, c.raw, c.dir, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if r.ID != c.rule {
				t.Fatalf("rule %d, want %d", r.ID, c.rule)
			}
			if c.residue >= 0 && out.Len() != 8+c.residue+8*len(payload) {
				t.Fatalf("SCHC packet of %d bits, want RuleID + %d residue bits + payload", out.Len(), c.residue)
			}
			padded := out.Clone()
			padded.Pad(8)
			back, _, err := rs.Decompress(st, padded, c.dir, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, c.raw) {
				t.Fatalf("decompressed\n% x\nwant\n% x", back, c.raw)
			}
		})
	}
	// A wrong checksum is not elided (it would come back different): the
	// packet goes uncompressed.
	bad := ipv6UDP(t, Up, "fe80::/64", "::200:0:0:42", "fe80::/64", "::1", 123, 124, 255, payload)
	bad[47] ^= 1
	if _, r, _ := rs.Compress(st, bad, Up, ctx); r.ID != 0 {
		t.Fatalf("a bad checksum was compressed by rule %d", r.ID)
	}
}

// Rule JSON is checked: bad operators, directions and lengths are refused.
// Covers: SIG-IPE-3786
func TestRuleSetRefusals(t *testing.T) {
	for _, bad := range []string{
		`{"rules":[{"ruleId":1,"fields":[{"fid":"x","fl":8,"mo":"equal","cda":"not-sent"}]}]}`,
		`{"rules":[{"ruleId":1,"fields":[{"fid":"x","fl":8,"tv":1,"mo":"nope","cda":"not-sent"}]}]}`,
		`{"rules":[{"ruleId":1,"fields":[{"fid":"x","fl":8,"tv":1,"mo":"equal","cda":"lsb"}]}]}`,
		`{"rules":[{"ruleId":1,"fields":[{"fid":"x","fl":4,"tv":300,"mo":"equal","cda":"not-sent"}]}]}`,
		`{"rules":[{"ruleId":1},{"ruleId":1,"ruleIdLength":8}]}`,
		`{"rules":[{"ruleId":2,"ruleIdLength":2},{"ruleId":8,"ruleIdLength":4}]}`,
		`{"rules":[{"ruleId":20,"fragmentation":{"mode":"ack-always","wSize":2,"fcnSize":1}}]}`,
		`{"rules":[{"ruleId":20,"fragmentation":{"mode":"ack-on-error","wSize":2,"fcnSize":6,"tileBits":4}}]}`,
		`{"rules":[{"ruleId":1,"kind":"no-compression"},{"ruleId":2,"kind":"no-compression"}]}`,
	} {
		if _, err := ParseRuleSet([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := ParseRuleSet([]byte(appendixARules)); err != nil {
		t.Fatal(err)
	}
	var d Duration
	if json.Unmarshal([]byte(`"36h"`), &d) != nil || d.D() != 36*time.Hour {
		t.Fatal("duration")
	}
}
