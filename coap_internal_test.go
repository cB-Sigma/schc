// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// coapCase is one message through one rule set: the compressed message
// padded to bytes, and back.
type coapCase struct {
	name  string
	stack string
	dir   Direction
	in    string // hex
	rule  uint32
	want  string // hex of the SCHC packet padded to 8 bits; "" to check the round trip only
	ctx   Context
}

func runCoAPCases(t *testing.T, rules string, cases []coapCase) {
	t.Helper()
	rs, err := ParseRuleSet([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		st, err := ParseStack(c.stack)
		if err != nil {
			t.Fatal(err)
		}
		in := mustHex(t, c.in)
		msg, r, err := rs.Compress(st, in, c.dir, c.ctx)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if r.ID != c.rule {
			t.Fatalf("%s: rule %d, want %d", c.name, r.ID, c.rule)
		}
		msg.Pad(8)
		if c.want != "" {
			if got := hex.EncodeToString(msg.Bytes()); got != strings.ReplaceAll(c.want, " ", "") {
				t.Fatalf("%s: compressed %s\nwant          %s", c.name, got, strings.ReplaceAll(c.want, " ", ""))
			}
		}
		back, _, err := rs.Decompress(st, msg, c.dir, c.ctx)
		if err != nil {
			t.Fatalf("%s: decompress: %v", c.name, err)
		}
		if !bytes.Equal(back, in) {
			t.Fatalf("%s: decompressed %x\nwant         %x", c.name, back, in)
		}
	}
}

// RFC 8824 7.3, table 6 and figures 8, 9, 16 and 17: the GET request and
// its Content response compressed by a CoAP-only rule, without OSCORE.
// Table 6 gives the uplink code as 2 (POST) while the request of figure 8
// is a GET (code 1) and figure 16 elides it; the rule here says 1.
func TestRFC8824Table6NoOSCORE(t *testing.T) {
	rules := `{"rules":[{"ruleId":1,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"up","tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"dw","tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"up","tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"dw","tv":[69,132],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(12)","cda":"lsb"},
	 {"fid":"coap.token","var":"tkl","tv":"80","mo":"msb(5)","cda":"lsb"},
	 {"fid":"coap.uriPath","var":"bytes","di":"up","tv":"temperature","mo":"equal","cda":"not-sent"}]},
	 {"ruleId":255,"kind":"no-compression"}]}`
	runCoAPCases(t, rules, []coapCase{
		// Figure 8 compressed to figure 16: RuleID 01, MID 0001, token 010, one bit of padding.
		{name: "GET", stack: "coap", dir: Up, in: "4101000182bb74656d7065726174757265", rule: 1, want: "0114"},
		// Figure 9 compressed to figure 17: code index 0, MID 0001, token 010, payload.
		{name: "Content", stack: "coap", dir: Down, in: "6145000182ff32332043", rule: 1, want: "010a32332043"},
		// A 4.04 response (index 1) and a request the rule does not fit.
		// A 4.04 response: code index 1, MID 0111, token 010.
		{name: "4.04", stack: "coap", dir: Down, in: "6184000782", rule: 1, want: "01ba"},
		{name: "GET other path", stack: "coap", dir: Up, in: "4101000182b3666f6f", rule: 255, want: "ff4101000182b3666f6f"},
	})
}

// RFC 8824 7.3, table 4 and figures 10 and 11: the inner rule compresses
// the OSCORE plaintexts (code, Class E options, payload).
func TestRFC8824Table4InnerRule(t *testing.T) {
	rules := `{"rules":[{"ruleId":0,"fields":[
	 {"fid":"coap.code","fl":8,"di":"up","tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"dw","tv":[69,132],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.uriPath","var":"bytes","di":"up","tv":"temperature","mo":"equal","cda":"not-sent"}]}]}`
	runCoAPCases(t, rules, []coapCase{
		// Figure 10: 13 bytes of plaintext to the RuleID alone.
		{name: "GET plaintext", stack: "coap-inner", dir: Up, in: "01bb74656d7065726174757265", rule: 0, want: "00"},
		// Figure 11: one bit of residue shifts the payload.
		{name: "Content plaintext", stack: "coap-inner", dir: Down, in: "45ff32332043", rule: 0, want: "001919902180"},
	})
}

// RFC 8824 7.3, table 5 and figures 12 to 15: the outer rule compresses the
// OSCORE-protected messages, whose payload is the ciphertext of the inner
// compressed plaintext. Three things differ from the RFC, which our
// vectors correct: the figures carry OSCORE as option 21 (a draft number;
// RFC 8613 assigned 9), table 5 gives the kid MSB(52) where a 48-bit kid
// with a 4-bit residue needs MSB(44), and its variable-length piv and kid
// residues are drawn without the size that RFC 8724 7.4.2 puts before a
// variable-length residue (4 bits each here). The response, whose OSCORE
// option is empty, compresses exactly to figure 15.
func TestRFC8824Table5OuterRule(t *testing.T) {
	rules := `{"rules":[{"ruleId":0,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"up","tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"dw","tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"up","tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"dw","tv":68,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(12)","cda":"lsb"},
	 {"fid":"coap.token","var":"tkl","tv":"80","mo":"msb(5)","cda":"lsb"},
	 {"fid":"coap.oscore.flags","fl":8,"di":"up","tv":"09","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.piv","var":"bits","di":"up","tv":"00","mo":"msb(4)","cda":"lsb"},
	 {"fid":"coap.oscore.kid","var":"bits","di":"up","tv":"636c69656e70","mo":"msb(44)","cda":"lsb"},
	 {"fid":"coap.oscore.kidctx","var":"bytes","tv":"","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.flags","var":"bytes","di":"dw","tv":"","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.piv","var":"bytes","di":"dw","tv":"","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.kid","var":"bytes","di":"dw","tv":"","mo":"equal","cda":"not-sent"}]}]}`
	runCoAPCases(t, rules, []coapCase{
		// Figure 12 with option 9: flags 09, piv 04, kid "client".
		// Residue 0001 (MID) 010 (token) 0100 0100 (piv: size 4, bits)
		// 0100 0100 (kid: size 4, bits), then the 9-byte ciphertext.
		{name: "protected GET", stack: "coap", dir: Up,
			in:   "4102000182" + "98" + "0904636c69656e74" + "ff" + "a2c54fe1b434297b62",
			rule: 0, want: "00148889458a9fc3686852f6c4"},
		// Figure 13 with option 9 (empty) to figure 15.
		{name: "protected Changed", stack: "coap", dir: Down,
			in:   "6144000182" + "90" + "ff" + "10c6d7c26cc1e9aef3f2461e0c29",
			rule: 0, want: "0014218daf84d983d35de7e48c3c1852"},
	})
}

// RFC 8824 7.1, table 3: the gateway sends a CON POST to the device, which
// acknowledges it. The 26 codes of RFC 7252 12.1 (0.00 included) map to 5
// bits, the type of the device's answer to 1 bit (ACK or RST), the MID to
// its 9 low bits.
func TestRFC8824Table3MandatoryHeader(t *testing.T) {
	codes := []int{0, 1, 2, 3, 4, 65, 66, 67, 68, 69, 128, 129, 130, 131, 132, 133, 134, 140, 141, 143, 160, 161, 162, 163, 164, 165}
	var cl []string
	for _, c := range codes {
		cl = append(cl, fmt.Sprint(c))
	}
	rules := `{"rules":[{"ruleId":1,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"dw","tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"up","tv":[2,3],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"tv":[` + strings.Join(cl, ",") + `],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(7)","cda":"lsb"},
	 {"fid":"coap.uriPath","var":"bytes","di":"dw","tv":"path","mo":"equal","cda":"not-sent"}]}]}`
	// POST (index 2 = 00010), MID 5 (000000101), payload "hi".
	post := mustBits(t, "00000001 00010 000000101")
	post.AppendBytes([]byte("hi"))
	post.Pad(8)
	// ACK (index 0), 2.04 Changed (index 8 = 01000), MID 5.
	ack := mustBits(t, "00000001 0 01000 000000101")
	ack.Pad(8)
	runCoAPCases(t, rules, []coapCase{
		{name: "CON POST /path", stack: "coap", dir: Down, in: "40020005" + "b470617468" + "ff6869", rule: 1, want: hex.EncodeToString(post.Bytes())},
		{name: "ACK 2.04", stack: "coap", dir: Up, in: "60440005", rule: 1, want: hex.EncodeToString(ack.Bytes())},
	})
}

// RFC 8824 5.3, table 2: the CORECONF path /c/X6?k=eth0. The residue is the
// second path element with its size (0x2, "X6") and the query's LSBs with
// theirs (0x4, "eth0").
func TestRFC8824Table2CORECONFURI(t *testing.T) {
	rules := `{"rules":[{"ruleId":3,"ruleIdLength":4,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"tv":5,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.mid","fl":16,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.uriPath","var":"bytes","fp":1,"di":"up","tv":"c","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.uriPath","var":"bytes","fp":2,"di":"up","mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.uriQuery","var":"bytes","fp":1,"di":"up","tv":"k=","mo":"msb(16)","cda":"lsb"}]}]}`
	// NON FETCH, MID 0x1234, Uri-Path "c", Uri-Path "X6", Uri-Query "k=eth0".
	in := "5005" + "1234" + "b163" + "025836" + "46" + hex.EncodeToString([]byte("k=eth0"))
	want := mustBits(t, "0011")
	want.AppendUint(0x1234, 16)
	want.AppendUint(2, 4)
	want.AppendBytes([]byte("X6"))
	want.AppendUint(4, 4)
	want.AppendBytes([]byte("eth0"))
	want.Pad(8)
	runCoAPCases(t, rules, []coapCase{{name: "/c/X6?k=eth0", stack: "coap", dir: Up, in: in, rule: 3, want: hex.EncodeToString(want.Bytes())}})
}

// RFC 8824 5.3, table 1: the paths /a/b and /c/d share one entry, one bit
// of residue, and the third element is sent with its size.
func TestRFC8824Table1GroupedPath(t *testing.T) {
	rules := `{"rules":[{"ruleId":1,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(8)","cda":"lsb"},
	 {"fid":"coap.uriPath","var":"bytes","fp":1,"di":"up","tv":[["a","b"],["c","d"]],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.uriPath","var":"bytes","fp":3,"di":"up","mo":"ignore","cda":"value-sent"}]},
	 {"ruleId":0,"kind":"no-compression"}]}`
	// GET /c/d/xyz, MID 0x0009: MID 00001001, path index 1, size 3, "xyz".
	want := mustBits(t, "00000001 00001001 1 0011")
	want.AppendBytes([]byte("xyz"))
	want.Pad(8)
	runCoAPCases(t, rules, []coapCase{
		{name: "/c/d/xyz", stack: "coap", dir: Up, in: "40010009" + "b163" + "0164" + "0378797a", rule: 1, want: hex.EncodeToString(want.Bytes())},
		{name: "/a/b/q", stack: "coap", dir: Up, in: "40010009" + "b161" + "0162" + "0171", rule: 1},
		{name: "/a/d/q", stack: "coap", dir: Up, in: "40010009" + "b161" + "0164" + "0171", rule: 0},
	})
	if _, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[{"fid":"coap.uriPath","var":"bytes","tv":[["a","b"],"c"],"mo":"match-mapping","cda":"mapping-sent"}]}]}`)); err == nil {
		t.Fatal("a target value mixing groups and values was accepted")
	}
	rs, _ := ParseRuleSet([]byte(rules))
	if _, err := rs.MarshalYANG(); err == nil {
		t.Fatal("a grouped entry was written as RFC 9363")
	}
}

// ipv6UDPCoAP is a CoAP message in UDP in IPv6 with a correct checksum.
func ipv6UDPCoAP(t *testing.T, dir Direction, coap []byte) []byte {
	t.Helper()
	return ipv6UDP(t, dir, "2001:db8::/64", "::1", "2001:db8:1::/64", "::2", 5683, 5683, 64, coap)
}

// RFC 8824 figure 1: one rule from IPv6 to CoAP. Lengths and checksum are
// computed, the addresses elided; the CoAP header as in table 6.
func TestCoAPOverIPv6UDPOneRule(t *testing.T) {
	rules := `{"rules":[{"ruleId":2,"ruleIdLength":3,"fields":[
	 {"fid":"ipv6.version","fl":4,"tv":6,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.hopLimit","fl":8,"tv":64,"mo":"ignore","cda":"not-sent"},
	 {"fid":"ipv6.devPrefix","fl":64,"tv":"2001:db8::/64","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.devIID","fl":64,"tv":"::1","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.appPrefix","fl":64,"tv":"2001:db8:1::/64","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.appIID","fl":64,"tv":"::2","mo":"equal","cda":"not-sent"},
	 {"fid":"udp.devPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
	 {"fid":"udp.appPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
	 {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"up","tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"dw","tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"up","tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.code","fl":8,"di":"dw","tv":[69,132],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(12)","cda":"lsb"},
	 {"fid":"coap.token","var":"tkl","tv":"80","mo":"msb(5)","cda":"lsb"},
	 {"fid":"coap.uriPath","var":"bytes","di":"up","tv":"temperature","mo":"equal","cda":"not-sent"}]},
	 {"ruleId":0,"ruleIdLength":3,"kind":"no-compression"}]}`
	get := ipv6UDPCoAP(t, Up, mustHex(t, "4101000182bb74656d7065726174757265"))
	content := ipv6UDPCoAP(t, Down, mustHex(t, "6145000182ff32332043"))
	// 3-bit RuleID 010, MID 0001, token 010: 10 bits, two bytes.
	runCoAPCases(t, rules, []coapCase{
		{name: "GET in IPv6/UDP", stack: "ipv6/udp/coap", dir: Up, in: hex.EncodeToString(get), rule: 2, want: "4280"},
		{name: "Content in IPv6/UDP", stack: "ipv6/udp/coap", dir: Down, in: hex.EncodeToString(content), rule: 2, want: hex.EncodeToString(func() []byte {
			b := mustBits(t, "010 0 0001 010")
			b.AppendBytes(mustHex(t, "32332043"))
			b.Pad(8)
			return b.Bytes()
		}())},
	})
	// A wrong UDP checksum is not elided: the packet goes uncompressed.
	bad := append([]byte(nil), get...)
	bad[46] ^= 0xFF
	runCoAPCases(t, rules, []coapCase{{name: "bad checksum", stack: "ipv6/udp/coap", dir: Up, in: hex.EncodeToString(bad), rule: 0}})
}

// RFC 8824 figure 2: CoAP compressed end to end by its own rules, and the
// IPv6/UDP packet that carries the SCHC packet compressed by the LPWAN's
// rules: two stages, each undone in turn.
func TestCoAPTwoStages(t *testing.T) {
	inner, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.tkl","fl":4,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.code","fl":8,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.mid","fl":16,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.token","var":"tkl","mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.uriPath","var":"bytes","fp":0,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.uriPath","var":"bytes","fp":0,"mo":"ignore","cda":"value-sent"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":5,"fields":[
	 {"fid":"ipv6.version","fl":4,"tv":6,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.hopLimit","fl":8,"tv":64,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.devPrefix","fl":64,"tv":"2001:db8::/64","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.devIID","fl":64,"mo":"ignore","cda":"deviid"},
	 {"fid":"ipv6.appPrefix","fl":64,"tv":"2001:db8:1::/64","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.appIID","fl":64,"tv":"::2","mo":"equal","cda":"not-sent"},
	 {"fid":"udp.devPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
	 {"fid":"udp.appPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
	 {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	coapSt, _ := ParseStack("coap")
	ipSt, _ := ParseStack("ipv6/udp")
	ctx := Context{DevIID: mustHex(t, "0000000000000001")}
	// CON GET, token 1234, Uri-Path "rd" and "abc", 4 bytes of payload.
	msg := mustHex(t, "4201abcd1234"+"b2"+hex.EncodeToString([]byte("rd"))+"03"+hex.EncodeToString([]byte("abc"))+"ff"+"01020304")
	c1, r1, err := inner.Compress(coapSt, msg, Up, Context{})
	if err != nil || r1.ID != 1 {
		t.Fatalf("stage 1: rule %v, %v", r1, err)
	}
	c1.Pad(8)
	pkt := ipv6UDP(t, Up, "2001:db8::/64", "::1", "2001:db8:1::/64", "::2", 5683, 5683, 64, c1.Bytes())
	c2, r2, err := outer.Compress(ipSt, pkt, Up, ctx)
	if err != nil || r2.ID != 5 {
		t.Fatalf("stage 2: rule %v, %v", r2, err)
	}
	if c2.Len() != 8+8*len(c1.Bytes()) {
		t.Fatalf("stage 2 has %d bits, want the RuleID and the stage 1 packet", c2.Len())
	}
	back2, _, err := outer.Decompress(ipSt, c2, Up, ctx)
	if err != nil || !bytes.Equal(back2, pkt) {
		t.Fatalf("stage 2 back: %v", err)
	}
	p, err := ipSt.Parse(back2, Up)
	if err != nil {
		t.Fatal(err)
	}
	back1, _, err := inner.Decompress(coapSt, BytesOf(p.Payload), Up, Context{})
	if err != nil || !bytes.Equal(back1, msg) {
		t.Fatalf("stage 1 back: %x %v", back1, err)
	}
}

// RFC 9363 subfields: a rule may describe the CoAP code as class and
// detail and the IPv6 Traffic Class as DSCP and ECN.
func TestSubfields(t *testing.T) {
	rules := `{"rules":[{"ruleId":7,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.codeClass","fl":3,"tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.codeDetail","fl":5,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.mid","fl":16,"mo":"ignore","cda":"value-sent"}]}]}`
	// NON 2.05, MID 0x0102: class 2 elided, detail 00101 sent.
	want := mustBits(t, "00000111 00101 0000000100000010")
	want.Pad(8)
	runCoAPCases(t, rules, []coapCase{{name: "class/detail", stack: "coap", dir: Down, in: "50450102", rule: 7, want: hex.EncodeToString(want.Bytes())}})

	rs, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[
	 {"fid":"ipv6.version","fl":4,"tv":6,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.ds","fl":6,"tv":46,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.ecn","fl":2,"mo":"ignore","cda":"value-sent"},
	 {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.hopLimit","fl":8,"tv":64,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.devPrefix","fl":64,"mo":"ignore","cda":"value-sent"},
	 {"fid":"ipv6.devIID","fl":64,"mo":"ignore","cda":"value-sent"},
	 {"fid":"ipv6.appPrefix","fl":64,"mo":"ignore","cda":"value-sent"},
	 {"fid":"ipv6.appIID","fl":64,"mo":"ignore","cda":"value-sent"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, 40, 44)
	pkt[0], pkt[1] = 0x6B, 0x90 // version 6, traffic class 0xB9: DSCP 46, ECN 01
	pkt[5], pkt[6], pkt[7] = 4, 17, 64
	pkt = append(pkt, 1, 2, 3, 4)
	st, _ := ParseStack("ipv6")
	msg, r, err := rs.Compress(st, pkt, Up, Context{})
	if err != nil || r.ID != 1 {
		t.Fatalf("rule %v, %v", r, err)
	}
	if msg.Slice(8, 10).String() != "01" {
		t.Fatalf("ECN residue %s", msg.Slice(8, 10))
	}
	back, _, err := rs.Decompress(st, msg, Up, Context{})
	if err != nil || !bytes.Equal(back, pkt) {
		t.Fatalf("back %x, %v", back, err)
	}
	if _, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[
	 {"fid":"coap.code","fl":8,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.codeClass","fl":3,"mo":"ignore","cda":"value-sent"}]}]}`)); err == nil {
		t.Fatal("a rule with the code both whole and as subfields was accepted")
	}
}

// randomCoAP is a CoAP message with random header, token, options (any
// number, including extended deltas and lengths and the OSCORE option)
// and payload.
func randomCoAP(rng *rand.Rand) []byte {
	tkl := rng.Intn(9)
	b := []byte{byte(1<<6 | rng.Intn(4)<<4 | tkl), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
	for i := 0; i < tkl; i++ {
		b = append(b, byte(rng.Intn(256)))
	}
	nums := []uint32{1, 3, 4, 5, 6, 7, 8, 9, 11, 11, 11, 12, 14, 15, 15, 16, 17, 19, 20, 21, 23, 27, 28, 31, 35, 39, 60, 252, 258, 292, 2049, 2053, 65001}
	var last uint32
	for _, n := range nums {
		if rng.Intn(3) != 0 {
			continue
		}
		var v []byte
		if n == OptionOSCORE {
			h, k, pivLen := rng.Intn(2), rng.Intn(2), rng.Intn(6)
			v = append(v, byte(h<<4|k<<3|pivLen))
			for i := 0; i < pivLen; i++ {
				v = append(v, byte(rng.Intn(256)))
			}
			if h == 1 {
				s := rng.Intn(4)
				v = append(v, byte(s))
				for i := 0; i < s; i++ {
					v = append(v, byte(rng.Intn(256)))
				}
			}
			if k == 1 {
				for i := rng.Intn(4); i > 0; i-- {
					v = append(v, byte(rng.Intn(256)))
				}
			}
			if rng.Intn(5) == 0 {
				v = nil
			}
		} else {
			l := rng.Intn(16)
			if rng.Intn(8) == 0 {
				l = 13 + rng.Intn(300)
			}
			for i := 0; i < l; i++ {
				v = append(v, byte('a'+rng.Intn(26)))
			}
		}
		dn, dx := optNibble(n - last)
		ln, lx := optNibble(uint32(len(v)))
		last = n
		b = append(b, byte(dn<<4|ln))
		b = append(b, dx...)
		b = append(b, lx...)
		b = append(b, v...)
	}
	if rng.Intn(2) == 0 {
		b = append(b, 0xFF)
		for i := rng.Intn(20) + 1; i > 0; i-- {
			b = append(b, byte(rng.Intn(256)))
		}
	}
	return b
}

// Every CoAP message is labelled and rebuilt byte for byte, and a rule
// that sends every field it was labelled with brings it back.
func TestCoAPParseBuildRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(8824))
	st, _ := ParseStack("coap")
	for i := 0; i < 2000; i++ {
		msg := randomCoAP(rng)
		p, err := st.Parse(msg, Up)
		if err != nil {
			t.Fatalf("parse %x: %v", msg, err)
		}
		back, err := st.BuildFields(p.Fields, p.Payload, Up)
		if err != nil || !bytes.Equal(back, msg) {
			t.Fatalf("build %x\n got  %x, %v", msg, back, err)
		}
		// A rule sending every field it found, in the order found.
		var fds []string
		for _, f := range p.Fields {
			switch {
			case f.FID == FCoAPToken:
				fds = append(fds, fmt.Sprintf(`{"fid":%q,"fp":%d,"var":"tkl","mo":"ignore","cda":"value-sent"}`, f.FID, f.Pos))
			case coapHeaderLengths[f.FID] > 0:
				fds = append(fds, fmt.Sprintf(`{"fid":%q,"fl":%d,"mo":"ignore","cda":"value-sent"}`, f.FID, coapHeaderLengths[f.FID]))
			default:
				fds = append(fds, fmt.Sprintf(`{"fid":%q,"fp":%d,"var":"bytes","mo":"ignore","cda":"value-sent"}`, f.FID, f.Pos))
			}
		}
		rs, err := ParseRuleSet([]byte(`{"maxPacketSize":65535,"rules":[{"ruleId":1,"fields":[` + strings.Join(fds, ",") + `]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		c, r, err := rs.Compress(st, msg, Up, Context{})
		if err != nil || r.ID != 1 {
			t.Fatalf("compress %x: %v %v", msg, r, err)
		}
		c.Pad(8)
		d, _, err := rs.Decompress(st, c, Up, Context{})
		if err != nil || !bytes.Equal(d, msg) {
			t.Fatalf("round trip %x\n got        %x, %v", msg, d, err)
		}
	}
}

// Malformed CoAP is not labelled: the reserved TKLs, a payload marker with
// no payload, option nibble 15, an option running past the end, an OSCORE
// option whose piv or kid context runs past its end.
func TestCoAPParseRefusals(t *testing.T) {
	st, _ := ParseStack("coap")
	for _, h := range []string{
		"40", "49010000", "4001000001", "40010000ff", "40010000f0", "40010000b3666f", "400100009102",
		"4001000093100261", "8001000000",
	} {
		if _, err := st.Parse(mustHex(t, h), Up); err == nil {
			t.Errorf("%s was labelled", h)
		}
	}
	if _, err := ParseStack("coap/wrapper"); err == nil {
		t.Error("coap/wrapper accepted")
	}
	if _, err := ParseStack("ipv6/udp/coap-inner"); err == nil {
		t.Error("coap-inner under udp accepted")
	}
	if _, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[{"fid":"coap.mid","var":"tkl","mo":"ignore","cda":"value-sent"}]}]}`)); err == nil {
		t.Error("var tkl on a field other than the token accepted")
	}
}

// Text options take a plain string as text; other fields take hex, or
// {"text": …} and {"hex": …}.
func TestTargetValueForms(t *testing.T) {
	rs, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[
	 {"fid":"coap.uriPath","var":"bytes","tv":"cafe","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.etag","var":"bytes","tv":"cafe","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.etag","fp":2,"var":"bytes","tv":{"text":"ok"},"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.uriQuery","var":"bytes","tv":{"hex":"6869"},"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.contentFormat","var":"bytes","tv":0,"mo":"equal","cda":"not-sent"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f := rs.Rules[0].Fields
	for i, want := range []string{"63616665", "cafe", "6f6b", "6869", ""} {
		if got := hex.EncodeToString(f[i].tv[0].Bytes()); got != want {
			t.Errorf("field %d: tv %s, want %s", i, got, want)
		}
	}
}

func FuzzCoAPParse(f *testing.F) {
	f.Add(mustHexF("4101000182bb74656d7065726174757265"))
	f.Add(mustHexF("4102000182980904636c69656e74ffa2c54fe1b434297b62"))
	f.Add(mustHexF("6144000182d008ff10c6d7c26cc1"))
	st, _ := ParseStack("coap")
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := st.Parse(b, Up)
		if err != nil {
			return
		}
		back, err := st.BuildFields(p.Fields, p.Payload, Up)
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("%x rebuilt as %x, %v", b, back, err)
		}
	})
}

func mustHexF(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
