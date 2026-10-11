// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// yangRoundTrip writes rs as RFC 9363 JSON, reads it back, writes it
// again, and checks the two documents are the same.
func yangRoundTrip(t *testing.T, rs *RuleSet, opt YANGOptions) *RuleSet {
	t.Helper()
	y1, err := rs.MarshalYANG()
	if err != nil {
		t.Fatal(err)
	}
	back, skipped, err := ParseYANGWith(y1, opt)
	if err != nil || len(skipped) > 0 {
		t.Fatalf("read back: %v %v\n%s", err, skipped, y1)
	}
	y2, err := back.MarshalYANG()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(y1, y2) {
		l1, l2 := strings.Split(string(y1), "\n"), strings.Split(string(y2), "\n")
		for i := range l1 {
			if i >= len(l2) || l1[i] != l2[i] {
				t.Fatalf("not stable at line %d:\n%s\n----\n%s", i+1, strings.Join(l1[max(0, i-12):min(len(l1), i+3)], "\n"), strings.Join(l2[max(0, i-12):min(len(l2), i+3)], "\n"))
			}
		}
		t.Fatal("not stable: the second is longer")
	}
	return back
}

// sameCompression checks that two rule sets compress and decompress
// packets the same.
func sameCompression(t *testing.T, a, b *RuleSet, stack string, dir Direction, ctx Context, pkts ...[]byte) {
	t.Helper()
	st, err := ParseStack(stack)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkts {
		ma, ra, err1 := a.Compress(st, p, dir, ctx)
		mb, rb, err2 := b.Compress(st, p, dir, ctx)
		if err1 != nil || err2 != nil || ra.ID != rb.ID || !ma.Equal(mb) {
			t.Fatalf("%x: %v/%v rule %v/%v\n%s\n%s", p, err1, err2, ra, rb, ma, mb)
		}
		mb.Pad(8)
		back, _, err := b.Decompress(st, mb, dir, ctx)
		if err != nil || !bytes.Equal(back, p) {
			t.Fatalf("%x back as %x, %v", p, back, err)
		}
	}
}

// Our JSON rules for IPv6/UDP (RFC 8724 appendix A), the IEC 62056-4-7
// wrapper, CoAP with OSCORE (RFC 8824 table 5) and the RFC 9011
// fragmentation rules go to RFC 9363 JSON and back unchanged, and
// compress the same.
func TestYANGRoundTrip(t *testing.T) {
	a, err := ParseRuleSet([]byte(appendixARules))
	if err != nil {
		t.Fatal(err)
	}
	ab := yangRoundTrip(t, a, YANGOptions{})
	ctx := Context{DevIID: mustHex(t, "0000000000000007")}
	sameCompression(t, a, ab, "ipv6/udp", Up, ctx,
		ipv6UDP(t, Up, "fe80::/64", "::7", "fe80::/64", "::1", 123, 124, 255, []byte("abc")),
		ipv6UDP(t, Up, "2001:db8:a::/64", "::7", "2001:db8:a::/64", "::1000", 5683, 5683, 255, []byte("abc")),
		ipv6UDP(t, Up, "2001:db8:a::/64", "::7", "2001:db8:c::/64", "::1000", 8722, 8725, 255, nil))

	w, err := ParseRuleSet([]byte(wrapperRules))
	if err != nil {
		t.Fatal(err)
	}
	wb := yangRoundTrip(t, w, YANGOptions{})
	sameCompression(t, w, wb, "wrapper", Up, Context{}, wpdu(1, 16, []byte{0xC0, 1}), wpdu(5, 300, []byte{1, 2, 3}))

	coap := `{"rules":[{"ruleId":0,"fields":[
	 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"up","tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.type","fl":2,"di":"dw","tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"coap.codeClass","fl":3,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.codeDetail","fl":5,"mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(12)","cda":"lsb"},
	 {"fid":"coap.token","var":"tkl","tv":"80","mo":"msb(5)","cda":"lsb"},
	 {"fid":"coap.uriPath","var":"bytes","fp":0,"di":"up","tv":["a","bc"],"mo":"match-mapping","cda":"mapping-sent"},
	 {"fid":"coap.echo","var":"bytes","di":"up","mo":"ignore","cda":"value-sent"},
	 {"fid":"coap.oscore.flags","fl":8,"di":"up","tv":"09","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.piv","var":"bits","di":"up","tv":"00","mo":"msb(4)","cda":"lsb"},
	 {"fid":"coap.oscore.kid","var":"bits","di":"up","tv":"636c69656e70","mo":"msb(44)","cda":"lsb"},
	 {"fid":"coap.oscore.kidctx","var":"bytes","tv":"","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.flags","var":"bytes","di":"dw","tv":"","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.piv","var":"bytes","di":"dw","tv":"","mo":"equal","cda":"not-sent"},
	 {"fid":"coap.oscore.kid","var":"bytes","di":"dw","tv":"","mo":"equal","cda":"not-sent"}]}]}`
	c, err := ParseRuleSet([]byte(coap))
	if err != nil {
		t.Fatal(err)
	}
	cb := yangRoundTrip(t, c, YANGOptions{})
	// POST, OSCORE flags 09 piv 04 kid "client", Uri-Path "bc", Echo "e".
	sameCompression(t, c, cb, "coap", Up, Context{}, mustHex(t, "4102000182"+"98"+"0904636c69656e74"+"22"+"6263"+"d1e4"+"65"+"ff"+"a2c5"))

	l := RuleSet{Rules: []Rule{LoRaWANUplinkRule(FPortUp, 10, false), LoRaWANDownlinkRule(FPortDown, ClassA, 0)}}
	l.Rules[0].Fragmentation.Direction = Up
	l.Rules[1].Fragmentation.Direction = Down
	if err := l.Compile(); err != nil {
		t.Fatal(err)
	}
	lb := yangRoundTrip(t, &l, YANGOptions{})
	for i := range l.Rules {
		p, q := l.Rules[i].Fragmentation, lb.Rules[i].Fragmentation
		if p.Mode != q.Mode || p.WSize != q.WSize || p.FCNSize != q.FCNSize || p.WindowSize != q.WindowSize ||
			p.TileSize != q.TileSize || p.LastTile != q.LastTile || p.MaxAckRequests != q.MaxAckRequests || p.Direction != q.Direction {
			t.Fatalf("rule %d: %+v\n became %+v", l.Rules[i].ID, p, q)
		}
	}
}

// The RFC 9441 augment carries the Compound ACK settings.
func TestYANGCompoundAck(t *testing.T) {
	rs, err := ParseRuleSet([]byte(`{"rules":[` + compoundRule[:len(compoundRule)-2] + `,"direction":"up","lastBitmapUncompressed":true}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	y, _ := rs.MarshalYANG()
	if !strings.Contains(string(y), `"ietf-schc-compound-ack:bitmap-format": "ietf-schc-compound-ack:bitmap-compound-ack"`) ||
		!strings.Contains(string(y), `"ietf-schc-compound-ack:last-bitmap-compression": false`) {
		t.Fatalf("no augment in\n%s", y)
	}
	back := yangRoundTrip(t, rs, YANGOptions{})
	if p := back.Rules[0].Fragmentation; !p.CompoundAck || !p.LastBitmapUncompressed || p.RCS != "crc8" {
		t.Fatalf("%+v", p)
	}
}

// What RFC 9363 cannot say is refused on the way out, not lost.
func TestYANGRefusals(t *testing.T) {
	for _, js := range []string{
		`{"rules":[{"ruleId":1,"fields":[{"fid":"coap.option.65001","var":"bytes","mo":"ignore","cda":"value-sent"}]}]}`,
		`{"rules":[{"ruleId":1,"fragmentation":{"mode":"no-ack","fcnSize":1}}]}`,
		`{"rules":[{"ruleId":1,"fragmentation":{"mode":"ack-on-error","direction":"up","wSize":1,"fcnSize":3,"tileBytes":40}}]}`,
	} {
		rs, err := ParseRuleSet([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rs.MarshalYANG(); err == nil {
			t.Errorf("written: %s", js)
		}
	}
	for _, y := range []string{
		`{"ietf-schc:schc":{"rule":[{"rule-id-value":1,"rule-id-length":8,"rule-nature":"ietf-schc:nature-compression","entry":[{"field-id":"ietf-schc:fid-coap-mid","field-length":16,"field-position":1,"direction-indicator":"ietf-schc:di-up","matching-operator":"ietf-schc:mo-msb","comp-decomp-action":"ietf-schc:cda-lsb","target-value":[{"index":0,"value":"AAA="}]}]}]}}`,
		`{"ietf-schc:schc":{"rule":[{"rule-id-value":1,"rule-id-length":8,"rule-nature":"ietf-schc:nature-fragmentation","fragmentation-mode":"ietf-schc:fragmentation-mode-no-ack","direction":"ietf-schc:di-bidirectional","fcn-size":1}]}}`,
		`{"ietf-schc:schc":{"rule":[{"rule-id-value":1,"rule-id-length":8,"rule-nature":"ietf-schc:nature-compression","entry":[{"field-id":"example:fid-foo","field-length":8,"field-position":1,"direction-indicator":"ietf-schc:di-up","matching-operator":"ietf-schc:mo-ignore","comp-decomp-action":"ietf-schc:cda-value-sent"}]}]}}`,
		`{"ietf-schc:schc":{"rule":[{"rule-id-value":1,"rule-id-length":8,"rule-nature":"ietf-schc:nature-compression","entry":[{"field-id":"ietf-schc:fid-coap-mid","field-length":16,"field-position":1,"direction-indicator":"ietf-schc:di-up","matching-operator":"ietf-schc:mo-equal","comp-decomp-action":"ietf-schc:cda-not-sent","target-value":[{"index":0,"value":"AQID"}]}]}]}}`,
	} {
		if _, err := ParseYANG([]byte(y)); err == nil {
			t.Errorf("read: %s", y)
		}
	}
}

// openschc's example rules in RFC 9363 JSON (examples/datamodel/schc.json,
// openschc commit 58293f71, MIT licence; see testdata/openschc) load,
// and their CoAP and ICMPv6 rules compress packets to the residues the
// rules describe.
func TestYANGOpenSCHCExample(t *testing.T) {
	b, err := os.ReadFile("testdata/openschc/schc.json")
	if err != nil {
		t.Fatal(err)
	}
	// openschc wrote its ACK-on-Error rules without tile-size (its own
	// configuration has tileSize 16 and 17 bits): read as RFC 9363 says,
	// tiles that fill their fragment, or with a size given.
	rs, err := ParseYANG(b)
	if err != nil || len(rs.Rules) != 8 || rs.ByID(1).Fragmentation.TileSize != 0 {
		t.Fatalf("read: %v", err)
	}
	yangRoundTrip(t, rs, YANGOptions{})
	rs, skipped, err := ParseYANGWith(b, YANGOptions{TileBits: 16})
	if err != nil || len(skipped) != 0 || len(rs.Rules) != 8 || rs.ByID(2).Fragmentation.TileSize != 16 {
		t.Fatalf("read with tile size: %v", err)
	}
	yangRoundTrip(t, rs, YANGOptions{TileBits: 16})

	// Rule 5 (3-bit RuleID 101), uplink: IPv6/UDP/CoAP POST with Uri-Path
	// foo/toto/x/yz, Uri-Query k=v1, token AB, payload "hi".
	vals := map[string]Bits{
		FIPv6Version: Uint(6, 4), FIPv6TrafficClass: Uint(1, 8), FIPv6FlowLabel: Uint(0x23456, 20),
		FIPv6NextHeader: Uint(17, 8), FIPv6HopLimit: Uint(255, 8),
		FUDPDevPort: Uint(5683, 16), FUDPAppPort: Uint(5683, 16),
	}
	for fid, s := range map[string]string{FIPv6DevPrefix: "2001:db8::/64", FIPv6DevIID: "::1", FIPv6AppPrefix: "2001:db8:1::/64", FIPv6AppIID: "::2"} {
		vals[fid], _ = IPv6Value(s)
	}
	coap := mustHex(t, "41021234ab"+"b3666f6f"+"04746f746f"+"0178"+"02797a"+"446b3d7631"+"ff6869")
	st, _ := ParseStack("ipv6/udp/coap")
	pkt, err := Stack{"ipv6", "udp"}.Build(vals, coap, Up)
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{DevIID: mustHex(t, "0000000000000001")}
	msg, r, err := rs.Compress(st, pkt, Up, ctx)
	if err != nil || r.ID != 5 {
		t.Fatalf("rule %v, %v", r, err)
	}
	want := mustBits(t, "101"+"00010001"+"00"+"00"+"0011"+"0011"+"00"+"0001"+"00000010"+"0001001000110100"+"10101011"+"1")
	want.AppendUint(1, 4)
	want.AppendBytes([]byte("x"))
	want.AppendUint(2, 4)
	want.AppendBytes([]byte("yz"))
	want.AppendUint(2, 4)
	want.AppendBytes([]byte("v1"))
	want.AppendBytes([]byte("hi"))
	if !msg.Equal(want) {
		t.Fatalf("rule 5:\n got  %s\n want %s", msg, want)
	}
	msg.Pad(8)
	back, _, err := rs.Decompress(st, msg, Up, ctx)
	if err != nil || !bytes.Equal(back, pkt) {
		t.Fatalf("rule 5 back: %v", err)
	}

	// Rule 6 (110): an ICMPv6 Echo Request from fe80::79 to fe80::7d4.
	vals = map[string]Bits{
		FIPv6Version: Uint(6, 4), FIPv6TrafficClass: Uint(0, 8), FIPv6FlowLabel: Uint(0, 20),
		FIPv6NextHeader: Uint(58, 8), FIPv6HopLimit: Uint(255, 8),
		FICMPv6Type: Uint(128, 8), FICMPv6Code: Uint(0, 8), FICMPv6Identifier: Uint(0x0102, 16), FICMPv6Sequence: Uint(7, 16),
	}
	for fid, s := range map[string]string{FIPv6DevPrefix: "fe80::/64", FIPv6DevIID: "::79", FIPv6AppPrefix: "fe80::/64", FIPv6AppIID: "::7d4"} {
		vals[fid], _ = IPv6Value(s)
	}
	ist, _ := ParseStack("ipv6/icmpv6")
	ping, err := ist.Build(vals, []byte("ping"), Up)
	if err != nil {
		t.Fatal(err)
	}
	ctx = Context{DevIID: mustHex(t, "0000000000000079")}
	msg, r, err = rs.Compress(ist, ping, Up, ctx)
	if err != nil || r.ID != 6 {
		t.Fatalf("rule %v, %v", r, err)
	}
	want = mustBits(t, "110"+"01"+"01"+"0000000100000010"+"0000000000000111")
	want.AppendBytes([]byte("ping"))
	if !msg.Equal(want) {
		t.Fatalf("rule 6:\n got  %s\n want %s", msg, want)
	}
	msg.Pad(8)
	if back, _, err := rs.Decompress(ist, msg, Up, ctx); err != nil || !bytes.Equal(back, ping) {
		t.Fatalf("rule 6 back: %v", err)
	}

	// The fragmentation rules: modes, directions, sizes.
	for id, want := range map[uint32]string{1: "ack-on-error dw 2 7 3", 2: "ack-on-error up 2 7 3", 3: "no-ack dw 2 0 3", 4: "no-ack up 2 0 3", 7: "ack-always up 2 1 3"} {
		p := rs.ByID(id).Fragmentation
		got := strings.Join([]string{p.Mode, string(p.Direction), itoa(p.DTagSize), itoa(p.WSize), itoa(p.FCNSize)}, " ")
		if got != want {
			t.Errorf("rule %d: %s, want %s", id, got, want)
		}
	}
	if rs.ByID(8).Kind != KindNoCompression {
		t.Error("rule 8 is not the no-compression rule")
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// A YANG timer holds a duration exactly when ticks can, else the nearest
// above in the finest tick.
func TestYANGTimers(t *testing.T) {
	for _, s := range []string{"1s", "1m", "12h", "1h", "100ms", "0s"} {
		var d Duration
		if err := json.Unmarshal([]byte(`"`+s+`"`), &d); err != nil {
			t.Fatal(err)
		}
		y, err := yangTimer(d.D())
		if err != nil {
			t.Fatal(err)
		}
		back := y.duration()
		if back < d.D() || back-d.D() > d.D()/1000+1 {
			t.Errorf("%s became %v (%d ticks of 2^%d µs)", s, back, *y.TicksNumbers, *y.TicksDuration)
		}
	}
}

// Fuzz: reading RFC 9363 JSON never panics; what it accepts writes back.
func FuzzParseYANG(f *testing.F) {
	b, err := os.ReadFile("testdata/openschc/schc.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"ietf-schc:schc":{"rule":[{"rule-id-value":1,"rule-id-length":8,"rule-nature":"nature-no-compression"}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, _, err := ParseYANGWith(b, YANGOptions{SkipBadRules: true, TileBits: 16})
		if err != nil {
			return
		}
		if _, err := rs.MarshalYANG(); err != nil {
			t.Fatalf("read but cannot write: %v", err)
		}
	})
}
