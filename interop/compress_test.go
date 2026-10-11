// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/cB-Sigma/schc"
)

// The same IPv6/UDP/CoAP rule in openschc's format and in ours: every
// matching operator and action both implement, residues of fixed and
// variable length, both directions.
var peerCoAPRules = []any{
	map[string]any{"RuleID": 5, "RuleIDLength": 3, "Compression": []any{
		map[string]any{"FID": "IPV6.VER", "TV": 6, "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "IPV6.TC", "TV": 0, "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "IPV6.FL", "MO": "ignore", "CDA": "value-sent"},
		map[string]any{"FID": "IPV6.LEN", "MO": "ignore", "CDA": "compute-length"},
		map[string]any{"FID": "IPV6.NXT", "TV": 17, "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "IPV6.HOP_LMT", "MO": "ignore", "CDA": "value-sent"},
		map[string]any{"FID": "IPV6.DEV_PREFIX", "TV": []string{"2001:db8::/64", "fe80::/64"}, "MO": "match-mapping", "CDA": "mapping-sent"},
		map[string]any{"FID": "IPV6.DEV_IID", "TV": "::1", "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "IPV6.APP_PREFIX", "TV": []string{"2001:db8:1::/64", "fe80::/64", "2001:db8:2::/64"}, "MO": "match-mapping", "CDA": "mapping-sent"},
		map[string]any{"FID": "IPV6.APP_IID", "MO": "ignore", "CDA": "value-sent"},
		map[string]any{"FID": "UDP.DEV_PORT", "TV": 5680, "MO": "MSB", "MO.VAL": 12, "CDA": "LSB"},
		map[string]any{"FID": "UDP.APP_PORT", "TV": 5680, "MO": "MSB", "MO.VAL": 12, "CDA": "LSB"},
		map[string]any{"FID": "UDP.LEN", "MO": "ignore", "CDA": "compute-length"},
		map[string]any{"FID": "UDP.CKSUM", "MO": "ignore", "CDA": "compute-checksum"},
		map[string]any{"FID": "COAP.VER", "TV": 1, "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "COAP.TYPE", "MO": "ignore", "CDA": "value-sent"},
		map[string]any{"FID": "COAP.TKL", "TV": 1, "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "COAP.CODE", "DI": "UP", "TV": []int{1, 2, 3}, "MO": "match-mapping", "CDA": "mapping-sent"},
		map[string]any{"FID": "COAP.CODE", "DI": "DW", "TV": []int{69, 132}, "MO": "match-mapping", "CDA": "mapping-sent"},
		map[string]any{"FID": "COAP.MID", "TV": 4096, "MO": "MSB", "MO.VAL": 12, "CDA": "LSB"},
		map[string]any{"FID": "COAP.TOKEN", "MO": "ignore", "CDA": "value-sent"},
		map[string]any{"FID": "COAP.URI-PATH", "FL": "var", "FP": 1, "DI": "UP", "TV": "temp", "MO": "equal", "CDA": "not-sent"},
		map[string]any{"FID": "COAP.URI-PATH", "FL": "var", "FP": 2, "DI": "UP", "MO": "ignore", "CDA": "value-sent"},
		map[string]any{"FID": "COAP.CONTENT-FORMAT", "FL": "var", "DI": "DW", "TV": 60, "MO": "equal", "CDA": "not-sent"},
	}},
	map[string]any{"RuleID": 7, "RuleIDLength": 3, "NoCompression": []any{}},
}

const ourCoAPRules = `{"rules":[{"ruleId":5,"ruleIdLength":3,"fields":[
 {"fid":"ipv6.version","fl":4,"tv":6,"mo":"equal","cda":"not-sent"},
 {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
 {"fid":"ipv6.flowLabel","fl":20,"mo":"ignore","cda":"value-sent"},
 {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute"},
 {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
 {"fid":"ipv6.hopLimit","fl":8,"mo":"ignore","cda":"value-sent"},
 {"fid":"ipv6.devPrefix","fl":64,"tv":["2001:db8::/64","fe80::/64"],"mo":"match-mapping","cda":"mapping-sent"},
 {"fid":"ipv6.devIID","fl":64,"tv":"::1","mo":"equal","cda":"not-sent"},
 {"fid":"ipv6.appPrefix","fl":64,"tv":["2001:db8:1::/64","fe80::/64","2001:db8:2::/64"],"mo":"match-mapping","cda":"mapping-sent"},
 {"fid":"ipv6.appIID","fl":64,"mo":"ignore","cda":"value-sent"},
 {"fid":"udp.devPort","fl":16,"tv":5680,"mo":"msb(12)","cda":"lsb"},
 {"fid":"udp.appPort","fl":16,"tv":5680,"mo":"msb(12)","cda":"lsb"},
 {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute"},
 {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute"},
 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.type","fl":2,"mo":"ignore","cda":"value-sent"},
 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.code","fl":8,"di":"up","tv":[1,2,3],"mo":"match-mapping","cda":"mapping-sent"},
 {"fid":"coap.code","fl":8,"di":"dw","tv":[69,132],"mo":"match-mapping","cda":"mapping-sent"},
 {"fid":"coap.mid","fl":16,"tv":4096,"mo":"msb(12)","cda":"lsb"},
 {"fid":"coap.token","var":"tkl","mo":"ignore","cda":"value-sent"},
 {"fid":"coap.uriPath","var":"bytes","di":"up","tv":"temp","mo":"equal","cda":"not-sent"},
 {"fid":"coap.uriPath","var":"bytes","fp":2,"di":"up","mo":"ignore","cda":"value-sent"},
 {"fid":"coap.contentFormat","var":"bytes","di":"dw","tv":60,"mo":"equal","cda":"not-sent"}]},
 {"ruleId":7,"ruleIdLength":3,"kind":"no-compression"}]}`

func mustRules(t *testing.T, s string) *schc.RuleSet {
	t.Helper()
	rs, err := schc.ParseRuleSet([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// ipv6UDP wraps a UDP payload in IPv6 and UDP headers with the length and
// checksum computed. dev and app are the device's and the application's
// addresses; dir says which is the source.
func ipv6UDP(t *testing.T, dir schc.Direction, dev, app string, devPort, appPort uint16, flow uint32, hop uint8, payload []byte) []byte {
	t.Helper()
	st, _ := schc.ParseStack("ipv6/udp")
	pfx := func(s string) schc.Bits {
		v, err := schc.IPv6Value(s + "/64")
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	iid := func(s string) schc.Bits {
		v, err := schc.IPv6Value(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	vals := map[string]schc.Bits{
		schc.FIPv6Version: schc.Uint(6, 4), schc.FIPv6TrafficClass: schc.Uint(0, 8),
		schc.FIPv6FlowLabel: schc.Uint(uint64(flow), 20), schc.FIPv6NextHeader: schc.Uint(17, 8),
		schc.FIPv6HopLimit:  schc.Uint(uint64(hop), 8),
		schc.FIPv6DevPrefix: pfx(dev), schc.FIPv6DevIID: iid(dev),
		schc.FIPv6AppPrefix: pfx(app), schc.FIPv6AppIID: iid(app),
		schc.FUDPDevPort: schc.Uint(uint64(devPort), 16), schc.FUDPAppPort: schc.Uint(uint64(appPort), 16),
	}
	b, err := st.Build(vals, payload, dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// coapGet is a CON GET /temp/<last> with a one-byte token and a payload.
func coapUp(t *testing.T) []byte {
	coap, _ := hex.DecodeString("41011003" + "ab" + "b474656d70" + "026131" + "ff" + "6869")
	return ipv6UDP(t, schc.Up, "2001:db8::1", "2001:db8:2::7", 5683, 5683, 0x12345, 64, coap)
}

// coapDown is an ACK 2.05 Content with Content-Format 60 and a payload.
func coapDown(t *testing.T) []byte {
	coap, _ := hex.DecodeString("61451003" + "ab" + "c13c" + "ff" + "a1617818")
	return ipv6UDP(t, schc.Down, "2001:db8::1", "2001:db8:2::7", 5683, 5683, 0x00001, 63, coap)
}

// peerCompressed reads "compressed <hex> <bits>".
func peerCompressed(t *testing.T, lines []string) schc.Bits {
	t.Helper()
	for _, l := range lines {
		if s, ok := strings.CutPrefix(l, "compressed "); ok {
			f := strings.Fields(s)
			if len(f) != 2 {
				t.Fatalf("peer: %q", l)
			}
			b, err := hex.DecodeString(f[0])
			if err != nil {
				t.Fatal(err)
			}
			n, err := strconv.Atoi(f[1])
			if err != nil {
				t.Fatal(err)
			}
			return schc.BitsOf(b, n)
		}
	}
	t.Fatalf("peer compressed nothing: %q", lines)
	return schc.Bits{}
}

func bitsHex(b schc.Bits) string { return fmt.Sprintf("%x/%d", b.Bytes(), b.Len()) }

// Covers: SIG-IPE-7300
func TestCompressionMatchesOpenschc(t *testing.T) {
	p := startPeer(t)
	rs := mustRules(t, ourCoAPRules)
	st, _ := schc.ParseStack("ipv6/udp/coap")
	for _, tc := range []struct {
		name, role string
		dir        schc.Direction
		pkt        []byte
	}{
		{"up", "device", schc.Up, coapUp(t)},
		{"down", "core", schc.Down, coapDown(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.setup(tc.role, peerCoAPRules, 4000)
			theirs := peerCompressed(t, p.do(map[string]any{"cmd": "compress", "hex": hex.EncodeToString(tc.pkt)}))
			ours, rule, err := rs.Compress(st, tc.pkt, tc.dir, schc.Context{})
			if err != nil {
				t.Fatal(err)
			}
			if rule.ID != 5 {
				t.Fatalf("our rule %d, want 5", rule.ID)
			}
			if !ours.Equal(theirs) {
				t.Fatalf("compressed differently:\n ours     %s\n openschc %s", bitsHex(ours), bitsHex(theirs))
			}
			back, _, err := rs.Decompress(st, theirs, tc.dir, schc.Context{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, tc.pkt) {
				t.Fatalf("openschc's residue decompressed to\n %x\nwant\n %x", back, tc.pkt)
			}
		})
	}
}

// Covers: SIG-IPE-7300
func TestOpenschcDecompressesOurs(t *testing.T) {
	p := startPeer(t)
	rs := mustRules(t, ourCoAPRules)
	st, _ := schc.ParseStack("ipv6/udp/coap")
	for _, tc := range []struct {
		name, role string // the peer receives: core gets uplinks
		dir        schc.Direction
		pkt        []byte
	}{
		{"up", "core", schc.Up, coapUp(t)},
		{"down", "device", schc.Down, coapDown(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.setup(tc.role, peerCoAPRules, 4000)
			msg, _, err := rs.Compress(st, tc.pkt, tc.dir, schc.Context{})
			if err != nil {
				t.Fatal(err)
			}
			msg.Pad(8)
			got := packets(t, p.do(map[string]any{"cmd": "recv", "hex": hex.EncodeToString(msg.Bytes())}))
			if len(got) != 1 || !bytes.Equal(got[0], tc.pkt) {
				t.Fatalf("openschc rebuilt %x\nwant %x", got, tc.pkt)
			}
		})
	}
}

// Covers: SIG-IPE-7300
func TestNoCompressionRuleWithOpenschc(t *testing.T) {
	p := startPeer(t)
	rs := mustRules(t, ourCoAPRules)
	st, _ := schc.ParseStack("ipv6/udp/coap")
	// A packet the compression rule does not fit (traffic class 1).
	pkt := coapUp(t)
	pkt[1] = 0x10 | pkt[1]&0x0F // traffic class 1: its low nibble is the high nibble of byte 1
	p.setup("device", peerCoAPRules, 4000)
	theirs := peerCompressed(t, p.do(map[string]any{"cmd": "compress", "hex": hex.EncodeToString(pkt)}))
	ours, rule, err := rs.Compress(st, pkt, schc.Up, schc.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID != 7 || !ours.Equal(theirs) {
		t.Fatalf("rule %d: ours %s, openschc %s", rule.ID, bitsHex(ours), bitsHex(theirs))
	}
}
