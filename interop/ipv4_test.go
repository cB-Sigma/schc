// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/schc"
)

// Covers: SIG-IPE-7304
//
// IPv4/UDP and IPv4/SCTP packets built by scapy 2.5.0 (in the openschc
// image) compress with every computed field elided (IPv4 IHL, Total
// Length and Header Checksum, UDP length and checksum, the SCTP CRC32c)
// and come back byte for byte: our checksums are scapy's.
func TestIPv4AndSCTPAgainstScapy(t *testing.T) {
	p := startPeer(t)
	rs := mustRules(t, `{"rules":[
	 {"ruleId":1,"fields":[
	  {"fid":"ipv4.version","fl":4,"tv":4,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.ihl","fl":4,"tv":5,"mo":"equal","cda":"compute"},
	  {"fid":"ipv4.tos","fl":8,"mo":"ignore","cda":"value-sent"},
	  {"fid":"ipv4.totalLength","fl":16,"mo":"ignore","cda":"compute"},
	  {"fid":"ipv4.identification","fl":16,"mo":"ignore","cda":"value-sent"},
	  {"fid":"ipv4.flags","fl":3,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.fragmentOffset","fl":13,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.ttl","fl":8,"mo":"ignore","cda":"value-sent"},
	  {"fid":"ipv4.protocol","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.checksum","fl":16,"mo":"ignore","cda":"compute"},
	  {"fid":"ipv4.devAddress","fl":32,"tv":"192.0.2.10","mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.appAddress","fl":32,"tv":["198.51.100.1","198.51.100.2"],"mo":"match-mapping","cda":"mapping-sent"},
	  {"fid":"udp.devPort","fl":16,"tv":5680,"mo":"msb(12)","cda":"lsb"},
	  {"fid":"udp.appPort","fl":16,"tv":5680,"mo":"msb(12)","cda":"lsb"},
	  {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute"},
	  {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute"}]},
	 {"ruleId":2,"fields":[
	  {"fid":"ipv4.version","fl":4,"tv":4,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.ihl","fl":4,"tv":5,"mo":"equal","cda":"compute"},
	  {"fid":"ipv4.ds","fl":6,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.ecn","fl":2,"mo":"ignore","cda":"value-sent"},
	  {"fid":"ipv4.totalLength","fl":16,"mo":"ignore","cda":"compute"},
	  {"fid":"ipv4.identification","fl":16,"mo":"ignore","cda":"value-sent"},
	  {"fid":"ipv4.flags","fl":3,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.fragmentOffset","fl":13,"tv":0,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.ttl","fl":8,"tv":64,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.protocol","fl":8,"tv":132,"mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.checksum","fl":16,"mo":"ignore","cda":"compute"},
	  {"fid":"ipv4.devAddress","fl":32,"tv":"192.0.2.10","mo":"equal","cda":"not-sent"},
	  {"fid":"ipv4.appAddress","fl":32,"mo":"ignore","cda":"value-sent"},
	  {"fid":"sctp.devPort","fl":16,"tv":2905,"mo":"equal","cda":"not-sent"},
	  {"fid":"sctp.appPort","fl":16,"tv":2905,"mo":"equal","cda":"not-sent"},
	  {"fid":"sctp.verificationTag","fl":32,"mo":"ignore","cda":"value-sent"},
	  {"fid":"sctp.checksum","fl":32,"mo":"ignore","cda":"compute"}]}]}`)
	for _, tc := range []struct {
		name, stack string
		cmd         map[string]any
		dir         schc.Direction
		rule        uint32
	}{
		{"udp-up", "ipv4/udp", map[string]any{"l4": "udp", "src": "192.0.2.10", "dst": "198.51.100.2", "sport": 5683, "dport": 5684, "ttl": 63, "id": 4242, "tos": 0xb8, "payload": "48656c6c6f"}, schc.Up, 1},
		{"udp-down", "ipv4/udp", map[string]any{"l4": "udp", "src": "198.51.100.1", "dst": "192.0.2.10", "sport": 5683, "dport": 5681, "ttl": 7, "id": 1, "payload": "0102030405060708090a"}, schc.Down, 1},
		{"sctp-up", "ipv4/sctp", map[string]any{"l4": "sctp", "src": "192.0.2.10", "dst": "203.0.113.9", "sport": 2905, "dport": 2905, "tag": 0x1a2b3c4d, "tos": 1, "payload": "0001000200030004deadbeef"}, schc.Up, 2},
		{"sctp-down", "ipv4/sctp", map[string]any{"l4": "sctp", "src": "203.0.113.9", "dst": "192.0.2.10", "sport": 2905, "dport": 2905, "tag": 7, "payload": "41"}, schc.Down, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cmd["cmd"] = "scapy4"
			got := lineArg(t, p.do(tc.cmd), "scapy")
			if len(got) != 1 {
				t.Fatalf("scapy: %q", got)
			}
			pkt := unhex(t, got[0])
			st, err := schc.ParseStack(tc.stack)
			if err != nil {
				t.Fatal(err)
			}
			c, r, err := rs.Compress(st, pkt, tc.dir, schc.Context{})
			if err != nil {
				t.Fatal(err)
			}
			if r.ID != tc.rule {
				t.Fatalf("compressed by rule %d, want %d (a computed field disagreed with scapy's)", r.ID, tc.rule)
			}
			back, _, err := rs.Decompress(st, c, tc.dir, schc.Context{})
			if err != nil || !bytes.Equal(back, pkt) {
				t.Fatalf("%x %v\nwant %x", back, err, pkt)
			}
		})
	}
}
