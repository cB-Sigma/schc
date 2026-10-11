// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"testing"
)

// Covers: SIG-IPE-7312
//
// IPv4 (RFC 791) with options and SCTP (RFC 9260) field descriptions:
// a header with a 4-byte option builds with a valid checksum, parses back
// to the same fields, and compresses with the options as a variable-length
// residue; the stack rules hold.
func TestIPv4OptionsAndSCTP(t *testing.T) {
	st, err := ParseStack("ipv4/sctp")
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]Bits{FIPv4Version: Uint(4, 4), FIPv4ToS: Uint(0, 8), FIPv4Identification: Uint(9, 16),
		FIPv4Flags: Uint(2, 3), FIPv4FragmentOffset: Uint(0, 13), FIPv4TTL: Uint(1, 8), FIPv4Protocol: Uint(132, 8),
		FIPv4DevAddress: BytesOf([]byte{10, 0, 0, 1}), FIPv4AppAddress: BytesOf([]byte{10, 0, 0, 2}),
		FIPv4Options: BytesOf([]byte{0x94, 0x04, 0, 0}), // Router Alert
		FSCTPDevPort: Uint(1, 16), FSCTPAppPort: Uint(2, 16), FSCTPVerificationTag: Uint(3, 32)}
	pkt, err := st.Build(vals, []byte{0, 3, 0, 4}, Up)
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != 0x46 || onesSum(pkt[:24]) != 0 {
		t.Fatalf("header %x", pkt[:24])
	}
	p, err := st.Parse(pkt, Up)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := fieldValue(p, FIPv4Options); !bytes.Equal(v.Bytes(), []byte{0x94, 4, 0, 0}) {
		t.Fatalf("options %s", v)
	}
	rs, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":4,"fields":[
	 {"fid":"ipv4.version","fl":4,"tv":4,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.ihl","fl":4,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv4.tos","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.totalLength","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv4.identification","fl":16,"mo":"ignore","cda":"value-sent"},
	 {"fid":"ipv4.flags","fl":3,"tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.fragmentOffset","fl":13,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.ttl","fl":8,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.protocol","fl":8,"tv":132,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.checksum","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv4.devAddress","fl":32,"tv":"10.0.0.1","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.appAddress","fl":32,"tv":"10.0.0.2","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv4.options","var":"bytes","mo":"ignore","cda":"value-sent"},
	 {"fid":"sctp.devPort","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
	 {"fid":"sctp.appPort","fl":16,"tv":2,"mo":"equal","cda":"not-sent"},
	 {"fid":"sctp.verificationTag","fl":32,"tv":3,"mo":"equal","cda":"not-sent"},
	 {"fid":"sctp.checksum","fl":32,"mo":"ignore","cda":"compute"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := rs.Compress(st, pkt, Up, Context{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 8+16+4+32+32 {
		t.Fatalf("compressed to %d bits", c.Len())
	}
	back, _, err := rs.Decompress(st, c, Up, Context{})
	if err != nil || !bytes.Equal(back, pkt) {
		t.Fatalf("%x %v\nwant %x", back, err, pkt)
	}
	// The rule in RFC 9363 form, with our module's IPv4 and SCTP identities.
	y, err := rs.MarshalYANG()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseYANG(y)
	if err != nil {
		t.Fatal(err)
	}
	if c2, _, err := again.Compress(st, pkt, Up, Context{}); err != nil || !c2.Equal(c) {
		t.Fatalf("after YANG: %s %v", c2, err)
	}
	for _, bad := range []string{"udp/sctp", "ipv4/sctp/coap", "ipv6/ipv4", "sctp"} {
		if _, err := ParseStack(bad); err == nil {
			t.Fatalf("stack %q accepted", bad)
		}
	}
	for _, good := range []string{"ipv4/udp/coap", "ipv4/udp/wrapper", "ipv6/sctp", "ipv4"} {
		if _, err := ParseStack(good); err != nil {
			t.Fatalf("stack %q: %v", good, err)
		}
	}
}
