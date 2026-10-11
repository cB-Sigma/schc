// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package coreconf_test

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/schc"
	"github.com/cB-Sigma/schc/coreconf"
)

// Covers: SIG-IPE-7312
//
// Rules with the IPv4 and SCTP fields of cb-sigma-schc revision 2026-10-12,
// and an implicit rule (rule-id-length 0), go to CBOR and back unchanged.
func TestIPv4SCTPAndImplicitRoundTrip(t *testing.T) {
	for _, js := range []string{
		`{"rules":[{"ruleId":4,"ruleIdLength":4,"fields":[
		 {"fid":"ipv4.version","fl":4,"tv":4,"mo":"equal","cda":"not-sent"},
		 {"fid":"ipv4.ds","fl":6,"tv":0,"mo":"equal","cda":"not-sent"},
		 {"fid":"ipv4.ecn","fl":2,"mo":"ignore","cda":"value-sent"},
		 {"fid":"ipv4.ttl","fl":8,"tv":64,"mo":"equal","cda":"not-sent"},
		 {"fid":"ipv4.devAddress","fl":32,"tv":"192.0.2.1","mo":"equal","cda":"not-sent"},
		 {"fid":"ipv4.options","var":"bytes","mo":"ignore","cda":"value-sent"},
		 {"fid":"sctp.verificationTag","fl":32,"mo":"ignore","cda":"value-sent"},
		 {"fid":"sctp.checksum","fl":32,"mo":"ignore","cda":"compute"}]}]}`,
		`{"rules":[{"ruleId":0,"implicit":true,"kind":"no-compression"}]}`,
	} {
		rs, err := schc.ParseRuleSet([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		b, err := coreconf.Marshal(rs, nil)
		if err != nil {
			t.Fatal(err)
		}
		back, skipped, err := coreconf.Unmarshal(b, nil, schc.YANGOptions{})
		if err != nil || len(skipped) > 0 {
			t.Fatalf("%v %v", err, skipped)
		}
		j1, _ := rs.MarshalYANG()
		j2, _ := back.MarshalYANG()
		if !bytes.Equal(j1, j2) {
			t.Fatalf("changed:\n%s\n---\n%s", j1, j2)
		}
	}
}
