// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Covers: SIG-IPE-7311
//
// Implicit rules (RuleID length 0): nothing of the RuleID is sent, for a
// compression rule and a fragmentation rule; such a rule is alone in its
// rule set; RFC 9363's rule-id-length 0 reads and writes as one.
func TestImplicitRules(t *testing.T) {
	rs, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":0,"implicit":true,"fields":[
	 {"fid":"udp.devPort","fl":16,"tv":5683,"mo":"equal","cda":"not-sent"},
	 {"fid":"udp.appPort","fl":16,"mo":"ignore","cda":"value-sent"},
	 {"fid":"udp.length","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"udp.checksum","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv6.version","fl":4,"tv":6,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.trafficClass","fl":8,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.flowLabel","fl":20,"tv":0,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.payloadLength","fl":16,"mo":"ignore","cda":"compute"},
	 {"fid":"ipv6.nextHeader","fl":8,"tv":17,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.hopLimit","fl":8,"tv":64,"mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.devPrefix","fl":64,"tv":"fe80::/64","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.devIID","fl":64,"tv":"::1","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.appPrefix","fl":64,"tv":"fe80::/64","mo":"equal","cda":"not-sent"},
	 {"fid":"ipv6.appIID","fl":64,"tv":"::2","mo":"equal","cda":"not-sent"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := ParseStack("ipv6/udp")
	vals := map[string]Bits{FIPv6Version: Uint(6, 4), FIPv6TrafficClass: Uint(0, 8), FIPv6FlowLabel: Uint(0, 20),
		FIPv6NextHeader: Uint(17, 8), FIPv6HopLimit: Uint(64, 8), FUDPDevPort: Uint(5683, 16), FUDPAppPort: Uint(40000, 16)}
	vals[FIPv6DevPrefix], _ = IPv6Value("fe80::/64")
	vals[FIPv6AppPrefix], _ = IPv6Value("fe80::/64")
	vals[FIPv6DevIID], _ = IPv6Value("::1")
	vals[FIPv6AppIID], _ = IPv6Value("::2")
	pkt, err := st.Build(vals, []byte("hi"), Up)
	if err != nil {
		t.Fatal(err)
	}
	c, r, err := rs.Compress(st, pkt, Up, Context{})
	if err != nil || !r.Implicit {
		t.Fatalf("%v %v", r, err)
	}
	if c.Len() != 16+16 || c.UintAt(0, 16) != 40000 {
		t.Fatalf("compressed to %s, want the app port then the payload", c)
	}
	back, _, err := rs.Decompress(st, c, Up, Context{})
	if err != nil || !bytes.Equal(back, pkt) {
		t.Fatalf("%x %v", back, err)
	}
	y, err := rs.MarshalYANG()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(y), " ", ""), `"rule-id-length":0`) {
		t.Fatalf("YANG %s", y)
	}
	again, err := ParseYANG(y)
	if err != nil || !again.Rules[0].Implicit {
		t.Fatalf("%v %v", again, err)
	}

	// A fragmentation rule without RuleID.
	fr := testRule(t, `{"ruleId":0,"implicit":true,"fragmentation":{"mode":"ack-on-error","dtagSize":0,"wSize":2,"fcnSize":3,"tileBytes":4,"retransmissionTimer":"1m","inactivityTimer":"1h"}}`)
	p := packetOf(700, 3)
	s, err := NewSender(fr, 8, 0, p)
	if err != nil {
		t.Fatal(err)
	}
	rv := NewReceiver(fr, 8, 0, 0, time.Now())
	w := &wire{t: t, s: s, r: rv, now: time.Now(), mtu: 64, dropUp: func(n int, _ *FragMsg) bool { return n == 2 }}
	w.run()
	if got, ok := rv.Packet(); !ok || !bytes.Equal(got.Slice(0, 700).Bytes(), p.Bytes()) {
		t.Fatalf("implicit fragmentation: %v", rv.Err())
	}

	// An implicit rule is alone in its set, and has no RuleID to give.
	if _, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":0,"implicit":true,"kind":"no-compression"},{"ruleId":1,"kind":"no-compression"}]}`)); err == nil {
		t.Fatal("an implicit rule beside another was accepted")
	}
	if _, err := ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"implicit":true,"kind":"no-compression"}]}`)); err == nil {
		t.Fatal("an implicit rule with a RuleID was accepted")
	}
}
