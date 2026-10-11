// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package coreconf_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/cB-Sigma/schc"
	"github.com/cB-Sigma/schc/coreconf"
)

const coapRules = `{"rules":[{"ruleId":1,"fields":[
 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.type","fl":2,"di":"up","tv":0,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.type","fl":2,"di":"dw","tv":2,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.code","fl":8,"di":"up","tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.code","fl":8,"di":"dw","tv":[69,132],"mo":"match-mapping","cda":"mapping-sent"},
 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(12)","cda":"lsb"},
 {"fid":"coap.token","var":"tkl","tv":"80","mo":"msb(5)","cda":"lsb"},
 {"fid":"coap.uriPath","var":"bytes","di":"up","tv":"temperature","mo":"equal","cda":"not-sent"}]},
 {"ruleId":4,"fields":[{"fid":"coap.echo","var":"bits","di":"up","mo":"ignore","cda":"value-sent"}]},
 {"ruleId":2,"fragmentation":{"mode":"ack-on-error","direction":"up","wSize":2,"fcnSize":6,"windowSize":63,"tileBytes":10,"rcs":"crc16-hdlc"}},
 {"ruleId":5,"fragmentation":{"mode":"ack-on-error","direction":"dw","wSize":2,"fcnSize":3,"tileBits":16,"compoundAck":true,"lastBitmapUncompressed":true}},
 {"ruleId":3,"fields":[{"fid":"wrapper.version","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
  {"fid":"wrapper.devWPort","fl":16,"mo":"ignore","cda":"value-sent"},
  {"fid":"wrapper.appWPort","fl":16,"mo":"ignore","cda":"value-sent"},
  {"fid":"wrapper.length","fl":16,"mo":"ignore","cda":"compute"}]},
 {"ruleId":255,"kind":"no-compression"}]}`

// The smallest rule set pins the encoding: {5095: {1: [{33: 8, 34: 0,
// 35: 5090}]}} — schc, rule (delta 1), rule-id-length, -value and
// -nature (deltas 33 to 35), nature-no-compression as a SID.
func TestEncodingOfANoCompressionRule(t *testing.T) {
	rs, err := schc.ParseRuleSet([]byte(`{"rules":[{"ruleId":0,"kind":"no-compression"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := coreconf.Marshal(rs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(b), "a11913e7a10181a31821081822001823"+"1913e2"; got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A field length function is an identity in a union: tag 45 around its
// SID (fl-variable is 5077).
func TestFieldLengthUnionTag(t *testing.T) {
	rs, err := schc.ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[{"fid":"coap.uriPath","var":"bytes","mo":"ignore","cda":"value-sent"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := coreconf.Marshal(rs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte{0xd8, 0x2d, 0x19, 0x13, 0xd5}) {
		t.Fatalf("no tag 45 with SID 5077 in %x", b)
	}
}

// Rule sets go to CBOR and back unchanged: the RFC 9363 JSON before and
// after is the same, and the CBOR is deterministic.
func TestRoundTrip(t *testing.T) {
	rs, err := schc.ParseRuleSet([]byte(coapRules))
	if err != nil {
		t.Fatal(err)
	}
	b1, err := coreconf.Marshal(rs, nil)
	if err != nil {
		t.Fatal(err)
	}
	back, skipped, err := coreconf.Unmarshal(b1, nil, schc.YANGOptions{})
	if err != nil || len(skipped) > 0 {
		t.Fatalf("%v %v", err, skipped)
	}
	j1, _ := rs.MarshalYANG()
	j2, _ := back.MarshalYANG()
	if !bytes.Equal(j1, j2) {
		t.Fatalf("changed:\n%s\n---\n%s", j1, j2)
	}
	b2, err := coreconf.Marshal(back, nil)
	if err != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("not deterministic: %v", err)
	}
	t.Logf("CBOR %d bytes, JSON %d", len(b1), len(j1))
	// The rules work after the trip.
	st, _ := schc.ParseStack("coap")
	get, _ := hex.DecodeString("4101000182bb74656d7065726174757265")
	m, r, err := back.Compress(st, get, schc.Up, schc.Context{})
	if err != nil || r.ID != 1 || m.Len() != 15 {
		t.Fatalf("rule %v, %d bits, %v", r, m.Len(), err)
	}
}

// openschc's example rule set converts to CBOR and back.
func TestOpenSCHCExample(t *testing.T) {
	js, err := os.ReadFile("../testdata/openschc/schc.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := coreconf.FromJSON(js, nil)
	if err != nil {
		t.Fatal(err)
	}
	opt := schc.YANGOptions{TileBits: 16}
	a, _, err := schc.ParseYANGWith(js, opt)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := coreconf.Unmarshal(b, nil, opt)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := a.MarshalYANG()
	jc, _ := c.MarshalYANG()
	if !bytes.Equal(ja, jc) {
		t.Fatal("the rules changed through CBOR")
	}
}

// Identities may come as names (RFC 9254 6.10.2); unknown SIDs and
// malformed input are errors, never panics.
func TestDecodeRefusals(t *testing.T) {
	// {5095: {1: [{33: 8, 34: 0, 35: "ietf-schc:nature-no-compression"}]}}
	named, _ := hex.DecodeString("a11913e7a10181a3182108182200182378" + "1f" + hex.EncodeToString([]byte("ietf-schc:nature-no-compression")))
	rs, _, err := coreconf.Unmarshal(named, nil, schc.YANGOptions{})
	if err != nil || len(rs.Rules) != 1 || rs.Rules[0].Kind != schc.KindNoCompression {
		t.Fatalf("identity by name: %v", err)
	}
	for _, h := range []string{
		"", "a1", "a11913e7a10181a3182108182200182319ffff", "a1190001a0", "a11913e7a1188881a0",
		"a11913e7a10181a318210818220018231913e2ff", "a11913e7a10181a31821381822001823" + "1913e2",
	} {
		b, _ := hex.DecodeString(h)
		if _, _, err := coreconf.Unmarshal(b, nil, schc.YANGOptions{}); err == nil {
			t.Errorf("%s was accepted", h)
		}
	}
}

// A SID file in the RFC 9595 form adds to a table.
func TestLoadSIDFile(t *testing.T) {
	s := coreconf.Default().Clone()
	err := s.LoadSIDFile([]byte(`{"ietf-sid-file:sid-file":{"module-name":"example-schc","item":[{"namespace":"identity","identifier":"rcs-x","sid":"61000"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LoadSIDFile([]byte(`{"item":[]}`)); err == nil || !strings.Contains(err.Error(), "module-name") {
		t.Fatalf("a file without module-name: %v", err)
	}
}

func FuzzUnmarshal(f *testing.F) {
	rs, _ := schc.ParseRuleSet([]byte(coapRules))
	b, _ := coreconf.Marshal(rs, nil)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = coreconf.Unmarshal(b, nil, schc.YANGOptions{SkipBadRules: true})
	})
}
