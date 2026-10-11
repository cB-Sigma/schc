// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/schc"
)

// Fragmentation rules, in openschc's format and ours, beside the CoAP
// compression rules: the fragmented SCHC Packets are IPv6/UDP/CoAP
// packets compressed by rule 5 (openschc sends a packet it cannot parse
// with no RuleID, and after reassembly delivers only packets of a
// compression rule).
func peerFragRules(mode, dir string) []any {
	prof := map[string]any{"dtagSize": 2, "FCNSize": 3, "L2WordSize": 8}
	id := 1
	if mode == "AckOnError" {
		prof["WSize"] = 3
		prof["tileSize"] = 32
		prof["lastTileInAll1"] = false
		id = 3
	}
	if mode == "NoAck" {
		prof["FCNSize"] = 1
	}
	return append(append([]any(nil), peerCoAPRules...),
		map[string]any{"RuleID": id, "RuleIDLength": 3, "Fragmentation": map[string]any{
			"FRMode": mode, "FRDirection": dir, "FRModeProfile": prof}})
}

func ourFragRules(t *testing.T, mode, dir string) (*schc.RuleSet, *schc.Rule) {
	t.Helper()
	var frag string
	switch mode {
	case "NoAck":
		frag = fmt.Sprintf(`{"ruleId":1,"ruleIdLength":3,"fragmentation":{"mode":"no-ack","direction":%q,"dtagSize":2,"fcnSize":1}}`, dir)
	case "AckOnError":
		frag = fmt.Sprintf(`{"ruleId":3,"ruleIdLength":3,"fragmentation":{"mode":"ack-on-error","direction":%q,"dtagSize":2,"wSize":3,"fcnSize":3,"tileBits":32,"lastTile":"regular","penultimateShort":true,"retransmissionTimer":"100s","inactivityTimer":"1000s"}}`, dir)
	}
	rs := mustRules(t, strings.TrimSuffix(strings.TrimSpace(ourCoAPRules), "]}")+","+frag+"]}")
	return rs, &rs.Rules[len(rs.Rules)-1]
}

func payloadOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

// coapPacket is the uplink CoAP request, or the downlink response, with a
// payload of n bytes.
func coapPacket(t *testing.T, dir schc.Direction, n int) []byte {
	t.Helper()
	if dir == schc.Up {
		coap, _ := hex.DecodeString("41011003" + "ab" + "b474656d70" + "026131" + "ff")
		return ipv6UDP(t, schc.Up, "2001:db8::1", "2001:db8:2::7", 5683, 5683, 0x12345, 64, append(coap, payloadOf(n)...))
	}
	coap, _ := hex.DecodeString("61451003" + "ab" + "c13c" + "ff")
	return ipv6UDP(t, schc.Down, "2001:db8::1", "2001:db8:2::7", 5683, 5683, 1, 63, append(coap, payloadOf(n)...))
}

var coapStack, _ = schc.ParseStack("ipv6/udp/coap")

// fromPeer has openschc fragment raw and our receiver reassemble it;
// drop lists the peer's messages (by order sent, from 0) the link loses.
// It returns the packet we rebuilt.
func fromPeer(t *testing.T, p *peer, rs *schc.RuleSet, rule *schc.Rule, raw []byte, drop map[int]bool) []byte {
	t.Helper()
	now := time.Unix(1_000_000, 0)
	queue := tx(t, p.do(map[string]any{"cmd": "send", "hex": hex.EncodeToString(raw)}))
	var rv *schc.Receiver
	sent := 0
	for step := 0; step < 500; step++ {
		if rv != nil && rv.Done() {
			break
		}
		if len(queue) == 0 {
			// Nothing in flight: let both clocks run to the next timer.
			now = now.Add(160 * time.Second)
			queue = tx(t, p.do(map[string]any{"cmd": "tick", "seconds": 160}))
			if rv != nil {
				for _, m := range rv.Tick(now) {
					queue = append(queue, tx(t, p.do(map[string]any{"cmd": "recv", "hex": hex.EncodeToString(m.Bytes())}))...)
				}
			}
			if len(queue) == 0 {
				t.Fatalf("the exchange stalled after %d peer messages", sent)
			}
			continue
		}
		m := queue[0]
		queue = queue[1:]
		idx := sent
		sent++
		if drop[idx] {
			t.Logf("lost peer message %d: %x", idx, m)
			continue
		}
		msg := schc.BytesOf(m)
		if rv == nil {
			fm, err := schc.DecodeAtReceiver(rule, msg, 8)
			if err != nil {
				t.Fatalf("peer message %x: %v", m, err)
			}
			rv = schc.NewReceiver(rule, 8, fm.DTag, 0, now)
		}
		out, err := rv.Receive(now, msg)
		if err != nil {
			t.Fatalf("our receiver, peer message %d %x: %v", idx, m, err)
		}
		for _, a := range out {
			queue = append(queue, tx(t, p.do(map[string]any{"cmd": "recv", "hex": hex.EncodeToString(a.Bytes())}))...)
		}
	}
	if rv == nil {
		t.Fatal("the peer sent nothing")
	}
	pkt, ok := rv.Packet()
	if !ok {
		t.Fatalf("reassembly did not finish: %v", rv.Err())
	}
	got, r, err := rs.Decompress(coapStack, pkt, rule.Fragmentation.Direction, schc.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 5 {
		t.Fatalf("decompressed with rule %d", r.ID)
	}
	return got
}

// toPeer has our sender fragment raw (compressed by the no-compression
// rule) and openschc reassemble it; it returns the packets openschc
// delivered.
func toPeer(t *testing.T, p *peer, rs *schc.RuleSet, rule *schc.Rule, raw []byte, mtu int, drop map[int]bool) [][]byte {
	t.Helper()
	now := time.Unix(1_000_000, 0)
	pkt, r, err := rs.Compress(coapStack, raw, rule.Fragmentation.Direction, schc.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 5 {
		t.Fatalf("compressed with rule %d", r.ID)
	}
	s, err := schc.NewSender(rule, 8, 0, pkt)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := s.Start(now, mtu)
	if err != nil {
		t.Fatal(err)
	}
	var delivered [][]byte
	sent := 0
	for step := 0; step < 500; step++ {
		if len(queue) == 0 {
			if s.Done() {
				break
			}
			if s.Deadline().IsZero() {
				t.Fatalf("our sender waits with no timer after %d messages", sent)
			}
			dt := s.Deadline().Sub(now)
			now = s.Deadline()
			lines := p.do(map[string]any{"cmd": "tick", "seconds": dt.Seconds()})
			delivered = append(delivered, packets(t, lines)...)
			more, err := s.Tick(now)
			if err != nil && !s.Done() {
				t.Fatal(err)
			}
			queue = append(queue, more...)
			for _, a := range tx(t, lines) {
				m, err := s.Receive(now, schc.BytesOf(a), mtu)
				if err != nil {
					t.Fatalf("our sender, peer message %x: %v", a, err)
				}
				queue = append(queue, m...)
			}
			if len(queue) == 0 && !s.Done() {
				t.Fatalf("the exchange stalled after %d messages", sent)
			}
			continue
		}
		m := queue[0]
		queue = queue[1:]
		idx := sent
		sent++
		if drop[idx] {
			t.Logf("lost our message %d: %s", idx, m)
			continue
		}
		lines := p.do(map[string]any{"cmd": "recv", "hex": hex.EncodeToString(m.Bytes())})
		delivered = append(delivered, packets(t, lines)...)
		for _, a := range tx(t, lines) {
			more, err := s.Receive(now, schc.BytesOf(a), mtu)
			if err != nil {
				t.Fatalf("our sender, peer message %x: %v", a, err)
			}
			queue = append(queue, more...)
		}
	}
	if s.Err() != nil {
		t.Fatalf("our sender: %v", s.Err())
	}
	return delivered
}

// TestAckOnErrorOpenschcLoneTileResend records openschc's resend of a lone
// missing tile: the fragment it sends is an All-1 (FCN all ones, with an
// RCS) in the window of the tile, so the tile number is lost and our
// receiver, rightly, cannot complete. The test passes while openschc
// behaves so; when it starts to pass the reassembly, the exchange is
// checked in full and this note can go.
func TestAckOnErrorOpenschcLoneTileResend(t *testing.T) {
	p := startPeer(t)
	p.setup("device", peerFragRules("AckOnError", "UP"), 120)
	rs, rule := ourFragRules(t, "AckOnError", "up")
	raw := coapPacket(t, schc.Up, 101)
	queue := tx(t, p.do(map[string]any{"cmd": "send", "hex": hex.EncodeToString(raw)}))
	// Message 2 starts with tile 0 of window 0, the only tile of window 0
	// it carries (the next are of window 1).
	m, err := schc.DecodeAtReceiver(rule, schc.BytesOf(queue[2]), 8)
	if err != nil || m.W != 0 || m.FCN != 0 {
		t.Fatalf("message 2 does not start with tile 0 of window 0: %+v, %v", m, err)
	}
	now := time.Unix(1_000_000, 0)
	rv := schc.NewReceiver(rule, 8, 0, 0, now)
	var acks []schc.Bits
	for i, b := range queue {
		if i == 2 {
			continue
		}
		out, err := rv.Receive(now, schc.BytesOf(b))
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, out...)
	}
	if len(acks) != 1 {
		t.Fatalf("our receiver sent %d ACKs after the All-1, want 1", len(acks))
	}
	resent := tx(t, p.do(map[string]any{"cmd": "recv", "hex": hex.EncodeToString(acks[0].Bytes())}))
	if len(resent) != 1 {
		t.Fatalf("openschc resent %d messages, want 1", len(resent))
	}
	r, err := schc.DecodeAtReceiver(rule, schc.BytesOf(resent[0]), 8)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != schc.MsgAll1 || r.W != 0 {
		_, _ = rv.Receive(now, schc.BytesOf(resent[0]))
		if pkt, ok := rv.Packet(); ok {
			if got, _, err := rs.Decompress(coapStack, pkt, schc.Up, schc.Context{}); err == nil && bytes.Equal(got, raw) {
				t.Log("openschc now resends a lone tile in a regular fragment: move this case into TestAckOnErrorFromOpenschc")
				return
			}
		}
		t.Fatalf("openschc's resend changed (%s, W %d) and the packet did not come through", r.Kind, r.W)
	}
	t.Logf("openschc resent tile 0 of window 0 as an All-1 of window 0: %x", resent[0])
}
