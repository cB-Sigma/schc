// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/schc"
)

// sigfoxLayouts are the three uplink ACK-on-Error header layouts of RFC
// 9442, with a RuleID of each as the reference names it (a bit string).
var sigfoxLayouts = []struct {
	name   string
	layout schc.SigfoxHeader
	id     uint32
	bits   string
	max    int // bytes
}{
	{"single-byte", schc.SigfoxSingleByte, 2, "010", 300},
	{"two-byte-1", schc.SigfoxTwoByte1, 0b111001, "111001", 480},
	{"two-byte-2", schc.SigfoxTwoByte2, 0b11111101, "11111101", 2400},
}

func sigfoxRule(t *testing.T, id uint32, h schc.SigfoxHeader) *schc.Rule {
	t.Helper()
	r, err := schc.SigfoxUplinkRule(id, h)
	if err != nil {
		t.Fatal(err)
	}
	rs := &schc.RuleSet{Rules: []schc.Rule{r}}
	if err := rs.Compile(); err != nil {
		t.Fatal(err)
	}
	return &rs.Rules[0]
}

func lineArg(t *testing.T, lines []string, prefix string) []string {
	t.Helper()
	var out []string
	for _, l := range lines {
		if s, ok := strings.CutPrefix(l, prefix+" "); ok {
			out = append(out, s)
		}
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-7303
//
// The reference fragments a packet; our receiver reassembles it, across
// lost fragments: each of our Compound ACKs, padded to the 8-byte
// downlink, is read by the reference's parser, and the fragments it reads
// as missing are sent again, then the All-1, as its sender does.
func TestSigfoxFromReference(t *testing.T) {
	p := startImage(t, sigfoxRI)
	for _, l := range sigfoxLayouts {
		r := sigfoxRule(t, l.id, l.layout)
		ws := r.Fragmentation.WindowSize
		for seed := int64(0); seed < 12; seed++ {
			rnd := rand.New(rand.NewSource(seed))
			size := 1 + rnd.Intn(l.max)
			if seed < 3 {
				size = []int{l.max, 10, 11}[seed]
			}
			pkt := make([]byte, size)
			rnd.Read(pkt)
			t.Run(fmt.Sprintf("%s-%d", l.name, size), func(t *testing.T) {
				frags := lineArg(t, p.do(map[string]any{"cmd": "fragment", "rule": l.bits, "hex": hex.EncodeToString(pkt)}), "fragment")
				byPlace := map[string]string{}
				var all1 string
				for _, f := range frags {
					m, err := schc.DecodeAtReceiver(r, schc.BytesOf(unhex(t, f)), 8)
					if err != nil {
						t.Fatalf("their fragment %s: %v", f, err)
					}
					if m.Kind == schc.MsgAll1 {
						all1 = f
						continue
					}
					byPlace[fmt.Sprintf("%d/%d", m.W, ws-1-int(m.FCN))] = f
				}
				now := time.Unix(1_000_000, 0)
				rv := schc.NewReceiver(r, 8, 0, 3000, now)
				queue := frags
				for round := 0; round < 30 && !rv.Done(); round++ {
					var acks []schc.Bits
					for i, f := range queue {
						if round == 0 && seed%2 == 1 && i != len(queue)-1 && rnd.Intn(4) == 0 {
							continue // lost on the first pass
						}
						out, err := rv.Receive(now, schc.BytesOf(unhex(t, f)))
						if err != nil {
							t.Fatal(err)
						}
						acks = append(acks, out...)
					}
					queue = nil
					for _, a := range acks {
						frame, err := schc.SigfoxDownlinkPayload(a)
						if err != nil {
							t.Fatal(err)
						}
						parsed := lineArg(t, p.do(map[string]any{"cmd": "parse-ack", "hex": hex.EncodeToString(frame)}), "parsed")
						if len(parsed) != 1 {
							t.Fatalf("the reference did not read our ACK %x", frame)
						}
						f := strings.Fields(parsed[0])
						if f[0] == "c=1" {
							continue
						}
						for _, wb := range f[1:] {
							w, bm, _ := strings.Cut(wb, ":")
							win := 0
							for _, c := range w {
								win = win*2 + int(c-'0')
							}
							for pos, bit := range bm {
								if bit == '0' {
									if frag, ok := byPlace[fmt.Sprintf("%d/%d", win, pos)]; ok {
										queue = append(queue, frag)
									}
								}
							}
						}
						queue = append(queue, all1)
					}
				}
				got, ok := rv.Packet()
				if !ok || !bytes.Equal(got.Bytes(), pkt) {
					t.Fatalf("reassembled %v (%v)", ok, rv.Err())
				}
			})
		}
	}
}

// Covers: SIG-IPE-7303
//
// Our sender fragments a packet; the reference's receiver reassembles it,
// its Compound ACKs read by our sender, across lost fragments.
func TestSigfoxToReference(t *testing.T) {
	p := startImage(t, sigfoxRI)
	for _, l := range sigfoxLayouts[:1] { // see TestSigfoxReferenceTwoByteParse
		r := sigfoxRule(t, l.id, l.layout)
		for seed := int64(0); seed < 12; seed++ {
			rnd := rand.New(rand.NewSource(seed + 100))
			size := 1 + rnd.Intn(l.max)
			if seed < 3 {
				size = []int{l.max, 10, 11}[seed]
			}
			pkt := make([]byte, size)
			rnd.Read(pkt)
			t.Run(fmt.Sprintf("%s-%d", l.name, size), func(t *testing.T) {
				p.do(map[string]any{"cmd": "reset"})
				now := time.Unix(1_000_000, 0)
				s, err := schc.NewSender(r, 8, 0, schc.BytesOf(pkt))
				if err != nil {
					t.Fatal(err)
				}
				queue, err := s.Start(now, schc.SigfoxUplinkMTU)
				if err != nil {
					t.Fatal(err)
				}
				var delivered []string
				first, sent0 := true, len(queue)
				for round := 0; round < 40 && !s.Done(); round++ {
					for i := 0; i < len(queue); i++ {
						m := queue[i]
						if first && seed%2 == 1 && i < sent0-1 && rnd.Intn(4) == 0 {
							continue // lost on the first pass
						}
						lines := p.do(map[string]any{"cmd": "recv", "hex": hex.EncodeToString(m.Bytes()), "time": now.Unix()})
						delivered = append(delivered, lineArg(t, lines, "packet")...)
						for _, a := range lineArg(t, lines, "ack") {
							more, err := s.Receive(now, schc.BytesOf(unhex(t, a)), schc.SigfoxUplinkMTU)
							if err != nil {
								t.Fatal(err)
							}
							queue = append(queue, more...)
						}
					}
					first = false
					queue = nil
					if !s.Done() {
						now = now.Add(time.Minute)
						if queue, err = s.Tick(now.Add(r.Fragmentation.Retransmission.D())); err != nil {
							t.Fatal(err)
						}
					}
				}
				if s.Err() != nil || len(delivered) != 1 || delivered[0] != hex.EncodeToString(pkt) {
					t.Fatalf("sender %v; the reference delivered %q", s.Err(), delivered)
				}
			})
		}
	}
}
