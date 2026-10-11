// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc_test

import (
	"bytes"
	"fmt"
	"time"

	"github.com/cB-Sigma/schc"
)

// Compress an IEC 62056-4-7 wrapper header (8 bytes) to a few bits with a
// rule that elides the constant fields and computes the length, then
// rebuild the frame on the other side from the same rules.
func ExampleRuleSet_Compress() {
	rules, err := schc.ParseRuleSet([]byte(`{"rules":[
	 {"ruleId":1,"fields":[
	  {"fid":"wrapper.version","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
	  {"fid":"wrapper.devWPort","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
	  {"fid":"wrapper.appWPort","fl":16,"tv":[16,32,48,64,80,96,102,1],"mo":"match-mapping","cda":"mapping-sent"},
	  {"fid":"wrapper.length","fl":16,"mo":"ignore","cda":"compute"}]},
	 {"ruleId":22,"kind":"no-compression"}]}`))
	if err != nil {
		panic(err)
	}
	stack, _ := schc.ParseStack("wrapper")
	apdu := []byte{0xC0, 0x01, 0xC1, 0x00, 0x03}
	frame := append([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, byte(len(apdu))}, apdu...)

	msg, rule, err := rules.Compress(stack, frame, schc.Up, schc.Context{})
	if err != nil {
		panic(err)
	}
	fmt.Println("rule", rule.ID, "header and payload in", msg.Len(), "bits instead of", 8*len(frame))

	msg.Pad(8)
	back, _, err := rules.Decompress(stack, msg, schc.Up, schc.Context{})
	fmt.Println(bytes.Equal(back, frame), err)
	// Output:
	// rule 1 header and payload in 51 bits instead of 104
	// true <nil>
}

// Fragment a 300-byte packet for LoRaWAN with the RFC 9011 uplink rule
// (ACK-on-Error) and reassemble it. Sender and Receiver are state machines
// without I/O: the caller carries their messages and drives their timers.
func ExampleNewSender() {
	rules := schc.RuleSet{Rules: []schc.Rule{schc.LoRaWANUplinkRule(schc.FPortUp, 10, false)}}
	if err := rules.Compile(); err != nil {
		panic(err)
	}
	rule := &rules.Rules[0]
	packet := schc.BytesOf(bytes.Repeat([]byte("sensor data "), 25))

	now := time.Now()
	sender, err := schc.NewSender(rule, 8, 0, packet)
	if err != nil {
		panic(err)
	}
	receiver := schc.NewReceiver(rule, 8, 0, 0, now)
	frags, err := sender.Start(now, 8+8*51) // FPort plus 51 bytes of LoRaWAN payload
	if err != nil {
		panic(err)
	}
	var acks []schc.Bits
	for _, f := range frags {
		lf, _ := schc.ToLoRaWAN(f) // what goes on the radio: FPort and payload
		a, err := receiver.Receive(now, schc.FromLoRaWAN(lf.FPort, lf.Payload))
		if err != nil {
			panic(err)
		}
		acks = append(acks, a...)
	}
	for _, a := range acks {
		if _, err := sender.Receive(now, a, 8+8*51); err != nil {
			panic(err)
		}
	}
	got, ok := receiver.Packet()
	same := ok && bytes.Equal(got.Slice(0, packet.Len()).Bytes(), packet.Bytes())
	fmt.Printf("%d fragments, reassembled %v, sender done %v\n", len(frags), same, sender.Done())
	// Output:
	// 7 fragments, reassembled true, sender done true
}
