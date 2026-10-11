// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Field is one header field a parser labelled (RFC 8724 7.1: rules do not
// say how fields are found; a parser alongside SCHC labels them).
type Field struct {
	FID   string
	Pos   int // occurrence, from 1
	Value Bits
}

// Packet is a parsed packet: its labelled header fields in header order
// and the payload that follows them.
type Packet struct {
	Fields  []Field
	Payload []byte
}

// Field IDs our parsers label. IPv6 and UDP follow RFC 8724 clause 10,
// naming addresses and ports by role (Dev, App) rather than position
// (10.7, 10.9). The wrapper fields are the IEC 62056-4-7 wrapper header,
// also named by role: the meter's wPort is devWPort.
const (
	FIPv6Version       = "ipv6.version"
	FIPv6TrafficClass  = "ipv6.trafficClass"
	FIPv6FlowLabel     = "ipv6.flowLabel"
	FIPv6PayloadLength = "ipv6.payloadLength"
	FIPv6NextHeader    = "ipv6.nextHeader"
	FIPv6HopLimit      = "ipv6.hopLimit"
	FIPv6DevPrefix     = "ipv6.devPrefix"
	FIPv6DevIID        = "ipv6.devIID"
	FIPv6AppPrefix     = "ipv6.appPrefix"
	FIPv6AppIID        = "ipv6.appIID"
	FUDPDevPort        = "udp.devPort"
	FUDPAppPort        = "udp.appPort"
	FUDPLength         = "udp.length"
	FUDPChecksum       = "udp.checksum"
	FWrapperVersion    = "wrapper.version"
	FWrapperDevWPort   = "wrapper.devWPort"
	FWrapperAppWPort   = "wrapper.appWPort"
	FWrapperLength     = "wrapper.length"
	// ICMPv6 (RFC 4443) for the ping of RFC 8724's OAM use, as openschc
	// labels it; identifier and sequence only in Echo Request and Reply.
	FICMPv6Type       = "icmpv6.type"
	FICMPv6Code       = "icmpv6.code"
	FICMPv6Checksum   = "icmpv6.checksum"
	FICMPv6Identifier = "icmpv6.identifier"
	FICMPv6Sequence   = "icmpv6.sequence"
)

// fieldLengths are the fixed lengths of the fields our parsers label.
var fieldLengths = map[string]int{
	FIPv6Version: 4, FIPv6TrafficClass: 8, FIPv6FlowLabel: 20, FIPv6PayloadLength: 16,
	FIPv6NextHeader: 8, FIPv6HopLimit: 8, FIPv6DevPrefix: 64, FIPv6DevIID: 64, FIPv6AppPrefix: 64, FIPv6AppIID: 64,
	FUDPDevPort: 16, FUDPAppPort: 16, FUDPLength: 16, FUDPChecksum: 16,
	FWrapperVersion: 16, FWrapperDevWPort: 16, FWrapperAppWPort: 16, FWrapperLength: 16,
	FICMPv6Type: 8, FICMPv6Code: 8, FICMPv6Checksum: 16, FICMPv6Identifier: 16, FICMPv6Sequence: 16,
}

// computed are the fields a compute CDA can rebuild.
var computed = map[string]bool{FIPv6PayloadLength: true, FUDPLength: true, FUDPChecksum: true, FWrapperLength: true, FICMPv6Checksum: true}

// Subfields a rule may describe in place of their field (RFC 9363 derives
// their identities from the field's): the IPv6 Traffic Class as DSCP and
// ECN (RFC 2474, RFC 3168), the CoAP Code as class and detail (RFC 7252 3).
// The parsers label the whole field; a rule that names a subfield gets the
// field cut into its subfields before matching, and decompression joins
// them again.
const (
	FIPv6DS  = "ipv6.ds"  // first 6 bits of the Traffic Class
	FIPv6ECN = "ipv6.ecn" // last 2 bits
)

type subfield struct {
	fid      string
	from, to int
}

var subfields = map[string][]subfield{
	FIPv6TrafficClass: {{FIPv6DS, 0, 6}, {FIPv6ECN, 6, 8}},
	FCoAPCode:         {{FCoAPCodeClass, 0, 3}, {FCoAPCodeDetail, 3, 8}},
}

// subfieldOf maps a subfield to its field.
var subfieldOf = func() map[string]string {
	m := map[string]string{}
	for parent, subs := range subfields {
		for _, s := range subs {
			m[s.fid] = parent
		}
	}
	return m
}()

// Stack is the protocol layers a packet's header is made of, outermost
// first: any of ipv6, udp, and then one of coap, coap-inner and wrapper,
// in that order, or ipv6/icmpv6. An empty stack has no header: the whole
// packet is payload.
//
// coap is a whole CoAP message (RFC 7252 3), alone or over ipv6/udp in one
// rule (RFC 8824 figures 1 and 2); coap-inner is an OSCORE plaintext (RFC
// 8613 5.3: the code, the Class E options and the payload), for the inner
// rules of RFC 8824 7.2, whose result is encrypted and carried in an outer
// CoAP message that the outer rules compress with coap or ipv6/udp/coap.
type Stack []string

// ParseStack reads "ipv6/udp/coap", "coap", "coap-inner",
// "ipv6/udp/wrapper", "wrapper", "ipv6/udp", "ipv6/icmpv6", "none" or "".
func ParseStack(s string) (Stack, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "none" || s == "raw" {
		return nil, nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ',' || r == '+' || r == ' ' })
	order := map[string]int{"ipv6": 0, "udp": 1, "icmpv6": 1, "wrapper": 2, "coap": 2, "coap-inner": 2}
	last := -1
	for _, p := range parts {
		o, ok := order[p]
		if !ok {
			return nil, fmt.Errorf("schc: layer %q is not ipv6, udp, icmpv6, coap, coap-inner or wrapper", p)
		}
		if o == 2 && last == 2 {
			return nil, fmt.Errorf("schc: layers %q have more than one of coap, coap-inner and wrapper", s)
		}
		if o <= last {
			return nil, fmt.Errorf("schc: layers %q are not in the order ipv6, udp, then coap, coap-inner or wrapper", s)
		}
		last = o
	}
	st := Stack(parts)
	if st.has("udp") && !st.has("ipv6") {
		return nil, errors.New("schc: udp is compressed under ipv6 only")
	}
	if st.has("coap-inner") && len(st) > 1 {
		return nil, errors.New("schc: coap-inner (an OSCORE plaintext) is compressed alone")
	}
	if st.has("icmpv6") && (!st.has("ipv6") || len(st) != 2) {
		return nil, errors.New("schc: icmpv6 is compressed as ipv6/icmpv6")
	}
	return st, nil
}

func (st Stack) has(l string) bool {
	for _, x := range st {
		if x == l {
			return true
		}
	}
	return false
}

// String is the stack as ParseStack reads it.
func (st Stack) String() string {
	if len(st) == 0 {
		return "none"
	}
	return strings.Join(st, "/")
}

var errNotStack = errors.New("schc: the packet is not of this header stack")

// Parse labels a packet's header fields. dir tells the Dev end from the
// App end (source is the Dev going up).
func (st Stack) Parse(raw []byte, dir Direction) (Packet, error) {
	var p Packet
	count := map[string]int{}
	add := func(fid string, v Bits) {
		count[fid]++
		p.Fields = append(p.Fields, Field{FID: fid, Pos: count[fid], Value: v})
	}
	b := raw
	var ipLen int
	if st.has("ipv6") {
		if len(b) < 40 || b[0]>>4 != 6 {
			return Packet{}, errNotStack
		}
		h := BytesOf(b[:40])
		add(FIPv6Version, h.Slice(0, 4))
		add(FIPv6TrafficClass, h.Slice(4, 12))
		add(FIPv6FlowLabel, h.Slice(12, 32))
		ipLen = int(binary.BigEndian.Uint16(b[4:6]))
		if ipLen != len(b)-40 {
			return Packet{}, errNotStack
		}
		add(FIPv6PayloadLength, h.Slice(32, 48))
		add(FIPv6NextHeader, h.Slice(48, 56))
		add(FIPv6HopLimit, h.Slice(56, 64))
		src, dst := h.Slice(64, 192), h.Slice(192, 320)
		dev, app := src, dst
		if dir == Down {
			dev, app = dst, src
		}
		// Header order: source first.
		if dir == Down {
			add(FIPv6AppPrefix, app.Slice(0, 64))
			add(FIPv6AppIID, app.Slice(64, 128))
			add(FIPv6DevPrefix, dev.Slice(0, 64))
			add(FIPv6DevIID, dev.Slice(64, 128))
		} else {
			add(FIPv6DevPrefix, dev.Slice(0, 64))
			add(FIPv6DevIID, dev.Slice(64, 128))
			add(FIPv6AppPrefix, app.Slice(0, 64))
			add(FIPv6AppIID, app.Slice(64, 128))
		}
		if (st.has("udp") && b[6] != 17) || (st.has("icmpv6") && b[6] != 58) {
			return Packet{}, errNotStack
		}
		b = b[40:]
	}
	if st.has("icmpv6") {
		if len(b) < 4 {
			return Packet{}, errNotStack
		}
		add(FICMPv6Type, BytesOf(b[0:1]).Clone())
		add(FICMPv6Code, BytesOf(b[1:2]).Clone())
		add(FICMPv6Checksum, BytesOf(b[2:4]).Clone())
		b = b[4:]
		if isEcho(raw[40]) {
			if len(b) < 4 {
				return Packet{}, errNotStack
			}
			add(FICMPv6Identifier, BytesOf(b[0:2]).Clone())
			add(FICMPv6Sequence, BytesOf(b[2:4]).Clone())
			b = b[4:]
		}
	}
	if st.has("udp") {
		if len(b) < 8 {
			return Packet{}, errNotStack
		}
		srcP, dstP := BytesOf(b[0:2]).Clone(), BytesOf(b[2:4]).Clone()
		if dir == Down {
			add(FUDPAppPort, srcP)
			add(FUDPDevPort, dstP)
		} else {
			add(FUDPDevPort, srcP)
			add(FUDPAppPort, dstP)
		}
		// The length is labelled only when it agrees with the IPv6 payload
		// length (RFC 8724 10.10); a packet that disagrees matches no rule
		// that has it.
		if int(binary.BigEndian.Uint16(b[4:6])) == ipLen {
			add(FUDPLength, BytesOf(b[4:6]).Clone())
		}
		add(FUDPChecksum, BytesOf(b[6:8]).Clone())
		b = b[8:]
	}
	if st.has("wrapper") {
		if len(b) < 8 {
			return Packet{}, errNotStack
		}
		srcW, dstW := BytesOf(b[2:4]).Clone(), BytesOf(b[4:6]).Clone()
		add(FWrapperVersion, BytesOf(b[0:2]).Clone())
		if dir == Down {
			add(FWrapperAppWPort, srcW)
			add(FWrapperDevWPort, dstW)
		} else {
			add(FWrapperDevWPort, srcW)
			add(FWrapperAppWPort, dstW)
		}
		if int(binary.BigEndian.Uint16(b[6:8])) == len(b)-8 {
			add(FWrapperLength, BytesOf(b[6:8]).Clone())
		}
		b = b[8:]
	}
	if st.has("coap") || st.has("coap-inner") {
		pl, err := parseCoAP(b, st.has("coap-inner"), add)
		if err != nil {
			return Packet{}, err
		}
		p.Payload = pl
		return p, nil
	}
	p.Payload = append([]byte(nil), b...)
	return p, nil
}

// Build writes a packet from its field values (by FID; fields missing
// from vals are computed) and payload. It is the inverse of Parse for
// headers whose fields appear once; use BuildFields for CoAP messages with
// repeated options.
func (st Stack) Build(vals map[string]Bits, payload []byte, dir Direction) ([]byte, error) {
	fields := make([]Field, 0, len(vals))
	for fid, v := range vals {
		fields = append(fields, Field{FID: fid, Pos: 1, Value: v})
	}
	return st.BuildFields(fields, payload, dir)
}

// BuildFields writes a packet from its labelled fields (fields missing are
// computed) and payload. It is the inverse of Parse: CoAP options are
// written in option-number order, repeated ones by position.
func (st Stack) BuildFields(fields []Field, payload []byte, dir Direction) ([]byte, error) {
	vals := map[string]Bits{}
	for _, f := range fields {
		if !isCoAPFID(f.FID) {
			vals[f.FID] = f.Value
		}
	}
	if st.has("coap") || st.has("coap-inner") {
		b, err := buildCoAP(fields, payload, st.has("coap-inner"))
		if err != nil {
			return nil, err
		}
		payload = b
	}
	get := func(fid string) (Bits, error) {
		v, ok := vals[fid]
		if !ok {
			return Bits{}, fmt.Errorf("schc: field %s has no value", fid)
		}
		if v.Len() != fieldLengths[fid] {
			return Bits{}, fmt.Errorf("schc: field %s has %d bits, not %d", fid, v.Len(), fieldLengths[fid])
		}
		return v, nil
	}
	body := payload
	if st.has("wrapper") {
		var h Bits
		for _, fid := range []string{FWrapperVersion, FWrapperDevWPort, FWrapperAppWPort} {
			if _, err := get(fid); err != nil {
				return nil, err
			}
		}
		h.Append(vals[FWrapperVersion])
		if dir == Down {
			h.Append(vals[FWrapperAppWPort])
			h.Append(vals[FWrapperDevWPort])
		} else {
			h.Append(vals[FWrapperDevWPort])
			h.Append(vals[FWrapperAppWPort])
		}
		if v, ok := vals[FWrapperLength]; ok {
			h.Append(v)
		} else {
			if len(body) > 0xFFFF {
				return nil, errors.New("schc: the wrapper payload is over 65535 bytes")
			}
			h.AppendUint(uint64(len(body)), 16)
		}
		body = append(h.Bytes(), body...)
	}
	var udp []byte
	if st.has("udp") {
		for _, fid := range []string{FUDPDevPort, FUDPAppPort} {
			if _, err := get(fid); err != nil {
				return nil, err
			}
		}
		udp = make([]byte, 8, 8+len(body))
		sp, dp := vals[FUDPDevPort].Bytes(), vals[FUDPAppPort].Bytes()
		if dir == Down {
			sp, dp = dp, sp
		}
		copy(udp[0:2], sp)
		copy(udp[2:4], dp)
		if v, ok := vals[FUDPLength]; ok {
			copy(udp[4:6], v.Bytes())
		} else {
			binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(body)))
		}
		udp = append(udp, body...)
		body = udp
	}
	var icmp []byte
	if st.has("icmpv6") {
		for _, fid := range []string{FICMPv6Type, FICMPv6Code} {
			if _, err := get(fid); err != nil {
				return nil, err
			}
		}
		icmp = append(vals[FICMPv6Type].Bytes(), vals[FICMPv6Code].Bytes()...)
		icmp = append(icmp, 0, 0)
		if v, ok := vals[FICMPv6Checksum]; ok {
			copy(icmp[2:4], v.Bytes())
		}
		if isEcho(icmp[0]) {
			for _, fid := range []string{FICMPv6Identifier, FICMPv6Sequence} {
				v, err := get(fid)
				if err != nil {
					return nil, err
				}
				icmp = append(icmp, v.Bytes()...)
			}
		}
		icmp = append(icmp, body...)
		body = icmp
	}
	if st.has("ipv6") {
		ip := make([]byte, 40)
		var h Bits
		for _, fid := range []string{FIPv6Version, FIPv6TrafficClass, FIPv6FlowLabel} {
			v, err := get(fid)
			if err != nil {
				return nil, err
			}
			h.Append(v)
		}
		if v, ok := vals[FIPv6PayloadLength]; ok {
			h.Append(v)
		} else {
			h.AppendUint(uint64(len(body)), 16)
		}
		for _, fid := range []string{FIPv6NextHeader, FIPv6HopLimit} {
			v, err := get(fid)
			if err != nil {
				return nil, err
			}
			h.Append(v)
		}
		order := []string{FIPv6DevPrefix, FIPv6DevIID, FIPv6AppPrefix, FIPv6AppIID}
		if dir == Down {
			order = []string{FIPv6AppPrefix, FIPv6AppIID, FIPv6DevPrefix, FIPv6DevIID}
		}
		for _, fid := range order {
			v, err := get(fid)
			if err != nil {
				return nil, err
			}
			h.Append(v)
		}
		copy(ip, h.Bytes())
		if udp != nil {
			if _, ok := vals[FUDPChecksum]; ok {
				copy(udp[6:8], vals[FUDPChecksum].Bytes())
			} else {
				binary.BigEndian.PutUint16(udp[6:8], udpChecksum(ip[8:24], ip[24:40], udp))
			}
		}
		if icmp != nil {
			if _, ok := vals[FICMPv6Checksum]; !ok {
				binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(ip[8:24], ip[24:40], icmp))
			}
		}
		body = append(ip, body...)
	} else if udp != nil || icmp != nil {
		return nil, errors.New("schc: udp and icmpv6 need ipv6")
	}
	return body, nil
}

// isEcho reports whether an ICMPv6 type is Echo Request or Echo Reply
// (RFC 4443 4.1, 4.2), whose identifier and sequence are labelled.
func isEcho(t byte) bool { return t == 128 || t == 129 }

// icmpv6Checksum is the ICMPv6 checksum (RFC 4443 2.3) over the IPv6
// pseudo-header with next header 58 and the message with its checksum
// field taken as zero.
func icmpv6Checksum(src, dst, msg []byte) uint16 {
	return l4Checksum(src, dst, msg, 58)
}

// udpChecksum is the UDP checksum over the IPv6 pseudo-header (RFC 8200
// 8.1) with the checksum field taken as zero; zero is sent as FFFFh.
func udpChecksum(src, dst, udp []byte) uint16 {
	c := l4Checksum(src, dst, udp, 17)
	if c == 0 {
		c = 0xFFFF
	}
	return c
}

// l4Checksum is the one's complement checksum of RFC 8200 8.1 over the
// pseudo-header and msg, whose checksum is at bytes 6-7 (UDP) or 2-3
// (ICMPv6) and is skipped.
func l4Checksum(src, dst, msg []byte, nh byte) uint16 {
	at := 6
	if nh == 58 {
		at = 2
	}
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	var l [8]byte
	binary.BigEndian.PutUint32(l[0:4], uint32(len(msg)))
	l[7] = nh
	add(l[:])
	add(msg[0:at])
	add(msg[at+2:])
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// computeValue is what a compute CDA would rebuild for fid in a packet
// (Build with the field left out), for the compressor to check that
// eliding it loses nothing.
func (st Stack) computeValue(fid string, p Packet, dir Direction) (Bits, bool) {
	var fields []Field
	for _, f := range p.Fields {
		if !computed[f.FID] {
			fields = append(fields, f)
		}
	}
	raw, err := st.BuildFields(fields, p.Payload, dir)
	if err != nil {
		return Bits{}, false
	}
	q, err := st.Parse(raw, dir)
	if err != nil {
		return Bits{}, false
	}
	for _, f := range q.Fields {
		if f.FID == fid {
			return f.Value, true
		}
	}
	return Bits{}, false
}
