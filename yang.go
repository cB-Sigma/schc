// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// Rules in the RFC 9363 data model.
//
// MarshalYANG and ParseYANG write and read a rule set as instance data of
// the ietf-schc YANG module (RFC 9363) in the JSON encoding of RFC 7951,
// the form openschc and other tools exchange. The coreconf subpackage
// carries the same data in CBOR with SIDs (RFC 9254).
//
// Choices where RFC 9363 leaves room, made as openschc makes them:
//
//   - a target value of a fixed-length field is its value as a big-endian
//     number in the fewest whole bytes that hold the field (a 4-bit 6 is
//     06h, a 16-bit 5683 is 1633h); a variable-length value is its bytes;
//   - the MSB length is matching-operator-value index 0, a big-endian
//     number;
//   - entries keep their order in the JSON array, which is the order of
//     the residue (RFC 8724 7.2), though the YANG list is keyed.
//
// Field IDs, field-length functions and RCS algorithms that ietf-schc
// does not define are written as identities of our module cb-sigma-schc
// (yang/cb-sigma-schc@2026-10-12.yang in this repository, from the ietf-schc
// bases): the IEC 62056-4-7 wrapper fields, the IPv4 and SCTP fields, the CoAP options registered
// after RFC 9363 (Hop-Limit, Q-Block1/2, EDHOC, Echo, Request-Tag, the
// two OCF options), variable lengths counted in bits and the RCS
// algorithms besides CRC32. ICMPv6 fields use the identities of the
// ietf-schc-oam draft module, as openschc does. A CoAP option known only
// by number (coap.option.N) has no identity, and an entry that groups
// several instances (RFC 8824 5.3) no form: such rules cannot be written.

// YANGModule is the module name of RFC 9363 and YANGExtModule ours.
const (
	YANGModule    = "ietf-schc"
	YANGExtModule = "cb-sigma-schc"
)

// yangFIDs maps our field IDs to their identities ("module:identity").
var yangFIDs = map[string]string{
	FIPv6Version: "ietf-schc:fid-ipv6-version", FIPv6TrafficClass: "ietf-schc:fid-ipv6-trafficclass",
	FIPv6DS: "ietf-schc:fid-ipv6-trafficclass-ds", FIPv6ECN: "ietf-schc:fid-ipv6-trafficclass-ecn",
	FIPv6FlowLabel: "ietf-schc:fid-ipv6-flowlabel", FIPv6PayloadLength: "ietf-schc:fid-ipv6-payload-length",
	FIPv6NextHeader: "ietf-schc:fid-ipv6-nextheader", FIPv6HopLimit: "ietf-schc:fid-ipv6-hoplimit",
	FIPv6DevPrefix: "ietf-schc:fid-ipv6-devprefix", FIPv6DevIID: "ietf-schc:fid-ipv6-deviid",
	FIPv6AppPrefix: "ietf-schc:fid-ipv6-appprefix", FIPv6AppIID: "ietf-schc:fid-ipv6-appiid",
	FUDPDevPort: "ietf-schc:fid-udp-dev-port", FUDPAppPort: "ietf-schc:fid-udp-app-port",
	FUDPLength: "ietf-schc:fid-udp-length", FUDPChecksum: "ietf-schc:fid-udp-checksum",
	FCoAPVersion: "ietf-schc:fid-coap-version", FCoAPType: "ietf-schc:fid-coap-type",
	FCoAPTKL: "ietf-schc:fid-coap-tkl", FCoAPCode: "ietf-schc:fid-coap-code",
	FCoAPCodeClass: "ietf-schc:fid-coap-code-class", FCoAPCodeDetail: "ietf-schc:fid-coap-code-detail",
	FCoAPMID: "ietf-schc:fid-coap-mid", FCoAPToken: "ietf-schc:fid-coap-token",
	FCoAPIfMatch: "ietf-schc:fid-coap-option-if-match", FCoAPUriHost: "ietf-schc:fid-coap-option-uri-host",
	FCoAPETag: "ietf-schc:fid-coap-option-etag", FCoAPIfNoneMatch: "ietf-schc:fid-coap-option-if-none-match",
	FCoAPObserve: "ietf-schc:fid-coap-option-observe", FCoAPUriPort: "ietf-schc:fid-coap-option-uri-port",
	FCoAPLocationPath: "ietf-schc:fid-coap-option-location-path", FCoAPUriPath: "ietf-schc:fid-coap-option-uri-path",
	FCoAPContentFormat: "ietf-schc:fid-coap-option-content-format", FCoAPMaxAge: "ietf-schc:fid-coap-option-max-age",
	FCoAPUriQuery: "ietf-schc:fid-coap-option-uri-query", FCoAPAccept: "ietf-schc:fid-coap-option-accept",
	FCoAPLocationQuery: "ietf-schc:fid-coap-option-location-query", FCoAPBlock2: "ietf-schc:fid-coap-option-block2",
	FCoAPBlock1: "ietf-schc:fid-coap-option-block1", FCoAPSize2: "ietf-schc:fid-coap-option-size2",
	FCoAPProxyURI: "ietf-schc:fid-coap-option-proxy-uri", FCoAPProxyScheme: "ietf-schc:fid-coap-option-proxy-scheme",
	FCoAPSize1: "ietf-schc:fid-coap-option-size1", FCoAPNoResponse: "ietf-schc:fid-coap-option-no-response",
	FOSCOREFlags: "ietf-schc:fid-coap-option-oscore-flags", FOSCOREPIV: "ietf-schc:fid-coap-option-oscore-piv",
	FOSCOREKID: "ietf-schc:fid-coap-option-oscore-kid", FOSCOREKIDCtx: "ietf-schc:fid-coap-option-oscore-kidctx",

	FCoAPHopLimit: "cb-sigma-schc:fid-coap-option-hop-limit", FCoAPQBlock1: "cb-sigma-schc:fid-coap-option-q-block1",
	FCoAPQBlock2: "cb-sigma-schc:fid-coap-option-q-block2", FCoAPEDHOC: "cb-sigma-schc:fid-coap-option-edhoc",
	FCoAPEcho: "cb-sigma-schc:fid-coap-option-echo", FCoAPRequestTag: "cb-sigma-schc:fid-coap-option-request-tag",
	FCoAPOCFAcceptCFVer: "cb-sigma-schc:fid-coap-option-ocf-accept-content-format-version",
	FCoAPOCFCFVer:       "cb-sigma-schc:fid-coap-option-ocf-content-format-version",
	FWrapperVersion:     "cb-sigma-schc:fid-wrapper-version", FWrapperDevWPort: "cb-sigma-schc:fid-wrapper-dev-wport",
	FWrapperAppWPort: "cb-sigma-schc:fid-wrapper-app-wport", FWrapperLength: "cb-sigma-schc:fid-wrapper-length",
	FIPv4Version: "cb-sigma-schc:fid-ipv4-version", FIPv4IHL: "cb-sigma-schc:fid-ipv4-ihl",
	FIPv4ToS: "cb-sigma-schc:fid-ipv4-tos", FIPv4DS: "cb-sigma-schc:fid-ipv4-tos-ds", FIPv4ECN: "cb-sigma-schc:fid-ipv4-tos-ecn",
	FIPv4TotalLength: "cb-sigma-schc:fid-ipv4-total-length", FIPv4Identification: "cb-sigma-schc:fid-ipv4-identification",
	FIPv4Flags: "cb-sigma-schc:fid-ipv4-flags", FIPv4FragmentOffset: "cb-sigma-schc:fid-ipv4-fragment-offset",
	FIPv4TTL: "cb-sigma-schc:fid-ipv4-ttl", FIPv4Protocol: "cb-sigma-schc:fid-ipv4-protocol",
	FIPv4Checksum: "cb-sigma-schc:fid-ipv4-checksum", FIPv4DevAddress: "cb-sigma-schc:fid-ipv4-dev-address",
	FIPv4AppAddress: "cb-sigma-schc:fid-ipv4-app-address", FIPv4Options: "cb-sigma-schc:fid-ipv4-options",
	FSCTPDevPort: "cb-sigma-schc:fid-sctp-dev-port", FSCTPAppPort: "cb-sigma-schc:fid-sctp-app-port",
	FSCTPVerificationTag: "cb-sigma-schc:fid-sctp-verification-tag", FSCTPChecksum: "cb-sigma-schc:fid-sctp-checksum",

	// The ICMPv6 identities of the ietf-schc-oam draft module, as openschc
	// writes them.
	FICMPv6Type: "ietf-schc-oam:fid-icmpv6-type", FICMPv6Code: "ietf-schc-oam:fid-icmpv6-code",
	FICMPv6Checksum: "ietf-schc-oam:fid-icmpv6-checksum", FICMPv6Identifier: "ietf-schc-oam:fid-icmpv6-identifier",
	FICMPv6Sequence: "ietf-schc-oam:fid-icmpv6-sequence",
}

var yangFIDsBack = invert(yangFIDs)

// YANG identities of the other enumerations, ours to theirs.
var (
	yangDI   = map[Direction]string{Up: "ietf-schc:di-up", Down: "ietf-schc:di-down", Bi: "ietf-schc:di-bidirectional"}
	yangMO   = map[string]string{MOEqual: "ietf-schc:mo-equal", MOIgnore: "ietf-schc:mo-ignore", MOMSB: "ietf-schc:mo-msb", MOMatchMapping: "ietf-schc:mo-match-mapping"}
	yangCDA  = map[string]string{CDANotSent: "ietf-schc:cda-not-sent", CDAValueSent: "ietf-schc:cda-value-sent", CDAMappingSent: "ietf-schc:cda-mapping-sent", CDALSB: "ietf-schc:cda-lsb", CDACompute: "ietf-schc:cda-compute", CDADevIID: "ietf-schc:cda-deviid", CDAAppIID: "ietf-schc:cda-appiid"}
	yangVar  = map[string]string{"bytes": "ietf-schc:fl-variable", VarTKL: "ietf-schc:fl-token-length", "bits": "cb-sigma-schc:fl-variable-bits"}
	yangKind = map[string]string{KindCompression: "ietf-schc:nature-compression", KindNoCompression: "ietf-schc:nature-no-compression", KindFragmentation: "ietf-schc:nature-fragmentation"}
	yangMode = map[string]string{NoAck: "ietf-schc:fragmentation-mode-no-ack", AckAlways: "ietf-schc:fragmentation-mode-ack-always", AckOnError: "ietf-schc:fragmentation-mode-ack-on-error"}
	yangLast = map[string]string{LastTileRegular: "ietf-schc:all-1-data-no", LastTileAll1: "ietf-schc:all-1-data-yes", LastTileEither: "ietf-schc:all-1-data-sender-choice"}
	yangRCS  = map[string]string{RCSCRC32: "ietf-schc:rcs-crc32", "crc32c": "cb-sigma-schc:rcs-crc32c", "crc16-hdlc": "cb-sigma-schc:rcs-crc16-hdlc", "crc8": "cb-sigma-schc:rcs-crc8"}
)

const (
	yangBitmapCompound = "ietf-schc-compound-ack:bitmap-compound-ack"
	yangBitmapRFC8724  = "ietf-schc-compound-ack:bitmap-RFC8724"
	yangAckAfterAll0   = "ietf-schc:ack-behavior-after-all-0"
	yangAckAfterAll1   = "ietf-schc:ack-behavior-after-all-1"
	yangAckByL2        = "ietf-schc:ack-behavior-by-layer2"
)

func invert[K comparable](m map[K]string) map[string]K {
	out := make(map[string]K, len(m))
	for k, v := range m {
		out[v] = k
	}
	return out
}

// YANG instance data, as RFC 7951 encodes ietf-schc.
type (
	// YANGDocument is the top of RFC 9363 instance data in JSON.
	YANGDocument struct {
		SCHC YANGSCHC `json:"ietf-schc:schc"`
	}
	// YANGSCHC is the schc container.
	YANGSCHC struct {
		Rule []YANGRule `json:"rule"`
	}
	// YANGRule is one rule of any nature.
	YANGRule struct {
		RuleIDValue  *uint32 `json:"rule-id-value,omitempty"`
		RuleIDLength *uint8  `json:"rule-id-length,omitempty"`
		RuleNature   string  `json:"rule-nature,omitempty"`

		Entry []YANGEntry `json:"entry,omitempty"`

		FragmentationMode    string     `json:"fragmentation-mode,omitempty"`
		L2WordSize           *uint8     `json:"l2-word-size,omitempty"`
		Direction            string     `json:"direction,omitempty"`
		DTagSize             *uint8     `json:"dtag-size,omitempty"`
		WSize                *uint8     `json:"w-size,omitempty"`
		FCNSize              *uint8     `json:"fcn-size,omitempty"`
		RCSAlgorithm         string     `json:"rcs-algorithm,omitempty"`
		MaximumPacketSize    *uint16    `json:"maximum-packet-size,omitempty"`
		WindowSize           *uint16    `json:"window-size,omitempty"`
		MaxInterleavedFrames *uint8     `json:"max-interleaved-frames,omitempty"`
		InactivityTimer      *YANGTimer `json:"inactivity-timer,omitempty"`
		RetransmissionTimer  *YANGTimer `json:"retransmission-timer,omitempty"`
		MaxAckRequests       *uint8     `json:"max-ack-requests,omitempty"`
		TileSize             *uint8     `json:"tile-size,omitempty"`
		TileInAll1           string     `json:"tile-in-all-1,omitempty"`
		AckBehavior          string     `json:"ack-behavior,omitempty"`

		// The RFC 9441 augment (module ietf-schc-compound-ack).
		BitmapFormat          string `json:"ietf-schc-compound-ack:bitmap-format,omitempty"`
		LastBitmapCompression *bool  `json:"ietf-schc-compound-ack:last-bitmap-compression,omitempty"`
	}
	// YANGTimer is a timer in ticks of 2^TicksDuration microseconds.
	YANGTimer struct {
		TicksDuration *uint8  `json:"ticks-duration,omitempty"`
		TicksNumbers  *uint16 `json:"ticks-numbers,omitempty"`
	}
	// YANGEntry is one field descriptor of a compression rule. FieldLength
	// is a number or an identity.
	YANGEntry struct {
		FieldID               string          `json:"field-id,omitempty"`
		FieldLength           json.RawMessage `json:"field-length,omitempty"`
		FieldPosition         *uint8          `json:"field-position,omitempty"`
		DirectionIndicator    string          `json:"direction-indicator,omitempty"`
		TargetValue           []YANGValue     `json:"target-value,omitempty"`
		MatchingOperator      string          `json:"matching-operator,omitempty"`
		MatchingOperatorValue []YANGValue     `json:"matching-operator-value,omitempty"`
		CompDecompAction      string          `json:"comp-decomp-action,omitempty"`
		CompDecompActionValue []YANGValue     `json:"comp-decomp-action-value,omitempty"`
	}
	// YANGValue is a tv-struct: an index and a binary value (base64 in
	// JSON).
	YANGValue struct {
		Index uint16 `json:"index"`
		Value []byte `json:"value"`
	}
)

// MarshalYANG writes the rule set as RFC 9363 instance data in RFC 7951
// JSON. The rule set must be compiled (ParseRuleSet does it).
func (rs *RuleSet) MarshalYANG() ([]byte, error) {
	doc, err := rs.YANG()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}

// YANG converts the rule set to the RFC 9363 tree.
func (rs *RuleSet) YANG() (*YANGDocument, error) {
	doc := &YANGDocument{}
	for i := range rs.Rules {
		yr, err := rs.Rules[i].yang(rs)
		if err != nil {
			return nil, fmt.Errorf("schc rule %d: %w", rs.Rules[i].ID, err)
		}
		doc.SCHC.Rule = append(doc.SCHC.Rule, yr)
	}
	return doc, nil
}

func ptr[T any](v T) *T { return &v }

func (r *Rule) yang(rs *RuleSet) (YANGRule, error) {
	if r.IDLength == 0 && !r.Implicit {
		return YANGRule{}, errors.New("the rule set is not compiled")
	}
	yr := YANGRule{RuleIDValue: ptr(r.ID), RuleIDLength: ptr(uint8(r.IDLength)), RuleNature: yangKind[r.Kind]}
	switch r.Kind {
	case KindCompression:
		for i := range r.Fields {
			e, err := r.Fields[i].yang()
			if err != nil {
				return YANGRule{}, fmt.Errorf("field %s: %w", r.Fields[i].FID, err)
			}
			yr.Entry = append(yr.Entry, e)
		}
	case KindFragmentation:
		p := r.Fragmentation
		yr.FragmentationMode = yangMode[p.Mode]
		if rs.L2Word != 8 {
			yr.L2WordSize = ptr(uint8(rs.L2Word))
		}
		switch p.Direction {
		case Up, Down:
			yr.Direction = yangDI[p.Direction]
		default:
			return YANGRule{}, errors.New("RFC 9363 needs a fragmentation rule's direction, up or dw")
		}
		yr.DTagSize, yr.FCNSize = ptr(uint8(p.DTagSize)), ptr(uint8(p.FCNSize))
		if p.Mode != NoAck {
			yr.WSize = ptr(uint8(p.WSize))
			yr.WindowSize = ptr(uint16(p.WindowSize))
			yr.MaxAckRequests = ptr(uint8(min(p.MaxAckRequests, 255)))
			t, err := yangTimer(p.Retransmission.D())
			if err != nil {
				return YANGRule{}, fmt.Errorf("retransmission timer: %w", err)
			}
			yr.RetransmissionTimer = t
		}
		rcs, ok := yangRCS[p.RCS]
		if !ok {
			return YANGRule{}, fmt.Errorf("RCS %s has no identity", p.RCS)
		}
		yr.RCSAlgorithm = rcs
		if rs.MaxPacketSize > 0 && rs.MaxPacketSize <= 0xFFFF {
			yr.MaximumPacketSize = ptr(uint16(rs.MaxPacketSize))
		}
		t, err := yangTimer(p.Inactivity.D())
		if err != nil {
			return YANGRule{}, fmt.Errorf("inactivity timer: %w", err)
		}
		yr.InactivityTimer = t
		if p.HeaderPadded || p.BitmapUncompressed || p.NoAckReq || p.FCNCountdown || p.FullFragments || p.AckMaxBits > 0 {
			return YANGRule{}, errors.New("RFC 9363 has no parameters for the profile options (headerPadded, bitmapUncompressed, noAckReq, fcnCountdown, fullFragments, ackMaxBits)")
		}
		if p.Mode == AckOnError {
			if p.TileSize > 255 {
				return YANGRule{}, fmt.Errorf("a tile of %d bits is over the 255 of RFC 9363's tile-size", p.TileSize)
			}
			if p.PenultimateShort {
				return YANGRule{}, errors.New("RFC 9363 has no penultimate-tile parameter")
			}
			if p.TileSize > 0 {
				yr.TileSize = ptr(uint8(p.TileSize))
			}
			yr.TileInAll1 = yangLast[p.LastTile]
			yr.AckBehavior = yangAckAfterAll1
			if p.AckEveryWindow {
				yr.AckBehavior = yangAckAfterAll0
			}
			if p.CompoundAck {
				yr.BitmapFormat = yangBitmapCompound
				yr.LastBitmapCompression = ptr(!p.LastBitmapUncompressed)
			}
		}
	}
	return yr, nil
}

// yangTimer is d in the coarsest tick (2^20 µs or more) that counts it
// exactly in 16 bits, else the finest that holds it.
func yangTimer(d time.Duration) (*YANGTimer, error) {
	us := d.Microseconds()
	if us <= 0 {
		return &YANGTimer{TicksDuration: ptr(uint8(20)), TicksNumbers: ptr(uint16(0))}, nil
	}
	// The finest tick that counts d in 16 bits, exactly when it can: one
	// form for each duration, so a rule set reads back as it was written.
	for td := 0; td < 63; td++ {
		tick := int64(1) << uint(td)
		if us%tick == 0 && us/tick <= 0xFFFF {
			return &YANGTimer{TicksDuration: ptr(uint8(td)), TicksNumbers: ptr(uint16(us / tick))}, nil
		}
		if us/tick > 0xFFFF {
			continue
		}
		break
	}
	for td := 0; td < 63; td++ {
		tick := int64(1) << uint(td)
		if (us+tick-1)/tick <= 0xFFFF {
			return &YANGTimer{TicksDuration: ptr(uint8(td)), TicksNumbers: ptr(uint16((us + tick - 1) / tick))}, nil
		}
	}
	return nil, fmt.Errorf("%v does not fit", d)
}

func (t *YANGTimer) duration() time.Duration {
	if t == nil || t.TicksNumbers == nil {
		return 0
	}
	td := uint8(20)
	if t.TicksDuration != nil {
		td = *t.TicksDuration
	}
	if td > 40 {
		td = 40 // beyond a year per tick; bounded so the product fits
	}
	return time.Duration(int64(*t.TicksNumbers)<<td) * time.Microsecond
}

func (f *FieldDescriptor) yang() (YANGEntry, error) {
	fid, ok := yangFIDs[f.FID]
	if !ok {
		return YANGEntry{}, errors.New("no YANG identity for this field")
	}
	e := YANGEntry{FieldID: fid, FieldPosition: ptr(uint8(f.fp)), DirectionIndicator: yangDI[f.DI],
		MatchingOperator: yangMO[f.MO], CompDecompAction: yangCDA[f.CDA]}
	if f.fp > 255 {
		return YANGEntry{}, fmt.Errorf("field position %d is over 255", f.fp)
	}
	if f.group > 1 {
		return YANGEntry{}, errors.New("RFC 9363 has no form for an entry that groups several instances (RFC 8824 5.3)")
	}
	if f.Var == "" {
		e.FieldLength, _ = json.Marshal(f.FL)
		if f.FL > 255 {
			return YANGEntry{}, fmt.Errorf("a field length of %d bits is over RFC 9363's uint8", f.FL)
		}
	} else {
		e.FieldLength, _ = json.Marshal(yangVar[f.Var])
	}
	for i, tv := range f.tv {
		e.TargetValue = append(e.TargetValue, YANGValue{Index: uint16(i), Value: yangBytes(tv, f.Var == "")})
	}
	if f.MO == MOMSB {
		e.MatchingOperatorValue = []YANGValue{{Index: 0, Value: new(big.Int).SetInt64(int64(f.MOArg)).Bytes()}}
		if f.MOArg == 0 {
			e.MatchingOperatorValue[0].Value = []byte{0}
		}
	}
	return e, nil
}

// yangBytes is a target value as RFC 9363 binary: a fixed-length field's
// value as a big-endian number in whole bytes, a variable one's bytes.
func yangBytes(v Bits, fixed bool) []byte {
	if !fixed {
		return v.Bytes()
	}
	n := (v.Len() + 7) / 8
	out := make([]byte, n)
	for i := 0; i < v.Len(); i++ {
		bit := v.Len() - 1 - i // from the least significant
		if v.Bit(i) == 1 {
			out[n-1-bit/8] |= 1 << uint(bit%8)
		}
	}
	return out
}

// YANGOptions say how ParseYANG treats what this module cannot use.
type YANGOptions struct {
	// SkipBadRules leaves out the rules that cannot be read (an unknown
	// field ID, a missing mandatory leaf, a value that does not fit)
	// instead of failing; ParseYANGWith reports each one.
	SkipBadRules bool
	// TileBits is a tile size for ACK-on-Error rules without tile-size,
	// for peers that expect one. 0 keeps RFC 9363's meaning: tiles fill
	// each fragment (FragParams.TileSize 0).
	TileBits int
}

// ParseYANG reads RFC 9363 instance data in RFC 7951 JSON and compiles it.
func ParseYANG(b []byte) (*RuleSet, error) {
	rs, _, err := ParseYANGWith(b, YANGOptions{})
	return rs, err
}

// ParseYANGWith is ParseYANG with options; skipped lists the rules left
// out under SkipBadRules and why.
func ParseYANGWith(b []byte, opt YANGOptions) (rs *RuleSet, skipped []error, err error) {
	var doc YANGDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("schc yang: %w", err)
	}
	return FromYANG(&doc, opt)
}

// FromYANG builds and compiles a rule set from the RFC 9363 tree.
func FromYANG(doc *YANGDocument, opt YANGOptions) (*RuleSet, []error, error) {
	rs := &RuleSet{}
	var skipped []error
	for i := range doc.SCHC.Rule {
		yr := &doc.SCHC.Rule[i]
		r, l2, mps, err := yr.rule(opt)
		if err == nil {
			// Compile the rule alone to find its errors here.
			one := RuleSet{L2Word: l2, Rules: []Rule{r}}
			err = one.Compile()
		}
		if err == nil && l2 != 0 {
			if rs.L2Word != 0 && rs.L2Word != l2 {
				err = fmt.Errorf("l2-word-size %d differs from another rule's %d", l2, rs.L2Word)
			} else {
				rs.L2Word = l2
			}
		}
		if err != nil {
			id := "?"
			if yr.RuleIDValue != nil {
				id = fmt.Sprint(*yr.RuleIDValue)
			}
			err = fmt.Errorf("schc yang rule %s: %w", id, err)
			if !opt.SkipBadRules {
				return nil, nil, err
			}
			skipped = append(skipped, err)
			continue
		}
		rs.MaxPacketSize = max(rs.MaxPacketSize, mps)
		rs.Rules = append(rs.Rules, r)
	}
	if err := rs.Compile(); err != nil {
		return nil, skipped, err
	}
	return rs, skipped, nil
}

// identity strips the module prefix if it is ietf-schc or ours; the value
// must be one of known.
func identity[K comparable](s string, known map[string]K, what string) (K, error) {
	var zero K
	if !strings.Contains(s, ":") {
		s = YANGModule + ":" + s
	}
	v, ok := known[s]
	if !ok {
		if alt := YANGExtModule + ":" + s[strings.Index(s, ":")+1:]; s != alt {
			if v, ok = known[alt]; ok {
				return v, nil
			}
		}
		return zero, fmt.Errorf("%s %q is not known", what, s)
	}
	return v, nil
}

func (yr *YANGRule) rule(opt YANGOptions) (r Rule, l2, mps int, err error) {
	if yr.RuleIDValue == nil || yr.RuleIDLength == nil {
		return r, 0, 0, errors.New("rule-id-value and rule-id-length are mandatory")
	}
	r.ID, r.IDLength = *yr.RuleIDValue, int(*yr.RuleIDLength)
	if r.IDLength == 0 {
		r.Implicit = true // rule-id-length 0: the RuleID is implicit
	}
	if yr.RuleNature == "" {
		return r, 0, 0, errors.New("rule-nature is mandatory")
	}
	if r.Kind, err = identity(yr.RuleNature, invert(yangKind), "rule-nature"); err != nil {
		return r, 0, 0, err
	}
	switch r.Kind {
	case KindCompression:
		for i := range yr.Entry {
			fd, err := yr.Entry[i].descriptor()
			if err != nil {
				return r, 0, 0, fmt.Errorf("entry %d: %w", i, err)
			}
			r.Fields = append(r.Fields, fd)
		}
	case KindFragmentation:
		p := &FragParams{}
		if p.Mode, err = identity(yr.FragmentationMode, invert(yangMode), "fragmentation-mode"); err != nil {
			return r, 0, 0, err
		}
		dir, err := identity(yr.Direction, invert(yangDI), "direction")
		if err != nil {
			return r, 0, 0, err
		}
		if dir == Bi {
			return r, 0, 0, errors.New("a fragmentation rule's direction is up or down")
		}
		p.Direction = dir
		if yr.FCNSize == nil {
			return r, 0, 0, errors.New("fcn-size is mandatory")
		}
		p.FCNSize = int(*yr.FCNSize)
		if yr.DTagSize != nil {
			p.DTagSize = int(*yr.DTagSize)
		}
		if yr.WSize != nil {
			p.WSize = int(*yr.WSize)
		}
		if yr.WindowSize != nil {
			p.WindowSize = int(*yr.WindowSize)
		}
		if yr.MaxAckRequests != nil {
			p.MaxAckRequests = int(*yr.MaxAckRequests)
		}
		p.RCS = RCSCRC32
		if yr.RCSAlgorithm != "" {
			if p.RCS, err = identity(yr.RCSAlgorithm, invert(yangRCS), "rcs-algorithm"); err != nil {
				return r, 0, 0, err
			}
		}
		// An inactivity timer of 0 disables it (RFC 9363 4.10.5); this
		// module's receivers always have one, so 0 keeps its default.
		p.Inactivity = Duration(yr.InactivityTimer.duration())
		p.Retransmission = Duration(yr.RetransmissionTimer.duration())
		if p.Mode == AckOnError {
			if yr.TileSize != nil && *yr.TileSize > 0 {
				p.TileSize = int(*yr.TileSize)
			} else {
				p.TileSize = opt.TileBits // 0: tiles fill their fragment
			}
			if yr.TileInAll1 != "" {
				if p.LastTile, err = identity(yr.TileInAll1, invert(yangLast), "tile-in-all-1"); err != nil {
					return r, 0, 0, err
				}
			}
			switch yr.AckBehavior {
			case "", yangAckAfterAll1, "ack-behavior-after-all-1", yangAckByL2, "ack-behavior-by-layer2":
				// After the All-1 (by-layer2: whenever asked, which our
				// receiver also does on an ACK REQ).
			case yangAckAfterAll0, "ack-behavior-after-all-0":
				p.AckEveryWindow = true
			default:
				return r, 0, 0, fmt.Errorf("ack-behavior %q is not known", yr.AckBehavior)
			}
			switch yr.BitmapFormat {
			case "", yangBitmapRFC8724, "bitmap-RFC8724":
			case yangBitmapCompound, "bitmap-compound-ack":
				p.CompoundAck = true
				p.LastBitmapUncompressed = yr.LastBitmapCompression != nil && !*yr.LastBitmapCompression
			default:
				return r, 0, 0, fmt.Errorf("bitmap-format %q is not known", yr.BitmapFormat)
			}
		}
		r.Fragmentation = p
		if yr.L2WordSize != nil {
			l2 = int(*yr.L2WordSize)
		}
		if yr.MaximumPacketSize != nil {
			mps = int(*yr.MaximumPacketSize)
		}
	}
	return r, l2, mps, nil
}

func (e *YANGEntry) descriptor() (FieldDescriptor, error) {
	var fd FieldDescriptor
	var err error
	if e.FieldID == "" {
		return fd, errors.New("field-id is mandatory")
	}
	if fd.FID, err = identity(e.FieldID, yangFIDsBack, "field-id"); err != nil {
		return fd, err
	}
	if len(e.FieldLength) == 0 {
		return fd, errors.New("field-length is mandatory")
	}
	var fl uint8
	var fls string
	if json.Unmarshal(e.FieldLength, &fl) == nil {
		fd.FL = int(fl)
	} else if json.Unmarshal(e.FieldLength, &fls) == nil {
		if fd.Var, err = identity(fls, invert(yangVar), "field-length"); err != nil {
			return fd, err
		}
	} else {
		return fd, fmt.Errorf("field-length %s is not a number or an identity", e.FieldLength)
	}
	if e.FieldPosition == nil {
		return fd, errors.New("field-position is mandatory")
	}
	fd.FP = ptr(int(*e.FieldPosition))
	if e.DirectionIndicator == "" {
		return fd, errors.New("direction-indicator is mandatory")
	}
	if fd.DI, err = identity(e.DirectionIndicator, invert(yangDI), "direction-indicator"); err != nil {
		return fd, err
	}
	if fd.MO, err = identity(e.MatchingOperator, invert(yangMO), "matching-operator"); err != nil {
		return fd, err
	}
	if fd.CDA, err = identity(e.CompDecompAction, invert(yangCDA), "comp-decomp-action"); err != nil {
		return fd, err
	}
	if len(e.CompDecompActionValue) > 0 {
		return fd, errors.New("comp-decomp-action-value is not used by any action of RFC 8724")
	}
	if fd.MO == MOMSB {
		if len(e.MatchingOperatorValue) != 1 {
			return fd, errors.New("mo-msb needs one matching-operator-value")
		}
		n := new(big.Int).SetBytes(e.MatchingOperatorValue[0].Value)
		if !n.IsInt64() || n.Int64() > 0xFFFF {
			return fd, errors.New("the MSB length does not fit")
		}
		fd.MOArg = int(n.Int64())
	}
	if len(e.TargetValue) > 0 {
		tvs := append([]YANGValue(nil), e.TargetValue...)
		sort.Slice(tvs, func(i, j int) bool { return tvs[i].Index < tvs[j].Index })
		var items []string
		for i, tv := range tvs {
			if int(tv.Index) != i {
				return fd, errors.New("target-value indexes are not 0, 1, 2, …")
			}
			items = append(items, `{"hex":"`+hex.EncodeToString(tv.Value)+`"}`)
		}
		if fd.MO == MOMatchMapping {
			fd.TV = json.RawMessage("[" + strings.Join(items, ",") + "]")
		} else {
			if len(items) > 1 {
				return fd, errors.New("more than one target-value for an operator other than match-mapping")
			}
			fd.TV = json.RawMessage(items[0])
		}
	}
	if fd.FL > 0 && fd.MO == MOMSB && len(fd.TV) == 0 {
		return fd, errors.New("mo-msb needs a target-value")
	}
	return fd, nil
}
