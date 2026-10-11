// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Direction is a field descriptor's Direction Indicator, or a packet's
// direction (RFC 8724 7.1): up (from the device), dw (to the device) or
// bi (both, descriptors only).
type Direction string

// Directions.
const (
	Up   Direction = "up"
	Down Direction = "dw"
	Bi   Direction = "bi"
)

// Matching operators (RFC 8724 7.3).
const (
	MOEqual        = "equal"
	MOIgnore       = "ignore"
	MOMSB          = "msb"
	MOMatchMapping = "match-mapping"
)

// Compression/decompression actions (RFC 8724 7.4).
const (
	CDANotSent     = "not-sent"
	CDAValueSent   = "value-sent"
	CDAMappingSent = "mapping-sent"
	CDALSB         = "lsb"
	CDACompute     = "compute"
	CDADevIID      = "deviid"
	CDAAppIID      = "appiid"
)

// Rule kinds.
const (
	KindCompression   = "compression"
	KindNoCompression = "no-compression"
	KindFragmentation = "fragmentation"
)

// Fragmentation modes (RFC 8724 8.4).
const (
	NoAck      = "no-ack"
	AckAlways  = "ack-always"
	AckOnError = "ack-on-error"
)

// Where an ACK-on-Error sender puts the last tile (RFC 8724 8.4.3).
const (
	LastTileRegular = "regular"
	LastTileAll1    = "all1"
	LastTileEither  = "either"
)

// RuleSet is a SCHC context: the rules both ends hold (RFC 8724 7.1).
// In JSON it is our own form; ParseYANG and MarshalYANG use RFC 9363's.
type RuleSet struct {
	// L2Word is the L2 Word size in bits (default 8, the LoRaWAN value of
	// RFC 9011 5.6).
	L2Word int    `json:"l2Word,omitempty"`
	Rules  []Rule `json:"rules"`
	// MaxPacketSize bounds a decompressed or reassembled packet in bytes
	// (RFC 8724 appendix D, clause 12; default 4096).
	MaxPacketSize int `json:"maxPacketSize,omitempty"`
}

// Rule is one rule: compression, no-compression or fragmentation.
type Rule struct {
	ID       uint32 `json:"ruleId"`
	IDLength int    `json:"ruleIdLength,omitempty"` // bits, default 8
	// Implicit is a rule whose RuleID is not sent (length 0): the context
	// says which rule applies, as when the rule set holds one rule or the
	// L2 tells rules apart (RFC 9363's rule-id-length 0). Its ID is 0, and
	// it must be the only rule of its rule set, since an empty RuleID
	// starts every other.
	Implicit bool   `json:"implicit,omitempty"`
	Kind     string `json:"kind,omitempty"` // default compression, or fragmentation when fragmentation is set
	// Name is a label for logs and the console.
	Name          string            `json:"name,omitempty"`
	Fields        []FieldDescriptor `json:"fields,omitempty"`
	Fragmentation *FragParams       `json:"fragmentation,omitempty"`

	splits map[string]bool // fields the rule describes as subfields
}

// VarTKL is the field length function of the CoAP token (RFC 8824 4.5):
// the token is as long as the TKL says, and no size goes in the residue.
const VarTKL = "tkl"

// FieldDescriptor is one line of a compression rule (RFC 8724 7.1).
type FieldDescriptor struct {
	FID string `json:"fid"`
	// FL is the field length in bits; 0 with Var set is a variable-length
	// field measured in Var units ("bits" or "bytes", RFC 8724 7.4.2), or
	// the CoAP token whose length is its TKL ("tkl", RFC 8824 4.5).
	FL  int    `json:"fl,omitempty"`
	Var string `json:"var,omitempty"`
	// FP is the field position, default 1; 0 is "don't care" (RFC 8724
	// 7.2).
	FP *int      `json:"fp,omitempty"`
	DI Direction `json:"di,omitempty"` // default bi
	// TV is a number, a hex string ("0x…" or bare hex), an IPv6 prefix or
	// address (for 64-bit prefix and IID fields), {"text": "…"} for UTF-8
	// bytes, {"hex": "…"}, or a list of these for match-mapping. For the
	// CoAP options that hold text (Uri-Host, Uri-Path, Uri-Query,
	// Location-Path, Location-Query, Proxy-Uri, Proxy-Scheme) a plain
	// string is the text. A number for a variable-length field is its
	// shortest big-endian form, as CoAP uint options are (0 is empty).
	TV    json.RawMessage `json:"tv,omitempty"`
	MO    string          `json:"mo"`
	MOArg int             `json:"moArg,omitempty"` // x of MSB(x)
	CDA   string          `json:"cda"`

	tv    []Bits // compiled target value(s)
	fp    int
	group int // instances of the field the entry covers (RFC 8824 5.3), 1 normally
}

// FragParams are a fragmentation rule's parameters (RFC 8724 8.2.4, 8.4
// and appendix D).
type FragParams struct {
	Mode       string    `json:"mode"`
	Direction  Direction `json:"direction,omitempty"` // up or dw: which way the fragments go
	DTagSize   int       `json:"dtagSize,omitempty"`  // T
	WSize      int       `json:"wSize,omitempty"`     // M
	FCNSize    int       `json:"fcnSize"`             // N
	WindowSize int       `json:"windowSize,omitempty"`
	// TileSize is the regular tile size in bits for ACK-on-Error; in
	// JSON tileBytes (bytes) or tileBits. 0 makes each tile fill its
	// fragment at the MTU the sender starts with, one tile per fragment
	// (RFC 9363's tile-size left out).
	TileSize  int `json:"tileBits,omitempty"`
	TileBytes int `json:"tileBytes,omitempty"`
	// RCS names the Reassembly Check Sequence algorithm (default "crc32",
	// RFC 8724 8.2.3; see RegisterRCS) and RCSSize its size in bits (by
	// default the algorithm's).
	RCS              string   `json:"rcs,omitempty"`
	RCSSize          int      `json:"rcsSize,omitempty"`
	MaxAckRequests   int      `json:"maxAckRequests,omitempty"`
	Retransmission   Duration `json:"retransmissionTimer,omitempty"`
	Inactivity       Duration `json:"inactivityTimer,omitempty"`
	LastTile         string   `json:"lastTile,omitempty"`         // ACK-on-Error: regular, all1 or either (default either)
	PenultimateShort bool     `json:"penultimateShort,omitempty"` // ACK-on-Error: penultimate tile may be one L2 Word short
	// AckEveryWindow: the ACK-on-Error receiver acknowledges every window
	// and the sender waits for it before the next (RFC 9011 5.6.2).
	AckEveryWindow bool `json:"ackEveryWindow,omitempty"`
	// CompoundAck: the ACK-on-Error receiver reports every window with
	// missing tiles in one SCHC Compound ACK, and the sender reads them
	// (RFC 9441); LastBitmapUncompressed sends its last bitmap whole.
	CompoundAck            bool `json:"compoundAck,omitempty"`
	LastBitmapUncompressed bool `json:"lastBitmapUncompressed,omitempty"`

	// Options of technology profiles (all off by default; the Sigfox
	// rules of RFC 9442 set them, see SigfoxUplinkRule):
	//
	// HeaderPadded pads every fragment header (an All-1's with its RCS)
	// to an L2 Word before the payload. BitmapUncompressed sends every ACK bitmap
	// whole (for a Compound ACK, as LastBitmapUncompressed). NoAckReq has
	// the sender ask for an ACK by sending the All-1 again, never an ACK
	// REQ. FCNCountdown numbers No-ACK fragments from the number of
	// fragments less one down to 1, the last being the All-1.
	// FullFragments (No-ACK and ACK-Always) fills every regular fragment
	// to the MTU, so no regular fragment needs padding; a remainder too
	// long for the All-1 goes in one more regular fragment and the All-1
	// follows empty.
	HeaderPadded       bool `json:"headerPadded,omitempty"`
	BitmapUncompressed bool `json:"bitmapUncompressed,omitempty"`
	NoAckReq           bool `json:"noAckReq,omitempty"`
	FCNCountdown       bool `json:"fcnCountdown,omitempty"`
	FullFragments      bool `json:"fullFragments,omitempty"`
	// AckMaxBits bounds the receiver's SCHC ACK (the frame it travels in,
	// 64 bits on a Sigfox downlink): a Compound ACK reports as many
	// windows with tiles missing as fit, lowest first. 0 is no bound.
	AckMaxBits int `json:"ackMaxBits,omitempty"`

	rcsAlg RCSAlgorithm
}

// countRCS reports whether the RCS field carries a fragment count
// (RCSFragmentCount) rather than a check value over the packet.
func (p *FragParams) countRCS() bool { return p.RCS == RCSFragmentCount }

// Duration is a JSON duration: "12h", "30s" or a number of seconds.
type Duration time.Duration

// D is the duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON writes a duration string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON reads "12h" or seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("a duration is a string such as \"30s\" or a number of seconds")
	}
	*d = Duration(n * float64(time.Second))
	return nil
}

// ParseRuleSet reads and checks a rule set from JSON.
func ParseRuleSet(b []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("schc rules: %w", err)
	}
	if err := rs.Compile(); err != nil {
		return nil, err
	}
	return &rs, nil
}

// Compile fills in defaults and checks the rules; it must run before use.
func (rs *RuleSet) Compile() error {
	if rs.L2Word == 0 {
		rs.L2Word = 8
	}
	if rs.L2Word < 1 || rs.L2Word > 64 {
		return fmt.Errorf("schc rules: l2Word %d is not 1 to 64 bits", rs.L2Word)
	}
	if rs.MaxPacketSize == 0 {
		rs.MaxPacketSize = 4096
	}
	noComp := 0
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if err := r.compile(rs.L2Word); err != nil {
			return fmt.Errorf("schc rule %d: %w", r.ID, err)
		}
		if r.Kind == KindNoCompression {
			noComp++
		}
	}
	// RuleIDs must be a prefix code: no ID may be the start of another.
	for i := range rs.Rules {
		for j := range rs.Rules {
			a, b := &rs.Rules[i], &rs.Rules[j]
			if i == j || a.IDLength > b.IDLength {
				continue
			}
			if b.ID>>uint(b.IDLength-a.IDLength) == a.ID {
				return fmt.Errorf("schc rules: rule ID %d/%d is ambiguous with %d/%d", a.ID, a.IDLength, b.ID, b.IDLength)
			}
		}
	}
	if noComp > 1 {
		return errors.New("schc rules: more than one no-compression rule")
	}
	return nil
}

func (r *Rule) compile(word int) error {
	if r.Implicit {
		if r.IDLength != 0 || r.ID != 0 {
			return errors.New("an implicit rule has no RuleID (ruleId 0, ruleIdLength 0)")
		}
	} else if r.IDLength == 0 {
		r.IDLength = 8
	}
	if !r.Implicit && (r.IDLength < 1 || r.IDLength > 32) {
		return fmt.Errorf("ruleIdLength %d is not 1 to 32", r.IDLength)
	}
	if uint64(r.ID) >= 1<<uint(r.IDLength) {
		return fmt.Errorf("rule ID %d does not fit in %d bits", r.ID, r.IDLength)
	}
	if r.Kind == "" {
		r.Kind = KindCompression
		if r.Fragmentation != nil {
			r.Kind = KindFragmentation
		}
	}
	switch r.Kind {
	case KindCompression:
		if r.Fragmentation != nil {
			return errors.New("a compression rule has no fragmentation parameters")
		}
		r.splits = nil
		for i := range r.Fields {
			if err := r.Fields[i].compile(); err != nil {
				return fmt.Errorf("field %s: %w", r.Fields[i].FID, err)
			}
			if parent, ok := subfieldOf[r.Fields[i].FID]; ok {
				if r.splits == nil {
					r.splits = map[string]bool{}
				}
				r.splits[parent] = true
			}
		}
		for i := range r.Fields {
			if r.splits[r.Fields[i].FID] {
				return fmt.Errorf("field %s is described both whole and as subfields", r.Fields[i].FID)
			}
		}
	case KindNoCompression:
		if len(r.Fields) > 0 || r.Fragmentation != nil {
			return errors.New("a no-compression rule has neither fields nor fragmentation")
		}
	case KindFragmentation:
		if r.Fragmentation == nil {
			return errors.New("a fragmentation rule needs its fragmentation parameters")
		}
		if len(r.Fields) > 0 {
			return errors.New("a fragmentation rule has no fields")
		}
		return r.Fragmentation.compile(word, r.IDLength)
	default:
		return fmt.Errorf("kind %q is not compression, no-compression or fragmentation", r.Kind)
	}
	return nil
}

func (f *FieldDescriptor) compile() error {
	if f.FID == "" {
		return errors.New("fid is required")
	}
	f.MO, f.CDA = strings.ToLower(f.MO), strings.ToLower(f.CDA)
	switch f.CDA {
	case "compute-*", "compute-length", "compute-checksum":
		f.CDA = CDACompute
	case "devIID", "dev-iid":
		f.CDA = CDADevIID
	case "appIID", "app-iid":
		f.CDA = CDAAppIID
	}
	if strings.HasPrefix(f.MO, "msb(") && strings.HasSuffix(f.MO, ")") {
		n, err := strconv.Atoi(f.MO[4 : len(f.MO)-1])
		if err != nil {
			return fmt.Errorf("mo %q: %w", f.MO, err)
		}
		f.MO, f.MOArg = MOMSB, n
	}
	f.fp = 1
	if f.FP != nil {
		if *f.FP < 0 {
			return fmt.Errorf("fp %d is negative", *f.FP)
		}
		f.fp = *f.FP
	}
	if f.DI == "" {
		f.DI = Bi
	}
	f.DI = Direction(strings.ToLower(string(f.DI)))
	if f.DI == "down" {
		f.DI = Down
	}
	if f.DI != Up && f.DI != Down && f.DI != Bi {
		return fmt.Errorf("di %q is not up, dw or bi", f.DI)
	}
	f.Var = strings.ToLower(f.Var)
	switch f.Var {
	case "":
		if f.FL < 1 || f.FL > 1024 {
			return fmt.Errorf("fl %d is not 1 to 1024 bits (or set var)", f.FL)
		}
	case "bits", "bytes":
		if f.FL != 0 {
			return errors.New("a variable-length field has no fl")
		}
	case VarTKL:
		if f.FL != 0 {
			return errors.New("a field of length tkl has no fl")
		}
		if f.FID != FCoAPToken {
			return fmt.Errorf("var tkl is for %s only", FCoAPToken)
		}
	default:
		return fmt.Errorf("var %q is not bits, bytes or tkl", f.Var)
	}
	switch f.MO {
	case MOEqual, MOIgnore, MOMatchMapping:
	case MOMSB:
		if f.MOArg < 0 || (f.Var == "" && f.MOArg > f.FL) {
			return fmt.Errorf("msb(%d) does not fit the field", f.MOArg)
		}
		if f.Var == "bytes" && f.MOArg%8 != 0 {
			return fmt.Errorf("msb(%d) of a field in bytes must be a multiple of 8", f.MOArg)
		}
	default:
		return fmt.Errorf("mo %q is not equal, ignore, msb(x) or match-mapping", f.MO)
	}
	switch f.CDA {
	case CDANotSent, CDAValueSent, CDACompute, CDADevIID, CDAAppIID:
	case CDAMappingSent:
		if f.MO != MOMatchMapping {
			return errors.New("mapping-sent goes with match-mapping")
		}
	case CDALSB:
		if f.MO != MOMSB {
			return errors.New("lsb goes with msb(x)")
		}
	default:
		return fmt.Errorf("cda %q is not not-sent, value-sent, mapping-sent, lsb, compute, deviid or appiid", f.CDA)
	}
	tv, group, err := parseTV(f.TV, f.FL, f.MO == MOMatchMapping, textOptions[f.FID])
	if err != nil {
		return fmt.Errorf("tv: %w", err)
	}
	f.tv, f.group = tv, group
	if group > 1 && (f.CDA != CDAMappingSent || f.Var != "bytes" || f.fp == 0) {
		return errors.New("a target value of grouped elements goes with match-mapping, mapping-sent, var bytes and a field position from 1 (RFC 8824 5.3)")
	}
	needTV := f.MO == MOEqual || f.MO == MOMSB || f.MO == MOMatchMapping || f.CDA == CDANotSent
	if needTV && len(tv) == 0 {
		return fmt.Errorf("mo %s with cda %s needs a tv", f.MO, f.CDA)
	}
	if f.MO == MOMSB && len(tv) == 1 && f.Var == "" && tv[0].Len() != f.FL {
		return errors.New("the tv of msb(x) is the whole field")
	}
	return nil
}

// parseTV reads a target value: one value, or a list for match-mapping.
// A list of lists groups that many consecutive instances of a repeated
// field in one entry (RFC 8824 5.3, table 1: ["a","b"] for the path /a/b);
// group is their number, 1 otherwise.
func parseTV(raw json.RawMessage, fl int, list, text bool) (tv []Bits, group int, err error) {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil, 1, nil
	}
	var items []json.RawMessage
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, 0, err
		}
		if !list {
			return nil, 0, errors.New("a list is a target value for match-mapping only")
		}
		if len(items) == 0 {
			return nil, 0, errors.New("match-mapping needs at least one value")
		}
	} else {
		items = []json.RawMessage{raw}
	}
	group = 1
	grouped := isGroupItem(items[0])
	out := make([]Bits, 0, len(items))
	for i, it := range items {
		if isGroupItem(it) != grouped {
			return nil, 0, errors.New("a target value mixes groups and single values")
		}
		if grouped {
			var elems []json.RawMessage
			if err := json.Unmarshal(it, &elems); err != nil {
				return nil, 0, err
			}
			if i == 0 {
				group = len(elems)
			}
			if len(elems) == 0 || len(elems) != group {
				return nil, 0, errors.New("every group of a target value has the same number of elements, at least one")
			}
			var vs []Bits
			for _, e := range elems {
				v, err := parseValue(e, fl, text)
				if err != nil {
					return nil, 0, err
				}
				vs = append(vs, v)
			}
			if group == 1 {
				out = append(out, vs[0])
			} else {
				out = append(out, groupValue(vs))
			}
			continue
		}
		v, err := parseValue(it, fl, text)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, group, nil
}

func isGroupItem(it json.RawMessage) bool {
	s := strings.TrimSpace(string(it))
	return len(s) > 0 && s[0] == '['
}

// groupValue is several instances of a field as one value to match: each
// instance's length in 16 bits, then its bytes.
func groupValue(vs []Bits) Bits {
	var g Bits
	for _, v := range vs {
		g.AppendUint(uint64(v.Len()/8), 16)
		g.Append(v)
	}
	return g
}

// ungroup splits a group value into n instances.
func ungroup(g Bits, n int) ([]Bits, bool) {
	var out []Bits
	at := 0
	for i := 0; i < n; i++ {
		if g.Len()-at < 16 {
			return nil, false
		}
		l := 8 * int(g.UintAt(at, 16))
		at += 16
		if g.Len()-at < l {
			return nil, false
		}
		out = append(out, g.Slice(at, at+l))
		at += l
	}
	return out, at == g.Len()
}

// fitBytes is b as a value of fl bits (fl 0: variable, b as it is): a
// big-endian number that must fit.
func fitBytes(b []byte, fl int, what string) (Bits, error) {
	if fl == 0 {
		return BytesOf(b), nil
	}
	bi := new(big.Int).SetBytes(b)
	if bi.BitLen() > fl {
		return Bits{}, fmt.Errorf("%s does not fit in %d bits", what, fl)
	}
	return bigBits(bi, fl), nil
}

// parseValue reads one value of fl bits (fl 0: variable, bytes as given);
// text says a plain string is text rather than hexadecimal.
func parseValue(raw json.RawMessage, fl int, text bool) (Bits, error) {
	var n json.Number
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return Bits{}, err
	}
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 1 {
			if s, ok := t["text"].(string); ok {
				if fl != 0 && 8*len(s) != fl {
					return Bits{}, fmt.Errorf("text %q is not %d bits", s, fl)
				}
				return BytesOf([]byte(s)), nil
			}
			if s, ok := t["hex"].(string); ok {
				b, err := hex.DecodeString(strings.TrimPrefix(strings.ReplaceAll(s, " ", ""), "0x"))
				if err != nil {
					return Bits{}, fmt.Errorf("%q is not hexadecimal", s)
				}
				return fitBytes(b, fl, s)
			}
		}
		return Bits{}, fmt.Errorf("%s is not {\"text\": …} or {\"hex\": …}", raw)
	case json.Number:
		n = t
		bi, ok := new(big.Int).SetString(n.String(), 10)
		if !ok || bi.Sign() < 0 {
			return Bits{}, fmt.Errorf("%s is not a whole number", n)
		}
		if fl == 0 {
			return BytesOf(bi.Bytes()), nil
		}
		if bi.BitLen() > fl {
			return Bits{}, fmt.Errorf("%s does not fit in %d bits", n, fl)
		}
		return bigBits(bi, fl), nil
	case string:
		if text {
			return parseValue(json.RawMessage(`{"text":`+string(raw)+`}`), fl, false)
		}
		s := strings.TrimSpace(t)
		if strings.Contains(s, ":") {
			return ipv6Value(s, fl)
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			if fl != 32 {
				return Bits{}, fmt.Errorf("an IPv4 address %q is for a 32-bit field", s)
			}
			b := a.As4()
			return BitsOf(b[:], 32).Clone(), nil
		}
		s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		if len(s)%2 == 1 {
			s = "0" + s
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return Bits{}, fmt.Errorf("%q is not hexadecimal", t)
		}
		if fl == 0 {
			return BytesOf(b), nil
		}
		bi := new(big.Int).SetBytes(b)
		if bi.BitLen() > fl {
			return Bits{}, fmt.Errorf("%q does not fit in %d bits", t, fl)
		}
		return bigBits(bi, fl), nil
	}
	return Bits{}, fmt.Errorf("%s is not a number, hex string or IPv6 value", raw)
}

func bigBits(v *big.Int, fl int) Bits {
	var x Bits
	for i := fl - 1; i >= 0; i-- {
		x.AppendBit(uint8(v.Bit(i)))
	}
	return x
}

// IPv6Value reads an IPv6 prefix ("fe80::/64") or interface identifier
// ("::1") as the 64 bits of a prefix or IID field.
func IPv6Value(s string) (Bits, error) { return ipv6Value(s, 64) }

// ipv6Value reads an IPv6 prefix ("fe80::/64": its first 64 bits) or an
// interface identifier ("::1": the last 64 bits) for a 64-bit field.
func ipv6Value(s string, fl int) (Bits, error) {
	if fl != 64 {
		return Bits{}, fmt.Errorf("an IPv6 value %q is for a 64-bit prefix or IID field", s)
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		a := p.Masked().Addr().As16()
		return BitsOf(append([]byte(nil), a[:8]...), 64), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() {
		return Bits{}, fmt.Errorf("%q is not an IPv6 prefix or address", s)
	}
	b := a.As16()
	return BitsOf(append([]byte(nil), b[8:]...), 64), nil
}

// Rule finds the rule whose ID starts msg.
func (rs *RuleSet) match(msg Bits) (*Rule, error) {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if msg.Len() >= r.IDLength && msg.UintAt(0, r.IDLength) == uint64(r.ID) {
			return r, nil
		}
	}
	return nil, errors.New("schc: no rule has this RuleID")
}

// ByID returns the rule with an ID (of any length), or nil.
func (rs *RuleSet) ByID(id uint32) *Rule {
	for i := range rs.Rules {
		if rs.Rules[i].ID == id {
			return &rs.Rules[i]
		}
	}
	return nil
}

// Fragmentation returns the fragmentation rules for a direction, in ID
// order.
func (rs *RuleSet) Fragmentation(dir Direction) []*Rule {
	var out []*Rule
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.Kind == KindFragmentation && (r.Fragmentation.Direction == dir || r.Fragmentation.Direction == Bi) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// idBits is the rule's RuleID as bits.
func (r *Rule) idBits() Bits { return Uint(uint64(r.ID), r.IDLength) }

func (p *FragParams) compile(word, _ int) error {
	p.Mode = strings.ToLower(p.Mode)
	if p.Direction == "" {
		p.Direction = Bi
	}
	if p.RCS == "" {
		p.RCS = RCSCRC32
	}
	p.RCS = strings.ToLower(p.RCS)
	alg, ok := LookupRCS(p.RCS)
	if !ok {
		return fmt.Errorf("rcs %q is not a registered algorithm (%s)", p.RCS, strings.Join(RCSAlgorithms(), ", "))
	}
	p.rcsAlg = alg
	if alg.Bits == 0 {
		// The fragment count: its size is the rule's.
		if p.RCSSize < 1 || p.RCSSize > 32 {
			return fmt.Errorf("rcs %s needs an rcsSize of 1 to 32 bits", alg.Name)
		}
	} else {
		if p.RCSSize == 0 {
			p.RCSSize = alg.Bits
		}
		if p.RCSSize != alg.Bits {
			return fmt.Errorf("rcsSize %d is not the %d bits of %s", p.RCSSize, alg.Bits, alg.Name)
		}
	}
	if p.FCNCountdown && p.Mode != NoAck {
		return errors.New("fcnCountdown is for no-ack")
	}
	if p.TileBytes != 0 {
		if p.TileSize != 0 && p.TileSize != 8*p.TileBytes {
			return errors.New("tileBytes and tileBits disagree")
		}
		p.TileSize = 8 * p.TileBytes
	}
	if p.DTagSize < 0 || p.DTagSize > 16 || p.FCNSize < 1 || p.FCNSize > 16 || p.WSize < 0 || p.WSize > 16 {
		return errors.New("dtagSize and wSize are 0 to 16 bits, fcnSize 1 to 16")
	}
	if p.MaxAckRequests == 0 {
		p.MaxAckRequests = 8
	}
	if p.Inactivity == 0 {
		p.Inactivity = Duration(12 * time.Hour)
	}
	if p.Retransmission == 0 {
		p.Retransmission = Duration(p.Inactivity.D() / time.Duration(p.MaxAckRequests+1))
	}
	if (p.CompoundAck || p.LastBitmapUncompressed) && p.Mode != AckOnError {
		return errors.New("compoundAck is for ack-on-error (RFC 9441)")
	}
	if p.LastBitmapUncompressed && !p.CompoundAck {
		return errors.New("lastBitmapUncompressed goes with compoundAck")
	}
	switch p.Mode {
	case NoAck:
		if p.WSize != 0 {
			return errors.New("no-ack has no W field (RFC 8724 8.4.1)")
		}
	case AckAlways:
		if p.WSize > 1 {
			// RFC 8724 8.4.2 has a 1-bit W; RFC 9442's downlink rule has
			// none, so the packet must fit in one window.
			return errors.New("ack-always has a 1-bit W field (RFC 8724 8.4.2), or none for a packet of one window")
		}
		if p.WindowSize == 0 {
			p.WindowSize = 1<<uint(p.FCNSize) - 1
		}
		if p.WindowSize < 1 || p.WindowSize >= 1<<uint(p.FCNSize) {
			return errors.New("windowSize must be less than 2^fcnSize")
		}
	case AckOnError:
		if p.WSize < 1 {
			return errors.New("ack-on-error needs a W field (RFC 8724 8.4.3)")
		}
		if p.WindowSize == 0 {
			p.WindowSize = 1<<uint(p.FCNSize) - 1
		}
		if p.WindowSize < 1 || p.WindowSize >= 1<<uint(p.FCNSize) {
			return errors.New("windowSize must be less than 2^fcnSize")
		}
		// Tile size 0: each tile fills its fragment (RFC 9363 tile-size
		// absent), cut at the MTU the sender starts with.
		if p.TileSize < 0 || (p.TileSize > 0 && p.TileSize < word) {
			return fmt.Errorf("ack-on-error needs a tile size of at least one L2 Word (%d bits), or 0 for tiles that fill their fragment", word)
		}
		if p.PenultimateShort && p.TileSize < 2*word {
			return errors.New("a penultimate tile one L2 Word short needs tiles of two L2 Words or more")
		}
		switch p.LastTile {
		case "":
			p.LastTile = LastTileEither
		case LastTileRegular, LastTileAll1, LastTileEither:
		default:
			return fmt.Errorf("lastTile %q is not regular, all1 or either", p.LastTile)
		}
	default:
		return fmt.Errorf("mode %q is not no-ack, ack-always or ack-on-error", p.Mode)
	}
	return nil
}
