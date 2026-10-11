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
// It is our own JSON form; RFC 9363's YANG model is not implemented.
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
	Kind     string `json:"kind,omitempty"`         // default compression, or fragmentation when fragmentation is set
	// Name is a label for logs and the console.
	Name          string            `json:"name,omitempty"`
	Fields        []FieldDescriptor `json:"fields,omitempty"`
	Fragmentation *FragParams       `json:"fragmentation,omitempty"`
}

// FieldDescriptor is one line of a compression rule (RFC 8724 7.1).
type FieldDescriptor struct {
	FID string `json:"fid"`
	// FL is the field length in bits; 0 with Var set is a variable-length
	// field measured in Var units ("bits" or "bytes", RFC 8724 7.4.2).
	FL  int    `json:"fl,omitempty"`
	Var string `json:"var,omitempty"`
	// FP is the field position, default 1; 0 is "don't care" (RFC 8724
	// 7.2).
	FP *int      `json:"fp,omitempty"`
	DI Direction `json:"di,omitempty"` // default bi
	// TV is a number, a hex string ("0x…" or bare hex), an IPv6 prefix or
	// address (for 64-bit prefix and IID fields), or a list of these for
	// match-mapping.
	TV    json.RawMessage `json:"tv,omitempty"`
	MO    string          `json:"mo"`
	MOArg int             `json:"moArg,omitempty"` // x of MSB(x)
	CDA   string          `json:"cda"`

	tv []Bits // compiled target value(s)
	fp int
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
	// JSON tileBytes (bytes) or tileBits.
	TileSize         int      `json:"tileBits,omitempty"`
	TileBytes        int      `json:"tileBytes,omitempty"`
	RCSSize          int      `json:"rcsSize,omitempty"` // bits, default 32 (CRC32)
	MaxAckRequests   int      `json:"maxAckRequests,omitempty"`
	Retransmission   Duration `json:"retransmissionTimer,omitempty"`
	Inactivity       Duration `json:"inactivityTimer,omitempty"`
	LastTile         string   `json:"lastTile,omitempty"`         // ACK-on-Error: regular, all1 or either (default either)
	PenultimateShort bool     `json:"penultimateShort,omitempty"` // ACK-on-Error: penultimate tile may be one L2 Word short
	// AckEveryWindow: the ACK-on-Error receiver acknowledges every window
	// and the sender waits for it before the next (RFC 9011 5.6.2).
	AckEveryWindow bool `json:"ackEveryWindow,omitempty"`
}

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
	if r.IDLength == 0 {
		r.IDLength = 8
	}
	if r.IDLength < 1 || r.IDLength > 32 {
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
		for i := range r.Fields {
			if err := r.Fields[i].compile(); err != nil {
				return fmt.Errorf("field %s: %w", r.Fields[i].FID, err)
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
	switch f.Var {
	case "":
		if f.FL < 1 || f.FL > 1024 {
			return fmt.Errorf("fl %d is not 1 to 1024 bits (or set var)", f.FL)
		}
	case "bits", "bytes":
		if f.FL != 0 {
			return errors.New("a variable-length field has no fl")
		}
	default:
		return fmt.Errorf("var %q is not bits or bytes", f.Var)
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
	tv, err := parseTV(f.TV, f.FL, f.MO == MOMatchMapping)
	if err != nil {
		return fmt.Errorf("tv: %w", err)
	}
	f.tv = tv
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
func parseTV(raw json.RawMessage, fl int, list bool) ([]Bits, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		if !list {
			return nil, errors.New("a list is a target value for match-mapping only")
		}
		if len(items) == 0 {
			return nil, errors.New("match-mapping needs at least one value")
		}
	} else {
		items = []json.RawMessage{raw}
	}
	out := make([]Bits, 0, len(items))
	for _, it := range items {
		v, err := parseValue(it, fl)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// parseValue reads one value of fl bits (fl 0: variable, bytes as given).
func parseValue(raw json.RawMessage, fl int) (Bits, error) {
	var n json.Number
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return Bits{}, err
	}
	switch t := v.(type) {
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
		s := strings.TrimSpace(t)
		if strings.Contains(s, ":") {
			return ipv6Value(s, fl)
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
	if p.RCSSize == 0 {
		p.RCSSize = 32
	}
	if p.RCSSize != 32 {
		return errors.New("only the CRC32 RCS of 32 bits is supported (RFC 8724 8.2.3)")
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
	switch p.Mode {
	case NoAck:
		if p.WSize != 0 {
			return errors.New("no-ack has no W field (RFC 8724 8.4.1)")
		}
	case AckAlways:
		if p.WSize != 1 {
			return errors.New("ack-always has a 1-bit W field (RFC 8724 8.4.2)")
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
		if p.TileSize < word {
			return fmt.Errorf("ack-on-error needs a tile size of at least one L2 Word (%d bits)", word)
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
