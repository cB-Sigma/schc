// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package coreconf carries SCHC rule sets in the CORECONF form: RFC 9363
// instance data encoded in CBOR with YANG Schema Item iDentifiers (SIDs),
// as RFC 9254 specifies, for rule management over CoAP (CORECONF).
//
// Map keys are SID deltas from the parent node's SID (RFC 9254 3.2);
// identityref leaves are SIDs (6.10.1), and in the field-length union
// they carry CBOR tag 45 (6.12); binary leaves are byte strings. The
// decoder also takes identities as names (6.10.2).
//
// RFC 9363 assigned no SIDs. Default uses openschc's assignment for
// ietf-schc@2023-01-28 (entry point 5000) and ietf-schc-oam@2021-11-10
// (2000000), and ours for the cb-sigma-schc extension module (60000) and
// RFC 9441's ietf-schc-compound-ack (60100), both in the experimental
// range of RFC 9595. None of them is IANA-registered,
// so a peer must use the same SID files: LoadSIDFile reads others, in the
// RFC 9595 format or openschc's older one.
//
// The CBOR codec is github.com/fxamacker/cbor/v2; this package is
// separate so that the schc package itself has no dependency outside the
// standard library.
package coreconf

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/cB-Sigma/schc"
	"github.com/fxamacker/cbor/v2"
)

//go:embed sid/*.sid
var sidFiles embed.FS

// SIDs maps schema items to SIDs: data nodes by schema path
// ("/ietf-schc:schc/rule/entry/field-id") and identities by
// "module:identity".
type SIDs struct {
	path     map[string]uint64
	identity map[string]uint64
	byPath   map[uint64]string
	byID     map[uint64]string
}

// NewSIDs is an empty table.
func NewSIDs() *SIDs {
	return &SIDs{path: map[string]uint64{}, identity: map[string]uint64{}, byPath: map[uint64]string{}, byID: map[uint64]string{}}
}

var (
	defaultOnce sync.Once
	defaultSIDs *SIDs
	defaultErr  error
)

// Default is the table of the embedded SID files (see the package
// documentation). It must not be changed; Clone it to add to it.
func Default() *SIDs {
	defaultOnce.Do(func() {
		s := NewSIDs()
		names, _ := sidFiles.ReadDir("sid")
		for _, n := range names {
			if !strings.HasSuffix(n.Name(), ".sid") {
				continue
			}
			b, err := sidFiles.ReadFile("sid/" + n.Name())
			if err == nil {
				err = s.LoadSIDFile(b)
			}
			if err != nil {
				defaultErr = fmt.Errorf("coreconf: %s: %w", n.Name(), err)
				return
			}
		}
		defaultSIDs = s
	})
	if defaultErr != nil {
		panic(defaultErr) // the embedded files are part of the build
	}
	return defaultSIDs
}

// Clone copies the table.
func (s *SIDs) Clone() *SIDs {
	c := NewSIDs()
	for k, v := range s.path {
		c.path[k], c.byPath[v] = v, k
	}
	for k, v := range s.identity {
		c.identity[k], c.byID[v] = v, k
	}
	return c
}

// sidNumber reads a SID given as a JSON number or string (RFC 9595 writes
// uint64 as strings).
type sidNumber uint64

func (n *sidNumber) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("SID %s is not a number", b)
	}
	*n = sidNumber(v)
	return nil
}

type sidItem struct {
	Namespace  string    `json:"namespace"`
	Identifier string    `json:"identifier"`
	SID        sidNumber `json:"sid"`
}

type sidFile struct {
	ModuleName string    `json:"module-name"`
	Items      []sidItem `json:"items"` // openschc's older format
	Item       []sidItem `json:"item"`  // RFC 9595
}

// LoadSIDFile adds the items of a SID file: RFC 9595's
// {"ietf-sid-file:sid-file": {…}} or the older form openschc uses.
func (s *SIDs) LoadSIDFile(b []byte) error {
	var wrapped struct {
		F *sidFile `json:"ietf-sid-file:sid-file"`
	}
	var f sidFile
	if err := json.Unmarshal(b, &wrapped); err == nil && wrapped.F != nil {
		f = *wrapped.F
	} else if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.ModuleName == "" {
		return errors.New("a SID file needs its module-name")
	}
	for _, it := range append(f.Items, f.Item...) {
		sid := uint64(it.SID)
		switch it.Namespace {
		case "identity":
			s.addIdentity(f.ModuleName+":"+it.Identifier, sid)
		case "data":
			s.addPath(it.Identifier, sid)
		}
	}
	return nil
}

func (s *SIDs) addPath(p string, sid uint64) {
	s.path[p], s.byPath[sid] = sid, p
}

func (s *SIDs) addIdentity(id string, sid uint64) {
	s.identity[id], s.byID[sid] = sid, id
}

// Kinds of leaf in ietf-schc, by name.
var (
	identityLeaves = map[string]bool{
		"rule-nature": true, "fragmentation-mode": true, "direction": true, "rcs-algorithm": true,
		"tile-in-all-1": true, "ack-behavior": true, "field-id": true, "direction-indicator": true,
		"matching-operator": true, "comp-decomp-action": true, "bitmap-format": true,
	}
	binaryLeaves = map[string]bool{"value": true}
	unionLeaves  = map[string]bool{"field-length": true} // uint8 or identityref
)

const tagIdentityref = 45 // RFC 9254 9.3

// Marshal writes a compiled rule set in the CORECONF form with sids
// (nil for Default).
func Marshal(rs *schc.RuleSet, sids *SIDs) ([]byte, error) {
	doc, err := rs.YANG()
	if err != nil {
		return nil, err
	}
	js, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return FromJSON(js, sids)
}

// Unmarshal reads a rule set in the CORECONF form and compiles it, with
// opt as for schc.ParseYANGWith; skipped lists rules left out.
func Unmarshal(b []byte, sids *SIDs, opt schc.YANGOptions) (rs *schc.RuleSet, skipped []error, err error) {
	js, err := ToJSON(b, sids)
	if err != nil {
		return nil, nil, err
	}
	return schc.ParseYANGWith(js, opt)
}

var encMode = func() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode() // deterministic: sorted keys, shortest forms
	if err != nil {
		panic(err)
	}
	return m
}()

var decMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		MaxNestedLevels:  16,
		MaxArrayElements: 1 << 16,
		MaxMapPairs:      1 << 16,
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IntDec:           cbor.IntDecConvertNone,
		DefaultMapType:   nil,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// FromJSON converts ietf-schc instance data from RFC 7951 JSON to CBOR
// with SIDs.
func FromJSON(js []byte, sids *SIDs) ([]byte, error) {
	if sids == nil {
		sids = Default()
	}
	var top map[string]any
	dec := json.NewDecoder(strings.NewReader(string(js)))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("coreconf: %w", err)
	}
	out := map[uint64]any{}
	for k, v := range top {
		p := "/" + k
		sid, ok := sids.path[p]
		if !ok {
			return nil, fmt.Errorf("coreconf: no SID for %s", p)
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("coreconf: %s is not a container", p)
		}
		enc, err := sids.encNode(p, sid, m)
		if err != nil {
			return nil, err
		}
		out[sid] = enc
	}
	return encMode.Marshal(out)
}

func (s *SIDs) encNode(path string, parent uint64, m map[string]any) (map[uint64]any, error) {
	out := map[uint64]any{}
	for k, v := range m {
		name := k
		p := path + "/" + k
		if i := strings.IndexByte(k, ':'); i >= 0 {
			name = k[i+1:] // a member from another module (RFC 7951 4)
		}
		sid, ok := s.path[p]
		if !ok {
			return nil, fmt.Errorf("coreconf: no SID for %s", p)
		}
		if sid < parent {
			return nil, fmt.Errorf("coreconf: %s has a SID below its parent's", p)
		}
		var enc any
		var err error
		switch t := v.(type) {
		case map[string]any:
			enc, err = s.encNode(p, sid, t)
		case []any:
			list := make([]any, 0, len(t))
			for _, it := range t {
				im, ok := it.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("coreconf: %s holds a %T, not list entries", p, it)
				}
				e, err := s.encNode(p, sid, im)
				if err != nil {
					return nil, err
				}
				list = append(list, e)
			}
			enc = list
		default:
			enc, err = s.encLeaf(p, name, v)
		}
		if err != nil {
			return nil, err
		}
		out[sid-parent] = enc
	}
	return out, nil
}

func (s *SIDs) encLeaf(p, name string, v any) (any, error) {
	switch t := v.(type) {
	case string:
		switch {
		case binaryLeaves[name]:
			var b []byte
			if err := json.Unmarshal([]byte(strconv.Quote(t)), &b); err != nil {
				return nil, fmt.Errorf("coreconf: %s: %w", p, err)
			}
			return b, nil
		case identityLeaves[name] || unionLeaves[name]:
			sid, ok := s.identity[t]
			if !ok {
				return nil, fmt.Errorf("coreconf: %s: no SID for identity %s", p, t)
			}
			if unionLeaves[name] {
				return cbor.Tag{Number: tagIdentityref, Content: sid}, nil
			}
			return sid, nil
		}
		return t, nil
	case json.Number:
		n, err := strconv.ParseUint(t.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("coreconf: %s: %s is not an unsigned integer", p, t)
		}
		return n, nil
	case bool:
		return t, nil
	}
	return nil, fmt.Errorf("coreconf: %s: a %T leaf", p, v)
}

// ToJSON converts ietf-schc instance data from CBOR with SIDs to RFC 7951
// JSON.
func ToJSON(b []byte, sids *SIDs) ([]byte, error) {
	if sids == nil {
		sids = Default()
	}
	var top map[any]any
	if err := decMode.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("coreconf: %w", err)
	}
	out := map[string]any{}
	for k, v := range top {
		sid, err := uintOf(k)
		if err != nil {
			return nil, err
		}
		p, ok := sids.byPath[sid]
		if !ok {
			return nil, fmt.Errorf("coreconf: SID %d is not a known data node", sid)
		}
		m, ok := v.(map[any]any)
		if !ok {
			return nil, fmt.Errorf("coreconf: %s is not a map", p)
		}
		node, err := sids.decNode(p, sid, m, 0)
		if err != nil {
			return nil, err
		}
		out[strings.TrimPrefix(p, "/")] = node
	}
	return json.Marshal(out)
}

func uintOf(k any) (uint64, error) {
	switch t := k.(type) {
	case uint64:
		return t, nil
	case int64:
		if t >= 0 {
			return uint64(t), nil
		}
	}
	return 0, fmt.Errorf("coreconf: key %v is not a SID delta", k)
}

func (s *SIDs) decNode(path string, parent uint64, m map[any]any, depth int) (map[string]any, error) {
	if depth > 8 {
		return nil, errors.New("coreconf: nested too deep")
	}
	out := map[string]any{}
	keys := make([]uint64, 0, len(m))
	vals := map[uint64]any{}
	for k, v := range m {
		d, err := uintOf(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, d)
		vals[d] = v
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, d := range keys {
		if d > math.MaxUint64-parent {
			return nil, fmt.Errorf("coreconf: delta %d overflows", d)
		}
		sid := parent + d
		p, ok := s.byPath[sid]
		if !ok || !strings.HasPrefix(p, path+"/") || strings.Contains(p[len(path)+1:], "/") {
			return nil, fmt.Errorf("coreconf: SID %d (delta %d) is not a child of %s", sid, d, path)
		}
		name := p[len(path)+1:]
		key := name
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[i+1:]
		}
		switch t := vals[d].(type) {
		case map[any]any:
			n, err := s.decNode(p, sid, t, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = n
		case []any:
			list := make([]any, 0, len(t))
			for _, it := range t {
				im, ok := it.(map[any]any)
				if !ok {
					return nil, fmt.Errorf("coreconf: %s holds a %T, not list entries", p, it)
				}
				n, err := s.decNode(p, sid, im, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, n)
			}
			out[key] = list
		default:
			v, err := s.decLeaf(p, name, t)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
	}
	return out, nil
}

func (s *SIDs) decLeaf(p, name string, v any) (any, error) {
	ident := func(sid uint64) (any, error) {
		id, ok := s.byID[sid]
		if !ok {
			return nil, fmt.Errorf("coreconf: %s: SID %d is not a known identity", p, sid)
		}
		return id, nil
	}
	switch t := v.(type) {
	case []byte:
		if !binaryLeaves[name] {
			return nil, fmt.Errorf("coreconf: %s: a byte string", p)
		}
		return t, nil // base64 in JSON
	case cbor.Tag:
		if t.Number != tagIdentityref || !unionLeaves[name] {
			return nil, fmt.Errorf("coreconf: %s: tag %d", p, t.Number)
		}
		switch c := t.Content.(type) {
		case uint64:
			return ident(c)
		case string:
			return c, nil
		}
		return nil, fmt.Errorf("coreconf: %s: tag 45 holds a %T", p, t.Content)
	case uint64:
		if identityLeaves[name] {
			return ident(t)
		}
		return t, nil
	case string:
		if identityLeaves[name] || unionLeaves[name] {
			return t, nil // an identity by name (RFC 9254 6.10.2)
		}
		return nil, fmt.Errorf("coreconf: %s: a text string", p)
	case bool:
		return t, nil
	}
	return nil, fmt.Errorf("coreconf: %s: a %T", p, v)
}
