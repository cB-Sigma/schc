// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"math/bits"
)

// Context is what the decompressor learns from the L2 (RFC 8724 7.4.7):
// the Dev's and the App's interface identifiers, 8 bytes each when known.
type Context struct {
	DevIID []byte
	AppIID []byte
}

// ErrNoRule is returned when no compression rule fits and the rule set has
// no no-compression rule.
var ErrNoRule = errors.New("schc: no rule compresses this packet and there is no no-compression rule")

// Compress parses raw with st and compresses it with the first rule that
// fits (RFC 8724 7.2), or sends it whole under the no-compression rule.
// The result is the SCHC Packet: RuleID, residue, payload (not padded).
func (rs *RuleSet) Compress(st Stack, raw []byte, dir Direction, ctx Context) (Bits, *Rule, error) {
	if p, err := st.Parse(raw, dir); err == nil {
		for i := range rs.Rules {
			r := &rs.Rules[i]
			if r.Kind != KindCompression {
				continue
			}
			if out, ok := r.compress(st, p, dir, ctx); ok {
				return out, r, nil
			}
		}
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.Kind == KindNoCompression {
			out := r.idBits()
			out.AppendBytes(raw)
			return out, r, nil
		}
	}
	return Bits{}, nil, ErrNoRule
}

// CompressPacket compresses fields a caller labelled itself (no stack:
// compute CDAs are not checked) with the first rule that fits.
func (rs *RuleSet) CompressPacket(p Packet, dir Direction, ctx Context) (Bits, *Rule, error) {
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.Kind != KindCompression {
			continue
		}
		if out, ok := r.compress(nil, p, dir, ctx); ok {
			return out, r, nil
		}
	}
	return Bits{}, nil, ErrNoRule
}

// applies reports whether a descriptor is for this direction.
func (f *FieldDescriptor) applies(dir Direction) bool { return f.DI == Bi || f.DI == dir }

// pair matches a rule's descriptors to a packet's fields by FID, DI and FP
// (RFC 8724 7.2): every field to exactly one descriptor and back.
func (r *Rule) pair(p Packet, dir Direction) ([]*FieldDescriptor, []Field, bool) {
	used := make([]bool, len(p.Fields))
	var fds []*FieldDescriptor
	var fs []Field
	for i := range r.Fields {
		fd := &r.Fields[i]
		if !fd.applies(dir) {
			continue
		}
		found := -1
		for j, f := range p.Fields {
			if !used[j] && f.FID == fd.FID && (fd.fp == 0 || fd.fp == f.Pos) {
				found = j
				break
			}
		}
		if found < 0 {
			return nil, nil, false
		}
		used[found] = true
		fds = append(fds, fd)
		fs = append(fs, p.Fields[found])
	}
	for _, u := range used {
		if !u {
			return nil, nil, false
		}
	}
	return fds, fs, true
}

// compress applies the rule's matching operators and actions; false when
// the rule does not fit.
func (r *Rule) compress(st Stack, p Packet, dir Direction, ctx Context) (Bits, bool) {
	fds, fs, ok := r.pair(p, dir)
	if !ok {
		return Bits{}, false
	}
	out := r.idBits()
	for i, fd := range fds {
		v := fs[i].Value
		if fd.Var == "" && v.Len() != fd.FL {
			return Bits{}, false
		}
		if fd.Var == "bytes" && v.Len()%8 != 0 {
			return Bits{}, false
		}
		if !fd.matches(v) {
			return Bits{}, false
		}
		switch fd.CDA {
		case CDANotSent:
			// With MO ignore the value may differ from the TV (RFC 8724
			// 7.4.3 allows it; the decompressed field is then the TV).
		case CDAValueSent:
			if fd.Var != "" {
				if !appendSize(&out, v.Len(), fd.Var) {
					return Bits{}, false
				}
			}
			out.Append(v)
		case CDAMappingSent:
			idx := -1
			for k, t := range fd.tv {
				if t.Equal(v) {
					idx = k
					break
				}
			}
			out.AppendUint(uint64(idx), indexBits(len(fd.tv)))
		case CDALSB:
			lsb := v.Slice(fd.MOArg, v.Len())
			if fd.Var != "" {
				if !appendSize(&out, lsb.Len(), fd.Var) {
					return Bits{}, false
				}
			}
			out.Append(lsb)
		case CDACompute:
			// Elided only when the decompressor rebuilds the same value.
			if st != nil {
				if c, ok := st.computeValue(fd.FID, p, dir); !ok || !c.Equal(v) {
					return Bits{}, false
				}
			} else if !computed[fd.FID] {
				return Bits{}, false
			}
		case CDADevIID, CDAAppIID:
			// Elided only when the L2 gives back the same IID; a rule
			// that would change the address is not used (RFC 8724
			// 12.1.3).
			iid := ctx.DevIID
			if fd.CDA == CDAAppIID {
				iid = ctx.AppIID
			}
			if len(iid) != v.Len()/8 || !BytesOf(iid).Equal(v) {
				return Bits{}, false
			}
		}
	}
	out.AppendBytes(p.Payload)
	return out, true
}

// matches applies the matching operator (RFC 8724 7.3).
func (fd *FieldDescriptor) matches(v Bits) bool {
	switch fd.MO {
	case MOIgnore:
		return true
	case MOEqual:
		return fd.tv[0].Equal(v)
	case MOMSB:
		if v.Len() < fd.MOArg || fd.tv[0].Len() < fd.MOArg {
			return false
		}
		return fd.tv[0].Slice(0, fd.MOArg).Equal(v.Slice(0, fd.MOArg))
	case MOMatchMapping:
		for _, t := range fd.tv {
			if t.Equal(v) {
				return true
			}
		}
	}
	return false
}

// indexBits is the smallest number of bits that codes n indices
// (RFC 8724 7.4.5).
func indexBits(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n - 1))
}

// appendSize writes a variable-length residue's size in its unit
// (RFC 8724 7.4.2): 4 bits up to 14, 1111 and 8 bits up to 254, else 12
// ones and 16 bits.
func appendSize(out *Bits, nbits int, unit string) bool {
	n := nbits
	if unit == "bytes" {
		n = nbits / 8
	}
	switch {
	case n < 15:
		out.AppendUint(uint64(n), 4)
	case n < 255:
		out.AppendUint(0xF, 4)
		out.AppendUint(uint64(n), 8)
	case n <= 0xFFFF:
		out.AppendUint(0xFFF, 12)
		out.AppendUint(uint64(n), 16)
	default:
		return false
	}
	return true
}

func readSize(r *reader, unit string) (int, error) {
	n, err := r.uint(4)
	if err != nil {
		return 0, err
	}
	if n == 0xF {
		if n, err = r.uint(8); err != nil {
			return 0, err
		}
		if n == 0xFF {
			if n, err = r.uint(16); err != nil {
				return 0, err
			}
		}
	}
	if unit == "bytes" {
		n *= 8
	}
	return int(n), nil
}

// Decompress reads a SCHC Packet (possibly followed by padding of less than
// one L2 Word) and rebuilds the original packet with st (RFC 8724 7.2).
func (rs *RuleSet) Decompress(st Stack, msg Bits, dir Direction, ctx Context) ([]byte, *Rule, error) {
	r, err := rs.match(msg)
	if err != nil {
		return nil, nil, err
	}
	rd := &reader{x: msg, pos: r.IDLength}
	switch r.Kind {
	case KindNoCompression:
		n := rd.rem() / 8
		if n > rs.MaxPacketSize {
			return nil, r, fmt.Errorf("schc: packet of %d bytes is over maxPacketSize", n)
		}
		b, _ := rd.bits(8 * n)
		return b.Bytes(), r, nil
	case KindFragmentation:
		return nil, r, fmt.Errorf("schc: rule %d is a fragmentation rule", r.ID)
	}
	fields, payload, err := r.decompress(rd, dir, ctx, rs.MaxPacketSize)
	if err != nil {
		return nil, r, err
	}
	vals := map[string]Bits{}
	for _, f := range fields {
		if _, known := fieldLengths[f.FID]; !known {
			return nil, r, fmt.Errorf("schc: field %s is not of the %s stack", f.FID, st)
		}
		if f.Value.Len() == 0 && computed[f.FID] {
			continue // compute: rebuilt by Build
		}
		vals[f.FID] = f.Value
	}
	out, err := st.Build(vals, payload, dir)
	if err != nil {
		return nil, r, err
	}
	if len(out) > rs.MaxPacketSize {
		return nil, r, fmt.Errorf("schc: packet of %d bytes is over maxPacketSize", len(out))
	}
	return out, r, nil
}

// DecompressPacket reads a SCHC Packet into labelled fields and payload
// without a stack (compute fields come back empty).
func (rs *RuleSet) DecompressPacket(msg Bits, dir Direction, ctx Context) (Packet, *Rule, error) {
	r, err := rs.match(msg)
	if err != nil {
		return Packet{}, nil, err
	}
	if r.Kind != KindCompression {
		return Packet{}, r, fmt.Errorf("schc: rule %d is not a compression rule", r.ID)
	}
	fields, payload, err := r.decompress(&reader{x: msg, pos: r.IDLength}, dir, ctx, rs.MaxPacketSize)
	return Packet{Fields: fields, Payload: payload}, r, err
}

func (r *Rule) decompress(rd *reader, dir Direction, ctx Context, maxSize int) ([]Field, []byte, error) {
	var fields []Field
	pos := map[string]int{}
	for i := range r.Fields {
		fd := &r.Fields[i]
		if !fd.applies(dir) {
			continue
		}
		var v Bits
		var err error
		switch fd.CDA {
		case CDANotSent:
			v = fd.tv[0]
		case CDAValueSent:
			n := fd.FL
			if fd.Var != "" {
				if n, err = readSize(rd, fd.Var); err != nil {
					return nil, nil, err
				}
			}
			v, err = rd.bits(n)
		case CDAMappingSent:
			var idx uint64
			if idx, err = rd.uint(indexBits(len(fd.tv))); err == nil {
				if int(idx) >= len(fd.tv) {
					return nil, nil, fmt.Errorf("schc: field %s: mapping index %d is out of the list", fd.FID, idx)
				}
				v = fd.tv[idx]
			}
		case CDALSB:
			n := fd.FL - fd.MOArg
			if fd.Var != "" {
				if n, err = readSize(rd, fd.Var); err != nil {
					return nil, nil, err
				}
			}
			var lsb Bits
			if lsb, err = rd.bits(n); err == nil {
				v = fd.tv[0].Slice(0, fd.MOArg)
				v.Append(lsb)
			}
		case CDACompute:
			// Rebuilt from the other fields (applied last, RFC 8724 7.2).
		case CDADevIID, CDAAppIID:
			iid := ctx.DevIID
			if fd.CDA == CDAAppIID {
				iid = ctx.AppIID
			}
			if len(iid) == 0 {
				return nil, nil, fmt.Errorf("schc: field %s: the %s is not known", fd.FID, fd.CDA)
			}
			v = BytesOf(append([]byte(nil), iid...))
		}
		if err != nil {
			return nil, nil, fmt.Errorf("schc: field %s: %w", fd.FID, err)
		}
		p := fd.fp
		if p == 0 {
			p = pos[fd.FID] + 1
		}
		pos[fd.FID] = max(pos[fd.FID], p)
		fields = append(fields, Field{FID: fd.FID, Pos: p, Value: v})
	}
	// Whole payload bytes; what is left is padding (fewer bits than a
	// byte, RFC 8724 clause 9).
	n := rd.rem() / 8
	if n > maxSize {
		return nil, nil, fmt.Errorf("schc: payload of %d bytes is over maxPacketSize", n)
	}
	b, _ := rd.bits(8 * n)
	return fields, b.Bytes(), nil
}
