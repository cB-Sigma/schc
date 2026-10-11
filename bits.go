// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"strings"
)

// Bits is a string of bits, most significant bit of the first byte first.
// SCHC works on bits, not bytes (RFC 8724 clause 9): residues, headers and
// tiles need not be whole bytes.
type Bits struct {
	b []byte
	n int
}

// BitsOf is the first n bits of b (b is not copied).
func BitsOf(b []byte, n int) Bits {
	if n > 8*len(b) {
		n = 8 * len(b)
	}
	if n < 0 {
		n = 0
	}
	return Bits{b: b, n: n}
}

// BytesOf is every bit of b.
func BytesOf(b []byte) Bits { return Bits{b: b, n: 8 * len(b)} }

// Uint is v in n bits (n up to 64).
func Uint(v uint64, n int) Bits {
	var x Bits
	x.AppendUint(v, n)
	return x
}

// Len is the number of bits.
func (x Bits) Len() int { return x.n }

// Bytes returns the bits zero-extended to whole bytes (a copy).
func (x Bits) Bytes() []byte {
	out := make([]byte, (x.n+7)/8)
	copy(out, x.b)
	if r := x.n % 8; r != 0 {
		out[len(out)-1] &= byte(0xFF << (8 - r))
	}
	return out
}

// Bit is bit i (0 or 1).
func (x Bits) Bit(i int) uint8 { return (x.b[i/8] >> (7 - uint(i%8))) & 1 }

// AppendBit appends one bit.
func (x *Bits) AppendBit(v uint8) {
	if x.n%8 == 0 {
		x.b = append(x.b[:x.n/8:x.n/8], 0)
	}
	if v != 0 {
		x.b[x.n/8] |= 0x80 >> uint(x.n%8)
	}
	x.n++
}

// AppendUint appends the n low bits of v, most significant first.
func (x *Bits) AppendUint(v uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		x.AppendBit(uint8(v >> uint(i) & 1))
	}
}

// Append appends y.
func (x *Bits) Append(y Bits) {
	if x.n%8 == 0 && y.n%8 == 0 {
		x.b = append(x.b[:x.n/8:x.n/8], y.b[:y.n/8]...)
		x.n += y.n
		return
	}
	for i := 0; i < y.n; i++ {
		x.AppendBit(y.Bit(i))
	}
}

// AppendBytes appends every bit of b.
func (x *Bits) AppendBytes(b []byte) { x.Append(BytesOf(b)) }

// Slice is bits [from, to) (a copy).
func (x Bits) Slice(from, to int) Bits {
	var y Bits
	if from%8 == 0 {
		nb := (to - from + 7) / 8
		y.b = append([]byte(nil), x.b[from/8:from/8+nb]...)
		y.n = to - from
		if r := y.n % 8; r != 0 {
			y.b[len(y.b)-1] &= byte(0xFF << (8 - r))
		}
		return y
	}
	for i := from; i < to; i++ {
		y.AppendBit(x.Bit(i))
	}
	return y
}

// UintAt reads n bits (up to 64) at bit offset from.
func (x Bits) UintAt(from, n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<1 | uint64(x.Bit(from+i))
	}
	return v
}

// Equal reports whether x and y hold the same bits.
func (x Bits) Equal(y Bits) bool {
	if x.n != y.n {
		return false
	}
	for i := 0; i < x.n; i++ {
		if x.Bit(i) != y.Bit(i) {
			return false
		}
	}
	return true
}

// Clone copies x.
func (x Bits) Clone() Bits { return x.Slice(0, x.n) }

// Pad appends zero bits up to a multiple of word bits and returns how
// many were added (RFC 8724 clause 9: fewer than one L2 Word; RFC 9011
// 5.4: always zero).
func (x *Bits) Pad(word int) int {
	if word <= 1 {
		return 0
	}
	k := (word - x.n%word) % word
	x.AppendUint(0, k)
	return k
}

// String shows the bits as 0 and 1, for tests and logs.
func (x Bits) String() string {
	var sb strings.Builder
	for i := 0; i < x.n; i++ {
		sb.WriteByte('0' + x.Bit(i))
	}
	return sb.String()
}

// ParseBits reads a string of 0 and 1 (spaces ignored), for tests.
func ParseBits(s string) (Bits, error) {
	var x Bits
	for _, c := range s {
		switch c {
		case '0', '1':
			x.AppendBit(uint8(c - '0'))
		case ' ', '_':
		default:
			return Bits{}, fmt.Errorf("%q is not a bit", c)
		}
	}
	return x, nil
}

var errShort = errors.New("schc: message too short")

// reader reads a Bits front to back.
type reader struct {
	x   Bits
	pos int
}

func (r *reader) rem() int { return r.x.n - r.pos }

func (r *reader) uint(n int) (uint64, error) {
	if n > r.rem() {
		return 0, errShort
	}
	v := r.x.UintAt(r.pos, n)
	r.pos += n
	return v, nil
}

func (r *reader) bits(n int) (Bits, error) {
	if n > r.rem() {
		return Bits{}, errShort
	}
	b := r.x.Slice(r.pos, r.pos+n)
	r.pos += n
	return b, nil
}

func (r *reader) rest() Bits { b := r.x.Slice(r.pos, r.x.n); r.pos = r.x.n; return b }
