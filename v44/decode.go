// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import "fmt"

// bitReader reads codes least significant bit first (6.6).
type bitReader struct {
	in    []byte
	pos   int // bits read
	short bool
}

// bits reads n bits; ok is false at the end of the input (and short is
// set: a stream decoder then waits for more).
func (r *bitReader) bits(n uint) (v uint32, ok bool) {
	if r.pos+int(n) > len(r.in)*8 {
		r.short = true
		return 0, false
	}
	for i := uint(0); i < n; i++ {
		b := r.in[r.pos>>3] >> (r.pos & 7) & 1
		v |= uint32(b) << i
		r.pos++
	}
	return v, true
}

// str is one string-collection entry (6.2.2): the position in the output
// of its last character and its length.
type str struct{ last, length int }

// Kinds of the previous code, for string creation (Table 2).
const (
	prevNone = iota // after initialization or REINIT
	prevOrdinal
	prevCodeword
	prevExtension
)

// decoder is the decoder dictionary and state variables (Table 12).
type decoder struct {
	p       Params
	r       bitReader
	out     []byte
	base    int   // where the current history starts in out (REINIT)
	strs    []str // indexed by codeword
	c1      int
	c2, c5  uint
	n1      uint
	prev    int // prevNone … prevExtension
	prevLen int // length of the previous ordinal (1) or codeword's string
	prevCW  int
	stepup  bool // a STEPUP was received and not yet applied
	// afterCW is whether the last code was a codeword, which selects the
	// code prefixes of Table 5 (a STEPUP in between clears it, while it
	// does not change string creation: Table 2).
	afterCW  bool
	flushed  bool
	onString func(cw int, s str) // test hook: a string was created

	// The multi-packet and stream methods.
	callStart int  // where this call's output starts in out
	stream    bool // FLUSH aligns and decoding goes on; ETM enters transparent mode
	mode      int  // modeCompressed, modeTransparent, modeParameter (stream)
	escape    byte // the current ESCAPE (7.14)
	params    []Parameter
	onParams  func([]Parameter)
	raw       bool // the packet was the annex B uncompressed form
}

// Decoder modes (6.5, 7.4.2).
const (
	modeCompressed = iota
	modeTransparent
	modeParameter
)

// trim drops the output before the current history, keeping string
// positions, so that a long-lived decoder does not grow without bound.
func (d *decoder) trim() {
	if d.base == 0 {
		return
	}
	for i := firstCW; i < len(d.strs); i++ {
		d.strs[i].last -= d.base
	}
	d.out = append(d.out[:0:0], d.out[d.base:]...)
	d.base = 0
}

// Decompress decodes one packet compressed with the packet method. An
// input whose first code is ETM is the annex B uncompressed form: the
// octets after the first are returned as they are.
func Decompress(p Params, src []byte) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	d := newDecoder(p.withDefaults(), src)
	if err := d.run(); err != nil {
		return nil, err
	}
	return d.out, nil
}

func newDecoder(p Params, src []byte) *decoder {
	d := &decoder{p: p, r: bitReader{in: src}, n1: p.maxCodewordBits()}
	d.reset()
	return d
}

// reset puts the dictionary in its initial state (7.5.2); the history
// starts after what is already decoded.
func (d *decoder) reset() {
	d.base = len(d.out)
	d.strs = d.strs[:0]
	for len(d.strs) < firstCW {
		d.strs = append(d.strs, str{})
	}
	d.c1, d.c2, d.c5 = firstCW, initC2, initC5
	d.prev, d.prevLen, d.prevCW, d.stepup, d.afterCW = prevNone, 0, 0, false, false
}

func (d *decoder) corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s (at bit %d)", ErrCorrupt, fmt.Sprintf(format, args...), d.r.pos)
}

// run decodes codes until FLUSH.
func (d *decoder) run() error {
	for !d.flushed {
		if err := d.step(); err != nil {
			return err
		}
	}
	return nil
}

// step decodes one code (6.4.1).
func (d *decoder) step() error {
	prefix, ok := d.r.bits(1)
	if !ok {
		return d.corrupt("the data ends without a FLUSH control code")
	}
	if prefix == 1 {
		if d.stepup {
			// A STEPUP followed by a codeword or control code raised the
			// codeword size (7.11.2).
			d.stepup = false
			if d.c2+1 > d.n1 {
				return d.corrupt("STEPUP beyond the maximum codeword size N1 = %d", d.n1)
			}
			d.c2++
		}
		v, ok := d.r.bits(d.c2)
		if !ok {
			return d.corrupt("the data ends inside a codeword")
		}
		if v < firstCW {
			// After a control code the prefixes are those of Table 5's
			// "otherwise" column.
			d.afterCW = false
			return d.control(v)
		}
		return d.codeword(int(v))
	}
	if d.afterCW {
		second, ok := d.r.bits(1)
		if !ok {
			return d.corrupt("the data ends inside a code prefix")
		}
		if second == 1 {
			return d.extension()
		}
	}
	return d.ordinal()
}

// control handles a control code (Table 8).
func (d *decoder) control(v uint32) error {
	switch v {
	case ctlETM:
		if d.stream {
			// 6.5.1: transparent mode from the next octet.
			if d.stepup {
				return d.corrupt("ETM straight after STEPUP")
			}
			d.alignRead()
			d.mode = modeTransparent
			return nil
		}
		// Annex B: ETM with its prefix at the start of a packet says the
		// rest is the original data, octet-aligned. Transparent mode is
		// not part of the packet methods.
		if d.r.pos != 1+int(d.c2) || len(d.out) != d.callStart {
			return d.corrupt("ETM inside a packet (transparent mode is not used by the packet methods)")
		}
		d.alignRead()
		rest := d.r.in[d.r.pos/8:]
		if len(rest) > d.p.Limit {
			return fmt.Errorf("%w (%d octets)", ErrLimit, len(rest))
		}
		d.out = append(d.out, rest...)
		d.flushed, d.raw = true, true
	case ctlFLUSH:
		if d.stepup {
			return d.corrupt("FLUSH straight after STEPUP")
		}
		if d.stream {
			d.alignRead() // 7.13: the next code starts on an octet
			return nil
		}
		d.flushed = true
	case ctlSTEPUP:
		if d.stepup {
			// STEPUP STEPUP: the first raised C2 before this one was read
			// (step already applied it), so this cannot happen here.
			return d.corrupt("two STEPUP control codes pending")
		}
		d.stepup = true
		d.afterCW = false
	case ctlREINIT:
		if d.stepup {
			return d.corrupt("REINIT straight after STEPUP")
		}
		d.reset()
	}
	return nil
}

// alignRead skips to the next octet boundary.
func (d *decoder) alignRead() { d.r.pos = (d.r.pos + 7) &^ 7 }

// room checks that n more characters fit the limit and the history.
func (d *decoder) room(n int) error {
	if len(d.out)-d.callStart+n > d.p.Limit {
		return fmt.Errorf("%w (%d octets)", ErrLimit, d.p.Limit)
	}
	if d.p.History > 0 && len(d.out)+n-d.base > d.p.History {
		return d.corrupt("the history would exceed N8 = %d without a REINIT", d.p.History)
	}
	return nil
}

// create adds a string ending at last of the given length, unless the
// string collection is full (B.1.1) or the string would be longer than N7
// (Table 2 note).
func (d *decoder) create(last, length int) {
	if d.c1 >= d.p.Codewords || length > d.p.MaxString {
		return
	}
	s := str{last: last, length: length}
	d.strs = append(d.strs, s)
	d.c1++
	if d.onString != nil {
		d.onString(d.c1-1, s)
	}
}

// createFromPrevious applies Table 2 when an ordinal or a codeword starts
// at position at: after an ordinal or a codeword, the previous string (or
// character) gains the first character of this one.
func (d *decoder) createFromPrevious(at int) {
	if d.prev == prevOrdinal || d.prev == prevCodeword {
		d.create(at, d.prevLen+1)
	}
}

// ordinal handles an ordinal, applying a pending ordinal STEPUP (7.11.1).
func (d *decoder) ordinal() error {
	if d.stepup {
		d.stepup = false
		if d.c5 == 8 {
			return d.corrupt("STEPUP beyond the 8-bit ordinal size")
		}
		d.c5 = 8
	}
	v, ok := d.r.bits(d.c5)
	if !ok {
		return d.corrupt("the data ends inside an ordinal")
	}
	if err := d.room(1); err != nil {
		return err
	}
	d.createFromPrevious(len(d.out))
	d.out = append(d.out, byte(v))
	d.prev, d.prevLen, d.afterCW = prevOrdinal, 1, false
	return nil
}

// codeword handles a codeword, including the one equal to C1 (6.4.1 rules
// 3 and 4): creating the pending string first makes it defined, and the
// forward copy then repeats its first character.
func (d *decoder) codeword(cw int) error {
	if cw > d.c1 {
		return d.corrupt("codeword %d is beyond the next codeword C1 = %d", cw, d.c1)
	}
	at := len(d.out)
	d.createFromPrevious(at)
	if cw >= d.c1 {
		return d.corrupt("codeword %d is not defined yet (C1 = %d)", cw, d.c1)
	}
	s := d.strs[cw]
	if err := d.room(s.length); err != nil {
		return err
	}
	for i, from := 0, s.last-s.length+1; i < s.length; i++ {
		d.out = append(d.out, d.out[from+i])
	}
	d.prev, d.prevLen, d.prevCW, d.afterCW = prevCodeword, s.length, cw, true
	return nil
}

// extension handles a string-extension length (6.4.1 rule 5): the
// characters after the previous codeword's string in the history are
// copied, and the extended string is created (Table 2).
func (d *decoder) extension() error {
	k, err := d.readExtension()
	if err != nil {
		return err
	}
	s := d.strs[d.prevCW]
	if s.length+k > d.p.MaxString {
		return d.corrupt("string extension to %d characters is longer than N7 = %d", s.length+k, d.p.MaxString)
	}
	if err := d.room(k); err != nil {
		return err
	}
	for i := 0; i < k; i++ {
		d.out = append(d.out, d.out[s.last+1+i])
	}
	d.create(len(d.out)-1, s.length+k)
	d.prev, d.afterCW = prevExtension, false
	return nil
}

// readExtension reads the subfields of a string-extension length (Tables 3
// and 4).
func (d *decoder) readExtension() (int, error) {
	read := func(n uint) (int, error) {
		v, ok := d.r.bits(n)
		if !ok {
			return 0, d.corrupt("the data ends inside a string-extension length")
		}
		return int(v), nil
	}
	b, err := read(1)
	if err != nil || b == 1 {
		return 1, err
	}
	v, err := read(2)
	if err != nil {
		return 0, err
	}
	if v != 0 {
		return v + 1, nil
	}
	b, err = read(1)
	if err != nil {
		return 0, err
	}
	if b == 0 {
		v, err = read(3)
		return v + 5, err
	}
	v, err = read(extensionBits(d.p.MaxString))
	return v + 13, err
}
