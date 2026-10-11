// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import "bytes"

// bitWriter packs codes least significant bit first, starting at bit 1 of
// each octet (6.6, Table 6).
type bitWriter struct {
	out  []byte
	acc  uint64
	nacc uint
}

// bits writes the n low bits of v, least significant first.
func (w *bitWriter) bits(v uint32, n uint) {
	w.acc |= uint64(v&(1<<n-1)) << w.nacc
	w.nacc += n
	for w.nacc >= 8 {
		w.out = append(w.out, byte(w.acc))
		w.acc >>= 8
		w.nacc -= 8
	}
}

// bit writes one bit.
func (w *bitWriter) bit(b uint32) { w.bits(b, 1) }

// align writes zero bits up to the next octet boundary.
func (w *bitWriter) align() {
	if w.nacc > 0 {
		w.out = append(w.out, byte(w.acc))
		w.acc, w.nacc = 0, 0
	}
}

// node is one encoder node-tree entry (6.2.1): the string-segment at
// history[pos : pos+length], the first node that follows it (down) and the
// next node at its own level (side); -1 is no node.
type node struct {
	pos, length int
	down, side  int
}

// encoder is the encoder dictionary and state variables (Table 12).
type encoder struct {
	p     Params
	w     bitWriter
	src   []byte // the history: the packet's characters
	root  [256]int
	nodes []node // indexed by codeword; entries below firstCW unused
	c1    int    // next codeword
	c2    uint   // codeword size
	c3    int    // codeword size threshold
	c5    uint   // ordinal size
	// afterCodeword is whether the last code transferred was a codeword,
	// which selects the code prefixes of Table 5.
	afterCodeword bool
}

// reset puts the dictionary in its initial state (7.5.1).
func (e *encoder) reset() {
	for i := range e.root {
		e.root[i] = -1
	}
	e.nodes = e.nodes[:firstCW]
	e.c1, e.c2, e.c3, e.c5 = firstCW, initC2, initC3, initC5
	e.afterCodeword = false
}

// Compress compresses one packet with the packet method: reset, encode,
// FLUSH, pad to an octet boundary.
func Compress(p Params, src []byte) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	e := newEncoder(p.withDefaults(), src)
	e.run()
	return e.w.out, nil
}

// CompressOrRaw returns the smaller of the compressed packet and the annex
// B uncompressed form (the ETM control code with its prefix in the first
// octet, then src), and whether it is compressed.
func CompressOrRaw(p Params, src []byte) ([]byte, bool, error) {
	c, err := Compress(p, src)
	if err != nil {
		return nil, false, err
	}
	if len(c) <= len(src)+1 {
		return c, true, nil
	}
	return append([]byte{rawIndicator}, src...), false, nil
}

// rawIndicator is the first octet of an uncompressed packet: code prefix
// "1", ETM (0) in the initial 6-bit codeword size, one bit of padding.
const rawIndicator = 0x01

func newEncoder(p Params, src []byte) *encoder {
	e := &encoder{p: p, src: src, nodes: make([]node, firstCW, 64)}
	e.reset()
	return e
}

// run encodes the whole packet, in runs of at most N8 characters when N8
// is set (each ended as if the history were full, then REINIT: 7.11.4,
// 7.12, B.2.1), and ends it with FLUSH (7.13).
func (e *encoder) run() {
	start := 0
	for start < len(e.src) {
		end := len(e.src)
		if e.p.History > 0 && end-start > e.p.History {
			end = start + e.p.History
		}
		e.encodeRun(start, end)
		start = end
		if start < len(e.src) {
			e.control(ctlREINIT)
			e.reset()
		}
	}
	e.control(ctlFLUSH)
	e.w.align()
}

// encodeRun encodes src[start:end] against a dictionary that covers only
// that run (6.3).
func (e *encoder) encodeRun(start, end int) {
	src := e.src
	n7 := e.p.MaxString
	for i := start; i < end; {
		c := src[i]
		// String matching (6.3.1): climb down from the root, taking at each
		// level the longest string-segment that the next characters match
		// completely.
		cur, j := -1, i+1
		for child := e.root[c]; child >= 0; {
			best, bestLen := -1, 0
			for n := child; n >= 0; n = e.nodes[n].side {
				nd := &e.nodes[n]
				if nd.length > bestLen && j+nd.length <= end && bytes.Equal(src[nd.pos:nd.pos+nd.length], src[j:j+nd.length]) {
					best, bestLen = n, nd.length
				}
			}
			if best < 0 {
				break
			}
			cur, j = best, j+bestLen
			child = e.nodes[best].down
		}
		if cur < 0 {
			// Matching failed: the ordinal, and the next character appended
			// to the root (Table 1, first row).
			e.ordinal(c)
			if i+1 < end {
				e.appendRoot(c, i+1)
			}
			i++
			continue
		}
		e.codeword(cur)
		// String extension (6.3.2) against the history after the last
		// matched string-segment, while the string stays within N7.
		total := j - i
		from := e.nodes[cur].pos + e.nodes[cur].length
		k := 0
		for j+k < end && total+k < n7 && src[from+k] == src[j+k] {
			k++
		}
		if k > 0 {
			e.extensionLength(k)
			e.child(cur, j, k)
			i = j + k
			continue
		}
		// Extension failed: the unmatched character is appended to the
		// last matched string-segment, unless the string is already N7
		// long (Table 2 note).
		if j < end && total < n7 {
			e.child(cur, j, 1)
		}
		i = j
	}
}

// newNode creates the next codeword's node, unless the node-tree is full:
// then the packet method creates no more (B.1.1). It returns -1 then.
func (e *encoder) newNode(pos, length int) int {
	if e.c1 >= e.p.Codewords {
		return -1
	}
	e.nodes = append(e.nodes, node{pos: pos, length: length, down: -1, side: -1})
	e.c1++
	return len(e.nodes) - 1
}

// appendRoot creates a 1-character string-segment after root c.
func (e *encoder) appendRoot(c byte, pos int) {
	n := e.newNode(pos, 1)
	if n < 0 {
		return
	}
	e.root[c] = e.link(e.root[c], n)
}

// link adds node n at the end of the sibling list that starts at first,
// the order the Appendix II tables show, and returns the list's head.
func (e *encoder) link(first, n int) int {
	if first < 0 {
		return n
	}
	last := first
	for e.nodes[last].side >= 0 {
		last = e.nodes[last].side
	}
	e.nodes[last].side = n
	return first
}

// child creates a string-segment following node parent.
func (e *encoder) child(parent, pos, length int) {
	n := e.newNode(pos, length)
	if n < 0 {
		return
	}
	e.nodes[parent].down = e.link(e.nodes[parent].down, n)
}

// control transfers a control code: prefix "1", then C2 bits.
func (e *encoder) control(code uint32) {
	e.w.bit(1)
	e.w.bits(code, e.c2)
	e.afterCodeword = false
}

// ordinal transfers a character, first stepping the ordinal size up to 8
// bits for the first one above 127 (7.11.1).
func (e *encoder) ordinal(c byte) {
	if c > 127 && e.c5 == 7 {
		e.control(ctlSTEPUP)
		e.c5 = 8
	}
	if e.afterCodeword {
		e.w.bit(0)
	}
	e.w.bit(0)
	e.w.bits(uint32(c), e.c5)
	e.afterCodeword = false
}

// codeword transfers a codeword, stepping the codeword size up as often as
// it needs (7.11.2).
func (e *encoder) codeword(cw int) {
	for cw >= e.c3 {
		e.control(ctlSTEPUP)
		e.c2++
		e.c3 <<= 1
	}
	e.w.bit(1)
	e.w.bits(uint32(cw), e.c2)
	e.afterCodeword = true
}

// extensionLength transfers a string-extension length (6.6.2, Tables 3
// and 4) after its prefix "0" "1".
func (e *encoder) extensionLength(k int) {
	e.w.bit(0)
	e.w.bit(1)
	e.w.writeExtension(k, e.p.MaxString)
	e.afterCodeword = false
}

// writeExtension writes the subfields of a string-extension length k for
// maximum string length n7.
func (w *bitWriter) writeExtension(k, n7 int) {
	switch {
	case k == 1:
		w.bit(1)
	case k <= 4:
		w.bit(0)
		w.bits(uint32(k-1), 2)
	case k <= 12:
		w.bit(0)
		w.bits(0, 2)
		w.bit(0)
		w.bits(uint32(k-5), 3)
	default:
		w.bit(0)
		w.bits(0, 2)
		w.bit(1)
		w.bits(uint32(k-13), extensionBits(n7))
	}
}

// extensionBits is the width of the last subfield of lengths 13 and above
// (Table 4).
func extensionBits(n7 int) uint {
	switch {
	case n7 <= 46:
		return 5
	case n7 <= 78:
		return 6
	case n7 <= 142:
		return 7
	}
	return 8
}
