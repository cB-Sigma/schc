// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package v44 is the ITU-T V.44 (11/2000, with Corrigendum 1 of 03/2002)
// data compression algorithm, packet method (annex B.1), in pure Go.
//
// Each call to Compress or Decompress is one packet: the dictionaries start
// in their initial state (7.5.1, 7.5.2), the encoder ends the packet with a
// FLUSH control code and zero bits up to the next octet boundary (7.13,
// B.1.1), and the decoder stops at the FLUSH, treating whatever follows it
// as padding. RFC 3051 (IPComp with V.44, clauses 2.1, 2.3 and 3.1) reads
// annex B.1 the same way: reset before every packet, flush after its last
// byte, whole octets.
//
// What is built, clause by clause:
//
//   - encoder dictionary of root array, node-tree and history (6.2.1);
//     decoder string collection and history (6.2.2);
//   - string matching down the tree-structures, string extension against
//     the history, and the append and extend rules for new string-segments
//     (6.3.1 to 6.3.4, Table 1);
//   - decoding of ordinals, codewords (including the codeword the decoder
//     has not created yet, 6.4.1 rules 3 and 4) and string-extension
//     lengths, with the string-creation rules of Table 2 (6.4);
//   - code prefixes (Table 5), control codes and codewords in C2 bits,
//     ordinals in C5 bits (6.6.1), string-extension lengths (Tables 3 and
//     4), least significant bit first (6.6, Table 6);
//   - STEPUP of the ordinal size (7.11.1) and of the codeword size
//     (7.11.2); the node-tree full rule of the packet method (B.1.1: no new
//     codewords, matching and extension go on); FLUSH (7.13); the decoder's
//     error conditions (7.15);
//   - the annex B indicator for a packet sent uncompressed (the ETM control
//     code with its prefix in the first octet, then the original octets).
//
// Parameters are the clause 8 set that matters to the packet method, with
// the B.1.2 defaults: N2 = 1525 codewords, N7 = 255. N8 (history size) is
// "not applicable" in the packet method, where the packet itself is the
// history; setting it bounds the history, and a packet longer than N8 is
// then coded as runs of N8 characters separated by REINIT control codes,
// as the multi-packet method does when its history fills (B.2.1, 7.11.4).
// The decoder also honours REINIT wherever it appears. The initial
// codeword size (6 bits) and ordinal size (7 bits) are fixed by 7.5 and are
// not parameters. Transparent mode (6.5) is not part of the packet method
// (annex B) and is not built; neither is the stream method.
//
// The decoder never panics on bad input and always ends: every code
// consumes at least one bit, and the output is bounded by Params.Limit.
package v44

import (
	"errors"
	"fmt"
	"math/bits"
)

// Params are the V.44 parameters one encoder and its peer decoder share.
// The zero value of a field means its default.
type Params struct {
	// Codewords is N2, the number of codewords including the four control
	// codes (Table 10: 256 to 65535; B.1.2 default 1525).
	Codewords int
	// MaxString is N7, the maximum string length (Table 10: 32 to 255;
	// B.1.2 default 255).
	MaxString int
	// History is N8, the history size. 0 (the default, B.1.2 "not
	// applicable") makes the whole packet the history. Otherwise at least
	// 512 (Table 10).
	History int
	// Limit bounds the decompressed size of one packet (not a V.44
	// parameter: a guard against hostile input). Default 1 MiB.
	Limit int
}

// Defaults of the packet method (annex B.1.2) and of Limit.
const (
	DefaultCodewords = 1525
	DefaultMaxString = 255
	DefaultLimit     = 1 << 20
)

// DefaultParams are the annex B.1.2 packet-method defaults.
func DefaultParams() Params {
	return Params{Codewords: DefaultCodewords, MaxString: DefaultMaxString, Limit: DefaultLimit}
}

// withDefaults fills zero fields.
func (p Params) withDefaults() Params {
	if p.Codewords == 0 {
		p.Codewords = DefaultCodewords
	}
	if p.MaxString == 0 {
		p.MaxString = DefaultMaxString
	}
	if p.Limit == 0 {
		p.Limit = DefaultLimit
	}
	return p
}

// Validate checks the parameters against the ranges of Table 10.
func (p Params) Validate() error {
	p = p.withDefaults()
	switch {
	case p.Codewords < 256 || p.Codewords > 65535:
		return fmt.Errorf("v44: codewords (N2) %d is outside 256 to 65535", p.Codewords)
	case p.MaxString < 32 || p.MaxString > 255:
		return fmt.Errorf("v44: maximum string length (N7) %d is outside 32 to 255", p.MaxString)
	case p.History != 0 && (p.History < 512 || p.History > 1<<30):
		return fmt.Errorf("v44: history size (N8) %d is not 0 (the whole packet) or 512 to 2^30", p.History)
	case p.Limit < 0:
		return fmt.Errorf("v44: limit %d is negative", p.Limit)
	}
	return nil
}

// maxCodewordBits is N1, the codeword size that holds N2 - 1 (Table 11).
func (p Params) maxCodewordBits() uint { return uint(bits.Len(uint(p.Codewords - 1))) }

// ErrCorrupt is wrapped by every decoding error caused by the input.
var ErrCorrupt = errors.New("v44: compressed data is not valid")

// ErrLimit is wrapped when the output would exceed Params.Limit.
var ErrLimit = errors.New("v44: decompressed data exceeds the limit")

// Control codes (Table 8).
const (
	ctlETM    = 0
	ctlFLUSH  = 1
	ctlSTEPUP = 2
	ctlREINIT = 3
	firstCW   = 4 // N5
)

// Initial state of both dictionaries (7.5.1, 7.5.2).
const (
	initC2 = 6
	initC3 = 64
	initC5 = 7
)
