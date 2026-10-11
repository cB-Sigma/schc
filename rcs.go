// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"strings"
	"sync"
)

// RCSAlgorithm is a Reassembly Check Sequence algorithm (RFC 8724 8.2.3):
// a check over the reassembled packet, zero-extended to whole bytes, sent
// in the All-1 fragment. RFC 8724 defines CRC32 and leaves others to
// profiles; a fragmentation rule names its algorithm ("rcs" in JSON,
// rcs-algorithm in RFC 9363).
type RCSAlgorithm struct {
	// Name is how rules name it, such as "crc32".
	Name string
	// Bits is the size of the RCS field, 1 to 32.
	Bits int
	// Sum computes the RCS of the packet bytes; only its low Bits bits are
	// sent.
	Sum func(packet []byte) uint32
}

// RCSCRC32 is the default algorithm: CRC32 with the reflected polynomial
// EDB88320h (RFC 8724 8.2.3, as Ethernet and ISO/IEC 3309 use it).
const RCSCRC32 = "crc32"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	rcsMu   sync.RWMutex
	rcsAlgs = map[string]RCSAlgorithm{
		RCSCRC32: {Name: RCSCRC32, Bits: 32, Sum: crc32.ChecksumIEEE},
		// CRC-32C (Castagnoli, RFC 3720 B.4), as iSCSI and SCTP use it.
		"crc32c": {Name: "crc32c", Bits: 32, Sum: func(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }},
		// CRC-16 of HDLC (ISO/IEC 13239, RFC 1662 C.2): reflected
		// polynomial 8408h, initial value and final XOR FFFFh.
		"crc16-hdlc": {Name: "crc16-hdlc", Bits: 16, Sum: crc16HDLC},
		// CRC-8 with polynomial 07h (ITU-T I.432.1 HEC without its XOR,
		// as SMBus uses it), initial value 0.
		"crc8": {Name: "crc8", Bits: 8, Sum: crc8},
		// The fragment count of RFC 9442 3.5.1.5 (see RCSFragmentCount):
		// not a sum, its size comes from the rule.
		RCSFragmentCount: {Name: RCSFragmentCount, Sum: func([]byte) uint32 { return 0 }},
	}
)

// RCSFragmentCount is the RCS of the Sigfox profile (RFC 9442 3.5.1.5): the
// field carries the number of fragments of the All-1's window, the All-1
// included (for No-ACK, of the whole packet), modulo 2^rcsSize, so the
// receiver knows how many tiles the last window has. It checks no content.
// The RFC does not say how the count is formed; this follows the
// implementation of the RFC's authors (github.com/schc-over-sigfox, MIT,
// Fragmenter.generate_fragment), see PROVENANCE.md. A rule naming it gives
// its size in rcsSize.
const RCSFragmentCount = "fragment-count"

// RegisterRCS adds an RCS algorithm a profile defines, for rules to name.
// A name already registered is an error.
func RegisterRCS(a RCSAlgorithm) error {
	a.Name = strings.ToLower(strings.TrimSpace(a.Name))
	if a.Name == "" || a.Sum == nil || a.Bits < 1 || a.Bits > 32 {
		return errors.New("schc: an RCS algorithm needs a name, a Sum and 1 to 32 bits")
	}
	rcsMu.Lock()
	defer rcsMu.Unlock()
	if _, dup := rcsAlgs[a.Name]; dup {
		return fmt.Errorf("schc: RCS algorithm %q is already registered", a.Name)
	}
	rcsAlgs[a.Name] = a
	return nil
}

// LookupRCS returns a registered RCS algorithm.
func LookupRCS(name string) (RCSAlgorithm, bool) {
	rcsMu.RLock()
	defer rcsMu.RUnlock()
	a, ok := rcsAlgs[strings.ToLower(name)]
	return a, ok
}

// RCSAlgorithms lists the registered algorithm names, sorted.
func RCSAlgorithms() []string {
	rcsMu.RLock()
	defer rcsMu.RUnlock()
	var out []string
	for n := range rcsAlgs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func crc16HDLC(b []byte) uint32 {
	crc := uint16(0xFFFF)
	for _, c := range b {
		crc ^= uint16(c)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return uint32(^crc)
}

func crc8(b []byte) uint32 {
	var crc uint8
	for _, c := range b {
		crc ^= c
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = crc<<1 ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return uint32(crc)
}
