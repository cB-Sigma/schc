// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"hash/crc32"
)

// MsgKind is a SCHC F/R message type (RFC 8724 8.2.1, 8.3).
type MsgKind int

// Message types.
const (
	MsgFragment      MsgKind = iota // Regular SCHC Fragment (including All-0)
	MsgAll1                         // All-1 SCHC Fragment
	MsgAckReq                       // SCHC ACK REQ
	MsgSenderAbort                  // SCHC Sender-Abort
	MsgAck                          // SCHC ACK
	MsgReceiverAbort                // SCHC Receiver-Abort
)

// String is the message type's short name, such as "ack-req".
func (k MsgKind) String() string {
	return [...]string{"fragment", "all-1", "ack-req", "sender-abort", "ack", "receiver-abort"}[k]
}

// FragMsg is one SCHC F/R message, decoded.
type FragMsg struct {
	Kind MsgKind
	Rule *Rule
	DTag uint32
	W    uint32
	FCN  uint32 // fragments
	RCS  uint32 // All-1
	// Payload is a fragment's payload bits (for an All-1 including its
	// padding, which cannot be told from tile bits, RFC 8724 8.4.3.2).
	Payload Bits
	C       bool   // ACK
	Bitmap  []bool // ACK with C=0: the window's bitmap, leftmost tile (WINDOW_SIZE-1) first, uncompressed
	// More are the further windows of a SCHC Compound ACK (RFC 9441), in
	// increasing window order after W; only with a rule's CompoundAck.
	More []WindowBitmap
}

// WindowBitmap is one window's bitmap in a SCHC Compound ACK.
type WindowBitmap struct {
	W      uint32
	Bitmap []bool
}

// rcs is the Reassembly Check Sequence over the packet zero-extended to
// whole bytes (RFC 8724 8.2.3), with the rule's algorithm (CRC32, reflected
// polynomial EDB88320h, by default), cut to the RCS size.
func (p *FragParams) rcs(packet Bits) uint32 {
	sum := crc32.ChecksumIEEE
	if p.rcsAlg.Sum != nil {
		sum = p.rcsAlg.Sum
	}
	v := sum(packet.Bytes())
	if p.RCSSize > 0 && p.RCSSize < 32 {
		v &= 1<<uint(p.RCSSize) - 1
	}
	return v
}

func (p *FragParams) all1() uint32 { return 1<<uint(p.FCNSize) - 1 }

// header writes RuleID, DTag and W.
func header(r *Rule, dtag, w uint32) Bits {
	p := r.Fragmentation
	h := r.idBits()
	h.AppendUint(uint64(dtag), p.DTagSize)
	h.AppendUint(uint64(w), p.WSize)
	return h
}

// Encode writes the message with padding to the L2 Word (RFC 8724 8.3,
// clause 9).
func (m *FragMsg) Encode(word int) Bits {
	r, p := m.Rule, m.Rule.Fragmentation
	switch m.Kind {
	case MsgFragment:
		h := header(r, m.DTag, m.W)
		h.AppendUint(uint64(m.FCN), p.FCNSize)
		h.Append(m.Payload)
		h.Pad(word)
		return h
	case MsgAll1:
		h := header(r, m.DTag, m.W)
		h.AppendUint(uint64(p.all1()), p.FCNSize)
		h.AppendUint(uint64(m.RCS), p.RCSSize)
		h.Append(m.Payload)
		h.Pad(word)
		return h
	case MsgAckReq:
		h := header(r, m.DTag, m.W)
		h.AppendUint(0, p.FCNSize)
		h.Pad(word)
		return h
	case MsgSenderAbort:
		h := header(r, m.DTag, 1<<uint(p.WSize)-1)
		h.AppendUint(uint64(p.all1()), p.FCNSize)
		h.Pad(word)
		return h
	case MsgAck:
		h := header(r, m.DTag, m.W)
		if m.C {
			h.AppendBit(1)
			h.Pad(word)
			return h
		}
		h.AppendBit(0)
		if p.CompoundAck {
			encodeCompound(&h, m, p, word)
			return h
		}
		compressBitmap(&h, m.Bitmap, word)
		return h
	case MsgReceiverAbort:
		h := header(r, m.DTag, 1<<uint(p.WSize)-1)
		h.AppendBit(1)
		for h.Len()%word != 0 {
			h.AppendBit(1)
		}
		h.AppendUint(^uint64(0), word)
		return h
	}
	return Bits{}
}

// compressBitmap appends the bitmap cut as RFC 8724 8.3.2.1 says: drop the
// trailing ones, but only up to an L2 Word boundary of the whole message;
// pad when nothing was dropped.
func compressBitmap(h *Bits, bm []bool, word int) {
	if !appendBitmap(h, bm, word, true) {
		h.Pad(word)
	}
}

// appendBitmap appends a bitmap, compressed when compress is set (the
// trailing ones cut up to an L2 Word boundary of the whole message), and
// reports whether bits were cut, which leaves the message on a boundary.
func appendBitmap(h *Bits, bm []bool, word int, compress bool) bool {
	start := h.Len()
	cut := len(bm)
	if compress {
		for cut > 0 && bm[cut-1] {
			cut--
		}
		for (start+cut)%word != 0 && cut < len(bm) {
			cut++
		}
	}
	for _, b := range bm[:cut] {
		if b {
			h.AppendBit(1)
		} else {
			h.AppendBit(0)
		}
	}
	return cut < len(bm)
}

// encodeCompound writes the bitmaps of a SCHC Compound ACK after its C bit
// (RFC 9441 3.1): the first window's (its W is in the header), then W and
// bitmap of each further window; every bitmap whole but the last, which
// is compressed unless the rule says otherwise. When the padding to the
// L2 Word would be M bits or more, M zero bits (no window 0 can follow)
// end the list first.
func encodeCompound(h *Bits, m *FragMsg, p *FragParams, word int) {
	all := append([]WindowBitmap{{W: m.W, Bitmap: m.Bitmap}}, m.More...)
	cut := false
	for i, wb := range all {
		if i > 0 {
			h.AppendUint(uint64(wb.W), p.WSize)
		}
		last := i == len(all)-1
		cut = appendBitmap(h, wb.Bitmap, word, last && !p.LastBitmapUncompressed)
	}
	if cut {
		return
	}
	if padOf(h.Len(), word) >= p.WSize {
		h.AppendUint(0, p.WSize)
	}
	h.Pad(word)
}

var errIgnore = errors.New("schc: message ignored")

// DecodeAtReceiver reads a message a fragment receiver gets: a fragment,
// All-1, ACK REQ or Sender-Abort (RFC 8724 8.3.1, 8.3.3, 8.3.4; they are
// told apart by FCN and size).
func DecodeAtReceiver(r *Rule, msg Bits, word int) (*FragMsg, error) {
	p := r.Fragmentation
	rd := &reader{x: msg, pos: r.IDLength}
	m := &FragMsg{Rule: r}
	var err error
	var v uint64
	if v, err = rd.uint(p.DTagSize); err != nil {
		return nil, err
	}
	m.DTag = uint32(v)
	if v, err = rd.uint(p.WSize); err != nil {
		return nil, err
	}
	m.W = uint32(v)
	if v, err = rd.uint(p.FCNSize); err != nil {
		return nil, err
	}
	m.FCN = uint32(v)
	switch {
	case m.FCN == p.all1() && rd.rem() < word:
		m.Kind = MsgSenderAbort
		if p.WSize > 0 && m.W != 1<<uint(p.WSize)-1 {
			return nil, errIgnore // RFC 8724 8.3.4: W must be all ones
		}
	case m.FCN == p.all1():
		m.Kind = MsgAll1
		if v, err = rd.uint(p.RCSSize); err != nil {
			return nil, err
		}
		m.RCS = uint32(v)
		m.Payload = rd.rest()
	case m.FCN == 0 && p.Mode != NoAck && rd.rem() < word:
		m.Kind = MsgAckReq
	default:
		m.Kind = MsgFragment
		m.Payload = rd.rest()
		if m.Payload.Len() < word {
			return nil, fmt.Errorf("schc: a fragment without a tile")
		}
	}
	return m, nil
}

// DecodeAtSender reads a message a fragment sender gets: an ACK or a
// Receiver-Abort (RFC 8724 8.3.2, 8.3.5).
func DecodeAtSender(r *Rule, msg Bits, word int) (*FragMsg, error) {
	p := r.Fragmentation
	rd := &reader{x: msg, pos: r.IDLength}
	m := &FragMsg{Rule: r, Kind: MsgAck}
	var err error
	var v uint64
	if v, err = rd.uint(p.DTagSize); err != nil {
		return nil, err
	}
	m.DTag = uint32(v)
	if v, err = rd.uint(p.WSize); err != nil {
		return nil, err
	}
	m.W = uint32(v)
	if v, err = rd.uint(1); err != nil {
		return nil, err
	}
	m.C = v == 1
	rest := rd.rest()
	if m.C {
		ones := rest.Len() >= word
		for i := 0; ones && i < rest.Len(); i++ {
			ones = rest.Bit(i) == 1
		}
		if ones {
			m.Kind = MsgReceiverAbort
			if p.WSize > 0 && m.W != 1<<uint(p.WSize)-1 {
				return nil, errIgnore // RFC 8724 8.3.5
			}
		}
		return m, nil
	}
	ws := p.WindowSize
	if p.Mode == NoAck {
		return nil, errors.New("schc: no-ack has no SCHC ACK")
	}
	readBitmap := func(from int) ([]bool, int) {
		bm := make([]bool, ws)
		for i := 0; i < ws; i++ {
			// Bits cut off by the compression are ones (RFC 8724 8.3.2.1).
			bm[i] = from+i >= rest.Len() || rest.Bit(from+i) == 1
		}
		return bm, min(rest.Len(), from+ws)
	}
	var at int
	m.Bitmap, at = readBitmap(0)
	if !p.CompoundAck {
		return m, nil
	}
	// A Compound ACK (RFC 9441 3.1): W and bitmap pairs until fewer than
	// M bits are left or the M zero bits that end the list.
	last := m.W
	for rest.Len()-at >= p.WSize && p.WSize > 0 {
		w := uint32(rest.UintAt(at, p.WSize))
		at += p.WSize
		if w == 0 {
			break
		}
		if w <= last {
			return nil, errIgnore // out of order or repeated: discard (RFC 9441 3.1)
		}
		last = w
		var bm []bool
		bm, at = readBitmap(at)
		m.More = append(m.More, WindowBitmap{W: w, Bitmap: bm})
	}
	return m, nil
}
