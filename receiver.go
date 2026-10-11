// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"time"
)

// Receiver reassembles one fragmented SCHC Packet (one RuleID and DTag)
// and runs the receiver side of its mode (RFC 8724 8.4.1.2, 8.4.2.2,
// 8.4.3.2). Like Sender it does no I/O: it returns the messages to send
// back and, once the integrity check passes, the SCHC Packet.
type Receiver struct {
	r    *Rule
	p    *FragParams
	word int
	dtag uint32
	max  int // bits

	inactivity time.Time
	attempts   int
	done       bool // the packet was reassembled (clean-up: ACKs are repeated)
	err        error
	packet     Bits

	// No-ACK: tiles in order of arrival.
	seq []Bits

	// ACK-Always.
	wc      uint32 // window counter
	phase   int    // 0 acceptance, 1 retransmission, 2 clean-up
	lastWin bool
	win     map[uint32]map[int]Bits // window → bitmap position → tile

	// ACK-on-Error.
	tiles  map[int]Bits // tile number → tile
	all1   bool
	all1W  uint32
	all1T  *Bits // the last tile carried in the All-1
	rcsGot uint32
	top    int // highest tile number seen, -1 none
	// alts are, with a rule's PenultimateShort, the other readings of a
	// fragment's end: a penultimate tile one L2 Word short, then the last
	// tile or only padding (the last tile in the All-1), keyed by the
	// penultimate's tile number. check tries them when the plain reading
	// fails the RCS.
	alts map[int][]altSplit
}

type altSplit struct{ pen, last Bits }

// Receiver phases (ACK-Always).
const (
	phAccept = iota
	phRetrans
	phCleanup
)

// ErrSenderAborted is the error of a transfer the sender aborted.
var ErrSenderAborted = errors.New("schc: the sender aborted the transfer")

// ErrInactive is the error of a transfer that timed out.
var ErrInactive = errors.New("schc: the transfer was inactive for too long")

// NewReceiver starts reassembly for a fragmentation rule and DTag.
// maxBytes bounds the reassembled packet (0: 4096).
func NewReceiver(r *Rule, word int, dtag uint32, maxBytes int, now time.Time) *Receiver {
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	rv := &Receiver{r: r, p: r.Fragmentation, word: word, dtag: dtag, max: 8*maxBytes + 64,
		win: map[uint32]map[int]Bits{}, tiles: map[int]Bits{}, top: -1}
	rv.inactivity = now.Add(rv.p.Inactivity.D())
	return rv
}

// Done reports whether the packet was reassembled or the transfer ended.
func (rv *Receiver) Done() bool { return rv.done || rv.err != nil }

// Packet is the reassembled SCHC Packet (with the padding bits of the
// fragment that carried the last tile, which decompression drops).
func (rv *Receiver) Packet() (Bits, bool) { return rv.packet, rv.done && rv.err == nil }

// Err is why reassembly failed.
func (rv *Receiver) Err() error { return rv.err }

// Deadline is when the inactivity timer expires.
func (rv *Receiver) Deadline() time.Time { return rv.inactivity }

func (rv *Receiver) enc(m *FragMsg) Bits { m.Rule, m.DTag = rv.r, rv.dtag; return m.Encode(rv.word) }

func (rv *Receiver) abort(err error) []Bits {
	rv.err = err
	if rv.p.Mode == NoAck {
		return nil // No-ACK sends no Receiver-Abort (RFC 8724 8.4.1)
	}
	return []Bits{rv.enc(&FragMsg{Kind: MsgReceiverAbort})}
}

// Tick runs the inactivity timer: on expiry reassembly ends (with a
// Receiver-Abort outside No-ACK). After success it just ends the clean-up.
func (rv *Receiver) Tick(now time.Time) []Bits {
	if rv.err != nil || now.Before(rv.inactivity) {
		return nil
	}
	if rv.done {
		rv.err = errDoneExpired
		return nil
	}
	return rv.abort(ErrInactive)
}

var errDoneExpired = errors.New("schc: clean-up ended")

// Receive handles a message; it returns the messages to send back.
func (rv *Receiver) Receive(now time.Time, msg Bits) ([]Bits, error) {
	if rv.err != nil {
		return nil, rv.err
	}
	m, err := DecodeAtReceiver(rv.r, msg, rv.word)
	if errors.Is(err, errIgnore) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if m.DTag != rv.dtag {
		return nil, nil
	}
	rv.inactivity = now.Add(rv.p.Inactivity.D())
	if m.Kind == MsgSenderAbort {
		if rv.done {
			return nil, nil
		}
		if rv.p.Mode == NoAck {
			rv.err = ErrSenderAborted
			return nil, rv.err
		}
		return rv.abort(ErrSenderAborted), ErrSenderAborted
	}
	switch rv.p.Mode {
	case NoAck:
		return rv.noAck(m)
	case AckAlways:
		return rv.ackAlways(m), rv.errIfAborted()
	default:
		return rv.aoe(m), rv.errIfAborted()
	}
}

func (rv *Receiver) errIfAborted() error {
	if rv.err != nil && !errors.Is(rv.err, errDoneExpired) {
		return rv.err
	}
	return nil
}

func (rv *Receiver) size() int {
	n := 0
	for _, t := range rv.seq {
		n += t.Len()
	}
	for _, w := range rv.win {
		for _, t := range w {
			n += t.Len()
		}
	}
	for _, t := range rv.tiles {
		n += t.Len()
	}
	return n
}

// noAck assembles fragments in order; the All-1 ends it (RFC 8724
// 8.4.1.2).
func (rv *Receiver) noAck(m *FragMsg) ([]Bits, error) {
	if rv.done {
		return nil, nil
	}
	if m.Kind == MsgAckReq {
		return nil, nil
	}
	rv.seq = append(rv.seq, m.Payload)
	if rv.size() > rv.max {
		rv.err = errors.New("schc: the reassembled packet is over maxPacketSize")
		return nil, rv.err
	}
	if m.Kind != MsgAll1 {
		return nil, nil
	}
	var pkt Bits
	for _, t := range rv.seq {
		pkt.Append(t)
	}
	ok := rv.p.rcs(pkt) == m.RCS
	if rv.p.countRCS() {
		// The count of fragments, the All-1 included (RFC 9442).
		ok = uint32(len(rv.seq))&(1<<uint(rv.p.RCSSize)-1) == m.RCS
	}
	if !ok {
		rv.err = errors.New("schc: the integrity check failed")
		return nil, rv.err
	}
	rv.packet, rv.done = pkt, true
	return nil, nil
}

// countOf is the fragment count an All-1 carried (RCSFragmentCount), 0
// read as 2^rcsSize.
func (rv *Receiver) countOf(rcs uint32) int {
	if rcs == 0 {
		return 1 << uint(rv.p.RCSSize)
	}
	return int(rcs)
}

// --- ACK-Always (RFC 8724 8.4.2.2) ---

func (rv *Receiver) ackMsg(w uint32, c bool, bm []bool) Bits {
	rv.attempts++
	return rv.enc(&FragMsg{Kind: MsgAck, W: w, C: c, Bitmap: bm})
}

func (rv *Receiver) aaBitmap() []bool {
	ws := rv.p.WindowSize
	bm := make([]bool, ws)
	for pos := range rv.win[rv.wc] {
		bm[pos] = true
	}
	return bm
}

// aaAck is the ACK for the current window.
func (rv *Receiver) aaAck() []Bits {
	if rv.attempts >= rv.p.MaxAckRequests && !rv.done {
		return rv.abort(errors.New("schc: MAX_ACK_REQUESTS reached"))
	}
	if rv.done {
		if rv.attempts >= rv.p.MaxAckRequests+1 {
			return nil
		}
		return []Bits{rv.ackMsg(rv.wc&1, true, nil)}
	}
	return []Bits{rv.ackMsg(rv.wc&1, false, rv.aaBitmap())}
}

func (rv *Receiver) aaStore(m *FragMsg) {
	ws := rv.p.WindowSize
	if rv.win[rv.wc] == nil {
		rv.win[rv.wc] = map[int]Bits{}
	}
	pos := ws - 1 - int(m.FCN)
	if m.Kind == MsgAll1 {
		pos = ws - 1
	}
	if pos < 0 || pos >= ws {
		return
	}
	rv.win[rv.wc][pos] = m.Payload
}

func (rv *Receiver) aaNext() {
	rv.wc++
	rv.attempts = 0
	rv.win[rv.wc] = map[int]Bits{}
}

// aaCheck runs the integrity check over windows 0..wc.
func (rv *Receiver) aaCheck(rcsGot uint32) bool {
	ws := rv.p.WindowSize
	if rv.p.countRCS() {
		// The last window has count-1 regular fragments from its first
		// place, then the All-1 in the last place.
		n := rv.countOf(rcsGot)
		tw := rv.win[rv.wc]
		if _, ok := tw[ws-1]; !ok || n > ws {
			return false
		}
		for pos := 0; pos < ws-1; pos++ {
			if _, ok := tw[pos]; ok != (pos < n-1) {
				return false
			}
		}
	}
	var pkt Bits
	for w := uint32(0); w <= rv.wc; w++ {
		tw := rv.win[w]
		for pos := 0; pos < ws; pos++ {
			t, ok := tw[pos]
			if !ok {
				if w < rv.wc {
					return false
				}
				continue
			}
			pkt.Append(t)
		}
	}
	if !rv.p.countRCS() && rv.p.rcs(pkt) != rcsGot {
		return false
	}
	rv.packet = pkt
	return true
}

func (rv *Receiver) aaFull() bool { return len(rv.win[rv.wc]) == rv.p.WindowSize }

func (rv *Receiver) ackAlways(m *FragMsg) []Bits {
	if rv.size() > rv.max {
		return rv.abort(errors.New("schc: the reassembled packet is over maxPacketSize"))
	}
	local := rv.wc & 1
	same := m.W == local
	all0 := m.Kind == MsgFragment && m.FCN == 0
	if m.Kind == MsgAll1 {
		rv.rcsGot = m.RCS
	}
	endAll1 := func() []Bits {
		rv.lastWin = true
		if rv.aaCheck(rv.rcsGot) {
			rv.done, rv.phase = true, phCleanup
			return rv.aaAck()
		}
		rv.phase = phRetrans
		return rv.aaAck()
	}
	switch rv.phase {
	case phAccept:
		if !same {
			return nil
		}
		switch {
		case m.Kind == MsgAckReq:
			return rv.aaAck()
		case m.Kind == MsgAll1:
			rv.aaStore(m)
			return endAll1()
		default:
			rv.aaStore(m)
			if all0 {
				rv.phase = phRetrans
				return rv.aaAck()
			}
		}
		return nil
	case phRetrans:
		if !rv.lastWin {
			if !same {
				switch {
				case m.Kind == MsgAckReq:
					rv.aaNext()
					rv.phase = phAccept
					return rv.aaAck()
				case m.Kind == MsgAll1:
					rv.aaNext()
					rv.aaStore(m)
					return endAll1()
				case all0:
					rv.aaNext()
					rv.aaStore(m)
					return rv.aaAck()
				default:
					rv.aaNext()
					rv.aaStore(m)
					rv.phase = phAccept
					return nil
				}
			}
			switch {
			case m.Kind == MsgAll1:
				return nil
			case m.Kind == MsgAckReq:
				return rv.aaAck()
			}
			rv.aaStore(m)
			if rv.aaFull() || all0 {
				return rv.aaAck()
			}
			return nil
		}
		// The last window.
		if !same {
			return nil
		}
		switch {
		case m.Kind == MsgAckReq:
			return rv.aaAck()
		case all0:
			return nil
		}
		rv.aaStore(m)
		if rv.aaCheck(rv.rcsGot) {
			rv.done, rv.phase = true, phCleanup
			return rv.aaAck()
		}
		if m.Kind == MsgAll1 {
			return rv.aaAck()
		}
		return nil
	default: // clean-up
		if same && (m.Kind == MsgAll1 || m.Kind == MsgAckReq) {
			return rv.aaAck()
		}
		return nil
	}
}

// --- ACK-on-Error (RFC 8724 8.4.3.2) ---

func (rv *Receiver) tileNo(w, idx uint32) int {
	ws := rv.p.WindowSize
	return int(w)*ws + ws - 1 - int(idx)
}

func (rv *Receiver) aoe(m *FragMsg) []Bits {
	ws, ts := rv.p.WindowSize, rv.p.TileSize
	limit := (1 << uint(rv.p.WSize)) * ws
	switch m.Kind {
	case MsgFragment:
		if int(m.FCN) >= ws {
			return nil
		}
		t := rv.tileNo(m.W, m.FCN)
		pl := m.Payload
		k := -1
		if ts > 0 {
			k = pl.Len() / ts
		}
		var events []uint32 // windows to acknowledge (ackEveryWindow)
		put := func(n int, b Bits) {
			if n >= limit {
				return
			}
			wasFull := rv.windowFull(uint32(n / ws))
			if _, seen := rv.tiles[n]; !seen {
				rv.attempts = 0 // progress: ACKs are counted without it
			}
			rv.tiles[n] = b
			rv.top = max(rv.top, n)
			w := uint32(n / ws)
			if n%ws == ws-1 || (!wasFull && rv.windowFull(w)) {
				events = append(events, w)
			}
		}
		if ts == 0 {
			// Tiles fill their fragment (RFC 9363 tile-size absent): the
			// payload is one tile, with any padding of the last.
			put(t, pl)
		}
		for i := 0; i < k; i++ {
			put(t+i, pl.Slice(i*ts, (i+1)*ts))
		}
		if left := pl.Len() - k*ts; k >= 0 && left >= rv.word {
			// A shorter tile at the end: the last tile (with its
			// padding), or a penultimate one L2 Word short.
			put(t+k, pl.Slice(k*ts, pl.Len()))
		}
		if rv.p.PenultimateShort && k >= 0 {
			// The same payload read as ending in a penultimate tile one
			// L2 Word short, followed by the last tile with its padding or
			// by padding alone (RFC 8724 8.4.3.1): the RCS decides between
			// the readings.
			pen := ts - rv.word
			if rv.alts == nil {
				rv.alts = map[int][]altSplit{}
			}
			if at := (k-1)*ts + pen; k >= 1 && pl.Len()-at >= rv.word && t+k < limit {
				rv.alts[t+k-1] = append(rv.alts[t+k-1], altSplit{pen: pl.Slice((k-1)*ts, at), last: pl.Slice(at, pl.Len())})
			}
			if left := pl.Len() - k*ts; left >= pen && left < pen+rv.word && t+k < limit {
				rv.alts[t+k] = append(rv.alts[t+k], altSplit{pen: pl.Slice(k*ts, k*ts+pen)})
			}
		}
		if rv.size() > rv.max {
			return rv.abort(errors.New("schc: the reassembled packet is over maxPacketSize"))
		}
		if rv.done {
			return nil
		}
		if rv.all1 && rv.check() {
			// A retransmission completed the packet; the sender's ACK REQ
			// or All-1 that follows is answered with C=1.
			return nil
		}
		if rv.p.AckEveryWindow && len(events) > 0 {
			w := events[0]
			if !rv.all1 || w < rv.all1W {
				return rv.aoeAck(w, false)
			}
		}
		return nil
	case MsgAll1:
		if !rv.all1 {
			rv.all1, rv.all1W, rv.rcsGot = true, m.W, m.RCS
			if m.Payload.Len() > 0 {
				// Fewer bits than an L2 Word may be padding or a last tile
				// that short (the sender puts such a tile in the All-1):
				// check tells them apart by the RCS.
				t := m.Payload
				rv.all1T = &t
			}
		}
		return rv.respond()
	case MsgAckReq:
		return rv.respond()
	}
	return nil
}

func (rv *Receiver) windowFull(w uint32) bool {
	ws := rv.p.WindowSize
	for i := 0; i < ws; i++ {
		if _, ok := rv.tiles[int(w)*ws+i]; !ok {
			return false
		}
	}
	return true
}

// check assembles and checks the packet once the All-1 is in.
func (rv *Receiver) check() bool {
	if !rv.all1 {
		return false
	}
	if rv.p.countRCS() {
		// RFC 9442: the All-1 says how many fragments its window has, so
		// the packet is the tiles before it, then the All-1's payload.
		r := rv.countRegular()
		if r < 0 || rv.top >= r {
			return false
		}
		var pkt Bits
		for n := 0; n < r; n++ {
			t, ok := rv.tiles[n]
			if !ok {
				return false
			}
			pkt.Append(t)
		}
		if rv.all1T != nil {
			pkt.Append(*rv.all1T)
		}
		rv.packet, rv.done = pkt, true
		return true
	}
	var pkt Bits
	for n := 0; n <= rv.top; n++ {
		t, ok := rv.tiles[n]
		if !ok {
			return false
		}
		pkt.Append(t)
	}
	if rv.checkPacket(pkt) {
		return true
	}
	// With a penultimate tile one L2 Word short, the fragment that ends
	// the packet reads differently: its last full-size tile is the short
	// penultimate one and what followed it the last tile. The plain
	// reading put the last tile at top (it was at least an L2 Word) or
	// took it for padding.
	for _, pen := range []int{rv.top - 1, rv.top} {
		if pen < 0 {
			continue
		}
		for _, a := range rv.alts[pen] {
			var alt Bits
			for n := 0; n < pen; n++ {
				alt.Append(rv.tiles[n])
			}
			alt.Append(a.pen)
			alt.Append(a.last)
			if rv.checkPacket(alt) {
				rv.tiles[pen] = a.pen
				rv.top = pen
				if a.last.Len() > 0 {
					rv.tiles[pen+1] = a.last
					rv.top = pen + 1
				}
				return true
			}
		}
	}
	return false
}

// checkPacket checks the reassembled tiles against the RCS, with the All-1's
// payload as the last tile or as padding.
func (rv *Receiver) checkPacket(pkt Bits) bool {
	if rv.all1T != nil {
		with := pkt.Clone()
		with.Append(*rv.all1T)
		if rv.p.rcs(with) == rv.rcsGot {
			rv.packet, rv.done = with, true
			return true
		}
		if rv.all1T.Len() >= rv.word {
			return false // a whole tile, not padding
		}
	}
	if rv.p.rcs(pkt) != rv.rcsGot {
		return false
	}
	rv.packet, rv.done = pkt, true
	return true
}

// countRegular is, with RCSFragmentCount, the number of tiles sent in
// regular fragments that the All-1's count gives; -1 when it cannot be.
func (rv *Receiver) countRegular() int {
	n := rv.countOf(rv.rcsGot)
	if n > rv.p.WindowSize {
		return -1
	}
	return int(rv.all1W)*rv.p.WindowSize + n - 1
}

// missingIn reports whether window w has tiles it knows are missing.
func (rv *Receiver) missingIn(w uint32) bool {
	ws := rv.p.WindowSize
	lo, hi := int(w)*ws, int(w)*ws+ws-1
	if rv.all1 && w == rv.all1W && rv.p.countRCS() {
		hi = rv.countRegular() - 1
	} else if rv.all1 && w == rv.all1W {
		// The last window: gaps below the highest tile seen in it, and
		// the rest when no tile of it came yet.
		hi = -1
		for n := lo; n < lo+ws; n++ {
			if _, ok := rv.tiles[n]; ok {
				hi = n
			}
		}
		if hi < 0 {
			return false // only the All-1 is known in it
		}
	}
	for n := lo; n <= hi; n++ {
		if _, ok := rv.tiles[n]; !ok {
			return true
		}
	}
	return false
}

// respond answers an All-1 or ACK REQ: C=1 once the check passes, else the
// lowest window with tiles missing, else the highest window with tiles,
// else window 0 (RFC 8724 8.4.3.2).
func (rv *Receiver) respond() []Bits {
	if rv.done || rv.check() {
		return rv.aoeAck(rv.all1W, true)
	}
	last := uint32(0)
	if rv.top >= 0 {
		last = uint32(rv.top / rv.p.WindowSize)
	}
	if rv.all1 && rv.all1W > last {
		last = rv.all1W
	}
	var missing []uint32
	for w := uint32(0); w <= last; w++ {
		if rv.missingIn(w) {
			if !rv.p.CompoundAck {
				return rv.aoeAck(w, false)
			}
			missing = append(missing, w)
		}
	}
	if rv.p.CompoundAck && rv.all1 && (len(missing) == 0 || missing[len(missing)-1] < rv.all1W) {
		// The check failed with the All-1 in: the last window misses
		// tiles too, as RFC 9441 figure 7 reports it.
		missing = append(missing, rv.all1W)
	}
	if len(missing) > 0 {
		// One SCHC Compound ACK for every window with tiles missing,
		// lowest first (RFC 9441 3.2.1.2).
		if max := rv.p.AckMaxBits; max > 0 {
			// Only the windows that fit the ACK's frame, lowest first; the
			// others come in a later ACK.
			for len(missing) > 1 && rv.enc(&FragMsg{Kind: MsgAck, W: missing[0], Bitmap: make([]bool, rv.p.WindowSize),
				More: windowBitmaps(missing[1:], rv.p.WindowSize)}).Len() > max {
				missing = missing[:len(missing)-1]
			}
		}
		return rv.aoeAck(missing[0], false, missing[1:]...)
	}
	return rv.aoeAck(last, false)
}

// aoeAck acknowledges window w (C=1, or C=0 with its bitmap) and, in a
// Compound ACK, the further windows more.
func (rv *Receiver) aoeAck(w uint32, c bool, more ...uint32) []Bits {
	if rv.attempts >= rv.p.MaxAckRequests {
		if rv.done {
			return nil
		}
		return rv.abort(errors.New("schc: MAX_ACK_REQUESTS exceeded"))
	}
	if c {
		return []Bits{rv.ackMsg(w, true, nil)}
	}
	m := &FragMsg{Kind: MsgAck, W: w, Bitmap: rv.aoeBitmap(w)}
	for _, x := range more {
		m.More = append(m.More, WindowBitmap{W: x, Bitmap: rv.aoeBitmap(x)})
	}
	rv.attempts++
	return []Bits{rv.enc(m)}
}

// aoeBitmap is window w's bitmap of received tiles.
func (rv *Receiver) aoeBitmap(w uint32) []bool {
	ws := rv.p.WindowSize
	bm := make([]bool, ws)
	for i := 0; i < ws; i++ {
		_, bm[i] = rv.tiles[int(w)*ws+i]
	}
	if rv.all1 && w == rv.all1W {
		bm[ws-1] = true // the All-1 was received (RFC 8724 figure 32)
	}
	return bm
}

// windowBitmaps are empty bitmaps of windows ws, to size a Compound ACK.
func windowBitmaps(ws []uint32, size int) []WindowBitmap {
	out := make([]WindowBitmap, len(ws))
	for i, w := range ws {
		out[i] = WindowBitmap{W: w, Bitmap: make([]bool, size)}
	}
	return out
}
