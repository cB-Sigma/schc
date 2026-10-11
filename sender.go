// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"time"
)

// Sender fragments one SCHC Packet under a fragmentation rule and runs the
// sender side of its mode (RFC 8724 8.4.1.1, 8.4.2.1, 8.4.3.1). It does no
// I/O: its methods return the encoded messages to transmit, and the caller
// runs the clock (Tick) and says how many bits the next message may have
// (mtu, the whole SCHC message including the RuleID).
type Sender struct {
	// NextMTU, when set, gives the MTU of each new fragment in place of
	// the mtu argument (an L2 whose MTU varies, RFC 8724 figure 32).
	NextMTU func() int

	r      *Rule
	p      *FragParams
	word   int
	dtag   uint32
	packet Bits

	attempts int
	timer    time.Time // retransmission timer; zero when stopped
	done     bool
	err      error

	// No-ACK and ACK-Always: tiles are cut as they are first sent.
	pos     int // bits of the packet cut into tiles so far
	win     uint32
	winTile []sentTile // tiles of the current window (ACK-Always)
	last    bool       // the current window is the last (ACK-Always)

	// ACK-on-Error.
	tiles     []Bits // all tiles, cut at the tile size
	lastInAll bool   // the last tile goes in the All-1
	lastPad   int    // padding after the last tile where it was sent
	rcsVal    uint32
	rcsSet    bool
	sentUpTo  int  // tiles sent in the blind transmission so far
	all1Sent  bool // the All-1 has been sent once
	waitWin   int  // ACK-on-Error with ackEveryWindow: the window awaited, -1 none
}

type sentTile struct {
	idx  uint32 // FCN; for the last tile of the packet, sent in the All-1, all ones
	bits Bits
	pad  int
}

// ErrAborted is the error of a transfer the other end aborted.
var ErrAborted = errors.New("schc: the receiver aborted the transfer")

// NewSender starts fragmenting packet under rule r with DTag dtag.
func NewSender(r *Rule, word int, dtag uint32, packet Bits) (*Sender, error) {
	if r.Kind != KindFragmentation {
		return nil, fmt.Errorf("schc: rule %d is not a fragmentation rule", r.ID)
	}
	p := r.Fragmentation
	if dtag >= 1<<uint(p.DTagSize) && !(p.DTagSize == 0 && dtag == 0) {
		return nil, fmt.Errorf("schc: DTag %d does not fit in %d bits", dtag, p.DTagSize)
	}
	if packet.Len() == 0 {
		return nil, errors.New("schc: nothing to fragment")
	}
	s := &Sender{r: r, p: p, word: word, dtag: dtag, packet: packet, waitWin: -1}
	if p.Mode == AckOnError && p.TileSize > 0 {
		if err := s.cutTiles(p.TileSize); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// cutTiles cuts the packet into tiles of ts bits (ACK-on-Error) and
// decides where the last one goes.
func (s *Sender) cutTiles(ts int) error {
	p, packet, word := s.p, s.packet, s.word
	for i := 0; i < packet.Len(); i += ts {
		s.tiles = append(s.tiles, packet.Slice(i, min(i+ts, packet.Len())))
	}
	if n := len(s.tiles); p.PenultimateShort && n >= 2 && s.tiles[n-1].Len() < word {
		// A last tile shorter than an L2 Word takes a word from the
		// penultimate tile, which is then one L2 Word short (RFC 8724
		// 8.4.3.1); the last tile can then travel in a regular fragment,
		// as openschc sends it.
		both := s.tiles[n-2].Clone()
		both.Append(s.tiles[n-1])
		s.tiles[n-2], s.tiles[n-1] = both.Slice(0, ts-word), both.Slice(ts-word, both.Len())
	}
	if len(s.tiles) > (1<<uint(p.WSize))*p.WindowSize {
		return fmt.Errorf("schc: %d tiles do not fit in %d windows of %d (RFC 8724 8.4.3.1)", len(s.tiles), 1<<uint(p.WSize), p.WindowSize)
	}
	lt := s.tiles[len(s.tiles)-1]
	lastIdx := p.WindowSize - 1 - (len(s.tiles)-1)%p.WindowSize
	h := s.headerBits(false)
	// The last tile goes in the All-1 when the profile says so, when it
	// is shorter than an L2 Word (a regular fragment's receiver would drop
	// it as padding), when its padding in a regular fragment could not be
	// told apart from a tile, or when it would share the rightmost bitmap
	// bit with the All-1 (tile index 0). With tiles that fill their
	// fragment the receiver takes a fragment's payload as one tile, so
	// padding is no question.
	fill := p.TileSize == 0
	s.lastInAll = p.LastTile == LastTileAll1 || lt.Len() < word || lastIdx == 0 ||
		(!fill && (ts%word != 0 || h%word != 0))
	if p.LastTile == LastTileRegular && s.lastInAll && lt.Len() >= word && lastIdx != 0 {
		s.lastInAll = false
	}
	if fill && s.lastInAll && s.headerBits(true)+lt.Len() > (h+ts) {
		// The last tile must go in the All-1 but does not fit beside the
		// RCS: cut it in two, the first ending its fragment on an L2
		// Word, the second small enough for the All-1.
		n := len(s.tiles) - 1
		a := (h+lt.Len()-1)/word*word - h
		b := lt.Len() - a
		if a < word || s.headerBits(true)+b > h+ts {
			return fmt.Errorf("schc: the MTU leaves no room for the last tile in the All-1")
		}
		s.tiles = append(s.tiles[:n], lt.Slice(0, a), lt.Slice(a, lt.Len()))
		if len(s.tiles) > (1<<uint(p.WSize))*p.WindowSize {
			return fmt.Errorf("schc: %d tiles do not fit in %d windows of %d (RFC 8724 8.4.3.1)", len(s.tiles), 1<<uint(p.WSize), p.WindowSize)
		}
		lt = s.tiles[n+1]
		lastIdx = p.WindowSize - 1 - (n+1)%p.WindowSize
		s.lastInAll = p.LastTile == LastTileAll1 || lt.Len() < word || lastIdx == 0
		if p.LastTile == LastTileRegular && s.lastInAll && lt.Len() >= word && lastIdx != 0 {
			s.lastInAll = false
		}
	}
	return nil
}

// Done reports whether the transfer ended; Err is its error (nil when the
// receiver confirmed the packet, or for No-ACK once everything was sent).
func (s *Sender) Done() bool { return s.done }

// Err is why the transfer failed.
func (s *Sender) Err() error { return s.err }

// Deadline is when Tick next has work (the retransmission timer), or zero.
func (s *Sender) Deadline() time.Time { return s.timer }

func (s *Sender) enc(m *FragMsg) Bits { m.Rule, m.DTag = s.r, s.dtag; return m.Encode(s.word) }

func (s *Sender) fail(err error) []Bits {
	s.done, s.err, s.timer = true, err, time.Time{}
	return []Bits{s.enc(&FragMsg{Kind: MsgSenderAbort})}
}

func (s *Sender) headerBits(all1 bool) int {
	h := s.r.IDLength + s.p.DTagSize + s.p.WSize + s.p.FCNSize
	if all1 {
		h += s.p.RCSSize
	}
	if s.p.HeaderPadded {
		h += padOf(h, s.word)
	}
	return h
}

// rcsFor is the All-1's RCS: the check over the packet and the padding of
// the fragment that carried its last tile, or, with RCSFragmentCount, the
// fragment count given.
func (s *Sender) rcsFor(pad, count int) uint32 {
	if s.p.countRCS() {
		return uint32(count) & (1<<uint(s.p.RCSSize) - 1)
	}
	return s.rcsWith(pad)
}

// all1Win is the All-1's window and, for RCSFragmentCount, the number of
// fragments of that window with the All-1. The All-1 takes the place after
// the last tile; when that tile ends a window and the count is sent, the
// All-1 opens the next window alone, as the Sigfox profile's sender does.
func (s *Sender) all1Win() (w uint32, count int) {
	ws := s.p.WindowSize
	last := len(s.tiles) - 1
	w, pos := uint32(last/ws), last%ws
	switch {
	case s.lastInAll:
		return w, pos + 1
	case pos+1 < ws || !s.p.countRCS():
		return w, pos + 2
	}
	return w + 1, 1
}

func padOf(n, word int) int { return (word - n%word) % word }

// rcsWith is the RCS over the packet and the padding of the fragment that
// carried its last tile (RFC 8724 8.2.3).
func (s *Sender) rcsWith(pad int) uint32 {
	x := s.packet.Clone()
	x.AppendUint(0, pad)
	return s.p.rcs(x)
}

// Start sends the first messages: every fragment in No-ACK, the first
// window otherwise.
func (s *Sender) Start(now time.Time, mtu int) ([]Bits, error) {
	switch s.p.Mode {
	case NoAck:
		return s.noAck(mtu)
	case AckAlways:
		return s.blindWindow(now, mtu)
	default:
		if s.tiles == nil {
			// Tiles that fill the fragment (RFC 9363 tile-size absent):
			// the whole L2 Words this MTU leaves after the header.
			ts := mtu/s.word*s.word - s.headerBits(false)
			if ts < s.word {
				return s.fail(fmt.Errorf("schc: an MTU of %d bits leaves no room for a tile", mtu)), s.err
			}
			if err := s.cutTiles(ts); err != nil {
				return s.fail(err), err
			}
		}
		if lt := s.tiles[len(s.tiles)-1]; s.lastInAll && s.headerBits(true)+lt.Len() > mtu && lt.Len() >= s.word {
			// The last tile does not fit beside the RCS: it goes in a
			// regular fragment and the All-1 follows it alone (as the
			// Sigfox profile sends a last tile of a whole fragment's size).
			if _, idx := s.tileWin(len(s.tiles) - 1); idx != 0 || s.p.countRCS() {
				s.lastInAll = false
			}
		}
		if s.p.countRCS() {
			if w, _ := s.all1Win(); w >= 1<<uint(s.p.WSize) {
				err := errors.New("schc: the All-1 would need a window past the last (RFC 8724 8.4.3.1)")
				return s.fail(err), err
			}
		}
		return s.aoeBlind(now, mtu)
	}
}

// cut takes the next tile for a regular fragment of at most mtu bits,
// leaving at least one L2 Word for the last tile.
func (s *Sender) mtu(mtu int) int {
	if s.NextMTU != nil {
		return s.NextMTU()
	}
	return mtu
}

func (s *Sender) cut(mtu int) (Bits, error) {
	h := s.headerBits(false)
	// The fragment is whole L2 Words: h + tile = k words.
	room := mtu/s.word*s.word - h
	rem := s.packet.Len() - s.pos
	for !s.p.FullFragments && room > 0 && room > rem-s.word {
		room -= s.word
	}
	if room < s.word {
		return Bits{}, fmt.Errorf("schc: an MTU of %d bits leaves no room for a tile", mtu)
	}
	t := s.packet.Slice(s.pos, s.pos+min(room, rem))
	s.pos += min(room, rem)
	return t, nil
}

// noAck sends every fragment: one tile each, the last in the All-1 with
// the RCS (RFC 8724 8.4.1.1). With FCNCountdown the regular fragments are
// numbered from the fragment count less one down to 1 (RFC 9442 3.6.1,
// 5.1).
func (s *Sender) noAck(mtu0 int) ([]Bits, error) {
	var tiles []Bits
	var all1 Bits
	var pad int
	for {
		mtu := s.mtu(mtu0)
		rem := s.packet.Len() - s.pos
		if s.headerBits(true)+rem <= mtu {
			all1 = s.packet.Slice(s.pos, s.packet.Len())
			pad = padOf(s.headerBits(true)+rem, s.word)
			s.pos = s.packet.Len()
			break
		}
		t, err := s.cut(mtu)
		if err != nil {
			s.done, s.err = true, err
			return nil, err
		}
		tiles = append(tiles, t)
	}
	n := len(tiles) + 1
	if s.p.FCNCountdown && n-1 >= int(s.p.all1()) {
		err := fmt.Errorf("schc: %d fragments do not fit a %d-bit FCN counting down", n, s.p.FCNSize)
		s.done, s.err = true, err
		return nil, err
	}
	out := make([]Bits, 0, n)
	for i, t := range tiles {
		fcn := uint32(0)
		if s.p.FCNCountdown {
			fcn = uint32(n - 1 - i)
		}
		out = append(out, s.enc(&FragMsg{Kind: MsgFragment, FCN: fcn, Payload: t}))
	}
	out = append(out, s.enc(&FragMsg{Kind: MsgAll1, W: 0, RCS: s.rcsFor(pad, n), Payload: all1}))
	s.done = true
	return out, nil
}

// blindWindow sends the current window of ACK-Always, one tile per
// fragment, and arms the retransmission timer (RFC 8724 8.4.2.1).
func (s *Sender) blindWindow(now time.Time, mtu int) ([]Bits, error) {
	if s.p.WSize == 0 && s.win > 0 {
		err := errors.New("schc: the packet does not fit in the one window of a rule without W")
		return s.fail(err), err
	}
	s.winTile = s.winTile[:0]
	s.attempts = 0
	var out []Bits
	w := s.win & 1
	mtu0 := mtu
	for idx := s.p.WindowSize - 1; idx >= 0; idx-- {
		mtu := s.mtu(mtu0)
		rem := s.packet.Len() - s.pos
		if s.headerBits(true)+rem <= mtu {
			t := s.packet.Slice(s.pos, s.packet.Len())
			s.pos = s.packet.Len()
			pad := padOf(s.headerBits(true)+rem, s.word)
			s.winTile = append(s.winTile, sentTile{idx: s.p.all1(), bits: t, pad: pad})
			s.rcsVal = s.rcsFor(pad, len(s.winTile))
			out = append(out, s.enc(&FragMsg{Kind: MsgAll1, W: w, RCS: s.rcsVal, Payload: t}))
			s.last = true
			break
		}
		t, err := s.cut(mtu)
		if err != nil {
			return append(out, s.fail(err)...), err
		}
		s.winTile = append(s.winTile, sentTile{idx: uint32(idx), bits: t})
		out = append(out, s.enc(&FragMsg{Kind: MsgFragment, W: w, FCN: uint32(idx), Payload: t}))
	}
	s.timer = now.Add(s.p.Retransmission.D())
	return out, nil
}

// Receive handles an ACK or Receiver-Abort.
func (s *Sender) Receive(now time.Time, msg Bits, mtu int) ([]Bits, error) {
	if s.done {
		return nil, nil
	}
	m, err := DecodeAtSender(s.r, msg, s.word)
	if errors.Is(err, errIgnore) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if m.DTag != s.dtag {
		return nil, nil
	}
	if m.Kind == MsgReceiverAbort {
		s.done, s.err, s.timer = true, ErrAborted, time.Time{}
		return nil, ErrAborted
	}
	switch s.p.Mode {
	case AckAlways:
		return s.ackAlways(now, m, mtu)
	case AckOnError:
		if s.tiles == nil {
			return nil, nil // not started: nothing was sent to acknowledge
		}
		return s.aoeAck(now, m, mtu)
	}
	return nil, nil
}

// ackAlways handles an ACK for the current window (RFC 8724 8.4.2.1).
func (s *Sender) ackAlways(now time.Time, m *FragMsg, mtu int) ([]Bits, error) {
	if m.W != s.win&1 {
		return nil, nil // another window's: silently ignored
	}
	ws := s.p.WindowSize
	if m.C {
		if s.last {
			s.done, s.timer = true, time.Time{}
			return nil, nil
		}
		// A C=1 ACK for a window that is not the last: taken as every
		// tile received (RFC 9011 appendix A.3 shows this; F-2101).
		m.Bitmap = make([]bool, ws)
		for i := range m.Bitmap {
			m.Bitmap[i] = true
		}
	}
	var missing []sentTile
	sent := map[int]bool{}
	for _, t := range s.winTile {
		pos := ws - 1 - int(t.idx)
		if t.idx == s.p.all1() {
			pos = ws - 1
		}
		sent[pos] = true
		if !m.Bitmap[pos] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		if s.attempts >= s.p.MaxAckRequests {
			return s.fail(errors.New("schc: tiles still missing after MAX_ACK_REQUESTS")), s.err
		}
		s.attempts++
		var out []Bits
		for _, t := range missing {
			if t.idx == s.p.all1() {
				if s.headerBits(true)+t.bits.Len() > mtu {
					return s.fail(errors.New("schc: the MTU fell below the last fragment")), s.err
				}
				out = append(out, s.enc(&FragMsg{Kind: MsgAll1, W: s.win & 1, RCS: s.rcsVal, Payload: t.bits}))
				continue
			}
			if s.headerBits(false)+t.bits.Len() > mtu {
				return s.fail(errors.New("schc: the MTU fell below a fragment to resend")), s.err
			}
			out = append(out, s.enc(&FragMsg{Kind: MsgFragment, W: s.win & 1, FCN: t.idx, Payload: t.bits}))
		}
		s.timer = now.Add(s.p.Retransmission.D())
		return out, nil
	}
	if s.last {
		for pos, got := range m.Bitmap {
			if got && !sent[pos] {
				return s.fail(errors.New("schc: the receiver reports more tiles than were sent")), s.err
			}
		}
		return s.fail(errors.New("schc: every tile arrived but the integrity check failed")), s.err
	}
	s.win++
	return s.blindWindow(now, mtu)
}

// Tick runs the retransmission timer: an ACK REQ (ACK-Always) or the
// All-1 again (ACK-on-Error), up to MAX_ACK_REQUESTS, then a Sender-Abort.
func (s *Sender) Tick(now time.Time) ([]Bits, error) {
	if s.done || s.timer.IsZero() || now.Before(s.timer) {
		return nil, nil
	}
	if s.attempts >= s.p.MaxAckRequests {
		return s.fail(errors.New("schc: no SCHC ACK after MAX_ACK_REQUESTS")), s.err
	}
	s.attempts++
	s.timer = now.Add(s.p.Retransmission.D())
	switch s.p.Mode {
	case AckAlways:
		if s.p.NoAckReq && s.last && len(s.winTile) > 0 {
			// The All-1 again asks for the ACK (RFC 9442 3.6.5.1).
			t := s.winTile[len(s.winTile)-1]
			return []Bits{s.enc(&FragMsg{Kind: MsgAll1, W: s.win & 1, RCS: s.rcsVal, Payload: t.bits})}, nil
		}
		return []Bits{s.enc(&FragMsg{Kind: MsgAckReq, W: s.win & 1})}, nil
	case AckOnError:
		if s.waitWin >= 0 {
			return []Bits{s.enc(&FragMsg{Kind: MsgAckReq, W: uint32(s.waitWin)})}, nil
		}
		return []Bits{s.all1Msg()}, nil
	}
	return nil, nil
}

// --- ACK-on-Error (RFC 8724 8.4.3.1) ---

func (s *Sender) tileWin(i int) (w, idx uint32) {
	ws := s.p.WindowSize
	return uint32(i / ws), uint32(ws - 1 - i%ws)
}

// all1Count is the fragment count of the All-1's window (RCSFragmentCount).
func (s *Sender) all1Count() int { _, c := s.all1Win(); return c }

func (s *Sender) all1Msg() Bits {
	w, _ := s.all1Win()
	m := &FragMsg{Kind: MsgAll1, W: w, RCS: s.rcsVal}
	if s.lastInAll {
		m.Payload = s.tiles[len(s.tiles)-1]
	}
	return s.enc(m)
}

// packTiles builds regular fragments for tiles [from, to), as many
// contiguous tiles per fragment as the MTU takes; stopAtWindow keeps each
// fragment within one window.
func (s *Sender) packTiles(from, to, mtu int, stopAtWindow bool) ([]Bits, error) {
	h := s.headerBits(false)
	var out []Bits
	for i := from; i < to; {
		mtu := s.mtu(mtu)
		w, idx := s.tileWin(i)
		var pl Bits
		j := i
		for j < to && h+pl.Len()+s.tiles[j].Len() <= mtu {
			if j > i && s.p.TileSize == 0 {
				break // a tile fills its fragment: one per fragment
			}
			if j > i && stopAtWindow {
				if wj, _ := s.tileWin(j); wj != w {
					break
				}
			}
			pl.Append(s.tiles[j])
			j++
		}
		if j == i {
			return out, fmt.Errorf("schc: an MTU of %d bits leaves no room for a tile", mtu)
		}
		if j == len(s.tiles) && !s.lastInAll {
			s.lastPad = padOf(h+pl.Len(), s.word)
			s.rcsVal, s.rcsSet = s.rcsFor(s.lastPad, s.all1Count()), true
		}
		out = append(out, s.enc(&FragMsg{Kind: MsgFragment, W: w, FCN: idx, Payload: pl}))
		i = j
	}
	return out, nil
}

// aoeBlind sends the tiles not sent yet (up to the end of the window with
// ackEveryWindow), then the All-1 once every tile went out.
func (s *Sender) aoeBlind(now time.Time, mtu int) ([]Bits, error) {
	n := len(s.tiles)
	if s.lastInAll {
		n-- // the last tile rides in the All-1
		if !s.rcsSet {
			s.lastPad = padOf(s.headerBits(true)+s.tiles[len(s.tiles)-1].Len(), s.word)
			s.rcsVal, s.rcsSet = s.rcsFor(s.lastPad, s.all1Count()), true
		}
	}
	to := n
	if s.p.AckEveryWindow {
		w, _ := s.tileWin(s.sentUpTo)
		to = min(n, int(w+1)*s.p.WindowSize)
	}
	out, err := s.packTiles(s.sentUpTo, to, mtu, s.p.AckEveryWindow)
	if err != nil {
		return append(out, s.fail(err)...), err
	}
	s.sentUpTo = to
	if s.p.AckEveryWindow && to < n {
		w, _ := s.tileWin(to - 1)
		s.waitWin = int(w)
		s.attempts = 0
		s.timer = now.Add(s.p.Retransmission.D())
		return out, nil
	}
	s.waitWin = -1
	if s.lastInAll && s.headerBits(true)+s.tiles[len(s.tiles)-1].Len() > mtu {
		return append(out, s.fail(errors.New("schc: the MTU is too small for the All-1 with the last tile"))...), s.err
	}
	out = append(out, s.all1Msg())
	s.all1Sent = true
	s.attempts++
	s.timer = now.Add(s.p.Retransmission.D())
	return out, nil
}

// aoeAck handles an ACK-on-Error SCHC ACK for window m.W.
func (s *Sender) aoeAck(now time.Time, m *FragMsg, mtu int) ([]Bits, error) {
	lw, _ := s.all1Win()
	reports := append([]WindowBitmap{{W: m.W, Bitmap: m.Bitmap}}, m.More...)
	for _, r := range reports {
		if r.W > lw {
			return nil, nil // a window never sent: the whole ACK is discarded (RFC 9441 3.1)
		}
	}
	if m.C {
		if m.W == lw && s.all1Sent {
			s.done, s.timer = true, time.Time{}
		}
		return nil, nil
	}
	ws := s.p.WindowSize
	// Tiles of the reported windows that were sent and are missing; a
	// Compound ACK reports several windows (RFC 9441 3.2.1.1).
	var missing []int
	isLast, all1Missing := false, false
	for _, r := range reports {
		first := int(r.W) * ws
		for i := first; i < min(first+ws, s.sentUpTo); i++ {
			_, idx := s.tileWin(i)
			if !r.Bitmap[ws-1-int(idx)] {
				missing = append(missing, i)
			}
		}
		if r.W == lw && s.all1Sent {
			isLast, all1Missing = true, !r.Bitmap[ws-1]
		}
	}
	if isLast && len(missing) == 0 && !all1Missing && s.lastInAll {
		return s.fail(errors.New("schc: every tile arrived but the integrity check failed")), s.err
	}
	var out []Bits
	// Resend missing tiles in runs of contiguous tiles.
	for k := 0; k < len(missing); {
		j := k
		for j+1 < len(missing) && missing[j+1] == missing[j]+1 {
			j++
		}
		o, err := s.packTiles(missing[k], missing[j]+1, mtu, false)
		if err != nil {
			return append(out, s.fail(err)...), err
		}
		out = append(out, o...)
		k = j + 1
	}
	if s.waitWin >= 0 && int(m.W) == s.waitWin {
		if len(missing) == 0 {
			// The window is complete: on to the next (RFC 9011 5.6.2).
			more, err := s.aoeBlind(now, mtu)
			return append(out, more...), err
		}
		s.timer = now.Add(s.p.Retransmission.D())
		return out, nil
	}
	if !s.all1Sent {
		return out, nil
	}
	if s.p.NoAckReq && !isLast {
		// An ACK that a window's end asked for (the Sigfox receiver sends
		// one after an All-0): resend its tiles; the All-1 asks again when
		// the timer runs out.
		return out, nil
	}
	if s.attempts >= s.p.MaxAckRequests {
		return append(out, s.fail(errors.New("schc: the packet is still incomplete after MAX_ACK_REQUESTS"))...), s.err
	}
	s.attempts++
	s.timer = now.Add(s.p.Retransmission.D())
	if all1Missing || (isLast && len(missing) == 0) || s.p.NoAckReq {
		return append(out, s.all1Msg()), nil
	}
	return append(out, s.enc(&FragMsg{Kind: MsgAckReq, W: lw})), nil
}
