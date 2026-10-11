// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import (
	"errors"
	"fmt"
)

// Method is how an Encoder and its Decoder keep their dictionaries.
type Method int

// Methods of V.44.
const (
	// MultiPacket keeps the dictionary and history from packet to packet
	// (annex B.2); every packet ends with FLUSH and octet alignment, and
	// the link must deliver every packet, in order.
	MultiPacket Method = iota + 1
	// Stream is the primary method of the main body: one continuous
	// stream of codes, FLUSH on request (7.13), transparent mode (6.5)
	// and parameter mode (7.4.2).
	Stream
)

// Defaults of the multi-packet and stream methods (Table 10, B.2.2).
const (
	DefaultStreamCodewords = 1024
)

// streamDefaults fills zero fields with the Table 10 defaults: N2 1024,
// N7 255 and N8 three times N2.
func (p Params) streamDefaults() Params {
	if p.Codewords == 0 {
		p.Codewords = DefaultStreamCodewords
	}
	if p.History == 0 {
		p.History = 3 * p.Codewords
	}
	return p.withDefaults()
}

// Encoder is a V.44 encoder whose dictionary lives across calls, for the
// multi-packet method (Packet, PacketOrRaw) or the stream method (Write,
// Flush, SetTransparent, SendParameters). It is not safe for concurrent
// use.
type Encoder struct {
	method      Method
	e           *encoder
	transparent bool
	escape      byte
	// Auto switches the stream between compressed and transparent mode
	// at each Flush (7.11.5): to transparent when the codes of the
	// segment took more bits than its characters, back to compressed
	// when a trial compression of a transparent segment saves at least
	// an eighth.
	Auto    bool
	segment []byte // the characters since the last Flush
	segBits int    // the bits of codes since the last Flush
}

// NewEncoder starts an encoder of the multi-packet or stream method. Zero
// parameters take the Table 10 defaults (N2 1024, N7 255, N8 3 × N2);
// N8 must exceed the longest packet for the multi-packet method to keep
// packets whole in one history (B.2.1), though longer ones still work.
func NewEncoder(m Method, p Params) (*Encoder, error) {
	if m != MultiPacket && m != Stream {
		return nil, errors.New("v44: the method is MultiPacket or Stream (Compress is the packet method)")
	}
	p = p.streamDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	e := newEncoder(p, nil)
	e.persist = true
	return &Encoder{method: m, e: e}, nil
}

// take returns the whole octets written so far.
func (en *Encoder) take() []byte {
	out := en.e.w.out
	en.e.w.out = nil
	return out
}

// feed encodes what can be encoded now: everything when flush is set,
// else all but the last N7 characters, which a string match or extension
// may still need (6.3).
func (e *encoder) feed(flush bool) {
	hcap := e.p.History
	for {
		end := min(len(e.src), hcap)
		limit := end
		if !flush && end < hcap {
			limit = end - e.p.MaxString
		}
		if e.pos >= limit {
			return
		}
		e.encodeTo(limit, end)
		if e.pos >= hcap {
			// History full (7.11.4): REINIT, and the next character goes
			// to the first position of the history.
			e.reinit()
		}
	}
}

// Packet compresses one packet with the multi-packet method: the codes,
// FLUSH and zero bits to the octet.
func (en *Encoder) Packet(src []byte) []byte {
	if en.method != MultiPacket {
		panic("v44: Packet on a stream encoder")
	}
	e := en.e
	e.src = append(e.src, src...)
	e.feed(true)
	e.control(ctlFLUSH)
	e.w.align()
	return en.take()
}

// PacketOrRaw is Packet, or the annex B uncompressed form (ETM with its
// prefix, in the codeword size the decoder has at the start of the
// packet, then the octets) when that is not larger; the second result is
// whether it is compressed. After an uncompressed packet both ends start
// a new dictionary (B.2.1).
func (en *Encoder) PacketOrRaw(src []byte) ([]byte, bool) {
	c2 := en.e.c2
	c := en.Packet(src)
	var ind bitWriter
	ind.bit(1)
	ind.bits(ctlETM, c2)
	ind.align()
	if len(c) <= len(ind.out)+len(src) {
		return c, true
	}
	e := en.e
	e.reset()
	e.src, e.pos = e.src[:0], 0
	return append(ind.out, src...), false
}

// Write encodes characters with the stream method and returns the octets
// complete so far; the codes of the last characters wait for more input
// or for Flush.
func (en *Encoder) Write(p []byte) []byte {
	if en.method != Stream {
		panic("v44: Write on a multi-packet encoder")
	}
	if en.Auto {
		en.segment = append(en.segment, p...)
	}
	if en.transparent {
		en.transparentChars(p)
		return en.take()
	}
	n := en.e.w.count
	en.e.src = append(en.e.src, p...)
	en.e.feed(false)
	en.segBits += en.e.w.count - n
	return en.take()
}

// transparentChars writes characters in transparent mode, the ESCAPE
// followed by EID wherever it occurs in the data (7.14).
func (en *Encoder) transparentChars(p []byte) {
	w := &en.e.w
	for _, c := range p {
		w.bits(uint32(c), 8)
		if c == en.escape {
			w.bits(cmdEID, 8)
			en.escape += 51
		}
	}
}

// Transparent-mode commands (Table 9) and the End parameter (Table 10).
const (
	cmdECM   = 0
	cmdEID   = 1
	cmdEPM   = 2
	paramEnd = 0xFF
)

// Flush ends the codes of every character written (7.13): FLUSH and zero
// bits to the octet in compressed mode. The dictionary is kept.
func (en *Encoder) Flush() []byte {
	if en.method != Stream {
		panic("v44: Flush on a multi-packet encoder")
	}
	if !en.transparent {
		n := en.e.w.count
		en.e.feed(true)
		en.e.control(ctlFLUSH)
		en.e.w.align()
		en.segBits += en.e.w.count - n
	}
	out := en.take()
	if en.Auto {
		out = append(out, en.monitor()...)
	}
	en.segment, en.segBits = en.segment[:0], 0
	return out
}

// monitor is the compressibility test of 7.11.5 on the segment just
// flushed.
func (en *Encoder) monitor() []byte {
	if len(en.segment) == 0 {
		return nil
	}
	if !en.transparent {
		if en.segBits > 8*len(en.segment) {
			return en.SetTransparent(true)
		}
		return nil
	}
	trial, err := Compress(Params{Codewords: en.e.p.Codewords, MaxString: en.e.p.MaxString}, en.segment)
	if err == nil && len(trial) <= len(en.segment)-len(en.segment)/8 {
		return en.SetTransparent(false)
	}
	return nil
}

// SetTransparent switches the stream to transparent mode (6.5.1: the
// characters written are encoded, then ETM and zero bits to the octet) or
// back to compressed mode (6.5.2: ESCAPE and ECM, and both dictionaries
// start again), and returns the octets that does.
func (en *Encoder) SetTransparent(on bool) []byte {
	if en.method != Stream {
		panic("v44: SetTransparent on a multi-packet encoder")
	}
	if on == en.transparent {
		return nil
	}
	e := en.e
	if on {
		e.feed(true)
		e.control(ctlETM)
		e.w.align()
		en.transparent = true
		return en.take()
	}
	e.w.bits(uint32(en.escape), 8)
	e.w.bits(cmdECM, 8)
	e.reset()
	e.src, e.pos = e.src[:0], 0
	en.transparent = false
	return en.take()
}

// SendParameters transfers parameters to the peer decoder in parameter
// mode (7.4.2): transparent mode if not in it, EPM, the parameters, End.
// The stream stays in transparent mode; the control function applies the
// agreed values by starting new encoders and decoders (7.5).
func (en *Encoder) SendParameters(ps []Parameter) ([]byte, error) {
	if en.method != Stream {
		return nil, errors.New("v44: parameter mode is part of the stream method")
	}
	body, err := marshalParameters(ps)
	if err != nil {
		return nil, err
	}
	out := en.SetTransparent(true)
	w := &en.e.w
	w.bits(uint32(en.escape), 8)
	w.bits(cmdEPM, 8)
	for _, b := range body {
		w.bits(uint32(b), 8)
	}
	w.bits(paramEnd, 8)
	return append(out, en.take()...), nil
}

// Decoder is a V.44 decoder whose dictionary lives across calls, the peer
// of an Encoder of the same method and parameters. It is not safe for
// concurrent use. After an error it refuses further input.
type Decoder struct {
	method Method
	d      *decoder
	err    error
	// OnParameters, when set, receives the parameters of each parameter
	// mode sequence (7.4.2).
	OnParameters func([]Parameter)
}

// NewDecoder starts a decoder of the multi-packet or stream method; p as
// for NewEncoder. Limit bounds the output of one call.
func NewDecoder(m Method, p Params) (*Decoder, error) {
	if m != MultiPacket && m != Stream {
		return nil, errors.New("v44: the method is MultiPacket or Stream (Decompress is the packet method)")
	}
	p = p.streamDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	d := newDecoder(p, nil)
	d.stream = m == Stream
	return &Decoder{method: m, d: d}, nil
}

// Packet decompresses one packet of the multi-packet method, up to its
// FLUSH; an uncompressed packet (ETM first) is returned as it is, and the
// dictionary starts again after it (B.2.1).
func (dc *Decoder) Packet(src []byte) ([]byte, error) {
	if dc.method != MultiPacket {
		return nil, errors.New("v44: Packet on a stream decoder")
	}
	if dc.err != nil {
		return nil, dc.err
	}
	d := dc.d
	d.trim()
	d.callStart = len(d.out)
	d.r = bitReader{in: src}
	d.flushed, d.raw = false, false
	if err := d.run(); err != nil {
		dc.err = err
		return nil, err
	}
	out := append([]byte(nil), d.out[d.callStart:]...)
	if d.raw {
		d.reset() // the history restarts after the packet
	}
	return out, nil
}

// Write decodes stream-method input as it arrives and returns the
// characters decoded so far; a code cut by the end of p waits for the
// next call.
func (dc *Decoder) Write(p []byte) ([]byte, error) {
	if dc.method != Stream {
		return nil, errors.New("v44: Write on a multi-packet decoder")
	}
	if dc.err != nil {
		return nil, dc.err
	}
	d := dc.d
	d.trim()
	d.callStart = len(d.out)
	// Keep the octet in progress and what follows.
	keep := d.r.pos / 8
	d.r.in = append(d.r.in[keep:keep:keep], d.r.in[keep:]...)
	d.r.in = append(d.r.in, p...)
	d.r.pos -= 8 * keep
	for {
		ok, err := dc.next()
		if err != nil {
			dc.err = err
			return nil, err
		}
		if !ok {
			break
		}
	}
	return append([]byte(nil), d.out[d.callStart:]...), nil
}

// next decodes one code, transparent character or command, or parameter;
// false when the input ends first (nothing is consumed then).
func (dc *Decoder) next() (bool, error) {
	d := dc.d
	switch d.mode {
	case modeTransparent:
		at := d.r.pos / 8
		if at >= len(d.r.in) {
			return false, nil
		}
		c := d.r.in[at]
		if c != d.escape {
			if len(d.out)-d.callStart+1 > d.p.Limit {
				return false, fmt.Errorf("%w (%d octets)", ErrLimit, d.p.Limit)
			}
			d.out = append(d.out, c)
			d.r.pos += 8
			return true, nil
		}
		if at+1 >= len(d.r.in) {
			return false, nil
		}
		d.r.pos += 16
		switch d.r.in[at+1] {
		case cmdECM:
			d.reset()
			d.mode = modeCompressed
		case cmdEID:
			d.out = append(d.out, d.escape)
			d.escape += 51
		case cmdEPM:
			d.mode, d.params = modeParameter, nil
		default:
			return false, d.corrupt("transparent-mode command %d", d.r.in[at+1])
		}
		return true, nil
	case modeParameter:
		at := d.r.pos / 8
		in := d.r.in
		if at >= len(in) {
			return false, nil
		}
		if in[at] == paramEnd {
			d.r.pos += 8
			d.mode = modeTransparent
			if dc.OnParameters != nil {
				dc.OnParameters(d.params)
			}
			return true, nil
		}
		if at+1 >= len(in) || at+2+int(in[at+1]) > len(in) {
			return false, nil
		}
		l := int(in[at+1])
		d.params = append(d.params, Parameter{ID: in[at], Value: append([]byte(nil), in[at+2:at+2+l]...)})
		if len(d.params) > 64 {
			return false, d.corrupt("more than 64 parameters")
		}
		d.r.pos += 8 * (2 + l)
		return true, nil
	}
	// Compressed mode: one code, or nothing if it is cut.
	snap := struct {
		pos     int
		c2, c5  uint
		stepup  bool
		afterCW bool
	}{d.r.pos, d.c2, d.c5, d.stepup, d.afterCW}
	if d.r.pos >= 8*len(d.r.in) {
		return false, nil
	}
	d.r.short = false
	if err := d.step(); err != nil {
		if d.r.short {
			d.r.pos, d.c2, d.c5, d.stepup, d.afterCW = snap.pos, snap.c2, snap.c5, snap.stepup, snap.afterCW
			return false, nil
		}
		return false, err
	}
	return true, nil
}
