// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44

import (
	"errors"
	"fmt"
)

// Parameter is one negotiation parameter of Table 10: its identifier and
// value octets.
type Parameter struct {
	ID    byte
	Value []byte
}

// Identifiers of Table 10.
const (
	ParamSetID       = 0x40 // parameter set identifier, "V44" (annex A)
	ParamCapability  = 0x41 // C0: P, M and N bits
	ParamRequest     = 0x42 // P0: directions
	ParamCodewordsTx = 0x43 // P1T
	ParamCodewordsRx = 0x44 // P1R
	ParamMaxStringTx = 0x45 // P2T
	ParamMaxStringRx = 0x46 // P2R
	ParamHistoryTx   = 0x47 // P3T
	ParamHistoryRx   = 0x48 // P3R
)

// Proposal is what one end proposes: the V.44 capability (C0) and the
// values of Table 10, in the directions of its own encoder (Tx) and
// decoder (Rx). Zero sizes are not sent, which leaves the peer the
// defaults.
type Proposal struct {
	// Packet and MultiPacket are the P and M bits (annex A, annex B):
	// the packet-network methods supported. Neither is a modem link.
	Packet, MultiPacket bool
	// AfterLink is the N bit: parameters negotiated in parameter mode
	// after the link is up (7.4.2) rather than in the XID exchange.
	AfterLink bool
	// Transmit and Receive are P0: compression wanted in the direction
	// of this end's encoder and of its decoder.
	Transmit, Receive        bool
	TxCodewords, RxCodewords int // P1T, P1R: 256 to 65535
	TxMaxString, RxMaxString int // P2T, P2R: 32 to 255
	TxHistory, RxHistory     int // P3T, P3R: 512 or more
}

// Parameters lists the proposal as Table 10 parameters, C0 and P0 first.
func (p Proposal) Parameters() []Parameter {
	c0 := byte(0)
	if p.Packet {
		c0 |= 0x80
	}
	if p.MultiPacket {
		c0 |= 0x40
	}
	if p.AfterLink {
		c0 |= 0x01
	}
	p0 := byte(0)
	if p.Transmit {
		p0 |= 0x01
	}
	if p.Receive {
		p0 |= 0x02
	}
	ps := []Parameter{{ParamCapability, []byte{c0}}, {ParamRequest, []byte{p0}}}
	add16 := func(id byte, v int) {
		if v > 0 {
			ps = append(ps, Parameter{id, []byte{byte(v >> 8), byte(v)}})
		}
	}
	add8 := func(id byte, v int) {
		if v > 0 {
			ps = append(ps, Parameter{id, []byte{byte(v)}})
		}
	}
	add16(ParamCodewordsTx, p.TxCodewords)
	add16(ParamCodewordsRx, p.RxCodewords)
	add8(ParamMaxStringTx, p.TxMaxString)
	add8(ParamMaxStringRx, p.RxMaxString)
	add16(ParamHistoryTx, p.TxHistory)
	add16(ParamHistoryRx, p.RxHistory)
	return ps
}

// ProposalOf reads a proposal from Table 10 parameters (from parameter
// mode or an XID). Unknown identifiers are skipped (Table 10 reserves
// them).
func ProposalOf(ps []Parameter) (Proposal, error) {
	var p Proposal
	for _, x := range ps {
		v := x.Value
		num := func(n int) (int, error) {
			if len(v) != n {
				return 0, fmt.Errorf("v44: parameter %#x has %d octets, not %d", x.ID, len(v), n)
			}
			r := 0
			for _, b := range v {
				r = r<<8 | int(b)
			}
			return r, nil
		}
		var err error
		switch x.ID {
		case ParamCapability:
			var c int
			if c, err = num(1); err == nil {
				p.Packet, p.MultiPacket, p.AfterLink = c&0x80 != 0, c&0x40 != 0, c&0x01 != 0
				if p.MultiPacket && !p.Packet {
					err = errors.New("v44: capability PM = 01 is not valid (annex A)")
				}
			}
		case ParamRequest:
			var c int
			if c, err = num(1); err == nil {
				p.Transmit, p.Receive = c&1 != 0, c&2 != 0
			}
		case ParamCodewordsTx:
			p.TxCodewords, err = num(2)
		case ParamCodewordsRx:
			p.RxCodewords, err = num(2)
		case ParamMaxStringTx:
			p.TxMaxString, err = num(1)
		case ParamMaxStringRx:
			p.RxMaxString, err = num(1)
		case ParamHistoryTx:
			p.TxHistory, err = num(2)
		case ParamHistoryRx:
			p.RxHistory, err = num(2)
		}
		if err != nil {
			return Proposal{}, err
		}
	}
	return p, nil
}

func marshalParameters(ps []Parameter) ([]byte, error) {
	var out []byte
	for _, x := range ps {
		if x.ID == paramEnd || len(x.Value) > 255 {
			return nil, fmt.Errorf("v44: parameter %#x cannot be sent", x.ID)
		}
		out = append(out, x.ID, byte(len(x.Value)))
		out = append(out, x.Value...)
	}
	return out, nil
}

func parseParameters(b []byte) ([]Parameter, error) {
	var ps []Parameter
	for len(b) > 0 {
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, errors.New("v44: a parameter runs past the end")
		}
		ps = append(ps, Parameter{ID: b[0], Value: append([]byte(nil), b[2:2+int(b[1])]...)})
		b = b[2+int(b[1]):]
	}
	return ps, nil
}

// MarshalXID is the user data subfield of an XID frame that proposes V.44
// (annex A, Table A.1): group identifier FFh, the parameter set
// identifier "V44", then the parameters. With AfterLink set only C0 and
// P0 go in it; the rest follows in parameter mode (7.4.1, 7.4.2).
func (p Proposal) MarshalXID() []byte {
	ps := p.Parameters()
	if p.AfterLink {
		ps = ps[:2]
	}
	body, _ := marshalParameters(append([]Parameter{{ParamSetID, []byte("V44")}}, ps...))
	return append([]byte{0xFF}, body...)
}

// ParseXID reads the V.44 proposal from an XID user data subfield: the
// parameters after the "V44" parameter set identifier, up to another
// parameter set or the end.
func ParseXID(b []byte) (Proposal, error) {
	if len(b) == 0 || b[0] != 0xFF {
		return Proposal{}, errors.New("v44: not a user data subfield (group identifier FFh)")
	}
	ps, err := parseParameters(b[1:])
	if err != nil {
		return Proposal{}, err
	}
	var mine []Parameter
	in := false
	for _, x := range ps {
		if x.ID == ParamSetID {
			in = string(x.Value) == "V44"
			continue
		}
		if in {
			mine = append(mine, x)
		}
	}
	if mine == nil {
		return Proposal{}, errors.New("v44: the subfield has no V.44 parameter set")
	}
	return ProposalOf(mine)
}

// Agreement is the outcome of a negotiation seen from one end: whether
// and with which parameters its encoder (Tx) and decoder (Rx) run, and
// the method.
type Agreement struct {
	TxOn, RxOn bool
	Tx, Rx     Params
	// Method is MultiPacket when both ends support it, 0 for the packet
	// method (both support only that), Stream for a modem link (neither
	// sets P).
	Method Method
}

// Agree applies 7.4 and annex B to this end's proposal and the peer's:
// each direction runs when the encoder's end asks to send and the
// decoder's end to receive; each size is the lesser of the two proposals
// for that direction (Table 10 defaults where one is absent); a value
// below its minimum is a procedural error.
func Agree(local, peer Proposal) (Agreement, error) {
	var a Agreement
	a.TxOn = local.Transmit && peer.Receive
	a.RxOn = local.Receive && peer.Transmit
	pick := func(x, y, def, lo, hi int, what string) (int, error) {
		if x == 0 {
			x = def
		}
		if y == 0 {
			y = def
		}
		v := min(x, y)
		if v < lo || v > hi {
			return 0, fmt.Errorf("v44: %s %d is outside %d to %d", what, v, lo, hi)
		}
		return v, nil
	}
	dir := func(myCW, peerCW, myN7, peerN7, myN8, peerN8 int) (Params, error) {
		var p Params
		var err error
		if p.Codewords, err = pick(myCW, peerCW, DefaultStreamCodewords, 256, 65535, "number of codewords"); err != nil {
			return p, err
		}
		if p.MaxString, err = pick(myN7, peerN7, DefaultMaxString, 32, 255, "maximum string length"); err != nil {
			return p, err
		}
		if p.History, err = pick(myN8, peerN8, 3*p.Codewords, 512, 1<<30, "history length"); err != nil {
			return p, err
		}
		return p, nil
	}
	var err error
	if a.Tx, err = dir(local.TxCodewords, peer.RxCodewords, local.TxMaxString, peer.RxMaxString, local.TxHistory, peer.RxHistory); err != nil {
		return Agreement{}, err
	}
	if a.Rx, err = dir(local.RxCodewords, peer.TxCodewords, local.RxMaxString, peer.TxMaxString, local.RxHistory, peer.TxHistory); err != nil {
		return Agreement{}, err
	}
	switch {
	case local.MultiPacket && peer.MultiPacket:
		a.Method = MultiPacket
	case local.Packet && peer.Packet:
		a.Method = 0
	case !local.Packet && !peer.Packet:
		a.Method = Stream
	default:
		return Agreement{}, errors.New("v44: one end is a packet network and the other a modem link")
	}
	return a, nil
}
