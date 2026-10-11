// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"time"
)

// SCHC over Sigfox (RFC 9442). Uplink frames carry 0 to 12 bytes, downlink
// frames exactly 8; the L2 Word is a byte (3.2, 3.3, 3.7). The RuleID is
// the first bits of the SCHC header (3.4); uplink fragmentation RuleIDs are
// 3 bits, or 6 bits starting 111, or 8 bits starting 111111 (4.1).
const (
	SigfoxUplinkMTU   = 96 // bits
	SigfoxDownlinkMTU = 64 // bits, every downlink frame
)

// SigfoxHeader is one of the uplink ACK-on-Error header layouts of RFC
// 9442 3.5.1.3.2 and 3.5.1.4.
type SigfoxHeader int

// The uplink ACK-on-Error layouts.
const (
	// SigfoxSingleByte: RuleID 3 bits, W 2, FCN 3, WINDOW_SIZE 7, tiles
	// of 11 bytes, a 3-bit RCS (3.5.1.3.2); RuleIDs 0 to 6.
	SigfoxSingleByte SigfoxHeader = iota
	// SigfoxTwoByte1: RuleID 6 bits, W 2, FCN 4, WINDOW_SIZE 12, tiles of
	// 10 bytes, a 4-bit RCS (3.5.1.4.1); RuleIDs 56 to 62 (111000 to
	// 111110).
	SigfoxTwoByte1
	// SigfoxTwoByte2: RuleID 8 bits, W 3, FCN 5, WINDOW_SIZE 31, tiles of
	// 10 bytes, a 5-bit RCS (3.5.1.4.2); RuleIDs 252 to 255.
	SigfoxTwoByte2
)

// sigfoxCommon are the parameters every Sigfox fragmentation rule shares:
// the RCS is a fragment count (3.5.1.5), the All-1's header is padded to a
// byte (figures 4, 7, 14, 21, 27), and the All-1, not an ACK REQ, asks for
// the ACK (3.6.2.1); MAX_ACK_REQUESTS is 5 and both timers default to 12
// hours.
func sigfoxCommon(p *FragParams) {
	p.RCS = RCSFragmentCount
	p.HeaderPadded = true
	p.MaxAckRequests = 5
	p.Retransmission = Duration(12 * time.Hour)
	p.Inactivity = Duration(12 * time.Hour)
}

// SigfoxUplinkNoAckRule is the uplink No-ACK rule of RFC 9442 3.5.1.3.1:
// RuleID 3 bits (0 to 6), no DTag or W, a 5-bit FCN counting down to 1
// with the All-1 last, 11-byte tiles, a 5-bit RCS, at most 340 bytes.
func SigfoxUplinkNoAckRule(id uint32) (Rule, error) {
	if id > 6 {
		return Rule{}, fmt.Errorf("schc: Sigfox single-byte RuleID %d is not 0 to 6 (RFC 9442 4.1)", id)
	}
	p := &FragParams{Mode: NoAck, Direction: Up, FCNSize: 5, RCSSize: 5, FCNCountdown: true, FullFragments: true}
	sigfoxCommon(p)
	return Rule{ID: id, IDLength: 3, Kind: KindFragmentation, Name: "sigfox-uplink-no-ack", Fragmentation: p}, nil
}

// SigfoxUplinkRule is an uplink ACK-on-Error rule of RFC 9442 in one of
// the three header layouts, with the SCHC Compound ACK (RFC 9441) its
// receiver must send, bitmaps whole, and the last tile in the All-1 when it
// fits there (else the All-1 follows it alone).
func SigfoxUplinkRule(id uint32, h SigfoxHeader) (Rule, error) {
	p := &FragParams{Mode: AckOnError, Direction: Up, CompoundAck: true, LastBitmapUncompressed: true,
		BitmapUncompressed: true, NoAckReq: true, LastTile: LastTileAll1, AckMaxBits: SigfoxDownlinkMTU}
	var idLen int
	switch h {
	case SigfoxSingleByte:
		if id > 6 {
			return Rule{}, fmt.Errorf("schc: Sigfox single-byte RuleID %d is not 0 to 6 (RFC 9442 4.1)", id)
		}
		idLen, p.WSize, p.FCNSize, p.WindowSize, p.TileSize, p.RCSSize = 3, 2, 3, 7, 88, 3
	case SigfoxTwoByte1:
		if id < 0b111000 || id > 0b111110 {
			return Rule{}, fmt.Errorf("schc: Sigfox two-byte RuleID %d is not 111000 to 111110 (RFC 9442 4.1)", id)
		}
		idLen, p.WSize, p.FCNSize, p.WindowSize, p.TileSize, p.RCSSize = 6, 2, 4, 12, 80, 4
	case SigfoxTwoByte2:
		if id < 0b11111100 || id > 0b11111111 {
			return Rule{}, fmt.Errorf("schc: Sigfox two-byte RuleID %d is not 11111100 to 11111111 (RFC 9442 4.1)", id)
		}
		idLen, p.WSize, p.FCNSize, p.WindowSize, p.TileSize, p.RCSSize = 8, 3, 5, 31, 80, 5
	default:
		return Rule{}, errors.New("schc: unknown Sigfox header layout")
	}
	sigfoxCommon(p)
	return Rule{ID: id, IDLength: idLen, Kind: KindFragmentation, Name: "sigfox-uplink-ack-on-error", Fragmentation: p}, nil
}

// SigfoxDownlinkRule is the downlink ACK-Always rule of RFC 9442 3.5.2:
// RuleID 3 bits (0 to 7), no DTag or W (one window), a 5-bit FCN,
// WINDOW_SIZE 31, 7-byte tiles filling each 8-byte frame, a 5-bit RCS and
// whole bitmaps in the device's ACK.
func SigfoxDownlinkRule(id uint32) (Rule, error) {
	if id > 7 {
		return Rule{}, fmt.Errorf("schc: Sigfox downlink RuleID %d is not 0 to 7 (RFC 9442 4.2)", id)
	}
	p := &FragParams{Mode: AckAlways, Direction: Down, FCNSize: 5, WindowSize: 31, RCSSize: 5,
		BitmapUncompressed: true, NoAckReq: true, FullFragments: true}
	sigfoxCommon(p)
	return Rule{ID: id, IDLength: 3, Kind: KindFragmentation, Name: "sigfox-downlink-ack-always", Fragmentation: p}, nil
}

// SigfoxDownlinkPayload pads a SCHC message with zeros to the 8 bytes of
// a Sigfox downlink frame (RFC 9442 3.7): every ACK and every downlink
// fragment travels so.
//
// A downlink All-1's padding cannot be told from tile bytes; RFC 9442
// leaves the length of the last tile to the receiver, and reassembly here
// keeps the padding as part of it (see PROVENANCE.md).
func SigfoxDownlinkPayload(msg Bits) ([]byte, error) {
	if msg.Len() > SigfoxDownlinkMTU {
		return nil, fmt.Errorf("schc: a %d-bit message does not fit a Sigfox downlink frame", msg.Len())
	}
	out := make([]byte, SigfoxDownlinkMTU/8)
	copy(out, msg.Bytes())
	return out, nil
}
