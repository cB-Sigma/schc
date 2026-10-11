// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"crypto/aes"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// SCHC over LoRaWAN (RFC 9011). The RuleID is 8 bits carried in the
// LoRaWAN FPort; the SCHC Message is FPort then FRMPayload (5.1, 5.2). The
// L2 Word is a byte and padding is zeros (5.4, 5.6).
const (
	// FPortUp is the recommended uplink fragmentation RuleID (5.2).
	FPortUp = 20
	// FPortDown is the recommended downlink fragmentation RuleID.
	FPortDown = 21
	// FPortNoCompression is the recommended RuleID for a packet no rule
	// compresses.
	FPortNoCompression = 22
)

// LoRaWAN device classes (RFC 9011 4.1).
const (
	ClassA = "A"
	ClassB = "B"
	ClassC = "C"
)

// LoRaWANUplinkRule is the uplink fragmentation rule of RFC 9011 5.6.2:
// ACK-on-Error, T=0, M=2, N=6, WINDOW_SIZE 63, 10-byte tiles, CRC32 RCS,
// MAX_ACK_REQUESTS 8, 12-hour timers, last tile in either fragment,
// regular penultimate tile. ackEveryWindow is the per-rule choice 5.6.2
// adds (recommended for battery devices).
func LoRaWANUplinkRule(fport uint8, tileBytes int, ackEveryWindow bool) Rule {
	if tileBytes == 0 {
		tileBytes = 10
	}
	return Rule{ID: uint32(fport), IDLength: 8, Kind: KindFragmentation, Name: "lorawan-uplink-fragmentation",
		Fragmentation: &FragParams{Mode: AckOnError, Direction: Up, DTagSize: 0, WSize: 2, FCNSize: 6, WindowSize: 63,
			TileSize: 8 * tileBytes, RCSSize: 32, MaxAckRequests: 8,
			Retransmission: Duration(12 * time.Hour), Inactivity: Duration(12 * time.Hour),
			LastTile: LastTileEither, AckEveryWindow: ackEveryWindow}}
}

// LoRaWANDownlinkRule is the unicast downlink fragmentation rule of RFC
// 9011 5.6.3: ACK-Always, T=0, M=1, N=1, WINDOW_SIZE 1, CRC32 RCS,
// MAX_ACK_REQUESTS 8, with the timers of the device class (5.6.3.5):
// class A inactivity 36 h and retransmission inactivity/(MAX+1); class B
// three ping slot periods; class C 30 s; B and C inactivity 12 h.
func LoRaWANDownlinkRule(fport uint8, class string, pingSlot time.Duration) Rule {
	inact := 12 * time.Hour
	var retrans time.Duration
	switch class {
	case ClassB:
		if pingSlot <= 0 {
			pingSlot = 32 * time.Second
		}
		retrans = 3 * pingSlot
	case ClassC:
		retrans = 30 * time.Second
	default:
		inact = 36 * time.Hour
		retrans = inact / 9
	}
	return Rule{ID: uint32(fport), IDLength: 8, Kind: KindFragmentation, Name: "lorawan-downlink-fragmentation",
		Fragmentation: &FragParams{Mode: AckAlways, Direction: Down, DTagSize: 0, WSize: 1, FCNSize: 1, WindowSize: 1,
			RCSSize: 32, MaxAckRequests: 8, Retransmission: Duration(retrans), Inactivity: Duration(inact)}}
}

// LoRaWANMulticastRule is the multicast downlink rule of RFC 9011 5.6.3:
// No-ACK, T=0, N=1.
func LoRaWANMulticastRule(fport uint8) Rule {
	return Rule{ID: uint32(fport), IDLength: 8, Kind: KindFragmentation, Name: "lorawan-multicast-fragmentation",
		Fragmentation: &FragParams{Mode: NoAck, Direction: Down, FCNSize: 1, RCSSize: 32, Inactivity: Duration(12 * time.Hour)}}
}

// LoRaWANFrame is a SCHC Message as it travels on LoRaWAN: the FPort and
// the FRMPayload.
type LoRaWANFrame struct {
	FPort   uint8
	Payload []byte
}

// ToLoRaWAN splits a SCHC Message (8-bit RuleID first) into FPort and
// payload, padding with zeros to whole bytes (RFC 9011 5.1, 5.4).
func ToLoRaWAN(msg Bits) (LoRaWANFrame, error) {
	if msg.Len() < 8 {
		return LoRaWANFrame{}, errors.New("schc: a SCHC Message on LoRaWAN starts with an 8-bit RuleID")
	}
	b := msg.Bytes()
	if b[0] == 0 || b[0] > 223 {
		return LoRaWANFrame{}, fmt.Errorf("schc: RuleID %d is not a LoRaWAN application FPort (1 to 223)", b[0])
	}
	return LoRaWANFrame{FPort: b[0], Payload: b[1:]}, nil
}

// FromLoRaWAN joins FPort and FRMPayload into the SCHC Message (RFC 9011
// 5.1, 5.5).
func FromLoRaWAN(fport uint8, payload []byte) Bits {
	b := make([]byte, 1+len(payload))
	b[0] = fport
	copy(b[1:], payload)
	return BytesOf(b)
}

// LoRaWANIID is the Dev IPv6 interface identifier of RFC 9011 5.3: the
// first 8 bytes of AES128-CMAC(AppSKey, DevEUI).
func LoRaWANIID(appSKey, devEUI []byte) ([]byte, error) {
	if len(appSKey) != 16 || len(devEUI) != 8 {
		return nil, errors.New("schc: the IID needs a 16-byte AppSKey and an 8-byte DevEUI")
	}
	mac, err := cmacAES128(appSKey, devEUI)
	if err != nil {
		return nil, err
	}
	return mac[:8], nil
}

// cmacAES128 is AES-CMAC (RFC 4493).
func cmacAES128(key, msg []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var zero, l [16]byte
	c.Encrypt(l[:], zero[:])
	k1 := dbl(l)
	k2 := dbl(k1)
	n := (len(msg) + 15) / 16
	complete := n > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	var last [16]byte
	if complete {
		copy(last[:], msg[16*(n-1):])
		subtle.XORBytes(last[:], last[:], k1[:])
	} else {
		rem := msg[16*(n-1):]
		copy(last[:], rem)
		last[len(rem)] = 0x80
		subtle.XORBytes(last[:], last[:], k2[:])
	}
	var x [16]byte
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x[:], x[:], msg[16*i:16*i+16])
		c.Encrypt(x[:], x[:])
	}
	subtle.XORBytes(x[:], x[:], last[:])
	c.Encrypt(x[:], x[:])
	return x[:], nil
}

// dbl doubles in GF(2^128) as RFC 4493 2.3 generates subkeys.
func dbl(in [16]byte) [16]byte {
	var out [16]byte
	carry := in[0] >> 7
	for i := 0; i < 15; i++ {
		out[i] = in[i]<<1 | in[i+1]>>7
	}
	out[15] = in[15] << 1
	if carry == 1 {
		out[15] ^= 0x87
	}
	return out
}
