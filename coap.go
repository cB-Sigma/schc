// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CoAP field IDs (RFC 8824). The header fields are labelled in header
// order; every option instance gets the FID of its option number, with
// Pos counting the instances of that option from 1, and its value as the
// field (the option's delta and length are not fields: they are rebuilt
// from the option number and the value). The payload marker is not a field
// either: it is sent when, and only when, the payload is not empty, as
// RFC 7252 3 requires.
//
// The OSCORE option (RFC 8613 6.1) is labelled as the four fields of RFC
// 8824 6.4: flags (the first byte), piv, kidctx (the s byte and the kid
// context) and kid. Each is empty when its part is absent; an empty OSCORE
// option gives four empty fields.
const (
	FCoAPVersion    = "coap.version"    // 2 bits
	FCoAPType       = "coap.type"       // 2 bits
	FCoAPTKL        = "coap.tkl"        // 4 bits, or 12 or 20 with the extended length of RFC 8974
	FCoAPCode       = "coap.code"       // 8 bits
	FCoAPCodeClass  = "coap.codeClass"  // first 3 bits of the code, when a rule describes them apart
	FCoAPCodeDetail = "coap.codeDetail" // last 5 bits of the code
	FCoAPMID        = "coap.mid"        // 16 bits
	FCoAPToken      = "coap.token"      // TKL bytes (fl "tkl" in a rule)

	FCoAPIfMatch        = "coap.ifMatch"                       // 1, RFC 7252
	FCoAPUriHost        = "coap.uriHost"                       // 3
	FCoAPETag           = "coap.etag"                          // 4
	FCoAPIfNoneMatch    = "coap.ifNoneMatch"                   // 5
	FCoAPObserve        = "coap.observe"                       // 6, RFC 7641
	FCoAPUriPort        = "coap.uriPort"                       // 7
	FCoAPLocationPath   = "coap.locationPath"                  // 8
	FCoAPUriPath        = "coap.uriPath"                       // 11
	FCoAPContentFormat  = "coap.contentFormat"                 // 12
	FCoAPMaxAge         = "coap.maxAge"                        // 14
	FCoAPUriQuery       = "coap.uriQuery"                      // 15
	FCoAPHopLimit       = "coap.hopLimit"                      // 16, RFC 8768
	FCoAPAccept         = "coap.accept"                        // 17
	FCoAPQBlock1        = "coap.qBlock1"                       // 19, RFC 9177
	FCoAPLocationQuery  = "coap.locationQuery"                 // 20
	FCoAPEDHOC          = "coap.edhoc"                         // 21, RFC 9668
	FCoAPBlock2         = "coap.block2"                        // 23, RFC 7959
	FCoAPBlock1         = "coap.block1"                        // 27, RFC 7959
	FCoAPSize2          = "coap.size2"                         // 28, RFC 7959
	FCoAPQBlock2        = "coap.qBlock2"                       // 31, RFC 9177
	FCoAPProxyURI       = "coap.proxyUri"                      // 35
	FCoAPProxyScheme    = "coap.proxyScheme"                   // 39
	FCoAPSize1          = "coap.size1"                         // 60
	FCoAPEcho           = "coap.echo"                          // 252, RFC 9175
	FCoAPNoResponse     = "coap.noResponse"                    // 258, RFC 7967
	FCoAPRequestTag     = "coap.requestTag"                    // 292, RFC 9175
	FCoAPOCFAcceptCFVer = "coap.ocfAcceptContentFormatVersion" // 2049
	FCoAPOCFCFVer       = "coap.ocfContentFormatVersion"       // 2053

	FOSCOREFlags  = "coap.oscore.flags"  // option 9 (RFC 8613), its first byte (RFC 8824 6.4)
	FOSCOREPIV    = "coap.oscore.piv"    // the Partial IV, n bytes
	FOSCOREKIDCtx = "coap.oscore.kidctx" // the s byte and the kid context
	FOSCOREKID    = "coap.oscore.kid"    // the kid, the rest of the value
)

// OptionOSCORE is the OSCORE option number (RFC 8613 2).
const OptionOSCORE = 9

// coapOptionNames are the FIDs of the option numbers we name. Any other
// option number n is labelled "coap.option.n".
var coapOptionNames = map[uint32]string{
	1: FCoAPIfMatch, 3: FCoAPUriHost, 4: FCoAPETag, 5: FCoAPIfNoneMatch, 6: FCoAPObserve,
	7: FCoAPUriPort, 8: FCoAPLocationPath, 11: FCoAPUriPath, 12: FCoAPContentFormat,
	14: FCoAPMaxAge, 15: FCoAPUriQuery, 16: FCoAPHopLimit, 17: FCoAPAccept, 19: FCoAPQBlock1,
	20: FCoAPLocationQuery, 21: FCoAPEDHOC, 23: FCoAPBlock2, 27: FCoAPBlock1, 28: FCoAPSize2,
	31: FCoAPQBlock2, 35: FCoAPProxyURI, 39: FCoAPProxyScheme, 60: FCoAPSize1, 252: FCoAPEcho,
	258: FCoAPNoResponse, 292: FCoAPRequestTag, 2049: FCoAPOCFAcceptCFVer, 2053: FCoAPOCFCFVer,
}

var coapOptionNumbers = func() map[string]uint32 {
	m := map[string]uint32{}
	for n, f := range coapOptionNames {
		m[f] = n
	}
	for _, f := range []string{FOSCOREFlags, FOSCOREPIV, FOSCOREKIDCtx, FOSCOREKID} {
		m[f] = OptionOSCORE
	}
	return m
}()

// textOptions hold UTF-8 strings (RFC 7252 3.2 "string" format): a rule's
// JSON string target value for them is the text itself, not hexadecimal.
var textOptions = map[string]bool{
	FCoAPUriHost: true, FCoAPLocationPath: true, FCoAPUriPath: true, FCoAPUriQuery: true,
	FCoAPLocationQuery: true, FCoAPProxyURI: true, FCoAPProxyScheme: true,
}

// CoAPOptionFID is the field ID of a CoAP option number (the OSCORE option
// is labelled as its four parts; this returns "coap.oscore").
func CoAPOptionFID(n uint32) string {
	if n == OptionOSCORE {
		return "coap.oscore"
	}
	if f, ok := coapOptionNames[n]; ok {
		return f
	}
	return "coap.option." + strconv.FormatUint(uint64(n), 10)
}

// CoAPOptionNumber is the option number of a CoAP option FID, including
// "coap.option.n" and the four OSCORE parts.
func CoAPOptionNumber(fid string) (uint32, bool) {
	if n, ok := coapOptionNumbers[fid]; ok {
		return n, true
	}
	if s, ok := strings.CutPrefix(fid, "coap.option."); ok {
		n, err := strconv.ParseUint(s, 10, 16)
		if err == nil && n != OptionOSCORE {
			return uint32(n), true
		}
	}
	return 0, false
}

// coapHeaderLengths are the fixed lengths of the CoAP header fields.
var coapHeaderLengths = map[string]int{
	FCoAPVersion: 2, FCoAPType: 2, FCoAPTKL: 4, FCoAPCode: 8, FCoAPMID: 16,
	FCoAPCodeClass: 3, FCoAPCodeDetail: 5,
}

// isCoAPFID reports whether fid is labelled by the coap or coap-inner layer.
func isCoAPFID(fid string) bool {
	if _, ok := coapHeaderLengths[fid]; ok {
		return true
	}
	if fid == FCoAPToken {
		return true
	}
	_, ok := CoAPOptionNumber(fid)
	return ok
}

// knownFID reports whether some layer labels fid.
func knownFID(fid string) bool {
	if _, ok := fieldLengths[fid]; ok || variableFIDs[fid] {
		return true
	}
	if _, ok := subfieldOf[fid]; ok {
		return true
	}
	return isCoAPFID(fid)
}

// parseCoAP labels a CoAP message (inner: the OSCORE plaintext of RFC 8613
// 5.3, code and options only) and returns its payload.
func parseCoAP(b []byte, inner bool, add func(fid string, v Bits)) ([]byte, error) {
	if inner {
		if len(b) < 1 {
			return nil, errNotStack
		}
		add(FCoAPCode, BytesOf(b[0:1]).Clone())
		b = b[1:]
	} else {
		if len(b) < 4 || b[0]>>6 != 1 {
			return nil, errNotStack
		}
		// The token length (RFC 8974 2.1): the TKL nibble, then for 13 and
		// 14 one or two bytes after the header. SCHC takes nibble and
		// extension as one TKL field of 4, 12 or 20 bits
		// (draft-ietf-schc-8824-update 4.3).
		ext := extLen[b[0]&0x0F]
		if b[0]&0x0F == 15 || len(b) < 4+ext {
			return nil, errNotStack
		}
		var tklField Bits
		tklField.AppendUint(uint64(b[0]&0x0F), 4)
		tklField.AppendBytes(b[4 : 4+ext])
		tkl, _ := tokenLength(tklField)
		if len(b) < 4+ext+tkl {
			return nil, errNotStack
		}
		h := BytesOf(b[0:4])
		add(FCoAPVersion, h.Slice(0, 2))
		add(FCoAPType, h.Slice(2, 4))
		add(FCoAPTKL, tklField.Clone())
		add(FCoAPCode, h.Slice(8, 16))
		add(FCoAPMID, h.Slice(16, 32))
		if tkl > 0 {
			add(FCoAPToken, BytesOf(append([]byte(nil), b[4+ext:4+ext+tkl]...)))
		}
		b = b[4+ext+tkl:]
	}
	var num uint32
	for len(b) > 0 {
		if b[0] == 0xFF {
			if len(b) == 1 {
				return nil, errNotStack // a marker with no payload is a format error (RFC 7252 3)
			}
			return append([]byte(nil), b[1:]...), nil
		}
		d, l := uint32(b[0]>>4), uint32(b[0]&0x0F)
		b = b[1:]
		var err error
		if d, b, err = optExt(d, b); err != nil {
			return nil, err
		}
		if l, b, err = optExt(l, b); err != nil {
			return nil, err
		}
		num += d
		if num > 0xFFFF || uint32(len(b)) < l {
			return nil, errNotStack
		}
		v := append([]byte(nil), b[:l]...)
		b = b[l:]
		if num == OptionOSCORE {
			flags, piv, kidctx, kid, err := splitOSCORE(v)
			if err != nil {
				return nil, err
			}
			add(FOSCOREFlags, BytesOf(flags))
			add(FOSCOREPIV, BytesOf(piv))
			add(FOSCOREKIDCtx, BytesOf(kidctx))
			add(FOSCOREKID, BytesOf(kid))
			continue
		}
		add(CoAPOptionFID(num), BytesOf(v))
	}
	return nil, nil
}

// extLen is the number of bytes of extended token length after the CoAP
// header for each TKL nibble (RFC 8974 2.1).
var extLen = [16]int{13: 1, 14: 2}

// tokenLength is the token length in bytes a TKL field of 4, 12 or 20
// bits gives (RFC 8974 2.1: nibble 13 adds 13 to the byte after it, 14
// adds 269 to the two); ok is false for a field of another size or a
// nibble of 15.
func tokenLength(tkl Bits) (int, bool) {
	if tkl.Len() < 4 {
		return 0, false
	}
	n := tkl.UintAt(0, 4)
	switch {
	case n == 13 && tkl.Len() == 12:
		return 13 + int(tkl.UintAt(4, 8)), true
	case n == 14 && tkl.Len() == 20:
		return 269 + int(tkl.UintAt(4, 16)), true
	case n < 13 && tkl.Len() == 4:
		return int(n), true
	}
	return 0, false
}

// optExt reads an option delta or length nibble's extension (RFC 7252 3.1).
func optExt(n uint32, b []byte) (uint32, []byte, error) {
	switch n {
	case 13:
		if len(b) < 1 {
			return 0, nil, errNotStack
		}
		return 13 + uint32(b[0]), b[1:], nil
	case 14:
		if len(b) < 2 {
			return 0, nil, errNotStack
		}
		return 269 + (uint32(b[0])<<8 | uint32(b[1])), b[2:], nil
	case 15:
		return 0, nil, errNotStack
	}
	return n, b, nil
}

// splitOSCORE cuts an OSCORE option value into the four parts of RFC 8824
// 6.4: the flag byte, the Partial IV (n bytes), the kid context with its
// size byte s (when h is set) and the kid (the rest; RFC 8613 6.1). The
// parts put back together are always the value.
func splitOSCORE(v []byte) (flags, piv, kidctx, kid []byte, err error) {
	if len(v) == 0 {
		return nil, nil, nil, nil, nil
	}
	flags, v = v[:1], v[1:]
	n := int(flags[0] & 0x07)
	if n > len(v) {
		return nil, nil, nil, nil, errNotStack
	}
	piv, v = v[:n], v[n:]
	if flags[0]&0x10 != 0 {
		if len(v) < 1 || len(v) < 1+int(v[0]) {
			return nil, nil, nil, nil, errNotStack
		}
		s := 1 + int(v[0])
		kidctx, v = v[:s], v[s:]
	}
	return flags, piv, kidctx, v, nil
}

// coapOption is one option to write.
type coapOption struct {
	num   uint32
	pos   int
	value []byte
}

// buildCoAP writes a CoAP message (inner: an OSCORE plaintext) from its
// labelled fields and payload.
func buildCoAP(fields []Field, payload []byte, inner bool) ([]byte, error) {
	one := map[string]Bits{}
	var opts []coapOption
	osc := map[int]*[4][]byte{} // OSCORE parts by position
	oscSet := map[int]*[4]bool{}
	for _, f := range fields {
		if !isCoAPFID(f.FID) {
			continue
		}
		if _, hdr := coapHeaderLengths[f.FID]; hdr || f.FID == FCoAPToken {
			if _, dup := one[f.FID]; dup {
				return nil, fmt.Errorf("schc: field %s appears twice", f.FID)
			}
			one[f.FID] = f.Value
			continue
		}
		if f.Value.Len()%8 != 0 {
			return nil, fmt.Errorf("schc: option field %s has %d bits, not whole bytes", f.FID, f.Value.Len())
		}
		n, _ := CoAPOptionNumber(f.FID)
		if n == OptionOSCORE {
			part := map[string]int{FOSCOREFlags: 0, FOSCOREPIV: 1, FOSCOREKIDCtx: 2, FOSCOREKID: 3}[f.FID]
			if osc[f.Pos] == nil {
				osc[f.Pos], oscSet[f.Pos] = &[4][]byte{}, &[4]bool{}
			}
			if oscSet[f.Pos][part] {
				return nil, fmt.Errorf("schc: field %s position %d appears twice", f.FID, f.Pos)
			}
			osc[f.Pos][part], oscSet[f.Pos][part] = f.Value.Bytes(), true
			continue
		}
		opts = append(opts, coapOption{num: n, pos: f.Pos, value: f.Value.Bytes()})
	}
	for pos, parts := range osc {
		if *oscSet[pos] != [4]bool{true, true, true, true} {
			return nil, errors.New("schc: an OSCORE option needs its four fields (flags, piv, kidctx, kid)")
		}
		var v []byte
		for _, p := range parts {
			v = append(v, p...)
		}
		opts = append(opts, coapOption{num: OptionOSCORE, pos: pos, value: v})
	}
	sort.SliceStable(opts, func(i, j int) bool {
		if opts[i].num != opts[j].num {
			return opts[i].num < opts[j].num
		}
		return opts[i].pos < opts[j].pos
	})
	get := func(fid string) (Bits, error) {
		v, ok := one[fid]
		if !ok {
			return Bits{}, fmt.Errorf("schc: field %s has no value", fid)
		}
		if v.Len() != coapHeaderLengths[fid] {
			return Bits{}, fmt.Errorf("schc: field %s has %d bits, not %d", fid, v.Len(), coapHeaderLengths[fid])
		}
		return v, nil
	}
	var h Bits
	if inner {
		v, err := get(FCoAPCode)
		if err != nil {
			return nil, err
		}
		h.Append(v)
		for _, fid := range []string{FCoAPVersion, FCoAPType, FCoAPTKL, FCoAPMID, FCoAPToken} {
			if _, ok := one[fid]; ok {
				return nil, fmt.Errorf("schc: field %s is not part of an OSCORE plaintext", fid)
			}
		}
	} else {
		tklField, ok := one[FCoAPTKL]
		if !ok {
			return nil, fmt.Errorf("schc: field %s has no value", FCoAPTKL)
		}
		tkl, ok := tokenLength(tklField)
		if !ok {
			return nil, fmt.Errorf("schc: field %s of %d bits is not a token length (RFC 8974)", FCoAPTKL, tklField.Len())
		}
		for _, fid := range []string{FCoAPVersion, FCoAPType} {
			v, err := get(fid)
			if err != nil {
				return nil, err
			}
			h.Append(v)
		}
		h.Append(tklField.Slice(0, 4))
		for _, fid := range []string{FCoAPCode, FCoAPMID} {
			v, err := get(fid)
			if err != nil {
				return nil, err
			}
			h.Append(v)
		}
		h.Append(tklField.Slice(4, tklField.Len())) // the extended length, if any
		tok := one[FCoAPToken]
		if tok.Len() != 8*tkl {
			return nil, fmt.Errorf("schc: the token has %d bits and TKL says %d bytes", tok.Len(), tkl)
		}
		h.Append(tok)
	}
	out := h.Bytes()
	var last uint32
	for _, o := range opts {
		d, l := o.num-last, uint32(len(o.value))
		if len(o.value) > 0xFFFF+269 {
			return nil, fmt.Errorf("schc: option %d of %d bytes is too long for CoAP", o.num, len(o.value))
		}
		last = o.num
		dn, dx := optNibble(d)
		ln, lx := optNibble(l)
		out = append(out, byte(dn<<4|ln))
		out = append(out, dx...)
		out = append(out, lx...)
		out = append(out, o.value...)
	}
	if len(payload) > 0 {
		out = append(out, 0xFF)
		out = append(out, payload...)
	}
	return out, nil
}

// optNibble is an option delta or length as its nibble and extension.
func optNibble(n uint32) (uint32, []byte) {
	switch {
	case n < 13:
		return n, nil
	case n < 269:
		return 13, []byte{byte(n - 13)}
	}
	n -= 269
	return 14, []byte{byte(n >> 8), byte(n)}
}
