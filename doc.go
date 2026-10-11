// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package schc is Static Context Header Compression and fragmentation (RFC
// 8724) for IPv6, IPv4, UDP, SCTP, ICMPv6 and CoAP (RFC 8824, with the
// extended token lengths of RFC 8974), with the LoRaWAN profile of RFC
// 9011, the Sigfox profile of RFC 9442, the Compound ACK of RFC 9441 and
// rules in the RFC 9363 data model, implicit rules included.
//
// Compression (compress.go): rules of field descriptors (FID, FL, FP, DI,
// TV, MO, CDA) matched as clause 7.2 says; the matching operators equal,
// ignore, MSB(x) and match-mapping; the actions not-sent, value-sent,
// mapping-sent, LSB, compute, DevIID and AppIID; variable-length residues
// with their 4/12/28-bit sizes. Fields are labelled by our parsers for
// IPv6 and UDP (clause 10, addresses and ports by Dev/App role), ICMPv6
// Echo, the IEC 62056-4-7 wrapper header (fields.go) and CoAP (coap.go);
// compute rebuilds the IPv6 and UDP lengths, the UDP and ICMPv6 checksums
// and the wrapper length, and a compute or DevIID field is elided only
// when the other end rebuilds the same value. A rule may describe the
// IPv6 Traffic Class as DSCP and ECN and the CoAP code as class and
// detail (RFC 9363's subfield identities).
//
// CoAP (coap.go, RFC 8824): the header fields, the token with the "tkl"
// length function (4.5), every option by number with the OSCORE option
// cut into flags, piv, kidctx and kid (6.4), and entries that group
// several Uri-Path or Uri-Query elements (5.3). The stack "coap" is a
// whole CoAP message, alone or as "ipv6/udp/coap" in one rule; the stack
// "coap-inner" is an OSCORE plaintext, for the inner rules of 7.2, whose
// encrypted result an outer rule compresses as the payload of the
// protected message. OSCORE protection itself is the caller's.
//
// Fragmentation (frag.go, sender.go, receiver.go): the message formats of
// clause 8.3 with bitmap compression, the RCS of 8.2.3 (CRC32 by default,
// others through RegisterRCS, rcs.go), and the sender and receiver of
// No-ACK, ACK-Always and ACK-on-Error (8.4) as clock-driven state
// machines without I/O. With a rule's CompoundAck the ACK-on-Error
// receiver reports every window with missing tiles in one SCHC Compound
// ACK and the sender reads it (RFC 9441).
//
// IPv4 (RFC 791, options as one field) and the SCTP common header (RFC
// 9260) are labelled too; compute rebuilds IHL, Total Length, the header
// checksum, the UDP checksum over IPv4 and the SCTP CRC32c.
//
// Sigfox (sigfox.go, RFC 9442): the uplink No-ACK rule, the three uplink
// ACK-on-Error header layouts with the Compound ACK in 8-byte downlinks,
// and the downlink ACK-Always rule, built from profile options any rule
// may use (FragParams: HeaderPadded, the fragment-count RCS,
// FCNCountdown, FullFragments, NoAckReq, BitmapUncompressed, AckMaxBits).
//
// LoRaWAN (lorawan.go): RuleID in the FPort, the uplink ACK-on-Error and
// downlink ACK-Always rules with their parameters and class timers, the
// multicast No-ACK rule, and the AES-CMAC IID of RFC 9011 5.3.
//
// Rules (rule.go, yang.go): our own JSON, which every feature has, and the
// RFC 9363 data model in RFC 7951 JSON (ParseYANG, MarshalYANG) with the
// RFC 9441 augment; package coreconf carries the latter in CBOR with SIDs.
package schc
