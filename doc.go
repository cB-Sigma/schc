// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package schc is Static Context Header Compression and fragmentation (RFC
// 8724) with the LoRaWAN profile of RFC 9011.
//
// Compression (compress.go): rules of field descriptors (FID, FL, FP, DI,
// TV, MO, CDA) matched as clause 7.2 says; the matching operators equal,
// ignore, MSB(x) and match-mapping; the actions not-sent, value-sent,
// mapping-sent, LSB, compute, DevIID and AppIID; variable-length residues
// with their 4/12/28-bit sizes. Fields are labelled by our parsers for
// IPv6 and UDP (clause 10, addresses and ports by Dev/App role) and the
// IEC 62056-4-7 wrapper header (fields.go); compute rebuilds the IPv6 and
// UDP lengths, the UDP checksum and the wrapper length, and a compute or
// DevIID field is elided only when the other end rebuilds the same value.
//
// Fragmentation (frag.go, sender.go, receiver.go): the message formats of
// clause 8.3 with bitmap compression, the CRC32 RCS of 8.2.3, and the
// sender and receiver of No-ACK, ACK-Always and ACK-on-Error (8.4) as
// clock-driven state machines without I/O.
//
// LoRaWAN (lorawan.go): RuleID in the FPort, the uplink ACK-on-Error and
// downlink ACK-Always rules with their parameters and class timers, the
// multicast No-ACK rule, and the AES-CMAC IID of RFC 9011 5.3.
//
// Rules are our own JSON (rule.go). RFC 9363's YANG data model is not
// implemented and is not claimed.
package schc
