# schc

Static Context Header Compression and fragmentation (SCHC, RFC 8724) for IPv6, IPv4, UDP, SCTP, ICMPv6 and CoAP (RFC 8824, with OSCORE and the extended tokens of RFC 8974), the LoRaWAN (RFC 9011) and Sigfox (RFC 9442) profiles, Compound ACK (RFC 9441), rules in the RFC 9363 YANG model as JSON or CORECONF CBOR (implicit rules included), and V.44 data compression (packet, multi-packet and stream methods), in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/schc.svg)](https://pkg.go.dev/github.com/cB-Sigma/schc) [![test](https://github.com/cB-Sigma/schc/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/schc/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

No cgo. The `schc` and `schc/v44` packages use only the Go standard
library; `schc/coreconf` adds github.com/fxamacker/cbor/v2. Written for
SigmaM2M, a oneM2M platform, where it carries DLMS/COSEM meter traffic over
LoRaWAN.

## Features

| Feature | Status |
|---|---|
| Compression: matching operators equal, ignore, MSB(x), match-mapping; actions not-sent, value-sent, mapping-sent, LSB, compute, DevIID, AppIID; variable-length residues | Implemented |
| Fields: IPv6 (Traffic Class whole or as DSCP and ECN), IPv4 (RFC 791: ToS whole or as DSCP and ECN, options as one field, addresses by role), UDP over either, SCTP common header (RFC 9260; chunks are payload), ICMPv6 Echo (type, code, checksum, identifier, sequence, as openschc labels them), IEC 62056-4-7 wrapper header; compute for IHL, the lengths and every checksum (IPv4, UDP, ICMPv6, SCTP CRC32c) | Implemented |
| Fields: CoAP (RFC 8824): version, type, TKL (4 bits, or 12 or 20 with the extended length of RFC 8974, as draft-ietf-schc-8824-update 4.3 takes it), code (whole or as class and detail), MID, token with the `tkl` length function, every option by number (named for the options of RFC 7252, 7641, 7959, 7967, 8613, 8768, 9175, 9177 and 9668, `coap.option.N` for any other), payload marker; several Uri-Path or Uri-Query elements in one entry (5.3) | Implemented |
| CoAP layouts: one rule from IPv6 to CoAP, CoAP alone (end-to-end, then IPv6/UDP in a second stage), OSCORE (RFC 8613 option as flags, piv, kidctx and kid; inner rules on the plaintext, outer rules on the protected message) | Implemented |
| Fragmentation: No-ACK, ACK-Always, ACK-on-Error (fixed tiles, or tiles that fill each fragment as an RFC 9363 rule without tile-size means), bitmap compression, a penultimate tile one L2 Word short (`penultimateShort`, how openschc sends a short last tile), implicit rules (RuleID length 0) | Implemented, as clock-driven sender and receiver state machines without I/O |
| SCHC Compound ACK (RFC 9441) | Implemented (`compoundAck` in a rule) |
| RCS algorithms: CRC32 (RFC 8724), CRC-32C, CRC-16 of HDLC, CRC-8, the fragment count of RFC 9442 (`fragment-count`), and any a profile registers with `RegisterRCS` | Implemented |
| LoRaWAN profile (RFC 9011): uplink ACK-on-Error, downlink ACK-Always, multicast No-ACK, class timers, FPort mapping, AES-CMAC interface identifier | Implemented |
| Sigfox profile (RFC 9442): uplink No-ACK (FCN counting down), uplink ACK-on-Error in the single-byte and both two-byte header layouts with the Compound ACK in 8-byte downlinks, downlink ACK-Always without W; the profile options (padded headers, fragment-count RCS, full fragments, the All-1 as ACK request, whole bitmaps, ACK size bound) open to any rule | Implemented (`SigfoxUplinkRule`, `SigfoxUplinkNoAckRule`, `SigfoxDownlinkRule`, `SigfoxDownlinkPayload`); RFC 9442 does not define how the RCS count is formed, see PROVENANCE.md |
| Rules in the RFC 9363 data model: RFC 7951 JSON read and written (`ParseYANG`, `MarshalYANG`), with the RFC 9441 augment; CORECONF form, CBOR with SIDs (RFC 9254), in `schc/coreconf` | Implemented. RFC 9363 assigned no SIDs: the defaults are openschc's assignment for ietf-schc, others load from SID files |
| Rules in this module's own JSON | Implemented (the form all features have; RFC 9363 cannot express every-option FIDs or grouped entries) |
| V.44 packet method (annex B.1) | Implemented |
| V.44 multi-packet (annex B.2) and stream methods, with transparent mode, ESCAPE, compressibility monitoring and parameter mode | Implemented; V.44 gives no vectors for them, so they are tested by round trip and the appendix II.1 sequence continued across a FLUSH |
| V.44 negotiation: Table 10 parameters in an XID user data subfield (annex A) or in parameter mode, and the agreement rules of 7.4 and annex B | Implemented; the V.42 LAPM procedures that carry the XID frame are not |

Not yet (planned for v0.4.0): the NB-IoT profile (RFC 9391); the V.42
LAPM procedures that carry the V.44 XID frame; a link simulator module
(schc-sim, loss and duty cycle); a round trip through a LoRaWAN network
server (ChirpStack); ACK-Always against another implementation (openschc
has no ACK-Always; libschc, through its Python binding pylibschc, is the
candidate). Standards and clause references are listed in
[PROVENANCE.md](PROVENANCE.md).

## Choosing a SCHC implementation

No other Go implementation of SCHC was found (GitHub and the Go module
proxy, October 2026). The other open implementations are in Python and
C; compared from their repositories at the versions named. Check the
projects themselves before relying on a row.

| | this module | openschc (Python) | microSCHC 0.22.0 (Python) | libschc (C) |
|---|---|---|---|---|
| Version looked at | v0.3.0 | master, commit 58293f71 of 2025-12-16, still the latest on 2026-10-12 (PyPI 0.0.3 is from 2022) | PyPI, 2026-03-02 | imec-idlab/libschc master, last push 2023-07-17 |
| Licence | Apache-2.0 | MIT | MIT | GPL-3.0, or a commercial licence |
| Compression of IPv6 and UDP | yes, and IPv4, SCTP, ICMPv6 Echo | yes, and ICMPv6 Echo | yes, and IPv4, SCTP | yes |
| CoAP fields (RFC 8824) | yes, with OSCORE inner and outer rules | yes | yes | yes |
| CoAP extended token lengths (RFC 8974) | yes | no: its parser reads the TKL nibble as the length | not checked | not checked |
| IEC 62056-4-7 wrapper (DLMS/COSEM) fields | yes | no | no | no |
| Fragmentation: No-ACK, ACK-Always, ACK-on-Error | yes | No-ACK and ACK-on-Error; ACK-Always raises NotImplementedError (protocol.py) | no | yes |
| Compound ACK (RFC 9441) | yes | not found in its source (its YANG files mention it) | no | not found in its source |
| LoRaWAN | the RFC 9011 profile: FPort mapping, timers, AES-CMAC interface identifier | examples carry the rule ID in FPort; no AES-CMAC identifier found | no | a LoRaWAN profile in its rule headers; no AES-CMAC identifier found |
| Rules as YANG / CORECONF | yes: RFC 9363 JSON and CORECONF CBOR, reads openschc's example rule file | yes | no (own data model) | no (C headers) |
| Sigfox profile (RFC 9442) | yes, all three uplink layouts and the downlink rule | no | no | not checked |
| V.44 compression | yes | no | no | no |
| Runs in a Go program without cgo | yes | no | no | no |

Pick this module for a Go program: a server or gateway that compresses
CoAP, UDP/IPv6 or DLMS/COSEM traffic for LoRaWAN or another LPWAN, or
that manages rules in the RFC 9363 model. Pick openschc when you want its
network simulator or work in Python; microSCHC for compression alone on
MicroPython; libschc on a microcontroller, if GPL-3.0 or its commercial
licence suits you. For Sigfox in Python there is schc-over-sigfox
(MIT, commit 1ec0b723 of 2023-02-18), the RFC 9442 authors' code: uplink
ACK-on-Error only, with Flask and HTTP callbacks.

## Install

```
go get github.com/cB-Sigma/schc@latest
```

Requires Go 1.24 or later.

## Quick start

Compress a CoAP request and its response with one rule that describes
both directions (RFC 8824 7.3, table 6; from `ExampleRuleSet_Compress_coap`):

```go
import "github.com/cB-Sigma/schc"

rules, err := schc.ParseRuleSet([]byte(`{"rules":[{"ruleId":1,"fields":[
 {"fid":"coap.version","fl":2,"tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.type","fl":2,"di":"up","tv":0,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.type","fl":2,"di":"dw","tv":2,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.tkl","fl":4,"tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.code","fl":8,"di":"up","tv":1,"mo":"equal","cda":"not-sent"},
 {"fid":"coap.code","fl":8,"di":"dw","tv":[69,132],"mo":"match-mapping","cda":"mapping-sent"},
 {"fid":"coap.mid","fl":16,"tv":0,"mo":"msb(12)","cda":"lsb"},
 {"fid":"coap.token","var":"tkl","tv":"80","mo":"msb(5)","cda":"lsb"},
 {"fid":"coap.uriPath","var":"bytes","di":"up","tv":"temperature","mo":"equal","cda":"not-sent"}]}]}`))
stack, _ := schc.ParseStack("coap") // "ipv6/udp/coap" for one rule over the whole packet
get, _ := hex.DecodeString("4101000182bb74656d7065726174757265")
msg, rule, err := rules.Compress(stack, get, schc.Up, schc.Context{})
msg.Pad(8) // GET /temperature, 17 bytes, becomes 01 14
back, _, err := rules.Decompress(stack, msg, schc.Up, schc.Context{})
```

The same rules as RFC 9363 instance data, and in CBOR:

```go
y, err := rules.MarshalYANG()          // RFC 7951 JSON of ietf-schc
again, err := schc.ParseYANG(y)
c, err := coreconf.Marshal(rules, nil) // import "github.com/cB-Sigma/schc/coreconf"
```

Fragmentation: `NewSender` and `NewReceiver` take a fragmentation rule.
The caller carries the sender's fragments to the receiver (`Start`,
`Receive`) and the receiver's acknowledgements back, and calls `Tick` at
each `Deadline`. `ExampleNewSender` fragments a 300-byte packet with the
RFC 9011 uplink rule and reassembles it; `ExampleRuleSet_Compress`
compresses an IEC 62056-4-7 wrapper header; `v44.ExampleCompress` and
`v44.ExampleNewEncoder` compress with the packet and multi-packet methods.

## Documentation

Reference: [pkg.go.dev/github.com/cB-Sigma/schc](https://pkg.go.dev/github.com/cB-Sigma/schc).

| Package | Contents |
|---|---|
| `schc` (module root) | Rules as our JSON or RFC 9363 JSON; compression and decompression of IPv6, IPv4, UDP, SCTP, ICMPv6, CoAP (with OSCORE and extended tokens) and IEC 62056-4-7 wrapper headers; fragmentation sender and receiver with Compound ACK, pluggable RCS and the profile options; the RFC 9011 LoRaWAN rules, FPort mapping and interface identifier; the RFC 9442 Sigfox rules |
| `schc/coreconf` | RFC 9363 rule sets in CBOR with SIDs (RFC 9254); SID files in the RFC 9595 format or openschc's |
| `schc/v44` | ITU-T V.44: packet method (dictionary reset per packet, FLUSH at the end, annex B indicator for packets sent uncompressed); multi-packet and stream methods (`Encoder`, `Decoder`); negotiation parameters, XID subfield and agreement |

The YANG module `yang/cb-sigma-schc@2026-10-12.yang` defines the
identities this module writes where ietf-schc has none (the wrapper
fields, IPv4 and SCTP fields, CoAP options registered after RFC 9363, variable lengths in bits,
the extra RCS algorithms).

## Testing

```
go test -race ./...
```

The tests re-enact the RFC 8724 appendix B and RFC 9011 appendix A
example exchanges message by message, the RFC 8824 examples of tables 1
to 6 (the GET and Content exchange with and without OSCORE, the inner
and outer rules, the CORECONF path) as our own hex, the RFC 9441 Compound
ACK sequence and message layout, and the V.44 appendix II examples;
sources are listed in [PROVENANCE.md](PROVENANCE.md), with the defects
found in those examples. There are fuzz tests for SCHC message decoding,
decompression, CoAP parsing, RFC 9363 JSON, CORECONF CBOR and the V.44
decoders. `// Covers: SIG-...` comments in tests are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.

### Interop tested against

- openschc's example rule set in RFC 9363 JSON (`examples/datamodel/schc.json`
  at commit 58293f71, MIT licence, in `testdata/openschc`): every rule
  loads (its two ACK-on-Error rules have no tile-size, so their tiles fill
  each fragment), its CoAP and ICMPv6 rules compress packets to the
  residues the rules describe, and it converts to CORECONF CBOR and back.

- openschc itself (commit 58293f71, its SCHCProtocol driven in Docker
  with a lower layer that hands every SCHC message to the test): IPv6/UDP/
  CoAP compression gives the same bits both ways and each end rebuilds the
  other's packets; No-ACK, uplink and downlink, both directions; ACK-on-
  Error, uplink and downlink, both directions, with fragments lost and
  resent. Its defects that stop some cases are kept as tests that fail
  once openschc changes: it resends a lone missing tile as an All-1, its
  receiver takes up to 8 bits left in a fragment for padding (so it fails
  some packets from its own sender as from ours), and it has no
  ACK-Always. Using it showed this module lacked the short penultimate
  tile openschc always sends; that is now implemented.
- schc-over-sigfox (commit 1ec0b723), the RFC 9442 authors' code, in
  Docker: its fragments of all three uplink layouts reassemble here, with
  its parser reading our Compound ACKs to choose what to resend; our
  single-byte fragments reassemble in its receiver, its Compound ACKs read
  by our sender, across loss. Its parser misreads 6- and 8-bit RuleIDs, so
  the two-byte layouts are checked one way only (a test records it).
- scapy 2.5.0: IPv4/UDP and IPv4/SCTP packets it builds compress with
  every length and checksum elided and come back byte for byte.

The interop tests are a separate module in `interop/` (Docker, opt-in):

```
cd interop && SIGMA_SCHC_INTEROP=1 go test ./...
```

Not yet tested: a LoRaWAN network server, a meter that uses V.44, another
V.44 implementation for the multi-packet and stream methods, ACK-Always
against another implementation, and the Sigfox downlink and No-ACK rules
against another implementation (schc-over-sigfox has neither).

## Related repositories

This module has no simulator. Its LoRaWAN fragmentation is exercised by
SigmaM2M's DLMS/COSEM tests.

## Status

v0.x. The API may change before v1; v0.3.0 and v0.2.0 only add to v0.1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
