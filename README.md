# schc

Static Context Header Compression and fragmentation (SCHC, RFC 8724) with the LoRaWAN profile (RFC 9011), and V.44 data compression (packet method), in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/schc.svg)](https://pkg.go.dev/github.com/cB-Sigma/schc) [![test](https://github.com/cB-Sigma/schc/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/schc/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

No cgo and no dependencies outside the Go standard library. Written for
SigmaM2M, a oneM2M platform, where it carries DLMS/COSEM meter traffic over
LoRaWAN.

## Features

| Feature | Status |
|---|---|
| Compression: matching operators equal, ignore, MSB(x), match-mapping; actions not-sent, value-sent, mapping-sent, LSB, compute, DevIID, AppIID; variable-length residues | Implemented |
| Fields: IPv6, UDP, IEC 62056-4-7 wrapper header | Implemented |
| Fields: CoAP (RFC 8824) | Not implemented |
| Fragmentation: No-ACK, ACK-Always, ACK-on-Error, bitmap compression, CRC32 RCS | Implemented, as clock-driven sender and receiver state machines without I/O |
| Other RCS algorithms | Not implemented |
| LoRaWAN profile (RFC 9011): uplink ACK-on-Error, downlink ACK-Always, multicast No-ACK, class timers, FPort mapping, AES-CMAC interface identifier | Implemented |
| Rule management (RFC 9363 YANG, RFC 9441 CORECONF) | Not implemented; rules are JSON in this module's own format |
| V.44 packet method (ITU-T V.44 annex B.1) | Implemented |
| V.44 stream and multi-packet methods, V.42 negotiation | Not implemented |

Standards and clause references are listed in [PROVENANCE.md](PROVENANCE.md).

## Choosing a SCHC implementation

No other Go implementation of SCHC was found (GitHub and the Go module
proxy, October 2026). The other open implementations are in Python and
C; compared from their repositories at the versions named. Check the
projects themselves before relying on a row.

| | this module | openschc (Python) | microSCHC 0.22.0 (Python) | libschc (C) |
|---|---|---|---|---|
| Version looked at | v0.x | master, last commit 2025-12-16 (PyPI 0.0.3 is from 2022) | PyPI, 2026-03-02 | master, last commit 2023-04-28 |
| Licence | Apache-2.0 | MIT | MIT | GPL-3.0, or a commercial licence |
| Compression of IPv6 and UDP | yes | yes | yes, and IPv4, SCTP | yes |
| CoAP fields (RFC 8824) | no | yes | yes | yes |
| IEC 62056-4-7 wrapper (DLMS/COSEM) fields | yes | no | no | no |
| Fragmentation: No-ACK, ACK-Always, ACK-on-Error | yes | yes | no | yes |
| LoRaWAN | the RFC 9011 profile: FPort mapping, timers, AES-CMAC interface identifier | examples carry the rule ID in FPort; no AES-CMAC identifier found | no | a LoRaWAN profile in its rule headers; no AES-CMAC identifier found |
| Rules as YANG / CORECONF | no (own JSON) | yes | no (own data model) | no (C headers) |
| V.44 compression | yes | no | no | no |
| Runs in a Go program without cgo | yes | no | no | no |

Pick this module for a Go server that receives DLMS/COSEM or other
UDP/IPv6 traffic over LoRaWAN. Pick openschc when you need CoAP rules,
YANG/CORECONF rule management or its network simulator, and Python is
fine; microSCHC for compression alone on MicroPython; libschc on a
microcontroller, if GPL-3.0 or its commercial licence suits you.

## Install

```
go get github.com/cB-Sigma/schc@latest
```

Requires Go 1.24 or later.

## Quick start

Compress an IEC 62056-4-7 wrapper header with a rule that elides the
constant fields and computes the length, then rebuild the frame from the
same rules (from `ExampleRuleSet_Compress`):

```go
import "github.com/cB-Sigma/schc"

rules, err := schc.ParseRuleSet([]byte(`{"rules":[
 {"ruleId":1,"fields":[
  {"fid":"wrapper.version","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
  {"fid":"wrapper.devWPort","fl":16,"tv":1,"mo":"equal","cda":"not-sent"},
  {"fid":"wrapper.appWPort","fl":16,"tv":[16,32,48,64,80,96,102,1],"mo":"match-mapping","cda":"mapping-sent"},
  {"fid":"wrapper.length","fl":16,"mo":"ignore","cda":"compute"}]},
 {"ruleId":22,"kind":"no-compression"}]}`))
if err != nil {
	return err
}
stack, _ := schc.ParseStack("wrapper")
apdu := []byte{0xC0, 0x01, 0xC1, 0x00, 0x03}
frame := append([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, byte(len(apdu))}, apdu...)

msg, rule, err := rules.Compress(stack, frame, schc.Up, schc.Context{})
// rule 1: header and payload in 51 bits instead of 104
msg.Pad(8) // whole bytes for the link
back, _, err := rules.Decompress(stack, msg, schc.Up, schc.Context{})
// bytes.Equal(back, frame) == true
```

Fragmentation: `NewSender` and `NewReceiver` take a fragmentation rule.
The caller carries the sender's fragments to the receiver (`Start`,
`Receive`) and the receiver's acknowledgements back, and calls `Tick` at
each `Deadline`. `ExampleNewSender` fragments a 300-byte packet with the
RFC 9011 uplink rule and reassembles it; `v44.ExampleCompress` compresses
and decompresses one V.44 packet.

## Documentation

Reference: [pkg.go.dev/github.com/cB-Sigma/schc](https://pkg.go.dev/github.com/cB-Sigma/schc).

| Package | Contents |
|---|---|
| `schc` (module root) | Rules as JSON; compression and decompression of IPv6, UDP and IEC 62056-4-7 wrapper headers; fragmentation sender and receiver; the RFC 9011 LoRaWAN rules, FPort mapping and interface identifier |
| `schc/v44` | ITU-T V.44 compression, packet method (dictionary reset per packet, FLUSH at the end), with the annex B indicator for packets sent uncompressed |

## Testing

```
go test -race ./...
```

The tests re-enact the RFC 8724 appendix B and RFC 9011 appendix A
example exchanges message by message, and the V.44 appendix II examples;
sources are listed in [PROVENANCE.md](PROVENANCE.md). There are fuzz
tests for SCHC message decoding, decompression and V.44. `// Covers: SIG-...` comments in tests are
requirement IDs of the SigmaM2M project's compliance report and have no
meaning outside it.

### Interop tested against

Nothing yet. No other SCHC implementation (openschc, libschc), no LoRaWAN
network server and no meter that uses V.44 has been tested against this
module.

## Related repositories

This module has no simulator. Its LoRaWAN fragmentation is exercised by
SigmaM2M's DLMS/COSEM tests.

## Status

v0.x. The API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
