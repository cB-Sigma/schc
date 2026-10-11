# Changelog

## v0.2.0 (2026-10-11)

Every "no" in the v0.1 feature table and every row where openschc or
libschc did more is now implemented. The API only grows; code written for
v0.1 builds unchanged.

### Added

- SCHC for CoAP (RFC 8824): the stacks `coap`, `ipv6/udp/coap` and
  `coap-inner` (the OSCORE plaintext); field IDs for the CoAP header, the
  token (`"var":"tkl"`, the length function of 4.5), every option by
  number (named ones such as `coap.uriPath`, `coap.option.N` for the
  rest) and the OSCORE option as `coap.oscore.flags`, `.piv`, `.kidctx`
  and `.kid`; entries that group several Uri-Path or Uri-Query elements
  (`"tv":[["a","b"],["c","d"]]`); `CoAPOptionFID`, `CoAPOptionNumber`.
- Subfields: `ipv6.ds` and `ipv6.ecn`, `coap.codeClass` and
  `coap.codeDetail`, in place of the whole field.
- ICMPv6 Echo fields (`ipv6/icmpv6`, `icmpv6.*`) with the checksum
  computed, as openschc compresses ping.
- Target values `{"text": …}` and `{"hex": …}`; for the CoAP options that
  hold text a plain string is the text.
- `Stack.BuildFields`, the inverse of `Parse` for repeated fields.
- Rules in the RFC 9363 data model: `ParseYANG`, `ParseYANGWith`
  (`YANGOptions`: skip rules that cannot be read, a fixed tile size for
  ACK-on-Error rules without one), `FromYANG`, `RuleSet.MarshalYANG`,
  `RuleSet.YANG`, the `YANG*` types; the RFC 9441 augment; our extension
  module `yang/cb-sigma-schc@2026-10-11.yang`.
- Package `schc/coreconf`: the same rules in CBOR with SIDs (RFC 9254),
  `Marshal`, `Unmarshal`, `FromJSON`, `ToJSON`, SID tables (`Default`,
  `LoadSIDFile`).
- ACK-on-Error with tiles that fill each fragment (`FragParams.TileSize`
  0, what an RFC 9363 rule without tile-size means): tiles cut at the MTU
  the sender starts with, one per fragment.
- SCHC Compound ACK (RFC 9441): `FragParams.CompoundAck` and
  `LastBitmapUncompressed`, `FragMsg.More`, `WindowBitmap`.
- RCS algorithms: `FragParams.RCS` (`"rcs"` in JSON), `RegisterRCS`,
  `LookupRCS`, `RCSAlgorithms`; CRC-32C, CRC-16 (HDLC) and CRC-8 beside
  CRC32.
- V.44 multi-packet (annex B.2) and stream methods: `v44.Encoder`
  (`Packet`, `PacketOrRaw`, `Write`, `Flush`, `SetTransparent`,
  `SendParameters`, `Auto`) and `v44.Decoder` (`Packet`, `Write`,
  `OnParameters`), with transparent mode, ESCAPE and parameter mode.
- V.44 negotiation: `v44.Proposal`, `Parameter`, `MarshalXID`,
  `ParseXID`, `ProposalOf`, `Agree`.

### Fixed

- ACK-on-Error: a last tile shorter than an L2 Word, which the sender puts
  in the All-1, was taken for padding by the receiver, whose check then
  failed with every tile in hand (a 289-bit packet in 3-byte tiles, for
  example). The receiver now tells tile from padding by the RCS.
- V.44 decoder: after any control code the code prefixes are those of
  Table 5's second column (it mattered only after FLUSH, which ended the
  packet method).

### Changed

- The module requires github.com/fxamacker/cbor/v2, used only by
  `schc/coreconf`.
- An ACK-on-Error rule without a tile size, refused before, now means
  tiles that fill their fragment.

## v0.1.1 and v0.1.0

First published releases; see the repository history.
