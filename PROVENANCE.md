# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, from the specifications below,
not ported from another implementation (no SCHC or V.44 code was
consulted). No specification text is reproduced; comments cite clause,
figure and table numbers in our own words.

For v0.2.0, openschc (commit 58293f71, MIT) was looked at only for its
data: its example rule file and SID files, and which identities and
target-value encodings it writes, so that our RFC 9363 JSON reads and
writes the same. None of its code was used.

For v0.3.0, two implementations were run as test peers in Docker and
read where their behaviour needed explaining, none of their code used:
openschc (same commit) and schc-over-sigfox
(https://github.com/schc-over-sigfox/schc-over-sigfox, commit 1ec0b723,
MIT), the RFC 9442 authors' code. RFC 9442 does not say how the RCS
count of 3.5.1.5 is formed; `RCSFragmentCount` follows what
schc-over-sigfox sends (the number of fragments of the All-1's window,
the All-1 included, the All-1 opening a new window when the last tile
filled one), and the Compound ACK of its receiver was taken as the
reference for the closing zero bits. The drivers in `interop/peer` and
`interop/sigfoxpeer` are ours.

## Specifications followed

| Package | Specifications |
|---|---|
| `schc` | RFC 8724 (SCHC: compression and fragmentation); RFC 8824 (SCHC for CoAP); RFC 7252, 7641, 7959, 7967, 8613 (6.1, the OSCORE option), 8768, 9175, 9177 and 9668 for the CoAP header and option numbers and formats; RFC 9011 (SCHC over LoRaWAN); RFC 9442 (SCHC over Sigfox); RFC 9441 (Compound ACK); RFC 8974 (extended token lengths) with draft-ietf-schc-8824-update-10 4.3 (TKL as one field); RFC 791 (IPv4), RFC 768 (UDP over IPv4), RFC 1071 (the Internet checksum), RFC 9260 3.1 and 6.8 (SCTP common header and CRC32c); RFC 9363 (the YANG data model) with RFC 7951 (its JSON encoding); RFC 8200 (IPv6 header fields), RFC 4443 (ICMPv6 Echo and checksum), RFC 2474 and 3168 (DSCP and ECN); RFC 4493 (AES-CMAC, for the RFC 9011 interface identifier). The IEC 62056-4-7 wrapper header is parsed as a field stack. RCS check values: CRC-32/ISO-HDLC, CRC-32/ISCSI (RFC 3720 B.4), CRC-16/IBM-SDLC (RFC 1662 C.2), CRC-8/SMBUS |
| `schc/coreconf` | RFC 9254 (YANG data in CBOR: SID deltas, identityref as SID, tag 45 in unions), RFC 9595 (SID files, the experimental SID range), RFC 9363 and RFC 9441 for the data |
| `v44` | ITU-T V.44 (11/2000) with Corrigendum 1 (03/2002): the packet method of annex B.1, the multi-packet method of annex B.2, the stream method of clauses 6 and 7 with transparent mode (6.5), FLUSH (7.13), ESCAPE (7.14), REINIT (7.11.3, 7.11.4, 7.12), parameter mode (7.4.2), Table 10 and the XID user data subfield of annex A; RFC 3051 2.1, 2.3 and 3.1 for how the packet method is used per datagram |

## Third-party data in this repository

| File | Source | Licence |
|---|---|---|
| `testdata/openschc/schc.json` | openschc, `examples/datamodel/schc.json`, commit 58293f71daac24036dd28aa7b1a2a241536c6aea (2025-12-16) | MIT, `testdata/openschc/LICENSE` |
| `coreconf/sid/ietf-schc@2023-01-28.sid`, `coreconf/sid/ietf-schc-oam@2021-11-10.sid` | openschc, `examples/datamodel/`, same commit: SID assignments for the RFC 9363 module and the ietf-schc-oam draft module (not IANA-registered) | MIT, `coreconf/sid/LICENSE-openschc` |

`coreconf/sid/cb-sigma-schc@2026-10-12.sid` and
`coreconf/sid/ietf-schc-compound-ack@2023-07-26.sid` are ours: SIDs from
the experimental range of RFC 9595 for our extension module and for the
RFC 9441 module, which has none registered. `yang/cb-sigma-schc@2026-10-12.yang`
is ours.

## Test vectors and where they come from

| Test | Source |
|---|---|
| schc fragmentation traces | RFC 8724 figures 29 to 31, 33, 34, 36 and 37 (appendix B), re-enacted message by message |
| schc compression of the appendix A flows | RFC 8724 figures 26 to 28, written as our JSON rules, with the residues of the figures |
| schc bitmap compression, residue sizes, message formats | RFC 8724 8.3.2.1 (figures 16 to 19), 7.4.2; RFC 9011 figures 10, 12 and 13 |
| schc LoRaWAN | RFC 9011 appendix A.2 and A.3 (fragment sizes and ACKs), figure 6 (interface identifier) |
| schc CoAP | RFC 8824 7.3: the messages of figures 8, 9, 12 and 13 and the plaintexts of figures 10 and 11, compressed by the rules of tables 4, 5 and 6 to the octets of figures 10, 11, 15, 16 and 17 (and figure 14 with the corrections below); the exchanges of 7.1 (table 3), 5.3 (tables 1 and 2) written as our own hex |
| schc Compound ACK | RFC 9441 section 4, figures 7 and 8 |
| schc RFC 9363 | openschc's example rule file (above): its rules load, and its CoAP and ICMPv6 rules compress packets we built to the residues the rules describe |
| coreconf | RFC 9254 encodings worked by hand for the smallest rule set and a field-length union |
| v44 | V.44 appendix II.1 and II.2 examples; Table 3, Table 5 and Table 6 bit layouts; appendix II.1 continued across its FLUSH for the stream method (codeword 15 on root C) |
| v44 TestTableF16Sizes | an informative size check only: a 167-octet DLMS/COSEM get-response APDU of 24 load-profile records, rebuilt from the description of IEC 62056-5-3:2023 Table F.14, and the compressed sizes of its Table F.16 |
| schc Sigfox | RFC 9442 figures 3 to 30 for the message layouts (our own bits); a Compound ACK captured from schc-over-sigfox at commit 1ec0b723 (`TestSigfoxCompoundAckFromReference`) |
| schc CoAP extended tokens | RFC 8974 2.1 length coding, worked by hand for tokens of 1 to 1000 bytes |
| schc IPv4 and SCTP | packets built by scapy 2.5.0 (interop tests); an IPv4 header with a Router Alert option worked by hand |

## Specification defects (F-numbers)

F-n in a comment refers to an entry in SigmaM2M's register of
specification defects; the substance is described here, in our own words.

- F-2101: RFC 9011 appendix A.3 draws the device's ACK after a downlink
  All-0 with C=1, while 5.6.3.5.1 implies C=0 with a bitmap of 1. Our
  receiver sends C=0; our sender accepts either.
- F-2102: RFC 9011 figure 34 labels the last downlink payload 37 bytes;
  its parts add up to 36 bytes of FRMPayload. Tested as 36.
- F-2103: RFC 8724 appendix B figures 34 and 37 show bitmaps that do not
  fit WINDOW_SIZE 7 or mark a tile that was never sent. Our receiver sends
  7-bit bitmaps with unsent positions 0.

Noted without a number (found for v0.2.0, not yet in SigmaM2M's
register):

- RFC 8824 table 6 gives the uplink CoAP code as 2 (POST), but figure 8's
  request is a GET (code 1) and figure 16 elides it. Our rule says 1.
- RFC 8824 figures 12 and 13 carry OSCORE as option 21, a number from a
  draft; RFC 8613 assigned 9. Our vectors use 9.
- RFC 8824 table 5 gives the kid MSB(52) for a 48-bit kid with a 4-bit
  residue (MSB(44) fits), and figure 14 draws the variable-length piv and
  kid residues without the size RFC 8724 7.4.2 puts before them. Our
  vector has MSB(44) and the two 4-bit sizes; the response (figure 15)
  matches the RFC exactly.
- RFC 8824 table 5's downlink OSCORE flags entry has a field length of 8
  bits and an empty target value; the response's OSCORE option is empty,
  so the entry is variable-length in our rule.
- RFC 9363 4.7 says target values are aligned to the left, while openschc
  writes numbers right-aligned in whole bytes; we follow openschc.
- RFC 9363 assigns no SIDs for ietf-schc, and RFC 9441 none for its
  module.
- V.44 7.11.3 reinitializes when a codeword cannot be created, B.2.1 when
  the last one has been created; we reinitialize at the first codeword
  that cannot be created (both decode the same, as REINIT is explicit).

Found for v0.3.0 (not yet in SigmaM2M's register):

- RFC 9442 3.5.1.5 names the RCS as a count of the last window's
  fragments, the All-1 included, without saying how it is formed or what
  happens past its 3 to 5 bits; we follow the authors' code (above).
- RFC 9442 3.7: a downlink frame is always 8 bytes, so the zero padding
  after a downlink All-1's last tile cannot be told from tile bytes; our
  receiver keeps it on the packet, which a decompressor then reads as
  payload. The RFC leaves the length to the receiver.
- RFC 9442 4.1 gives the two-byte option 2 RuleIDs as 11111100 to
  11111111 but shows 00111111 as an example; we accept the range.
- RFC 9442 3.6.3.4 gives the option 1 Sender-Abort as 2 bytes, its figure
  12 bits; ours is 12 bits padded to 2 bytes.
- RFC 9442 3.6.4.3 allows a Compound ACK of up to 3 windows for option 2,
  but with 31-bit bitmaps only one fits the 64-bit downlink; our receiver
  sends the windows that fit, lowest first (`AckMaxBits`).
- RFC 8974 makes TKL 9 to 12 token lengths (RFC 7252 reserved them); our
  parser now takes them.

One more defect is noted without a number: the V.44 sizes of IEC
62056-5-3 Table F.16 for 48 to 168 records cannot be reached with V.44's
maximum string length of 255 octets per codeword or extension (see the
comment on `TestTableF16Sizes`).
