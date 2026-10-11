# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, from the specifications below,
not ported from another implementation (no SCHC or V.44 code was
consulted). No specification text is reproduced; comments cite clause,
figure and table numbers in our own words.

## Specifications followed

| Package | Specifications |
|---|---|
| `schc` | RFC 8724 (SCHC: compression and fragmentation); RFC 9011 (SCHC over LoRaWAN); RFC 8200 (IPv6 header fields); RFC 4493 (AES-CMAC, for the RFC 9011 interface identifier). The IEC 62056-4-7 wrapper header is parsed as a field stack. RFC 9363 (the YANG data model) is not implemented: rules are our own JSON |
| `v44` | ITU-T V.44 (11/2000) with Corrigendum 1 (03/2002), packet method of annex B.1; RFC 3051 2.1, 2.3 and 3.1 for how the packet method is used per datagram |

## Test vectors and where they come from

| Test | Source |
|---|---|
| schc fragmentation traces | RFC 8724 figures 29 to 31, 33, 34, 36 and 37 (appendix B), re-enacted message by message |
| schc compression of the appendix A flows | RFC 8724 figures 26 to 28, written as our JSON rules, with the residues of the figures |
| schc bitmap compression, residue sizes, message formats | RFC 8724 8.3.2.1 (figures 16 to 19), 7.4.2; RFC 9011 figures 10, 12 and 13 |
| schc LoRaWAN | RFC 9011 appendix A.2 and A.3 (fragment sizes and ACKs), figure 6 (interface identifier) |
| v44 | V.44 appendix II.1 and II.2 examples; Table 3, Table 5 and Table 6 bit layouts |
| v44 TestTableF16Sizes | an informative size check only: a 167-octet DLMS/COSEM get-response APDU of 24 load-profile records, rebuilt from the description of IEC 62056-5-3:2023 Table F.14, and the compressed sizes of its Table F.16 |

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

One more defect is noted without a number: the V.44 sizes of IEC
62056-5-3 Table F.16 for 48 to 168 records cannot be reached with V.44's
maximum string length of 255 octets per codeword or extension (see the
comment on `TestTableF16Sizes`).
