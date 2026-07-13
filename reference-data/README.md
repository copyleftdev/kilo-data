# KiloCheck reference data

This directory is a review corpus for designing KiloCheck's bulk-source ETL.
It is not yet a production feed bundle and none of these artifacts should be
treated as approved for redistribution or automatic blocking merely because it
is present here.

Collected at: `2026-07-13T03:52:11Z`

## Collection boundary

Included sources publish a complete dataset as a static file, archive, or
source repository. Per-indicator lookups, paginated search APIs, authenticated
enrichment APIs, live DNS, RDAP, and WHOIS queries are intentionally excluded.

The artifacts are preserved byte-for-byte. `CHECKSUMS.sha256` identifies this
specific collection. A future collector should write a retrieval receipt beside
each artifact before compiling a new immutable snapshot.

## Corpus overview

| Area | Publishers | Shape observed |
| --- | --- | --- |
| Address semantics | IANA | Small CSV registries with CIDR/range semantics and RFC references |
| Allocations | AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC | Pipe-delimited NRO extended delegation records |
| Routing | RIPE RIS | Gzipped tab-delimited origin-AS, prefix, peer-count dumps |
| High-confidence threat | Spamhaus, abuse.ch | NDJSON CIDRs/ASNs and JSON exact-IP C2 records |
| Sensor activity | SANS ISC/DShield | Commented tabular feeds ranging from 20 prefixes to millions of events |
| Anonymity | Tor Project | Complete newline-delimited exit IP list |
| Provider context | AWS, Google, Cloudflare | JSON/CSV/text CIDR publications with varying metadata depth |
| Known crawlers | Google | JSON CIDR publications separated by crawler/fetcher role |
| Curated context collection | CIRCL/MISP | Repository archive containing many warning-list JSON documents |

Total at collection time: 32 payloads, approximately 214 MiB.

## Immediate shape findings

- A source is not equivalent to a classification. Feodo records include IP,
  port, online state, ASN, country, timestamps, and malware family.
- Scope varies: exact IP, CIDR, and ASN all occur in the core corpus.
- Publication timestamps are inconsistent. Some live in payload headers, some
  in JSON metadata, some in comments, and some only in HTTP metadata.
- Bulk size varies by five orders of magnitude. DShield `daily_sources` is about
  114 MiB and 2.7 million lines, while Cloudflare's IPv6 list is 104 bytes.
- Absence and lifecycle need source-specific semantics. Feodo distinguishes
  offline infrastructure; Spamhaus DROP is a current set; routing dumps express
  current visibility rather than abuse.
- MISP warning lists are valuable for discovering legitimate scanners, cloud
  providers, CDNs, sinkholes, and false-positive contexts, but many entries are
  derived from upstream sources. They must not be counted as independent
  evidence from those upstream publications.

## Important review flags

- `threat/dshield/block.txt` embeds a CC BY-NC-SA notice, while SANS's feed
  documentation describes additional commercial-use terms. This source stays
  license-review-only until the applicable terms are reconciled.
- Spamhaus requires attribution and retention of its date/copyright material.
- The MISP archive combines data with heterogeneous upstream provenance and
  licensing. Treat it as a discovery/context collection, not one evidence vote.
- RIR country codes describe registry/delegation data; they are not reliable
  physical geolocation claims.
- AWS/GCP regions and published service ranges describe provider infrastructure,
  not the identity or intent of a tenant using an address.
- Azure's official bulk file was not collected because its download URL is
  release-specific rather than a stable canonical artifact URL. It should be
  added only after defining a deterministic discovery mechanism that does not
  use a query API.

## Expected recurring collection process

1. Read a versioned source catalog.
2. Fetch each complete bulk artifact to a temporary location.
3. Record URL, retrieval time, response metadata, byte length, and digest.
4. Reject HTML/error responses and violations of source-specific size/shape
   invariants.
5. Preserve the original bytes by content hash.
6. Parse each artifact into source-native claims.
7. Normalize claims while retaining source record fields and lineage.
8. Rebuild the entire compiled snapshot from the selected artifact set.
9. Validate counts, timestamps, CIDRs, relationships, and determinism.
10. Atomically activate the snapshot only after verification succeeds.

See `SOURCES.md` for canonical locations and review status.
