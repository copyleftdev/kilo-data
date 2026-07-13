# Canonical dataset

This directory contains the first semantically normalized KiloCheck dataset.
It was compiled from the artifact set pinned in `reference-data/sources.toml`.

| Table | Rows | Purpose |
| --- | ---: | --- |
| `indicators.parquet` | 2,139,370 | Deduplicated IPv4, IPv6, prefix, ASN, and ASN-range subjects |
| `network_allocations.parquet` | 775,284 | RIR allocation and registration context |
| `route_origins.parquet` | 1,548,992 | RIPE RIS prefix-to-origin-AS observations, including MOAS |
| `provider_ranges.parquet` | 19,541 | AWS, Google/GCP, Cloudflare, and Google crawler context |
| `claims.parquet` | 3,591 | Spamhaus, Feodo, and Tor source claims |
| `special_purpose.parquet` | 60 | IANA address and ASN semantics with RFC lifecycle properties |

All subject identifiers are deterministic SHA-256 values represented as
lowercase hexadecimal UTF-8 in this review format. IP addresses and prefixes
are canonicalized before identifiers are calculated.

## Deliberate exclusions

- DShield is retained in the source-native table but excluded from canonical
  claims pending license review. Its daily feed also explicitly warns that it
  is unfiltered data rather than a blocklist.
- MISP warning lists are retained source-native and used for schema research,
  but are not emitted as independent evidence because they aggregate and derive
  from many upstream sources.
- IANA special-purpose values are preserved as strings where footnotes or `N/A`
  make a simple boolean misleading.
- Provider ranges are context only and cannot independently increase malicious
  confidence.

`kilo-data validate-canonical` verifies unique indicators and claims and checks
that every allocation, route, provider, and claim reference resolves.

Two complete builds from identical inputs were byte-identical.
