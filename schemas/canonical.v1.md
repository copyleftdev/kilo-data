# KiloCheck canonical dataset v1 draft

This is the semantic target for the next compiler stage. It is intentionally a
set of related tables rather than one flattened reputation table.

## Shared conventions

- IDs are lowercase hexadecimal SHA-256 values unless explicitly documented.
- IPv4 and IPv6 values are stored in canonical text during the review phase;
  fixed-width binary representations will be selected after lookup benchmarks.
- Timestamps use Arrow `Timestamp(Microsecond, UTC)`.
- Missing, not observed, expired, and unavailable are distinct states.
- Source-native values remain available through `source_records.parquet`.

## `artifacts`

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `artifact_id` | UTF-8 | no |
| `source_id` | UTF-8 | no |
| `sha256` | FixedSizeBinary(32) | no |
| `retrieved_at` | Timestamp(µs, UTC) | no |
| `published_at` | Timestamp(µs, UTC) | yes |
| `byte_length` | UInt64 | no |
| `media_type` | UTF-8 | yes |
| `source_url` | UTF-8 | no |
| `adapter_version` | UTF-8 | no |

## `indicators`

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `indicator_id` | FixedSizeBinary(32) | no |
| `kind` | Dictionary(UInt8, UTF-8) | no |
| `canonical_value` | UTF-8 | no |
| `ip_version` | UInt8 | yes |
| `prefix_length` | UInt8 | yes |

Initial indicator kinds are `ipv4`, `ipv6`, `prefix`, and `asn`.

## `claims`

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `claim_id` | FixedSizeBinary(32) | no |
| `source_id` | UTF-8 | no |
| `artifact_id` | UTF-8 | no |
| `source_record_index` | UInt64 | no |
| `source_record_id` | UTF-8 | yes |
| `claim_type` | Dictionary(UInt16, UTF-8) | no |
| `source_classification` | UTF-8 | yes |
| `source_confidence` | Float32 | yes |
| `first_seen` | Timestamp(µs, UTC) | yes |
| `last_seen` | Timestamp(µs, UTC) | yes |
| `valid_until` | Timestamp(µs, UTC) | yes |
| `withdrawn_at` | Timestamp(µs, UTC) | yes |
| `raw_record_hash` | FixedSizeBinary(32) | no |

## `claim_indicators`

This many-to-many table preserves claims that refer to more than one subject.

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `claim_id` | FixedSizeBinary(32) | no |
| `indicator_id` | FixedSizeBinary(32) | no |
| `relationship` | Dictionary(UInt8, UTF-8) | no |

## `network_allocations`

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `indicator_id` | FixedSizeBinary(32) | no |
| `registry` | Dictionary(UInt8, UTF-8) | no |
| `status` | Dictionary(UInt8, UTF-8) | yes |
| `registered_country` | FixedSizeBinary(2) | yes |
| `allocation_date` | Date32 | yes |
| `artifact_id` | UTF-8 | no |

`registered_country` must never be presented as physical geolocation.

## `route_origins`

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `prefix_indicator_id` | FixedSizeBinary(32) | no |
| `origin_asn_indicator_id` | FixedSizeBinary(32) | no |
| `ris_peer_count` | UInt32 | yes |
| `observed_at` | Timestamp(µs, UTC) | no |
| `artifact_id` | UTF-8 | no |

Multiple rows for one prefix are valid and represent multi-origin routing.

## `provider_ranges`

| Field | Arrow type | Nullable |
| --- | --- | --- |
| `indicator_id` | FixedSizeBinary(32) | no |
| `provider` | Dictionary(UInt16, UTF-8) | no |
| `service` | Dictionary(UInt16, UTF-8) | yes |
| `provider_region` | Dictionary(UInt16, UTF-8) | yes |
| `network_border_group` | UTF-8 | yes |
| `role` | Dictionary(UInt16, UTF-8) | no |
| `artifact_id` | UTF-8 | no |

Provider presence is context and cannot independently increase malicious
confidence.

## Required invariants

1. Every canonical row traces to an artifact and source record.
2. A malformed subject never becomes an indicator.
3. Duplicate or derived sources never increase independence.
4. Exact-IP and containing-prefix claims remain distinguishable.
5. No normalizer silently replaces a source-native value.
6. Recompiling identical inputs with identical versions is byte-identical.
