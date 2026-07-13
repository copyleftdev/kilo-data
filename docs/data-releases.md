# Dataset cadence and release policy

KiloCheck publishes two dataset channels because the upstream sources do not
share one meaningful refresh interval.

## Source cadence

| Tier | Sources | Upstream behavior | KiloCheck schedule |
| --- | --- | --- | --- |
| Fast | Feodo Tracker, Tor exits | Feodo is generated every 5 minutes and recommends retrieval every 5–15 minutes; Tor is a changing network view | Every 15 minutes at minutes 07, 22, 37, and 52 |
| Daily | Spamhaus DROP | Changes daily | Daily base build |
| Daily | AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC delegation statistics | Daily registry reports | Daily base build |
| Daily | RIPE RISwhois IPv4/IPv6 dumps | Published daily | Daily base build |
| Change-driven | IANA registries | Updated when registry assignments change | Checked during daily base build |
| Change-driven | AWS, GCP, Cloudflare, Google crawler ranges | Provider-published snapshots with irregular changes | Checked during daily base build |
| Deferred | DShield | Block feed no more than hourly; daily sources around 04:00 UTC | Not publicly released pending license review |
| Deferred | MISP warning lists | Repository changes irregularly and contains derived upstream data | Not independently released pending lineage review |

The base workflow runs at 05:37 UTC. This is intentionally away from the start
of the hour, after the usual publication window for the daily routing and
registry sources. The edge schedule is also offset from common high-load cron
boundaries.

## Release channels

### Stable base

The daily workflow builds the complete canonical tables and creates an immutable
release named `data-YYYYMMDD` only when the semantic table hashes changed. It is
marked as the repository's latest stable release.

Assets:

```text
kilocheck-data-base.tar.gz
kilocheck-data-base.tar.gz.sha256
base-manifest.json
```

### Rolling edge

The fast workflow builds only Feodo and Tor indicators and claims. It updates a
single prerelease tag, `data-edge`, only when the source hashes changed.

Assets:

```text
kilocheck-data-edge.tar.gz
kilocheck-data-edge.tar.gz.sha256
edge-manifest.json
```

The release tag is mutable, but `snapshot_id` is a deterministic immutable
content identity. A client must verify the archive checksum and manifest
snapshot before activation.

## Client merge contract

The base remains a complete standalone snapshot. When an edge overlay is
installed, its `feodo-c2` and `tor-exits` claims replace those source groups from
the base; all other base claims and context remain unchanged. Replacement by
source group prevents duplicate votes and stale fast-source claims.

The future CLI should:

1. Resolve the latest stable GitHub release.
2. Download and verify the base archive and manifest.
3. Resolve the fixed `data-edge` release.
4. Download the edge overlay only when its snapshot ID differs locally.
5. Reject future-dated, malformed, or over-age manifests.
6. Install base and edge atomically.

## Failure and freshness rules

- A failed update never replaces the last verified local snapshot.
- Publication timestamps are checked for Spamhaus, RIPE RIS, AWS, and GCP.
- Feodo and Tor downloads must be non-empty and accompanied by retrieval headers.
- A scheduled run that sees no semantic change does not publish a release.
- Source age is recorded independently from release creation time.
- Edge unavailability degrades freshness but does not invalidate the base.

GitHub scheduled workflows may be delayed or dropped during high load, and
public-repository schedules are automatically disabled after 60 days without
repository activity. Production monitoring must therefore alert on manifest
age from outside the workflow itself. A successful workflow cannot monitor its
own absence.

GitHub permits release assets under 2 GiB, so the current approximately 177 MiB
base dataset fits comfortably. The release artifact—not the Git repository—is
the distribution boundary.

## Primary references

- [GitHub scheduled workflow behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub release asset limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
- [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- [RIPE RISwhois dumps](https://ris.ripe.net/docs/ris-whois/)
- [ARIN extended delegation statistics](https://www.arin.net/reference/research/statistics/nro_stats/)
- [DShield feed guidance](https://isc.sans.edu/feeds_doc.html)
- [Feodo Tracker blocklists](https://feodotracker.abuse.ch/blocklist/)
