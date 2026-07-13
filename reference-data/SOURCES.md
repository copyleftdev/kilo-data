# Source catalog

Status values are preliminary: `candidate` means technically suitable for ETL
review; `license-review` means the payload is retained for shape analysis but
must not be shipped until usage terms are resolved; `context-only` means the
source must not independently increase malicious confidence.

## Internet registries and routing

| Local artifact | Canonical bulk URL | Status | Expected refresh |
| --- | --- | --- | --- |
| `iana/ipv4-special-registry.csv` | https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv | candidate | registry change |
| `iana/ipv6-special-registry.csv` | https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv | candidate | registry change |
| `iana/asn-special-registry.csv` | https://www.iana.org/assignments/iana-as-numbers-special-registry/special-purpose-as-numbers.csv | candidate | registry change |
| `iana/ipv4-address-space.csv` | https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv | candidate | registry change |
| `iana/ipv6-address-space.csv` | https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space-1.csv | candidate | registry change |
| `rir/delegated-afrinic-extended-latest` | https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest | candidate | daily |
| `rir/delegated-apnic-extended-latest` | https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest | candidate | daily |
| `rir/delegated-arin-extended-latest` | https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest | candidate | daily |
| `rir/delegated-lacnic-extended-latest` | https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest | candidate | daily |
| `rir/delegated-ripencc-extended-latest` | https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest | candidate | daily |
| `routing/riswhois-ipv4.gz` | https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz | candidate | daily |
| `routing/riswhois-ipv6.gz` | https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz | candidate | daily |

## Threat and activity observations

| Local artifact | Canonical bulk URL | Status | Expected refresh |
| --- | --- | --- | --- |
| `threat/spamhaus/drop-v4.json` | https://www.spamhaus.org/drop/drop_v4.json | candidate; attribution required | daily |
| `threat/spamhaus/drop-v6.json` | https://www.spamhaus.org/drop/drop_v6.json | candidate; attribution required | daily |
| `threat/spamhaus/asn-drop.json` | https://www.spamhaus.org/drop/asndrop.json | candidate; attribution required | daily |
| `threat/abusech/feodo-ipblocklist.json` | https://feodotracker.abuse.ch/downloads/ipblocklist.json | candidate; CC0 | about 5 minutes |
| `threat/abusech/feodo-recommended.txt` | https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt | candidate; CC0 | about 5 minutes |
| `threat/dshield/block.txt` | https://feeds.dshield.org/block.txt | license-review | hourly |
| `threat/dshield/daily-sources.txt` | https://feeds.dshield.org/daily_sources | license-review | daily |

## Anonymity and infrastructure context

| Local artifact | Canonical bulk URL | Status | Expected refresh |
| --- | --- | --- | --- |
| `anonymity/tor/tor-bulk-exit-list.txt` | https://check.torproject.org/torbulkexitlist | context-only | frequent |
| `infrastructure/aws/ip-ranges.json` | https://ip-ranges.amazonaws.com/ip-ranges.json | context-only | on provider change |
| `infrastructure/aws/geo-ip-feed.csv` | https://ip-ranges.amazonaws.com/geo-ip-feed.csv | context-only | on provider change |
| `infrastructure/gcp/goog.json` | https://www.gstatic.com/ipranges/goog.json | context-only | on provider change |
| `infrastructure/gcp/cloud.json` | https://www.gstatic.com/ipranges/cloud.json | context-only | on provider change |
| `infrastructure/cloudflare/ips-v4.txt` | https://www.cloudflare.com/ips-v4 | context-only | on provider change |
| `infrastructure/cloudflare/ips-v6.txt` | https://www.cloudflare.com/ips-v6 | context-only | on provider change |
| `infrastructure/google-crawlers/common-crawlers.json` | https://developers.google.com/static/crawling/ipranges/common-crawlers.json | context-only | on provider change |
| `infrastructure/google-crawlers/special-crawlers.json` | https://developers.google.com/static/crawling/ipranges/special-crawlers.json | context-only | on provider change |
| `infrastructure/google-crawlers/user-triggered-fetchers.json` | https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json | context-only | on provider change |
| `infrastructure/google-crawlers/user-triggered-fetchers-google.json` | https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json | context-only | on provider change |
| `infrastructure/google-crawlers/user-triggered-agents.json` | https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json | context-only | on provider change |

## Curated repository collections

| Local artifact | Canonical bulk URL | Status | Notes |
| --- | --- | --- | --- |
| `collections/misp-warninglists/main.tar.gz` | https://codeload.github.com/MISP/misp-warninglists/tar.gz/refs/heads/main | context-only; upstream license review | Complete branch archive from the CIRCL/MISP project. Pin a commit rather than `main` in a production collector. |

## Deliberately excluded

- GreyNoise, AbuseIPDB, and other per-IP enrichment APIs.
- ThreatFox's authenticated query API. A future adapter may be considered only
  for an official complete static export with stable terms and URL.
- Live DNS, RDAP, WHOIS, and BGP query services.
- Unattributed mega-blocklists and mirrors that erase original provenance.
- Azure service tags until the release-specific download discovery process is
  made deterministic without relying on a query API.
