#!/usr/bin/env bash
set -euo pipefail

fetch() {
  local url="$1" path="$2" tmp="${2}.tmp"
  mkdir -p "$(dirname "$path")"
  curl --fail --location --silent --show-error --retry 3 --dump-header "${path}.headers" --output "$tmp" "$url"
  mv "$tmp" "$path"
}

fetch https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv reference-data/iana/ipv4-special-registry.csv
fetch https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv reference-data/iana/ipv6-special-registry.csv
fetch https://www.iana.org/assignments/iana-as-numbers-special-registry/special-purpose-as-numbers.csv reference-data/iana/asn-special-registry.csv
fetch https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv reference-data/iana/ipv4-address-space.csv
fetch https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space-1.csv reference-data/iana/ipv6-address-space.csv
fetch https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest reference-data/rir/delegated-afrinic-extended-latest
fetch https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest reference-data/rir/delegated-apnic-extended-latest
fetch https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest reference-data/rir/delegated-arin-extended-latest
fetch https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest reference-data/rir/delegated-lacnic-extended-latest
fetch https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest reference-data/rir/delegated-ripencc-extended-latest
fetch https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz reference-data/routing/riswhois-ipv4.gz
fetch https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz reference-data/routing/riswhois-ipv6.gz
fetch https://www.spamhaus.org/drop/drop_v4.json reference-data/threat/spamhaus/drop-v4.json
fetch https://www.spamhaus.org/drop/drop_v6.json reference-data/threat/spamhaus/drop-v6.json
fetch https://www.spamhaus.org/drop/asndrop.json reference-data/threat/spamhaus/asn-drop.json
fetch https://feodotracker.abuse.ch/downloads/ipblocklist.json reference-data/threat/abusech/feodo-ipblocklist.json
fetch https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt reference-data/threat/abusech/feodo-recommended.txt
fetch https://check.torproject.org/torbulkexitlist reference-data/anonymity/tor/tor-bulk-exit-list.txt
fetch https://ip-ranges.amazonaws.com/ip-ranges.json reference-data/infrastructure/aws/ip-ranges.json
fetch https://ip-ranges.amazonaws.com/geo-ip-feed.csv reference-data/infrastructure/aws/geo-ip-feed.csv
fetch https://www.gstatic.com/ipranges/goog.json reference-data/infrastructure/gcp/goog.json
fetch https://www.gstatic.com/ipranges/cloud.json reference-data/infrastructure/gcp/cloud.json
fetch https://www.cloudflare.com/ips-v4 reference-data/infrastructure/cloudflare/ips-v4.txt
fetch https://www.cloudflare.com/ips-v6 reference-data/infrastructure/cloudflare/ips-v6.txt
fetch https://developers.google.com/static/crawling/ipranges/common-crawlers.json reference-data/infrastructure/google-crawlers/common-crawlers.json
fetch https://developers.google.com/static/crawling/ipranges/special-crawlers.json reference-data/infrastructure/google-crawlers/special-crawlers.json
fetch https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json reference-data/infrastructure/google-crawlers/user-triggered-fetchers.json
fetch https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json reference-data/infrastructure/google-crawlers/user-triggered-fetchers-google.json
fetch https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json reference-data/infrastructure/google-crawlers/user-triggered-agents.json
