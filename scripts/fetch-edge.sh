#!/usr/bin/env bash
set -euo pipefail

fetch() {
  local url="$1" path="$2" tmp="${2}.tmp"
  mkdir -p "$(dirname "$path")"
  curl --fail --location --silent --show-error --retry 3 --dump-header "${path}.headers" --output "$tmp" "$url"
  mv "$tmp" "$path"
}

fetch https://feodotracker.abuse.ch/downloads/ipblocklist.json reference-data/threat/abusech/feodo-ipblocklist.json
fetch https://check.torproject.org/torbulkexitlist reference-data/anonymity/tor/tor-bulk-exit-list.txt
