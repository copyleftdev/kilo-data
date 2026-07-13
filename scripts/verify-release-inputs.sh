#!/usr/bin/env bash
set -euo pipefail

now=$(date -u +%s)

gate_epoch() {
  local source="$1" epoch="$2" maximum="$3"
  if [ -z "$epoch" ] || [ "$epoch" = "null" ]; then
    echo "missing publication time: $source" >&2
    exit 1
  fi
  local age=$((now - epoch))
  if [ "$age" -lt 0 ] || [ "$age" -gt "$maximum" ]; then
    echo "stale publication: $source age=${age}s maximum=${maximum}s" >&2
    exit 1
  fi
  echo "fresh $source age=${age}s"
}

spamhaus_epoch=$(tail -n 1 reference-data/threat/spamhaus/drop-v4.json | jq -r .timestamp)
gate_epoch spamhaus-drop "$spamhaus_epoch" 172800

ris_generated=$(gzip -dc reference-data/routing/riswhois-ipv4.gz | sed -n '2s/^% This file was generated at \(.*\)\.$/\1/p')
gate_epoch ripe-ris "$(date -u -d "$ris_generated" +%s)" 172800

aws_created=$(jq -r .createDate reference-data/infrastructure/aws/ip-ranges.json)
aws_date="${aws_created:0:10} ${aws_created:11:2}:${aws_created:14:2}:${aws_created:17:2} UTC"
gate_epoch aws-ranges "$(date -u -d "$aws_date" +%s)" 604800

gcp_created=$(jq -r .creationTime reference-data/infrastructure/gcp/cloud.json)
gate_epoch gcp-ranges "$(date -u -d "$gcp_created UTC" +%s)" 604800

for path in reference-data/threat/abusech/feodo-ipblocklist.json reference-data/anonymity/tor/tor-bulk-exit-list.txt; do
  test -s "$path"
  test -s "${path}.headers"
done
