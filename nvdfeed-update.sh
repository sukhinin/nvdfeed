#!/usr/bin/env bash

set -exo pipefail

temp_file=$(mktemp)
trap "rm -f $temp_file" EXIT
curl -sL https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz | gunzip > $temp_file
mkdir -p static
node nvdfeed-map.js $temp_file static/nvdcve-mapped.json
