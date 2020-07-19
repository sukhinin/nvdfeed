#!/usr/bin/env bash

set -exo pipefail

DIST_DIR=${1:-dist}
SITE_NAME=${2:-nvdfeed.netlify.app}

[[ -z "$NETLIFY_AUTH_TOKEN" ]] && { echo '$NETLIFY_AUTH_TOKEN environment variable not set'; exit 1; }
[[ -d "$DIST_DIR" ]] || { echo "Distribution directory is missing"; exit 1; }

temp_file=$(mktemp)
trap "rm -f $temp_file" EXIT

pushd $DIST_DIR
zip -r - . > $temp_file
popd

curl -H "Content-Type: application/zip" \
     -H "Authorization: Bearer $NETLIFY_AUTH_TOKEN" \
     -s --data-binary "@$temp_file" \
     https://api.netlify.com/api/v1/sites/$SITE_NAME/deploys
