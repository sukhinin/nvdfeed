#!/usr/bin/env bash

set -exo pipefail

GIT_BRANCH=$(git branch --show-current)
GIT_COMMIT=$(git rev-parse --short HEAD)
GIT_DIRTY=$(git diff --quiet || echo ' (dirty)')

UPDATE_TIME=$(date -u "+%Y-%m-%dT%H:%M:%SZ")

mkdir -p static
cat > static/metadata.json <<EOF
{
  "git_commit": "$GIT_COMMIT@$GIT_BRANCH$GIT_DIRTY",
  "last_update": "$UPDATE_TIME"
}
EOF
