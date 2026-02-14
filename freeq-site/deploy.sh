#!/bin/bash
# Deploy freeq-site to Miren
# Copies docs from repo root before deploying

set -e
cd "$(dirname "$0")"

# Copy docs from parent repo
rm -rf docs
cp -r ../docs ./docs

echo "Deploying freeq-site..."
miren deploy -f

# Clean up
rm -rf docs
