#!/usr/bin/env sh
set -e

git pull --ff-only
reposhield scan --mode ci --fail-on high
npm ci --ignore-scripts
npm run build

# TODO: Replace YOUR_SERVICE with the service manager's unit name.
systemctl restart YOUR_SERVICE
