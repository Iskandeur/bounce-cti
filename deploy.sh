#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/bounce-cti"
VENV="$APP_DIR/.venv"

cd "$APP_DIR"

echo "==> Pulling latest code..."
git fetch origin main
BEFORE=$(git rev-parse HEAD)
git reset --hard origin/main
AFTER=$(git rev-parse HEAD)

if [ "$BEFORE" = "$AFTER" ]; then
    echo "==> No changes, nothing to deploy."
    exit 0
fi

echo "==> Deploying $BEFORE -> $AFTER"

# Check if Python dependencies changed
if git diff --name-only "$BEFORE" "$AFTER" | grep -q "requirements.txt"; then
    echo "==> requirements.txt changed, installing deps..."
    "$VENV/bin/pip" install --quiet -r requirements.txt
fi

# Check if frontend changed
if git diff --name-only "$BEFORE" "$AFTER" | grep -q "^frontend/"; then
    echo "==> Frontend changed, rebuilding..."
    cd "$APP_DIR/frontend"
    npm ci --silent
    npm run build
    cd "$APP_DIR"
fi

echo "==> Restarting service..."
sudo -n /bin/systemctl restart bounce-cti

# Wait and verify
sleep 2
if sudo -n /bin/systemctl is-active --quiet bounce-cti; then
    echo "==> Deploy OK! Running commit: $(git rev-parse --short HEAD)"
else
    echo "==> ERROR: service failed to start!"
    sudo -n /bin/systemctl status bounce-cti --no-pager
    exit 1
fi
