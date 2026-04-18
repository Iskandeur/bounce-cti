#!/usr/bin/env bash
set -euo pipefail

# Wrap in a block so bash reads the entire script into memory before executing.
# This prevents issues when git reset --hard overwrites this file mid-execution.
main() {
    local APP_DIR="/opt/bounce-cti"
    local VENV="$APP_DIR/.venv"

    cd "$APP_DIR"

    echo "==> Pulling latest code..."
    git fetch origin main
    local BEFORE
    BEFORE=$(git rev-parse HEAD)
    git reset --hard origin/main
    local AFTER
    AFTER=$(git rev-parse HEAD)

    if [ "$BEFORE" = "$AFTER" ]; then
        echo "==> No changes, nothing to deploy."
        return 0
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
    if sudo -n /bin/systemctl status bounce-cti > /dev/null 2>&1; then
        echo "==> Deploy OK! Running commit: $(git rev-parse --short HEAD)"
    else
        echo "==> ERROR: service failed to start!"
        return 1
    fi
}

main "$@"
