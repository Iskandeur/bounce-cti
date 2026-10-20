# bounce-cti in one container: the FastAPI backend, the built frontend it serves, and the
# `claude` CLI it spawns for every investigation phase. Run it with docker-compose.yml
# (README, Setup > "With Docker (one command)"); the guard on this file is
# backend/tests/test_docker_packaging.py.

# ── Stage 1: build the frontend (Vite) ──────────────────────────────────────────────────
FROM node:22-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Stage 2: runtime ────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl + certificates: the claude CLI installer below, and HTTPS to every CTI source.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Not root: `claude -p --permission-mode bypassPermissions` refuses to run as root.
# /app belongs to that user: the backend writes data/ and per-investigation files there.
RUN useradd --create-home --uid 10001 bounce \
 && mkdir -p /app/data \
 && chown -R bounce:bounce /app
WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

USER bounce

# The claude CLI, from Anthropic's native installer, into ~/.local/bin (a path
# agent_runner._resolve_claude_bin() also probes). `stable`, `latest` or a version.
ARG CLAUDE_CODE_VERSION=stable
RUN curl -fsSL https://claude.ai/install.sh | bash -s -- "$CLAUDE_CODE_VERSION" \
 && /home/bounce/.local/bin/claude --version
ENV PATH="/home/bounce/.local/bin:${PATH}"

COPY --chown=bounce:bounce . .
COPY --chown=bounce:bounce --from=frontend /build/frontend/dist ./frontend/dist

# SQLite database, cache, per-investigation logs and captures. A named volume in compose.
VOLUME ["/app/data"]

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/', timeout=4)"

# 0.0.0.0 inside the container only: compose publishes the port on the host's 127.0.0.1.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8001"]
