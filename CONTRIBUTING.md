# Contributing to Bounce-CTI

Thanks for your interest in improving Bounce-CTI! This guide covers how to
contribute and the few rules that keep the project safe to deploy.

> **License note.** Bounce-CTI is **source-available**, not OSI open-source
> (see [LICENSE](./LICENSE) and [COMMERCIAL.md](./COMMERCIAL.md)). Contributions
> are welcome, but before your first contribution can be merged you must sign
> the **[Contributor License Agreement](./CLA.md)** — this is what lets the
> project reuse your work across all its distributions. See "CLA" below.

## CLA — required before your first merge

We use **CLA-Assistant**. On your first pull request, a bot comments with a
link to sign the [CLA](./CLA.md). Sign once and it covers all your future PRs.
**A PR cannot be merged until the CLA check is green.** If you contribute on
behalf of an employer, make sure you're authorized to sign.

## Before you start

- **Open an issue first** for anything non-trivial (a new source, a schema
  change, a workflow change). Small fixes (typos, responsive CSS, a single bug)
  can go straight to a PR.
- Good first issues are labelled `good first issue`.

## Development setup

```bash
# Backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload

# Frontend (separate terminal)
cd frontend && npm install && npm run dev   # Vite on :5173, proxies to :8001
```

See [CLAUDE.md](./CLAUDE.md) and [ARCHITECTURE.md](./ARCHITECTURE.md) for the
full architecture, conventions, and project layout.

## The rules that matter (please read)

1. **`main` deploys straight to production — there is no staging.** Every merge
   to `main` is live within minutes. Your PR must pass the CI merge-gate
   (`.github/workflows/ci.yml`): the backend must import and the frontend must
   build. Run both locally before pushing:
   ```bash
   python -c "import backend.main"        # must succeed
   cd frontend && npm run build           # must succeed
   ```
2. **Never commit secrets.** No API keys, tokens, PINs, or `.env` contents.
   `.env` is gitignored — keep it that way. Use `.env.example` for new config
   keys (with a placeholder value, never a real one).
3. **Keep docs in sync in the same commit.** If you change project layout, MCP
   tools, routes, the DB schema, auth, the deploy pipeline, `.env.example`, or
   user-visible features, update the relevant docs (`README.md`, `CLAUDE.md`,
   `ARCHITECTURE.md`, `PURPOSE.md`) in the *same* commit. See the
   "Documentation upkeep" table in [CLAUDE.md](./CLAUDE.md).
4. **Agent-behaviour changes require an EVAL re-run.** If your change touches the
   agent system prompt or workflow (`backend/agent_runner.py`) or anything that
   alters the agent's output, re-run [EVAL_PROTOCOL.md](./EVAL_PROTOCOL.md) and
   note the result in your PR. CTI must stay iso-functional.
5. **Don't include third-party code without flagging it.** If you copy or adapt
   code/data from another project, note its source and license in your PR so it
   can be tracked in `THIRD_PARTY_LICENSES` / `NOTICE`. Avoid copyleft
   (GPL/AGPL) code — see [CLA.md](./CLA.md) §4.

## Pull-request checklist

- [ ] CLA signed (the bot check is green).
- [ ] `import backend.main` succeeds and `npm run build` succeeds.
- [ ] No secrets in the diff.
- [ ] Docs updated in the same commit (if applicable).
- [ ] EVAL re-run noted (if the agent's behaviour changed).
- [ ] PR description explains the *why*, not just the *what*.

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities. Email
**alexandre.pinoteau@protonmail.com** directly.

Thanks for contributing! — Alexandre
