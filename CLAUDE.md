# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DockInv (Dock[er] Inv[entory]) gives an overview of Docker images running across multiple
servers and flags end-of-life or vulnerable images using **Trivy** (vulnerabilities) and
**Xeol** (end-of-life). It has two independently-deployed parts that share no code:

- **`agent/`** — a tiny single-file Flask app (`agent.py`) deployed next to each Docker host.
  It mounts the host's `docker.sock` (read-only) and exposes `GET /containers`, returning the
  running containers plus each one's `repo_digest`. Auth is a single shared secret compared
  against the `Authorization` header via `hmac.compare_digest` (`HTTP_TOKEN` env var). Runs as
  **root** because it needs the Docker socket.

- **`server/`** — the Flask web app + Celery worker that polls agents, stores results in SQLite,
  runs the scanners, and renders the dashboard. Runs as a non-root user.

The two communicate only over HTTP(S); the server is the client, the agent is the server. Agents
are expected to live on a private network, not the public internet.

## Architecture (server)

The server follows the Flask app-factory pattern. `create_app()` in `server/app.py` wires together
blueprints, extensions (`server/extensions.py`: SQLAlchemy `db`, Flask-Migrate, CSRF), and CLI
command groups. Key flows:

- **Data collection** (`server/tasks.py` → `data_collector_background_task`): Celery beat polls
  every enabled `Host`'s `/containers` endpoint, upserts `Image` + `Container` rows, and **deletes
  stale containers** no longer reported by the host. This is the only writer of inventory data.
- **Scanning** (`trivy_background_task`, `xeol_background_task`): for images that have containers
  and are stale (>24h) or unscanned, shells out to the `trivy`/`xeol` binaries and stores the raw
  JSON output in `Image.status_trivy` / `Image.status_xeol` (JSON columns).
- **Presentation** (`server/routes/frontend.py`): parses that stored scanner JSON on the fly into
  counts/sorted findings for the templates. The transform helpers (`count_trivy_findings*`,
  `is_image_eol`, `transform_*_for_display`) encapsulate the scanner JSON schema — change them
  together if a scanner output format changes.

Data model (`server/models/`, all `@dataclass` + `BaseModel`): `Host` 1—N `Container` N—1 `Image`.
`BaseModel.save()`/`delete()` wrap commit with rollback-on-error and return `None` on failure
(callers in `tasks.py` check for this). `Image.repo_digest` is the unique natural key for images.

The Celery worker process reuses the Flask app via `ContextTask`, which pushes an app context
around every task so tasks can use the SQLAlchemy models directly.

**Auth (`server/auth.py`) is optional OIDC.** `init_auth(app)` (called in `create_app`) registers
an Authlib client and a `before_request` login guard **only** when `OIDC_DISCOVERY_URL`,
`OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` are all set; otherwise the UI runs unauthenticated and a
startup warning is emitted. `/health` and static assets stay public so health probes keep working.

## Commands

All server/Flask commands must run from `server/` (that dir must be on `PYTHONPATH`; the Docker
image sets `PYTHONPATH=/app`). The app reads config from env vars (`server/config.py`), notably
`SQLALCHEMY_DATABASE_URI` (defaults to `sqlite:////data/database.db`).

**Run everything locally via Docker Compose (preferred):**
```bash
docker compose -f docker-compose-dev.yml up          # server :8000, agent :9999, redis, worker
docker compose -f docker-compose-dev.yml up --build   # after Dockerfile/dependency changes
```
Code is bind-mounted, so Flask (debug mode) auto-reloads. The **Celery worker does NOT auto-reload
— restart it manually after editing `tasks.py`.** The dev compose auto-runs migrations
(`DATABASE_AUTO_UPGRADE=1`) and auto-registers the dev agent (`HOSTS_ADD_DEV_AGENT=1`).

**CLI (management commands, registered in `server/app.py` from `server/commands/`):**
```bash
flask hosts ls|add|edit|rm      # manage agents the server polls (aliases exist, e.g. add/create/new)
flask images ls                 # list images with trivy/xeol summaries
flask containers ls
flask db upgrade                # apply migrations
flask db migrate -m "message"   # generate a migration after changing a model — commit it
```

**CSS** is compiled from Tailwind + DaisyUI at Docker build time (first stage of
`server/Dockerfile`): `npx tailwindcss -i static/css/input.css -o static/css/theme.css`.
`theme.css` is gitignored and generated — do not edit it by hand.

## Conventions & Gotchas

- **No test suite and no linter config exist** despite the parent `CLAUDE.md` mentioning pytest/
  pylint generically. There is nothing to run; don't assume `pytest` is wired up.
- **Database migrations are required** for any model change — generate with `flask db migrate` and
  commit the version file under `server/migrations/versions/`.
- The agent shares no dependencies or code with the server (`agent/requirements.txt` is just
  `flask` + `docker`). Keep it minimal and self-contained.
- Images are published to Docker Hub (`tldevde/dockinv-{agent,server}`) and GHCR on push to `main`
  (`:main` tag) and on release (`:latest` + version tag) via `.github/workflows/build.yml`.
- `SECRET_KEY` must be set in production; without it `create_app` warns and generates an ephemeral
  key (sessions break across workers/restarts).
