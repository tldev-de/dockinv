# Dock[er]Inv[entory]

<p>
    <a href="https://github.com/tldev-de/dockinv/blob/main/LICENSE"><img src="https://img.shields.io/github/license/tldev-de/dockinv" /></a>
    <img src="https://img.shields.io/github/languages/code-size/tldev-de/dockinv" />
    <img src="https://img.shields.io/github/last-commit/tldev-de/dockinv">
    <img src="https://img.shields.io/github/v/release/tldev-de/dockinv">
    <img src="https://img.shields.io/github/actions/workflow/status/tldev-de/dockinv/build.yml?event=release">
    <a href="https://sonarcloud.io/summary/overall?id=tldev-de_dockinv" target="_blank"><img src="https://sonarcloud.io/api/project_badges/measure?project=tldev-de_dockinv&metric=alert_status"></a>
    <img src="https://img.shields.io/docker/pulls/tldevde/dockinv-agent?label=agent%20docker%20pulls">
    <img src="https://img.shields.io/docker/pulls/tldevde/dockinv-server?label=server%20docker%20pulls">
</p>

> [!WARNING]  
> This project is currently in heavy development and not ready for production use. Please use it only, if you know what
> you're doing. In the future, there will be a stable release.

## Description

DockInv helps to get an overview of used docker images across multiple servers. It uses trivy and xeol to find
end-of-live or vulnerable docker images. It consists of two parts: dockinv agent and dockinv server. The agent is a
simple python script that gives limited external access to the containers endpoint of the docker api. The server is a
web application that collects the information and displays it in a web interface.

## Tech Stack

- **Flask** as web framework (with SQLAlchemy, flask_migrate, gunicorn, click, ...)
- **Celery** as background task runner
- **Docker** as deployment platform
- **Trivy** as vulnerability scanner
- **Xeol** as end-of-life scanner
- **SQLite** as database

## Installation

At the moment, the server needs to reach the agents via http(s). Since you should not expose the agents to the
internet, there must be a secure connection between the server and the agents. The `docker-compose.yml` file contains a
sample agent and server setup. You can use it as a starting point. Please change the `HTTP_TOKEN` environment variable
of the agent to a random string (at least 32 chars). Use the cli to add the agent to the server (see below).

## Web interface

The server ships a web interface (by default at `http://localhost:8000`) that lists hosts, images and
containers together with their Trivy (vulnerability) and Xeol (end-of-life) findings. Hosts can be
added, edited and removed directly from the UI.

### Authentication (optional OIDC)

By default the web interface runs **without authentication** — only expose it on a trusted network.
To protect it, configure an OIDC provider by setting all three environment variables on the server
(and worker) container; a login via your identity provider is then enforced for the whole UI:

| Variable              | Description                                             |
|-----------------------|--------------------------------------------------------|
| `OIDC_DISCOVERY_URL`  | `.../.well-known/openid-configuration` of your provider |
| `OIDC_CLIENT_ID`      | OIDC client id                                          |
| `OIDC_CLIENT_SECRET`  | OIDC client secret                                      |
| `OIDC_SCOPE`          | optional, defaults to `openid email profile`           |
| `OIDC_REDIRECT_URI`   | optional, override the callback URL behind a proxy      |

Also set a persistent `SECRET_KEY` so sessions survive restarts and are shared across workers.

## CLI

Alongside the web interface, a CLI is available via the `flask` command for scripted management:

| Command               | Description                                            |
|-----------------------|--------------------------------------------------------|
| `flask db upgrade`    | Upgrade database                                       |
| `flask hosts ls`      | List all hosts                                         |
| `flask hosts add`     | Add a new host                                         |
| `flask hosts edit`    | Edit a host                                            |
| `flask hosts rm`      | Remove a host                                          |
| `flask images ls`     | List all images (including the trivy and xeol results) |
| `flask containers ls` | List all found containers                              |

Use the `--help` flag to get more information about the commands.

## Dev Setup

You can run the server and the agent on your local machine via docker compose. The agent will be available
at http://localhost:9999/. The server will be available at `http://localhost:8000`.

```bash
docker compose -f docker-compose-dev.yml up
```

The files are mounted into the containers, so you can change the code and the changes will be reflected in the
containers immediately. Since flask runs in debug mode, the server will restart automatically when you change the code.
The celery worker has to be restarted manually.

Whenever you change some Dockerfile related stuff, you have to use the `--build` flag to rebuild the images:

```bash
docker compose -f docker-compose-dev.yml up --build
```

### Database Migration

Whenever you change the database models, please create and commit a new migration:

```bash
flask db migrate -m "[your description of the changes]"
```

### Tests

Both parts have a pytest suite (server and agent are tested independently). Install the dev
dependencies and run them from the respective directory:

```bash
# server
pip install -r server/requirements-dev.txt
cd server && PYTHONPATH=. pytest

# agent
pip install -r agent/requirements-dev.txt
cd agent && PYTHONPATH=. pytest
```

There is also a browser-based end-to-end suite (Playwright) for the HTMX frontend, kept separate
from the unit tests:

```bash
pip install -r server/requirements-e2e.txt
python -m playwright install --with-deps chromium
cd server && PYTHONPATH=. pytest e2e
```

The unit, agent and e2e suites all run in CI on every push and pull request
(see `.github/workflows/test.yml`).

## Keywords

- Docker Security Dashboard
- Docker Inventory
- Docker scan full host
- Docker scan all images