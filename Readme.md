# Dock[er]Inv[entory]

<p>
    <a href="https://github.com/tldev-de/dockinv/blob/main/LICENSE"><img src="https://badges.fw-web.space/github/license/tldev-de/dockinv" /></a>
    <img src="https://badges.fw-web.space/github/languages/code-size/tldev-de/dockinv" />
    <img src="https://badges.fw-web.space/github/last-commit/tldev-de/dockinv">
    <img src="https://badges.fw-web.space/github/release/tldev-de/dockinv">
    <img src="https://badges.fw-web.space/github/actions/workflow/status/tldev-de/dockinv/build.yml?event=release">
    <img src="https://badges.fw-web.space/docker/pulls/tldevde/dockinv-agent?label=agent%20docker%20pulls">
    <img src="https://badges.fw-web.space/docker/pulls/tldevde/dockinv-server?label=server%20docker%20pulls">
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

## CLI

Since there is no web interface yet, you can use the CLI to interact with the database. The CLI is available via the
`flask` command. You can use the following commands:

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

## Keywords

- Docker Security Dashboard
- Docker Inventory
- Docker scan full host
- Docker scan all images