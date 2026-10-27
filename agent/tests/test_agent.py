"""§3 – Agent unit tests: ref parsing, token enforcement, /containers, /health."""
import os
import subprocess
import sys
from unittest.mock import MagicMock

import docker
import pytest

import agent as agent_module
from conftest import TOKEN

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --- split_image_ref (Bug-3 regression) ------------------------------------

@pytest.mark.parametrize("ref,expected", [
    ("app", ("app", "latest")),
    ("app:1.2", ("app", "1.2")),
    ("registry:5000/app", ("registry:5000/app", "latest")),
    ("registry:5000/app:tag", ("registry:5000/app", "tag")),
    ("ghcr.io/org/app:v1", ("ghcr.io/org/app", "v1")),
    ("app@sha256:abc", ("app", "latest")),
    ("registry:5000/app@sha256:abc", ("registry:5000/app", "latest")),
])
def test_split_image_ref(ref, expected):
    assert agent_module.split_image_ref(ref) == expected


# --- token enforcement (subprocess, isolates module-level SystemExit) -------

def _import_agent(env):
    child_env = dict(os.environ)
    child_env.pop("HTTP_TOKEN", None)
    child_env.pop("DOCKINV_ALLOW_NO_TOKEN", None)
    child_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", "import agent"],
        cwd=AGENT_DIR, env=child_env, capture_output=True, text=True,
    )


def test_refuses_to_start_without_token():
    res = _import_agent({})
    assert res.returncode != 0
    assert "HTTP_TOKEN" in res.stderr


def test_starts_with_optout():
    assert _import_agent({"DOCKINV_ALLOW_NO_TOKEN": "1"}).returncode == 0


def test_starts_with_token():
    assert _import_agent({"HTTP_TOKEN": "something"}).returncode == 0


# --- /containers auth + payload --------------------------------------------

def test_containers_rejects_missing_token(client):
    assert client.get("/containers").status_code == 403


def test_containers_rejects_wrong_token(client):
    assert client.get("/containers", headers={"Authorization": "wrong"}).status_code == 403


def test_containers_returns_payload(client, monkeypatch):
    image = MagicMock(id="img1", attrs={"RepoDigests": ["nginx@sha256:aaa"]})
    container = MagicMock(id="c1", status="running")
    container.name = "web"  # `name=` kwarg is reserved by MagicMock, set explicitly
    container.attrs = {
        "Config": {"Image": "registry:5000/nginx:1.2"},
        "Image": "img1",
        "State": {"StartedAt": "2024-12-29T17:34:19Z"},
    }
    docker_client = MagicMock()
    docker_client.containers.list.return_value = [container]
    docker_client.images.list.return_value = [image]
    monkeypatch.setattr(agent_module.docker, "from_env", lambda: docker_client)

    res = client.get("/containers", headers={"Authorization": TOKEN})
    assert res.status_code == 200
    data = res.get_json()
    assert data[0]["image_name"] == "registry:5000/nginx"
    assert data[0]["image_tag"] == "1.2"
    assert data[0]["repo_digest"] == "nginx@sha256:aaa"
    assert data[0]["status"] == "running"


# --- /health ---------------------------------------------------------------

def test_health_ok(client, monkeypatch):
    docker_client = MagicMock()
    docker_client.version.return_value = {"Version": "1.2.3"}
    monkeypatch.setattr(agent_module.docker, "from_env", lambda: docker_client)
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_health_error(client, monkeypatch):
    def boom():
        raise docker.errors.DockerException("docker down")
    monkeypatch.setattr(agent_module.docker, "from_env", boom)
    assert client.get("/health").status_code == 500
