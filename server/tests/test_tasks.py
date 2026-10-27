"""§4/§5 – Integration tests for the Celery tasks (data collection + scanners)."""
import json
import subprocess
from datetime import datetime, timezone

import requests_mock
from freezegun import freeze_time

import tasks
from extensions import db
from models import Host, Image, Container

AGENT = "http://agent/"


def mk_host(name="h1", enabled=True):
    h = Host(name=name, address=AGENT, enabled=enabled, token="tok")
    h.save()
    return h


def payload(name="c1", image_name="nginx", image_tag="1.0",
            repo_digest="nginx@sha256:aaa", status="running",
            started="2024-12-29T17:34:19.123456Z"):
    return {"name": name, "image_name": image_name, "image_tag": image_tag,
            "repo_digest": repo_digest, "status": status, "started_at": started}


def mk_container(host, image, name="c1"):
    Container(host_id=host.id, name=name, image_string="nginx:1.0",
              image_id=image.id, status="running",
              started_at=datetime.now(timezone.utc)).save()


# --- §4 data collection ----------------------------------------------------

def test_creates_rows(app, run_task):
    mk_host()
    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[payload()])
        run_task(tasks.data_collector_background_task)
    assert (Host.query.count(), Image.query.count(), Container.query.count()) == (1, 1, 1)
    c = Container.query.first()
    assert c.image_string == "nginx:1.0" and c.status == "running"


def test_bug1_image_change_updates_image_id(app, run_task):
    mk_host()
    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[payload(repo_digest="nginx@sha256:aaa")])
        run_task(tasks.data_collector_background_task)
    old_image_id = Container.query.first().image_id

    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[payload(repo_digest="nginx@sha256:bbb")])
        run_task(tasks.data_collector_background_task)

    c = Container.query.first()
    assert c.image_id != old_image_id
    assert Image.query.get(c.image_id).repo_digest == "nginx@sha256:bbb"


def test_bug2_digestless_images_not_collapsed(app, run_task):
    mk_host()
    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[
            payload(name="a", image_name="img-a", repo_digest=None),
            payload(name="b", image_name="img-b", repo_digest=None),
        ])
        run_task(tasks.data_collector_background_task)
    assert Image.query.count() == 2


def test_bug2_digestless_same_name_single_row(app, run_task):
    mk_host()
    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[
            payload(name="a", image_name="img-a", repo_digest=None),
            payload(name="b", image_name="img-a", repo_digest=None),
        ])
        run_task(tasks.data_collector_background_task)
    assert Image.query.count() == 1
    assert Container.query.count() == 2


def test_stale_container_removed(app, run_task):
    mk_host()
    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[
            payload(name="a"),
            payload(name="b", repo_digest="other@sha256:bbb"),
        ])
        run_task(tasks.data_collector_background_task)
    assert Container.query.count() == 2

    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", json=[payload(name="a")])
        run_task(tasks.data_collector_background_task)
    assert {c.name for c in Container.query.all()} == {"a"}


def test_agent_error_skips_host_without_crash(app, run_task):
    mk_host()
    with requests_mock.Mocker() as m:
        m.get(AGENT + "containers", status_code=500)
        run_task(tasks.data_collector_background_task)  # must not raise
    assert Container.query.count() == 0


def test_disabled_host_not_polled(app, run_task):
    mk_host(enabled=False)
    with requests_mock.Mocker() as m:
        adapter = m.get(AGENT + "containers", json=[payload()])
        run_task(tasks.data_collector_background_task)
    assert not adapter.called
    assert Container.query.count() == 0


# --- §5 scanner tasks ------------------------------------------------------

def _patch_subprocess(monkeypatch, stdout="{}", raise_called_process=False, raise_timeout=False):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if raise_called_process:
            raise subprocess.CalledProcessError(1, cmd, stderr="boom")
        if raise_timeout:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)
    return calls


def test_trivy_scans_and_stores(app, run_task, monkeypatch):
    h = mk_host()
    image = Image(name="nginx", repo_digest="nginx@sha256:aaa")
    image.save()
    mk_container(h, image)
    _patch_subprocess(monkeypatch, stdout=json.dumps({"Results": []}))

    run_task(tasks.trivy_background_task)

    stored = Image.query.get(image.id)
    assert stored.status_trivy == {"Results": []}
    assert stored.updated_at is not None


def test_xeol_scans_and_stores(app, run_task, monkeypatch):
    h = mk_host()
    image = Image(name="nginx", repo_digest="nginx@sha256:aaa")
    image.save()
    mk_container(h, image)
    _patch_subprocess(monkeypatch, stdout=json.dumps({"matches": []}))

    run_task(tasks.xeol_background_task)

    assert Image.query.get(image.id).status_xeol == {"matches": []}


def test_trivy_skips_image_without_container(app, run_task, monkeypatch):
    Image(name="orphan", repo_digest="orphan@sha256:zzz").save()
    calls = _patch_subprocess(monkeypatch)
    run_task(tasks.trivy_background_task)
    assert calls == []


def test_trivy_skips_already_scanned(app, run_task, monkeypatch):
    h = mk_host()
    image = Image(name="nginx", repo_digest="nginx@sha256:aaa", status_trivy={"Results": []})
    image.save()
    mk_container(h, image)
    calls = _patch_subprocess(monkeypatch)
    run_task(tasks.trivy_background_task)
    assert calls == []


def test_trivy_rescans_when_stale(app, run_task, monkeypatch):
    h = mk_host()
    with freeze_time("2026-01-01 00:00:00"):
        image = Image(name="nginx", repo_digest="nginx@sha256:aaa")
        image.save()
        image.status_trivy = {"old": True}
        image.save()  # onupdate sets updated_at to the frozen (long-past) time
        mk_container(h, image)
    # back to real "now" -> updated_at is far older than 24h -> rescan
    _patch_subprocess(monkeypatch, stdout=json.dumps({"Results": []}))
    run_task(tasks.trivy_background_task)
    assert Image.query.get(image.id).status_trivy == {"Results": []}


def test_trivy_handles_called_process_error(app, run_task, monkeypatch):
    h = mk_host()
    image = Image(name="nginx", repo_digest="nginx@sha256:aaa")
    image.save()
    mk_container(h, image)
    _patch_subprocess(monkeypatch, raise_called_process=True)
    run_task(tasks.trivy_background_task)  # must not raise
    assert Image.query.get(image.id).status_trivy is None


def test_xeol_handles_called_process_error(app, run_task, monkeypatch):
    h = mk_host()
    image = Image(name="nginx", repo_digest="nginx@sha256:aaa")
    image.save()
    mk_container(h, image)
    _patch_subprocess(monkeypatch, raise_called_process=True)
    run_task(tasks.xeol_background_task)  # must not raise
    assert Image.query.get(image.id).status_xeol is None


def _image_to_scan(monkeypatch):
    h = mk_host()
    image = Image(name="nginx", repo_digest="nginx@sha256:aaa")
    image.save()
    mk_container(h, image)
    return image


def test_trivy_handles_timeout(app, run_task, monkeypatch):
    image = _image_to_scan(monkeypatch)
    _patch_subprocess(monkeypatch, raise_timeout=True)
    run_task(tasks.trivy_background_task)  # must not raise / hang
    assert Image.query.get(image.id).status_trivy is None


def test_xeol_handles_timeout(app, run_task, monkeypatch):
    image = _image_to_scan(monkeypatch)
    _patch_subprocess(monkeypatch, raise_timeout=True)
    run_task(tasks.xeol_background_task)
    assert Image.query.get(image.id).status_xeol is None


def test_trivy_handles_invalid_json(app, run_task, monkeypatch):
    image = _image_to_scan(monkeypatch)
    _patch_subprocess(monkeypatch, stdout="not valid json")
    run_task(tasks.trivy_background_task)  # JSONDecodeError must be caught
    assert Image.query.get(image.id).status_trivy is None


def test_scan_passes_timeout_kwarg(app, run_task, monkeypatch):
    from config import Config
    _image_to_scan(monkeypatch)
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"Results": []}), stderr="")

    monkeypatch.setattr(tasks.subprocess, "run", fake_run)
    run_task(tasks.trivy_background_task)
    assert seen["timeout"] == Config.TASK_SCAN_TIMEOUT
