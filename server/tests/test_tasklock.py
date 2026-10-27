"""Overlap guard for periodic tasks (issue #1): single_instance Redis lock."""
from unittest.mock import MagicMock

import redis

import tasklock
from tasklock import single_instance


def _wrapped():
    calls = []

    @single_instance()
    def task():
        calls.append(1)
        return "ran"

    return task, calls


def _fake_client(acquire_result):
    client = MagicMock()
    lock = MagicMock()
    lock.acquire.return_value = acquire_result
    client.lock.return_value = lock
    return client, lock


def test_runs_without_broker(monkeypatch):
    monkeypatch.setattr(tasklock, "_get_redis", lambda: None)
    task, calls = _wrapped()
    assert task() == "ran"
    assert calls == [1]


def test_runs_and_releases_when_lock_acquired(monkeypatch):
    client, lock = _fake_client(True)
    monkeypatch.setattr(tasklock, "_get_redis", lambda: client)
    task, calls = _wrapped()
    assert task() == "ran"
    assert calls == [1]
    lock.acquire.assert_called_once_with(blocking=False)
    lock.release.assert_called_once()


def test_skips_when_lock_already_held(monkeypatch):
    client, lock = _fake_client(False)
    monkeypatch.setattr(tasklock, "_get_redis", lambda: client)
    task, calls = _wrapped()
    assert task() is None       # skipped
    assert calls == []          # body NOT executed
    lock.release.assert_not_called()


def test_fail_open_on_redis_error(monkeypatch):
    client = MagicMock()
    lock = MagicMock()
    lock.acquire.side_effect = redis.exceptions.RedisError("backend down")
    client.lock.return_value = lock
    monkeypatch.setattr(tasklock, "_get_redis", lambda: client)
    task, calls = _wrapped()
    assert task() == "ran"      # runs anyway
    assert calls == [1]


def test_expired_lock_release_is_swallowed(monkeypatch):
    client, lock = _fake_client(True)
    lock.release.side_effect = redis.exceptions.LockError("already expired")
    monkeypatch.setattr(tasklock, "_get_redis", lambda: client)
    task, _ = _wrapped()
    assert task() == "ran"      # no exception despite release failure


def test_collector_skipped_when_lock_held(app, run_task, monkeypatch):
    # integration: a held lock must make the real task a no-op (no polling)
    import requests_mock
    import tasks
    from models import Host, Container

    client, lock = _fake_client(False)      # acquire -> False (already running)
    monkeypatch.setattr(tasklock, "_get_redis", lambda: client)

    Host(name="h", address="http://a/", enabled=True, token="t").save()
    with requests_mock.Mocker() as m:
        adapter = m.get("http://a/containers", json=[{"name": "c1", "image_name": "x",
                                                      "image_tag": "1", "repo_digest": None,
                                                      "status": "running",
                                                      "started_at": "2024-01-01T00:00:00Z"}])
        run_task(tasks.data_collector_background_task)

    assert not adapter.called            # skipped -> never polled the agent
    assert Container.query.count() == 0  # and wrote nothing
