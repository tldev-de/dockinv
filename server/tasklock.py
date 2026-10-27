"""Prevent overlapping runs of the same periodic Celery task (issue #1).

A task of the same type can overlap if a run takes longer than its schedule
interval (e.g. the collector polling many hosts). ``single_instance`` guards a
task with a non-blocking Redis lock on the existing broker: if another run already
holds the lock, this run is skipped. The lock has a timeout so a crashed worker
can't hold it forever.

Fail-safe: if no broker is configured or Redis is unreachable, the task simply
runs without a lock (locking is a best-effort guard, not a correctness barrier —
and without a broker there are no concurrent workers anyway).
"""
import os
from functools import wraps

import redis
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

_client = None


def _get_redis():
    """Return a cached Redis client built from CELERY_BROKER_URL, or None."""
    global _client
    if _client is None:
        url = os.getenv('CELERY_BROKER_URL')
        if not url:
            return None
        _client = redis.Redis.from_url(url)
    return _client


def single_instance(timeout=3600):
    """Skip the wrapped task if another instance already holds its lock."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client = _get_redis()
            if client is None:
                return func(*args, **kwargs)  # no broker -> no concurrent workers

            lock = client.lock(f'dockinv:lock:{func.__name__}', timeout=timeout)
            try:
                acquired = lock.acquire(blocking=False)
            except redis.exceptions.RedisError as e:
                logger.warning(f'lock backend unavailable ({e}); running {func.__name__} unlocked')
                return func(*args, **kwargs)

            if not acquired:
                logger.info(f'{func.__name__} skipped: another run is already in progress')
                return None
            try:
                return func(*args, **kwargs)
            finally:
                try:
                    lock.release()
                except redis.exceptions.LockError:
                    pass  # lock already expired (run exceeded the timeout)

        return wrapper
    return decorator
