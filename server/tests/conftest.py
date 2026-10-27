"""Shared pytest fixtures for the DockInv server test-suite.

Two project-specific gotchas are handled here (see testing-plan.md §1):

1. ``Config.SQLALCHEMY_DATABASE_URI`` is evaluated at import time, so a test DB
   cannot be injected via ``monkeypatch.setenv``. We build a per-test config
   object with a temp-file SQLite DB and pass it to ``create_app``. ``SECRET_KEY``
   and the ``OIDC_*`` vars *are* read at call time, so those use ``setenv``.

2. Celery tasks must not be called naively: ``ContextTask.__call__`` would build
   its own app via ``create_app(Config)`` and write to the real ``/data`` DB. The
   ``run_task`` fixture pins ``ContextTask._app`` to the test app first.
"""
import pytest

from config import Config


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app(monkeypatch, tmp_path):
    # OIDC off by default (read from os.environ at create_app/init_auth time).
    for var in ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SECRET_KEY", "test")

    class _Cfg(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"

    from app import create_app
    from extensions import db

    application = create_app(_Cfg)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def cli(app):
    return app.test_cli_runner()


@pytest.fixture(autouse=True)
def _reset_health_cache():
    # /health caches the detected scanner versions in a module global; clear it so
    # the "tools present" and "tool missing" tests don't depend on execution order.
    import routes.general as general
    general._tool_versions = None
    yield
    general._tool_versions = None


@pytest.fixture
def run_task(app):
    """Run a @celery.task against the test app/DB instead of the real one."""
    import tasks

    tasks.ContextTask._app = app
    try:
        # Calling the task runs it synchronously; ContextTask.__call__ pushes the
        # test app's context because _app is set above.
        yield lambda task, *a, **k: task(*a, **k)
    finally:
        tasks.ContextTask._app = None
