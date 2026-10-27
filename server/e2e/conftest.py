"""End-to-end (browser) test fixtures.

These tests need a real browser (Playwright) and are kept out of the default unit
run (`pytest` uses testpaths=tests). Run them with a browser available:

    pip install -r requirements.txt -r requirements-e2e.txt
    python -m playwright install --with-deps chromium
    cd server && PYTHONPATH=. pytest e2e
"""
import os
import threading

import pytest
from werkzeug.serving import make_server

from config import Config

HOST = "127.0.0.1"
PORT = 8099


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("e2e") / "e2e.db"

    class _Cfg(Config):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
        # Allow the threaded dev server to share the SQLite file across threads.
        SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
        WTF_CSRF_ENABLED = True  # exercise the real CSRF-over-HTMX path

    os.environ.setdefault("SECRET_KEY", "e2e-secret")

    from app import create_app
    from extensions import db
    from models import Host

    app = create_app(_Cfg)
    with app.app_context():
        db.create_all()
        Host(name="smoke-host", address="http://a/", enabled=True, token="t").save()

    server = make_server(HOST, PORT, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{HOST}:{PORT}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def console_errors(page):
    """Collect browser console errors + uncaught page errors (incl. CSP violations)."""
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    return errors
