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

    from datetime import datetime, timezone

    from app import create_app
    from extensions import db
    from models import Host, Image, Container
    import vulnerabilities as vuln_service

    app = create_app(_Cfg)
    with app.app_context():
        db.create_all()
        host = Host(name="smoke-host", address="http://a/", enabled=True, token="t")
        host.save()
        # Seed an image + container + two CVEs so the Vulnerabilities page has data to filter.
        image = Image(name="nginx", repo_digest="nginx@sha256:a")
        image.save()
        Container(host_id=host.id, name="web", image_string="nginx:1", image_id=image.id,
                  status="running", started_at=datetime.now(timezone.utc)).save()
        vuln_service.set_trivy_result(image, {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-111111", "Severity": "CRITICAL", "PkgName": "libssl",
             "CVSS": {"nvd": {"V3Score": 9.8}}},
            {"VulnerabilityID": "CVE-2026-222222", "Severity": "LOW", "PkgName": "zlib",
             "CVSS": {"nvd": {"V3Score": 3.1}}},
        ]}]})

    server = make_server(HOST, PORT, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{HOST}:{PORT}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args):
    # GitHub's ubuntu-latest (24.04) AppArmor blocks Chromium's user-namespace
    # sandbox, so the browser fails to launch without --no-sandbox. Harmless for
    # these tests; required for CI.
    return {**browser_type_launch_args, "args": ["--no-sandbox"]}


@pytest.fixture
def console_errors(page):
    """Collect browser console errors + uncaught page errors (incl. CSP violations)."""
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    return errors
