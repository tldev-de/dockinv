"""§6 – Optional OIDC authentication.

Each OIDC test builds its own app with the three OIDC env vars set *before*
create_app, and swaps in a fresh Authlib ``OAuth`` registry (the module-level
singleton would otherwise carry a client registration across tests).
"""
import warnings

import pytest
import responses
from authlib.integrations.flask_client import OAuth

import auth as auth_module
from config import Config

DISCOVERY = "https://idp.example/.well-known/openid-configuration"


def build_oidc_app(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test")
    monkeypatch.setenv("OIDC_DISCOVERY_URL", DISCOVERY)
    monkeypatch.setenv("OIDC_CLIENT_ID", "cid")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "csecret")
    monkeypatch.setattr(auth_module, "oauth", OAuth())  # fresh registry per test

    from app import create_app
    from extensions import db

    class _Cfg(Config):
        TESTING = True
        WTF_CSRF_ENABLED = False
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'oidc.db'}"

    application = create_app(_Cfg)
    with application.app_context():
        db.create_all()
    return application


def _add_discovery():
    responses.add(
        responses.GET, DISCOVERY,
        json={
            "issuer": "https://idp.example",
            "authorization_endpoint": "https://idp.example/authorize",
            "token_endpoint": "https://idp.example/token",
            "userinfo_endpoint": "https://idp.example/userinfo",
            "jwks_uri": "https://idp.example/jwks",
        },
    )


def test_oidc_disabled_runs_without_guard(app, client):
    # `app` fixture clears OIDC env -> no guard, just a startup warning.
    assert client.get("/hosts").status_code == 200


def test_oidc_disabled_emits_warning(monkeypatch, tmp_path):
    for var in ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SECRET_KEY", "test")
    monkeypatch.setattr(auth_module, "oauth", OAuth())
    from app import create_app

    class _Cfg(Config):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'noauth.db'}"

    with pytest.warns(UserWarning, match="OIDC is not configured"):
        create_app(_Cfg)


def test_guard_redirects_unauthenticated(tmp_path, monkeypatch):
    app = build_oidc_app(tmp_path, monkeypatch)
    r = app.test_client().get("/hosts")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_health_stays_public(tmp_path, monkeypatch):
    app = build_oidc_app(tmp_path, monkeypatch)
    # /health may 200 or 500 (trivy/xeol binaries), but must not redirect to login
    r = app.test_client().get("/health")
    assert r.status_code != 302


@responses.activate
def test_login_redirects_to_idp_with_params(tmp_path, monkeypatch):
    app = build_oidc_app(tmp_path, monkeypatch)
    _add_discovery()
    r = app.test_client().get("/login")
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert loc.startswith("https://idp.example/authorize")
    assert "client_id=cid" in loc
    assert "redirect_uri=" in loc
    assert "scope=" in loc
    assert "state=" in loc


def test_callback_sets_session_user(tmp_path, monkeypatch):
    app = build_oidc_app(tmp_path, monkeypatch)
    monkeypatch.setattr(
        auth_module.oauth.oidc, "authorize_access_token",
        lambda: {"userinfo": {"sub": "s1", "email": "user@example.com", "name": "User"}},
    )
    client = app.test_client()
    r = client.get("/auth/callback")
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert sess["user"]["email"] == "user@example.com"
