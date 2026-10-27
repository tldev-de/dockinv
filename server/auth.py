"""Optional OIDC authentication for the web UI.

Authentication is *optional*: it is only enforced when OIDC is configured via the
environment (``OIDC_DISCOVERY_URL``, ``OIDC_CLIENT_ID``, ``OIDC_CLIENT_SECRET``).
If OIDC is not configured the application runs without authentication, exactly as
before, and emits a startup warning.

This keeps the tool easy to run on a trusted private network while allowing a
real login to be switched on with a few environment variables.
"""
import os
import warnings

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, redirect, request, session, url_for, flash

oauth = OAuth()
auth = Blueprint('auth', __name__)

# Endpoints reachable without a login. The health check must stay open so the
# Docker/orchestrator health probe keeps working; static assets must load on the
# login page itself.
_PUBLIC_ENDPOINTS = {'auth.login', 'auth.callback', 'auth.logout', 'general.get_health'}


def oidc_enabled():
    """Return True only when all required OIDC settings are present."""
    return all(
        os.environ.get(key)
        for key in ('OIDC_DISCOVERY_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET')
    )


def init_auth(app):
    """Register the OAuth client and the login guard, if OIDC is configured."""
    oauth.init_app(app)

    if not oidc_enabled():
        warnings.warn(
            "OIDC is not configured (OIDC_DISCOVERY_URL / OIDC_CLIENT_ID / "
            "OIDC_CLIENT_SECRET). The web UI runs WITHOUT authentication.",
            stacklevel=2,
        )
        return

    oauth.register(
        name='oidc',
        client_id=os.environ['OIDC_CLIENT_ID'],
        client_secret=os.environ['OIDC_CLIENT_SECRET'],
        server_metadata_url=os.environ['OIDC_DISCOVERY_URL'],
        client_kwargs={'scope': os.environ.get('OIDC_SCOPE', 'openid email profile')},
    )

    # Carry the forwarded scheme/host through a reverse proxy so the external
    # redirect URI is built correctly (https, public host).
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def require_login():
        endpoint = request.endpoint or ''
        if endpoint in _PUBLIC_ENDPOINTS or endpoint.endswith('static'):
            return None
        if session.get('user'):
            return None
        return redirect(url_for('auth.login', next=request.full_path))


@auth.route('/login')
def login():
    if not oidc_enabled():
        return redirect(url_for('frontend.get_hosts'))
    session['next'] = request.args.get('next') or url_for('frontend.get_hosts')
    redirect_uri = os.environ.get('OIDC_REDIRECT_URI') or url_for('auth.callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@auth.route('/auth/callback')
def callback():
    token = oauth.oidc.authorize_access_token()
    userinfo = token.get('userinfo') or oauth.oidc.userinfo()
    session['user'] = {
        'sub': userinfo.get('sub'),
        'email': userinfo.get('email'),
        'name': userinfo.get('name') or userinfo.get('preferred_username'),
    }
    return redirect(session.pop('next', None) or url_for('frontend.get_hosts'))


@auth.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('frontend.get_hosts'))
