"""§6 – Web UI routes and host CRUD (OIDC off; CSRF disabled via TestConfig)."""
from datetime import datetime, timezone

from models import Host, Image, Container


def seed():
    host = Host(name="h1", address="http://a/", enabled=True, token="t")
    host.save()
    image = Image(name="nginx", repo_digest="nginx@sha256:a")
    image.save()
    Container(host_id=host.id, name="c1", image_string="nginx:1",
              image_id=image.id, status="running",
              started_at=datetime.now(timezone.utc)).save()
    return host, image


class TestPages:
    def test_hosts(self, client):
        seed()
        assert client.get("/hosts").status_code == 200

    def test_images(self, client):
        seed()
        assert client.get("/images").status_code == 200

    def test_host_detail(self, client):
        host, _ = seed()
        assert client.get(f"/hosts/{host.id}").status_code == 200

    def test_image_detail(self, client):
        _, image = seed()
        assert client.get(f"/images/{image.id}").status_code == 200

    def test_container_detail(self, client):
        seed()
        cid = Container.query.first().id
        assert client.get(f"/container/{cid}").status_code == 200

    def test_unknown_host_redirects(self, client):
        r = client.get("/hosts/999")
        assert r.status_code == 302 and "/hosts" in r.headers["Location"]

    def test_unknown_image_redirects(self, client):
        r = client.get("/images/999")
        assert r.status_code == 302 and "/images" in r.headers["Location"]

    def test_unknown_container_redirects(self, client):
        r = client.get("/container/999")
        assert r.status_code == 302 and "/hosts" in r.headers["Location"]

    def test_add_host_form_renders(self, client):
        assert client.get("/hosts/add").status_code == 200

    def test_edit_host_form_renders(self, client):
        host, _ = seed()
        assert client.get(f"/hosts/edit/{host.id}").status_code == 200

    def test_edit_unknown_host_redirects(self, client):
        r = client.get("/hosts/edit/999")
        assert r.status_code == 302 and "/hosts" in r.headers["Location"]

    def test_seeded_host_name_rendered(self, client):
        seed()
        assert b"h1" in client.get("/hosts").data


class TestHostCrud:
    def test_save_normalizes_slash_and_autogenerates_token(self, client):
        r = client.post("/hosts/save",
                        data={"name": "n", "address": "http://x", "token": "", "enabled": "on"})
        assert r.status_code == 302
        h = Host.query.filter_by(name="n").first()
        assert h.address == "http://x/"   # trailing slash added
        assert len(h.token) == 32         # auto-generated

    def test_save_requires_address(self, client):
        r = client.post("/hosts/save", data={"name": "n", "address": "", "token": "t"})
        assert r.status_code == 302
        assert Host.query.count() == 0

    def test_save_rejects_duplicate(self, client):
        seed()  # existing h1 @ http://a/
        client.post("/hosts/save", data={"name": "h1", "address": "http://a/", "token": "t"})
        assert Host.query.filter_by(name="h1").count() == 1

    def test_update(self, client):
        host, _ = seed()
        client.post(f"/hosts/update/{host.id}",
                    data={"name": "h1", "address": "http://new", "token": "tok2", "enabled": "on"})
        updated = Host.query.get(host.id)
        assert updated.address == "http://new/" and updated.token == "tok2"

    def test_update_requires_address(self, client):
        host, _ = seed()
        r = client.post(f"/hosts/update/{host.id}",
                        data={"name": "h1", "address": "", "token": "t"})
        assert r.status_code == 302
        assert Host.query.get(host.id).address == "http://a/"  # unchanged

    def test_update_unknown_host_redirects(self, client):
        r = client.post("/hosts/update/999", data={"name": "x", "address": "http://y", "token": "t"})
        assert r.status_code == 302 and "/hosts" in r.headers["Location"]

    def test_update_autogenerates_token_when_blank(self, client):
        host, _ = seed()
        client.post(f"/hosts/update/{host.id}",
                    data={"name": "h1", "address": "http://new", "token": ""})
        assert len(Host.query.get(host.id).token) == 32

    def test_delete_host_without_containers(self, client):
        host = Host(name="bare", address="http://bare/", enabled=True, token="t")
        host.save()
        client.post(f"/hosts/delete/{host.id}")
        assert Host.query.get(host.id) is None

    def test_delete_host_cascades_containers(self, client):
        # delete-orphan cascade removes the host's containers along with it
        host, _ = seed()
        client.post(f"/hosts/delete/{host.id}")
        assert Host.query.get(host.id) is None
        assert Container.query.filter_by(host_id=host.id).count() == 0


class TestHealth:
    def test_ok_when_tools_present(self, client, monkeypatch):
        import subprocess
        from routes import general

        def fake_run(cmd, **kwargs):
            tool = cmd[0]
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{tool} Version: 0.50.1\n", stderr="")

        monkeypatch.setattr(general.subprocess, "run", fake_run)
        res = client.get("/health")
        assert res.status_code == 200
        assert res.get_json()["status"] == "ok"

    def test_error_when_tool_missing(self, client, monkeypatch):
        from routes import general

        def boom(cmd, **kwargs):
            raise FileNotFoundError(cmd[0])

        monkeypatch.setattr(general.subprocess, "run", boom)
        res = client.get("/health")
        assert res.status_code == 500
        assert res.get_json()["status"] == "error"


def test_edit_page_forms_not_nested(client):
    # #1: delete form must be a separate (non-nested) form, wired via form= attribute
    host, _ = seed()
    html = client.get(f"/hosts/edit/{host.id}").data.decode()
    assert 'id="editForm"' in html and 'id="deleteForm"' in html
    assert 'form="editForm"' in html and 'form="deleteForm"' in html
    # the delete <form> opens after the edit <form> has closed (not inside it)
    assert html.index('id="deleteForm"') > html.index('</form>')


def test_image_detail_has_no_stack_column(client):
    # #4: the dead "Stack" column is gone
    seed()
    image_id = Image.query.first().id
    assert b"Stack" not in client.get(f"/images/{image_id}").data


def test_hosts_last_seen_shows_never_before_first_poll(client):
    # #2: a never-polled host shows "never", not its create/update time
    seed()
    assert b"never" in client.get("/hosts").data


def test_host_page_shows_stack_and_hostnames(client):
    host, _ = seed()
    container = Container.query.first()
    container.stack = "mystack"
    container.hostnames = "app.example, api.example"
    container.save()
    html = client.get(f"/hosts/{host.id}").data.decode()
    assert "mystack" in html
    assert 'href="https://app.example"' in html    # rendered as a link
    assert 'href="https://api.example"' in html


def test_host_page_shows_critical_count_separately(client):
    # the aggregated Trivy view lists Critical as its own column (not folded into High)
    host, image = seed()
    image.status_trivy = {"Results": [{"Vulnerabilities": [
        {"Severity": "CRITICAL"}, {"Severity": "HIGH"}]}]}
    image.save()
    html = client.get(f"/hosts/{host.id}").data.decode()
    assert 'title="Critical">1<' in html
    assert 'title="High">1<' in html


def test_logout_clears_session(client):
    with client.session_transaction() as sess:
        sess["user"] = {"email": "user@example.com"}
    r = client.get("/logout")
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_csrf_rejects_post_without_token(monkeypatch, tmp_path):
    # The default fixtures disable CSRF for convenience; build a CSRF-enabled app
    # and confirm a form POST without a token is rejected (Flask-WTF -> 400).
    for var in ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SECRET_KEY", "test")
    from app import create_app
    from extensions import db
    from config import Config

    class _Cfg(Config):
        WTF_CSRF_ENABLED = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'csrf.db'}"

    app = create_app(_Cfg)
    with app.app_context():
        db.create_all()
    r = app.test_client().post("/hosts/save",
                               data={"name": "n", "address": "http://x", "token": "t"})
    assert r.status_code == 400
    with app.app_context():
        assert Host.query.count() == 0
