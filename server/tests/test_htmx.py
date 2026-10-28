"""HTMX partials, on-demand collect trigger, and security headers."""
from datetime import datetime, timezone
from unittest.mock import MagicMock

import tasks
from models import Host, Image, Container


def seed_host():
    host = Host(name="h1", address="http://a/", enabled=True, token="t")
    host.save()
    image = Image(name="nginx", repo_digest="nginx@sha256:a")
    image.save()
    Container(host_id=host.id, name="c1", image_string="nginx:1",
              image_id=image.id, status="running",
              started_at=datetime.now(timezone.utc)).save()
    return host


class TestHtmxWiring:
    def test_page_loads_local_htmx_and_app_js(self, client):
        html = client.get("/hosts").data
        assert b"js/htmx.min.js" in html   # vendored locally, no CDN
        assert b"js/app.js" in html

    def test_collect_button_present(self, client):
        assert b'hx-post="/hosts/collect"' in client.get("/hosts").data

    def test_toast_container_present(self, client):
        assert b'id="toast"' in client.get("/hosts").data   # OOB target for feedback toasts

    def test_rows_use_data_href_not_inline_onclick(self, client):
        seed_host()
        html = client.get("/hosts").data
        assert b"data-href=" in html
        assert b"onclick=" not in html


class TestHostsTablePartial:
    def test_partial_returns_table(self, client):
        seed_host()
        r = client.get("/hosts/table")
        assert r.status_code == 200
        assert b'id="hostTable"' in r.data
        assert b'hx-get="/hosts/table"' in r.data   # keeps polling after swap
        assert b"<html" not in r.data               # partial, not a full page

    def test_partial_empty_state(self, client):
        r = client.get("/hosts/table")
        assert r.status_code == 200
        assert b"No hosts yet" in r.data


class TestCollectTrigger:
    def test_collect_enqueues_and_returns_table_with_toast(self, client, monkeypatch):
        mock = MagicMock()
        monkeypatch.setattr(tasks.data_collector_background_task, "delay", mock)
        r = client.post("/hosts/collect")
        assert r.status_code == 200
        mock.assert_called_once()
        assert b'id="hostTable"' in r.data
        # OOB toast gives immediate feedback and schedules a one-shot refresh
        assert b'id="toast"' in r.data and b'hx-swap-oob="true"' in r.data
        assert b"Collection queued" in r.data
        assert b'hx-get="/hosts/table"' in r.data and b'hx-trigger="load delay:3s"' in r.data

    def test_collect_survives_broker_error(self, client, monkeypatch):
        def boom():
            raise RuntimeError("broker unreachable")
        monkeypatch.setattr(tasks.data_collector_background_task, "delay", boom)
        r = client.post("/hosts/collect")
        assert r.status_code == 200          # error is caught, table still rendered
        assert b'id="hostTable"' in r.data
        assert b"Could not trigger collection" in r.data and b"alert-error" in r.data


class TestScanTrigger:
    def test_images_page_has_scan_button(self, client):
        assert b'hx-post="/images/scan"' in client.get("/images").data

    def test_images_table_partial(self, client):
        r = client.get("/images/table")
        assert r.status_code == 200
        assert b'id="imagesTable"' in r.data
        assert b"<html" not in r.data   # partial, not a full page

    def test_scan_enqueues_trivy_and_xeol_with_toast(self, client, monkeypatch):
        trivy = MagicMock()
        xeol = MagicMock()
        monkeypatch.setattr(tasks.trivy_background_task, "delay", trivy)
        monkeypatch.setattr(tasks.xeol_background_task, "delay", xeol)
        r = client.post("/images/scan")
        assert r.status_code == 200
        trivy.assert_called_once()
        xeol.assert_called_once()
        assert b'id="imagesTable"' in r.data
        assert b'id="toast"' in r.data and b"Scan queued" in r.data
        assert b'hx-get="/images/table"' in r.data

    def test_scan_survives_broker_error(self, client, monkeypatch):
        def boom():
            raise RuntimeError("broker unreachable")
        monkeypatch.setattr(tasks.trivy_background_task, "delay", boom)
        monkeypatch.setattr(tasks.xeol_background_task, "delay", MagicMock())
        r = client.post("/images/scan")
        assert r.status_code == 200
        assert b'id="imagesTable"' in r.data
        assert b"Could not trigger scan" in r.data and b"alert-error" in r.data

    def test_image_detail_has_rescan_button(self, client):
        seed_host()
        image_id = Image.query.first().id
        html = client.get(f"/images/{image_id}").data
        assert f'hx-post="/images/{image_id}/scan"'.encode() in html
        assert b"Rescan now" in html

    def test_rescan_single_image_enqueues_with_toast(self, client, monkeypatch):
        seed_host()
        image_id = Image.query.first().id
        mock = MagicMock()
        monkeypatch.setattr(tasks.rescan_image_task, "delay", mock)
        r = client.post(f"/images/{image_id}/scan")
        assert r.status_code == 200
        mock.assert_called_once_with(image_id)
        assert b'id="toast"' in r.data and b"Rescan queued" in r.data

    def test_rescan_unknown_image_returns_error_toast(self, client):
        r = client.post("/images/9999/scan")
        assert r.status_code == 200
        assert b"alert-error" in r.data


class TestSecurityHeaders:
    def test_csp_and_nosniff_present(self, client):
        r = client.get("/hosts")
        csp = r.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert r.headers["X-Content-Type-Options"] == "nosniff"
