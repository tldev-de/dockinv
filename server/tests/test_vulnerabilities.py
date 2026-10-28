"""Vulnerability projection: extraction, atomic sync, drift detection, routes, CLI."""
from datetime import datetime, timezone

import vulnerabilities as vuln_service
from extensions import db
from models import Host, Image, Container, Vulnerability


# --- builders --------------------------------------------------------------

def make_host(name="h1"):
    h = Host(name=name, address=f"http://{name}/", enabled=True, token="t")
    h.save()
    return h


def make_image_with_container(host, name="nginx", digest=None, cname=None):
    img = Image(name=name, repo_digest=digest or f"{name}@sha256:{host.id}")
    img.save()
    Container(host_id=host.id, name=cname or f"c-{name}", image_string=f"{name}:1",
              image_id=img.id, status="running", started_at=datetime.now(timezone.utc)).save()
    return img


def vuln(cve, severity="HIGH", v3=9.2, pkg="libfoo", installed="1.0", fixed="1.1",
         title=None, cwes=None):
    d = {"VulnerabilityID": cve, "Severity": severity, "PkgName": pkg,
         "InstalledVersion": installed, "FixedVersion": fixed, "PrimaryURL": f"https://x/{cve}"}
    if v3 is not None:
        d["CVSS"] = {"nvd": {"V3Score": v3}}
    if title is not None:
        d["Title"] = title
    if cwes is not None:
        d["CweIDs"] = cwes
    return d


def trivy_blob(*vulns):
    return {"Results": [{"Target": "os", "Vulnerabilities": list(vulns)}]}


# --- extraction ------------------------------------------------------------

class TestExtraction:
    def test_cvss_prefers_v3(self):
        assert vuln_service._cvss_score({"CVSS": {"nvd": {"V2Score": 7.5, "V3Score": 9.2}}}) == 9.2

    def test_cvss_v2_fallback(self):
        assert vuln_service._cvss_score({"CVSS": {"nvd": {"V2Score": 7.5}}}) == 7.5

    def test_cvss_max_across_sources(self):
        assert vuln_service._cvss_score({"CVSS": {"nvd": {"V3Score": 8.1}, "redhat": {"V3Score": 9.2}}}) == 9.2

    def test_cvss_none(self):
        assert vuln_service._cvss_score({}) is None

    def test_extract_dedups_identical(self):
        rows = vuln_service.extract_vulnerabilities(trivy_blob(vuln("CVE-1"), vuln("CVE-1")))
        assert len(rows) == 1

    def test_extract_ignores_entries_without_id(self):
        blob = {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}
        assert vuln_service.extract_vulnerabilities(blob) == []

    def test_extract_empty(self):
        assert vuln_service.extract_vulnerabilities(None) == []
        assert vuln_service.extract_vulnerabilities({"Results": []}) == []

    def test_extract_flags_rce_by_cwe(self):
        rows = vuln_service.extract_vulnerabilities(trivy_blob(vuln("CVE-RCE", cwes=["CWE-94"])))
        assert rows[0]["is_rce"] is True

    def test_extract_flags_rce_by_title(self):
        rows = vuln_service.extract_vulnerabilities(trivy_blob(
            vuln("CVE-RCE2", title="Allows remote code execution via crafted input")))
        assert rows[0]["is_rce"] is True

    def test_extract_non_rce_is_false(self):
        rows = vuln_service.extract_vulnerabilities(trivy_blob(
            vuln("CVE-DOS", title="Denial of service", cwes=["CWE-400"])))
        assert rows[0]["is_rce"] is False


# --- atomic sync / no drift ------------------------------------------------

class TestSync:
    def test_set_trivy_result_creates_rows_and_json(self, app):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-2026-109618", v3=9.2)))
        assert img.status_trivy is not None
        rows = Vulnerability.query.filter_by(image_id=img.id).all()
        assert len(rows) == 1
        assert rows[0].cve_id == "CVE-2026-109618" and rows[0].score == 9.2
        assert vuln_service.find_drift() == []

    def test_set_trivy_result_replaces_previous(self, app):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-A"), vuln("CVE-B", pkg="bar")))
        assert Vulnerability.query.count() == 2
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-C")))
        cves = {v.cve_id for v in Vulnerability.query.all()}
        assert cves == {"CVE-C"}
        assert vuln_service.find_drift() == []

    def test_empty_result_clears_rows(self, app):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-A")))
        vuln_service.set_trivy_result(img, {"Results": []})
        assert Vulnerability.query.filter_by(image_id=img.id).count() == 0
        assert vuln_service.find_drift() == []

    def test_image_delete_cascades_vulns(self, app):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-A")))
        # remove the container first (so the image is deletable), then the image
        Container.query.filter_by(image_id=img.id).delete()
        db.session.commit()
        img.delete()
        assert Vulnerability.query.count() == 0


class TestDriftDetection:
    def test_no_drift_after_sync(self, app):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-A"), vuln("CVE-B", pkg="bar")))
        assert vuln_service.find_drift() == []

    def test_drift_detected_when_rows_tampered(self, app):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-A")))
        # simulate drift: delete the row directly, leaving the JSON intact
        Vulnerability.query.filter_by(image_id=img.id).delete()
        db.session.commit()
        assert img.id in vuln_service.find_drift()

    def test_drift_from_legacy_json_then_rebuild(self, app):
        img = make_image_with_container(make_host())
        # legacy data: status_trivy written WITHOUT going through set_trivy_result
        img.status_trivy = trivy_blob(vuln("CVE-LEGACY"))
        img.save()
        assert img.id in vuln_service.find_drift()
        vuln_service.rebuild_all()
        assert vuln_service.find_drift() == []


# --- routes ----------------------------------------------------------------

class TestRoutes:
    def _seed_two(self):
        h1, h2 = make_host("h1"), make_host("h2")
        img1 = make_image_with_container(h1, "a", "a@sha256:1", "c-a")
        img2 = make_image_with_container(h2, "b", "b@sha256:2", "c-b")
        vuln_service.set_trivy_result(img1, trivy_blob(
            vuln("CVE-2026-109618", severity="CRITICAL", v3=9.2),
            vuln("CVE-2026-109619", severity="HIGH", v3=9.2, pkg="bar")))
        vuln_service.set_trivy_result(img2, trivy_blob(
            vuln("CVE-2026-109618", severity="CRITICAL", v3=9.2)))
        return img1, img2

    def test_list_aggregates(self, client):
        self._seed_two()
        html = client.get("/vulnerabilities").data.decode()
        assert "CVE-2026-109618" in html and "CVE-2026-109619" in html

    def test_list_empty_state(self, client):
        assert b"No vulnerabilities match" in client.get("/vulnerabilities").data

    def test_list_shows_packages(self, client):
        self._seed_two()
        html = client.get("/vulnerabilities").data.decode()
        assert "libfoo" in html and "bar" in html   # package names listed inline

    def test_filter_controls_present(self, client):
        html = client.get("/vulnerabilities").data.decode()
        assert 'name="cve"' in html and 'name="severity"' in html and 'name="min_cvss"' in html
        assert 'name="fixable"' in html   # "only fixable" toggle
        assert 'hx-get="/vulnerabilities/table"' in html

    def _seed_fixable_and_not(self, suffix="f"):
        host = make_host(f"h{suffix}")
        img = make_image_with_container(host, f"i{suffix}", f"i{suffix}@sha256:7", f"c-{suffix}")
        vuln_service.set_trivy_result(img, trivy_blob(
            vuln("CVE-FIXABLE", severity="HIGH", v3=8.0, pkg="p1", fixed="1.2"),
            vuln("CVE-NOFIX", severity="HIGH", v3=8.0, pkg="p2", fixed="")))
        return img

    def test_list_shows_fix_availability(self, client):
        self._seed_fixable_and_not()
        html = client.get("/vulnerabilities").data.decode()
        assert "✓ fix" in html and "✗ none" in html

    def test_filter_only_fixable(self, client):
        self._seed_fixable_and_not("f2")
        html = client.get("/vulnerabilities?fixable=1").data.decode()
        assert "CVE-FIXABLE" in html
        assert "CVE-NOFIX" not in html   # no fixed version -> hidden

    def test_dashboard_overview_severity_counts(self, app):
        self._seed_two()  # CVE-...618 CRITICAL (2 images), CVE-...619 HIGH
        from routes.frontend import _dashboard_overview
        d = _dashboard_overview()
        assert d['host_total'] == 2
        assert d['severities']['critical'] == 1   # distinct CVEs, not occurrences
        assert d['severities']['high'] == 1
        assert d['eol_total'] == 0

    def test_dashboard_route_renders(self, client):
        self._seed_two()
        html = client.get("/").data.decode()
        assert "/vulnerabilities?severity=CRITICAL" in html
        assert "/vulnerabilities?severity=HIGH" in html

    def _seed_kernel_and_rce(self, suffix="k"):
        host = make_host(f"h{suffix}")
        img = make_image_with_container(host, f"i{suffix}", f"i{suffix}@sha256:5", f"c-{suffix}")
        vuln_service.set_trivy_result(img, trivy_blob(
            vuln("CVE-KERNEL", pkg="linux-libc-dev", severity="HIGH", v3=7.0),
            vuln("CVE-RCE", pkg="libfoo", severity="CRITICAL", v3=9.8, cwes=["CWE-94"]),
            vuln("CVE-PLAIN", pkg="libbar", severity="MEDIUM", v3=5.0)))
        return img

    def test_kernel_noise_hidden_by_default(self, client):
        self._seed_kernel_and_rce()
        html = client.get("/vulnerabilities").data.decode()
        assert "CVE-KERNEL" not in html     # linux-libc-dev dropped
        assert "CVE-RCE" in html

    def test_show_kernel_noise_when_requested(self, client):
        self._seed_kernel_and_rce("k2")
        html = client.get("/vulnerabilities?show_kernel=1").data.decode()
        assert "CVE-KERNEL" in html

    def test_rce_badge_and_only_filter(self, client):
        self._seed_kernel_and_rce("k3")
        html = client.get("/vulnerabilities").data.decode()
        assert 'title="Remote code execution class">RCE<' in html   # badge rendered
        only = client.get("/vulnerabilities?rce=1").data.decode()
        assert "CVE-RCE" in only
        assert "CVE-PLAIN" not in only

    def test_filter_controls_include_kernel_and_rce(self, client):
        html = client.get("/vulnerabilities").data.decode()
        assert 'name="show_kernel"' in html and 'name="rce"' in html

    def test_filter_by_cve(self, client):
        self._seed_two()
        html = client.get("/vulnerabilities?cve=109619").data.decode()
        assert "CVE-2026-109619" in html
        assert "CVE-2026-109618" not in html

    def test_filter_by_min_severity(self, client):
        self._seed_two()
        html = client.get("/vulnerabilities?severity=CRITICAL").data.decode()
        assert "CVE-2026-109618" in html       # CRITICAL
        assert "CVE-2026-109619" not in html   # HIGH -> below the minimum

    def test_filter_by_min_cvss(self, client):
        host = make_host("hc")
        img = make_image_with_container(host, "ci", "ci@sha256:9", "c-ci")
        vuln_service.set_trivy_result(img, trivy_blob(
            vuln("CVE-HIGHSCORE", severity="HIGH", v3=9.5, pkg="p1"),
            vuln("CVE-LOWSCORE", severity="LOW", v3=3.1, pkg="p2")))
        html = client.get("/vulnerabilities?min_cvss=5").data.decode()
        assert "CVE-HIGHSCORE" in html
        assert "CVE-LOWSCORE" not in html

    def test_table_partial_is_filtered(self, client):
        self._seed_two()
        r = client.get("/vulnerabilities/table?cve=109618")
        assert r.status_code == 200
        html = r.data.decode()
        assert "CVE-2026-109618" in html and "CVE-2026-109619" not in html
        assert "<html" not in html   # partial, not a full page

    def test_detail_lists_all_affected_containers(self, client):
        self._seed_two()
        html = client.get("/vulnerabilities/CVE-2026-109618").data.decode()
        assert "c-a" in html and "c-b" in html   # affected across both hosts

    def test_detail_unknown_cve_redirects(self, client):
        r = client.get("/vulnerabilities/CVE-0000-0")
        assert r.status_code == 302 and "/vulnerabilities" in r.headers["Location"]

    def test_image_detail_links_to_vuln_page(self, client):
        img = make_image_with_container(make_host())
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-PIVOT")))
        html = client.get(f"/images/{img.id}").data.decode()
        assert "/vulnerabilities/CVE-PIVOT" in html

    def test_image_without_container_excluded(self, client):
        # an image with the CVE but no container must not appear as "vulnerable"
        img = Image(name="idle", repo_digest="idle@sha256:x")
        img.save()
        vuln_service.set_trivy_result(img, trivy_blob(vuln("CVE-IDLE")))
        assert b"CVE-IDLE" not in client.get("/vulnerabilities").data


# --- CLI -------------------------------------------------------------------

class TestCli:
    def test_verify_ok(self, cli, app):
        vuln_service.set_trivy_result(make_image_with_container(make_host()),
                                      trivy_blob(vuln("CVE-A")))
        res = cli.invoke(args=["vulns", "verify"])
        assert res.exit_code == 0 and "in sync" in res.output

    def test_verify_detects_drift_and_rebuild_repairs(self, cli, app):
        img = make_image_with_container(make_host())
        img.status_trivy = trivy_blob(vuln("CVE-DRIFT"))   # legacy direct write
        img.save()
        res = cli.invoke(args=["vulns", "verify"])
        assert res.exit_code == 1 and "DRIFT" in res.output

        cli.invoke(args=["vulns", "rebuild"])
        assert vuln_service.find_drift() == []
        assert cli.invoke(args=["vulns", "verify"]).exit_code == 0

    def test_ls_runs(self, cli, app):
        vuln_service.set_trivy_result(make_image_with_container(make_host()),
                                      trivy_blob(vuln("CVE-A", v3=9.2)))
        res = cli.invoke(args=["vulns", "ls"])
        assert res.exit_code == 0 and "CVE-A" in res.output
