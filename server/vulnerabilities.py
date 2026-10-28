"""Keep the ``Vulnerability`` table a drift-free projection of ``Image.status_trivy``.

``Image.status_trivy`` (the raw Trivy JSON) is the single source of truth. The
``vulnerability`` table is a materialized index derived from it. To make drift
impossible:

* ``set_trivy_result`` is the ONLY supported way to write a scan result — it
  updates the JSON and rebuilds the rows in a single transaction.
* ``rebuild_all`` re-derives everything from the JSON (backfill / repair).
* ``find_drift`` compares the table against a fresh derivation and reports any
  image whose rows disagree (used by ``flask vulns verify``).
"""
from extensions import db
from models import Image, Vulnerability


# Remote code execution: an attacker runs code over the network. Flagged only when
# BOTH hold, so the heuristic stays precise instead of over-counting:
#   * a network attack vector (CVSS AV:N) — this rules out local / crafted-file
#     "code execution" (binutils, imagemagick-via-file, m4, …) that is not remotely
#     reachable and was the main source of false positives;
#   * a code-execution CWE, or explicit RCE / command-injection wording.
_RCE_CWES = {"CWE-94", "CWE-95", "CWE-77", "CWE-78", "CWE-502", "CWE-917", "CWE-1336"}
_RCE_PHRASES = ("remote code execution", "arbitrary code execution",
                "command injection", "deserialization of untrusted data")


def _cvss_vectors(v):
    """All CVSS vector strings across sources (V4/V3/V2)."""
    out = []
    for source in (v.get("CVSS") or {}).values():
        if isinstance(source, dict):
            for key in ("V4Vector", "V3Vector", "V2Vector"):
                vec = source.get(key)
                if isinstance(vec, str):
                    out.append(vec)
    return out


def _is_rce(v):
    if not any("AV:N" in vec for vec in _cvss_vectors(v)):
        return False  # not network-reachable -> not a remote RCE for triage
    if any(c in _RCE_CWES for c in (v.get("CweIDs") or [])):
        return True
    text = f"{v.get('Title', '')} {v.get('Description', '')}".lower()
    return any(p in text for p in _RCE_PHRASES)


def _cvss_score(vuln):
    """Pick a representative CVSS score: highest V4/V3 across sources, else V2."""
    cvss = vuln.get("CVSS") or {}
    v3 = [s[k] for s in cvss.values() if isinstance(s, dict)
          for k in ("V4Score", "V3Score") if isinstance(s.get(k), (int, float))]
    if v3:
        return float(max(v3))
    v2 = [s["V2Score"] for s in cvss.values()
          if isinstance(s, dict) and isinstance(s.get("V2Score"), (int, float))]
    return float(max(v2)) if v2 else None


def extract_vulnerabilities(status_trivy):
    """Derive normalized, de-duplicated vulnerability rows from a Trivy JSON blob."""
    if not status_trivy:
        return []
    seen = set()
    rows = []
    for result in status_trivy.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            cve = v.get("VulnerabilityID")
            if not cve:
                continue
            row = {
                "cve_id": cve,
                "severity": v.get("Severity"),
                "score": _cvss_score(v),
                "pkg_name": v.get("PkgName"),
                "installed_version": v.get("InstalledVersion"),
                "fixed_version": v.get("FixedVersion"),
                "primary_url": v.get("PrimaryURL"),
                "is_rce": _is_rce(v),
            }
            key = _key(row)
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    return rows


def _key(row):
    """Identity of a vulnerability row for drift comparison (ignores primary_url)."""
    return (row["cve_id"], row["severity"], row["score"],
            row["pkg_name"], row["installed_version"], row["fixed_version"])


def _replace_rows(image, status_trivy):
    """Stage a full replacement of the image's vuln rows (NO commit — caller commits)."""
    Vulnerability.query.filter_by(image_id=image.id).delete(synchronize_session=False)
    for row in extract_vulnerabilities(status_trivy):
        db.session.add(Vulnerability(image_id=image.id, **row))


def set_trivy_result(image, result_json):
    """Atomically store a Trivy result AND rebuild its vuln rows (one transaction).

    This is the single writer of ``status_trivy`` so the table can never drift.
    """
    image.status_trivy = result_json
    db.session.add(image)
    _replace_rows(image, result_json)
    db.session.commit()


def sync_image(image):
    """Rebuild one image's vuln rows from its current ``status_trivy`` and commit."""
    _replace_rows(image, image.status_trivy)
    db.session.commit()


def rebuild_all():
    """Re-derive every image's vuln rows from its JSON (backfill/repair). Returns count."""
    images = Image.query.all()
    for image in images:
        _replace_rows(image, image.status_trivy)
    db.session.commit()
    return len(images)


def find_drift():
    """Return the ids of images whose stored rows disagree with a fresh derivation."""
    drifted = []
    for image in Image.query.all():
        expected = {_key(r) for r in extract_vulnerabilities(image.status_trivy)}
        actual = {(v.cve_id, v.severity, v.score, v.pkg_name,
                   v.installed_version, v.fixed_version) for v in image.vulnerabilities}
        if expected != actual:
            drifted.append(image.id)
    return drifted
