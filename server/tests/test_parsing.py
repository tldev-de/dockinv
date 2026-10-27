"""§2 – Unit tests for the Trivy/Xeol JSON parsing helpers (no DB required)."""
import json
import os
from types import SimpleNamespace

import pytest

from routes import frontend
from util import parse_trivy_to_str, parse_xeol_to_str, generate_random_string

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


TRIVY = _load("trivy_sample.json")
XEOL = _load("xeol_sample.json")


def img(image_id=1, trivy=None, xeol=None):
    return SimpleNamespace(id=image_id, status_trivy=trivy, status_xeol=xeol)


def host_with(*images):
    return SimpleNamespace(containers=[SimpleNamespace(image=i) for i in images])


class TestCountTrivyFindingsImage:
    def test_counts_crit_high_medium_low(self):
        f = frontend.count_trivy_findings_image(img(trivy=TRIVY))
        assert (f.high, f.medium, f.low) == (2, 1, 2)  # CRITICAL+HIGH -> high

    def test_none_when_no_status(self):
        assert frontend.count_trivy_findings_image(img(trivy=None)) is None
        assert frontend.count_trivy_findings_image(None) is None

    def test_empty_results(self):
        f = frontend.count_trivy_findings_image(img(trivy={"Results": []}))
        assert (f.high, f.medium, f.low) == (0, 0, 0)

    def test_result_without_vulnerabilities(self):
        f = frontend.count_trivy_findings_image(img(trivy={"Results": [{"Target": "x"}]}))
        assert (f.high, f.medium, f.low) == (0, 0, 0)


class TestIsImageEol:
    def test_true_when_eol_present(self):
        assert frontend.is_image_eol(img(xeol=XEOL)) is True

    def test_false_when_no_eol_key(self):
        xeol = {"matches": [{"Cycle": {"ProductName": "Debian", "ReleaseCycle": "12"}}]}
        assert frontend.is_image_eol(img(xeol=xeol)) is False

    def test_none_when_no_status(self):
        assert frontend.is_image_eol(img(xeol=None)) is None
        assert frontend.is_image_eol(None) is None


class TestHostAggregation:
    def test_count_eol_images_dedups_per_image_id(self):
        shared = img(image_id=7, xeol=XEOL)
        # same image in two containers must be counted once
        assert frontend.count_eol_images(host_with(shared, shared)) == 1

    def test_count_trivy_findings_dedups_per_image(self):
        # a shared image across two containers is counted once (fixed to match
        # count_eol_images' dedup behaviour)
        shared = img(trivy=TRIVY)
        f = frontend.count_trivy_findings(host_with(shared, shared))
        assert (f.high, f.medium, f.low) == (2, 1, 2)

    def test_count_trivy_findings_sums_distinct_images(self):
        f = frontend.count_trivy_findings(host_with(img(image_id=1, trivy=TRIVY),
                                                     img(image_id=2, trivy=TRIVY)))
        assert (f.high, f.medium, f.low) == (4, 2, 4)

    def test_count_trivy_findings_ignores_images_without_status(self):
        f = frontend.count_trivy_findings(host_with(img(trivy=None)))
        assert (f.high, f.medium, f.low) == (0, 0, 0)


class TestTransformForDisplay:
    def test_trivy_sorted_by_severity(self):
        out = frontend.transform_trivy_findings_for_display(img(trivy=TRIVY))
        assert [v["Severity"] for v in out] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOW"]

    def test_trivy_none_when_no_status(self):
        assert frontend.transform_trivy_findings_for_display(img(trivy=None)) is None

    def test_trivy_raises_keyerror_without_results_key(self):
        # Documents the hard status_trivy["Results"] access.
        with pytest.raises(KeyError):
            frontend.transform_trivy_findings_for_display(img(trivy={"foo": "bar"}))

    def test_xeol_mapping_and_sort(self):
        out = frontend.transform_xeol_findings_for_display(img(xeol=XEOL))
        assert out[0] == {
            "Name": "Debian",
            "Version": "10",
            "ReleaseDate": "2019-07-06",
            "EolDate": "2022-09-10",
        }

    def test_xeol_none_when_no_status(self):
        assert frontend.transform_xeol_findings_for_display(img(xeol=None)) is None


class TestUtilStringHelpers:
    def test_parse_trivy_to_str_counts(self):
        # CRITICAL is folded into "High" (same as the web view).
        assert parse_trivy_to_str(TRIVY) == "High: 2, Medium: 1, Low: 2"

    def test_parse_trivy_to_str_counts_critical_only(self):
        trivy = {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}]}]}
        assert parse_trivy_to_str(trivy) == "High: 1, Medium: 0, Low: 0"

    def test_parse_trivy_to_str_na(self):
        assert parse_trivy_to_str(None) == "n/a"

    def test_parse_trivy_to_str_ok(self):
        assert parse_trivy_to_str({"Results": []}) == "OK"

    def test_parse_xeol_to_str_line(self):
        assert parse_xeol_to_str(XEOL) == "Debian 10 (EOL 2022-09-10)"

    def test_parse_xeol_to_str_na(self):
        assert parse_xeol_to_str(None) == "n/a"

    def test_parse_xeol_to_str_ok(self):
        assert parse_xeol_to_str({"matches": []}) == "OK"

    def test_generate_random_string(self):
        s = generate_random_string(32)
        assert len(s) == 32 and s.isalnum()
