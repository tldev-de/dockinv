"""§2 – Unit tests for the Trivy/Xeol JSON parsing helpers (no DB required)."""
import json
import os
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

from routes import frontend
from util import (parse_trivy_to_str, parse_xeol_to_str, generate_random_string,
                  cycle_is_eol, humanize_age, is_stale)

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


def xeol_with(eol, product="Redis", cycle="7.4", version="7.4.12"):
    """A single-match xeol result whose cycle carries the given ``Eol`` value."""
    return {"matches": [{"Cycle": {"ProductName": product, "ReleaseCycle": cycle,
                                   "ReleaseDate": "2024-07-01", "Eol": eol},
                         "artifact": {"name": product.lower(), "version": version}}]}


class TestCountTrivyFindingsImage:
    def test_counts_crit_high_medium_low(self):
        f = frontend.count_trivy_findings_image(img(trivy=TRIVY))
        assert (f.critical, f.high, f.medium, f.low) == (1, 1, 1, 2)  # CRITICAL kept separate

    def test_none_when_no_status(self):
        assert frontend.count_trivy_findings_image(img(trivy=None)) is None
        assert frontend.count_trivy_findings_image(None) is None

    def test_empty_results(self):
        f = frontend.count_trivy_findings_image(img(trivy={"Results": []}))
        assert (f.critical, f.high, f.medium, f.low) == (0, 0, 0, 0)

    def test_result_without_vulnerabilities(self):
        f = frontend.count_trivy_findings_image(img(trivy={"Results": [{"Target": "x"}]}))
        assert (f.critical, f.high, f.medium, f.low) == (0, 0, 0, 0)

    def test_missing_results_key_tolerated(self):
        # Trivy omits "Results" when it can't analyze an image; count as zero, don't crash.
        f = frontend.count_trivy_findings_image(img(trivy={"foo": "bar"}))
        assert (f.critical, f.high, f.medium, f.low) == (0, 0, 0, 0)


class TestCycleIsEol:
    def test_past_date_is_eol(self):
        assert cycle_is_eol({"Eol": "2000-01-01"}) is True

    def test_future_date_not_eol(self):
        # a known EOL date still in the future is NOT end-of-life yet
        assert cycle_is_eol({"Eol": "2999-12-31"}) is False

    def test_boundary_today_is_eol(self):
        assert cycle_is_eol({"Eol": "2026-06-15"}, today=date(2026, 6, 15)) is True

    def test_boolean_true_and_false(self):
        assert cycle_is_eol({"Eol": True}) is True
        assert cycle_is_eol({"Eol": False}) is False

    def test_missing_key_or_malformed_or_none(self):
        assert cycle_is_eol({"ProductName": "x"}) is False
        assert cycle_is_eol({"Eol": "not-a-date"}) is False
        assert cycle_is_eol(None) is False


class TestIsImageEol:
    def test_true_when_eol_present(self):
        assert frontend.is_image_eol(img(xeol=XEOL)) is True  # fixture EOL 2022-09-10 (past)

    def test_false_when_eol_date_in_future(self):
        # regression: Redis 7.4 (EOL 2026-11-30) must not be flagged before the date
        assert frontend.is_image_eol(img(xeol=xeol_with("2999-12-31"))) is False

    def test_true_when_eol_date_in_past(self):
        assert frontend.is_image_eol(img(xeol=xeol_with("2000-01-01"))) is True

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
        assert (f.critical, f.high, f.medium, f.low) == (1, 1, 1, 2)

    def test_count_trivy_findings_sums_distinct_images(self):
        f = frontend.count_trivy_findings(host_with(img(image_id=1, trivy=TRIVY),
                                                     img(image_id=2, trivy=TRIVY)))
        assert (f.critical, f.high, f.medium, f.low) == (2, 2, 2, 4)

    def test_count_trivy_findings_ignores_images_without_status(self):
        f = frontend.count_trivy_findings(host_with(img(trivy=None)))
        assert (f.critical, f.high, f.medium, f.low) == (0, 0, 0, 0)


class TestTrivySortWeight:
    def test_none_sorts_lowest(self):
        assert frontend.trivy_sort_weight(None) == -1

    def test_composite_value(self):
        assert frontend.trivy_sort_weight(frontend.TrivyFindings(2, 3, 4, 5)) == 2_000_000_000 + 3_000_000 + 4_000 + 5

    def test_one_critical_outranks_many_lower(self):
        one_crit = frontend.trivy_sort_weight(frontend.TrivyFindings(1, 0, 0, 0))
        many_low = frontend.trivy_sort_weight(frontend.TrivyFindings(0, 99, 99, 99))
        assert one_crit > many_low   # severity priority, not raw counts


class TestTransformForDisplay:
    def test_trivy_sorted_by_severity(self):
        out = frontend.transform_trivy_findings_for_display(img(trivy=TRIVY))
        assert [v["Severity"] for v in out] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOW"]

    def test_trivy_none_when_no_status(self):
        assert frontend.transform_trivy_findings_for_display(img(trivy=None)) is None

    def test_trivy_tolerates_missing_results_key(self):
        # Trivy omits "Results" when it can't analyze an image; must not crash the page.
        assert frontend.transform_trivy_findings_for_display(img(trivy={"foo": "bar"})) == []

    def test_xeol_mapping_and_sort(self):
        out = frontend.transform_xeol_findings_for_display(img(xeol=XEOL))
        assert out[0] == {
            "Name": "Debian",
            "Version": "10",
            "ReleaseDate": "2019-07-06",
            "EolDate": "2022-09-10",
            "IsEol": True,  # past EOL date
        }

    def test_xeol_iseol_flag_reflects_date(self):
        future = frontend.transform_xeol_findings_for_display(img(xeol=xeol_with("2999-12-31")))
        assert future[0]["IsEol"] is False
        past = frontend.transform_xeol_findings_for_display(img(xeol=xeol_with("2000-01-01")))
        assert past[0]["IsEol"] is True

    def test_xeol_none_when_no_status(self):
        assert frontend.transform_xeol_findings_for_display(img(xeol=None)) is None


class TestUtilStringHelpers:
    def test_parse_trivy_to_str_counts(self):
        # CRITICAL is reported separately (same as the web view).
        assert parse_trivy_to_str(TRIVY) == "Critical: 1, High: 1, Medium: 1, Low: 2"

    def test_parse_trivy_to_str_counts_critical_only(self):
        trivy = {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}]}]}
        assert parse_trivy_to_str(trivy) == "Critical: 1, High: 0, Medium: 0, Low: 0"

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

    def test_parse_xeol_to_str_ok_when_only_future_eol(self):
        # a cycle with a future EOL date is reported as OK, not EOL
        assert parse_xeol_to_str(xeol_with("2999-12-31")) == "OK"

    def test_generate_random_string(self):
        s = generate_random_string(32)
        assert len(s) == 32 and s.isalnum()


class TestHumanizeAge:
    NOW = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

    def test_none(self):
        assert humanize_age(None) == "never"

    def test_just_now(self):
        assert humanize_age(self.NOW - timedelta(seconds=10), now=self.NOW) == "just now"

    def test_minutes(self):
        assert humanize_age(self.NOW - timedelta(minutes=5), now=self.NOW) == "5 min ago"

    def test_hours(self):
        assert humanize_age(self.NOW - timedelta(hours=3), now=self.NOW) == "3 h ago"

    def test_days(self):
        assert humanize_age(self.NOW - timedelta(days=2), now=self.NOW) == "2 d ago"

    def test_naive_timestamp_treated_as_utc(self):
        naive = (self.NOW - timedelta(minutes=10)).replace(tzinfo=None)
        assert humanize_age(naive, now=self.NOW) == "10 min ago"

    def test_future_clamps_to_just_now(self):
        assert humanize_age(self.NOW + timedelta(minutes=5), now=self.NOW) == "just now"


class TestIsStale:
    NOW = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

    def test_none_is_stale(self):
        assert is_stale(None, 45) is True

    def test_recent_not_stale(self):
        assert is_stale(self.NOW - timedelta(minutes=10), 45, now=self.NOW) is False

    def test_old_is_stale(self):
        assert is_stale(self.NOW - timedelta(minutes=60), 45, now=self.NOW) is True

    def test_naive_treated_as_utc(self):
        naive = (self.NOW - timedelta(minutes=60)).replace(tzinfo=None)
        assert is_stale(naive, 45, now=self.NOW) is True
