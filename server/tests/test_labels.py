"""Unit tests for Docker/Traefik label extraction (labels.py)."""
import pytest

from labels import extract_stack, extract_hostnames


class TestStack:
    def test_present(self):
        assert extract_stack({"com.docker.compose.project": "myapp"}) == "myapp"

    def test_absent(self):
        assert extract_stack({"other": "x"}) is None

    def test_empty_and_none(self):
        assert extract_stack({}) is None
        assert extract_stack(None) is None


class TestHostnames:
    def test_single_host(self):
        assert extract_hostnames({"traefik.http.routers.web.rule": "Host(`example.com`)"}) == ["example.com"]

    def test_multiple_hosts_in_one_rule(self):
        assert extract_hostnames(
            {"traefik.http.routers.web.rule": "Host(`a.com`, `b.com`)"}) == ["a.com", "b.com"]

    def test_or_combination(self):
        assert extract_hostnames(
            {"traefik.http.routers.web.rule": "Host(`a.com`) || Host(`b.com`)"}) == ["a.com", "b.com"]

    def test_with_pathprefix(self):
        assert extract_hostnames(
            {"traefik.http.routers.api.rule": "Host(`api.com`) && PathPrefix(`/v1`)"}) == ["api.com"]

    def test_multiple_routers_deduped_and_sorted(self):
        labels = {
            "traefik.http.routers.a.rule": "Host(`y.com`)",
            "traefik.http.routers.b.rule": "Host(`y.com`) || Host(`x.com`)",
        }
        assert extract_hostnames(labels) == ["x.com", "y.com"]

    @pytest.mark.parametrize("labels", [{}, None, {"traefik.enable": "true"},
                                        {"traefik.http.routers.web.rule": "PathPrefix(`/x`)"}])
    def test_no_hostnames(self, labels):
        assert extract_hostnames(labels) == []
