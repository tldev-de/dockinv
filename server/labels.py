"""Extract useful info from Docker container labels (collected by the agent).

Currently: the Compose stack name and the hostnames a service is exposed under
via Traefik router rules (``Host(`a.example`)`` / ``Host(`a`) || Host(`b`)`` /
``Host(`a`, `b`)``).
"""
import re

_HOST_RE = re.compile(r'Host\(([^)]*)\)')
_BACKTICK_RE = re.compile(r'`([^`]+)`')


def extract_stack(labels):
    """Return the Docker Compose project (stack) name, or None."""
    return (labels or {}).get('com.docker.compose.project') or None


def extract_hostnames(labels):
    """Return the sorted, de-duplicated hostnames from Traefik router rules."""
    hosts = set()
    for key, value in (labels or {}).items():
        if key.startswith('traefik.') and key.endswith('.rule') and value:
            for inner in _HOST_RE.findall(value):
                hosts.update(_BACKTICK_RE.findall(inner))
    return sorted(hosts)
