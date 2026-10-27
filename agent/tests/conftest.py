"""Agent test fixtures.

A token must exist before ``agent`` is imported, otherwise the module refuses to
start (that refusal is itself tested separately via a subprocess).
"""
import os

os.environ.setdefault("HTTP_TOKEN", "testtoken")

import pytest

import agent as agent_module

TOKEN = "testtoken"


@pytest.fixture
def agent_app():
    agent_module.app.config.update(TESTING=True)
    return agent_module.app


@pytest.fixture
def client(agent_app):
    return agent_app.test_client()
