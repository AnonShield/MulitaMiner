"""Shared fixtures. MockLLM lets pipeline tests run without a real (paid) LLM."""
import json

import pytest


class _FakeResponse:
    """Minimal stand-in for a LangChain AIMessage (has ``.content``)."""
    def __init__(self, content):
        self.content = content


class MockLLM:
    """Stand-in for an initialized LLM: ``invoke(prompt)`` returns a fixed
    response and records the prompts it was called with."""
    def __init__(self, content="[]"):
        self.content = content
        self.calls = []

    def invoke(self, prompt):
        self.calls.append(prompt)
        return _FakeResponse(self.content)


@pytest.fixture
def mock_llm():
    return MockLLM(content=json.dumps([{"Name": "Example", "description": ["a finding"]}]))


@pytest.fixture
def openvas_profile():
    from mulitaminer.llm import load_profile
    return load_profile("openvas")
