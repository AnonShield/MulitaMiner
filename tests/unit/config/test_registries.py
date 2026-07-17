"""One Open/Closed registry pattern across the three extension axes.

Scanners, LLM providers, and output converters all self-register by decorator
(replacing a hand-maintained dict, an if/elif provider chain, and an if/elif
converter chain respectively — §3 of the tech-debt analysis). Adding one is a
new file + a decorator, never an edit to the dispatch.
"""
import types

import pytest

from mulitaminer.llm.llm_factory import init_llm
from mulitaminer.llm.providers import (
    OpenAIProvider,
    get_provider_factory,
    registered_providers,
)
from mulitaminer.scanners.openvas import OpenVASStrategy
from mulitaminer.scanners.registry import get_strategy
from mulitaminer.scanners.tenablewas import TenableWASStrategy
from mulitaminer.writers.base_converter import available_formats, get_converter_factory
import mulitaminer.writers.conversions  # noqa: F401 — triggers converter registration


# --- Scanners ---------------------------------------------------------------

def test_scanner_strategies_self_registered():
    assert isinstance(get_strategy("openvas"), OpenVASStrategy)
    assert isinstance(get_strategy("tenable"), TenableWASStrategy)


# --- Providers --------------------------------------------------------------

def test_all_builtin_providers_registered():
    for name in ("openai", "ollama", "huggingface", "hf", "lm_studio"):
        assert get_provider_factory(name) is not None
    assert set(registered_providers()) >= {"openai", "ollama", "huggingface", "hf", "lm_studio"}


def test_init_llm_resolves_via_registry():
    provider = init_llm({
        "provider": "openai", "model": "gpt-4o-mini",
        "api_key": "x", "endpoint": "https://api.openai.com/v1",
    })
    assert isinstance(provider, OpenAIProvider)


def test_init_llm_unknown_provider_lists_registered():
    with pytest.raises(ValueError, match="Registered providers"):
        init_llm({"provider": "definitely-not-a-provider"})


# --- Converters -------------------------------------------------------------

def test_converter_formats_registered():
    assert set(available_formats()) == {"csv", "tsv", "xlsx"}


def test_converter_factory_builds_from_args():
    args = types.SimpleNamespace(csv_delimiter=";", csv_encoding="utf-8")
    csv_conv = get_converter_factory("csv")(args)
    assert csv_conv.delimiter == ";"
    tsv_conv = get_converter_factory("tsv")(args)
    assert tsv_conv.delimiter == "\t"
