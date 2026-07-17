"""Config validation: every shipped config must pass, malformed ones must fail."""
import glob
import os

import pytest
from pydantic import ValidationError

from mulitaminer.configs.schemas import LLMConfig, ScannerConfig
from mulitaminer.llm.config_loader import load_llm, load_profile

_LLM_NAMES = sorted(
    os.path.splitext(os.path.basename(f))[0]
    for f in glob.glob("src/mulitaminer/configs/llms/*.json")
)
_SCANNER_NAMES = sorted(
    os.path.splitext(os.path.basename(f))[0]
    for f in glob.glob("src/mulitaminer/configs/scanners/*.json")
)


@pytest.mark.parametrize("name", _LLM_NAMES)
def test_every_shipped_llm_config_validates(name):
    cfg = load_llm(name)
    assert cfg is not None
    LLMConfig.model_validate(cfg)  # raises if invalid


@pytest.mark.parametrize("name", _SCANNER_NAMES)
def test_every_shipped_scanner_config_validates(name):
    cfg = load_profile(name)
    assert cfg is not None
    ScannerConfig.model_validate(cfg)  # raises if invalid


def test_llm_config_requires_model():
    with pytest.raises(ValidationError):
        LLMConfig.model_validate({"provider": "openai"})  # no 'model'


def test_llm_config_rejects_wrong_type():
    with pytest.raises(ValidationError):
        LLMConfig.model_validate({"model": "x", "max_tokens": "not-an-int"})


def test_llm_config_allows_extra_fields():
    cfg = LLMConfig.model_validate({"model": "x", "some_future_field": 123})
    assert cfg.model == "x"


def test_scanner_config_requires_prompt_template():
    with pytest.raises(ValidationError):
        ScannerConfig.model_validate({"reader": "openvas"})  # no prompt_template


def test_load_llm_unknown_returns_none():
    assert load_llm("definitely_not_a_real_llm") is None
