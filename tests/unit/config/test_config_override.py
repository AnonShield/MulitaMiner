"""MULITA_CONFIG_DIR lets a user add/override LLM & scanner JSONs from outside
the package (e.g. a mounted dir in Docker), without touching the shipped configs."""
import json

from mulitaminer.llm.config_loader import load_llm, load_profile


def _write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_override_dir_adds_new_llm(tmp_path, monkeypatch):
    _write(tmp_path / "llms" / "mycustom.json", {"model": "custom-x", "provider": "openai"})
    monkeypatch.setenv("MULITA_CONFIG_DIR", str(tmp_path))
    cfg = load_llm("mycustom")
    assert cfg is not None
    assert cfg["model"] == "custom-x"


def test_override_dir_shadows_shipped_llm(tmp_path, monkeypatch):
    _write(tmp_path / "llms" / "gpt4.json", {"model": "shadowed-model", "provider": "openai"})
    monkeypatch.setenv("MULITA_CONFIG_DIR", str(tmp_path))
    assert load_llm("gpt4")["model"] == "shadowed-model"


def test_override_dir_falls_back_to_package(tmp_path, monkeypatch):
    # Override set but empty → a shipped name still resolves from the package.
    monkeypatch.setenv("MULITA_CONFIG_DIR", str(tmp_path))
    assert load_llm("gpt4") is not None  # packaged gpt4.json


def test_override_dir_adds_new_scanner(tmp_path, monkeypatch):
    _write(tmp_path / "scanners" / "myscanner.json",
           {"reader": "openvas", "prompt_template": "configs/prompts/openvas_prompt.txt"})
    monkeypatch.setenv("MULITA_CONFIG_DIR", str(tmp_path))
    cfg = load_profile("myscanner")
    assert cfg is not None
    assert cfg["reader"] == "openvas"


def test_no_override_uses_package(monkeypatch):
    monkeypatch.delenv("MULITA_CONFIG_DIR", raising=False)
    assert load_llm("gpt4") is not None
