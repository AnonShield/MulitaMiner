from mulitaminer.chunking.processing import extract_response_content
from mulitaminer.llm import load_profile


def test_load_openvas_profile():
    prof = load_profile("openvas")
    assert prof is not None
    assert "prompt_template" in prof


def test_load_unknown_profile_returns_none():
    assert load_profile("definitely_not_a_real_profile") is None


def test_mock_llm_invoke_roundtrips(mock_llm):
    response = mock_llm.invoke("a prompt")
    content = extract_response_content(response)
    assert "Example" in content
    assert mock_llm.calls == ["a prompt"]
