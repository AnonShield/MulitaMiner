import pytest
import tiktoken

from mulitaminer.chunking import (
    TokenChunk,
    build_prompt,
    detect_scanner_pattern,
    get_token_based_chunks,
    smart_chunk_vulnerabilities,
    split_text_to_subchunks,
)
from mulitaminer.chunking.errors import _is_fatal_api_error
from mulitaminer.chunking.retry import _detect_underextraction, _is_empty_response


@pytest.fixture
def tok():
    return tiktoken.get_encoding("cl100k_base")


def test_get_token_based_chunks_splits_long_text(tok):
    chunks = get_token_based_chunks("word " * 600, max_tokens=200,
                                    reserve_for_response=50, tokenizer=tok)
    assert len(chunks) > 1
    assert all(isinstance(c, TokenChunk) for c in chunks)


def test_get_token_based_chunks_small_text_single(tok):
    chunks = get_token_based_chunks("short", max_tokens=1000,
                                    reserve_for_response=100, tokenizer=tok)
    assert len(chunks) == 1


def test_detect_scanner_pattern_openvas():
    assert detect_scanner_pattern("NVT: Foo\n")["scanner_type"] == "openvas"


def test_detect_scanner_pattern_tenable():
    info = detect_scanner_pattern("VULNERABILITY HIGH PLUGIN ID 12345\n")
    assert info["scanner_type"] == "tenable_was"


def test_detect_scanner_pattern_unknown():
    assert detect_scanner_pattern("just some random text")["scanner_type"] == "unknown"


def test_smart_chunk_groups_by_marker(tok):
    text = "".join(f"NVT: V{i}\nbody line {i}\n" for i in range(6))
    chunks = smart_chunk_vulnerabilities(text, r"^NVT:", max_tokens=1000,
                                         reserve_for_response=200,
                                         max_vulnerabilities_per_chunk=2, tokenizer=tok)
    assert len(chunks) == 3  # 6 markers, max 2/chunk


def test_smart_chunk_no_marker_falls_back(tok):
    chunks = smart_chunk_vulnerabilities("plain text, no markers here", "",
                                         max_tokens=1000, reserve_for_response=200,
                                         max_vulnerabilities_per_chunk=3, tokenizer=tok)
    assert len(chunks) >= 1


def test_split_text_under_target_returns_single():
    assert split_text_to_subchunks("small", 1000) == ["small"]


def test_build_prompt_embeds_content(openvas_profile):
    prompt = build_prompt(TokenChunk("NVT: hello"), openvas_profile)
    assert "<report_content>" in prompt
    assert "NVT: hello" in prompt


@pytest.mark.parametrize("content,expected", [
    ("[]", True),
    ("[ ]", True),
    ("", True),
    (None, True),
    ('[{"a": 1}]', False),
])
def test_is_empty_response(content, expected):
    assert _is_empty_response(content) is expected


def test_detect_underextraction_true_when_too_few():
    profile = {"chunking": {"marker_pattern": r"^NVT:"}}
    text = "NVT: a\nNVT: b\nNVT: c\nNVT: d\n"  # 4 markers
    assert _detect_underextraction(text, 1, profile) is True  # 1*2 < 4


def test_detect_underextraction_false_when_enough():
    profile = {"chunking": {"marker_pattern": r"^NVT:"}}
    text = "NVT: a\nNVT: b\n"  # 2 markers
    assert _detect_underextraction(text, 2, profile) is False


def test_detect_underextraction_no_profile():
    assert _detect_underextraction("anything", 0, None) is False


@pytest.mark.parametrize("exc,fatal", [
    (Exception("insufficient_quota"), True),
    (Exception("Rate limit exceeded"), True),
    (Exception("HTTP 429 Too Many Requests"), True),
    (Exception("permission denied"), True),
    (ValueError("some ordinary parse bug"), False),
])
def test_is_fatal_api_error(exc, fatal):
    assert _is_fatal_api_error(exc) is fatal
