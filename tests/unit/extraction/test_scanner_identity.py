"""Scanner identity flows from the --scanner parameter; guessing is fallback.

Regression tests for §2 of the tech-debt analysis: identity used to be
re-derived in four independent places (PDF filename sniffing, body regex,
first record's `source`, path re-checks), each able to silently override an
explicitly informed --scanner.
"""

from mulitaminer.chunking.tokens import detect_scanner_pattern
from mulitaminer.readers.pdf_loader import _resolve_scanner
from mulitaminer.scanners.consolidation import central_custom_allow_duplicates
from mulitaminer.scanners.openvas import OpenVASStrategy
from mulitaminer.scanners.registry import get_strategy
from mulitaminer.scanners.tenablewas import TenableWASStrategy


# --- _resolve_scanner: parameter is authoritative, sniffing is fallback -----

def test_explicit_scanner_beats_conflicting_filename():
    # A PDF named "tenable_report.pdf" processed with --scanner openvas is
    # OpenVAS. The old code sniffed the filename and silently flipped it.
    assert _resolve_scanner("tenable_report.pdf", scanner="openvas") == "openvas"


def test_explicit_scanner_works_with_neutral_filename():
    # The original failure mode: a PDF not named "*openvas*" lost the
    # summary/body split even with --scanner openvas explicitly given.
    assert _resolve_scanner("report_2026.pdf", scanner="openvas") == "openvas"
    assert _resolve_scanner("report_2026.pdf", scanner="cais_openvas") == "openvas"
    assert _resolve_scanner("report_2026.pdf", scanner="tenable") == "tenable"


def test_default_profile_falls_back_to_filename(capsys):
    assert _resolve_scanner("scan_openvas_v1.pdf", scanner="default") == "openvas"
    assert "[WARN]" in capsys.readouterr().out  # sniffing announces itself


def test_unknown_scanner_does_not_sniff():
    # Identity was informed; a family we don't know gets generic handling,
    # never a filename guess.
    assert _resolve_scanner("something_openvas.pdf", scanner="nexpose") is None
    assert _resolve_scanner("plain.pdf", scanner=None) is None


# --- get_strategy: family aliases resolve -----------------------------------

def test_strategy_resolves_llm_stamped_source():
    # Records stamp source='TENABLEWAS' but the registry key is 'tenable';
    # the old exact-match lookup silently returned None for every Tenable run.
    assert isinstance(get_strategy("TENABLEWAS"), TenableWASStrategy)
    assert isinstance(get_strategy("OPENVAS"), OpenVASStrategy)
    assert isinstance(get_strategy("cais_openvas"), OpenVASStrategy)
    assert get_strategy("nexpose") is None
    assert get_strategy(None) is None


# --- detect_scanner_pattern: informed identity is never contradicted --------

def test_chunking_detection_respects_informed_reader():
    tenable_text = "VULNERABILITY HIGH PLUGIN ID 12345\ndetails\n"
    # No identity informed: content detection is allowed (legacy behavior).
    assert detect_scanner_pattern(tenable_text)["scanner_type"] == "tenable_was"
    # Identity says openvas: the text's Tenable fingerprint must NOT flip it.
    info = detect_scanner_pattern(tenable_text, {"reader": "openvas"})
    assert info["scanner_type"] == "unknown"


def test_chunking_detection_confirms_informed_reader():
    openvas_text = "NVT: Some Finding\ndetails\n"
    info = detect_scanner_pattern(openvas_text, {"reader": "openvas"})
    assert info["scanner_type"] == "openvas"


# --- consolidation: profile reader preferred over first record's source -----

def test_consolidation_prefers_profile_reader(tmp_path):
    # Two Tenable records, same (Name, plugin): the Tenable custom merge
    # combines their instances. Dispatch comes from the profile's reader even
    # though the records carry the raw LLM-stamped source.
    vulns = [
        {"Name": "XSS", "description": ["d1"], "plugin": 42,
         "instances": [{"instance": "https://a"}], "source": "TENABLEWAS"},
        {"Name": "XSS", "description": ["d2"], "plugin": 42,
         "instances": [{"instance": "https://b"}], "source": "TENABLEWAS"},
    ]
    out = tmp_path / "out.json"
    result = central_custom_allow_duplicates(
        vulns, {"reader": "tenable"}, allow_duplicates=False, output_file=str(out)
    )
    assert len(result) == 1
    assert [i["instance"] for i in result[0]["instances"]] == ["https://a", "https://b"]


def test_consolidation_falls_back_to_record_source(tmp_path):
    # No profile: the first record's source still resolves the strategy.
    vulns = [
        {"Name": "A", "description": ["d"], "severity": "HIGH", "source": "OPENVAS"},
    ]
    out = tmp_path / "out.json"
    result = central_custom_allow_duplicates(
        vulns, None, allow_duplicates=True, output_file=str(out)
    )
    assert len(result) == 1


# --- openvas strategy: no path re-check after dispatch ----------------------

def test_openvas_visual_context_accepts_any_filename(tmp_path):
    # The strategy was already dispatched as openvas; a layout file not named
    # "*openvas*" must still be read (the old code returned empty context).
    layout = tmp_path / "neutral_name.txt"
    layout.write_text(
        "Host 10.0.0.5\nPort summary for host\nHigh 25/tcp\nHigh (CVSS: 7.5)\nNVT: X\n",
        encoding="utf-8",
    )
    lines, severity, port, protocol, host = OpenVASStrategy().extract_visual_context(str(layout))
    assert severity == "High"
    assert port == "25"
    assert protocol == "tcp"
