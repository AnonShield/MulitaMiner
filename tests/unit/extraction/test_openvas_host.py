"""Host extraction for OpenVAS: the scanned target is per-host section
metadata (the IP above "Host scan start"), assigned deterministically — never
extracted by the LLM, since it sits before the first NVT and so never reaches
the chunked body."""
from mulitaminer.scanners.openvas import OpenVASStrategy


def _layout(tmp_path, body: str):
    # The guard in extract_visual_context requires 'openvas' in the path.
    p = tmp_path / "openvas_layout.txt"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_extract_visual_context_detects_bare_ip_host(tmp_path):
    layout = _layout(tmp_path,
        "Results per Host\n"
        "127.0.0.1\n"
        "Host scan start Wed Oct 15 17:36:57 2025 UTC\n"
        "High 25/tcp\n"
        "High (CVSS: 7.5)\n"
    )
    ctx = OpenVASStrategy().extract_visual_context(layout)
    assert ctx[4] == "127.0.0.1"


def test_extract_visual_context_detects_section_numbered_host(tmp_path):
    # Artifactory-style layout: a "2.1 " section number prefixes the IP.
    layout = _layout(tmp_path,
        "2 Results per Host\n"
        "2.1 172.31.1.54\n"
        "Host scan start Mon Jan 26 08:56:34 2026 UTC\n"
        "Critical 8019/tcp\n"
    )
    ctx = OpenVASStrategy().extract_visual_context(layout)
    assert ctx[4] == "172.31.1.54"


def test_extract_visual_context_no_host_returns_none(tmp_path):
    layout = _layout(tmp_path, "High 25/tcp\nHigh (CVSS: 7.5)\n")
    ctx = OpenVASStrategy().extract_visual_context(layout)
    assert ctx[4] is None


def test_create_blocks_stamps_host_on_every_block(tmp_path):
    report = (
        "High 25/tcp\nHigh (CVSS: 7.5)\nNVT: First\nSummary\nfoo\n"
        "Medium 80/tcp\nMedium (CVSS: 5.0)\nNVT: Second\nSummary\nbar\n"
    )
    ctx = ([], "High", "25", "tcp", "10.1.2.3")
    blocks = OpenVASStrategy().create_blocks(report, str(tmp_path), ctx)
    assert len(blocks) >= 2
    assert all(b["host"] == "10.1.2.3" for b in blocks)


def test_create_blocks_switches_host_on_multi_host_boundary(tmp_path):
    # A second host section interleaved in the body: blocks before the
    # boundary keep the initial host, blocks after inherit the new one.
    report = (
        "High 25/tcp\nHigh (CVSS: 7.5)\nNVT: OnHostA\nSummary\nfoo\n"
        "2.2 192.168.0.9\n"
        "Host scan start Mon Jan 26 09:00:00 2026 UTC\n"
        "High 80/tcp\nHigh (CVSS: 7.1)\nNVT: OnHostB\nSummary\nbar\n"
    )
    ctx = ([], "High", "25", "tcp", "10.0.0.1")
    blocks = OpenVASStrategy().create_blocks(report, str(tmp_path), ctx)
    hosts = [b["host"] for b in blocks]
    assert hosts[0] == "10.0.0.1"
    assert hosts[-1] == "192.168.0.9"
