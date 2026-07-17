"""Typed contracts on the block/visual-context seams (§5).

The block dict and the visual-context tuple were implicit contracts: the tuple
annotation claimed 4 elements but returned 5, and host was stamped onto
records only when a strategy happened to set the key — so Tenable/default
records silently never got a host. These are now a NamedTuple and a TypedDict,
and host stamping is unconditional.
"""

from mulitaminer.scanners.base import ScannerStrategy, VisualContext


def test_visual_context_is_named_and_five_fields():
    ctx = VisualContext(["hdr"], "HIGH", "443", "tcp", "host-1")
    assert ctx.lines == ["hdr"]
    assert ctx.severity == "HIGH"
    assert ctx.host == "host-1"
    # Still a tuple: legacy unpacking keeps working.
    lines, severity, port, protocol, host = ctx
    assert (severity, port, protocol, host) == ("HIGH", "443", "tcp", "host-1")


def test_default_strategy_visual_context_is_typed():
    class _Bare(ScannerStrategy):
        def vulnerability_processing_logic(self, vulns, allow_duplicates=True, profile_config=None):
            return vulns

    ctx = _Bare().extract_visual_context("")
    assert isinstance(ctx, VisualContext)
    assert ctx == VisualContext([], None, None, None, None)


def test_default_create_blocks_stamps_host_key(tmp_path):
    class _Bare(ScannerStrategy):
        scanner_name = "bare"
        def vulnerability_processing_logic(self, vulns, allow_duplicates=True, profile_config=None):
            return vulns

    blocks = _Bare().create_blocks("body text", str(tmp_path), VisualContext([], None, None, None, "h9"))
    assert blocks[0]["host"] == "h9"
    assert "file" in blocks[0]
