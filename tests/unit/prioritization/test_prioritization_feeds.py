"""Feed staleness / auto-sync logic (no network — sync_feeds is monkeypatched)."""
import json
from datetime import UTC, datetime

from mulitaminer.prioritization import feeds


def _write_meta(dest, synced_at):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "meta.json").write_text(
        json.dumps({"synced_at": synced_at, "epss_score_date": "2026-06-20T00:00:00"}),
        encoding="utf-8",
    )


def test_fresh_feeds_are_not_resynced(tmp_path, monkeypatch):
    _write_meta(tmp_path, datetime.now(UTC).isoformat())  # just synced
    monkeypatch.setattr(feeds, "sync_feeds", lambda *a, **k: pytest_fail())

    assert feeds.ensure_fresh_feeds(tmp_path, max_age_days=1.0) is False


def test_missing_feeds_trigger_sync(tmp_path, monkeypatch):
    called = {"n": 0}

    def fake_sync(dest=tmp_path):
        called["n"] += 1
        return {}

    monkeypatch.setattr(feeds, "sync_feeds", fake_sync)

    assert feeds.ensure_fresh_feeds(tmp_path) is True
    assert called["n"] == 1


def test_stale_feeds_trigger_sync(tmp_path, monkeypatch):
    _write_meta(tmp_path, "2000-01-01T00:00:00+00:00")  # ancient
    called = {"n": 0}
    monkeypatch.setattr(feeds, "sync_feeds", lambda *a, **k: called.__setitem__("n", 1))

    assert feeds.ensure_fresh_feeds(tmp_path) is True
    assert called["n"] == 1


def test_sync_failure_is_swallowed(tmp_path, monkeypatch, capsys):
    def boom(*a, **k):
        raise ConnectionError("offline")

    monkeypatch.setattr(feeds, "sync_feeds", boom)

    # missing feeds + offline must not raise — fall back to local snapshot.
    assert feeds.ensure_fresh_feeds(tmp_path) is False
    assert "auto-sync skipped" in capsys.readouterr().out


def pytest_fail():
    raise AssertionError("sync_feeds should not have been called for fresh feeds")
