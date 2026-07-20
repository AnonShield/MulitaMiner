"""Download the KEV + EPSS feeds for prioritization into ``resources/feeds/``.

Thin wrapper — the implementation lives in :mod:`mulitaminer.prioritization.feeds`
(also exposed as the ``mulita-sync-feeds`` entry point). Usage::

    python tools/sync_feeds.py [--dest resources/feeds]
"""
from mulitaminer.prioritization.feeds import main

if __name__ == "__main__":
    main()
