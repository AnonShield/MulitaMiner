"""Cross-run aggregation: mean ± std, statistical tests.

Aggregators run *after* per-run pipelines (``metrics/pipelines/``) have
written their XLSX/JSON artifacts. They walk the result tree, collect the
summary numbers, group by ``(version, target, model, field, metric)`` and
emit aggregated tables.

Layered: ``discovery`` finds runs, ``multi_run`` aggregates,
``statistical_tests`` consumes the tidy output.
"""
