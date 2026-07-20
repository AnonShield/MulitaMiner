"""Run metric pipelines across all extracted runs.

Thin wrapper — the implementation lives in :mod:`metrics.run_metrics`
(also exposed as the ``mulita-metrics`` entry point; requires the
``[metrics]`` extra). See that module's docstring for usage examples.
"""
from metrics.run_metrics import main

if __name__ == "__main__":
    main()
