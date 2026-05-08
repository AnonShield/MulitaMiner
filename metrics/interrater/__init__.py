"""Inter-rater agreement on the human baseline (metrics.md §6).

These metrics establish the *ceiling* for any model: if two human
annotators only agree X% of the time on ``severity``, asking the LLM to
exceed X% is unrealistic. They also blind the paper against the reviewer
question "is the ground truth itself reliable?".

Single-annotator projects can omit this layer and document it as an
acknowledged limitation — the metrics module simply reports
"insufficient annotators" in that case.
"""
