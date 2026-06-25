"""Prioritization layer — turns extracted findings into a remediation queue.

Deterministic and auditable: an SSVC-style decision tree maps each finding to a
category (Act / Attend / Track* / Track) from KEV + EPSS + CVSS + asset exposure.
No LLM in the ranking. See ``archive/notes/PLANO_PRIORIZACAO.md``.
"""
