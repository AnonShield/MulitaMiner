"""Single source of truth for the vulnerability record.

Wired into metrics/pipelines/schema_check.py and src/mulitaminer/llm/llm_processing.py
(both derive their field/type map from `validation_types()` / `expected_fields()`
below). Before this, the "V3 schema" lived, un-coordinated, in several places:

    - the prompts (prose, per scanner): configs/prompts/openvas_prompt.txt,
      configs/prompts/tenable_prompt.txt
    - the validator (a hand-copied dict): metrics/pipelines/schema_check.py:V3_SCHEMA
    - the metric field lists: configs/schema/field_categories.json
    - the baseline type checks: metrics/common/io.py:_BASELINE_EXPECTED_TYPES

They drift. (Concrete proof: schema_check validated `plugin` as str|None, but
tenable_prompt tells the LLM to emit a number — so every correct Tenable record
was flagged.) One Pydantic model fixes that: from THIS class the validator and
the metric config derive their contract. Change a field here, they follow.

The prompts stay hand-written (their exact field order/wording matters — a
regeneration experiment measurably hurt port/protocol extraction). A test guards
them against drift instead: tests/unit/test_schema_single_source.py asserts every
model field appears in each prompt's schema block.

Extensibility (adding a scanner): subclass the base (see OpenVASRecord /
TenableRecord) declaring only what differs; or drop scanner-specific extras into
`scanner_specific` with no code change at all.
"""
from __future__ import annotations

import types as _pytypes
import typing
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Severity spans both scanners' vocabularies: OpenVAS uses LOG for the
# informational tier, Tenable uses INFO. Kept as one shared Literal on purpose —
# llm_processing normalizes INFO→LOG post-extraction, so a Tenable record is INFO
# before that step and LOG after; a single field must accept both.
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOG", "INFO"]


class VulnRecord(BaseModel):
    """Core contract shared by every scanner. Validated, stable.

    A record that validates against this base is guaranteed to carry the
    fields the prioritization layer and the standard-format exporters
    (SARIF/CSAF/...) rely on. Scanner-specific extras never live here — they
    go in `scanner_specific` or in a subclass.
    """

    # extra="allow": same choice already made for LLMConfig/ScannerConfig in
    # schemas.py — tolerate keys a scanner emits that we didn't declare, rather
    # than hard-failing. Safety net, not the organizing mechanism.
    # populate_by_name: accept BOTH the JSON key `Name` (current V3) and the
    # pythonic attribute `name` — the alias below is the only V3 field whose
    # JSON key isn't snake_case (SCHEMA_PROPOSAL §4.14). One line papers over it.
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str = Field(alias="Name")
    description: list[str] = []
    solution: list[str] = []
    impact: list[str] = []
    insight: list[str] = []
    references: list[str] = []

    # Both current prompts emit all of these: OpenVAS fills detection_*/log_method
    # with real content and plugin/plugin_details/instances as null/empty; Tenable
    # does the reverse. So the base declares them all; subclasses refine the TYPES
    # of the ones a scanner really populates (see TenableRecord).
    detection_result: list[str] = []
    detection_method: list[str] = []
    product_detection_result: list[str] = []
    log_method: list[str] = []
    plugin: int | None = None
    plugin_details: dict = {}
    instances: list = []

    # cvss on the base is the OpenVAS shape: a single numeric score (int or
    # float, so 7 vs 7.0 isn't a type error) or null. Tenable overrides it to a
    # list of raw CVSS strings (see TenableRecord) — genuinely a different type
    # per scanner, so it's refined in the subclass, not a base union (a union
    # would make a missing OpenVAS cvss default to [] instead of null). The
    # hybrid `ratings[]` (SCHEMA_PROPOSAL §4.5) is what normalizes this away.
    cvss: float | int | None = None
    severity: Severity

    # host is NOT produced by the LLM's content extraction — the pipeline assigns
    # it from the report's per-host section. So the metric must not count it
    # "missing" when the raw LLM output lacks it: llm_produced=False.
    host: str | None = Field(default=None, json_schema_extra={"llm_produced": False})
    port: int | str | None = None
    protocol: Literal["tcp", "udp"] | None = None

    source: str

    # The overflow bucket. A brand-new scanner can dump anything here with ZERO
    # changes to this file. Cost: fields inside are not individually typed —
    # promote them to a subclass (below) when they deserve validation.
    # Also not an LLM field — it's a post-processing namespace.
    scanner_specific: dict = Field(default_factory=dict, json_schema_extra={"llm_produced": False})


# --- Scanner-specific submodels (used only where the fields are real) --------


class PluginDetails(BaseModel):
    """Tenable's Plugin Details block. Empty ({}) for OpenVAS."""

    model_config = ConfigDict(extra="allow")

    publication_date: str | None = None
    modification_date: str | None = None
    family: str | None = None
    severity: str | None = None
    plugin_id: int | None = None


class Instance(BaseModel):
    """One Tenable WAS instance (a URL/endpoint the finding was seen on)."""

    model_config = ConfigDict(extra="allow")

    instance: str = ""
    input_type: str = ""
    input_name: str = ""
    payload: str = ""
    proof: str = ""
    output: str = ""
    request_method: str = ""
    http_status_code: int | None = None
    http_protocol: str = ""
    response_content_type: str = ""


# --- Per-scanner records: the "add a scanner" extension point -----------------
# Adding a scanner = one subclass. You declare only what differs; everything in
# VulnRecord is inherited. This is the typed alternative to scanner_specific.


class OpenVASRecord(VulnRecord):
    """OpenVAS/Greenbone. Network scan: CVE-rich, has detection metadata.

    Adds no fields — it only pins ``source`` and inherits the base as-is (the
    base's loose plugin/instances match OpenVAS's always-empty case).
    """

    source: Literal["OPENVAS"] = "OPENVAS"


class TenableRecord(VulnRecord):
    """Tenable WAS. Web app scan: mostly CVE-less, per-URL instances.

    Refines the types of the fields it really populates: cvss is a list of raw
    CVSS strings, the plugin block is structured, each instance is typed.
    """

    source: Literal["TENABLEWAS"] = "TENABLEWAS"

    cvss: list[str] = []
    plugin_details: PluginDetails = Field(default_factory=PluginDetails)
    instances: list[Instance] = []


# --- Dispatch + validation helpers (what schema_check / llm_processing use) ----

# Dispatch a raw dict to the right typed record by its `source`.
_BY_SOURCE: dict[str, type[VulnRecord]] = {
    "OPENVAS": OpenVASRecord,
    "TENABLEWAS": TenableRecord,
}


def parse_record(data: dict) -> VulnRecord:
    """Validate one raw record into the correct typed model by its `source`
    (unknown source → base model, which still validates the core contract)."""
    model = _BY_SOURCE.get(data.get("source", ""), VulnRecord)
    return model.model_validate(data)


def json_schema_for(source: str) -> dict:
    """The formal JSON Schema for a scanner — for a future converter/constrained
    decoder, not the prompt."""
    return _BY_SOURCE.get(source, VulnRecord).model_json_schema()


def _outer_types(annotation) -> tuple[type, ...]:
    """Reduce a field annotation to the top-level runtime types a plain
    isinstance() can check — the granularity schema_check verifies.

    e.g. ``float | int | None`` -> ``(float, int, NoneType)``,
    ``Literal["tcp","udp"] | None`` -> ``(str, NoneType)``,
    ``list[Instance]`` -> ``(list,)``, a nested BaseModel -> ``(dict,)``.
    """
    origin = typing.get_origin(annotation)
    if origin is typing.Literal:
        return tuple(dict.fromkeys(type(a) for a in typing.get_args(annotation)))
    if origin in (typing.Union, getattr(_pytypes, "UnionType", None)):
        out: list[type] = []
        for arg in typing.get_args(annotation):
            for t in _outer_types(arg):
                if t not in out:
                    out.append(t)
        return tuple(out)
    if origin is not None:  # parametrized container (list[...], dict[...])
        return (origin,)
    if annotation is type(None):
        return (type(None),)
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return (dict,)  # a nested model round-trips through a dict
    if isinstance(annotation, type):
        return (annotation,)
    return (object,)  # unknown annotation → accept anything (defensive)


def _field_key(name: str, field) -> str:
    return field.alias or name


def _is_llm_produced(field) -> bool:
    extra = field.json_schema_extra if isinstance(field.json_schema_extra, dict) else {}
    return extra.get("llm_produced", True)


def _model_for(source: str | None) -> type[VulnRecord]:
    return _BY_SOURCE.get(source or "", VulnRecord)


def validation_types(source: str | None = None) -> dict[str, tuple[type, ...]]:
    """field-alias -> allowed runtime types, for the given scanner.

    Replaces the hand-copied ``V3_SCHEMA`` dict in schema_check: same shape,
    generated from the model so the types can never drift from the contract.
    """
    model = _model_for(source)
    return {_field_key(n, f): _outer_types(f.annotation) for n, f in model.model_fields.items()}


def expected_fields(source: str | None = None) -> list[str]:
    """The fields the LLM is responsible for producing — everything except the
    pipeline-filled fields (host, scanner_specific). One of these missing from
    the raw output is a real conformance failure; a pipeline field missing is not.
    """
    model = _model_for(source)
    return [_field_key(n, f) for n, f in model.model_fields.items() if _is_llm_produced(f)]
