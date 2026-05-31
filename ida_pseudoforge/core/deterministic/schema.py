from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SUPPORTED_SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = {1, 2}

SUPPORTED_V1_PHASES = {
    "rename",
    "semantic_comment",
}

SUPPORTED_V2_PHASES = SUPPORTED_V1_PHASES | {
    "call_arg_rewrite",
}

SUPPORTED_PHASES = SUPPORTED_V2_PHASES

SUPPORTED_V1_EMISSION_KINDS = {
    "rename",
    "semantic_comment",
}

SUPPORTED_V2_EMISSION_KINDS = SUPPORTED_V1_EMISSION_KINDS | {
    "call_arg_rewrite",
}

SUPPORTED_EMISSION_KINDS = SUPPORTED_V2_EMISSION_KINDS

SUPPORTED_SCOPE_OPERATORS = {
    "calls_any",
    "calls_all",
    "lvars_any",
    "function_name_regex",
    "prototype_contains",
    "text_contains",
    "text_contains_all",
}

SUPPORTED_MATCH_OPERATORS = {
    "regex",
    "assignment_regex",
    "text_contains",
    "text_contains_all",
}

FORBIDDEN_RULE_KEYS = {
    "command",
    "command_template",
    "exec",
    "executable",
    "network",
    "open",
    "path_write",
    "python",
    "shell",
    "subprocess",
    "url",
}


@dataclass(slots=True)
class Rule:
    id: str
    phase: str
    priority: int
    confidence: float
    scope: dict[str, Any]
    match: dict[str, Any]
    emit: dict[str, Any]
    enabled: bool = True
    override_of: str = ""
    source_path: str = ""
    source_label: str = ""
    source_order: int = 0
    pack_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RulePack:
    schema_version: int
    id: str
    description: str
    rules: list[Rule] = field(default_factory=list)
    source_path: str = ""
    source_label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuleMatch:
    rule_id: str
    phase: str
    confidence: float
    bindings: dict[str, str] = field(default_factory=dict)
    span: tuple[int, int] | None = None
    evidence: str = ""
    emission_kind: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuleEmission:
    kind: str
    rule_id: str
    confidence: float
    payload: dict[str, Any]
    evidence: str = ""
    priority: int = 0
    source_path: str = ""
    source_label: str = ""
    source_order: int = 0
    override_of: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuleReport:
    matched_rules: list[dict[str, Any]] = field(default_factory=list)
    rejected_emissions: list[dict[str, Any]] = field(default_factory=list)
    load_errors: list[dict[str, Any]] = field(default_factory=list)
    validation_errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched_rules": list(self.matched_rules),
            "rejected_emissions": list(self.rejected_emissions),
            "load_errors": list(self.load_errors),
            "validation_errors": list(self.validation_errors),
        }


@dataclass(slots=True)
class RuleRunResult:
    emissions: list[RuleEmission] = field(default_factory=list)
    report: RuleReport = field(default_factory=RuleReport)
