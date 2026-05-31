from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ida_pseudoforge.core.deterministic.schema import (
    FORBIDDEN_RULE_KEYS,
    SUPPORTED_MATCH_OPERATORS,
    SUPPORTED_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    SUPPORTED_V1_EMISSION_KINDS,
    SUPPORTED_V1_PHASES,
    SUPPORTED_V2_EMISSION_KINDS,
    SUPPORTED_V2_PHASES,
    SUPPORTED_SCOPE_OPERATORS,
)


class RulePackValidationError(ValueError):
    pass


def parse_rule_pack_file(path: str | Path) -> tuple[dict[str, Any] | None, list[str]]:
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ["file not found"]
    except (OSError, UnicodeDecodeError) as exc:
        return None, ["could not read file: %s" % exc]
    except json.JSONDecodeError as exc:
        return None, ["invalid JSON: line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg)]
    if not isinstance(data, dict):
        return None, ["rule pack root must be an object"]
    return data, []


def validate_rule_pack_data(data: dict[str, Any], source_path: str = "") -> list[str]:
    errors: list[str] = []
    if _contains_forbidden_key(data):
        errors.append("rule pack contains forbidden execution or network field")

    schema_version = data.get("schema_version")
    if not _is_supported_schema_version(schema_version):
        errors.append("unsupported schema_version %r" % (schema_version,))
        schema_version = SUPPORTED_SCHEMA_VERSION

    pack_id = data.get("id")
    if not isinstance(pack_id, str) or not pack_id.strip():
        errors.append("pack id is required")

    description = data.get("description", "")
    if description is not None and not isinstance(description, str):
        errors.append("description must be a string")

    rules = data.get("rules")
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        return errors

    seen_rule_ids = set()
    for index, item in enumerate(rules):
        prefix = "rules[%d]" % index
        if not isinstance(item, dict):
            errors.append("%s must be an object" % prefix)
            continue
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append("%s.id is required" % prefix)
        elif rule_id in seen_rule_ids:
            errors.append("duplicate rule id %s" % rule_id)
        else:
            seen_rule_ids.add(rule_id)
        errors.extend(_validate_rule(item, prefix, int(schema_version)))

    return errors


def validate_rule_pack_file(path: str | Path) -> list[str]:
    data, errors = parse_rule_pack_file(path)
    if errors:
        return errors
    assert data is not None
    return validate_rule_pack_data(data, str(path))


def _validate_rule(rule: dict[str, Any], prefix: str, schema_version: int) -> list[str]:
    errors: list[str] = []
    if _contains_forbidden_key(rule):
        errors.append("%s contains forbidden execution or network field" % prefix)

    phase = rule.get("phase")
    supported_phases = _supported_phases(schema_version)
    if phase not in supported_phases:
        errors.append("%s.phase must be one of %s" % (prefix, ", ".join(sorted(supported_phases))))

    confidence = rule.get("confidence")
    if not _is_real_number(confidence) or not 0.0 <= float(confidence) <= 1.0:
        errors.append("%s.confidence must be between 0.0 and 1.0" % prefix)

    priority = rule.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool):
        errors.append("%s.priority must be an integer" % prefix)

    enabled = rule.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.append("%s.enabled must be a boolean" % prefix)

    override_of = rule.get("override_of", "")
    if override_of is not None and not isinstance(override_of, str):
        errors.append("%s.override_of must be a string" % prefix)

    scope = rule.get("scope", {})
    if not isinstance(scope, dict):
        errors.append("%s.scope must be an object" % prefix)
        scope = {}
    errors.extend(_validate_operator_map(scope, SUPPORTED_SCOPE_OPERATORS, "%s.scope" % prefix))
    errors.extend(_validate_scope_values(scope, "%s.scope" % prefix))
    errors.extend(_validate_scope_regexes(scope, "%s.scope" % prefix))

    match = rule.get("match")
    if not isinstance(match, dict):
        errors.append("%s.match must be an object" % prefix)
        match = {}
    errors.extend(_validate_operator_map(match, SUPPORTED_MATCH_OPERATORS, "%s.match" % prefix))
    errors.extend(_validate_regexes(match, "%s.match" % prefix))
    errors.extend(_validate_match_values(match, "%s.match" % prefix))
    errors.extend(_validate_match_shape(match, "%s.match" % prefix))
    if not any(key in match for key in SUPPORTED_MATCH_OPERATORS):
        errors.append("%s.match must define at least one supported operator" % prefix)

    emit = rule.get("emit")
    if not isinstance(emit, dict):
        errors.append("%s.emit must be an object" % prefix)
        return errors
    errors.extend(_validate_emit(emit, phase, "%s.emit" % prefix, schema_version))
    if phase == "call_arg_rewrite":
        errors.extend(_validate_call_arg_rewrite_scope(scope, emit, "%s.scope" % prefix))
    return errors


def _validate_operator_map(data: dict[str, Any], supported: set[str], prefix: str) -> list[str]:
    errors = []
    for key in data:
        if key not in supported:
            errors.append("%s.%s is not supported" % (prefix, key))
    return errors


def _validate_regexes(match: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    for key in ("regex", "assignment_regex"):
        if key not in match:
            continue
        pattern = match.get(key)
        if not isinstance(pattern, str) or not pattern:
            errors.append("%s.%s must be a non-empty regex string" % (prefix, key))
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append("%s.%s invalid regex: %s" % (prefix, key, exc))
    return errors


def _validate_scope_values(scope: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    for key in ("calls_any", "calls_all", "lvars_any", "text_contains_all"):
        if key in scope:
            errors.extend(_validate_string_or_string_list(scope.get(key), "%s.%s" % (prefix, key)))
    for key in ("prototype_contains", "text_contains"):
        if key in scope:
            errors.extend(_validate_non_empty_string(scope.get(key), "%s.%s" % (prefix, key)))
    return errors


def _validate_match_values(match: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    if "text_contains" in match:
        errors.extend(_validate_non_empty_string(match.get("text_contains"), "%s.text_contains" % prefix))
    if "text_contains_all" in match:
        errors.extend(_validate_string_or_string_list(match.get("text_contains_all"), "%s.text_contains_all" % prefix))
    return errors


def _validate_match_shape(match: dict[str, Any], prefix: str) -> list[str]:
    primary_regexes = [key for key in ("regex", "assignment_regex") if key in match]
    if len(primary_regexes) > 1:
        return ["%s must not combine regex and assignment_regex" % prefix]
    return []


def _validate_scope_regexes(scope: dict[str, Any], prefix: str) -> list[str]:
    errors = []
    pattern = scope.get("function_name_regex")
    if pattern is None:
        return errors
    if not isinstance(pattern, str) or not pattern:
        errors.append("%s.function_name_regex must be a non-empty regex string" % prefix)
        return errors
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append("%s.function_name_regex invalid regex: %s" % (prefix, exc))
    return errors


def _validate_non_empty_string(value: object, prefix: str) -> list[str]:
    if isinstance(value, str) and value:
        return []
    return ["%s must be a non-empty string" % prefix]


def _validate_string_or_string_list(value: object, prefix: str) -> list[str]:
    if isinstance(value, str):
        if value:
            return []
        return ["%s must be a non-empty string or non-empty string list" % prefix]
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return []
    return ["%s must be a non-empty string or non-empty string list" % prefix]


def _is_real_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_emit(emit: dict[str, Any], phase: object, prefix: str, schema_version: int) -> list[str]:
    errors: list[str] = []
    kind = emit.get("kind")
    supported_kinds = _supported_emission_kinds(schema_version)
    if kind not in supported_kinds:
        errors.append("%s.kind must be one of %s" % (prefix, ", ".join(sorted(supported_kinds))))
        return errors
    if phase != kind:
        errors.append("%s.kind must match rule phase" % prefix)

    if kind == "rename":
        for field_name in ("target", "new_name"):
            if not isinstance(emit.get(field_name), str) or not emit.get(field_name):
                errors.append("%s.%s is required" % (prefix, field_name))
        rename_kind = emit.get("rename_kind", "lvar")
        if not isinstance(rename_kind, str) or not rename_kind:
            errors.append("%s.rename_kind must be a string" % prefix)
    elif kind == "semantic_comment":
        for field_name in ("comment_kind", "text"):
            if not isinstance(emit.get(field_name), str) or not emit.get(field_name):
                errors.append("%s.%s is required" % (prefix, field_name))
    elif kind == "call_arg_rewrite":
        errors.extend(_validate_call_arg_rewrite_emit(emit, prefix))
    return errors


def _validate_call_arg_rewrite_emit(emit: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    for field_name in ("function_name", "replacement"):
        if not isinstance(emit.get(field_name), str) or not emit.get(field_name):
            errors.append("%s.%s is required" % (prefix, field_name))
    argument_index = emit.get("argument_index")
    if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        errors.append("%s.argument_index must be a non-negative integer" % prefix)
    if emit.get("preview_only") is not True:
        errors.append("%s.preview_only must be true" % prefix)
    return errors


def _validate_call_arg_rewrite_scope(scope: dict[str, Any], emit: dict[str, Any], prefix: str) -> list[str]:
    function_name = emit.get("function_name")
    if not isinstance(function_name, str) or not function_name:
        return []
    if "$" in function_name:
        if _has_call_scope_gate(scope):
            return []
        return ["%s must gate call_arg_rewrite with calls_any/calls_all" % prefix]
    if _scope_calls_include(scope.get("calls_any"), function_name):
        return []
    if _scope_calls_include(scope.get("calls_all"), function_name):
        return []
    return ["%s must gate call_arg_rewrite with calls_any/calls_all for %s" % (prefix, function_name)]


def _has_call_scope_gate(scope: dict[str, Any]) -> bool:
    return "calls_any" in scope or "calls_all" in scope


def _scope_calls_include(value: object, function_name: str) -> bool:
    if isinstance(value, str):
        return value == function_name
    if isinstance(value, list):
        return function_name in value
    return False


def _is_supported_schema_version(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in SUPPORTED_SCHEMA_VERSIONS


def _supported_phases(schema_version: int) -> set[str]:
    if schema_version <= 1:
        return SUPPORTED_V1_PHASES
    return SUPPORTED_V2_PHASES


def _supported_emission_kinds(schema_version: int) -> set[str]:
    if schema_version <= 1:
        return SUPPORTED_V1_EMISSION_KINDS
    return SUPPORTED_V2_EMISSION_KINDS


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_RULE_KEYS:
                return True
            if _contains_forbidden_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(item) for item in value)
    return False
