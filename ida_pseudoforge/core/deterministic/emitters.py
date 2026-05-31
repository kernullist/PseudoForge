from __future__ import annotations

import re
from typing import Any

from ida_pseudoforge.core.deterministic.schema import Rule, RuleEmission, RuleMatch, RuleReport
from ida_pseudoforge.core.plan_schema import RenameSuggestion


def emissions_to_renames(emissions: list[RuleEmission]) -> list[RenameSuggestion]:
    suggestions = []
    for emission in emissions:
        if emission.kind != "rename":
            continue
        payload = emission.payload
        suggestions.append(
            RenameSuggestion(
                kind=str(payload.get("rename_kind", "lvar")),
                old=str(payload.get("target", "")),
                new=str(payload.get("new_name", "")),
                confidence=float(emission.confidence),
                source=str(payload.get("source", "rule")),
                evidence=str(emission.evidence or payload.get("evidence", "")),
            )
        )
    return suggestions


def emissions_to_comments(emissions: list[RuleEmission]) -> list[dict[str, Any]]:
    comments = []
    for emission in emissions:
        if emission.kind != "semantic_comment":
            continue
        payload = emission.payload
        comments.append(
            {
                "kind": str(payload.get("comment_kind", "rule")),
                "text": str(payload.get("text", "")),
                "confidence": float(emission.confidence),
                "rule_id": emission.rule_id,
            }
        )
    return comments


def build_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    kind = str(emit.get("kind", ""))
    if kind == "rename":
        return _build_rename_emission(rule, match, report)
    if kind == "semantic_comment":
        return _build_comment_emission(rule, match, report)
    if kind == "call_arg_rewrite":
        return _build_call_arg_rewrite_emission(rule, match, report)
    _reject(report, rule, "unsupported emission kind %s" % kind)
    return None


def _build_rename_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    target = _resolve_binding(str(emit.get("target", "")), match.bindings)
    new_name = _resolve_binding(str(emit.get("new_name", "")), match.bindings)
    if not target or not new_name:
        _reject(report, rule, "rename emission target or new_name could not be resolved")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    return RuleEmission(
        kind="rename",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "rename_kind": str(emit.get("rename_kind", "lvar")),
            "target": target,
            "new_name": new_name,
            "source": "rule",
            "evidence": evidence,
        },
    )


def _build_comment_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    comment_kind = _resolve_binding(str(emit.get("comment_kind", "")), match.bindings)
    text = _resolve_binding(str(emit.get("text", "")), match.bindings)
    if not comment_kind or not text:
        _reject(report, rule, "semantic_comment emission kind or text could not be resolved")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    return RuleEmission(
        kind="semantic_comment",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "comment_kind": comment_kind,
            "text": text,
            "evidence": evidence,
        },
    )


def _build_call_arg_rewrite_emission(rule: Rule, match: RuleMatch, report: RuleReport) -> RuleEmission | None:
    emit = rule.emit or {}
    function_name = _resolve_binding(str(emit.get("function_name", "")), match.bindings)
    replacement = _resolve_binding(str(emit.get("replacement", "")), match.bindings)
    argument_index = emit.get("argument_index")
    if not function_name or not replacement:
        _reject(report, rule, "call_arg_rewrite function_name or replacement could not be resolved")
        return None
    if not isinstance(argument_index, int) or isinstance(argument_index, bool) or argument_index < 0:
        _reject(report, rule, "call_arg_rewrite argument_index is invalid")
        return None
    if emit.get("preview_only") is not True:
        _reject(report, rule, "call_arg_rewrite must be preview_only")
        return None
    evidence = _resolve_binding(str(emit.get("evidence", "") or rule.id), match.bindings)
    return RuleEmission(
        kind="call_arg_rewrite",
        rule_id=rule.id,
        confidence=rule.confidence,
        priority=rule.priority,
        source_path=rule.source_path,
        source_label=rule.source_label,
        source_order=rule.source_order,
        override_of=rule.override_of,
        evidence=evidence,
        payload={
            "function_name": function_name,
            "argument_index": argument_index,
            "replacement": replacement,
            "preview_only": True,
            "source": "rule",
            "evidence": evidence,
        },
    )


def _resolve_binding(value: str, bindings: dict[str, str]) -> str:
    result = value
    for key, replacement in bindings.items():
        result = result.replace("$" + key, replacement)
    if re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", result):
        return ""
    return result


def _reject(report: RuleReport, rule: Rule, reason: str) -> None:
    report.rejected_emissions.append(
        {
            "rule_id": rule.id,
            "reason": reason,
            "source": rule.source_label or rule.pack_id,
        }
    )
