from __future__ import annotations


def _rule_pack(rules, schema_version: int = 1):
    return {
        "schema_version": schema_version,
        "id": "test.rules",
        "description": "test rules",
        "rules": rules,
    }


def _rename_rule(
    rule_id: str = "test.rename.v1",
    pattern: str = r"\b(?P<dst>v1)\s*=\s*a1\b",
    new_name: str = "inputValue",
    source: str = "rule",
    override_of: str = "",
    scope_text: str = "v1 = a1",
):
    rule = {
        "id": rule_id,
        "phase": "rename",
        "priority": 100,
        "confidence": 0.91,
        "override_of": override_of,
        "scope": {
            "text_contains": scope_text
        },
        "match": {
            "assignment_regex": pattern
        },
        "emit": {
            "kind": "rename",
            "rename_kind": "lvar",
            "target": "$dst",
            "new_name": new_name,
            "source": source,
            "evidence": "test binding"
        },
    }
    if not override_of:
        del rule["override_of"]
    return rule


def _call_arg_rewrite_rule() -> dict:
    return {
        "id": "test.call_arg_rewrite.v2",
        "phase": "call_arg_rewrite",
        "priority": 50,
        "confidence": 0.90,
        "scope": {
            "calls_any": ["ProbeForRead"]
        },
        "match": {
            "text_contains": "ProbeForRead"
        },
        "emit": {
            "kind": "call_arg_rewrite",
            "function_name": "ProbeForRead",
            "argument_index": 1,
            "replacement": "sizeof(*inputBuffer)",
            "preview_only": True,
            "evidence": "preview-only call argument rewrite"
        },
    }


def _call_arg_gate_match(
    function_name: str = "ProbeForRead",
    count: int = 3,
    argument_index: int = 2,
    value: str = "1",
) -> dict:
    return {
        "call_arg_count": {
            "function_name": function_name,
            "count": count,
        },
        "call_arg_literal": {
            "function_name": function_name,
            "argument_index": argument_index,
            "value": value,
        },
    }
