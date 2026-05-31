from __future__ import annotations

import re
from dataclasses import dataclass, field

from ida_pseudoforge.core.normalize import (
    extract_identifiers,
    find_matching_paren,
    split_parameters_with_spans,
)
from ida_pseudoforge.core.plan_schema import FunctionCapture


@dataclass(slots=True)
class LvarFact:
    name: str
    type: str = ""
    is_arg: bool = False
    index: int = -1
    location: str = ""
    identity: str = ""


@dataclass(slots=True)
class AssignmentFact:
    target: str
    expression: str
    span: tuple[int, int]
    rhs_identifiers: list[str] = field(default_factory=list)
    rhs_literals: list[str] = field(default_factory=list)
    rhs_call_name: str = ""
    rhs_call_arguments: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CallSiteFact:
    name: str
    span: tuple[int, int]
    arguments: list[str] = field(default_factory=list)
    argument_spans: list[tuple[int, int]] = field(default_factory=list)
    line_index: int = 0


@dataclass(slots=True)
class LabelFact:
    name: str
    span: tuple[int, int]


@dataclass(slots=True)
class LiteralFact:
    value: str
    span: tuple[int, int]


@dataclass(slots=True)
class RuleContext:
    capture: FunctionCapture
    text: str
    lines: list[str]
    lvar_names: set[str]
    calls: set[str]
    lvar_types: dict[str, str] = field(default_factory=dict)
    arg_names: set[str] = field(default_factory=set)
    lvar_facts: list[LvarFact] = field(default_factory=list)
    assignments: list[AssignmentFact] = field(default_factory=list)
    call_sites: list[CallSiteFact] = field(default_factory=list)
    labels: list[LabelFact] = field(default_factory=list)
    literals: list[LiteralFact] = field(default_factory=list)


_ASSIGNMENT_RE = re.compile(
    r"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;\n]+);"
)
_CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_LABEL_RE = re.compile(r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_]*):")
_LITERAL_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]+|\d+)\b")


def build_rule_context(capture: FunctionCapture, text: str | None = None) -> RuleContext:
    rule_text = capture.pseudocode if text is None else text
    lvar_facts = _lvar_facts(capture)
    return RuleContext(
        capture=capture,
        text=rule_text or "",
        lines=(rule_text or "").splitlines(),
        lvar_names={fact.name for fact in lvar_facts if fact.name},
        lvar_types=_lvar_types(lvar_facts),
        arg_names={fact.name for fact in lvar_facts if fact.name and fact.is_arg},
        calls={str(name) for name in capture.calls},
        lvar_facts=lvar_facts,
        assignments=_assignment_facts(rule_text or ""),
        call_sites=_call_site_facts(rule_text or ""),
        labels=_label_facts(rule_text or ""),
        literals=_literal_facts(rule_text or ""),
    )


def _lvar_facts(capture: FunctionCapture) -> list[LvarFact]:
    return [
        LvarFact(
            name=var.name,
            type=var.type,
            is_arg=var.is_arg,
            index=var.index,
            location=var.location,
            identity=var.identity,
        )
        for var in capture.lvars
        if var.name
    ]


def _lvar_types(facts: list[LvarFact]) -> dict[str, str]:
    result: dict[str, str] = {}
    for fact in facts:
        if fact.name and fact.type and fact.name not in result:
            result[fact.name] = fact.type
    return result


def _assignment_facts(text: str) -> list[AssignmentFact]:
    result = []
    for match in _ASSIGNMENT_RE.finditer(text):
        expression = match.group("expr").strip()
        fact_text = _mask_quoted_text(expression)
        rhs_call_name, rhs_call_arguments = _rhs_call_expression(expression)
        result.append(
            AssignmentFact(
                target=match.group("target"),
                expression=expression,
                span=match.span(),
                rhs_identifiers=sorted(extract_identifiers(fact_text)),
                rhs_literals=_literal_values(fact_text),
                rhs_call_name=rhs_call_name,
                rhs_call_arguments=rhs_call_arguments,
            )
        )
    return result


def _call_site_facts(text: str) -> list[CallSiteFact]:
    result = []
    for match in _CALL_RE.finditer(text):
        open_index = match.end() - 1
        close_index = find_matching_paren(text, open_index)
        line_index = text.count("\n", 0, match.start())
        if close_index < 0:
            result.append(CallSiteFact(name=match.group("name"), span=match.span(), line_index=line_index))
            continue
        argument_text = text[open_index + 1:close_index]
        arguments_with_spans = split_parameters_with_spans(argument_text)
        result.append(
            CallSiteFact(
                name=match.group("name"),
                span=(match.start(), close_index + 1),
                arguments=[item for item, _span in arguments_with_spans],
                argument_spans=[
                    (open_index + 1 + span[0], open_index + 1 + span[1])
                    for _item, span in arguments_with_spans
                ],
                line_index=line_index,
            )
        )
    return result


def _label_facts(text: str) -> list[LabelFact]:
    return [LabelFact(name=match.group("name"), span=match.span()) for match in _LABEL_RE.finditer(text)]


def _literal_facts(text: str) -> list[LiteralFact]:
    return [LiteralFact(value=match.group(0), span=match.span()) for match in _LITERAL_RE.finditer(text)]


def _literal_values(text: str) -> list[str]:
    return [match.group(0) for match in _LITERAL_RE.finditer(text)]


def _mask_quoted_text(text: str) -> str:
    result = []
    quote = ""
    escape = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            result.append(" ")
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        prefix_length = _quoted_prefix_length(text, index)
        if prefix_length:
            quote = text[index + prefix_length]
            result.extend([" "] * (prefix_length + 1))
            index += prefix_length + 1
            escape = False
            continue
        if char in "\"'":
            quote = char
            result.append(" ")
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _quoted_prefix_length(text: str, index: int) -> int:
    for prefix in ("u8", "L", "u", "U", "R"):
        quote_index = index + len(prefix)
        if text.startswith(prefix, index) and quote_index < len(text) and text[quote_index] in "\"'":
            return len(prefix)
    return 0


def _rhs_call_expression(expression: str) -> tuple[str, list[str]]:
    candidate = expression.strip()
    match = _CALL_RE.match(candidate)
    if match is None:
        return ("", [])
    open_index = match.end() - 1
    close_index = find_matching_paren(candidate, open_index)
    if close_index < 0:
        return ("", [])
    if candidate[close_index + 1:].strip():
        return ("", [])
    argument_text = candidate[open_index + 1:close_index]
    return (
        match.group("name"),
        [item for item, _span in split_parameters_with_spans(argument_text)],
    )
