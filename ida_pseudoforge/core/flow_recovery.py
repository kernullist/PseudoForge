from __future__ import annotations

import re
from collections import Counter

from ida_pseudoforge.core.normalize import extract_parameters_from_signature
from ida_pseudoforge.core.plan_schema import FlowRewrite, FunctionCapture
from ida_pseudoforge.profiles.loader import (
    get_process_information_class_name,
    get_system_information_class_name,
)


_CAST_PREFIX = r"(?:\(\s*(?:_DWORD|int|unsigned\s+int|ULONG|LONG|DWORD|PROCESSINFOCLASS|SYSTEM_INFORMATION_CLASS)\s*\)\s*)*"
_CASE_INTEGER_SUFFIX = r"ui64|i64|u?ll|llu|ul|lu|u|l"
_CASE_LITERAL = r"(?:(?:0x[0-9A-Fa-f]+|\d+)(?i:%s)?|'[^'\\]')" % _CASE_INTEGER_SUFFIX
_CASE_INTEGER_SUFFIX_RE = re.compile(r"(?:%s)$" % _CASE_INTEGER_SUFFIX, re.IGNORECASE)
COMPARE_RE = re.compile(
    r"(?<![A-Za-z0-9_])%s(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=|>=|<=|>|<)\s*(?P<value>\d+)\b"
    % _CAST_PREFIX
)
SUB_RE = re.compile(
    r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*-\s*(?P<value>\d+)\b"
)
NOT_TEMP_RE = re.compile(r"if\s*\(\s*!(?P<temp>[A-Za-z_][A-Za-z0-9_]*)\s*\)")
EQ_TEMP_RE = re.compile(
    r"if\s*\(\s*(?P<temp>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*(?P<value>\d+)\s*\)"
)
RANGE_SUB_RE = re.compile(
    r"\(\s*(?:unsigned\s+int\s*)?\(\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*-\s*"
    r"(?P<base>\d+)\s*\)\s*>\s*(?P<count>\d+)\s*\)"
)
SWITCH_RE = re.compile(r"\bswitch\s*\(\s*%s(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\)" % _CAST_PREFIX)
CASE_LABEL_RE = re.compile(r"^\s*case\s+(?P<value>%s)\s*:\s*$" % _CASE_LITERAL)
DIRECT_IF_EQ_RE = re.compile(
    r"if\s*\(\s*%s(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*(?P<value>\d+)\s*\)" % _CAST_PREFIX
)


def recover_flow(capture: FunctionCapture, rename_map: dict[str, str] | None = None) -> list[FlowRewrite]:
    if _looks_like_template_or_tracing_function(capture):
        return []

    text = capture.pseudocode
    dispatcher = _find_dispatcher(text)
    if not dispatcher:
        return []

    cases = _recover_cases(text, dispatcher)
    case_bodies = _recover_case_bodies(text, dispatcher)
    cases.update(case_bodies)
    case_anchors = _recover_case_anchors(text, dispatcher)
    state_bodies = _recover_case_body_state_bodies(text, dispatcher, case_bodies)
    case_body_states = _case_body_states(cases, state_bodies)
    case_labels = _case_labels(case_bodies)
    renamed_dispatcher = (rename_map or {}).get(dispatcher, dispatcher)
    is_system_information_dispatcher = _is_system_information_dispatcher(capture, dispatcher, renamed_dispatcher)
    is_process_information_dispatcher = _is_process_information_dispatcher(capture, dispatcher, renamed_dispatcher)
    case_names = {}
    if is_system_information_dispatcher:
        case_names = {
            value: name
            for value in sorted(cases)
            for name in [get_system_information_class_name(value)]
            if name
        }
    elif is_process_information_dispatcher:
        case_names = {
            value: name
            for value in sorted(cases)
            for name in [get_process_information_class_name(value)]
            if name
        }
    confidence = min(0.98, 0.45 + len(cases) * 0.03)

    minimum_cases = 3 if is_system_information_dispatcher or is_process_information_dispatcher else 4
    if len(cases) < minimum_cases:
        return []

    return [
        FlowRewrite(
            kind="switch_recovery",
            dispatcher=renamed_dispatcher,
            recovered_cases=sorted(cases),
            case_bodies=case_bodies,
            case_names=case_names,
            case_body_states=case_body_states,
            case_anchors=case_anchors,
            case_labels=case_labels,
            confidence=round(confidence, 2),
            export_only=True,
            evidence=(
                f"Recovered {len(cases)} case values and {len(case_bodies)} case bodies "
                "from comparisons and subtraction chains"
            ),
        )
    ]


def _looks_like_template_or_tracing_function(capture: FunctionCapture) -> bool:
    signature_text = " ".join([capture.name or "", capture.prototype or ""])
    body_text = capture.pseudocode or ""
    combined = signature_text + "\n" + body_text[:1200]
    lowered = combined.lower()
    if "_tlg" in lowered or "tracelogging" in lowered:
        return True
    if re.search(r"\b_tlgwrapper[A-Za-z0-9_]*\b", combined):
        return True
    return bool(re.search(r"\b[A-Za-z_][A-Za-z0-9_:]*<[^;\n{}()]*>\s*[A-Za-z_][A-Za-z0-9_:]*\s*\(", signature_text))


def _is_system_information_dispatcher(
    capture: FunctionCapture,
    dispatcher: str,
    renamed_dispatcher: str,
) -> bool:
    dispatcher_names = {dispatcher, renamed_dispatcher}
    normalized_names = {name.lower() for name in dispatcher_names if name}
    if {"infoclass", "systeminformationclass"} & normalized_names:
        return True
    if capture.name == "NtSetSystemInformation":
        return True
    return "SYSTEM_INFORMATION_CLASS" in (capture.prototype or "")


def _is_process_information_dispatcher(
    capture: FunctionCapture,
    dispatcher: str,
    renamed_dispatcher: str,
) -> bool:
    dispatcher_names = {dispatcher, renamed_dispatcher}
    normalized_names = {name.lower() for name in dispatcher_names if name}
    if "processinformationclass" in normalized_names:
        return True
    if "PROCESSINFOCLASS" in (capture.prototype or ""):
        return True
    if capture.name != "NtSetInformationProcess":
        return False
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) < 2:
        return False
    return dispatcher == params[1][0] or renamed_dispatcher == "processInformationClass"


def _find_dispatcher(text: str) -> str:
    switch_dispatcher = _find_largest_switch_dispatcher(text or "")
    if switch_dispatcher:
        return switch_dispatcher

    scores = Counter()
    for match in COMPARE_RE.finditer(text or ""):
        scores[match.group("var")] += 2
    for match in SUB_RE.finditer(text or ""):
        scores[match.group("src")] += 3
    for match in RANGE_SUB_RE.finditer(text or ""):
        scores[match.group("var")] += 3
    if not scores:
        return ""
    name, score = scores.most_common(1)[0]
    return name if score >= 4 else ""


def _find_largest_switch_dispatcher(text: str) -> str:
    lines = (text or "").splitlines()
    best_dispatcher = ""
    best_count = 0
    for index, line in enumerate(lines):
        switch_match = SWITCH_RE.search(line)
        if not switch_match:
            continue
        case_count = _count_switch_cases(lines, index)
        if case_count > best_count:
            best_dispatcher = switch_match.group("var")
            best_count = case_count
    return best_dispatcher


def _count_switch_cases(lines: list[str], switch_index: int) -> int:
    count = 0
    depth = 0
    seen_open = False
    for line in lines[switch_index:]:
        stripped = line.strip()
        opens = stripped.count("{")
        closes = stripped.count("}")
        if opens:
            depth += opens
            seen_open = True
        if seen_open and depth >= 1 and CASE_LABEL_RE.match(line):
            count += 1
        if closes:
            depth -= closes
            if seen_open and depth <= 0:
                break
    return count


def _recover_cases(text: str, dispatcher: str) -> set[int]:
    cases = set()
    offsets: dict[str, int] = {}
    lines = (text or "").splitlines()

    if SWITCH_RE.search(text or ""):
        return _recover_switch_cases(lines, dispatcher)

    for line in lines:
        for match in COMPARE_RE.finditer(line):
            if match.group("var") == dispatcher:
                cases.add(int(match.group("value")))

        range_match = RANGE_SUB_RE.search(line)
        if range_match and range_match.group("var") == dispatcher:
            base = int(range_match.group("base"))
            count = int(range_match.group("count"))
            for value in range(base, base + count + 1):
                cases.add(value)

        sub_match = SUB_RE.search(line)
        if sub_match:
            dst = sub_match.group("dst")
            src = sub_match.group("src")
            value = int(sub_match.group("value"))
            if src == dispatcher:
                offsets[dst] = value
            elif src in offsets:
                offsets[dst] = offsets[src] + value

        not_match = NOT_TEMP_RE.search(line)
        if not_match:
            temp = not_match.group("temp")
            if temp in offsets:
                cases.add(offsets[temp])

        eq_match = EQ_TEMP_RE.search(line)
        if eq_match:
            temp = eq_match.group("temp")
            if temp in offsets:
                cases.add(offsets[temp] + int(eq_match.group("value")))

    return cases


def _recover_case_bodies(text: str, dispatcher: str) -> dict[int, list[str]]:
    lines = (text or "").splitlines()
    bodies: dict[int, list[str]] = {}
    offsets: dict[str, int] = {}

    if SWITCH_RE.search(text or ""):
        bodies.update(_recover_switch_case_bodies(lines, dispatcher))

    for index, line in enumerate(lines):
        sub_match = SUB_RE.search(line)
        if sub_match:
            dst = sub_match.group("dst")
            src = sub_match.group("src")
            value = int(sub_match.group("value"))
            if src == dispatcher:
                offsets[dst] = value
            elif src in offsets:
                offsets[dst] = offsets[src] + value

        case_value = _case_value_for_condition(line, dispatcher, offsets)
        if case_value is None:
            continue

        body = _collect_if_body(lines, index)
        if body:
            bodies.setdefault(case_value, body)

    return bodies


def _recover_case_anchors(text: str, dispatcher: str) -> dict[int, int]:
    lines = (text or "").splitlines()
    anchors: dict[int, int] = {}
    offsets: dict[str, int] = {}

    if SWITCH_RE.search(text or ""):
        anchors.update(_recover_switch_case_anchors(lines, dispatcher))

    for index, line in enumerate(lines):
        sub_match = SUB_RE.search(line)
        if sub_match:
            dst = sub_match.group("dst")
            src = sub_match.group("src")
            value = int(sub_match.group("value"))
            if src == dispatcher:
                offsets[dst] = value
            elif src in offsets:
                offsets[dst] = offsets[src] + value

        case_value = _case_value_for_condition(line, dispatcher, offsets)
        if case_value is not None:
            anchors.setdefault(case_value, index + 1)
    return anchors


def _recover_switch_case_anchors(lines: list[str], dispatcher: str) -> dict[int, int]:
    anchors: dict[int, int] = {}
    in_target_switch = False
    depth = 0

    for index, line in enumerate(lines):
        switch_match = SWITCH_RE.search(line)
        if not in_target_switch:
            if switch_match and switch_match.group("var") == dispatcher:
                in_target_switch = True
                depth += line.strip().count("{")
            continue

        stripped = line.strip()
        closes = stripped.count("}")
        if closes:
            depth -= closes
            if depth <= 0:
                in_target_switch = False
                depth = 0
                continue

        case_match = CASE_LABEL_RE.match(line)
        if depth == 1 and case_match:
            anchors.setdefault(_parse_case_literal(case_match.group("value")), index + 1)

        opens = stripped.count("{")
        if opens:
            depth += opens
    return anchors


def _recover_case_body_state_bodies(
    text: str,
    dispatcher: str,
    case_bodies: dict[int, list[str]],
) -> dict[int, list[str]]:
    state_bodies = dict(case_bodies)
    if SWITCH_RE.search(text or ""):
        state_bodies.update(
            _recover_switch_case_bodies((text or "").splitlines(), dispatcher, keep_empty=True)
        )
    return state_bodies


def _case_body_states(cases: set[int], case_bodies: dict[int, list[str]]) -> dict[int, str]:
    return {
        value: _case_body_state(case_bodies.get(value))
        for value in sorted(cases)
    }


def _case_body_state(body: list[str] | None) -> str:
    if body is None:
        return "complex_unsliced"
    statements = [line.strip() for line in body if line.strip() and not line.strip().startswith("//")]
    if not statements:
        return "fallthrough_or_join"
    if any(_goto_label_from_line(line) for line in statements):
        return "shared_tail"
    if len(statements) == 1 and (statements[0].startswith("return ") or statements[0] == "return;"):
        return "single_statement_body"
    if _is_complete_branch_slice(statements):
        return "complete_branch_slice"
    return "complex_unsliced"


def _is_complete_branch_slice(statements: list[str]) -> bool:
    if len(statements) < 2:
        return False
    for line in statements:
        stripped = line.strip()
        if stripped in {"{", "}"}:
            return False
        if stripped.endswith(":"):
            return False
        if _goto_label_from_line(stripped):
            return False
        if stripped.startswith(("if ", "else", "for ", "while ", "do", "switch ")):
            return False
        if not stripped.endswith(";"):
            return False
    final_statement = statements[-1]
    if not (final_statement.startswith("return ") or final_statement == "return;"):
        return False
    return not any(
        line.startswith(("return ", "return;", "break;", "continue;"))
        for line in statements[:-1]
    )


def _case_labels(case_bodies: dict[int, list[str]]) -> dict[int, str]:
    result: dict[int, str] = {}
    for value, body in case_bodies.items():
        for line in body:
            label = _goto_label_from_line(line)
            if label:
                result[value] = label
                break
    return result


def _goto_label_from_line(line: str) -> str:
    match = re.search(r"\bgoto\s+(?P<label>[A-Za-z_][A-Za-z0-9_]*)\s*;", line or "")
    return match.group("label") if match else ""


def _recover_switch_cases(lines: list[str], dispatcher: str) -> set[int]:
    return set(_recover_switch_case_bodies(lines, dispatcher, keep_empty=True))


def _recover_switch_case_bodies(
    lines: list[str],
    dispatcher: str,
    keep_empty: bool = False,
) -> dict[int, list[str]]:
    bodies: dict[int, list[str]] = {}
    current_case: int | None = None
    current_body: list[str] = []
    in_target_switch = False
    depth = 0

    for line in lines:
        switch_match = SWITCH_RE.search(line)
        if not in_target_switch:
            if switch_match and switch_match.group("var") == dispatcher:
                in_target_switch = True
                depth += line.strip().count("{")
            continue

        stripped = line.strip()
        closes = stripped.count("}")
        if closes:
            depth -= closes
            if depth <= 0:
                if current_case is not None:
                    bodies[current_case] = _trim_case_body(current_body)
                current_case = None
                current_body = []
                in_target_switch = False
                depth = 0
                continue

        case_match = CASE_LABEL_RE.match(line)
        if depth == 1 and case_match:
            if current_case is not None:
                bodies[current_case] = _trim_case_body(current_body)
            current_case = _parse_case_literal(case_match.group("value"))
            current_body = []
            continue

        if depth == 1 and stripped == "default:":
            if current_case is not None:
                bodies[current_case] = _trim_case_body(current_body)
            current_case = None
            current_body = []
            continue

        if current_case is not None and stripped not in {"{", "}"}:
            current_body.append(line.rstrip())

        opens = stripped.count("{")
        if opens:
            depth += opens

    if keep_empty:
        return bodies
    return {case: body for case, body in bodies.items() if body}


def _parse_case_literal(value: str) -> int:
    token = (value or "").strip()
    if token.startswith("'") and token.endswith("'") and len(token) == 3:
        return ord(token[1])
    parsed = _parse_c_integer_literal(token)
    if parsed is None:
        return int(token, 0)
    return parsed


def _parse_c_integer_literal(value: str) -> int | None:
    token = _CASE_INTEGER_SUFFIX_RE.sub("", (value or "").strip())
    try:
        return int(token, 0)
    except ValueError:
        return None


def _trim_case_body(body: list[str]) -> list[str]:
    trimmed = [line.strip() for line in body]
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    return trimmed


def _case_value_for_condition(
    line: str,
    dispatcher: str,
    offsets: dict[str, int],
) -> int | None:
    direct_match = DIRECT_IF_EQ_RE.search(line)
    if direct_match and direct_match.group("var") == dispatcher:
        return int(direct_match.group("value"))

    not_match = NOT_TEMP_RE.search(line)
    if not_match:
        temp = not_match.group("temp")
        if temp in offsets:
            return offsets[temp]

    eq_match = EQ_TEMP_RE.search(line)
    if eq_match:
        temp = eq_match.group("temp")
        if temp in offsets:
            return offsets[temp] + int(eq_match.group("value"))

    return None


def _collect_if_body(lines: list[str], condition_index: int) -> list[str]:
    line = lines[condition_index]
    inline_tail = _inline_if_tail(line)
    if inline_tail:
        return [inline_tail]

    next_index = _next_non_empty_line(lines, condition_index + 1)
    if next_index is None:
        return []

    next_line = lines[next_index].strip()
    if next_line == "{":
        return _collect_braced_body(lines, next_index)
    if next_line.startswith("{"):
        return _collect_braced_body(lines, next_index)
    if next_line.startswith("else"):
        return []
    return [lines[next_index].strip()]


def _inline_if_tail(line: str) -> str:
    close_index = line.rfind(")")
    if close_index < 0:
        return ""
    tail = line[close_index + 1:].strip()
    if tail.startswith("{"):
        return ""
    return tail.rstrip(";") + ";" if tail else ""


def _next_non_empty_line(lines: list[str], start: int) -> int | None:
    for index in range(start, len(lines)):
        if lines[index].strip():
            return index
    return None


def _collect_braced_body(lines: list[str], brace_index: int) -> list[str]:
    body = []
    depth = 0
    started = False

    for index in range(brace_index, len(lines)):
        line = lines[index]
        stripped = line.strip()
        opens = stripped.count("{")
        closes = stripped.count("}")

        if opens:
            depth += opens
            started = True
            if stripped == "{":
                continue

        if started and depth > 0 and stripped not in {"{", "}"}:
            body.append(stripped)

        if closes:
            depth -= closes
            if started and depth <= 0:
                break

    return body
