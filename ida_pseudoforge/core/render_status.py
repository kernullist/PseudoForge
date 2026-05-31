from __future__ import annotations

import re

from ida_pseudoforge.core.api_semantics import FUNCTION_SIGNATURE_OVERRIDES, NTSTATUS_RETURN_MAP
from ida_pseudoforge.core.kernel_semantics import looks_like_driver_entry, looks_like_irp_dispatch
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture


def _replace_status_returns(text: str) -> str:
    return _replace_status_literals(text, None)


def _replace_status_literals(text: str, capture: FunctionCapture | None, plan: CleanPlan | None = None) -> str:
    result = text
    status_function = _looks_like_status_function(capture, result)
    status_zero_return = _allows_zero_status_return(capture)
    status_zero_assignment = _allows_zero_status_assignment(capture, plan)
    result = _replace_status_context(
        result,
        re.compile(
            r"(?P<prefix>\breturn\s+)(?P<cast>\([A-Za-z_][A-Za-z0-9_\s\*]*\)\s*)?"
            r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
        ),
        allow_zero=status_zero_return,
    )
    result = _replace_status_context(
        result,
        re.compile(
            r"(?P<prefix>\b(?:status|updated|result|returnStatus|ntStatus)\s*=\s*)(?P<cast>\([^)]+\)\s*)?"
            r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
        ),
        allow_zero=status_function and status_zero_assignment,
    )
    result = _replace_32bit_error_status_literals(result, capture)
    return result


def _replace_status_context(text: str, pattern: re.Pattern[str], allow_zero: bool) -> str:
    def repl(match: re.Match[str]) -> str:
        literal = match.group("literal")
        name = _status_name_for_literal(literal, allow_zero=allow_zero)
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("end")

    return pattern.sub(repl, text)


def _replace_32bit_error_status_literals(text: str, capture: FunctionCapture | None) -> str:
    result = text
    four_byte_targets = _four_byte_scalar_names(result, capture)

    if four_byte_targets:
        assignment_pattern = re.compile(
            r"(?P<prefix>\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)"
            r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
        )

        def replace_assignment(match: re.Match[str]) -> str:
            if match.group("target") not in four_byte_targets:
                return match.group(0)
            name = _error_status_name_for_literal(match.group("literal"))
            if not name:
                return match.group(0)
            return match.group("prefix") + name + match.group("end")

        result = assignment_pattern.sub(replace_assignment, result)

    store_pattern = re.compile(
        r"(?m)(?P<prefix>^[ \t]*\*\(_DWORD\s+\*\)[^=\n]+?=\s*)"
        r"(?P<literal>-?(?:0x[0-9A-Fa-f]+|\d+))(?P<suffix>u?LL|ULL|LL|u|U|L)?(?P<end>\s*;)"
    )

    def replace_store(match: re.Match[str]) -> str:
        name = _error_status_name_for_literal(match.group("literal"))
        if not name:
            return match.group(0)
        return match.group("prefix") + name + match.group("end")

    return store_pattern.sub(replace_store, result)


def _four_byte_scalar_names(text: str, capture: FunctionCapture | None) -> set[str]:
    names: set[str] = set()
    if capture is not None:
        for local in capture.lvars:
            if _is_four_byte_scalar_type(local.type):
                names.add(local.name)

    declaration_pattern = re.compile(
        r"(?m)^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_\s]*?)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=|\[)"
    )
    for match in declaration_pattern.finditer(text):
        if _is_four_byte_scalar_type(match.group("type")):
            names.add(match.group("name"))
    return names


def _is_four_byte_scalar_type(type_text: str) -> bool:
    if "*" in type_text or "&" in type_text:
        return False
    normalized = re.sub(r"\b(?:const|volatile|signed)\b", " ", type_text, flags=re.IGNORECASE)
    normalized = re.sub(r"\s+", " ", normalized).strip().upper()
    return normalized in {
        "_DWORD",
        "INT",
        "UNSIGNED INT",
        "LONG",
        "ULONG",
        "DWORD",
        "NTSTATUS",
        "ACCESS_MASK",
        "__INT32",
        "UNSIGNED __INT32",
        "INT32_T",
        "UINT32_T",
    }


def _error_status_name_for_literal(literal: str) -> str:
    value = _parse_numeric_literal(literal)
    if value is None:
        return ""
    unsigned_value = value & 0xFFFFFFFF
    if (unsigned_value & 0xF0000000) != 0xC0000000:
        return ""
    return _status_name_for_literal(literal, allow_zero=False)


def _status_name_for_literal(literal: str, allow_zero: bool) -> str:
    value = _parse_numeric_literal(literal)
    if value is None:
        return ""
    if value == 0 and not allow_zero:
        return ""
    candidates = [str(value), literal]
    if value < 0:
        candidates.append(str(value & 0xFFFFFFFF))
    else:
        unsigned_value = value & 0xFFFFFFFF
        candidates.append(str(unsigned_value))
        if unsigned_value & 0x80000000:
            candidates.append(str(unsigned_value - 0x100000000))
        candidates.append("0x%08X" % unsigned_value)
        candidates.append("0x%X" % unsigned_value)
    for candidate in candidates:
        name = NTSTATUS_RETURN_MAP.get(candidate)
        if name:
            return name
    return ""


def _parse_numeric_literal(literal: str) -> int | None:
    try:
        if literal.lower().startswith("-0x"):
            return -int(literal[3:], 16)
        if literal.lower().startswith("0x"):
            return int(literal, 16)
        return int(literal, 10)
    except ValueError:
        return None


def _looks_like_status_function(capture: FunctionCapture | None, text: str) -> bool:
    if capture is not None and "NTSTATUS" in (capture.prototype or ""):
        return True
    return any(literal in text for literal in ("-107374", "322122", "STATUS_"))


def _allows_zero_status_return(capture: FunctionCapture | None) -> bool:
    if capture is None:
        return False
    prototype = capture.prototype or ""
    if "NTSTATUS" in prototype:
        return True
    if looks_like_driver_entry(capture):
        return True
    if looks_like_irp_dispatch(capture):
        return True
    if capture.name in FUNCTION_SIGNATURE_OVERRIDES:
        return True
    return bool(re.match(r"^(?:Nt|Zw)[A-Z_]", capture.name or ""))


def _allows_zero_status_assignment(capture: FunctionCapture | None, plan: CleanPlan | None) -> bool:
    if _allows_zero_status_return(capture):
        return True
    if plan is None:
        return False
    return any(
        item.apply and item.new == "status" and item.source == "kernel-status"
        for item in plan.renames
    )


def _upgrade_kernel_status_types(text: str, capture: FunctionCapture, plan: CleanPlan) -> str:
    if "STATUS_" not in text or not _has_status_accumulator(plan):
        return text
    result = re.sub(
        r"(?m)^__int64(\s+__fastcall\s+%s\s*\()" % re.escape(capture.name),
        r"NTSTATUS\1",
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^(\s*)(?:unsigned int|ULONG) status(\s*;[^\n]*)$",
        r"\1NTSTATUS status\2",
        result,
        count=1,
    )
    return result


def _has_status_accumulator(plan: CleanPlan) -> bool:
    return any(
        item.apply and item.new == "status" and item.source in {"kernel-status", "semantic-rule"}
        for item in plan.renames
    )
