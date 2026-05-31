from __future__ import annotations

import re
from collections.abc import Callable

from ida_pseudoforge.core.normalize import extract_parameters_from_signature
from ida_pseudoforge.core.plan_schema import FunctionCapture


def apply_known_callback_signature(
    text: str,
    capture: FunctionCapture,
    find_signature_end: Callable[[list[str], int], int],
) -> str:
    if not capture.name or not _looks_like_object_pre_operation_callback(capture):
        return text
    if len(extract_parameters_from_signature(capture.prototype)) != 2:
        return text

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\b%s\s*\(" % re.escape(capture.name), line):
            end_index = find_signature_end(lines, index)
            if end_index < index:
                return text
            signature_text = " ".join(item.strip() for item in lines[index : end_index + 1])
            params = extract_parameters_from_signature(signature_text)
            context_name = "registrationContext"
            if params:
                context_name = _stable_callback_parameter_name(params[0][0], "registrationContext")
            override = [
                "OB_PREOP_CALLBACK_STATUS __fastcall %s(" % capture.name,
                "        PVOID %s," % context_name,
                "        POB_PRE_OPERATION_INFORMATION preOperationInfo)",
            ]
            lines = lines[:index] + override + lines[end_index + 1 :]
            return _rewrite_ob_preop_success_returns("\n".join(lines))
    return text


def normalize_callback_registration_toggle_body(text: str, capture: FunctionCapture) -> str:
    result = re.sub(
        r"(?m)^(?:__int64|int|unsigned\s+int|NTSTATUS)(\s+__fastcall\s+%s\s*\()"
        % re.escape(capture.name),
        r"NTSTATUS\1",
        text,
        count=1,
    )
    result = re.sub(r"\bchar\s+enable\b", "BOOLEAN enable", result, count=1)
    result = re.sub(
        r"\breturn\s+\(\s*unsigned\s+int\s*\)\s*(?P<status>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        r"return \g<status>;",
        result,
        count=1,
    )
    return result


def normalize_registry_callback_registration_body(text: str) -> str:
    result = re.sub(r"\bregisterExStatus\s*>=\s*0\b", "NT_SUCCESS(registerExStatus)", text)
    result = re.sub(r"\bregisterStatus\s*>=\s*0\b", "NT_SUCCESS(registerStatus)", result)
    return result


def _stable_callback_parameter_name(name: str, fallback: str) -> str:
    if re.fullmatch(r"(?:a\d+|argument\d+)", name or ""):
        return fallback
    return name or fallback


def _rewrite_ob_preop_success_returns(text: str) -> str:
    return re.sub(r"\breturn\s+0(?:LL|i64|L|u|U)?\s*;", "return OB_PREOP_SUCCESS;", text)


def _looks_like_object_pre_operation_callback(capture: FunctionCapture) -> bool:
    function_name = capture.name or ""
    if function_name.endswith("ObjectPreOperation"):
        return True
    if _has_known_ob_pre_operation_signature(capture):
        return True
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 2:
        return False
    operation_info = params[1][0]
    return _has_ob_pre_operation_field_evidence(capture.pseudocode, operation_info)


def _has_known_ob_pre_operation_signature(capture: FunctionCapture) -> bool:
    prototype = capture.prototype or ""
    if "OB_PREOP_CALLBACK_STATUS" in prototype and "PRE_OPERATION" in prototype:
        return True
    return False


def _has_ob_pre_operation_field_evidence(text: str, variable: str) -> bool:
    escaped = re.escape(variable)
    operation_check = re.search(
        r"\*\(_DWORD\s+\*\)\s*%s\b\s*==\s*[12]\b" % escaped,
        text,
    )
    desired_access_load = re.search(
        r"\*\(_DWORD\s+\*\)\(\s*(?:\*\(_QWORD\s+\*\)\(\s*%s\s*\+\s*32(?:LL|i64|L)?\s*\)|"
        r"\*\(\(_QWORD\s+\*\)\s*%s\s*\+\s*4\s*\))\s*\+\s*4(?:LL|i64|L)?\s*\)"
        % (escaped, escaped),
        text,
    )
    object_load = re.search(
        r"\*\(\(\s*PEPROCESS\s+\*\s*\)\s*%s\s*\+\s*1\s*\)" % escaped,
        text,
    )
    return bool(operation_check and (desired_access_load or object_load))
