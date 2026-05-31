from __future__ import annotations

import re

from ida_pseudoforge.core.ioctl import (
    decode_ioctl_code,
    format_ctl_code_from_literal,
    looks_like_ioctl_dispatcher_name,
    parse_c_integer_literal,
)
from ida_pseudoforge.core.kernel_semantics import looks_like_irp_dispatch
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture

_C_INTEGER_SUFFIX_PATTERN = r"(?i:ui64|i64|u?ll|llu|ul|lu|u|l)"
_C_UNSIGNED_INTEGER_LITERAL_PATTERN = r"(?:0x[0-9A-Fa-f]+|\d+)(?:%s)?" % _C_INTEGER_SUFFIX_PATTERN


def irp_dispatch_signature_override(function_name: str) -> list[str]:
    return [
        "NTSTATUS __fastcall %s(" % (function_name or "DriverDispatch"),
        "        PDEVICE_OBJECT deviceObject,",
        "        PIRP irp)",
    ]


def normalize_irp_dispatch_body(text: str) -> str:
    result = re.sub(
        r"(?m)^(\s*)(?:int|unsigned int|ULONG)\s+status(\s*;[^\n]*)$",
        r"\1NTSTATUS status\2",
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^(\s*)(?:__int64|unsigned __int64|int|unsigned int|ULONG)\s+"
        r"(inputBufferLength|outputBufferLength|ioControlCode)(\s*;[^\n]*)$",
        r"\1ULONG \2\3",
        result,
    )
    result = re.sub(
        r"(?m)^(\s*)(?:__int64|unsigned __int64|ULONG_PTR)\s+information(\s*;[^\n]*)$",
        r"\1ULONG_PTR information\2",
        result,
        count=1,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<extension>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"\*\(\s*_QWORD\s+\*\s*\)\s*\(\s*deviceObject\s*\+\s*64\s*\)\s*;",
        r"\g<indent>\g<extension> = deviceObject->DeviceExtension;",
        result,
        count=1,
    )
    result = _rewrite_irp_parameter_aliases(result)
    result = _rewrite_redundant_irp_completion_casts(result)
    result = re.sub(r"\breturn\s+\(\s*unsigned\s+int\s*\)\s*status\s*;", "return status;", result)
    return result


def annotate_ioctl_code_switch_cases(text: str, plan: CleanPlan) -> str:
    dispatcher_names = _ioctl_dispatcher_names(text, plan)
    if not dispatcher_names:
        return text

    case_pattern = re.compile(
        rf"(?m)^(?P<indent>\s*)case\s+(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})(?P<suffix>\s*:)\s*$"
    )

    def replace_case(match: re.Match[str]) -> str:
        annotation = format_ctl_code_from_literal(match.group("value"))
        if not annotation:
            return match.group(0)
        return "%scase %s%s // %s" % (
            match.group("indent"),
            match.group("value"),
            match.group("suffix"),
            annotation,
        )

    switch_pattern = _switch_pattern_for_dispatchers(dispatcher_names)
    lines = text.splitlines()
    result = []
    in_target_switch = False
    seen_open = False
    depth = 0

    for line in lines:
        if not in_target_switch and switch_pattern.search(line):
            in_target_switch = True
            seen_open = False
            depth = 0

        updated = line
        if in_target_switch:
            updated = case_pattern.sub(replace_case, updated)
            stripped = updated.strip()
            opens = stripped.count("{")
            closes = stripped.count("}")
            if opens:
                seen_open = True
                depth += opens
            if closes:
                depth -= closes
                if seen_open and depth <= 0:
                    in_target_switch = False
                    seen_open = False
                    depth = 0

        result.append(updated)

    return "\n".join(result)


def rewrite_device_control_system_buffer(text: str, plan: CleanPlan, capture: FunctionCapture) -> str:
    if not looks_like_irp_dispatch(capture):
        return text
    dispatcher_names = _ioctl_dispatcher_names(text, plan)
    if (
        not dispatcher_names
        or not _has_device_control_stack_evidence(text, dispatcher_names)
        or not _all_ioctl_cases_method_buffered(text, plan, dispatcher_names)
    ):
        return text

    result = text
    assignment_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<buffer>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?P<irp>[A-Za-z_][A-Za-z0-9_]*)->AssociatedIrp\.MasterIrp\s*;"
    )
    for match in assignment_pattern.finditer(text):
        buffer_name = match.group("buffer")
        if "systembuffer" not in buffer_name.lower() and buffer_name != "systemBuffer":
            continue
        escaped = re.escape(buffer_name)
        result = re.sub(
            r"(?m)^(?P<indent>\s*)(?:struct\s+_IRP\s+\*|IRP\s+\*|PIRP\s+)%s(?P<suffix>\s*;[^\n]*)$"
            % escaped,
            r"\g<indent>PVOID %s\g<suffix>" % buffer_name,
            result,
            count=1,
        )
        result = re.sub(
            r"\b%s\s*=\s*%s->AssociatedIrp\.MasterIrp\s*;"
            % (escaped, re.escape(match.group("irp"))),
            "%s = %s->AssociatedIrp.SystemBuffer;" % (buffer_name, match.group("irp")),
            result,
            count=1,
        )
    offset_assignment_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<buffer>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"\*\([^;\n]*\*+\s*\)\s*\(\s*(?P<irp>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*24\s*\)\s*;"
    )
    for match in offset_assignment_pattern.finditer(text):
        buffer_name = match.group("buffer")
        if "systembuffer" not in buffer_name.lower() and buffer_name != "systemBuffer":
            continue
        escaped = re.escape(buffer_name)
        result = re.sub(
            r"(?m)^(?P<indent>\s*)(?:struct\s+[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*|__m128i)"
            r"\s+\*%s(?P<suffix>\s*;[^\n]*)$" % escaped,
            r"\g<indent>PVOID %s\g<suffix>" % buffer_name,
            result,
            count=1,
        )
        result = re.sub(
            r"(?m)^(?P<indent>\s*)%s\s*=\s*\*\([^;\n]*\*+\s*\)\s*\(\s*%s\s*\+\s*24\s*\)\s*;$"
            % (escaped, re.escape(match.group("irp"))),
            r"\g<indent>%s = %s->AssociatedIrp.SystemBuffer;" % (buffer_name, match.group("irp")),
            result,
            count=1,
        )
    return result


def rewrite_irp_stack_location_fields(text: str, plan: CleanPlan, capture: FunctionCapture) -> str:
    if not looks_like_irp_dispatch(capture):
        return text
    dispatcher_names = _ioctl_dispatcher_names(text, plan)
    if not dispatcher_names:
        return text

    result = text
    for stack_name in _dword_irp_stack_location_variables(text):
        if not _looks_like_device_control_irp_stack_usage(text, stack_name, dispatcher_names):
            continue
        result = _rewrite_device_control_irp_stack_location(result, stack_name)
    return result


def _ioctl_dispatcher_names(text: str, plan: CleanPlan) -> set[str]:
    dispatcher_names = {
        flow.dispatcher
        for flow in plan.flow_rewrites
        if looks_like_ioctl_dispatcher_name(flow.dispatcher)
    }
    for rename in plan.renames:
        if rename.apply and looks_like_ioctl_dispatcher_name(rename.new):
            dispatcher_names.add(rename.old)
            dispatcher_names.add(rename.new)
    if re.search(r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*ioControlCode\s*\)", text):
        dispatcher_names.add("ioControlCode")
    return {name for name in dispatcher_names if name}


def _switch_pattern_for_dispatchers(dispatcher_names: set[str]) -> re.Pattern[str]:
    dispatcher_pattern = "|".join(re.escape(name) for name in sorted(dispatcher_names))
    return re.compile(
        r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*\b(?:%s)\b[^)]*\)" % dispatcher_pattern
    )


def _rewrite_redundant_irp_completion_casts(text: str) -> str:
    return re.sub(
        r"\b(Iof?CompleteRequest\s*\()\s*\(\s*(?:PIRP|(?:struct\s+)?_?IRP\s*\*)\s*\)\s*irp\s*,",
        r"\1irp,",
        text,
    )


def _rewrite_irp_parameter_aliases(text: str) -> str:
    lines = text.splitlines()
    declaration_index = -1
    alias = ""
    for index, line in enumerate(lines):
        match = re.match(r"^\s*IRP\s+\*(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*;[^\n]*$", line)
        if match is not None:
            declaration_index = index
            alias = match.group("alias")
            break
    if declaration_index < 0:
        return text
    if re.search(r"\b%s\s*(?:\+|\[)" % re.escape(alias), text):
        return text
    assignment_index = -1
    for index in range(declaration_index + 1, len(lines)):
        stripped = lines[index].strip()
        if re.match(r"%s\s*=\s*\(\s*IRP\s+\*\s*\)irp\s*;" % re.escape(alias), stripped):
            assignment_index = index
            break
        if re.match(r"(?:if|for|while|switch|case|default|goto|return)\b", stripped):
            return text
    if assignment_index < 0:
        return text
    del lines[assignment_index]
    del lines[declaration_index]
    result = "\n".join(lines)
    result = re.sub(r"\b%s(?=\s*->)" % re.escape(alias), "irp", result)
    result = re.sub(r"\bIof?CompleteRequest\s*\(\s*%s\s*," % re.escape(alias), "IofCompleteRequest(irp,", result)
    return result


def _all_ioctl_cases_method_buffered(text: str, plan: CleanPlan, dispatcher_names: set[str]) -> bool:
    if _all_recovered_ioctl_cases_method_buffered(plan, dispatcher_names):
        return True
    found = False
    for dispatcher in dispatcher_names:
        values = _switch_case_values_for_dispatcher(text, dispatcher)
        if not values:
            continue
        found = True
        for value in values:
            decoded = decode_ioctl_code(value)
            if decoded is None or decoded.method != 0:
                return False
    return found


def _all_recovered_ioctl_cases_method_buffered(plan: CleanPlan, dispatcher_names: set[str]) -> bool:
    found = False
    for flow in plan.flow_rewrites:
        if flow.dispatcher not in dispatcher_names and not looks_like_ioctl_dispatcher_name(flow.dispatcher):
            continue
        for value in flow.recovered_cases:
            decoded = decode_ioctl_code(value)
            if decoded is None or decoded.method != 0:
                return False
            found = True
    return found


def _switch_case_values_for_dispatcher(text: str, dispatcher: str) -> list[int]:
    switch_match = re.search(
        r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*%s\s*\)" % re.escape(dispatcher),
        text,
    )
    if switch_match is None:
        return []
    open_index = text.find("{", switch_match.end())
    if open_index < 0:
        return []
    depth = 0
    end_index = -1
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end_index = index
                break
    if end_index < 0:
        return []
    values: list[int] = []
    body = text[open_index:end_index]
    for match in re.finditer(r"\bcase\s+(?P<value>%s)\s*:" % _C_UNSIGNED_INTEGER_LITERAL_PATTERN, body):
        value = parse_c_integer_literal(match.group("value"))
        if value is not None:
            values.append(value)
    return values


def _has_device_control_stack_evidence(text: str, dispatcher_names: set[str]) -> bool:
    for stack_name in _dword_irp_stack_location_variables(text):
        if _looks_like_device_control_irp_stack_usage(text, stack_name, dispatcher_names):
            return True
    for dispatcher in dispatcher_names:
        escaped = re.escape(dispatcher)
        if re.search(
            r"\b%s\s*=\s*[A-Za-z_][A-Za-z0-9_]*->Parameters\.DeviceIoControl\.IoControlCode\s*;"
            % escaped,
            text,
        ):
            return True
    return False


def _dword_irp_stack_location_variables(text: str) -> list[str]:
    variables: list[str] = []
    for match in re.finditer(
        r"(?m)^\s*(?:_DWORD|unsigned\s+int|ULONG)\s+\*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;[^\n]*$",
        text,
    ):
        name = match.group("name")
        lowered = name.lower()
        if ("stack" in lowered and "location" in lowered) or _looks_like_device_control_irp_stack_usage(text, name):
            variables.append(name)
    return variables


def _looks_like_device_control_irp_stack_usage(
    text: str,
    stack_name: str,
    dispatcher_names: set[str] | None = None,
) -> bool:
    escaped = re.escape(stack_name)
    match = re.search(
        r"(?m)^\s*(?P<dispatcher>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*\[\s*6\s*\]\s*;" % escaped,
        text,
    )
    if match is None:
        return False
    dispatcher = match.group("dispatcher")
    if dispatcher_names and dispatcher in dispatcher_names:
        return True
    return re.search(
        r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*%s\s*\)" % re.escape(dispatcher),
        text,
    ) is not None


def _rewrite_device_control_irp_stack_location(text: str, stack_name: str) -> str:
    escaped = re.escape(stack_name)
    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?:_DWORD|unsigned\s+int|ULONG)\s+\*%s(?P<suffix>\s*;[^\n]*)$" % escaped,
        r"\g<indent>PIO_STACK_LOCATION %s\g<suffix>" % stack_name,
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^(?P<prefix>\s*%s\s*=\s*)\(\s*_DWORD\s+\*\s*\)(?P<call>\s*[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n]*\)\s*;)"
        % escaped,
        r"\g<prefix>(PIO_STACK_LOCATION)\g<call>",
        result,
        count=1,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*=\s*\*\([^;\n]*\*+\s*\)\s*\(\s*(?P<irp>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*184\s*\)\s*;$"
        % escaped,
        r"\g<indent>%s = \g<irp>->Tail.Overlay.CurrentStackLocation;" % stack_name,
        result,
        count=1,
    )
    field_map = {
        "2": "OutputBufferLength",
        "4": "InputBufferLength",
        "6": "IoControlCode",
    }
    for index, field_name in field_map.items():
        result = re.sub(
            r"\b%s\s*\[\s*%s\s*\]" % (escaped, index),
            "%s->Parameters.DeviceIoControl.%s" % (stack_name, field_name),
            result,
        )
    return result
