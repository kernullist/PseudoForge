from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ida_pseudoforge.core.api_semantics import FUNCTION_SIGNATURE_OVERRIDES
from ida_pseudoforge.core.kernel_api import apply_kernel_api_rewrites, kernel_api_prelude
from ida_pseudoforge.core.kernel_rewrites import apply_kernel_rewrites, apply_known_kernel_struct_rewrites
from ida_pseudoforge.core.kernel_semantics import (
    looks_like_callback_registration_toggle,
    looks_like_driver_entry,
    looks_like_irp_dispatch,
    looks_like_registry_callback_registration,
    looks_like_zw_api_probe,
)
from ida_pseudoforge.core.normalize import extract_parameters_from_signature, safe_identifier_replace
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render_callbacks import (
    apply_known_callback_signature as _apply_known_callback_signature_impl,
    normalize_callback_registration_toggle_body as _normalize_callback_registration_toggle_body,
    normalize_registry_callback_registration_body as _normalize_registry_callback_registration_body,
)
from ida_pseudoforge.core.render_dispatcher import (
    replace_char_literal_cases as _replace_char_literal_cases,
    rewrite_process_information_class_literals as _rewrite_process_information_class_literals,
    rewrite_system_information_class_literals as _rewrite_system_information_class_literals,
)
from ida_pseudoforge.core.render_driver_entry import (
    driver_entry_signature_override as _driver_entry_signature_override,
    normalize_driver_entry_body as _normalize_driver_entry_body,
)
from ida_pseudoforge.core.render_flow import (
    format_flow_case_value as _format_flow_case_value,
    is_safe_switch_outline_body as _is_safe_switch_outline_body,
    native_switch_dispatchers as _native_switch_dispatchers,
    render_flow_report,
    render_switch_outline as _render_switch_outline_impl,
)
from ida_pseudoforge.core.render_ioctl import (
    annotate_ioctl_code_switch_cases as _annotate_ioctl_code_switch_cases,
    irp_dispatch_signature_override as _irp_dispatch_signature_override,
    normalize_irp_dispatch_body as _normalize_irp_dispatch_body,
    rewrite_device_control_system_buffer as _rewrite_device_control_system_buffer,
    rewrite_irp_stack_location_fields as _rewrite_irp_stack_location_fields,
)
from ida_pseudoforge.core.render_labels import (
    annotate_kernel_labels as _annotate_kernel_labels,
    hoist_embedded_semantic_tail_labels as _hoist_embedded_semantic_tail_labels,
    normalize_semantic_label_indentation as _normalize_semantic_label_indentation,
    rename_kernel_labels as _rename_kernel_labels,
    semantic_label_display as _semantic_label_display,
    semantic_label_map as _semantic_label_map,
    semantic_label_name as _semantic_label_name,
)
from ida_pseudoforge.core.render_literals import (
    escape_path_like_string_literals as _escape_path_like_string_literals,
    finalize_rendered_c_like_text as _finalize_rendered_c_like_text,
)
from ida_pseudoforge.core.render_status import (
    _has_status_accumulator,
    _replace_status_literals,
    _replace_status_returns,
    _upgrade_kernel_status_types,
)
from ida_pseudoforge.core.render_style import enforce_generated_code_style
from ida_pseudoforge.core.render_ntset import (
    normalize_ntset_system_information_body as _normalize_ntset_system_information_body,
)
from ida_pseudoforge.core.render_warnings import (
    display_warning_count,
    display_warnings as _display_warnings,
    format_warning as _format_warning,
)
from ida_pseudoforge.core.render_zw import normalize_zw_api_probe_body as _normalize_zw_api_probe_body
from ida_pseudoforge.version import VERSION


@dataclass(slots=True)
class RenderContext:
    capture: FunctionCapture
    plan: CleanPlan
    rename_map: dict[str, str]
    display_warnings: list[object]
    native_switch_dispatchers: set[str]

    @classmethod
    def from_plan(cls, capture: FunctionCapture, plan: CleanPlan) -> RenderContext:
        return cls(
            capture=capture,
            plan=plan,
            rename_map={item.old: item.new for item in plan.renames if item.apply},
            display_warnings=_display_warnings(plan),
            native_switch_dispatchers=set(),
        )

    def with_native_switch_metadata(self, text: str) -> RenderContext:
        return RenderContext(
            capture=self.capture,
            plan=self.plan,
            rename_map=self.rename_map,
            display_warnings=_display_warnings(self.plan),
            native_switch_dispatchers=_native_switch_dispatchers(text, self.plan),
        )


def render_cleaned_pseudocode(capture: FunctionCapture, plan: CleanPlan) -> str:
    context = RenderContext.from_plan(capture, plan)
    text = safe_identifier_replace(capture.pseudocode, context.rename_map)
    text = _replace_status_literals(text, capture, plan)
    text = apply_kernel_rewrites(text, plan)
    text = apply_kernel_api_rewrites(text)
    text = _upgrade_kernel_status_types(text, capture, plan)
    text = _apply_known_function_signature(text, capture)
    text = _apply_known_callback_signature(text, capture)
    text = _apply_known_signature_body_rewrites(text, capture)
    text = apply_known_kernel_struct_rewrites(text, capture)
    text = _rewrite_device_control_system_buffer(text, plan, capture)
    text = _rewrite_irp_stack_location_fields(text, plan, capture)
    text = _rewrite_system_information_class_literals(text)
    text = _rewrite_process_information_class_literals(text)
    text = _annotate_ioctl_code_switch_cases(text, plan)
    text = _rewrite_parameter_low_byte_call_arguments(text)
    text = _replace_char_literal_cases(text)
    text = _escape_path_like_string_literals(text)
    text = _rewrite_critical_region_entry(text, plan)
    text = _annotate_kernel_hints(text, plan)
    text = _rename_kernel_labels(text, plan)
    text = _annotate_kernel_labels(text, plan)
    text = enforce_generated_code_style(text, capture)
    text = _normalize_semantic_label_indentation(text, plan)
    text = _hoist_embedded_semantic_tail_labels(text, plan)
    prelude = kernel_api_prelude(text)
    if prelude:
        text = prelude + text
    context = context.with_native_switch_metadata(text)

    header = [
        "/*",
        "    Generated by PseudoForge.",
        f"    Version: {VERSION}",
        "    Preview/export only. IDB was not modified.",
        f"    Function: {context.capture.name}",
        f"    Fingerprint: {context.plan.input_fingerprint}",
        f"    Rename candidates: {len(context.rename_map)}",
        f"    Flow rewrites: {len(context.plan.flow_rewrites)}",
        f"    Kernel semantic rewrites: {_kernel_semantic_rewrite_count(context.plan)}",
        f"    Warnings: {len(context.display_warnings)}",
    ]

    if context.plan.flow_rewrites:
        for flow in context.plan.flow_rewrites:
            cases = ", ".join(_format_flow_case_value(flow, value) for value in flow.recovered_cases[:64])
            if len(flow.recovered_cases) > 64:
                cases += ", ..."
            source_suffix = ""
            if flow.dispatcher in context.native_switch_dispatchers:
                source_suffix = " source=native_switch outline=suppressed"
            header.append(
                f"    Flow: {flow.kind} dispatcher={flow.dispatcher} cases=[{cases}] "
                f"confidence={flow.confidence:.2f}{source_suffix}"
            )

    if context.plan.comments:
        header.append("    Kernel insights:")
        for comment in context.plan.comments[:16]:
            kind = _ascii_comment_text(str(comment.get("kind", "kernel")))
            confidence = float(comment.get("confidence", 0.0))
            text_value = _ascii_comment_text(str(comment.get("text", "")))
            header.append(f"      - {kind}: {text_value} confidence={confidence:.2f}")

    if context.plan.cleanup_labels:
        header.append("    Label roles:")
        semantic_label_map = _semantic_label_map(context.plan)
        for label in context.plan.cleanup_labels[:16]:
            display_label = _semantic_label_display(label.label, label.classification, semantic_label_map)
            evidence = _ascii_comment_text(label.evidence)
            header.append(
                f"      - {display_label}: {label.classification} confidence={label.confidence:.2f} "
                f"({evidence})"
            )

    if context.display_warnings:
        header.append("    Warning detail:")
        for warning in context.display_warnings[:8]:
            header.append(f"      - {_format_warning(warning)}")
        if len(context.display_warnings) > 8:
            header.append(f"      - ... {len(context.display_warnings) - 8} more warning(s)")

    if context.rename_map:
        rename_items = {item.old: item for item in context.plan.renames if item.apply}
        pairs = ", ".join(
            f"{old}->{item.new}({item.confidence:.2f},{item.source})"
            for old, item in sorted(rename_items.items())
        )
        header.append(f"    Renames: {pairs}")

    header.append("*/")
    body_sections = []
    if context.plan.flow_rewrites:
        body_sections.append(
            "/*\n"
            "    PseudoForge normalized original pseudocode.\n"
            "*/\n\n"
            + text
        )
        body_sections.append(
            "/*\n"
            "    PseudoForge recovered switch view.\n"
            "    Auxiliary dispatcher outline; review with the normalized original pseudocode above.\n"
            "*/\n\n"
            + render_switch_outline(context.capture, context.plan, rendered_text=text).rstrip()
        )
    else:
        body_sections.append(text)
    return _finalize_rendered_c_like_text("\n".join(header) + "\n\n" + "\n\n".join(body_sections))


def write_export_bundle(
    output_dir: str | Path,
    capture: FunctionCapture,
    plan: CleanPlan,
    entrypoint: str = "export_bundle",
    summary_suffix: str = "summary",
) -> dict[str, str]:
    from ida_pseudoforge.core.export_bundle import write_export_bundle as _write_export_bundle

    return _write_export_bundle(
        output_dir,
        capture,
        plan,
        entrypoint=entrypoint,
        summary_suffix=summary_suffix,
    )


def render_switch_outline(
    capture: FunctionCapture,
    plan: CleanPlan,
    rendered_text: str | None = None,
) -> str:
    return _finalize_rendered_c_like_text(_render_switch_outline_impl(capture, plan, rendered_text=rendered_text))


def _apply_known_function_signature(text: str, capture: FunctionCapture) -> str:
    override = FUNCTION_SIGNATURE_OVERRIDES.get(capture.name)
    if not override and looks_like_driver_entry(capture):
        override = _driver_entry_signature_override()
    if not override and looks_like_irp_dispatch(capture):
        override = _irp_dispatch_signature_override(capture.name or extract_function_name(capture.prototype))
    if not override:
        return text

    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\b%s\s*\(" % re.escape(capture.name), line):
            end_index = _find_signature_end(lines, index)
            if end_index < index:
                return text
            lines = lines[:index] + override + lines[end_index + 1 :]
            return "\n".join(lines)
    return text


def _apply_known_callback_signature(text: str, capture: FunctionCapture) -> str:
    return _apply_known_callback_signature_impl(text, capture, _find_signature_end)


def _apply_known_signature_body_rewrites(text: str, capture: FunctionCapture) -> str:
    if capture.name != "NtSetSystemInformation":
        if looks_like_driver_entry(capture):
            return _normalize_driver_entry_body(text)
        if looks_like_irp_dispatch(capture):
            return _normalize_irp_dispatch_body(text)
        if looks_like_callback_registration_toggle(capture):
            return _normalize_callback_registration_toggle_body(text, capture)
        if looks_like_registry_callback_registration(capture):
            return _normalize_registry_callback_registration_body(text)
        if looks_like_zw_api_probe(capture):
            return _normalize_zw_api_probe_body(text)
        return text
    return _normalize_ntset_system_information_body(text)


def _rewrite_parameter_low_byte_call_arguments(text: str) -> str:
    parameter_names = _rendered_parameter_names(text)
    if not parameter_names:
        return text

    lines = text.splitlines()
    result = []
    index = 0
    while index < len(lines):
        match = re.match(
            r"^(?P<indent>\s*)LOBYTE\(\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*(?P<expr>[^;\n]+);\s*$",
            lines[index],
        )
        if not match or match.group("target") not in parameter_names or index + 1 >= len(lines):
            result.append(lines[index])
            index += 1
            continue

        rewritten = _replace_call_argument_low_byte(lines[index + 1], match.group("target"), match.group("expr").strip())
        if rewritten == lines[index + 1]:
            result.append(lines[index])
            index += 1
            continue

        result.append(rewritten)
        index += 2

    return "\n".join(result)


def _rendered_parameter_names(text: str) -> set[str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "(" not in line:
            continue
        end_index = _find_signature_end(lines, index)
        if end_index < index:
            continue
        signature = "\n".join(lines[index : end_index + 1])
        if "{" in signature or ";" in signature:
            continue
        params = extract_parameters_from_signature(signature)
        if params:
            return {name for name, _type_text in params}
    return set()


def _replace_call_argument_low_byte(line: str, target: str, expr: str) -> str:
    if "(" not in line or ")" not in line:
        return line
    replacement = "(unsigned __int8)%s" % expr
    pattern = re.compile(r"(?P<prefix>[(,]\s*)%s(?P<suffix>\s*[,)])" % re.escape(target))
    updated = pattern.sub(lambda match: match.group("prefix") + replacement + match.group("suffix"), line)
    return updated


def _find_signature_end(lines: list[str], start_index: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_index, len(lines)):
        for char in lines[index]:
            if char == "(":
                depth += 1
                seen_open = True
            elif char == ")":
                depth -= 1
                if seen_open and depth <= 0:
                    return index
    return -1


def _rewrite_critical_region_entry(text: str, plan: CleanPlan) -> str:
    if not _has_comment_kind(plan, "critical_region"):
        return text

    matched_var = ""

    def repl(match: re.Match[str]) -> str:
        nonlocal matched_var
        matched_var = match.group("var")
        return match.group("indent") + "KeEnterCriticalRegion();"

    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<var>[A-Za-z_][A-Za-z0-9_]*) = KeGetCurrentThread\(\);\n"
        r"(?P=indent)--(?P=var)->KernelApcDisable;",
        repl,
        text,
        count=1,
    )
    if matched_var and matched_var not in _strip_declaration_for_var(result, matched_var):
        result = re.sub(
            r"(?m)^\s*struct _KTHREAD \*%s\s*;[^\n]*\n" % re.escape(matched_var),
            "",
            result,
            count=1,
        )
    return result


def _strip_declaration_for_var(text: str, name: str) -> str:
    return re.sub(
        r"(?m)^\s*(?:struct\s+)?[A-Za-z_][A-Za-z0-9_\s]*\*?\s*%s\s*;[^\n]*$" % re.escape(name),
        "",
        text,
    )


def _has_comment_kind(plan: CleanPlan, kind: str) -> bool:
    return any(str(comment.get("kind", "")) == kind for comment in plan.comments)


def _kernel_semantic_rewrite_count(plan: CleanPlan) -> int:
    count = 0
    rewrite_comment_kinds = {
        "callback_registration",
        "critical_region",
        "device_extension_layout",
        "driver_dispatch_table",
        "driver_entry",
        "inferred_record_layout",
        "list_entry_insert_tail",
        "list_entry_unlink",
        "memory_manager_probe",
        "pool_tag",
        "registry_callback_registration",
        "zw_api_probe",
    }
    for comment in plan.comments:
        if str(comment.get("kind", "")) in rewrite_comment_kinds:
            count += 1
    count += len([label for label in plan.cleanup_labels if _semantic_label_name(label.classification)])
    if _has_status_accumulator(plan):
        count += 1
    return count


def _annotate_kernel_hints(text: str, plan: CleanPlan) -> str:
    comment_kinds = {str(comment.get("kind", "")) for comment in plan.comments}
    if not comment_kinds:
        return text
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        indent = line[: len(line) - len(line.lstrip())]
        if "list_entry_unlink" in comment_kinds and _is_list_unlink_assignment(stripped):
            lines.append(indent + "// PseudoForge: validated RemoveEntryList(providerLink).")
        if "list_entry_insert_tail" in comment_kinds and _is_list_insert_tail_assignment(stripped):
            if "providerListHead" in stripped:
                lines.append(indent + "// PseudoForge: validated InsertTailList(providerListHead, newProviderLink).")
            else:
                lines.append(indent + "// PseudoForge: InsertTailList(&ExpFirmwareTableProviderListHead, newProviderLink).")
        lines.append(line)
        if "inferred_record_layout" in comment_kinds and _is_provider_link_assignment(stripped):
            if "CONTAINING_RECORD(providerLink" in stripped:
                lines.append(indent + "// PseudoForge: providerRecord owns providerLink at Link offset +0x18.")
            else:
                lines.append(indent + "// PseudoForge: providerLink is providerRecord->Link at offset +0x18.")
    return "\n".join(lines)


def _is_provider_link_assignment(stripped: str) -> bool:
    return (
        re.match(r"providerLink\s*=\s*providerRecord\s*\+\s*6\s*;", stripped) is not None
        or stripped == "providerLink = &providerRecord->Link;"
        or stripped.startswith("providerRecord = CONTAINING_RECORD(providerLink, ")
    )


def _is_list_unlink_assignment(stripped: str) -> bool:
    return stripped in {
        "*previousLink = nextLink;",
        "previousLink->Flink = nextLink;",
        "RemoveEntryList(providerLink);",
    }


def _is_list_insert_tail_assignment(stripped: str) -> bool:
    return stripped in {
        "*newProviderLink = &ExpFirmwareTableProviderListHead;",
        "newProviderLink->Flink = &ExpFirmwareTableProviderListHead;",
        "InsertTailList(providerListHead, newProviderLink);",
    }


def _safe_file_stem(name: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return cleaned.strip("._") or "function"


def _ascii_comment_text(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")
