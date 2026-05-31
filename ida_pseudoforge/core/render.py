from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ida_pseudoforge.core.kernel_api import apply_kernel_api_rewrites, kernel_api_prelude
from ida_pseudoforge.core.kernel_rewrites import apply_kernel_rewrites, apply_known_kernel_struct_rewrites
from ida_pseudoforge.core.normalize import safe_identifier_replace
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render_call_args import (
    rewrite_parameter_low_byte_call_arguments as _rewrite_parameter_low_byte_call_arguments,
)
from ida_pseudoforge.core.render_dispatcher import (
    replace_char_literal_cases as _replace_char_literal_cases,
    rewrite_process_information_class_literals as _rewrite_process_information_class_literals,
    rewrite_system_information_class_literals as _rewrite_system_information_class_literals,
)
from ida_pseudoforge.core.render_flow import (
    is_safe_switch_outline_body as _is_safe_switch_outline_body,
    native_switch_dispatchers as _native_switch_dispatchers,
    render_flow_report,
    render_switch_outline as _render_switch_outline_impl,
)
from ida_pseudoforge.core.render_header import (
    kernel_semantic_rewrite_count as _kernel_semantic_rewrite_count,
    render_header_lines as _render_header_lines,
)
from ida_pseudoforge.core.render_ioctl import (
    annotate_ioctl_code_switch_cases as _annotate_ioctl_code_switch_cases,
    rewrite_device_control_system_buffer as _rewrite_device_control_system_buffer,
    rewrite_irp_stack_location_fields as _rewrite_irp_stack_location_fields,
)
from ida_pseudoforge.core.render_kernel_hints import (
    annotate_kernel_hints as _annotate_kernel_hints,
    has_comment_kind as _has_comment_kind,
    rewrite_critical_region_entry as _rewrite_critical_region_entry,
)
from ida_pseudoforge.core.render_labels import (
    annotate_kernel_labels as _annotate_kernel_labels,
    hoist_embedded_semantic_tail_labels as _hoist_embedded_semantic_tail_labels,
    normalize_semantic_label_indentation as _normalize_semantic_label_indentation,
    rename_kernel_labels as _rename_kernel_labels,
)
from ida_pseudoforge.core.render_literals import (
    escape_path_like_string_literals as _escape_path_like_string_literals,
    finalize_rendered_c_like_text as _finalize_rendered_c_like_text,
)
from ida_pseudoforge.core.render_status import (
    _replace_status_literals,
    _replace_status_returns,
    _upgrade_kernel_status_types,
)
from ida_pseudoforge.core.render_style import enforce_generated_code_style
from ida_pseudoforge.core.render_signatures import (
    apply_known_callback_signature as _apply_known_callback_signature,
    apply_known_function_signature as _apply_known_function_signature,
    apply_known_signature_body_rewrites as _apply_known_signature_body_rewrites,
    find_signature_end as _find_signature_end,
)
from ida_pseudoforge.core.render_warnings import (
    display_warning_count,
    display_warnings as _display_warnings,
)
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

    header = _render_header_lines(
        context.capture,
        context.plan,
        context.rename_map,
        context.display_warnings,
        context.native_switch_dispatchers,
        VERSION,
    )
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


def _safe_file_stem(name: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    return cleaned.strip("._") or "function"
