from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

from ida_pseudoforge.core.buffer_contracts import (
    buffer_contracts_json_payload,
    render_buffer_contract_report,
    render_buffer_struct_header,
)
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render import (
    render_cleaned_pseudocode,
    render_flow_report,
    render_switch_outline,
)
from ida_pseudoforge.core.rule_diagnostics import summarize_rule_report
from ida_pseudoforge.profiles.loader import (
    active_profile_manifests,
    active_profile_names,
    active_profile_root,
    profile_load_warnings,
)
from ida_pseudoforge.version import VERSION


def write_export_bundle(
    output_dir: str | Path,
    capture: FunctionCapture,
    plan: CleanPlan,
    entrypoint: str = "export_bundle",
    summary_suffix: str = "summary",
    cleaned_text: str | None = None,
    extra_summary: dict[str, object] | None = None,
    file_stem: str | None = None,
) -> dict[str, str]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    safe_name = safe_artifact_stem(
        file_stem or capture.name or "function",
        digest_source="%X:%s" % (capture.ea, capture.name or file_stem or "function"),
    )

    cleaned_path = output_path / f"{safe_name}.cleaned.cpp"
    switch_outline_path = output_path / f"{safe_name}.switch-outline.cpp"
    rename_map_path = output_path / f"{safe_name}.rename-map.json"
    flow_report_path = output_path / f"{safe_name}.flow-report.md"
    buffer_contract_report_path = output_path / f"{safe_name}.buffer-contracts.md"
    buffer_contract_json_path = output_path / f"{safe_name}.buffer-contracts.json"
    buffer_struct_header_path = output_path / f"{safe_name}.buffer-structs.hpp"
    rule_report_path = output_path / f"{safe_name}.rule-report.json"
    raw_path = output_path / f"{safe_name}.raw.cpp"
    warnings_path = output_path / f"{safe_name}.warnings.json"
    diff_path = output_path / f"{safe_name}.raw-vs-cleaned.diff"
    summary_path = output_path / f"{safe_name}.{safe_artifact_stem(summary_suffix or 'summary', 48)}.json"

    if cleaned_text is None:
        cleaned_text = render_cleaned_pseudocode(capture, plan)
    raw_text = capture.pseudocode.rstrip() + "\n"
    switch_outline_text = render_switch_outline(capture, plan)
    flow_report_text = render_flow_report(capture, plan)
    buffer_contract_report_text = render_buffer_contract_report(capture, plan.buffer_contracts)
    buffer_struct_header_text = render_buffer_struct_header(capture, plan.buffer_contracts)
    warnings = _combined_export_warnings(plan)

    cleaned_path.write_text(cleaned_text, encoding="utf-8")
    switch_outline_path.write_text(switch_outline_text, encoding="utf-8")
    rename_map_path.write_text(
        json.dumps(plan.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    flow_report_path.write_text(flow_report_text, encoding="utf-8")
    buffer_contract_report_path.write_text(buffer_contract_report_text, encoding="utf-8")
    buffer_contract_json_path.write_text(
        json.dumps(buffer_contracts_json_payload(plan.buffer_contracts), indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    buffer_struct_header_path.write_text(buffer_struct_header_text, encoding="utf-8")
    rule_report_path.write_text(
        json.dumps(plan.rule_report or {}, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    raw_path.write_text(raw_text, encoding="utf-8")
    warnings_path.write_text(json.dumps(warnings, indent=2, ensure_ascii=True), encoding="utf-8")
    diff_path.write_text(_raw_vs_cleaned_diff(safe_name, raw_text, cleaned_text), encoding="utf-8")

    artifacts = {
        "cleaned_pseudocode": str(cleaned_path),
        "switch_outline": str(switch_outline_path),
        "rename_map": str(rename_map_path),
        "flow_report": str(flow_report_path),
        "buffer_contract_report": str(buffer_contract_report_path),
        "buffer_contracts": str(buffer_contract_json_path),
        "buffer_structs": str(buffer_struct_header_path),
        "rule_report": str(rule_report_path),
        "raw_pseudocode": str(raw_path),
        "warnings": str(warnings_path),
        "raw_vs_cleaned_diff": str(diff_path),
        "summary": str(summary_path),
    }
    summary_payload = _export_summary_payload(capture, plan, entrypoint, warnings, artifacts)
    if extra_summary:
        summary_payload.update(extra_summary)
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )
    return artifacts


def safe_artifact_stem(name: str, max_length: int = 96, digest_source: str | None = None) -> str:
    cleaned = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_"
        for char in str(name or "function")
    )
    cleaned = cleaned.strip("._") or "function"
    limit = max(16, int(max_length or 0))
    if len(cleaned) <= limit:
        return cleaned
    digest_input = str(digest_source if digest_source is not None else name)
    digest = hashlib.sha256(digest_input.encode("utf-8", errors="replace")).hexdigest()[:12]
    suffix = "_" + digest
    prefix_length = max(1, limit - len(suffix))
    prefix = cleaned[:prefix_length].rstrip("._-") or "function"
    return prefix + suffix


def _combined_export_warnings(plan: CleanPlan) -> list[str]:
    result = []
    seen = set()
    for warning in list(plan.warnings) + profile_load_warnings():
        text = str(warning)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _raw_vs_cleaned_diff(safe_name: str, raw_text: str, cleaned_text: str) -> str:
    return "".join(
        difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            cleaned_text.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % safe_name,
            tofile="cleaned/%s.cpp" % safe_name,
            lineterm="\n",
        )
    )


def _export_summary_payload(
    capture: FunctionCapture,
    plan: CleanPlan,
    entrypoint: str,
    warnings: list[str],
    artifacts: dict[str, str],
) -> dict[str, object]:
    rule_diagnostics = summarize_rule_report(plan.rule_report)
    return {
        "mode": entrypoint,
        "pseudoforge_version": VERSION,
        "function": capture.name,
        "function_ea": "0x%X" % capture.ea,
        "source_path": capture.source_path,
        "input_fingerprint": plan.input_fingerprint,
        "rename_candidates": len(plan.renames),
        "renames": len(plan.active_renames()),
        "flow_rewrites": len(plan.flow_rewrites),
        "buffer_contracts": len(plan.buffer_contracts),
        "warnings": len(warnings),
        "rule_diagnostics": rule_diagnostics,
        "rule_load_errors": list(rule_diagnostics["load_error_details"]),
        "rule_validation_errors": list(rule_diagnostics["validation_error_details"]),
        "profile_root": active_profile_root(),
        "active_profiles": active_profile_names(),
        "profile_warnings": profile_load_warnings(),
        "profile_manifests": active_profile_manifests(),
        "artifacts": dict(artifacts),
    }
