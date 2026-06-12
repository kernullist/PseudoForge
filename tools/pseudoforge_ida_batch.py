from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
import time
import traceback
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


for module_name in list(sys.modules):
    if module_name == "ida_pseudoforge" or module_name.startswith("ida_pseudoforge."):
        del sys.modules[module_name]

from ida_pseudoforge.config import LlmConfig, get_provider_api_key, load_config
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import safe_artifact_stem, write_export_bundle
from ida_pseudoforge.core.forge_store import (
    parse_forge_function_sections,
    render_forge_function_section,
    upsert_forge_section,
)
from ida_pseudoforge.core.helper_aliases import (
    RuntimeHelperAlias,
    apply_runtime_helper_aliases,
    infer_direct_runtime_helper_aliases,
    infer_runtime_helper_aliases_from_texts,
    is_runtime_helper_alias_advisory,
    runtime_helper_alias_summary,
)
from ida_pseudoforge.core.llm_failures import (
    format_llm_fallback_warning,
    is_llm_provider_cyber_policy_block,
    summarize_llm_failure,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture, LocalVariable
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles.loader import active_profile_root, configure_profile_dir, profile_load_warnings
from ida_pseudoforge.ida.decompiler import merge_lvars_from_text_and_cfunc
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_ORDER,
    normalize_provider,
    provider_defaults,
    provider_requires_api_key,
)
from ida_pseudoforge.version import VERSION

try:
    import ida_auto  # type: ignore
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_loader  # type: ignore
    import ida_nalt  # type: ignore
    import ida_pro  # type: ignore
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import idc  # type: ignore
except Exception:
    ida_auto = None
    ida_funcs = None
    ida_hexrays = None
    ida_loader = None
    ida_nalt = None
    ida_pro = None
    idaapi = None
    idautils = None
    idc = None


_DIRECT_HELPER_ALIAS_MAX_CALLEES = 8


@dataclass(frozen=True)
class _BatchRenderResult:
    cleaned: str
    plan: CleanPlan
    aliases: dict[str, RuntimeHelperAlias]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(_script_argv() if argv is None else argv)
    configure_profile_dir(args.profile_dir)
    started = time.monotonic()
    exit_code = 0
    reporter = _JsonlReporter(args.report)
    forge_writer = None

    try:
        _require_ida()
        if not args.no_auto_wait:
            ida_auto.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler is not available")

        idb_path = _idb_path()
        target_path = Path(args.target_path) if args.target_path else _target_path(idb_path)
        forge_path = Path(args.forge_path) if args.forge_path else target_path.with_suffix(".forge")
        compare_dir = Path(args.compare_dir) if args.compare_dir else None
        export_dir = Path(args.export_dir) if args.export_dir else None
        corpus_metadata_path = Path(args.corpus_metadata) if args.corpus_metadata else None
        cancel_file = Path(args.cancel_file) if args.cancel_file else None
        rename_provider, llm_info = _build_llm_context(args)
        skip_eas = _existing_forge_eas(forge_path) if args.resume else set()
        forge_writer = None if args.upsert_forge else _BatchForgeWriter(
            forge_path,
            target_path,
            overwrite=args.overwrite_forge and not args.resume,
        )
        selected = list(_iter_function_eas(args, skip_eas))
        total_selected = len(selected)
        reporter.write(
            {
                "event": "start",
                "time": _utc_now(),
                "idb_path": str(idb_path) if idb_path else "",
                "target_path": str(target_path),
                "forge_path": str(forge_path),
                "compare_dir": str(compare_dir) if compare_dir else "",
                "export_dir": str(export_dir) if export_dir else "",
                "corpus_metadata": str(corpus_metadata_path) if corpus_metadata_path else "",
                "cancel_file": str(cancel_file) if cancel_file else "",
                "llm": llm_info,
                "profile_dir": active_profile_root(),
                "selected_functions": total_selected,
                "resume_skipped": len(skip_eas),
                "max_functions": args.max_functions,
            }
        )
        if corpus_metadata_path is not None:
            metadata_record = _write_corpus_metadata(
                corpus_metadata_path,
                idb_path,
                target_path,
                selected,
                args,
            )
            reporter.write(metadata_record)

        processed = 0
        succeeded = 0
        skipped = 0
        failed = 0
        for ea in selected:
            if args.max_seconds and time.monotonic() - started >= args.max_seconds:
                reporter.write({"event": "stop", "reason": "max_seconds", "processed": processed})
                break
            if args.max_functions and processed >= args.max_functions:
                break
            if _cancel_file_requested(cancel_file):
                reporter.write(
                    {
                        "event": "stop",
                        "reason": "cancel_file",
                        "cancel_file": str(cancel_file),
                        "processed": processed,
                    }
                )
                break

            reporter.write(_batch_progress_record(ea, _function_name(ea), processed + 1, total_selected))
            processed += 1
            result = _analyze_function(ea, target_path, forge_path, forge_writer, args, rename_provider, llm_info)
            reporter.write(result)
            if result.get("status") == "ok":
                succeeded += 1
            elif result.get("status") == "skipped":
                skipped += 1
            else:
                failed += 1
                exit_code = 1
                if args.stop_on_error:
                    break

        if forge_writer is not None:
            forge_writer.close()
            forge_writer = None
        postprocess_result = _apply_runtime_helper_aliases_to_batch_outputs(
            forge_path,
            compare_dir,
            args.compare_context,
            export_dir=export_dir,
        )
        if postprocess_result.get("aliases"):
            reporter.write(postprocess_result)

        reporter.write(
            {
                "event": "summary",
                "time": _utc_now(),
                "processed": processed,
                "succeeded": succeeded,
                "skipped": skipped,
                "failed": failed,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        )
    except Exception as exc:
        exit_code = 1
        reporter.write(
            {
                "event": "fatal",
                "time": _utc_now(),
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        if forge_writer is not None:
            forge_writer.close()
        reporter.close()
        if not args.no_exit and ida_pro is not None:
            ida_pro.qexit(exit_code)

    return exit_code


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run PseudoForge over IDA Hex-Rays decompiled functions.")
    parser.add_argument("--target-path", default="", help="Original binary path used in .forge metadata.")
    parser.add_argument("--forge-path", default="", help="Aggregate .forge output path.")
    parser.add_argument("--compare-dir", default="", help="Directory for raw Hex-Rays, PseudoForge, and unified diff artifacts.")
    parser.add_argument("--export-dir", default="", help="Directory for full per-function export bundles.")
    parser.add_argument("--corpus-metadata", default="", help="Path for global IDB corpus metadata JSON.")
    parser.add_argument("--metadata-max-strings", type=int, default=20000, help="Maximum strings to store in corpus metadata.")
    parser.add_argument("--metadata-max-names", type=int, default=20000, help="Maximum named addresses to store in corpus metadata.")
    parser.add_argument(
        "--profile-dir",
        default="",
        help="Optional profile directory for target-build-specific profile sets.",
    )
    parser.add_argument("--compare-context", type=int, default=3, help="Unified diff context lines for --compare-dir artifacts.")
    parser.add_argument("--llm-renames", action="store_true", help="Use the configured LLM provider for additional rename suggestions.")
    parser.add_argument(
        "--llm-renames-auto",
        action="store_true",
        help="Use saved plugin LLM settings only when plugin LLM assist is enabled.",
    )
    parser.add_argument(
        "--require-configured-llm",
        action="store_true",
        help="Fail when --llm-renames-auto is used but saved plugin LLM assist is disabled.",
    )
    parser.add_argument("--llm-provider", choices=PROVIDER_ORDER, default="", help="Override configured LLM provider.")
    parser.add_argument("--llm-api-key", default="", help="Override provider API key for this run. Not written to reports.")
    parser.add_argument("--llm-base-url", default="", help="Override HTTP provider base URL.")
    parser.add_argument("--llm-model", default="", help="Override model for this run.")
    parser.add_argument("--llm-command", default="", help="Override CLI provider command template.")
    parser.add_argument("--llm-timeout", type=int, default=0, help="Override per-function LLM timeout seconds.")
    parser.add_argument("--report", default="", help="JSONL progress report path.")
    parser.add_argument("--cancel-file", default="", help="Stop before the next function when this file exists.")
    parser.add_argument("--max-functions", type=int, default=0, help="Maximum functions to process. 0 means all.")
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum wall time. 0 means unlimited.")
    parser.add_argument(
        "--ea",
        action="append",
        default=[],
        help="Only process this function EA. Can be repeated; accepts hex or decimal.",
    )
    parser.add_argument(
        "--ea-file",
        default="",
        help="Only process function EAs listed in this text file. Whitespace, comma, and semicolon separators are accepted.",
    )
    parser.add_argument("--start-ea", default="", help="First function EA, inclusive.")
    parser.add_argument("--end-ea", default="", help="Last function EA, inclusive.")
    parser.add_argument("--name-regex", default="", help="Only process function names matching this regex.")
    parser.add_argument("--resume", action="store_true", help="Skip functions already present in the .forge output.")
    parser.add_argument("--overwrite-forge", action="store_true", help="Overwrite the .forge output before appending.")
    parser.add_argument("--upsert-forge", action="store_true", help="Use exact aggregate upsert writes instead of append-only batch writes.")
    parser.add_argument("--skip-lib-thunk", action="store_true", help="Skip library and thunk functions.")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop after the first failed function.")
    parser.add_argument("--no-auto-wait", action="store_true", help="Do not wait for IDA autoanalysis first.")
    parser.add_argument("--no-exit", action="store_true", help="Do not call ida_pro.qexit at the end.")
    return parser.parse_args(argv)


def _script_argv() -> list[str]:
    try:
        raw = list(getattr(idc, "ARGV", []) or [])
    except Exception:
        raw = []
    if raw:
        if raw[0].lower().endswith(".py"):
            return raw[1:]
        return raw
    return sys.argv[1:]


def _require_ida() -> None:
    missing = [
        name
        for name, module in (
            ("ida_auto", ida_auto),
            ("ida_funcs", ida_funcs),
            ("ida_hexrays", ida_hexrays),
            ("ida_pro", ida_pro),
            ("idautils", idautils),
        )
        if module is None
    ]
    if missing:
        raise RuntimeError("IDA modules are not available: %s" % ", ".join(missing))


def _analyze_function(
    ea: int,
    target_path: Path,
    forge_path: Path,
    forge_writer: "_BatchForgeWriter | None",
    args: argparse.Namespace,
    rename_provider: Any | None,
    llm_info: dict[str, Any],
) -> dict[str, Any]:
    started = time.monotonic()
    name = _function_name(ea)
    try:
        func = ida_funcs.get_func(ea)
        if func is None:
            return _skipped_function(ea, name, "function object is not available", started)

        try:
            cfunc = ida_hexrays.decompile(func)
        except Exception as exc:
            return _skipped_function(ea, name, "Hex-Rays decompile failed: %s" % exc, started)
        if cfunc is None:
            return _skipped_function(ea, name, "Hex-Rays returned no cfunc", started)

        pseudocode = _cfunc_text(cfunc)
        capture = capture_from_pseudocode(pseudocode, name=name, ea=ea, source_path=str(target_path))
        capture.lvars = merge_lvars_from_text_and_cfunc(capture.lvars, _extract_lvars_from_cfunc(cfunc))
        plan, llm_status, llm_error, llm_error_class, llm_error_summary = _build_plan_with_optional_llm(
            capture,
            rename_provider,
        )
        render_result = _render_cleaned_with_ida_postprocess(capture, plan)
        plan = render_result.plan
        cleaned = render_result.cleaned
        section = render_forge_function_section(capture, plan, cleaned)
        if forge_writer is not None:
            forge_writer.write_section(section)
        else:
            _write_forge_section(forge_path, target_path, capture.ea, section)
        warnings = _combined_warnings(plan.warnings, profile_load_warnings())
        result = {
            "event": "function",
            "status": "ok",
            "ea": "0x%X" % ea,
            "name": name,
            "renames": len(plan.active_renames()),
            "flow_rewrites": len(plan.flow_rewrites),
            "warnings": len(warnings),
            "warning_samples": warnings[:5],
            "helper_aliases": runtime_helper_alias_summary(render_result.aliases),
            "llm_status": llm_status,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        profile_warnings = profile_load_warnings()
        if profile_warnings:
            result["profile_warnings"] = profile_warnings
        if llm_info.get("enabled"):
            result["llm_provider"] = llm_info.get("provider", "")
            result["llm_model"] = llm_info.get("model", "")
        if llm_error:
            result["llm_error"] = llm_error
        if llm_error_summary:
            result["llm_error_summary"] = llm_error_summary
        if llm_error_class:
            result["llm_error_class"] = llm_error_class
        if args.compare_dir:
            result["comparison"] = _write_compare_artifacts(
                Path(args.compare_dir),
                capture.ea,
                name,
                pseudocode,
                cleaned,
                section,
                args.compare_context,
            )
        if args.export_dir:
            result["export"] = _write_export_artifacts(
                Path(args.export_dir),
                capture,
                plan,
                cleaned,
                render_result.aliases,
                llm_status,
                llm_error,
                llm_error_class,
                llm_error_summary,
                llm_info,
            )
        return result
    except Exception as exc:
        return {
            "event": "function",
            "status": "error",
            "ea": "0x%X" % ea,
            "name": name,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def _skipped_function(ea: int, name: str, reason: str, started: float) -> dict[str, Any]:
    return {
        "event": "function",
        "status": "skipped",
        "ea": "0x%X" % ea,
        "name": name,
        "reason": reason,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _cancel_file_requested(cancel_file: Path | None) -> bool:
    if cancel_file is None:
        return False
    try:
        return cancel_file.exists()
    except Exception:
        return False


def _batch_progress_record(ea: int, name: str, index: int, selected_functions: int) -> dict[str, Any]:
    return {
        "event": "progress",
        "phase": "function_start",
        "time": _utc_now(),
        "index": index,
        "selected_functions": selected_functions,
        "ea": "0x%X" % ea,
        "name": name,
    }


def _build_llm_context(args: argparse.Namespace) -> tuple[Any | None, dict[str, Any]]:
    force_enabled = bool(getattr(args, "llm_renames", False))
    auto_enabled = bool(getattr(args, "llm_renames_auto", False))
    require_configured = bool(getattr(args, "require_configured_llm", False))
    if not force_enabled and not auto_enabled:
        return None, {"enabled": False}

    saved_config = load_config()
    if auto_enabled and not force_enabled and not saved_config.llm.enabled:
        if require_configured:
            raise RuntimeError("Plugin LLM rename assist is disabled in saved PseudoForge settings")
        return None, {
            "enabled": False,
            "config_enabled": False,
            "mode": "auto",
            "reason": "plugin_llm_disabled",
        }

    provider = normalize_provider(args.llm_provider or saved_config.llm.provider)
    defaults = provider_defaults(provider)
    timeout_seconds = args.llm_timeout if args.llm_timeout > 0 else saved_config.llm.timeout_seconds
    timeout_seconds = min(max(int(timeout_seconds or 60), 5), 600)
    llm_config = LlmConfig(
        enabled=True,
        provider=provider,
        base_url=args.llm_base_url or saved_config.llm.base_url or defaults.base_url,
        model=args.llm_model or saved_config.llm.model or defaults.model,
        timeout_seconds=timeout_seconds,
        command_template=args.llm_command or saved_config.llm.command_template or defaults.command_template,
        extra_headers=saved_config.llm.extra_headers,
    )
    if args.llm_api_key:
        api_key = args.llm_api_key
    elif provider_requires_api_key(provider):
        api_key = get_provider_api_key(saved_config, provider)
    else:
        api_key = ""
    provider_instance = build_rename_provider(llm_config, api_key=api_key)
    return provider_instance, {
        "enabled": True,
        "provider": provider,
        "model": llm_config.model,
        "timeout_seconds": llm_config.timeout_seconds,
        "config_enabled": bool(saved_config.llm.enabled),
    }


def _build_plan_with_optional_llm(capture, rename_provider: Any | None):
    if rename_provider is None:
        return build_clean_plan(capture), "disabled", "", "", ""
    try:
        return build_clean_plan(capture, rename_provider=rename_provider), "ok", "", "", ""
    except Exception as exc:
        plan = build_clean_plan(capture)
        plan.warnings.insert(0, format_llm_fallback_warning(exc))
        error_class = "cyber_policy_block" if is_llm_provider_cyber_policy_block(exc) else "provider_failure"
        return plan, "fallback", str(exc), error_class, summarize_llm_failure(exc)


def _render_cleaned_with_ida_postprocess(
    capture: FunctionCapture,
    plan: CleanPlan,
    helper_text_loader: Any | None = None,
) -> _BatchRenderResult:
    aliases = _direct_runtime_helper_aliases(capture.pseudocode, capture, helper_text_loader)
    render_plan = _plan_without_runtime_helper_alias_warnings(plan, aliases)
    cleaned = render_cleaned_pseudocode(capture, render_plan)
    if not aliases:
        aliases = _direct_runtime_helper_aliases(cleaned, capture, helper_text_loader)
        render_plan = _plan_without_runtime_helper_alias_warnings(plan, aliases)
        if render_plan is not plan:
            cleaned = render_cleaned_pseudocode(capture, render_plan)
    if aliases:
        cleaned = apply_runtime_helper_aliases(cleaned, aliases)
    return _BatchRenderResult(cleaned=cleaned, plan=render_plan, aliases=aliases)


def _plan_without_runtime_helper_alias_warnings(plan: CleanPlan, aliases: dict[str, RuntimeHelperAlias]) -> CleanPlan:
    if not aliases or not plan.warnings:
        return plan
    filtered = [
        warning
        for warning in plan.warnings
        if not is_runtime_helper_alias_advisory(warning, aliases)
    ]
    if len(filtered) == len(plan.warnings):
        return plan
    return replace(plan, warnings=filtered)


def _direct_runtime_helper_aliases(
    text: str,
    capture: FunctionCapture,
    helper_text_loader: Any | None = None,
) -> dict[str, RuntimeHelperAlias]:
    if helper_text_loader is None:
        helper_text_loader = lambda call_name: _render_helper_text_for_alias(call_name, capture)
    return infer_direct_runtime_helper_aliases(
        text,
        capture.name,
        helper_text_loader,
        max_callees=_DIRECT_HELPER_ALIAS_MAX_CALLEES,
    )


def _render_helper_text_for_alias(call_name: str, caller_capture: FunctionCapture) -> str | None:
    helper_capture = _capture_function_by_name(call_name, caller_capture.source_path)
    if helper_capture is None or helper_capture.ea == caller_capture.ea:
        return None
    helper_plan = build_clean_plan(helper_capture)
    return render_cleaned_pseudocode(helper_capture, helper_plan)


def _combined_warnings(primary: list[object], secondary: list[str]) -> list[str]:
    result = []
    seen = set()
    for warning in list(primary) + list(secondary):
        text = str(warning)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _iter_function_eas(args: argparse.Namespace, skip_eas: set[int]) -> Iterable[int]:
    start_ea = _parse_ea(args.start_ea)
    end_ea = _parse_ea(args.end_ea)
    name_re = re.compile(args.name_regex) if args.name_regex else None
    requested_eas = _requested_function_eas(args)
    function_eas = requested_eas if requested_eas else [int(ea) for ea in idautils.Functions()]
    seen: set[int] = set()
    for ea in function_eas:
        ea = int(ea)
        func = ida_funcs.get_func(ea) if ida_funcs is not None else None
        if func is not None:
            ea = int(getattr(func, "start_ea", ea))
        if ea in seen:
            continue
        seen.add(ea)
        if ea in skip_eas:
            continue
        if start_ea is not None and ea < start_ea:
            continue
        if end_ea is not None and ea > end_ea:
            continue
        name = _function_name(ea)
        if name_re is not None and not name_re.search(name):
            continue
        if args.skip_lib_thunk and _is_lib_or_thunk(ea):
            continue
        yield ea


def _requested_function_eas(args: argparse.Namespace) -> list[int]:
    values: list[int] = []
    for item in getattr(args, "ea", []) or []:
        values.extend(_parse_ea_tokens(str(item)))
    ea_file = str(getattr(args, "ea_file", "") or "")
    if ea_file:
        try:
            text = Path(ea_file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise RuntimeError("EA file could not be read: %s" % exc) from exc
        values.extend(_parse_ea_tokens(text))
    return values


def _parse_ea_tokens(text: str) -> list[int]:
    values: list[int] = []
    for line in str(text or "").splitlines():
        line = line.split("#", 1)[0]
        for token in re.split(r"[\s,;]+", line.strip()):
            if not token:
                continue
            values.append(int(token, 0))
    return values


def _parse_ea(value: str) -> int | None:
    if not value:
        return None
    return int(value, 0)


def _is_lib_or_thunk(ea: int) -> bool:
    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    flags = int(getattr(func, "flags", 0))
    lib_flag = int(getattr(ida_funcs, "FUNC_LIB", 0))
    thunk_flag = int(getattr(ida_funcs, "FUNC_THUNK", 0))
    return bool(flags & (lib_flag | thunk_flag))


def _existing_forge_eas(path: Path) -> set[int]:
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()
    return {section.ea for section in parse_forge_function_sections(text)}


def _write_forge_section(forge_path: Path, target_path: Path, function_ea: int, section: str) -> str:
    forge_path.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if forge_path.exists():
        existing = forge_path.read_text(encoding="utf-8", errors="replace")
    updated = upsert_forge_section(existing, str(target_path), function_ea, section)
    forge_path.write_text(updated, encoding="utf-8")
    return updated


def _write_compare_artifacts(
    compare_dir: Path,
    ea: int,
    name: str,
    raw_text: str,
    cleaned_text: str,
    section_text: str,
    context_lines: int = 3,
) -> dict[str, Any]:
    stem = _function_file_stem(ea, name)
    raw_path = compare_dir / "raw" / (stem + ".cpp")
    cleaned_path = compare_dir / "cleaned" / (stem + ".cpp")
    forge_path = compare_dir / "forge" / (stem + ".forge")
    diff_path = compare_dir / "diff" / (stem + ".diff")

    for path in (raw_path, cleaned_path, forge_path, diff_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    raw_output = raw_text.rstrip() + "\n"
    cleaned_output = cleaned_text.rstrip() + "\n"
    section_output = section_text.rstrip() + "\n"
    diff_output = "".join(
        difflib.unified_diff(
            raw_output.splitlines(keepends=True),
            cleaned_output.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % stem,
            tofile="cleaned/%s.cpp" % stem,
            n=max(0, int(context_lines)),
        )
    )

    raw_path.write_text(raw_output, encoding="utf-8")
    cleaned_path.write_text(cleaned_output, encoding="utf-8")
    forge_path.write_text(section_output, encoding="utf-8")
    diff_path.write_text(diff_output, encoding="utf-8")

    artifacts = {
        "raw_pseudocode": str(raw_path),
        "cleaned_pseudocode": str(cleaned_path),
        "forge_section": str(forge_path),
        "raw_vs_cleaned_diff": str(diff_path),
    }
    return {
        "mode": "ida_batch",
        "schema": "ida_batch_compare_v2",
        "artifacts": artifacts,
        "raw_path": str(raw_path),
        "cleaned_path": str(cleaned_path),
        "forge_path": str(forge_path),
        "diff_path": str(diff_path),
        "raw_sha256": _sha256_text(raw_output),
        "cleaned_sha256": _sha256_text(cleaned_output),
        "forge_sha256": _sha256_text(section_output),
        "raw_lines": len(raw_output.splitlines()),
        "cleaned_lines": len(cleaned_output.splitlines()),
        "forge_lines": len(section_output.splitlines()),
        "diff_lines": len(diff_output.splitlines()),
    }


def _write_export_artifacts(
    export_dir: Path,
    capture: FunctionCapture,
    plan: CleanPlan,
    cleaned_text: str,
    aliases: dict[str, RuntimeHelperAlias],
    llm_status: str,
    llm_error: str,
    llm_error_class: str,
    llm_error_summary: str,
    llm_info: dict[str, Any],
) -> dict[str, Any]:
    function_dir = export_dir / _function_file_stem(capture.ea, capture.name)
    extra_summary: dict[str, object] = {
        "llm_status": llm_status,
        "helper_aliases": runtime_helper_alias_summary(aliases),
    }
    if llm_info.get("enabled"):
        extra_summary["llm_provider"] = str(llm_info.get("provider", ""))
        extra_summary["llm_model"] = str(llm_info.get("model", ""))
        extra_summary["llm_timeout_seconds"] = int(llm_info.get("timeout_seconds", 0) or 0)
    if llm_error:
        extra_summary["llm_error"] = llm_error
    if llm_error_class:
        extra_summary["llm_error_class"] = llm_error_class
    if llm_error_summary:
        extra_summary["llm_error_summary"] = llm_error_summary

    artifacts = write_export_bundle(
        function_dir,
        capture,
        plan,
        entrypoint="ida_batch_export",
        summary_suffix="ida-batch-summary",
        cleaned_text=cleaned_text.rstrip() + "\n",
        extra_summary=extra_summary,
        file_stem="function",
    )
    return {
        "mode": "ida_batch_export",
        "schema": "ida_batch_export_v1",
        "directory": str(function_dir),
        "artifacts": artifacts,
    }


def _write_corpus_metadata(
    path: Path,
    idb_path: Path | None,
    target_path: Path,
    selected_eas: list[int],
    args: argparse.Namespace,
) -> dict[str, Any]:
    started = time.monotonic()
    payload = _build_corpus_metadata(
        idb_path,
        target_path,
        selected_eas,
        max_strings=max(0, int(getattr(args, "metadata_max_strings", 0) or 0)),
        max_names=max(0, int(getattr(args, "metadata_max_names", 0) or 0)),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    return {
        "event": "corpus_metadata",
        "status": "ok",
        "path": str(path),
        "functions": len(payload.get("functions", [])),
        "imports": len(payload.get("imports", [])),
        "exports": len(payload.get("exports", [])),
        "strings": len(payload.get("strings", [])),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _build_corpus_metadata(
    idb_path: Path | None,
    target_path: Path,
    selected_eas: list[int],
    max_strings: int = 20000,
    max_names: int = 20000,
) -> dict[str, Any]:
    imports = _collect_imports()
    exports = _collect_exports()
    strings = _collect_strings(max_strings)
    names = _collect_names(max_names)
    segments = _collect_segments()
    imports_by_ea = {_parse_hex_ea(item.get("ea", "")): item for item in imports}
    strings_by_ea = {_parse_hex_ea(item.get("ea", "")): item for item in strings}
    imports_by_ea = {key: value for key, value in imports_by_ea.items() if key is not None}
    strings_by_ea = {key: value for key, value in strings_by_ea.items() if key is not None}

    functions = [
        _collect_function_metadata(ea, imports_by_ea, strings_by_ea)
        for ea in selected_eas
    ]
    functions = [item for item in functions if item]
    functions_by_ea = {_parse_hex_ea(item.get("ea", "")): item for item in functions}
    functions_by_ea = {key: value for key, value in functions_by_ea.items() if key is not None}
    callers: dict[int, set[int]] = {ea: set() for ea in functions_by_ea}
    for caller_ea, function in functions_by_ea.items():
        for callee_ea in function.get("callee_eas", []) or []:
            parsed = _parse_hex_ea(str(callee_ea))
            if parsed in callers:
                callers[parsed].add(caller_ea)

    for ea, function in functions_by_ea.items():
        caller_eas = sorted(callers.get(ea, set()))
        function["caller_eas"] = [_format_ea(item) for item in caller_eas]
        function["caller_names"] = [
            str(functions_by_ea[item].get("name", ""))
            for item in caller_eas
            if item in functions_by_ea
        ]

    return {
        "schema": "pseudoforge_corpus_metadata_v1",
        "pseudoforge_version": VERSION,
        "generated_at": _utc_now(),
        "idb_path": str(idb_path) if idb_path else "",
        "target_path": str(target_path),
        "input_file_path": str(_target_path(idb_path)),
        "image_base": _format_ea(_image_base()),
        "processor": _processor_name(),
        "segments": segments,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "names": names,
        "functions": functions,
        "limits": {
            "max_strings": max_strings,
            "max_names": max_names,
        },
    }


def _collect_function_metadata(
    ea: int,
    imports_by_ea: dict[int, dict[str, Any]],
    strings_by_ea: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    func = ida_funcs.get_func(ea) if ida_funcs is not None else None
    start_ea = int(getattr(func, "start_ea", ea) if func is not None else ea)
    end_ea = int(getattr(func, "end_ea", start_ea) if func is not None else start_ea)
    flags = int(getattr(func, "flags", 0) if func is not None else 0)
    callee_eas: set[int] = set()
    import_refs: dict[int, dict[str, Any]] = {}
    string_refs: dict[int, dict[str, Any]] = {}
    code_ref_count = 0
    data_ref_count = 0

    for item_ea in _func_items(start_ea):
        for target_ea in _code_refs_from(item_ea):
            code_ref_count += 1
            import_record = imports_by_ea.get(target_ea)
            if import_record is not None:
                import_refs[target_ea] = import_record
            callee_func = ida_funcs.get_func(target_ea) if ida_funcs is not None else None
            if callee_func is not None:
                callee_start = int(getattr(callee_func, "start_ea", target_ea))
                if callee_start != start_ea:
                    callee_eas.add(callee_start)
        for target_ea in _data_refs_from(item_ea):
            data_ref_count += 1
            string_record = strings_by_ea.get(target_ea)
            if string_record is not None:
                string_refs[target_ea] = string_record

    return {
        "ea": _format_ea(start_ea),
        "end_ea": _format_ea(end_ea),
        "name": _function_name(start_ea),
        "size": max(0, end_ea - start_ea),
        "segment": _segment_name(start_ea),
        "flags": flags,
        "is_library": _is_library_function(flags),
        "is_thunk": _is_thunk_function(flags),
        "callee_eas": [_format_ea(item) for item in sorted(callee_eas)],
        "callee_names": [_function_name(item) for item in sorted(callee_eas)],
        "caller_eas": [],
        "caller_names": [],
        "imports_called": list(import_refs.values()),
        "strings_referenced": list(string_refs.values()),
        "code_ref_count": code_ref_count,
        "data_ref_count": data_ref_count,
    }


def _collect_imports() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if ida_nalt is None:
        return result
    try:
        count = int(ida_nalt.get_import_module_qty())
    except Exception:
        return result
    for index in range(count):
        try:
            module_name = str(ida_nalt.get_import_module_name(index) or "")
        except Exception:
            module_name = ""

        def import_callback(ea, name, ordinal):
            result.append(
                {
                    "ea": _format_ea(int(ea)),
                    "module": module_name,
                    "name": str(name or ""),
                    "ordinal": int(ordinal or 0),
                }
            )
            return True

        try:
            ida_nalt.enum_import_names(index, import_callback)
        except Exception:
            continue
    result.sort(key=lambda item: (str(item.get("module", "")), str(item.get("name", "")), str(item.get("ea", ""))))
    return result


def _collect_exports() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if idautils is None:
        return result
    try:
        entries = list(idautils.Entries())
    except Exception:
        return result
    for entry in entries:
        try:
            index, ordinal, ea, name = entry
        except Exception:
            continue
        result.append(
            {
                "index": int(index),
                "ordinal": int(ordinal),
                "ea": _format_ea(int(ea)),
                "name": str(name or ""),
            }
        )
    return result


def _collect_strings(max_strings: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if idautils is None or max_strings == 0:
        return result
    try:
        strings = idautils.Strings()
    except Exception:
        return result
    for index, item in enumerate(strings):
        if index >= max_strings:
            break
        try:
            value = str(item)
            ea = int(getattr(item, "ea", 0))
            length = int(getattr(item, "length", len(value)))
            string_type = int(getattr(item, "strtype", 0))
        except Exception:
            continue
        result.append(
            {
                "ea": _format_ea(ea),
                "length": length,
                "type": string_type,
                "value": value[:512],
            }
        )
    return result


def _collect_names(max_names: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if idautils is None or max_names == 0:
        return result
    try:
        names = list(idautils.Names())
    except Exception:
        return result
    for index, item in enumerate(names):
        if index >= max_names:
            break
        try:
            ea, name = item
        except Exception:
            continue
        result.append({"ea": _format_ea(int(ea)), "name": str(name or "")})
    return result


def _collect_segments() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if idautils is None:
        return result
    try:
        segments = list(idautils.Segments())
    except Exception:
        return result
    for ea in segments:
        start_ea = int(ea)
        result.append(
            {
                "name": _segment_name(start_ea),
                "start_ea": _format_ea(start_ea),
                "end_ea": _format_ea(_segment_end(start_ea)),
            }
        )
    return result


def _func_items(ea: int) -> list[int]:
    if idautils is None:
        return []
    try:
        return [int(item) for item in idautils.FuncItems(ea)]
    except Exception:
        return []


def _code_refs_from(ea: int) -> list[int]:
    if idautils is None:
        return []
    try:
        return [int(item) for item in idautils.CodeRefsFrom(ea, 0)]
    except Exception:
        return []


def _data_refs_from(ea: int) -> list[int]:
    if idautils is None:
        return []
    try:
        return [int(item) for item in idautils.DataRefsFrom(ea)]
    except Exception:
        return []


def _segment_name(ea: int) -> str:
    if idc is None:
        return ""
    for attr_name in ("get_segm_name", "SegName"):
        getter = getattr(idc, attr_name, None)
        if callable(getter):
            try:
                return str(getter(ea) or "")
            except Exception:
                pass
    return ""


def _segment_end(ea: int) -> int:
    if idc is None:
        return ea
    for attr_name in ("get_segm_end", "SegEnd"):
        getter = getattr(idc, attr_name, None)
        if callable(getter):
            try:
                return int(getter(ea))
            except Exception:
                pass
    return ea


def _image_base() -> int:
    if idaapi is not None:
        getter = getattr(idaapi, "get_imagebase", None)
        if callable(getter):
            try:
                return int(getter())
            except Exception:
                pass
    if ida_nalt is not None:
        getter = getattr(ida_nalt, "get_imagebase", None)
        if callable(getter):
            try:
                return int(getter())
            except Exception:
                pass
    return 0


def _processor_name() -> str:
    if idaapi is not None:
        try:
            inf = idaapi.get_inf_structure()
            procname = getattr(inf, "procname", "")
            if procname:
                return str(procname)
        except Exception:
            pass
    return ""


def _is_library_function(flags: int) -> bool:
    lib_flag = int(getattr(ida_funcs, "FUNC_LIB", 0)) if ida_funcs is not None else 0
    return bool(flags & lib_flag)


def _is_thunk_function(flags: int) -> bool:
    thunk_flag = int(getattr(ida_funcs, "FUNC_THUNK", 0)) if ida_funcs is not None else 0
    return bool(flags & thunk_flag)


def _format_ea(value: int) -> str:
    return "0x%X" % int(value)


def _parse_hex_ea(value: str) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _apply_runtime_helper_aliases_to_batch_outputs(
    forge_path: Path,
    compare_dir: Path | None,
    context_lines: int,
    export_dir: Path | None = None,
) -> dict[str, Any]:
    cleaned_texts: list[str] = []
    if compare_dir is not None:
        cleaned_dir = compare_dir / "cleaned"
        if cleaned_dir.exists():
            cleaned_texts = [
                path.read_text(encoding="utf-8", errors="replace")
                for path in sorted(cleaned_dir.glob("*.cpp"))
            ]
    if export_dir is not None and export_dir.exists():
        export_cleaned_paths = sorted(export_dir.glob("*/*.cleaned.cpp"))
        cleaned_texts.extend(
            path.read_text(encoding="utf-8", errors="replace")
            for path in export_cleaned_paths
        )

    aggregate_text = ""
    if forge_path.exists():
        aggregate_text = forge_path.read_text(encoding="utf-8", errors="replace")
    if not cleaned_texts and aggregate_text:
        cleaned_texts = [section.text for section in parse_forge_function_sections(aggregate_text)]

    aliases = infer_runtime_helper_aliases_from_texts(cleaned_texts)
    if not aliases:
        return {
            "event": "postprocess",
            "phase": "runtime_helper_aliases",
            "status": "unchanged",
            "aliases": [],
            "rewritten_files": 0,
        }

    rewritten_files = 0
    if aggregate_text:
        updated = apply_runtime_helper_aliases(aggregate_text, aliases)
        if updated != aggregate_text:
            forge_path.write_text(updated, encoding="utf-8")
            rewritten_files += 1

    if compare_dir is not None:
        rewritten_files += _apply_runtime_helper_aliases_to_compare_dir(
            compare_dir,
            aliases,
            context_lines,
        )
    if export_dir is not None:
        rewritten_files += _apply_runtime_helper_aliases_to_export_dir(export_dir, aliases)

    return {
        "event": "postprocess",
        "phase": "runtime_helper_aliases",
        "status": "ok",
        "aliases": runtime_helper_alias_summary(aliases),
        "rewritten_files": rewritten_files,
    }


def _apply_runtime_helper_aliases_to_export_dir(
    export_dir: Path,
    aliases: dict[str, RuntimeHelperAlias],
) -> int:
    rewritten = 0
    if not export_dir.exists():
        return rewritten
    for cleaned_path in sorted(export_dir.glob("*/*.cleaned.cpp")):
        original = cleaned_path.read_text(encoding="utf-8", errors="replace")
        updated = apply_runtime_helper_aliases(original, aliases)
        if updated == original:
            continue
        cleaned_path.write_text(updated, encoding="utf-8")
        rewritten += 1
        _refresh_export_diff(cleaned_path)
    return rewritten


def _refresh_export_diff(cleaned_path: Path) -> None:
    safe_name = cleaned_path.name[: -len(".cleaned.cpp")]
    raw_path = cleaned_path.with_name(safe_name + ".raw.cpp")
    diff_path = cleaned_path.with_name(safe_name + ".raw-vs-cleaned.diff")
    if not raw_path.exists():
        return
    raw_output = raw_path.read_text(encoding="utf-8", errors="replace")
    cleaned_output = cleaned_path.read_text(encoding="utf-8", errors="replace")
    diff_output = "".join(
        difflib.unified_diff(
            raw_output.splitlines(keepends=True),
            cleaned_output.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % safe_name,
            tofile="cleaned/%s.cpp" % safe_name,
            lineterm="\n",
        )
    )
    diff_path.write_text(diff_output, encoding="utf-8")


def _apply_runtime_helper_aliases_to_compare_dir(
    compare_dir: Path,
    aliases: dict[str, RuntimeHelperAlias],
    context_lines: int,
) -> int:
    rewritten = 0
    for relative_dir in ("cleaned", "forge"):
        root = compare_dir / relative_dir
        if not root.exists():
            continue
        for path in sorted(root.glob("*.cpp" if relative_dir == "cleaned" else "*.forge")):
            original = path.read_text(encoding="utf-8", errors="replace")
            updated = apply_runtime_helper_aliases(original, aliases)
            if updated == original:
                continue
            path.write_text(updated, encoding="utf-8")
            rewritten += 1
            if relative_dir == "cleaned":
                _refresh_compare_diff(compare_dir, path, context_lines)
    return rewritten


def _refresh_compare_diff(compare_dir: Path, cleaned_path: Path, context_lines: int) -> None:
    raw_path = compare_dir / "raw" / cleaned_path.name
    diff_path = compare_dir / "diff" / cleaned_path.with_suffix(".diff").name
    if not raw_path.exists():
        return
    raw_output = raw_path.read_text(encoding="utf-8", errors="replace")
    cleaned_output = cleaned_path.read_text(encoding="utf-8", errors="replace")
    stem = cleaned_path.stem
    diff_output = "".join(
        difflib.unified_diff(
            raw_output.splitlines(keepends=True),
            cleaned_output.splitlines(keepends=True),
            fromfile="raw/%s.cpp" % stem,
            tofile="cleaned/%s.cpp" % stem,
            n=max(0, int(context_lines)),
        )
    )
    diff_path.parent.mkdir(parents=True, exist_ok=True)
    diff_path.write_text(diff_output, encoding="utf-8")


def _function_file_stem(ea: int, name: str) -> str:
    safe_name = safe_artifact_stem(
        re.sub(r"[^A-Za-z0-9_.@$-]+", "_", name or "function"),
        max_length=64,
        digest_source="%X:%s" % (ea, name or "function"),
    )
    return "%016X_%s" % (ea, safe_name)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _target_path(idb_path: Path | None) -> Path:
    raw_path = ""
    if ida_nalt is not None:
        try:
            raw_path = ida_nalt.get_input_file_path() or ""
        except Exception:
            raw_path = ""
    if not raw_path and idaapi is not None:
        getter = getattr(idaapi, "get_input_file_path", None)
        if callable(getter):
            try:
                raw_path = getter() or ""
            except Exception:
                raw_path = ""
    if raw_path:
        path = Path(raw_path)
        if path.is_absolute():
            return path
        if idb_path is not None:
            return idb_path.parent / path.name
        return Path.cwd() / path.name
    if idb_path is not None:
        return idb_path
    return Path.cwd() / "pseudoforge.bin"


def _idb_path() -> Path | None:
    if ida_loader is not None:
        try:
            getter = getattr(ida_loader, "get_path", None)
            path_type = getattr(ida_loader, "PATH_TYPE_IDB", None)
            if callable(getter) and path_type is not None:
                value = getter(path_type)
                if value:
                    return Path(str(value))
        except Exception:
            pass
    if idaapi is not None:
        try:
            value = getattr(idaapi, "cvar", None)
            if value is not None:
                database_idb = getattr(value, "database_idb", "")
                if database_idb:
                    return Path(str(database_idb))
        except Exception:
            pass
    return None


def _function_name(ea: int) -> str:
    try:
        name = ida_funcs.get_func_name(ea) or ""
    except Exception:
        name = ""
    return name or "sub_%X" % ea


def _capture_function_by_name(name: str, source_path: str = "") -> FunctionCapture | None:
    if ida_hexrays is None or ida_funcs is None:
        return None
    ea = _function_ea_by_name(name)
    if ea is None:
        return None
    try:
        func = ida_funcs.get_func(ea)
    except Exception:
        return None
    if func is None:
        return None
    try:
        cfunc = ida_hexrays.decompile(func)
    except Exception:
        return None
    if cfunc is None:
        return None
    pseudocode = _cfunc_text(cfunc)
    try:
        function_name = ida_funcs.get_func_name(getattr(func, "start_ea", ea)) or name
    except Exception:
        function_name = name
    capture = capture_from_pseudocode(
        pseudocode,
        name=function_name,
        ea=int(getattr(func, "start_ea", ea)),
        source_path=source_path,
    )
    capture.lvars = merge_lvars_from_text_and_cfunc(capture.lvars, _extract_lvars_from_cfunc(cfunc))
    return capture


def _function_ea_by_name(name: str) -> int | None:
    if not name:
        return None
    badaddr = getattr(idaapi, "BADADDR", None) if idaapi is not None else None
    if idc is not None:
        getter = getattr(idc, "get_name_ea_simple", None)
        if callable(getter):
            try:
                ea = int(getter(name))
                if badaddr is None or ea != int(badaddr):
                    return ea
            except Exception:
                pass
    if idaapi is not None:
        getter = getattr(idaapi, "get_name_ea", None)
        if callable(getter):
            try:
                ea = int(getter(int(badaddr or 0), name))
                if badaddr is None or ea != int(badaddr):
                    return ea
            except Exception:
                pass
    return None


def _cfunc_text(cfunc: Any) -> str:
    lines = []
    try:
        pseudocode = cfunc.get_pseudocode()
        for line in pseudocode:
            raw = getattr(line, "line", str(line))
            if idaapi is not None:
                try:
                    raw = idaapi.tag_remove(raw)
                except Exception:
                    pass
            lines.append(str(raw))
    except Exception:
        return str(cfunc)
    return "\n".join(lines)


def _extract_lvars_from_cfunc(cfunc: Any) -> list[LocalVariable]:
    result: list[LocalVariable] = []
    try:
        lvars = list(cfunc.lvars)
    except Exception:
        return result

    for index, lvar in enumerate(lvars):
        name = str(getattr(lvar, "name", "") or "")
        if not name:
            continue
        type_text = ""
        for attr in ("type", "tif"):
            value = getattr(lvar, attr, None)
            if callable(value):
                try:
                    type_text = str(value())
                    break
                except Exception:
                    pass
            elif value is not None:
                type_text = str(value)
                break
        is_arg = False
        method = getattr(lvar, "is_arg_var", None)
        if callable(method):
            try:
                is_arg = bool(method())
            except Exception:
                is_arg = False
        result.append(LocalVariable(name=name, type=type_text, is_arg=is_arg, index=index))
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class _JsonlReporter:
    def __init__(self, path: str) -> None:
        self._handle = None
        if path:
            report_path = Path(path)
        else:
            report_path = Path.cwd() / ("pseudoforge_ida_batch_%s.jsonl" % int(time.time()))
        report_path.parent.mkdir(parents=True, exist_ok=True)
        self.path = report_path
        self._handle = report_path.open("a", encoding="utf-8")

    def write(self, record: dict[str, Any]) -> None:
        payload = json.dumps(record, ensure_ascii=True, sort_keys=True)
        self._handle.write(payload + "\n")
        self._handle.flush()
        print(payload)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()


class _BatchForgeWriter:
    def __init__(self, path: Path, target_path: Path, overwrite: bool = False) -> None:
        self.path = path
        self.target_path = target_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if overwrite or not path.exists() or path.stat().st_size == 0:
            path.write_text(
                "// PseudoForge aggregate preview file\n"
                "// This file is maintained by PseudoForge.\n"
                "// Function sections are replaced by EA, so multiple analyzed functions can share one file.\n"
                "// Target: %s\n" % target_path,
                encoding="utf-8",
            )
        self._handle = path.open("a", encoding="utf-8")

    def write_section(self, section: str) -> None:
        self._handle.write("\n")
        self._handle.write(section.rstrip())
        self._handle.write("\n")
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
