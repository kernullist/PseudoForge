from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
import time
import traceback
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
from ida_pseudoforge.core.forge_store import (
    parse_forge_function_sections,
    render_forge_function_section,
    upsert_forge_section,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import LocalVariable
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.profiles.loader import profile_load_warnings
from ida_pseudoforge.ida.decompiler import merge_lvars_from_text_and_cfunc
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_ORDER,
    normalize_provider,
    provider_defaults,
)

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


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(_script_argv() if argv is None else argv)
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
                "llm": llm_info,
                "selected_functions": total_selected,
                "resume_skipped": len(skip_eas),
                "max_functions": args.max_functions,
            }
        )

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
    parser.add_argument("--compare-context", type=int, default=3, help="Unified diff context lines for --compare-dir artifacts.")
    parser.add_argument("--llm-renames", action="store_true", help="Use the configured LLM provider for additional rename suggestions.")
    parser.add_argument("--llm-provider", choices=PROVIDER_ORDER, default="", help="Override configured LLM provider.")
    parser.add_argument("--llm-api-key", default="", help="Override provider API key for this run. Not written to reports.")
    parser.add_argument("--llm-base-url", default="", help="Override HTTP provider base URL.")
    parser.add_argument("--llm-model", default="", help="Override model for this run.")
    parser.add_argument("--llm-command", default="", help="Override CLI provider command template.")
    parser.add_argument("--llm-timeout", type=int, default=0, help="Override per-function LLM timeout seconds.")
    parser.add_argument("--report", default="", help="JSONL progress report path.")
    parser.add_argument("--max-functions", type=int, default=0, help="Maximum functions to process. 0 means all.")
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum wall time. 0 means unlimited.")
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
        plan, llm_status, llm_error = _build_plan_with_optional_llm(capture, rename_provider)
        cleaned = render_cleaned_pseudocode(capture, plan)
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


def _build_llm_context(args: argparse.Namespace) -> tuple[Any | None, dict[str, Any]]:
    if not args.llm_renames:
        return None, {"enabled": False}

    saved_config = load_config()
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
    api_key = args.llm_api_key or get_provider_api_key(saved_config, provider)
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
        return build_clean_plan(capture), "disabled", ""
    try:
        return build_clean_plan(capture, rename_provider=rename_provider), "ok", ""
    except Exception as exc:
        plan = build_clean_plan(capture)
        plan.warnings.insert(0, "LLM rename assist failed; deterministic fallback used: %s" % exc)
        return plan, "fallback", str(exc)


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
    for ea in idautils.Functions():
        ea = int(ea)
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


def _function_file_stem(ea: int, name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_.@$-]+", "_", name or "function").strip("._")
    if not safe_name:
        safe_name = "function"
    if len(safe_name) > 96:
        safe_name = safe_name[:96]
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
