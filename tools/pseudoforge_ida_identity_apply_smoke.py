from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
_root_key = os.path.normcase(str(ROOT))
sys.path = [entry for entry in sys.path if os.path.normcase(entry) != _root_key]
sys.path.insert(0, str(ROOT))

for module_name in list(sys.modules):
    if module_name == "ida_pseudoforge" or module_name.startswith("ida_pseudoforge."):
        del sys.modules[module_name]

from ida_pseudoforge.core.plan_schema import CleanPlan, LocalVariable, RenameSuggestion
from ida_pseudoforge.core.validation import is_valid_c_identifier
from ida_pseudoforge.ida.apply_changes import apply_selected_renames, preflight_selected_renames
from ida_pseudoforge.ida.decompiler import _extract_lvars_from_cfunc

try:
    import ida_auto  # type: ignore
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_pro  # type: ignore
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import idc  # type: ignore
except Exception:
    ida_auto = None
    ida_funcs = None
    ida_hexrays = None
    ida_pro = None
    idaapi = None
    idautils = None
    idc = None


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(_script_argv() if argv is None else argv)
    reporter = _JsonReporter(args.report)
    exit_code = 0
    try:
        _require_ida()
        if not args.no_auto_wait:
            ida_auto.auto_wait()
        input_path = _input_file_path()
        if not args.allow_non_temp_input and not _is_temp_path(input_path):
            raise RuntimeError(
                "Refusing to modify a non-temp input without --allow-non-temp-input: %s" % input_path
            )
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler is not available")
        reporter.write(
            {
                "event": "start",
                "time": _utc_now(),
                "max_functions": args.max_functions,
                "rename_prefix": args.rename_prefix,
                "input_path": input_path,
            }
        )
        result = _run_smoke(args, reporter)
        reporter.write({"event": "summary", "time": _utc_now(), **result})
        if result["status"] != "ok":
            exit_code = 1
    except Exception as exc:
        exit_code = 1
        reporter.write(
            {
                "event": "fatal",
                "time": _utc_now(),
                "status": "error",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        reporter.close()
        if not args.no_exit and ida_pro is not None:
            ida_pro.qexit(exit_code)
    return exit_code


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate PseudoForge IDA identity-backed rename apply.")
    parser.add_argument("--report", default="", help="JSON report path.")
    parser.add_argument("--max-functions", type=int, default=150, help="Maximum functions to scan.")
    parser.add_argument("--rename-prefix", default="pfIdentitySmoke", help="Rename prefix used in the temp IDB.")
    parser.add_argument("--no-auto-wait", action="store_true", help="Do not wait for IDA autoanalysis.")
    parser.add_argument("--no-exit", action="store_true", help="Do not call ida_pro.qexit at the end.")
    parser.add_argument(
        "--allow-non-temp-input",
        action="store_true",
        help="Allow the smoke test to modify an IDB whose input file is outside the temp directory.",
    )
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


def _input_file_path() -> str:
    for getter in (
        getattr(idaapi, "get_input_file_path", None),
        getattr(idc, "get_input_file_path", None),
    ):
        if not callable(getter):
            continue
        try:
            value = str(getter() or "")
        except Exception:
            value = ""
        if value:
            return value
    return ""


def _is_temp_path(path: str) -> bool:
    if not path:
        return False
    temp_root = os.path.abspath(os.environ.get("TEMP") or os.environ.get("TMP") or "")
    if not temp_root:
        return False
    temp_root = os.path.normcase(temp_root)
    candidate = os.path.normcase(os.path.abspath(path))
    try:
        return os.path.commonpath([temp_root, candidate]) == temp_root
    except ValueError:
        return False


def _run_smoke(args: argparse.Namespace, reporter: "_JsonReporter") -> dict[str, Any]:
    scanned = 0
    candidate_skips = 0
    for ea in idautils.Functions():
        if args.max_functions and scanned >= args.max_functions:
            break
        scanned += 1
        result = _try_function(int(ea), args.rename_prefix)
        reporter.write(result)
        if result.get("status") == "ok":
            return {"status": "ok", "scanned": scanned, "validated_ea": result.get("ea", "")}
        if result.get("status") == "skipped":
            candidate_skips += 1
    return {
        "status": "failed",
        "scanned": scanned,
        "skipped": candidate_skips,
        "error": "No function with stable identity-backed local rename candidate was validated.",
    }


def _try_function(ea: int, rename_prefix: str) -> dict[str, Any]:
    started = time.monotonic()
    name = _function_name(ea)
    try:
        func = ida_funcs.get_func(ea)
        if func is None:
            return _skip(ea, name, "function object is not available", started)
        cfunc = ida_hexrays.decompile(func)
        if cfunc is None:
            return _skip(ea, name, "Hex-Rays returned no cfunc", started)
        captured_lvars = _extract_lvars_from_cfunc(cfunc)
        candidate = _select_candidate(captured_lvars, rename_prefix)
        if candidate is None:
            return _skip(ea, name, "no identity-backed local candidate", started)
        _refresh_cfunc(ea)
        refreshed = ida_hexrays.decompile(func)
        if refreshed is None:
            return _skip(ea, name, "Hex-Rays refresh returned no cfunc", started)
        current_lvars = _extract_lvars_from_cfunc(refreshed)
        current = _find_lvar(current_lvars, candidate.name)
        if current is None:
            return _skip(ea, name, "candidate disappeared after refresh", started)
        if current.identity != candidate.identity:
            return _skip(ea, name, "candidate identity changed after refresh", started)

        new_name = _candidate_new_name(rename_prefix, [var.name for var in current_lvars], 0)
        plan = _plan_for_candidate(ea, name, candidate, new_name)
        accepted, rejected = preflight_selected_renames(
            plan,
            [candidate.name],
            captured_lvars=captured_lvars,
            current_lvars=current_lvars,
        )
        if rejected or len(accepted) != 1:
            return _error(ea, name, "identity-backed preflight rejected stable candidate", started, rejected)

        drift_current_lvars = _replace_lvar(current_lvars, _drifted_lvar(current))
        _accepted, drift_rejected = preflight_selected_renames(
            plan,
            [candidate.name],
            captured_lvars=captured_lvars,
            current_lvars=drift_current_lvars,
        )
        if not any("identity changed" in item for item in drift_rejected):
            return _error(ea, name, "identity drift was not rejected", started, drift_rejected)

        apply_result = apply_selected_renames(
            ea,
            plan,
            [candidate.name],
            captured_lvars=captured_lvars,
            current_lvars=current_lvars,
        )
        if not apply_result.applied:
            return _error(ea, name, "IDA rejected identity-backed rename", started, apply_result.rejected)

        _refresh_cfunc(ea)
        after = ida_hexrays.decompile(func)
        after_lvars = _extract_lvars_from_cfunc(after) if after is not None else []
        if _find_lvar(after_lvars, new_name) is None:
            return _error(ea, name, "renamed local was not visible after refresh", started, apply_result.rejected)

        return {
            "event": "function",
            "status": "ok",
            "ea": "0x%X" % ea,
            "name": name,
            "old_name": candidate.name,
            "new_name": new_name,
            "identity_prefix": candidate.identity[:16],
            "drift_rejected": True,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
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


def _select_candidate(lvars: Iterable[LocalVariable], rename_prefix: str) -> LocalVariable | None:
    candidates = [
        var
        for var in lvars
        if var.name
        and var.identity
        and not var.is_arg
        and is_valid_c_identifier(var.name)
        and not var.name.startswith(rename_prefix)
    ]
    if not candidates:
        candidates = [
            var
            for var in lvars
            if var.name
            and var.identity
            and is_valid_c_identifier(var.name)
            and not var.name.startswith(rename_prefix)
        ]
    return candidates[0] if candidates else None


def _candidate_new_name(rename_prefix: str, existing_names: Iterable[str], index: int) -> str:
    existing = set(existing_names)
    base = "%s%02d" % (rename_prefix, max(0, int(index)))
    if base not in existing:
        return base
    suffix = 1
    while True:
        candidate = "%s%02d_%d" % (rename_prefix, max(0, int(index)), suffix)
        if candidate not in existing:
            return candidate
        suffix += 1


def _plan_for_candidate(ea: int, function_name: str, candidate: LocalVariable, new_name: str) -> CleanPlan:
    return CleanPlan(
        function_ea=ea,
        function_name=function_name,
        input_fingerprint="ida-identity-apply-smoke",
        renames=[
            RenameSuggestion(
                "arg" if candidate.is_arg else "lvar",
                candidate.name,
                new_name,
                1.0,
                "ida-identity-apply-smoke",
                "manual IDA validation",
                identity=candidate.identity,
            )
        ],
    )


def _replace_lvar(lvars: Iterable[LocalVariable], replacement: LocalVariable) -> list[LocalVariable]:
    result = []
    replaced = False
    for var in lvars:
        if not replaced and var.name == replacement.name:
            result.append(replacement)
            replaced = True
        else:
            result.append(var)
    return result


def _drifted_lvar(var: LocalVariable) -> LocalVariable:
    identity = (var.identity or "") + ":drift"
    return replace(var, identity=identity)


def _find_lvar(lvars: Iterable[LocalVariable], name: str) -> LocalVariable | None:
    for var in lvars:
        if var.name == name:
            return var
    return None


def _refresh_cfunc(ea: int) -> None:
    for method_name, args in (
        ("mark_cfunc_dirty", (ea, True)),
        ("clear_cached_cfuncs", ()),
    ):
        method = getattr(ida_hexrays, method_name, None)
        if not callable(method):
            continue
        try:
            method(*args)
        except Exception:
            pass


def _function_name(ea: int) -> str:
    try:
        name = ida_funcs.get_func_name(ea) or ""
    except Exception:
        name = ""
    return name or "sub_%X" % ea


def _skip(ea: int, name: str, reason: str, started: float) -> dict[str, Any]:
    return {
        "event": "function",
        "status": "skipped",
        "ea": "0x%X" % ea,
        "name": name,
        "reason": reason,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _error(ea: int, name: str, error: str, started: float, details: list[str]) -> dict[str, Any]:
    return {
        "event": "function",
        "status": "error",
        "ea": "0x%X" % ea,
        "name": name,
        "error": error,
        "details": details,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class _JsonReporter:
    def __init__(self, path: str) -> None:
        self._handle = None
        self.path = Path(path) if path else Path.cwd() / ("pseudoforge_ida_identity_apply_%s.jsonl" % int(time.time()))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8")

    def write(self, record: dict[str, Any]) -> None:
        payload = json.dumps(record, ensure_ascii=True, sort_keys=True)
        self._handle.write(payload + "\n")
        self._handle.flush()
        print(payload)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
