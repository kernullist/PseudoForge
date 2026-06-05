from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.models.subprocess_utils import hidden_subprocess_kwargs
from ida_pseudoforge.version import VERSION, plugin_title
from tools.summarize_pseudoforge_ida_batch import (
    load_records,
    print_text_summary,
    summarize_records,
)


@dataclass(frozen=True)
class IdaCliRun:
    ida_path: Path
    idb_path: Path
    output_dir: Path
    functions_dir: Path
    report_path: Path
    summary_path: Path
    manifest_path: Path
    forge_path: Path
    ida_log_path: Path
    cancel_file: Path
    cancel_file_is_default: bool
    corpus_metadata_path: Path
    corpus_index_path: Path
    corpus_overview_path: Path
    compare_dir: Path | None
    batch_args: list[str]
    ida_args: list[str]
    ida_env: dict[str, str] | None
    pdb_paths: list[Path]
    pdb_symbol_path: str
    pdb_alt_symbol_path: str


@dataclass
class _ReportProgressMonitor:
    path: Path
    offset: int = 0
    pending: str = ""

    def poll(self, final: bool = False) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            handle.seek(self.offset)
            chunk = handle.read()
            self.offset = handle.tell()
        if chunk:
            text = self.pending + chunk
            lines = text.splitlines(keepends=True)
            if lines and not lines[-1].endswith(("\n", "\r")):
                self.pending = lines.pop()
            else:
                self.pending = ""
            for line in lines:
                _print_progress_line(line)
        if final and self.pending:
            line = self.pending
            self.pending = ""
            _print_progress_line(line)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        run = _prepare_run(args)
        if not args.dry_run and run.cancel_file_is_default:
            _clear_cancel_file(run.cancel_file)
        _print_start(run, args)
        if args.dry_run:
            _write_manifest(
                run,
                args,
                status="dry_run",
                ida_exit_code=None,
                pid=None,
                summary=None,
                index_result=None,
            )
            print("Dry run: IDA was not started.")
            return 0
        if args.no_wait:
            process = subprocess.Popen(
                run.ida_args,
                cwd=str(ROOT),
                **_subprocess_kwargs(run, args),
            )
            _write_manifest(
                run,
                args,
                status="started",
                ida_exit_code=None,
                pid=process.pid,
                summary=None,
                index_result=None,
            )
            print("Started IDA batch process")
            print("PID: %s" % process.pid)
            return 0

        ida_exit_code, cli_exit_code, interrupted = _run_ida_and_monitor(run, args)
        summary = _write_summary(run)
        index_result = None if interrupted or args.no_index else _write_corpus_index(run)
        status = "interrupted" if interrupted else ("complete" if ida_exit_code == 0 else "failed")
        _write_manifest(
            run,
            args,
            status=status,
            ida_exit_code=ida_exit_code,
            pid=None,
            summary=summary,
            index_result=index_result,
        )
        _print_finish(run, ida_exit_code, summary, args)
        return cli_exit_code
    except KeyboardInterrupt:
        print("PseudoForge IDA CLI interrupted.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError) as exc:
        print("PseudoForge IDA CLI failed: %s" % exc, file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Open an IDB in IDA, decompile all selected functions, run PseudoForge "
            "with saved plugin LLM settings, and write per-function artifacts."
        )
    )
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("ida_path", help="Path to ida.exe or ida64.exe.")
    parser.add_argument("idb_path", help="Path to the .idb or .i64 database.")
    parser.add_argument("output_dir", help="Directory where run and per-function artifacts are written.")
    parser.add_argument("--target-path", default="", help="Original binary path for artifact metadata.")
    parser.add_argument(
        "--profile-dir",
        default="",
        help="Optional profile directory for target-build-specific profile sets.",
    )
    parser.add_argument("--compare-dir", default="", help="Optional legacy raw/cleaned/diff compare directory.")
    parser.add_argument(
        "--cancel-file",
        default="",
        help="Override the cancel sentinel used by Ctrl+C and external stop requests.",
    )
    parser.add_argument("--max-functions", type=int, default=0, help="Maximum functions to process. 0 means all.")
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum wall time. 0 means unlimited.")
    parser.add_argument("--metadata-max-strings", type=int, default=20000, help="Maximum strings to store in corpus metadata.")
    parser.add_argument("--metadata-max-names", type=int, default=20000, help="Maximum named addresses to store in corpus metadata.")
    parser.add_argument("--start-ea", default="", help="First function EA, inclusive.")
    parser.add_argument("--end-ea", default="", help="Last function EA, inclusive.")
    parser.add_argument("--name-regex", default="", help="Only process function names matching this regex.")
    parser.add_argument("--resume", action="store_true", help="Skip EAs already present in the aggregate .forge file.")
    parser.add_argument("--skip-lib-thunk", action="store_true", help="Skip library and thunk functions.")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop after the first failed function.")
    parser.add_argument("--no-pdb", action="store_true", help="Pass -Opdb:off to IDA.")
    parser.add_argument(
        "--pdb-path",
        action="append",
        default=[],
        help=(
            "Local PDB file or symbol directory to prepend to IDA's _NT_SYMBOL_PATH. "
            "Can be repeated; semicolon-separated values are also accepted."
        ),
    )
    parser.add_argument(
        "--symbol-path",
        default="",
        help="Raw DbgHelp/IDA symbol path to prepend, such as srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols.",
    )
    parser.add_argument("--no-auto-wait", action="store_true", help="Do not wait for IDA autoanalysis first.")
    parser.add_argument("--allow-no-llm", action="store_true", help="Do not fail when saved plugin LLM assist is disabled.")
    parser.add_argument("--visible", action="store_true", help="Do not request a hidden IDA window.")
    parser.add_argument("--no-wait", action="store_true", help="Start IDA and return immediately.")
    parser.add_argument("--no-summary", action="store_true", help="Do not print a text summary after IDA exits.")
    parser.add_argument("--no-index", action="store_true", help="Do not build corpus index artifacts after IDA exits.")
    parser.add_argument("--dry-run", action="store_true", help="Write the manifest and print paths without starting IDA.")
    return parser


def _prepare_run(args: argparse.Namespace) -> IdaCliRun:
    ida_path = Path(args.ida_path)
    idb_path = Path(args.idb_path)
    output_dir = Path(args.output_dir)
    if not ida_path.exists():
        raise RuntimeError("IDA executable not found: %s" % ida_path)
    if not idb_path.exists():
        raise RuntimeError("IDB path not found: %s" % idb_path)
    if args.no_pdb and (args.pdb_path or args.symbol_path):
        raise RuntimeError("--no-pdb cannot be used together with --pdb-path or --symbol-path")

    batch_script = ROOT / "tools" / "pseudoforge_ida_batch.py"
    if not batch_script.exists():
        raise RuntimeError("IDA batch script not found: %s" % batch_script)

    output_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = _safe_file_stem(idb_path.stem)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    functions_dir = output_dir / "functions"
    report_path = output_dir / ("%s_%s.jsonl" % (safe_stem, timestamp))
    summary_path = output_dir / "pseudoforge-ida-summary.json"
    manifest_path = output_dir / "pseudoforge-ida-run.json"
    forge_path = output_dir / ("%s.forge" % safe_stem)
    ida_log_path = output_dir / ("%s_%s_ida.log" % (safe_stem, timestamp))
    cancel_file_is_default = not bool(args.cancel_file)
    cancel_file = Path(args.cancel_file) if args.cancel_file else output_dir / "pseudoforge-ida-cancel.txt"
    corpus_metadata_path = output_dir / "pseudoforge-corpus-metadata.json"
    corpus_index_path = output_dir / "pseudoforge-corpus-index.json"
    corpus_overview_path = output_dir / "pseudoforge-corpus-overview.md"
    compare_dir = Path(args.compare_dir) if args.compare_dir else None
    pdb_paths = _resolve_pdb_paths(args.pdb_path)
    pdb_symbol_path, pdb_alt_symbol_path = _build_symbol_paths(args.symbol_path, pdb_paths)
    ida_env = _build_ida_env(pdb_symbol_path, pdb_alt_symbol_path)
    batch_args = _build_batch_args(
        args,
        batch_script=batch_script,
        idb_path=idb_path,
        functions_dir=functions_dir,
        report_path=report_path,
        forge_path=forge_path,
        cancel_file=cancel_file,
        corpus_metadata_path=corpus_metadata_path,
        compare_dir=compare_dir,
    )
    ida_args = _build_ida_args(args, ida_path, idb_path, ida_log_path, batch_args)
    return IdaCliRun(
        ida_path=ida_path,
        idb_path=idb_path,
        output_dir=output_dir,
        functions_dir=functions_dir,
        report_path=report_path,
        summary_path=summary_path,
        manifest_path=manifest_path,
        forge_path=forge_path,
        ida_log_path=ida_log_path,
        cancel_file=cancel_file,
        cancel_file_is_default=cancel_file_is_default,
        corpus_metadata_path=corpus_metadata_path,
        corpus_index_path=corpus_index_path,
        corpus_overview_path=corpus_overview_path,
        compare_dir=compare_dir,
        batch_args=batch_args,
        ida_args=ida_args,
        ida_env=ida_env,
        pdb_paths=pdb_paths,
        pdb_symbol_path=pdb_symbol_path,
        pdb_alt_symbol_path=pdb_alt_symbol_path,
    )


def _build_batch_args(
    args: argparse.Namespace,
    batch_script: Path,
    idb_path: Path,
    functions_dir: Path,
    report_path: Path,
    forge_path: Path,
    cancel_file: Path,
    corpus_metadata_path: Path,
    compare_dir: Path | None,
) -> list[str]:
    target_path = Path(args.target_path) if args.target_path else idb_path
    result = [
        str(batch_script),
        "--report",
        str(report_path),
        "--forge-path",
        str(forge_path),
        "--target-path",
        str(target_path),
        "--export-dir",
        str(functions_dir),
        "--corpus-metadata",
        str(corpus_metadata_path),
        "--llm-renames-auto",
    ]
    if not args.allow_no_llm:
        result.append("--require-configured-llm")
    if compare_dir is not None:
        result.extend(["--compare-dir", str(compare_dir)])
    _append_option(result, "--profile-dir", args.profile_dir)
    result.extend(["--cancel-file", str(cancel_file)])
    _append_int_option(result, "--max-functions", args.max_functions)
    _append_int_option(result, "--max-seconds", args.max_seconds)
    _append_int_option(result, "--metadata-max-strings", args.metadata_max_strings)
    _append_int_option(result, "--metadata-max-names", args.metadata_max_names)
    _append_option(result, "--start-ea", args.start_ea)
    _append_option(result, "--end-ea", args.end_ea)
    _append_option(result, "--name-regex", args.name_regex)
    if args.resume:
        result.append("--resume")
    else:
        result.append("--overwrite-forge")
    if args.skip_lib_thunk:
        result.append("--skip-lib-thunk")
    if args.stop_on_error:
        result.append("--stop-on-error")
    if args.no_auto_wait:
        result.append("--no-auto-wait")
    return result


def _subprocess_kwargs(run: IdaCliRun, args: argparse.Namespace) -> dict[str, Any]:
    kwargs: dict[str, Any] = {} if args.visible else hidden_subprocess_kwargs()
    if run.ida_env is not None:
        kwargs["env"] = run.ida_env
    return kwargs


def _run_ida_and_monitor(run: IdaCliRun, args: argparse.Namespace) -> tuple[int | None, int, bool]:
    process = subprocess.Popen(
        run.ida_args,
        cwd=str(ROOT),
        **_subprocess_kwargs(run, args),
    )
    monitor = _ReportProgressMonitor(run.report_path)
    try:
        ida_exit_code = _wait_for_process_exit(process, monitor, timeout_seconds=None)
        return ida_exit_code, int(ida_exit_code if ida_exit_code is not None else 1), False
    except KeyboardInterrupt:
        print("Ctrl+C received; requesting IDA batch cancellation.", file=sys.stderr)
        ida_exit_code = _request_process_stop(process, run.cancel_file, monitor)
        return ida_exit_code, 130, True


def _wait_for_process_exit(
    process: subprocess.Popen[Any],
    monitor: _ReportProgressMonitor,
    timeout_seconds: float | None,
) -> int | None:
    deadline = None if timeout_seconds is None else time.monotonic() + max(0.0, timeout_seconds)
    while True:
        exit_code = process.poll()
        monitor.poll(final=exit_code is not None)
        if exit_code is not None:
            return int(exit_code)
        if deadline is not None and time.monotonic() >= deadline:
            return None
        time.sleep(0.25)


def _request_process_stop(
    process: subprocess.Popen[Any],
    cancel_file: Path,
    monitor: _ReportProgressMonitor,
    cancel_timeout_seconds: float = 5.0,
    terminate_timeout_seconds: float = 5.0,
) -> int | None:
    cancel_requested = False
    try:
        _write_cancel_file(cancel_file)
        cancel_requested = True
        print("Cancel file: %s" % cancel_file, file=sys.stderr)
    except OSError as exc:
        print("Cancel file write failed: %s" % exc, file=sys.stderr)

    if cancel_requested:
        try:
            exit_code = _wait_for_process_exit(process, monitor, timeout_seconds=cancel_timeout_seconds)
            if exit_code is not None:
                return exit_code
        except KeyboardInterrupt:
            print("Second Ctrl+C received; terminating IDA process.", file=sys.stderr)

    print("IDA is still running; terminating process.", file=sys.stderr)
    try:
        process.terminate()
    except OSError as exc:
        print("IDA terminate failed: %s" % exc, file=sys.stderr)
    try:
        exit_code = _wait_for_process_exit(process, monitor, timeout_seconds=terminate_timeout_seconds)
        if exit_code is not None:
            return exit_code
    except KeyboardInterrupt:
        print("Additional Ctrl+C received; killing IDA process.", file=sys.stderr)

    print("IDA did not terminate; killing process.", file=sys.stderr)
    try:
        process.kill()
    except OSError as exc:
        print("IDA kill failed: %s" % exc, file=sys.stderr)
    try:
        return _wait_for_process_exit(process, monitor, timeout_seconds=terminate_timeout_seconds)
    except KeyboardInterrupt:
        return None


def _clear_cancel_file(cancel_file: Path) -> None:
    try:
        cancel_file.unlink()
    except FileNotFoundError:
        pass


def _write_cancel_file(cancel_file: Path) -> None:
    cancel_file.parent.mkdir(parents=True, exist_ok=True)
    cancel_file.write_text("cancel requested\n", encoding="utf-8")


def _print_progress_line(line: str) -> None:
    text = line.strip()
    if not text:
        return
    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        return
    if record.get("event") != "progress" or record.get("phase") != "function_start":
        return
    index = _safe_int(record.get("index"))
    total = _safe_int(record.get("selected_functions"))
    name = str(record.get("name") or "<unnamed>")
    ea = str(record.get("ea") or "")
    if index > 0 and total > 0:
        prefix = "Analyzing %d/%d: %s" % (index, total, name)
    elif index > 0:
        prefix = "Analyzing %d: %s" % (index, name)
    else:
        prefix = "Analyzing: %s" % name
    if ea:
        prefix = "%s (%s)" % (prefix, ea)
    print(prefix, flush=True)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _build_ida_args(
    args: argparse.Namespace,
    ida_path: Path,
    idb_path: Path,
    ida_log_path: Path,
    batch_args: list[str],
) -> list[str]:
    script_command = subprocess.list2cmdline(batch_args)
    result = [str(ida_path), "-A"]
    if args.no_pdb:
        result.append("-Opdb:off")
    result.append("-L" + str(ida_log_path))
    result.append("-S" + script_command)
    result.append(str(idb_path))
    return result


def _append_option(result: list[str], name: str, value: str) -> None:
    if value:
        result.extend([name, str(value)])


def _append_int_option(result: list[str], name: str, value: int) -> None:
    if value > 0:
        result.extend([name, str(value)])


def _resolve_pdb_paths(values: list[str]) -> list[Path]:
    result: list[Path] = []
    for value in values or []:
        for part in str(value).split(";"):
            text = part.strip().strip('"')
            if not text:
                continue
            path = Path(text)
            if not path.exists():
                raise RuntimeError("PDB path not found: %s" % path)
            result.append(path)
    return result


def _build_symbol_paths(raw_symbol_path: str, pdb_paths: list[Path]) -> tuple[str, str]:
    entries = _split_symbol_path(raw_symbol_path)
    entries.extend(_pdb_search_entry(path) for path in pdb_paths)
    if not entries:
        return "", ""
    symbol_path = ";".join(_dedupe_symbol_entries(entries + _split_symbol_path(os.environ.get("_NT_SYMBOL_PATH", ""))))
    alt_symbol_path = ";".join(_dedupe_symbol_entries(entries + _split_symbol_path(os.environ.get("_NT_ALT_SYMBOL_PATH", ""))))
    return symbol_path, alt_symbol_path


def _build_ida_env(pdb_symbol_path: str, pdb_alt_symbol_path: str) -> dict[str, str] | None:
    if not pdb_symbol_path and not pdb_alt_symbol_path:
        return None
    env = dict(os.environ)
    if pdb_symbol_path:
        env["_NT_SYMBOL_PATH"] = pdb_symbol_path
    if pdb_alt_symbol_path:
        env["_NT_ALT_SYMBOL_PATH"] = pdb_alt_symbol_path
    return env


def _split_symbol_path(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split(";") if part.strip()]


def _pdb_search_entry(path: Path) -> str:
    return str(path.parent if path.is_file() else path)


def _dedupe_symbol_entries(entries: list[str]) -> list[str]:
    result = []
    seen = set()
    for entry in entries:
        key = entry.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
    return result


def _write_summary(run: IdaCliRun) -> dict[str, Any] | None:
    if not run.report_path.exists():
        return None
    summary = summarize_records(load_records(run.report_path))
    run.summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True), encoding="utf-8")
    return summary


def _write_corpus_index(run: IdaCliRun) -> dict[str, Any] | None:
    if not run.functions_dir.exists():
        return None
    from tools.pseudoforge_corpus_index import build_corpus_index

    index = build_corpus_index(
        run.output_dir,
        functions_dir=run.functions_dir,
        metadata_path=run.corpus_metadata_path,
        report_path=run.report_path,
        index_path=run.corpus_index_path,
        overview_path=run.corpus_overview_path,
    )
    return {
        "index_path": str(run.corpus_index_path),
        "overview_path": str(run.corpus_overview_path),
        "functions": int(index.get("overview", {}).get("functions", 0) or 0),
        "clusters": len(index.get("clusters", [])),
    }


def _write_manifest(
    run: IdaCliRun,
    args: argparse.Namespace,
    status: str,
    ida_exit_code: int | None,
    pid: int | None,
    summary: dict[str, Any] | None,
    index_result: dict[str, Any] | None,
) -> None:
    payload: dict[str, Any] = {
        "mode": "ida_auto_cli",
        "pseudoforge_version": VERSION,
        "status": status,
        "ida_exit_code": ida_exit_code,
        "pid": pid,
        "ida_path": str(run.ida_path),
        "idb_path": str(run.idb_path),
        "output_dir": str(run.output_dir),
        "functions_dir": str(run.functions_dir),
        "forge_path": str(run.forge_path),
        "report_path": str(run.report_path),
        "summary_path": str(run.summary_path),
        "manifest_path": str(run.manifest_path),
        "ida_log_path": str(run.ida_log_path),
        "cancel_file": str(run.cancel_file),
        "corpus_metadata_path": str(run.corpus_metadata_path),
        "corpus_index_path": str(run.corpus_index_path),
        "corpus_overview_path": str(run.corpus_overview_path),
        "compare_dir": str(run.compare_dir) if run.compare_dir else "",
        "pdb": {
            "enabled": not bool(args.no_pdb),
            "disabled": bool(args.no_pdb),
            "paths": [str(path) for path in run.pdb_paths],
            "symbol_path": run.pdb_symbol_path,
            "alt_symbol_path": run.pdb_alt_symbol_path,
        },
        "llm": {
            "mode": "plugin_config",
            "required": not bool(args.allow_no_llm),
        },
        "ida_args": list(run.ida_args),
        "batch_args": list(run.batch_args),
    }
    if summary is not None:
        payload["summary"] = summary.get("summary", {})
        payload["status_counts"] = summary.get("status_counts", {})
        payload["llm_status_counts"] = summary.get("llm_status_counts", {})
    if index_result is not None:
        payload["corpus_index"] = index_result
    run.manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _print_start(run: IdaCliRun, args: argparse.Namespace) -> None:
    print("PseudoForge IDA CLI")
    print("Version: %s" % VERSION)
    print("IDA: %s" % run.ida_path)
    print("IDB: %s" % run.idb_path)
    print("Output: %s" % run.output_dir)
    print("Functions: %s" % run.functions_dir)
    print("Forge: %s" % run.forge_path)
    print("Corpus metadata: %s" % run.corpus_metadata_path)
    print("Corpus index: %s" % run.corpus_index_path)
    print("Report: %s" % run.report_path)
    print("IDA log: %s" % run.ida_log_path)
    print("Cancel file: %s" % run.cancel_file)
    if args.no_pdb:
        print("PDB: disabled (-Opdb:off)")
    elif run.pdb_symbol_path:
        print("PDB symbol path: %s" % run.pdb_symbol_path)
    else:
        print("PDB: IDA defaults")
    print("LLM: plugin settings%s" % ("" if not args.allow_no_llm else " (optional)"))
    if not args.no_wait and not args.dry_run:
        print("Press Ctrl+C to request cancellation.")


def _print_finish(
    run: IdaCliRun,
    exit_code: int | None,
    summary: dict[str, Any] | None,
    args: argparse.Namespace,
) -> None:
    print("IDA exit: %s" % ("unknown" if exit_code is None else exit_code))
    if summary is not None:
        print("Summary: %s" % run.summary_path)
        if not args.no_summary:
            print_text_summary(summary)
    else:
        print("Summary: not written because report was not found")
    print("Manifest: %s" % run.manifest_path)


def _safe_file_stem(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    return cleaned.strip("._") or "idb"


if __name__ == "__main__":
    raise SystemExit(main())
