from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError
from tools.kernel_corpus.schema import (
    EVIDENCE_PACK_SCHEMA_VERSION,
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    PACK_SCHEMA_VERSION,
    SQLITE_FILENAME,
)
from tools.kernel_corpus.store import connect_database, read_manifest_rows

REPORT_SCHEMA_VERSION = "kernel_corpus_pack_validation_report_v1"
ATLAS_DIR = Path("reports") / "atlas"
EVIDENCE_PACK_DIR = Path("evidence-packs")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = validate_pack(
            args.pack_root,
            evidence_packs=args.evidence_pack,
            atlas_pages=args.atlas_page,
            include_derived=args.include_derived,
        )
    except (OSError, KernelCorpusError, ValueError) as exc:
        print("Kernel corpus pack validation failed: %s" % exc, file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    else:
        print(format_text_report(report))
    return 0 if report["ok"] else 2


def validate_pack(
    pack_root: str | Path,
    *,
    evidence_packs: list[str] | tuple[str, ...] | None = None,
    atlas_pages: list[str] | tuple[str, ...] | None = None,
    include_derived: bool = False,
) -> dict[str, Any]:
    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    root = Path(pack_root)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA_VERSION,
        "ok": False,
        "status": "fail",
        "checked_at": checked_at,
        "pack_root": str(root.resolve()) if root.exists() else str(root),
        "manifest_path": str((root / MANIFEST_FILENAME).resolve()) if root.exists() else str(root / MANIFEST_FILENAME),
        "sqlite_path": str((root / SQLITE_FILENAME).resolve()) if root.exists() else str(root / SQLITE_FILENAME),
        "manifest": {},
        "counts": {},
        "derived": {
            "evidence_packs": [],
            "atlas_pages": [],
        },
        "issues": [],
        "summary": {},
    }
    issues: list[dict[str, Any]] = report["issues"]

    if not root.exists():
        _issue(issues, "error", "pack_root_missing", "Pack root does not exist.", path=root)
        return _finalize(report)
    if not root.is_dir():
        _issue(issues, "error", "pack_root_not_directory", "Pack root is not a directory.", path=root)
        return _finalize(report)

    manifest_path = root / MANIFEST_FILENAME
    sqlite_path = root / SQLITE_FILENAME
    if not manifest_path.is_file():
        _issue(issues, "error", "manifest_missing", "Pack manifest is missing.", path=manifest_path)
    if not sqlite_path.is_file():
        _issue(issues, "error", "sqlite_missing", "Pack SQLite database is missing.", path=sqlite_path)

    manifest = _read_json_file(manifest_path, issues, label="manifest") if manifest_path.is_file() else {}
    if manifest:
        report["manifest"] = _manifest_summary(manifest)
        _validate_manifest_schema(manifest, issues, manifest_path)

    if sqlite_path.is_file():
        _validate_sqlite_pack(sqlite_path, manifest, report, issues)

    if manifest:
        _validate_source_index_hash(manifest, issues)

    evidence_paths = _derived_paths(
        root,
        evidence_packs or [],
        EVIDENCE_PACK_DIR,
        "*.json",
        include_derived,
    )
    atlas_paths = _derived_paths(
        root,
        atlas_pages or [],
        ATLAS_DIR,
        "*.md",
        include_derived,
    )
    manifest_generated = _parse_timestamp(str(manifest.get("generated_at", "") if manifest else ""))
    for path in evidence_paths:
        result = _validate_evidence_pack(path, root, manifest, manifest_generated, issues)
        report["derived"]["evidence_packs"].append(result)
    for path in atlas_paths:
        result = _validate_atlas_page(path, root, manifest, manifest_generated, issues)
        report["derived"]["atlas_pages"].append(result)

    return _finalize(report)


def format_text_report(report: dict[str, Any]) -> str:
    status = str(report.get("status", "fail")).upper()
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    lines = [
        "Kernel Corpus pack validation: %s" % status,
        "Pack root: %s" % report.get("pack_root", ""),
        "Errors: %s" % summary.get("error_count", 0),
        "Warnings: %s" % summary.get("warning_count", 0),
    ]
    counts = report.get("counts", {}) if isinstance(report.get("counts"), dict) else {}
    if counts:
        lines.append("Functions: manifest=%s sqlite=%s" % (
            report.get("manifest", {}).get("function_count", ""),
            counts.get("functions", ""),
        ))
    for issue in report.get("issues", []):
        if not isinstance(issue, dict):
            continue
        line = "[%s] %s: %s" % (
            str(issue.get("severity", "")).upper(),
            issue.get("code", ""),
            issue.get("message", ""),
        )
        if issue.get("path"):
            line += " (%s)" % issue["path"]
        lines.append(line)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Kernel Corpus pack freshness and derived artifacts.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--evidence-pack", action="append", default=[], help="Optional evidence-pack JSON path. Can be repeated.")
    parser.add_argument("--atlas-page", action="append", default=[], help="Optional atlas Markdown page path. Can be repeated.")
    parser.add_argument("--include-derived", action="store_true", help="Scan <pack-root>\\evidence-packs and <pack-root>\\reports\\atlas.")
    parser.add_argument("--format", choices=("json", "text"), default="json", help="Output format.")
    return parser


def _validate_manifest_schema(manifest: dict[str, Any], issues: list[dict[str, Any]], path: Path) -> None:
    _require_manifest_value(manifest, issues, path, "schema", MANIFEST_SCHEMA_VERSION)
    _require_manifest_value(manifest, issues, path, "pack_schema", PACK_SCHEMA_VERSION)
    for key in ("source_index_sha256", "source_index_path", "function_count", "unique_ea_count", "generated_at"):
        if str(manifest.get(key, "")) == "":
            _issue(issues, "error", "manifest_field_missing", "Manifest field is missing: %s" % key, path=path)


def _require_manifest_value(
    manifest: dict[str, Any],
    issues: list[dict[str, Any]],
    path: Path,
    key: str,
    expected: str,
) -> None:
    actual = str(manifest.get(key, ""))
    if actual != expected:
        _issue(
            issues,
            "error",
            "unsupported_manifest_schema",
            "Unsupported manifest %s." % key,
            path=path,
            expected=expected,
            actual=actual,
        )


def _validate_sqlite_pack(
    sqlite_path: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    issues: list[dict[str, Any]],
) -> None:
    try:
        with connect_database(sqlite_path) as connection:
            db_manifest = read_manifest_rows(connection)
            _validate_db_manifest_rows(manifest, db_manifest, issues, sqlite_path)
            counts = _sqlite_counts(connection, issues, sqlite_path)
            report["counts"] = counts
            _validate_counts(manifest, counts, issues, sqlite_path)
    except sqlite3.Error as exc:
        _issue(issues, "error", "sqlite_unreadable", "Pack SQLite database could not be read: %s" % exc, path=sqlite_path)


def _validate_db_manifest_rows(
    manifest: dict[str, Any],
    db_manifest: dict[str, str],
    issues: list[dict[str, Any]],
    sqlite_path: Path,
) -> None:
    if not manifest:
        return
    if not db_manifest:
        _issue(issues, "error", "sqlite_manifest_empty", "SQLite corpus_manifest table has no rows.", path=sqlite_path)
        return
    for key, value in sorted(manifest.items()):
        expected = _manifest_row_value(value)
        actual = db_manifest.get(key)
        if actual is None:
            _issue(
                issues,
                "error",
                "sqlite_manifest_key_missing",
                "SQLite corpus_manifest row is missing: %s" % key,
                path=sqlite_path,
                expected=expected,
                actual="",
            )
        elif actual != expected:
            _issue(
                issues,
                "error",
                "sqlite_manifest_mismatch",
                "SQLite corpus_manifest row differs: %s" % key,
                path=sqlite_path,
                expected=expected,
                actual=actual,
            )


def _sqlite_counts(
    connection: sqlite3.Connection,
    issues: list[dict[str, Any]],
    sqlite_path: Path,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in ("functions", "function_tags", "call_edges", "function_imports", "function_strings"):
        counts[table] = _table_count(connection, table, issues, sqlite_path)
    if _has_table(connection, "function_fts"):
        counts["function_fts"] = _table_count(connection, "function_fts", issues, sqlite_path)
    else:
        counts["function_fts"] = 0
    return counts


def _validate_counts(
    manifest: dict[str, Any],
    counts: dict[str, int],
    issues: list[dict[str, Any]],
    sqlite_path: Path,
) -> None:
    count_pairs = (
        ("function_count", "functions"),
        ("unique_ea_count", "functions"),
        ("tag_count", "function_tags"),
        ("edge_count", "call_edges"),
        ("import_count", "function_imports"),
        ("string_count", "function_strings"),
    )
    for manifest_key, table_key in count_pairs:
        if manifest_key not in manifest:
            continue
        expected = _int_or_none(manifest.get(manifest_key))
        actual = counts.get(table_key)
        if expected is None or actual is None:
            continue
        if expected != actual:
            _issue(
                issues,
                "error",
                "count_mismatch",
                "Manifest count %s does not match SQLite %s rows." % (manifest_key, table_key),
                path=sqlite_path,
                expected=expected,
                actual=actual,
            )
    if bool(manifest.get("fts5_enabled", False)) and "fts_row_count" in manifest:
        expected = _int_or_none(manifest.get("fts_row_count"))
        actual = counts.get("function_fts")
        if expected is not None and actual is not None and expected != actual:
            _issue(
                issues,
                "error",
                "count_mismatch",
                "Manifest fts_row_count does not match SQLite function_fts rows.",
                path=sqlite_path,
                expected=expected,
                actual=actual,
            )


def _validate_source_index_hash(manifest: dict[str, Any], issues: list[dict[str, Any]]) -> None:
    expected = str(manifest.get("source_index_sha256", "") or "")
    source_path = Path(str(manifest.get("source_index_path", "") or ""))
    if not expected:
        return
    if not str(source_path):
        _issue(issues, "warning", "source_index_unverifiable", "Manifest has no source index path.")
        return
    if not source_path.is_file():
        _issue(
            issues,
            "warning",
            "source_index_unverifiable",
            "Source index path is not accessible; freshness cannot be verified.",
            path=source_path,
        )
        return
    actual = _sha256_file(source_path)
    if actual != expected:
        _issue(
            issues,
            "error",
            "source_index_hash_mismatch",
            "Current source index hash differs from manifest.source_index_sha256.",
            path=source_path,
            expected=expected,
            actual=actual,
        )


def _validate_evidence_pack(
    path: Path,
    pack_root: Path,
    manifest: dict[str, Any],
    manifest_generated: datetime | None,
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    result = {
        "path": str(path.resolve()) if path.exists() else str(path),
        "ok": False,
        "topic": "",
        "created_at": "",
    }
    if not path.is_file():
        _issue(issues, "warning", "evidence_pack_missing", "Evidence pack does not exist.", path=path)
        return result
    data = _read_json_file(path, issues, label="evidence pack")
    if not data:
        return result
    result["topic"] = str(data.get("topic", "") or "")
    result["created_at"] = str(data.get("created_at", "") or "")
    if str(data.get("schema", "")) != EVIDENCE_PACK_SCHEMA_VERSION:
        _issue(
            issues,
            "error",
            "evidence_schema_mismatch",
            "Evidence pack schema is unsupported.",
            path=path,
            expected=EVIDENCE_PACK_SCHEMA_VERSION,
            actual=str(data.get("schema", "")),
        )
    if not _same_path(data.get("pack_root", ""), pack_root):
        _issue(
            issues,
            "error",
            "evidence_pack_root_mismatch",
            "Evidence pack pack_root does not match validated pack root.",
            path=path,
            expected=str(pack_root.resolve()),
            actual=str(data.get("pack_root", "")),
        )
    expected_topic = _expected_evidence_topic(path, pack_root)
    if expected_topic and result["topic"] != expected_topic:
        _issue(
            issues,
            "error",
            "evidence_topic_mismatch",
            "Evidence pack topic does not match its filename.",
            path=path,
            expected=expected_topic,
            actual=result["topic"],
        )
    _validate_generated_time(
        issues,
        path,
        result["created_at"],
        manifest_generated,
        missing_code="evidence_created_at_missing",
        stale_code="evidence_pack_stale",
        label="Evidence pack",
    )
    status = data.get("status", {}) if isinstance(data.get("status"), dict) else {}
    _compare_optional_status_count(status, manifest, issues, path, "function_count")
    _compare_optional_status_count(status, manifest, issues, path, "skipped_count")
    result["ok"] = not _path_has_errors(issues, path)
    return result


def _validate_atlas_page(
    path: Path,
    pack_root: Path,
    manifest: dict[str, Any],
    manifest_generated: datetime | None,
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    result = {
        "path": str(path.resolve()) if path.exists() else str(path),
        "ok": False,
        "generated_at": "",
        "pack_root": "",
        "schema_version": "",
    }
    if not path.is_file():
        _issue(issues, "warning", "atlas_page_missing", "Atlas page does not exist.", path=path)
        return result
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _issue(issues, "warning", "atlas_page_unreadable", "Atlas page could not be read: %s" % exc, path=path)
        return result
    metadata = _atlas_metadata(text)
    result.update(metadata)
    if metadata.get("pack_root") and not _same_path(metadata.get("pack_root", ""), pack_root):
        _issue(
            issues,
            "error",
            "atlas_pack_root_mismatch",
            "Atlas page pack root does not match validated pack root.",
            path=path,
            expected=str(pack_root.resolve()),
            actual=metadata.get("pack_root", ""),
        )
    elif not metadata.get("pack_root"):
        _issue(issues, "warning", "atlas_pack_root_missing", "Atlas page has no pack-root metadata.", path=path)
    expected_schema = str(manifest.get("pack_schema", "") or PACK_SCHEMA_VERSION)
    if metadata.get("schema_version") and metadata.get("schema_version") != expected_schema:
        _issue(
            issues,
            "error",
            "atlas_schema_mismatch",
            "Atlas page schema metadata does not match pack schema.",
            path=path,
            expected=expected_schema,
            actual=metadata.get("schema_version", ""),
        )
    elif not metadata.get("schema_version"):
        _issue(issues, "warning", "atlas_schema_missing", "Atlas page has no schema metadata.", path=path)
    _validate_generated_time(
        issues,
        path,
        metadata.get("generated_at", ""),
        manifest_generated,
        missing_code="atlas_generated_at_missing",
        stale_code="atlas_page_stale",
        label="Atlas page",
    )
    if metadata.get("function_count") and "function_count" in manifest:
        expected_count = _int_or_none(manifest.get("function_count"))
        actual_count = _int_or_none(metadata.get("function_count"))
        if expected_count is not None and actual_count is not None and expected_count != actual_count:
            _issue(
                issues,
                "error",
                "atlas_function_count_mismatch",
                "Atlas page function-count metadata does not match manifest.",
                path=path,
                expected=expected_count,
                actual=actual_count,
            )
    result["ok"] = not _path_has_errors(issues, path)
    return result


def _validate_generated_time(
    issues: list[dict[str, Any]],
    path: Path,
    value: str,
    manifest_generated: datetime | None,
    *,
    missing_code: str,
    stale_code: str,
    label: str,
) -> None:
    if not value:
        _issue(issues, "warning", missing_code, "%s has no generated timestamp." % label, path=path)
        return
    generated = _parse_timestamp(value)
    if generated is None:
        _issue(issues, "warning", missing_code, "%s generated timestamp could not be parsed." % label, path=path, actual=value)
        return
    if manifest_generated is not None and generated < manifest_generated:
        _issue(
            issues,
            "error",
            stale_code,
            "%s is older than the pack manifest and should be regenerated." % label,
            path=path,
            expected=manifest_generated.isoformat(),
            actual=generated.isoformat(),
        )


def _compare_optional_status_count(
    status: dict[str, Any],
    manifest: dict[str, Any],
    issues: list[dict[str, Any]],
    path: Path,
    key: str,
) -> None:
    if key not in status or key not in manifest:
        return
    expected = _int_or_none(manifest.get(key))
    actual = _int_or_none(status.get(key))
    if expected is not None and actual is not None and expected != actual:
        _issue(
            issues,
            "error",
            "evidence_status_count_mismatch",
            "Evidence pack status %s does not match pack manifest." % key,
            path=path,
            expected=expected,
            actual=actual,
        )


def _read_json_file(path: Path, issues: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _issue(issues, "error", "%s_unreadable" % label.replace(" ", "_"), "%s could not be read: %s" % (label.title(), exc), path=path)
        return {}
    if not isinstance(data, dict):
        _issue(issues, "error", "%s_not_object" % label.replace(" ", "_"), "%s is not a JSON object." % label.title(), path=path)
        return {}
    return data


def _derived_paths(
    pack_root: Path,
    explicit_paths: list[str] | tuple[str, ...],
    relative_dir: Path,
    pattern: str,
    include_derived: bool,
) -> list[Path]:
    paths = [Path(item) for item in explicit_paths if str(item)]
    if include_derived:
        directory = pack_root / relative_dir
        if directory.is_dir():
            paths.extend(sorted(directory.glob(pattern), key=lambda item: str(item).lower()))
    return _dedupe_paths(paths)


def _atlas_metadata(text: str) -> dict[str, str]:
    metadata = {
        "generated_at": _match_markdown_value(text, r"^Generated:\s*`([^`]+)`"),
        "pack_root": _match_markdown_value(text, r"^\s*-\s*Pack root:\s*`([^`]+)`"),
        "schema_version": _match_markdown_value(text, r"^\s*-\s*Schema:\s*`([^`]+)`"),
        "function_count": _match_markdown_value(text, r"^\s*-\s*Functions:\s*`([^`]+)`"),
    }
    return metadata


def _match_markdown_value(text: str, pattern: str) -> str:
    match = re.search(pattern, text or "", flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _expected_evidence_topic(path: Path, pack_root: Path) -> str:
    try:
        parent = path.resolve().parent
        expected_parent = (pack_root / EVIDENCE_PACK_DIR).resolve()
    except OSError:
        return ""
    if _same_path(parent, expected_parent):
        return path.stem
    return ""


def _manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "schema",
        "pack_schema",
        "source_index_path",
        "source_index_sha256",
        "target_path",
        "function_count",
        "unique_ea_count",
        "skipped_count",
        "generated_at",
        "builder",
    )
    return {key: manifest.get(key, "") for key in keys if key in manifest}


def _finalize(report: dict[str, Any]) -> dict[str, Any]:
    issues = [issue for issue in report.get("issues", []) if isinstance(issue, dict)]
    error_count = sum(1 for issue in issues if issue.get("severity") == "error")
    warning_count = sum(1 for issue in issues if issue.get("severity") == "warning")
    report["summary"] = {
        "error_count": error_count,
        "warning_count": warning_count,
        "issue_count": len(issues),
    }
    report["ok"] = error_count == 0
    if error_count:
        report["status"] = "fail"
    elif warning_count:
        report["status"] = "warn"
    else:
        report["status"] = "pass"
    return report


def _issue(
    issues: list[dict[str, Any]],
    severity: str,
    code: str,
    message: str,
    *,
    path: str | Path | None = None,
    expected: Any = None,
    actual: Any = None,
) -> None:
    payload: dict[str, Any] = {
        "severity": severity,
        "code": code,
        "message": message,
    }
    if path is not None:
        payload["path"] = str(path)
    if expected is not None:
        payload["expected"] = expected
    if actual is not None:
        payload["actual"] = actual
    issues.append(payload)


def _path_has_errors(issues: list[dict[str, Any]], path: Path) -> bool:
    target = _path_key(path)
    return any(
        issue.get("severity") == "error" and _path_key(issue.get("path", "")) == target
        for issue in issues
        if isinstance(issue, dict)
    )


def _has_table(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?",
        (table,),
    ).fetchone() is not None


def _table_count(
    connection: sqlite3.Connection,
    table: str,
    issues: list[dict[str, Any]],
    sqlite_path: Path,
) -> int:
    try:
        return int(connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])
    except sqlite3.Error as exc:
        _issue(issues, "error", "sqlite_table_unreadable", "SQLite table could not be counted: %s" % table, path=sqlite_path, actual=str(exc))
        return 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_row_value(value: Any) -> str:
    if isinstance(value, (dict, list, tuple, bool)) or value is None:
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


def _parse_timestamp(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _same_path(left: Any, right: Any) -> bool:
    if not str(left) or not str(right):
        return False
    return _path_key(left) == _path_key(right)


def _path_key(value: Any) -> str:
    try:
        path = Path(str(value)).resolve()
    except OSError:
        path = Path(str(value)).absolute()
    return os.path.normcase(os.path.normpath(str(path)))


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    result = []
    seen = set()
    for path in paths:
        key = _path_key(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
