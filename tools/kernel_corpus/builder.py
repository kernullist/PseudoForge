from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.ea import normalize_ea
from tools.kernel_corpus.errors import InvalidCorpusError, KernelCorpusError
from tools.kernel_corpus.paths import validate_corpus_root
from tools.kernel_corpus.schema import (
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_VERSION,
    PACK_SCHEMA_VERSION,
    PSEUDOFORGE_INDEX_SCHEMA,
    SQLITE_FILENAME,
)
from tools.kernel_corpus.store import connect_database, create_schema, import_index, write_manifest_rows


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = build_pack(
            args.corpus_root,
            args.pack_root,
            overwrite=args.overwrite,
            max_cleaned_chars=args.max_cleaned_chars,
        )
    except KernelCorpusError as exc:
        print("Kernel corpus builder failed: %s" % exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    else:
        manifest = result["manifest"]
        print("Kernel corpus pack built")
        print("Pack root: %s" % result["pack_root"])
        print("SQLite: %s" % result["sqlite_path"])
        print("Functions: %s" % manifest["function_count"])
        print("Unique EAs: %s" % manifest["unique_ea_count"])
        print("FTS5: %s" % ("enabled" if manifest["fts5_enabled"] else "disabled"))
    return 0


def build_pack(
    corpus_root: str | Path,
    pack_root: str | Path,
    *,
    overwrite: bool = False,
    max_cleaned_chars: int = 4000,
) -> dict[str, Any]:
    corpus_paths = validate_corpus_root(corpus_root)
    source_index = _read_index(corpus_paths.index_path)
    pack_path = Path(pack_root)
    sqlite_path = pack_path / SQLITE_FILENAME
    manifest_path = pack_path / MANIFEST_FILENAME
    _prepare_pack_root(pack_path, sqlite_path, manifest_path, overwrite=overwrite)

    index_hash = _sha256_file(corpus_paths.index_path)
    manifest = _build_manifest(
        source_index,
        corpus_paths.index_path,
        corpus_paths.root,
        sqlite_path,
        max_cleaned_chars=max_cleaned_chars,
        source_index_sha256=index_hash,
    )
    with connect_database(sqlite_path) as connection:
        fts5_enabled = create_schema(connection)
        import_summary = import_index(
            connection,
            source_index,
            corpus_paths.root,
            max_cleaned_chars=max_cleaned_chars,
            fts5_enabled=fts5_enabled,
        )
        manifest.update(import_summary)
        manifest["fts5_enabled"] = fts5_enabled
        write_manifest_rows(connection, manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    return {
        "pack_root": str(pack_path.resolve()),
        "sqlite_path": str(sqlite_path.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "manifest": manifest,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a SQLite Kernel Corpus pack from PseudoForge artifacts.")
    parser.add_argument("--corpus-root", required=True, help="PseudoForge corpus output directory.")
    parser.add_argument("--pack-root", required=True, help="Output directory for manifest.json and corpus.sqlite.")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing manifest or SQLite pack.")
    parser.add_argument("--max-cleaned-chars", type=int, default=4000, help="Maximum cleaned excerpt chars per function.")
    parser.add_argument("--json", action="store_true", help="Print the build result as JSON.")
    return parser


def _prepare_pack_root(pack_root: Path, sqlite_path: Path, manifest_path: Path, *, overwrite: bool) -> None:
    if pack_root.exists() and not pack_root.is_dir():
        raise InvalidCorpusError("Pack root exists but is not a directory: %s" % pack_root)
    pack_root.mkdir(parents=True, exist_ok=True)
    existing = [path for path in (sqlite_path, manifest_path) if path.exists()]
    if existing and not overwrite:
        raise KernelCorpusError("Pack already exists; use --overwrite: %s" % ", ".join(str(path) for path in existing))
    if overwrite:
        for path in existing:
            if path.is_dir():
                raise KernelCorpusError("Refusing to overwrite directory artifact: %s" % path)
            path.unlink()


def _read_index(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidCorpusError("Corpus index could not be read: %s" % exc) from exc
    if not isinstance(data, dict):
        raise InvalidCorpusError("Corpus index is not a JSON object: %s" % path)
    if data.get("schema") != PSEUDOFORGE_INDEX_SCHEMA:
        raise InvalidCorpusError("Unsupported corpus index schema: %s" % data.get("schema", ""))
    return data


def _build_manifest(
    index: dict[str, Any],
    index_path: Path,
    corpus_root: Path,
    sqlite_path: Path,
    *,
    max_cleaned_chars: int,
    source_index_sha256: str,
) -> dict[str, Any]:
    functions = [item for item in index.get("functions", []) or [] if isinstance(item, dict)]
    unique_eas = set()
    for function in functions:
        try:
            unique_eas.add(normalize_ea(function.get("ea", "")))
        except (TypeError, ValueError):
            continue
    overview = index.get("overview", {}) if isinstance(index.get("overview"), dict) else {}
    report_counts = overview.get("report_status_counts", {}) if isinstance(overview.get("report_status_counts"), dict) else {}
    report_summary = index.get("report_summary", {}) if isinstance(index.get("report_summary"), dict) else {}
    status_counts = report_summary.get("status_counts", {}) if isinstance(report_summary.get("status_counts"), dict) else {}
    metadata = index.get("metadata", {}) if isinstance(index.get("metadata"), dict) else {}
    skipped_count = int(report_counts.get("skipped", status_counts.get("skipped", 0)) or 0)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return {
        "schema": MANIFEST_SCHEMA_VERSION,
        "pack_schema": PACK_SCHEMA_VERSION,
        "source_index_schema": str(index.get("schema", "")),
        "source_corpus_root": str(corpus_root.resolve()),
        "source_index_path": str(index_path.resolve()),
        "source_index_sha256": source_index_sha256,
        "sqlite_path": str(sqlite_path.resolve()),
        "pseudoforge_version": str(index.get("pseudoforge_version", "")),
        "target_path": str(metadata.get("target_path", "")),
        "function_count": len(functions),
        "unique_ea_count": len(unique_eas),
        "skipped_count": skipped_count,
        "max_cleaned_chars": max(0, int(max_cleaned_chars or 0)),
        "fts5_enabled": False,
        "generated_at": generated_at,
        "builder": "tools.kernel_corpus.builder",
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
