from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.atlas import generate_atlas
from tools.kernel_corpus.builder import build_pack
from tools.kernel_corpus.errors import KernelCorpusError
from tools.kernel_corpus.lifecycle import trace_lifecycle
from tools.kernel_corpus.query import corpus_status, get_neighbors, search_functions


PROFILE_SCHEMA = "kernel_corpus_performance_profile_v1"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = run_profile(
            pack_root=args.pack_root or None,
            build_corpus_root=args.build_corpus_root or None,
            build_pack_root=args.build_pack_root or None,
            overwrite_build=args.overwrite_build,
            query=args.query,
            tag=args.tag,
            neighbor_ea=args.neighbor_ea,
            lifecycle_topic=args.lifecycle_topic,
            lifecycle_max_seeds=args.lifecycle_max_seeds,
            lifecycle_depth=args.lifecycle_depth,
            atlas_output_dir=args.atlas_output_dir or None,
            atlas_limit=args.atlas_limit,
            skip_atlas=args.skip_atlas,
        )
    except (OSError, KernelCorpusError, ValueError) as exc:
        print("Kernel corpus performance profile failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def run_profile(
    *,
    pack_root: str | Path | None,
    build_corpus_root: str | Path | None = None,
    build_pack_root: str | Path | None = None,
    overwrite_build: bool = False,
    query: str = "process",
    tag: str = "process_thread",
    neighbor_ea: str = "",
    lifecycle_topic: str = "process_object",
    lifecycle_max_seeds: int = 32,
    lifecycle_depth: int = 2,
    atlas_output_dir: str | Path | None = None,
    atlas_limit: int = 24,
    skip_atlas: bool = False,
) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    active_pack_root = Path(pack_root) if pack_root is not None else None

    if build_corpus_root is not None or build_pack_root is not None:
        if build_corpus_root is None or build_pack_root is None:
            raise ValueError("--build-corpus-root and --build-pack-root must be used together")
        build_result = _time_operation(
            "pack_build",
            lambda: build_pack(
                build_corpus_root,
                build_pack_root,
                overwrite=overwrite_build,
            ),
            _summarize_build,
        )
        operations.append(build_result)
        active_pack_root = Path(build_pack_root)

    if active_pack_root is None:
        raise ValueError("A --pack-root or --build-pack-root is required")

    status_result = _time_operation("status", lambda: corpus_status(active_pack_root), _summarize_status)
    operations.append(status_result)

    text_results: list[dict[str, Any]] = []
    text_result = _time_operation(
        "text_search",
        lambda: search_functions(active_pack_root, query=query, limit=24),
        lambda payload: _summarize_search(payload, "query", query),
    )
    text_results = text_result.pop("_payload")
    operations.append(text_result)

    tag_results: list[dict[str, Any]] = []
    tag_result = _time_operation(
        "tag_search",
        lambda: search_functions(active_pack_root, tags=[tag], limit=24),
        lambda payload: _summarize_search(payload, "tag", tag),
    )
    tag_results = tag_result.pop("_payload")
    operations.append(tag_result)

    root_ea = str(neighbor_ea or "")
    if not root_ea:
        root_ea = _first_ea(text_results) or _first_ea(tag_results)
    if root_ea:
        operations.append(
            _time_operation(
                "neighbor_traversal",
                lambda: get_neighbors(active_pack_root, root_ea, direction="both", depth=2, limit=120),
                _summarize_neighbors,
            )
        )
    else:
        operations.append(
            {
                "name": "neighbor_traversal",
                "ok": False,
                "duration_ms": 0.0,
                "summary": {"reason": "no root EA found"},
            }
        )

    operations.append(
        _time_operation(
            "lifecycle_tracing",
            lambda: trace_lifecycle(
                active_pack_root,
                lifecycle_topic,
                max_seeds=lifecycle_max_seeds,
                depth=lifecycle_depth,
            ),
            _summarize_lifecycle,
        )
    )

    if not skip_atlas:
        temp_dir: tempfile.TemporaryDirectory[str] | None = None
        atlas_dir: Path
        if atlas_output_dir is None:
            temp_dir = tempfile.TemporaryDirectory(prefix="kernel-corpus-atlas-profile-")
            atlas_dir = Path(temp_dir.name)
        else:
            atlas_dir = Path(atlas_output_dir)
            if atlas_dir.exists():
                shutil.rmtree(atlas_dir)
        try:
            operations.append(
                _time_operation(
                    "atlas_generation",
                    lambda: generate_atlas(active_pack_root, atlas_dir, limit=atlas_limit),
                    _summarize_atlas,
                )
            )
        finally:
            if temp_dir is not None:
                temp_dir.cleanup()

    return {
        "schema": PROFILE_SCHEMA,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "pack_root": str(active_pack_root.resolve()),
        "parameters": {
            "query": query,
            "tag": tag,
            "neighbor_ea": root_ea,
            "lifecycle_topic": lifecycle_topic,
            "lifecycle_max_seeds": lifecycle_max_seeds,
            "lifecycle_depth": lifecycle_depth,
            "atlas_limit": atlas_limit,
            "skip_atlas": skip_atlas,
        },
        "operations": operations,
    }


def _time_operation(
    name: str,
    callback: Callable[[], Any],
    summarize: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    started = time.perf_counter_ns()
    payload = callback()
    duration_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    result = {
        "name": name,
        "ok": True,
        "duration_ms": round(duration_ms, 3),
        "summary": summarize(payload),
    }
    if name in {"text_search", "tag_search"}:
        result["_payload"] = payload
    return result


def _summarize_build(payload: dict[str, Any]) -> dict[str, Any]:
    manifest = payload.get("manifest", {}) if isinstance(payload.get("manifest"), dict) else {}
    return {
        "function_count": int(manifest.get("function_count", 0) or 0),
        "edge_count": int(manifest.get("edge_count", 0) or 0),
        "tag_count": int(manifest.get("tag_count", 0) or 0),
        "fts5_enabled": bool(manifest.get("fts5_enabled", False)),
    }


def _summarize_status(payload: dict[str, Any]) -> dict[str, Any]:
    counts = payload.get("counts", {}) if isinstance(payload.get("counts"), dict) else {}
    manifest = payload.get("manifest", {}) if isinstance(payload.get("manifest"), dict) else {}
    return {
        "function_count": int(manifest.get("function_count", 0) or 0),
        "skipped_count": int(manifest.get("skipped_count", 0) or 0),
        "call_edges": int(counts.get("call_edges", 0) or 0),
        "function_fts": int(counts.get("function_fts", 0) or 0),
        "warning_count": len(payload.get("warnings", []) if isinstance(payload.get("warnings"), list) else []),
    }


def _summarize_search(payload: list[dict[str, Any]], field: str, value: str) -> dict[str, Any]:
    return {
        field: value,
        "result_count": len(payload),
        "first_ea": _first_ea(payload),
        "first_name": str(payload[0].get("name", "")) if payload else "",
    }


def _summarize_neighbors(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "root_ea": str(payload.get("root_ea", "")),
        "node_count": len(payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []),
        "edge_count": len(payload.get("edges", []) if isinstance(payload.get("edges"), list) else []),
        "depth": int(payload.get("depth", 0) or 0),
        "limit": int(payload.get("limit", 0) or 0),
    }


def _summarize_lifecycle(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    candidates = payload.get("candidates", []) if isinstance(payload.get("candidates"), list) else []
    edges = payload.get("edges", []) if isinstance(payload.get("edges"), list) else []
    return {
        "topic": str(payload.get("topic", "")),
        "selected_count": len(candidates),
        "edge_count": len(edges),
        "phase_count": int(summary.get("phase_count", 0) or 0),
        "gap_count": len(payload.get("gaps", []) if isinstance(payload.get("gaps"), list) else []),
    }


def _summarize_atlas(payload: dict[str, Any]) -> dict[str, Any]:
    pages = payload.get("pages", []) if isinstance(payload.get("pages"), list) else []
    return {
        "page_count": int(payload.get("page_count", 0) or 0),
        "total_functions": sum(int(page.get("function_count", 0) or 0) for page in pages if isinstance(page, dict)),
        "total_hubs": sum(int(page.get("hub_count", 0) or 0) for page in pages if isinstance(page, dict)),
        "total_gaps": sum(int(page.get("gap_count", 0) or 0) for page in pages if isinstance(page, dict)),
    }


def _first_ea(results: list[dict[str, Any]]) -> str:
    if not results:
        return ""
    return str(results[0].get("ea", ""))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Profile Kernel Corpus build and retrieval scale behavior.")
    parser.add_argument("--pack-root", default="", help="Existing Kernel Corpus pack root.")
    parser.add_argument("--build-corpus-root", default="", help="Optional source corpus root to profile pack build.")
    parser.add_argument("--build-pack-root", default="", help="Optional output pack root for build profiling.")
    parser.add_argument("--overwrite-build", action="store_true", help="Overwrite existing build-profile pack artifacts.")
    parser.add_argument("--query", default="process", help="Text query for the text search timing.")
    parser.add_argument("--tag", default="process_thread", help="Tag for the tag search timing.")
    parser.add_argument("--neighbor-ea", default="", help="Optional root EA for neighbor traversal.")
    parser.add_argument("--lifecycle-topic", default="process_object", help="Lifecycle topic to profile.")
    parser.add_argument("--lifecycle-max-seeds", type=int, default=32, help="Lifecycle max seed count.")
    parser.add_argument("--lifecycle-depth", type=int, default=2, help="Lifecycle graph expansion depth.")
    parser.add_argument("--atlas-output-dir", default="", help="Optional atlas output dir. Default uses a temp dir.")
    parser.add_argument("--atlas-limit", type=int, default=24, help="Atlas per-page function limit.")
    parser.add_argument("--skip-atlas", action="store_true", help="Skip atlas generation timing.")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
