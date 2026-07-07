from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_pseudoforge.version import VERSION, plugin_title
from tools.summarize_pseudoforge_ida_batch import load_records, summarize_records


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_INTERESTING_LINE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bDriverEntry\b",
        r"\bIRP_MJ_",
        r"\bIOCTL\b",
        r"\bDeviceIoControl\b",
        r"\bIo[A-Z][A-Za-z0-9_]*\b",
        r"\bZw[A-Z][A-Za-z0-9_]*\b",
        r"\bNt[A-Z][A-Za-z0-9_]*\b",
        r"\bPs[A-Z][A-Za-z0-9_]*\b",
        r"\bOb[A-Z][A-Za-z0-9_]*\b",
        r"\bMm[A-Z][A-Za-z0-9_]*\b",
        r"\bKe[A-Z][A-Za-z0-9_]*\b",
        r"\bEx[A-Z][A-Za-z0-9_]*\b",
        r"\bCm[A-Z][A-Za-z0-9_]*\b",
        r"\bWdf[A-Z][A-Za-z0-9_]*\b",
        r"\bFlt[A-Z][A-Za-z0-9_]*\b",
        r"\breturn STATUS_",
        r"\bcase\s+0x[0-9A-Fa-f]+",
    )
]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    index = build_corpus_index(
        args.output_dir,
        functions_dir=Path(args.functions_dir) if args.functions_dir else None,
        metadata_path=Path(args.metadata) if args.metadata else None,
        report_path=Path(args.report) if args.report else None,
        index_path=Path(args.index_output) if args.index_output else None,
        overview_path=Path(args.markdown_output) if args.markdown_output else None,
        max_cleaned_chars=args.max_cleaned_chars,
    )
    if args.json:
        print(json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True))
    else:
        overview = index.get("overview", {})
        print("PseudoForge corpus index")
        print("Functions: %s" % overview.get("functions", 0))
        print("Clusters: %s" % len(index.get("clusters", [])))
        print("Index: %s" % index.get("index_path", ""))
        print("Overview: %s" % index.get("overview_path", ""))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a searchable PseudoForge corpus index from IDA batch artifacts.")
    parser.add_argument("--version", action="version", version=plugin_title())
    parser.add_argument("output_dir", help="PseudoForge IDA CLI output directory.")
    parser.add_argument("--functions-dir", default="", help="Override per-function export bundle directory.")
    parser.add_argument("--metadata", default="", help="Override corpus metadata JSON path.")
    parser.add_argument("--report", default="", help="Override IDA batch JSONL report path.")
    parser.add_argument("--index-output", default="", help="Output corpus index JSON path.")
    parser.add_argument("--markdown-output", default="", help="Output corpus overview Markdown path.")
    parser.add_argument("--max-cleaned-chars", type=int, default=4000, help="Maximum cleaned excerpt chars per function.")
    parser.add_argument("--json", action="store_true", help="Print the generated index JSON to stdout.")
    return parser


def build_corpus_index(
    output_dir: str | Path,
    functions_dir: str | Path | None = None,
    metadata_path: str | Path | None = None,
    report_path: str | Path | None = None,
    index_path: str | Path | None = None,
    overview_path: str | Path | None = None,
    max_cleaned_chars: int = 4000,
) -> dict[str, Any]:
    output_root = Path(output_dir)
    manifest = _read_json(output_root / "pseudoforge-ida-run.json")
    functions_root = Path(functions_dir) if functions_dir is not None else _manifest_path(
        manifest,
        "functions_dir",
        output_root / "functions",
    )
    metadata_file = Path(metadata_path) if metadata_path is not None else _manifest_path(
        manifest,
        "corpus_metadata_path",
        output_root / "pseudoforge-corpus-metadata.json",
    )
    report_file = Path(report_path) if report_path is not None else _manifest_path(
        manifest,
        "report_path",
        _latest_report(output_root),
    )
    index_file = Path(index_path) if index_path is not None else output_root / "pseudoforge-corpus-index.json"
    overview_file = Path(overview_path) if overview_path is not None else output_root / "pseudoforge-corpus-overview.md"
    metadata = _read_json(metadata_file)
    if not isinstance(metadata, dict):
        metadata = {}
    report_summary = _summarize_report(report_file)
    metadata_functions = {
        _normalize_ea(item.get("ea", "")): item
        for item in _coerce_list(metadata.get("functions", []))
        if isinstance(item, dict) and _normalize_ea(item.get("ea", ""))
    }

    functions = []
    for summary_path in _iter_summary_paths(functions_root):
        item = _build_function_index_item(
            summary_path,
            metadata_functions,
            max_cleaned_chars=max(0, max_cleaned_chars),
        )
        if item:
            functions.append(item)
    functions.sort(key=lambda item: int(str(item.get("ea", "0")), 0))

    clusters = _build_clusters(functions)
    overview = _build_overview(functions, clusters, metadata, report_summary)
    index = {
        "schema": "pseudoforge_corpus_index_v1",
        "pseudoforge_version": VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "output_dir": str(output_root),
        "functions_dir": str(functions_root),
        "metadata_path": str(metadata_file),
        "report_path": str(report_file) if report_file else "",
        "index_path": str(index_file),
        "overview_path": str(overview_file),
        "overview": overview,
        "clusters": clusters,
        "functions": functions,
        "metadata": _metadata_brief(metadata),
        "report_summary": report_summary,
    }
    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_text(json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    overview_file.parent.mkdir(parents=True, exist_ok=True)
    overview_file.write_text(render_overview_markdown(index), encoding="utf-8")
    return index


def _build_function_index_item(
    summary_path: Path,
    metadata_functions: dict[str, dict[str, Any]],
    max_cleaned_chars: int,
) -> dict[str, Any] | None:
    summary = _read_json(summary_path)
    if not summary:
        return None
    artifacts = _coerce_dict(summary.get("artifacts", {}))
    ea = _normalize_ea(summary.get("function_ea", ""))
    name = str(summary.get("function", "") or summary_path.parent.name)
    metadata = _coerce_dict(metadata_functions.get(ea, {}))
    cleaned_path = _artifact_path(artifacts, "cleaned_pseudocode")
    raw_path = _artifact_path(artifacts, "raw_pseudocode")
    rename_map_path = _artifact_path(artifacts, "rename_map")
    warnings_path = _artifact_path(artifacts, "warnings")
    buffer_contracts_path = _artifact_path(artifacts, "buffer_contracts")
    rule_report_path = _artifact_path(artifacts, "rule_report")
    cleaned_text = _read_text(cleaned_path)
    raw_text = _read_text(raw_path)
    rename_map = _coerce_dict(_read_json(rename_map_path))
    warnings = _read_json(warnings_path)
    if not isinstance(warnings, list):
        warnings = []
    buffer_contracts = _read_json(buffer_contracts_path)
    if not isinstance(buffer_contracts, list):
        buffer_contracts = []
    rule_report = _coerce_dict(_read_json(rule_report_path))
    active_renames = [
        item
        for item in rename_map.get("renames", []) or []
        if isinstance(item, dict) and item.get("apply")
    ]
    imports_called = _coerce_list(metadata.get("imports_called", []))
    strings_referenced = _coerce_list(metadata.get("strings_referenced", []))
    data_refs = _coerce_list(metadata.get("data_refs", []))
    interesting_lines = _interesting_lines(cleaned_text or raw_text)
    tags = _classify_function(
        name=name,
        cleaned_text=cleaned_text,
        imports_called=imports_called,
        strings_referenced=strings_referenced,
        buffer_contracts=buffer_contracts,
        rule_report=rule_report,
        metadata=metadata,
    )
    terms = sorted(
        _tokens(name)
        | set(tags)
        | _tokens(" ".join(str(item.get("name", "")) for item in imports_called if isinstance(item, dict)))
        | _tokens(" ".join(str(item.get("value", "")) for item in strings_referenced if isinstance(item, dict)))
        | _tokens(" ".join(_data_ref_search_text(item) for item in data_refs if isinstance(item, dict)))
        | _tokens("\n".join(interesting_lines))
    )
    return {
        "ea": ea,
        "name": name,
        "directory": str(summary_path.parent),
        "summary_path": str(summary_path),
        "artifacts": artifacts,
        "tags": tags,
        "terms": terms[:512],
        "source_path": str(summary.get("source_path", "")),
        "mode": str(summary.get("mode", "")),
        "counts": {
            "rename_candidates": int(summary.get("rename_candidates", 0) or 0),
            "renames": int(summary.get("renames", 0) or 0),
            "flow_rewrites": int(summary.get("flow_rewrites", 0) or 0),
            "buffer_contracts": int(summary.get("buffer_contracts", len(buffer_contracts)) or 0),
            "warnings": int(summary.get("warnings", len(warnings)) or 0),
            "active_renames": len(active_renames),
            "matched_rules": int(_coerce_dict(summary.get("rule_diagnostics", {})).get("matched_rules", 0) or 0),
            "data_refs": len(data_refs),
        },
        "llm_status": str(summary.get("llm_status", "")),
        "llm_provider": str(summary.get("llm_provider", "")),
        "callee_eas": _normalize_ea_list(metadata.get("callee_eas", [])),
        "callee_names": [str(item) for item in _coerce_list(metadata.get("callee_names", []))],
        "caller_eas": _normalize_ea_list(metadata.get("caller_eas", [])),
        "caller_names": [str(item) for item in _coerce_list(metadata.get("caller_names", []))],
        "imports_called": imports_called[:64],
        "strings_referenced": strings_referenced[:64],
        "data_refs": data_refs,
        "interesting_lines": interesting_lines[:32],
        "cleaned_excerpt": (cleaned_text or raw_text)[:max_cleaned_chars],
    }


def _classify_function(
    name: str,
    cleaned_text: str,
    imports_called: list[Any],
    strings_referenced: list[Any],
    buffer_contracts: list[Any],
    rule_report: dict[str, Any],
    metadata: dict[str, Any],
) -> list[str]:
    text = "\n".join(
        [
            name,
            cleaned_text[:12000],
            " ".join(str(item.get("name", "")) for item in imports_called if isinstance(item, dict)),
            " ".join(str(item.get("value", "")) for item in strings_referenced if isinstance(item, dict)),
        ]
    ).lower()
    tags = set()
    if "driverentry" in text:
        tags.add("entrypoint")
    if "irp_mj" in text or "dispatch" in text:
        tags.add("dispatch")
    if "ioctl" in text or "iostacklocation" in text or buffer_contracts:
        tags.add("ioctl")
    if "callback" in text or "notifyroutine" in text or "createprocessnotify" in text:
        tags.add("callback")
    if any(token in text for token in ("psset", "pslookup", "process", "thread", "image notify")):
        tags.add("process_thread")
    if any(token in text for token in ("obregistercallbacks", "oboperation", "handle")):
        tags.add("object_callback")
    if any(token in text for token in ("mm", "mdl", "pool", "virtual", "physical", "probe")):
        tags.add("memory")
    if any(token in text for token in ("zwcreatefile", "zwreadfile", "fileobject", "registry", "cmregister")):
        tags.add("io_registry")
    if any(token in text for token in ("wdf", "wdm", "deviceobject", "symboliclink")):
        tags.add("driver_framework")
    if rule_report.get("matched_rules"):
        tags.add("rule_matched")
    if metadata.get("is_thunk"):
        tags.add("thunk")
    if metadata.get("is_library"):
        tags.add("library")
    if not tags:
        tags.add("general")
    return sorted(tags)


def _build_clusters(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for function in functions:
        for tag in function.get("tags", []) or []:
            grouped[str(tag)].append(function)
    clusters = []
    for tag, items in sorted(grouped.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        clusters.append(
            {
                "tag": tag,
                "count": len(items),
                "functions": [
                    {
                        "ea": item.get("ea", ""),
                        "name": item.get("name", ""),
                        "summary_path": item.get("summary_path", ""),
                    }
                    for item in items[:200]
                ],
            }
        )
    return clusters


def _build_overview(
    functions: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    metadata: dict[str, Any],
    report_summary: dict[str, Any],
) -> dict[str, Any]:
    warning_count = sum(int(item.get("counts", {}).get("warnings", 0) or 0) for item in functions)
    buffer_count = sum(int(item.get("counts", {}).get("buffer_contracts", 0) or 0) for item in functions)
    llm_counts = Counter(str(item.get("llm_status", "")) for item in functions if item.get("llm_status"))
    return {
        "functions": len(functions),
        "imports": len(metadata.get("imports", []) or []),
        "exports": len(metadata.get("exports", []) or []),
        "strings": len(metadata.get("strings", []) or []),
        "segments": len(metadata.get("segments", []) or []),
        "warnings": warning_count,
        "buffer_contracts": buffer_count,
        "llm_status_counts": dict(sorted(llm_counts.items())),
        "top_clusters": [
            {"tag": item["tag"], "count": item["count"]}
            for item in clusters[:12]
        ],
        "report_status_counts": report_summary.get("status_counts", {}),
    }


def render_overview_markdown(index: dict[str, Any]) -> str:
    overview = index.get("overview", {})
    lines = [
        "# PseudoForge Corpus Overview",
        "",
        "- Schema: `%s`" % index.get("schema", ""),
        "- PseudoForge version: `%s`" % index.get("pseudoforge_version", ""),
        "- Functions: %s" % overview.get("functions", 0),
        "- Imports: %s" % overview.get("imports", 0),
        "- Exports: %s" % overview.get("exports", 0),
        "- Strings: %s" % overview.get("strings", 0),
        "- Warnings: %s" % overview.get("warnings", 0),
        "- Buffer contracts: %s" % overview.get("buffer_contracts", 0),
        "",
        "## Clusters",
        "",
    ]
    for cluster in index.get("clusters", [])[:20]:
        lines.append("- `%s`: %s functions" % (cluster.get("tag", ""), cluster.get("count", 0)))
    lines.extend(["", "## High-Signal Functions", ""])
    for function in _high_signal_functions(index.get("functions", []))[:30]:
        lines.append(
            "- `%s` `%s`: tags=%s warnings=%s buffers=%s"
            % (
                function.get("ea", ""),
                function.get("name", ""),
                ",".join(function.get("tags", [])),
                function.get("counts", {}).get("warnings", 0),
                function.get("counts", {}).get("buffer_contracts", 0),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _high_signal_functions(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def score(function: dict[str, Any]) -> int:
        tags = set(function.get("tags", []) or [])
        counts = _coerce_dict(function.get("counts", {}))
        value = 0
        value += 8 if "entrypoint" in tags else 0
        value += 7 if "ioctl" in tags else 0
        value += 6 if "callback" in tags else 0
        value += 5 if "dispatch" in tags else 0
        value += int(counts.get("buffer_contracts", 0) or 0) * 3
        value += min(5, int(counts.get("warnings", 0) or 0))
        value += min(5, len(function.get("imports_called", []) or []))
        return value

    return sorted(functions, key=score, reverse=True)


def _iter_summary_paths(functions_root: Path) -> list[Path]:
    if not functions_root.exists():
        return []
    paths = sorted(functions_root.glob("*/*.ida-batch-summary.json"))
    if paths:
        return paths
    return sorted(functions_root.glob("*/*.summary.json"))


def _interesting_lines(text: str) -> list[str]:
    result = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(pattern.search(stripped) for pattern in _INTERESTING_LINE_PATTERNS):
            result.append(stripped[:240])
    return result


def _tokens(text: str) -> set[str]:
    return {item.lower() for item in _TOKEN_RE.findall(text or "")}


def _data_ref_search_text(item: dict[str, Any]) -> str:
    return " ".join(
        str(item.get(key, "") or "")
        for key in ("target_ea", "target_name", "segment", "ref_kind", "value")
    )


def _artifact_path(artifacts: dict[str, Any], key: str) -> Path:
    value = str(artifacts.get(key, "") or "")
    return Path(value) if value else Path()


def _read_json(path: str | Path) -> dict[str, Any] | list[Any]:
    path = Path(path)
    if not str(path) or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def _read_text(path: Path) -> str:
    if not str(path) or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _summarize_report(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {}
    return summarize_records(load_records(path))


def _latest_report(output_root: Path) -> Path | None:
    reports = sorted(output_root.glob("*.jsonl"), key=lambda item: item.stat().st_mtime if item.exists() else 0)
    return reports[-1] if reports else None


def _manifest_path(manifest: dict[str, Any] | list[Any], key: str, fallback: Path | None) -> Path | None:
    if isinstance(manifest, dict):
        value = str(manifest.get(key, "") or "")
        if value:
            return Path(value)
    return fallback


def _metadata_brief(metadata: dict[str, Any] | list[Any]) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    return {
        "schema": metadata.get("schema", ""),
        "idb_path": metadata.get("idb_path", ""),
        "target_path": metadata.get("target_path", ""),
        "image_base": metadata.get("image_base", ""),
        "processor": metadata.get("processor", ""),
        "segments": metadata.get("segments", []),
    }


def _normalize_ea(value: object) -> str:
    try:
        return "0x%X" % int(str(value), 0)
    except (TypeError, ValueError):
        return ""


def _normalize_ea_list(values: object) -> list[str]:
    return [item for item in (_normalize_ea(value) for value in _coerce_list(values)) if item]


def _coerce_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _coerce_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


if __name__ == "__main__":
    raise SystemExit(main())
