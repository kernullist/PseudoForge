from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.canonical_store import (  # noqa: E402
    CANONICAL_DIR_NAME,
    MAX_TOPICS as MAX_CANONICAL_TOPICS,
    PRIORITY_ORDER,
    STATUS_ORDER,
    list_canonical_answers,
)
from tools.kernel_corpus.errors import KernelCorpusError, QueryError  # noqa: E402
from tools.kernel_corpus.query import corpus_status  # noqa: E402

CANONICAL_DRIFT_SCHEMA_VERSION = "kernel_corpus_canonical_drift_v1"
DEFAULT_MAX_TOPICS = 20
MAX_TOPICS = 200
DEFAULT_MAX_FUNCTION_CHANGES = 20
DEFAULT_MAX_EDGE_CHANGES = 24
DEFAULT_MAX_ARTIFACT_PAIRS = 16
DEFAULT_REPORT_CHARS = 30000
MAX_REPORT_CHARS = 200000
SAFE_TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9_]*$")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = compare_canonical_answers(
            args.pack_root_a,
            args.pack_root_b,
            label_a=args.label_a or "",
            label_b=args.label_b or "",
            topic_id=args.topic or "",
            priority=args.priority or "",
            status=args.status or "",
            max_topics=args.max_topics,
        )
        if args.report_out:
            payload["report_out"] = write_report(payload, args.report_out, requested_format=args.format)
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel canonical drift compare failed: %s" % exc, file=sys.stderr)
        return 1

    if args.format == "markdown":
        print(render_markdown_report(payload))
    elif args.format == "text":
        print(render_text_report(payload))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def compare_canonical_answers(
    pack_root_a: str | Path,
    pack_root_b: str | Path,
    *,
    label_a: str = "",
    label_b: str = "",
    topic_id: str = "",
    priority: str = "",
    status: str = "",
    max_topics: int = DEFAULT_MAX_TOPICS,
) -> dict[str, Any]:
    selected_topic = str(topic_id or "").strip()
    if selected_topic:
        _validate_topic_id(selected_topic)
    priority_filter = str(priority or "").strip().upper()
    if priority_filter and priority_filter not in PRIORITY_ORDER:
        raise QueryError("Unsupported priority filter: %s" % priority)
    status_filter = str(status or "").strip().lower()
    if status_filter and status_filter not in STATUS_ORDER:
        raise QueryError("Unsupported status filter: %s" % status)

    side_a = _load_side(pack_root_a, label_a or "A")
    side_b = _load_side(pack_root_b, label_b or "B")
    limit = _bounded_int(max_topics, DEFAULT_MAX_TOPICS, MAX_TOPICS)
    topic_ids = _select_topic_ids(
        side_a,
        side_b,
        topic_id=selected_topic,
        priority=priority_filter,
        status=status_filter,
    )
    topic_ids.sort(key=lambda item: _topic_sort_key(item, side_a, side_b))
    selected_ids = topic_ids[:limit]
    topic_payloads = [_compare_topic(topic_id_value, side_a, side_b) for topic_id_value in selected_ids]
    warnings = []
    warnings.extend(_side_warnings(side_a))
    warnings.extend(_side_warnings(side_b))
    if topic_ids and len(topic_ids) > len(selected_ids):
        warnings.append("Topic comparison output truncated: returned %d of %d." % (len(selected_ids), len(topic_ids)))
    if selected_topic and selected_topic not in topic_ids:
        warnings.append("Requested topic was not found after filters: %s" % selected_topic)

    return {
        "schema": CANONICAL_DRIFT_SCHEMA_VERSION,
        "ok": True,
        "generated_at": _utc_now(),
        "pack_a": side_a["identity"],
        "pack_b": side_b["identity"],
        "labels": {
            "a": side_a["label"],
            "b": side_b["label"],
        },
        "filters": {
            "topic_id": selected_topic,
            "priority": priority_filter,
            "status": status_filter,
            "max_topics": limit,
        },
        "source_identity": _source_identity_payload(side_a, side_b),
        "catalog_summary": _catalog_summary(side_a, side_b, topic_ids, selected_ids),
        "topic_count": len(topic_ids),
        "returned_count": len(topic_payloads),
        "topics_truncated": len(topic_ids) > len(selected_ids),
        "topics": topic_payloads,
        "warnings": warnings,
    }


def get_canonical_drift_report(
    pack_root_a: str | Path,
    pack_root_b: str | Path,
    *,
    topic_id: str = "",
    priority: str = "",
    status: str = "",
    max_topics: int = DEFAULT_MAX_TOPICS,
    max_chars: int = DEFAULT_REPORT_CHARS,
) -> dict[str, Any]:
    payload = compare_canonical_answers(
        pack_root_a,
        pack_root_b,
        topic_id=topic_id,
        priority=priority,
        status=status,
        max_topics=max_topics,
    )
    limit = _bounded_int(max_chars, DEFAULT_REPORT_CHARS, MAX_REPORT_CHARS)
    markdown = render_markdown_report(payload)
    truncated = len(markdown) > limit
    return {
        "schema": "%s_report" % CANONICAL_DRIFT_SCHEMA_VERSION,
        "ok": True,
        "pack_root_a": payload["pack_a"]["pack_root"],
        "pack_root_b": payload["pack_b"]["pack_root"],
        "topic_id": str(topic_id or ""),
        "markdown": _truncate_text(markdown, limit),
        "max_chars": limit,
        "truncated": truncated,
        "warnings": payload.get("warnings", []),
    }


def write_report(payload: dict[str, Any], report_out: str | Path, *, requested_format: str = "json") -> str:
    path = Path(report_out)
    if any(part == ".." for part in path.parts):
        raise QueryError("Drift report output must not contain parent traversal: %s" % report_out)
    if not path.is_absolute():
        path = Path.cwd() / path
    resolved = path.resolve()
    for key in ("pack_a", "pack_b"):
        pack_root = Path(str(payload.get(key, {}).get("pack_root", "") or ""))
        if pack_root and _is_inside(resolved, pack_root):
            raise QueryError("Drift report output must not be inside compared pack roots: %s" % resolved)
    fmt = _format_from_path(resolved, requested_format)
    if fmt == "markdown":
        text = render_markdown_report(payload)
    elif fmt == "text":
        text = render_text_report(payload)
    else:
        text = json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(text, encoding="utf-8")
    return str(resolved)


def render_text_report(payload: dict[str, Any]) -> str:
    lines = [
        "Kernel canonical drift report",
        "schema: %s" % payload.get("schema", ""),
        "A: %s" % payload.get("pack_a", {}).get("pack_root", ""),
        "B: %s" % payload.get("pack_b", {}).get("pack_root", ""),
        "topics: %s returned=%s truncated=%s"
        % (payload.get("topic_count", 0), payload.get("returned_count", 0), payload.get("topics_truncated", False)),
    ]
    for topic in payload.get("topics", []):
        lines.append(
            "- %s presence=%s changed=%s"
            % (topic.get("topic_id", ""), topic.get("presence", ""), topic.get("changed", False))
        )
        catalog = topic.get("catalog_changes", {}) if isinstance(topic.get("catalog_changes"), dict) else {}
        if catalog.get("quality_status"):
            lines.append("  quality: %s -> %s" % (catalog["quality_status"].get("a", ""), catalog["quality_status"].get("b", "")))
        evidence = topic.get("evidence_changes", {}) if isinstance(topic.get("evidence_changes"), dict) else {}
        if evidence:
            lines.append(
                "  functions: same_name_ea=%d added=%d removed=%d phase=%d edges_added=%d edges_removed=%d"
                % (
                    len(evidence.get("same_name_different_ea", [])),
                    len(evidence.get("functions_added", [])),
                    len(evidence.get("functions_removed", [])),
                    len(evidence.get("phase_assignment_changes", [])),
                    len(evidence.get("call_edges_added", [])),
                    len(evidence.get("call_edges_removed", [])),
                )
            )
    for warning in payload.get("warnings", []):
        lines.append("warning: %s" % warning)
    return "\n".join(lines).rstrip() + "\n"


def render_markdown_report(payload: dict[str, Any], *, max_chars: int | None = None) -> str:
    source = payload.get("source_identity", {}) if isinstance(payload.get("source_identity"), dict) else {}
    catalog = payload.get("catalog_summary", {}) if isinstance(payload.get("catalog_summary"), dict) else {}
    lines = [
        "# Kernel Canonical Drift Report",
        "",
        "- Schema: `%s`" % payload.get("schema", ""),
        "- Generated: `%s`" % payload.get("generated_at", ""),
        "- A: `%s` `%s`" % (payload.get("labels", {}).get("a", "A"), payload.get("pack_a", {}).get("pack_root", "")),
        "- B: `%s` `%s`" % (payload.get("labels", {}).get("b", "B"), payload.get("pack_b", {}).get("pack_root", "")),
        "- Compared topics: `%s`; returned: `%s`; truncated: `%s`"
        % (payload.get("topic_count", 0), payload.get("returned_count", 0), payload.get("topics_truncated", False)),
        "",
        "## Source Identity",
        "",
        "| Field | A | B | Changed |",
        "| --- | --- | --- | --- |",
    ]
    for item in source.get("field_diffs", []):
        lines.append(
            "| `%s` | `%s` | `%s` | `%s` |"
            % (
                item.get("field", ""),
                _markdown_cell(item.get("a", "")),
                _markdown_cell(item.get("b", "")),
                item.get("changed", False),
            )
        )
    lines.extend(
        [
            "",
            "## Catalog",
            "",
            "- Common topics: `%s`" % catalog.get("common_count", 0),
            "- Missing in A: %s" % _inline_code_list(catalog.get("missing_in_a", [])),
            "- Missing in B: %s" % _inline_code_list(catalog.get("missing_in_b", [])),
            "",
            "## Topic Drift",
            "",
        ]
    )
    for topic in payload.get("topics", []):
        lines.extend(_topic_markdown(topic))
    warnings = [str(item) for item in payload.get("warnings", [])]
    if warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in warnings:
            lines.append("- %s" % warning)
    text = "\n".join(lines).rstrip() + "\n"
    if max_chars is not None:
        return _truncate_text(text, _bounded_int(max_chars, DEFAULT_REPORT_CHARS, MAX_REPORT_CHARS))
    return text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare Kernel Corpus canonical answer drift across two pack roots.")
    parser.add_argument("--pack-root-a", required=True, help="First Kernel Corpus pack root.")
    parser.add_argument("--pack-root-b", required=True, help="Second Kernel Corpus pack root.")
    parser.add_argument("--label-a", default="", help="Human label for pack A.")
    parser.add_argument("--label-b", default="", help="Human label for pack B.")
    parser.add_argument("--topic", default="", help="Optional canonical topic id.")
    parser.add_argument("--priority", default="", choices=("", "P0", "P1", "P2"), help="Optional priority filter.")
    parser.add_argument("--status", default="", choices=("", "pass", "degraded", "fail", "missing"), help="Optional quality status filter.")
    parser.add_argument("--max-topics", type=int, default=DEFAULT_MAX_TOPICS, help="Maximum topics to return.")
    parser.add_argument("--format", default="json", choices=("json", "text", "markdown"), help="Output format.")
    parser.add_argument("--report-out", default="", help="Optional output report path outside compared pack roots.")
    return parser


def _load_side(pack_root: str | Path, label: str) -> dict[str, Any]:
    root = Path(pack_root)
    status = corpus_status(root)
    catalog = list_canonical_answers(root, max_topics=MAX_CANONICAL_TOPICS)
    identity = _identity_payload(root, label, status, catalog)
    topics = {}
    warnings = list(_coerce_warnings(status)) + list(_coerce_warnings(catalog))
    canonical_root = root / CANONICAL_DIR_NAME
    if not (canonical_root / "quality-report.json").is_file():
        warnings.append("%s canonical quality-report.json is missing: %s" % (label, canonical_root / "quality-report.json"))
    if int(catalog.get("topic_count", 0) or 0) > int(catalog.get("returned_count", 0) or 0):
        warnings.append(
            "%s canonical catalog is truncated by canonical_store max_topics: %s of %s."
            % (label, catalog.get("returned_count", 0), catalog.get("topic_count", 0))
        )
    for metadata in catalog.get("topics", []):
        if not isinstance(metadata, dict):
            continue
        topic = _load_topic(root, metadata, label, warnings)
        topics[topic["topic_id"]] = topic
    return {
        "label": label,
        "root": root,
        "identity": identity,
        "catalog": catalog,
        "topics": topics,
        "warnings": warnings,
    }


def _identity_payload(root: Path, label: str, status: dict[str, Any], catalog: dict[str, Any]) -> dict[str, Any]:
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    return {
        "label": label,
        "pack_root": _path_payload(root),
        "manifest_path": str(status.get("manifest_path", "")),
        "sqlite_path": str(status.get("sqlite_path", "")),
        "canonical_root": str(catalog.get("canonical_root", "")),
        "schema_version": str(status.get("schema_version", "")),
        "target_path": str(manifest.get("target_path", "")),
        "source_corpus_root": str(manifest.get("source_corpus_root", "")),
        "source_index_path": str(manifest.get("source_index_path", "")),
        "source_index_sha256": str(manifest.get("source_index_sha256", "")),
        "function_count": _int_value(manifest.get("function_count"), 0),
        "skipped_count": _int_value(manifest.get("skipped_count"), 0),
        "generated_at": str(manifest.get("generated_at", "")),
    }


def _load_topic(root: Path, metadata: dict[str, Any], label: str, warnings: list[str]) -> dict[str, Any]:
    topic_id = str(metadata.get("topic_id", "") or "")
    paths = metadata.get("paths", {}) if isinstance(metadata.get("paths"), dict) else {}
    directory = Path(str(metadata.get("directory", "") or "")) if metadata.get("directory") else root / CANONICAL_DIR_NAME / str(metadata.get("priority", "")) / topic_id
    evidence_path = _artifact_path(paths, "evidence_pack", directory / "evidence-pack.json", directory, warnings)
    trace_path = _artifact_path(paths, "trace", directory / "trace.json", directory, warnings)
    manifest_path = _artifact_path(paths, "manifest", directory / "manifest.json", directory, warnings)
    validation_path = _artifact_path(paths, "validation", directory / "validation.json", directory, warnings)
    quality_json_path = directory / "quality.json"
    if not quality_json_path.is_file():
        warnings.append("%s canonical topic quality.json is missing for %s: %s" % (label, topic_id, quality_json_path))
    evidence = _read_json_object(evidence_path, warnings, "%s evidence-pack" % topic_id)
    trace = _read_json_object(trace_path, warnings, "%s trace" % topic_id)
    manifest = _read_json_object(manifest_path, warnings, "%s manifest" % topic_id)
    validation = _read_json_object(validation_path, warnings, "%s validation" % topic_id)
    quality = _read_json_object(quality_json_path, warnings, "%s quality" % topic_id)
    functions = _collect_functions(evidence, trace)
    edges = _collect_edges(evidence, functions["ea_to_key"], functions["by_key"])
    stale_warnings = _topic_stale_warnings(root, metadata, manifest, label, topic_id)
    warnings.extend(stale_warnings)
    return {
        "topic_id": topic_id,
        "metadata": metadata,
        "manifest": manifest,
        "validation": validation,
        "quality": quality,
        "evidence": evidence,
        "functions": functions["functions"],
        "function_by_key": functions["by_key"],
        "edges": edges,
        "directory": _path_payload(directory),
        "quality_json_path": _path_payload(quality_json_path),
        "warnings": stale_warnings,
    }


def _topic_stale_warnings(root: Path, metadata: dict[str, Any], manifest: dict[str, Any], label: str, topic_id: str) -> list[str]:
    warnings = []
    pack_status = corpus_status(root)
    pack_manifest = pack_status.get("manifest", {}) if isinstance(pack_status.get("manifest"), dict) else {}
    pack_hash = str(pack_manifest.get("source_index_sha256", "") or "")
    topic_hash = str(metadata.get("source_index_sha256", "") or manifest.get("source_index_sha256", "") or "")
    if pack_hash and topic_hash and pack_hash != topic_hash:
        warnings.append("%s canonical topic %s source_index_sha256 differs from pack manifest." % (label, topic_id))
    pack_generated = str(pack_manifest.get("generated_at", "") or "")
    topic_generated = str(metadata.get("pack_generated_at", "") or manifest.get("pack_generated_at", "") or "")
    if pack_generated and topic_generated and pack_generated != topic_generated:
        warnings.append("%s canonical topic %s pack_generated_at differs from pack manifest generated_at." % (label, topic_id))
    return warnings


def _select_topic_ids(
    side_a: dict[str, Any],
    side_b: dict[str, Any],
    *,
    topic_id: str,
    priority: str,
    status: str,
) -> list[str]:
    if topic_id:
        ids = [topic_id]
    else:
        ids = sorted(set(side_a["topics"]) | set(side_b["topics"]))
    result = []
    for current in ids:
        topic_a = side_a["topics"].get(current)
        topic_b = side_b["topics"].get(current)
        if priority and not _topic_matches_priority(topic_a, topic_b, priority):
            continue
        if status and not _topic_matches_status(topic_a, topic_b, status):
            continue
        result.append(current)
    return result


def _compare_topic(topic_id: str, side_a: dict[str, Any], side_b: dict[str, Any]) -> dict[str, Any]:
    topic_a = side_a["topics"].get(topic_id)
    topic_b = side_b["topics"].get(topic_id)
    presence = "both"
    if topic_a is None:
        presence = "missing_in_a"
    elif topic_b is None:
        presence = "missing_in_b"
    catalog_changes = _catalog_changes(topic_a, topic_b)
    evidence_changes = _evidence_changes(topic_a, topic_b) if topic_a is not None and topic_b is not None else {}
    changed = presence != "both" or _has_changes(catalog_changes) or _has_evidence_changes(evidence_changes)
    return {
        "topic_id": topic_id,
        "presence": presence,
        "changed": changed,
        "a": _topic_reference(topic_a),
        "b": _topic_reference(topic_b),
        "catalog_changes": catalog_changes,
        "evidence_changes": evidence_changes,
        "warnings": _topic_warnings(topic_a, topic_b),
    }


def _catalog_changes(topic_a: dict[str, Any] | None, topic_b: dict[str, Any] | None) -> dict[str, Any]:
    if topic_a is None or topic_b is None:
        return {}
    meta_a = topic_a["metadata"]
    meta_b = topic_b["metadata"]
    quality_a = meta_a.get("quality", {}) if isinstance(meta_a.get("quality"), dict) else {}
    quality_b = meta_b.get("quality", {}) if isinstance(meta_b.get("quality"), dict) else {}
    return {
        "priority": _field_change(meta_a.get("priority", ""), meta_b.get("priority", "")),
        "mode": _field_change(meta_a.get("mode", ""), meta_b.get("mode", "")),
        "title": _field_change(meta_a.get("title", ""), meta_b.get("title", "")),
        "quality_status": _field_change(quality_a.get("status", "missing"), quality_b.get("status", "missing")),
        "score": _number_change(quality_a.get("score"), quality_b.get("score")),
        "validation_warning_count": _number_change(
            quality_a.get("validation_warning_count"),
            quality_b.get("validation_warning_count"),
        ),
        "gap_count": _number_change(quality_a.get("gap_count"), quality_b.get("gap_count")),
        "selected_function_count": _number_change(
            quality_a.get("selected_function_count"),
            quality_b.get("selected_function_count"),
        ),
        "edge_count": _number_change(quality_a.get("edge_count"), quality_b.get("edge_count")),
    }


def _evidence_changes(topic_a: dict[str, Any], topic_b: dict[str, Any]) -> dict[str, Any]:
    functions_a = topic_a["function_by_key"]
    functions_b = topic_b["function_by_key"]
    keys_a = set(functions_a)
    keys_b = set(functions_b)
    common = sorted(keys_a & keys_b, key=lambda key: functions_b.get(key, functions_a[key])["name"].lower())
    same_name_different_ea = []
    phase_assignment_changes = []
    artifact_path_pairs = []
    for key in common:
        item_a = functions_a[key]
        item_b = functions_b[key]
        if item_a["eas"] != item_b["eas"]:
            same_name_different_ea.append(
                {
                    "name": item_b["name"],
                    "a_eas": item_a["eas"],
                    "b_eas": item_b["eas"],
                    "note": "EA differs for the same normalized function name; treat EA as build-local evidence.",
                }
            )
        if item_a["phases"] != item_b["phases"]:
            phase_assignment_changes.append(
                {
                    "name": item_b["name"],
                    "a_phases": item_a["phases"],
                    "b_phases": item_b["phases"],
                }
            )
        artifact_path_pairs.append(
            {
                "name": item_b["name"],
                "a_artifacts": item_a["artifacts"][:4],
                "b_artifacts": item_b["artifacts"][:4],
                "changed": item_a["artifacts"] != item_b["artifacts"],
            }
        )
    edge_keys_a = {_edge_key(edge) for edge in topic_a["edges"]}
    edge_keys_b = {_edge_key(edge) for edge in topic_b["edges"]}
    edge_by_key_a = {_edge_key(edge): edge for edge in topic_a["edges"]}
    edge_by_key_b = {_edge_key(edge): edge for edge in topic_b["edges"]}
    return {
        "same_name_different_ea": _limit_items(same_name_different_ea, DEFAULT_MAX_FUNCTION_CHANGES),
        "same_name_different_ea_truncated": len(same_name_different_ea) > DEFAULT_MAX_FUNCTION_CHANGES,
        "functions_added": _limit_items(
            [_function_summary(functions_b[key]) for key in sorted(keys_b - keys_a, key=lambda item: functions_b[item]["name"].lower())],
            DEFAULT_MAX_FUNCTION_CHANGES,
        ),
        "functions_added_truncated": len(keys_b - keys_a) > DEFAULT_MAX_FUNCTION_CHANGES,
        "functions_removed": _limit_items(
            [_function_summary(functions_a[key]) for key in sorted(keys_a - keys_b, key=lambda item: functions_a[item]["name"].lower())],
            DEFAULT_MAX_FUNCTION_CHANGES,
        ),
        "functions_removed_truncated": len(keys_a - keys_b) > DEFAULT_MAX_FUNCTION_CHANGES,
        "phase_assignment_changes": _limit_items(phase_assignment_changes, DEFAULT_MAX_FUNCTION_CHANGES),
        "phase_assignment_changes_truncated": len(phase_assignment_changes) > DEFAULT_MAX_FUNCTION_CHANGES,
        "call_edges_added": _limit_items(
            [edge_by_key_b[key] for key in sorted(edge_keys_b - edge_keys_a)],
            DEFAULT_MAX_EDGE_CHANGES,
        ),
        "call_edges_added_truncated": len(edge_keys_b - edge_keys_a) > DEFAULT_MAX_EDGE_CHANGES,
        "call_edges_removed": _limit_items(
            [edge_by_key_a[key] for key in sorted(edge_keys_a - edge_keys_b)],
            DEFAULT_MAX_EDGE_CHANGES,
        ),
        "call_edges_removed_truncated": len(edge_keys_a - edge_keys_b) > DEFAULT_MAX_EDGE_CHANGES,
        "artifact_path_pairs": _limit_items(artifact_path_pairs, DEFAULT_MAX_ARTIFACT_PAIRS),
        "artifact_path_pairs_truncated": len(artifact_path_pairs) > DEFAULT_MAX_ARTIFACT_PAIRS,
    }


def _collect_functions(evidence: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    by_key: dict[str, dict[str, Any]] = {}
    ea_to_key: dict[str, str] = {}
    for function in evidence.get("functions", []) if isinstance(evidence.get("functions"), list) else []:
        if isinstance(function, dict):
            _add_function(by_key, ea_to_key, function, str(function.get("phase", "") or "selected"))
    for phase in evidence.get("phases", []) if isinstance(evidence.get("phases"), list) else []:
        if not isinstance(phase, dict):
            continue
        phase_id = str(phase.get("id", "") or phase.get("phase", "") or "")
        for function in phase.get("functions", []) if isinstance(phase.get("functions"), list) else []:
            if isinstance(function, dict):
                _add_function(by_key, ea_to_key, function, phase_id or str(function.get("phase", "") or "selected"))
    for function in trace.get("selected_candidates", []) if isinstance(trace.get("selected_candidates"), list) else []:
        if isinstance(function, dict):
            _add_function(by_key, ea_to_key, function, str(function.get("phase", "") or "selected"))
    functions = [_freeze_function(item) for item in by_key.values()]
    functions.sort(key=lambda item: item["name"].lower())
    return {
        "functions": functions,
        "by_key": {item["normalized_name"]: item for item in functions},
        "ea_to_key": ea_to_key,
    }


def _add_function(by_key: dict[str, dict[str, Any]], ea_to_key: dict[str, str], function: dict[str, Any], phase: str) -> None:
    name = str(function.get("name", "") or "").strip()
    key = _normalize_name(name)
    if not key:
        return
    item = by_key.setdefault(
        key,
        {
            "name": name,
            "normalized_name": key,
            "eas": set(),
            "phases": set(),
            "roles": set(),
            "tags": set(),
            "artifacts": set(),
        },
    )
    if len(name) > len(item["name"]):
        item["name"] = name
    ea = _normalize_ea_text(function.get("ea", ""))
    if ea:
        item["eas"].add(ea)
        ea_to_key[ea.lower()] = key
    if phase:
        item["phases"].add(str(phase))
    role = str(function.get("role", "") or "")
    if role:
        item["roles"].add(role)
    for tag in _strings(function.get("tags")):
        item["tags"].add(tag)
    for artifact in _function_artifacts(function):
        item["artifacts"].add(artifact)


def _freeze_function(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item["name"],
        "normalized_name": item["normalized_name"],
        "eas": sorted(item["eas"], key=_ea_sort_key),
        "phases": sorted(item["phases"]),
        "roles": sorted(item["roles"]),
        "tags": sorted(item["tags"]),
        "artifacts": sorted(item["artifacts"]),
    }


def _collect_edges(evidence: dict[str, Any], ea_to_key: dict[str, str], functions_by_key: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for edge in evidence.get("edges", []) if isinstance(evidence.get("edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        src_key = ea_to_key.get(_normalize_ea_text(edge.get("src_ea", "")).lower(), "")
        dst_key = ea_to_key.get(_normalize_ea_text(edge.get("dst_ea", "")).lower(), "")
        if not src_key or not dst_key:
            continue
        src_name = functions_by_key[src_key]["name"]
        dst_name = functions_by_key[dst_key]["name"]
        result.append(
            {
                "src_name": src_name,
                "dst_name": dst_name,
                "edge_kind": str(edge.get("edge_kind", "") or "call"),
                "src_ea": _normalize_ea_text(edge.get("src_ea", "")),
                "dst_ea": _normalize_ea_text(edge.get("dst_ea", "")),
            }
        )
    unique = {_edge_key(edge): edge for edge in result}
    return [unique[key] for key in sorted(unique)]


def _function_artifacts(function: dict[str, Any]) -> list[str]:
    artifacts = []
    for key in ("artifacts", "artifact_paths"):
        value = function.get(key)
        if isinstance(value, dict):
            artifacts.extend(str(item) for item in value.values() if str(item))
    evidence = function.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict) and str(item.get("path", "") or ""):
                artifacts.append(str(item["path"]))
    for key in ("summary_path", "cleaned_path", "raw_path", "source_path"):
        value = str(function.get(key, "") or "")
        if value:
            artifacts.append(value)
    return _unique_strings(artifacts)


def _catalog_summary(
    side_a: dict[str, Any],
    side_b: dict[str, Any],
    topic_ids: list[str],
    selected_ids: list[str],
) -> dict[str, Any]:
    ids_a = set(side_a["topics"])
    ids_b = set(side_b["topics"])
    common = sorted(ids_a & ids_b, key=lambda item: _topic_sort_key(item, side_a, side_b))
    missing_in_a = sorted(ids_b - ids_a, key=lambda item: _topic_sort_key(item, side_a, side_b))
    missing_in_b = sorted(ids_a - ids_b, key=lambda item: _topic_sort_key(item, side_a, side_b))
    return {
        "a_topic_count": len(ids_a),
        "b_topic_count": len(ids_b),
        "common_count": len(ids_a & ids_b),
        "filtered_topic_count": len(topic_ids),
        "returned_topic_count": len(selected_ids),
        "missing_in_a": _limit_items(missing_in_a, DEFAULT_MAX_FUNCTION_CHANGES),
        "missing_in_a_truncated": len(missing_in_a) > DEFAULT_MAX_FUNCTION_CHANGES,
        "missing_in_b": _limit_items(missing_in_b, DEFAULT_MAX_FUNCTION_CHANGES),
        "missing_in_b_truncated": len(missing_in_b) > DEFAULT_MAX_FUNCTION_CHANGES,
        "common_topics": _limit_items(common, DEFAULT_MAX_FUNCTION_CHANGES),
        "common_topics_truncated": len(common) > DEFAULT_MAX_FUNCTION_CHANGES,
    }


def _source_identity_payload(side_a: dict[str, Any], side_b: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "target_path",
        "source_corpus_root",
        "source_index_path",
        "source_index_sha256",
        "function_count",
        "skipped_count",
        "generated_at",
        "schema_version",
    )
    return {
        "a": side_a["identity"],
        "b": side_b["identity"],
        "field_diffs": [
            {
                "field": field,
                "a": side_a["identity"].get(field, ""),
                "b": side_b["identity"].get(field, ""),
                "changed": side_a["identity"].get(field, "") != side_b["identity"].get(field, ""),
            }
            for field in fields
        ],
    }


def _topic_markdown(topic: dict[str, Any]) -> list[str]:
    lines = [
        "### `%s`" % topic.get("topic_id", ""),
        "",
        "- Presence: `%s`" % topic.get("presence", ""),
        "- Changed: `%s`" % topic.get("changed", False),
    ]
    catalog = topic.get("catalog_changes", {}) if isinstance(topic.get("catalog_changes"), dict) else {}
    changed_fields = [
        (key, value)
        for key, value in catalog.items()
        if isinstance(value, dict) and bool(value.get("changed"))
    ]
    if changed_fields:
        lines.extend(["", "Catalog changes:"])
        for key, value in changed_fields:
            if "delta" in value:
                lines.append("- `%s`: `%s` -> `%s` delta=`%s`" % (key, value.get("a", ""), value.get("b", ""), value.get("delta", "")))
            else:
                lines.append("- `%s`: `%s` -> `%s`" % (key, value.get("a", ""), value.get("b", "")))
    evidence = topic.get("evidence_changes", {}) if isinstance(topic.get("evidence_changes"), dict) else {}
    if evidence:
        lines.extend(["", "Evidence changes:"])
        _append_change_list(lines, "Same-name different EA", evidence.get("same_name_different_ea", []), _function_ea_line)
        _append_change_list(lines, "Functions added", evidence.get("functions_added", []), _function_summary_line)
        _append_change_list(lines, "Functions removed", evidence.get("functions_removed", []), _function_summary_line)
        _append_change_list(lines, "Phase assignment changes", evidence.get("phase_assignment_changes", []), _phase_line)
        _append_change_list(lines, "Call edges added", evidence.get("call_edges_added", []), _edge_line)
        _append_change_list(lines, "Call edges removed", evidence.get("call_edges_removed", []), _edge_line)
    warnings = [str(item) for item in topic.get("warnings", [])]
    if warnings:
        lines.extend(["", "Topic warnings:"])
        for warning in warnings:
            lines.append("- %s" % warning)
    lines.append("")
    return lines


def _append_change_list(lines: list[str], title: str, values: list[Any], formatter: Any) -> None:
    if not values:
        return
    lines.append("- %s:" % title)
    for value in values:
        lines.append("  - %s" % formatter(value))


def _function_ea_line(item: dict[str, Any]) -> str:
    return "`%s` A=%s B=%s" % (item.get("name", ""), _inline_code_list(item.get("a_eas", [])), _inline_code_list(item.get("b_eas", [])))


def _function_summary_line(item: dict[str, Any]) -> str:
    return "`%s` EAs=%s phases=%s" % (item.get("name", ""), _inline_code_list(item.get("eas", [])), _inline_code_list(item.get("phases", [])))


def _phase_line(item: dict[str, Any]) -> str:
    return "`%s` A=%s B=%s" % (item.get("name", ""), _inline_code_list(item.get("a_phases", [])), _inline_code_list(item.get("b_phases", [])))


def _edge_line(item: dict[str, Any]) -> str:
    return "`%s` -> `%s` kind=`%s`" % (item.get("src_name", ""), item.get("dst_name", ""), item.get("edge_kind", ""))


def _topic_reference(topic: dict[str, Any] | None) -> dict[str, Any]:
    if topic is None:
        return {"present": False}
    metadata = topic["metadata"]
    quality = metadata.get("quality", {}) if isinstance(metadata.get("quality"), dict) else {}
    return {
        "present": True,
        "priority": metadata.get("priority", ""),
        "mode": metadata.get("mode", ""),
        "title": metadata.get("title", ""),
        "quality": quality,
        "directory": topic.get("directory", ""),
        "function_count": len(topic.get("functions", [])),
        "edge_count": len(topic.get("edges", [])),
    }


def _topic_warnings(topic_a: dict[str, Any] | None, topic_b: dict[str, Any] | None) -> list[str]:
    warnings = []
    if topic_a is not None:
        warnings.extend(topic_a.get("warnings", []))
    if topic_b is not None:
        warnings.extend(topic_b.get("warnings", []))
    return warnings


def _has_changes(changes: dict[str, Any]) -> bool:
    return any(isinstance(value, dict) and bool(value.get("changed")) for value in changes.values())


def _has_evidence_changes(changes: dict[str, Any]) -> bool:
    if not changes:
        return False
    for key, value in changes.items():
        if key == "artifact_path_pairs":
            if any(isinstance(item, dict) and bool(item.get("changed")) for item in value):
                return True
            continue
        if key.endswith("_truncated"):
            continue
        if isinstance(value, list) and value:
            return True
    return False


def _field_change(a_value: Any, b_value: Any) -> dict[str, Any]:
    return {
        "a": a_value,
        "b": b_value,
        "changed": a_value != b_value,
    }


def _number_change(a_value: Any, b_value: Any) -> dict[str, Any]:
    a_number = _int_or_float(a_value)
    b_number = _int_or_float(b_value)
    return {
        "a": a_value,
        "b": b_value,
        "delta": None if a_number is None or b_number is None else b_number - a_number,
        "changed": a_value != b_value,
    }


def _function_summary(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": function.get("name", ""),
        "eas": function.get("eas", []),
        "phases": function.get("phases", []),
        "roles": function.get("roles", []),
        "artifacts": function.get("artifacts", [])[:4],
    }


def _edge_key(edge: dict[str, Any]) -> tuple[str, str, str]:
    return (
        _normalize_name(str(edge.get("src_name", "") or "")),
        _normalize_name(str(edge.get("dst_name", "") or "")),
        str(edge.get("edge_kind", "") or "call"),
    )


def _topic_sort_key(topic_id: str, side_a: dict[str, Any], side_b: dict[str, Any]) -> tuple[int, str]:
    topic_a = side_a["topics"].get(topic_id)
    topic_b = side_b["topics"].get(topic_id)
    priority_a = _topic_priority_rank(topic_a)
    priority_b = _topic_priority_rank(topic_b)
    return (min(priority_a, priority_b), topic_id)


def _topic_priority_rank(topic: dict[str, Any] | None) -> int:
    if topic is None:
        return 99
    return PRIORITY_ORDER.get(str(topic["metadata"].get("priority", "")).upper(), 99)


def _topic_matches_priority(topic_a: dict[str, Any] | None, topic_b: dict[str, Any] | None, priority: str) -> bool:
    return priority in {
        str(topic["metadata"].get("priority", "")).upper()
        for topic in (topic_a, topic_b)
        if topic is not None
    }


def _topic_matches_status(topic_a: dict[str, Any] | None, topic_b: dict[str, Any] | None, status: str) -> bool:
    statuses = set()
    for topic in (topic_a, topic_b):
        if topic is None:
            statuses.add("missing")
            continue
        quality = topic["metadata"].get("quality", {}) if isinstance(topic["metadata"].get("quality"), dict) else {}
        statuses.add(str(quality.get("status", "missing") or "missing").lower())
    return status in statuses


def _artifact_path(paths: dict[str, Any], key: str, fallback: Path, topic_dir: Path, warnings: list[str]) -> Path:
    value = str(paths.get(key, "") or "")
    path = Path(value) if value else fallback
    if not path.is_absolute():
        path = topic_dir / path
    resolved = path.resolve()
    if not _is_inside(resolved, topic_dir):
        warnings.append("Canonical artifact path escaped topic directory: %s" % resolved)
        return fallback.resolve()
    return resolved


def _read_json_object(path: Path, warnings: list[str], label: str) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append("Could not read %s JSON file %s: %s" % (label, path, exc))
        return {}
    if not isinstance(data, dict):
        warnings.append("%s JSON file is not an object: %s" % (label, path))
        return {}
    return data


def _side_warnings(side: dict[str, Any]) -> list[str]:
    return ["%s: %s" % (side["label"], warning) for warning in _unique_strings(side.get("warnings", []))]


def _coerce_warnings(payload: dict[str, Any]) -> list[str]:
    values = payload.get("warnings", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return [str(item) for item in values]


def _format_from_path(path: Path, requested_format: str) -> str:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix == ".txt":
        return "text"
    if suffix == ".json":
        return "json"
    requested = str(requested_format or "json").lower()
    if requested not in {"json", "text", "markdown"}:
        return "json"
    return requested


def _inline_code_list(values: Any) -> str:
    strings = _strings(values)
    if not strings:
        return "`none`"
    return ", ".join("`%s`" % item for item in strings[:8])


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker = "\n\n[truncated]\n"
    if max_chars <= len(marker):
        return marker[:max_chars]
    return text[: max_chars - len(marker)].rstrip() + marker


def _limit_items(values: list[Any], limit: int) -> list[Any]:
    return list(values[:limit])


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _int_or_float(value: Any) -> int | float | None:
    if value in (None, ""):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if result.is_integer():
        return int(result)
    return result


def _normalize_name(name: str) -> str:
    text = str(name or "").strip().lower()
    text = re.sub(r"\s+", "", text)
    return text


def _normalize_ea_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        number = int(str(value), 0)
    except (TypeError, ValueError):
        return str(value)
    if number < 0:
        return str(value)
    return "0x%X" % number


def _ea_sort_key(value: str) -> tuple[int, str]:
    try:
        return (0, "%016X" % int(str(value), 0))
    except (TypeError, ValueError):
        return (1, str(value))


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item)]
    return [str(value)] if str(value) else []


def _unique_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _path_payload(path: Path) -> str:
    return str(path.resolve()) if path.exists() else str(path)


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _validate_topic_id(topic_id: str) -> None:
    if not SAFE_TOPIC_RE.match(str(topic_id or "")):
        raise QueryError("Canonical topic id must be an identifier, not a path: %s" % topic_id)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
