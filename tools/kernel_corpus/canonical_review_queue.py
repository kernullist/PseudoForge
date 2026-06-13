from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError, QueryError

REVIEW_QUEUE_SCHEMA_VERSION = "kernel_corpus_canonical_review_queue_v1"
REVIEW_DECISIONS_SCHEMA_VERSION = "kernel_corpus_canonical_review_decisions_v1"
CANONICAL_DIR_NAME = "canonical-answers"
DEFAULT_MAX_TOPICS = 100
MAX_TOPICS = 500
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}
QUALITY_ORDER = {"fail": 0, "degraded": 1, "missing": 2, "pass": 3}
VALID_DECISIONS = {"approved", "needs_review", "rejected", "superseded"}
SAFE_TOPIC_RE = re.compile(r"^[a-z0-9][a-z0-9_]*$")
IMPORTANT_ARTIFACTS = (
    ("manifest", "manifest.json"),
    ("answer", "answer.md"),
    ("candidate_review", "candidate-review.md"),
    ("quality_json", "quality.json"),
    ("quality", "quality.md"),
    ("gaps", "gaps.md"),
    ("source_map", "source-map.md"),
    ("evidence_pack", "evidence-pack.json"),
    ("trace", "trace.json"),
    ("validation", "validation.json"),
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = build_review_queue(
            args.pack_root,
            canonical_root=args.canonical_root or None,
            priority=args.priority,
            status=args.status,
            max_topics=args.max_topics,
            decision_file=args.decision_file or None,
        )
        if args.report_out:
            payload["report_paths"] = write_review_queue_reports(payload, args.report_out)
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel canonical review queue failed: %s" % exc, file=sys.stderr)
        return 1
    if args.format == "markdown":
        print(render_markdown_report(payload))
    elif args.format == "text":
        print(render_text_report(payload))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def build_review_queue(
    pack_root: str | Path,
    *,
    canonical_root: str | Path | None = None,
    priority: str | list[str] | tuple[str, ...] | None = None,
    status: str | list[str] | tuple[str, ...] | None = None,
    max_topics: int = DEFAULT_MAX_TOPICS,
    decision_file: str | Path | None = None,
) -> dict[str, Any]:
    pack_path = Path(pack_root)
    canonical_path = Path(canonical_root) if canonical_root else pack_path / CANONICAL_DIR_NAME
    _require_inside(canonical_path, pack_path, "Canonical root")
    warnings: list[str] = []
    pack_manifest_path = pack_path / "manifest.json"
    pack_manifest = _read_json_object(pack_manifest_path, warnings)
    canonical_index = _read_json_object(canonical_path / "index.json", warnings)
    root_quality = _read_json_object(canonical_path / "quality-report.json", warnings)
    decision_path = Path(decision_file) if decision_file else canonical_path / "review-decisions.json"
    decisions, decision_summary = _load_decisions(decision_path, canonical_path, warnings)

    topics = []
    if canonical_path.is_dir():
        quality_by_topic = _quality_by_topic(root_quality)
        for topic_dir, fallback_priority, fallback_topic_id in _discover_topic_dirs(canonical_path, warnings):
            topics.append(
                _build_topic_entry(
                    topic_dir,
                    fallback_priority,
                    fallback_topic_id,
                    pack_manifest,
                    canonical_index,
                    quality_by_topic,
                    decisions,
                    warnings,
                )
            )
    else:
        warnings.append("Canonical answer root does not exist: %s" % canonical_path)

    filtered = _filter_entries(topics, priority=priority, status=status)
    filtered.sort(key=_queue_sort_key)
    limit = _bounded_int(max_topics, DEFAULT_MAX_TOPICS, MAX_TOPICS)
    returned = filtered[:limit]
    counts = _queue_counts(filtered)
    return {
        "schema": REVIEW_QUEUE_SCHEMA_VERSION,
        "ok": True,
        "pack_root": _path_payload(pack_path),
        "canonical_root": _path_payload(canonical_path),
        "source_identity": _source_identity(pack_manifest, pack_manifest_path, canonical_index, canonical_path),
        "decision_file": {
            "path": _path_payload(decision_path),
            "exists": decision_path.is_file(),
            "schema": decision_summary.get("schema", ""),
            "loaded_count": decision_summary.get("loaded_count", 0),
            "effective_count": decision_summary.get("effective_count", 0),
        },
        "topic_count": len(filtered),
        "returned_count": len(returned),
        "max_topics": limit,
        "counts": counts,
        "topics": returned,
        "warnings": warnings,
    }


def write_review_queue_reports(payload: dict[str, Any], report_out: str | Path) -> dict[str, str]:
    canonical_root = Path(str(payload.get("canonical_root", "") or ""))
    report_path = Path(report_out)
    _require_inside(report_path.parent, canonical_root, "Review queue report directory")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report_path.suffix.lower() == ".json":
        json_path = report_path
        md_path = report_path.with_suffix(".md")
    elif report_path.suffix.lower() == ".md":
        md_path = report_path
        json_path = report_path.with_suffix(".json")
    else:
        json_path = report_path.with_suffix(".json")
        md_path = report_path.with_suffix(".md")
    paths = {
        "json": _path_payload(json_path),
        "markdown": _path_payload(md_path),
    }
    payload_with_paths = dict(payload)
    payload_with_paths["report_paths"] = paths
    json_path.write_text(json.dumps(payload_with_paths, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_markdown_report(payload_with_paths), encoding="utf-8")
    return paths


def render_text_report(payload: dict[str, Any]) -> str:
    counts = payload.get("counts", {}) if isinstance(payload.get("counts"), dict) else {}
    lines = [
        "Canonical review queue",
        "canonical_root: %s" % payload.get("canonical_root", ""),
        "topics: %s returned: %s approved: %s fail: %s degraded: %s missing: %s pass_unreviewed: %s"
        % (
            payload.get("topic_count", 0),
            payload.get("returned_count", 0),
            counts.get("approved", 0),
            counts.get("fail", 0),
            counts.get("degraded", 0),
            counts.get("missing", 0),
            counts.get("pass_unreviewed", 0),
        ),
        "",
    ]
    for topic in payload.get("topics", []):
        if not isinstance(topic, dict):
            continue
        lines.append(
            "%s %s quality=%s review=%s score=%s warnings=%s action=%s"
            % (
                topic.get("priority", ""),
                topic.get("topic_id", ""),
                topic.get("quality_status", ""),
                topic.get("review_state", ""),
                topic.get("score", ""),
                topic.get("validation_warning_count", 0),
                topic.get("suggested_review_action", ""),
            )
        )
    return "\n".join(lines).rstrip()


def render_markdown_report(payload: dict[str, Any]) -> str:
    counts = payload.get("counts", {}) if isinstance(payload.get("counts"), dict) else {}
    lines = [
        "# Canonical Review Queue",
        "",
        "- Schema: `%s`" % payload.get("schema", ""),
        "- Pack root: `%s`" % payload.get("pack_root", ""),
        "- Canonical root: `%s`" % payload.get("canonical_root", ""),
        "- Topics: `%s`" % payload.get("topic_count", 0),
        "- Returned: `%s`" % payload.get("returned_count", 0),
        "- Approved: `%s`" % counts.get("approved", 0),
        "- Stale decisions: `%s`" % counts.get("stale_decision", 0),
        "",
    ]
    groups = [
        ("Failing Topics", lambda item: item.get("quality_status") == "fail"),
        ("Degraded Topics", lambda item: item.get("quality_status") == "degraded"),
        ("Missing Quality Topics", lambda item: item.get("quality_status") == "missing"),
        (
            "Passing But Unreviewed Topics",
            lambda item: item.get("quality_status") == "pass" and item.get("review_state") != "approved",
        ),
        ("Approved Topics", lambda item: item.get("review_state") == "approved"),
        ("Stale Review Decisions", lambda item: bool(item.get("review_decision", {}).get("stale"))),
    ]
    topics = [item for item in payload.get("topics", []) if isinstance(item, dict)]
    for title, predicate in groups:
        selected = [item for item in topics if predicate(item)]
        lines.extend(["## %s" % title, ""])
        if not selected:
            lines.extend(["- None", ""])
            continue
        for topic in selected:
            lines.append(_markdown_topic_line(topic))
        lines.append("")
    warnings = [str(item) for item in payload.get("warnings", []) if str(item)]
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings[:20]:
            lines.append("- %s" % warning)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a canonical answer production review queue.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--canonical-root", default="", help="Canonical answer root. Defaults to <pack-root>\\canonical-answers.")
    parser.add_argument("--priority", action="append", choices=["P0", "P1", "P2"], help="Filter by priority.")
    parser.add_argument("--status", action="append", choices=["pass", "degraded", "fail", "missing"], help="Filter by quality status.")
    parser.add_argument("--max-topics", type=int, default=DEFAULT_MAX_TOPICS, help="Maximum topics to return.")
    parser.add_argument("--format", choices=["json", "text", "markdown"], default="json", help="Output format.")
    parser.add_argument("--report-out", default="", help="Write review-queue JSON and Markdown reports under the canonical root.")
    parser.add_argument("--decision-file", default="", help="Review decision ledger under the canonical root.")
    return parser


def _discover_topic_dirs(canonical_root: Path, warnings: list[str]) -> list[tuple[Path, str, str]]:
    discovered: dict[str, tuple[Path, str, str]] = {}
    index = _read_json_object(canonical_root / "index.json", warnings)
    for item in index.get("topics", []) if isinstance(index.get("topics"), list) else []:
        if not isinstance(item, dict):
            continue
        topic_id = str(item.get("id", "") or "")
        priority = str(item.get("priority", "") or "")
        if not _is_safe_topic_id(topic_id) or not priority:
            continue
        directory = Path(str(item.get("directory", "") or ""))
        if directory.is_dir() and not _is_inside(directory, canonical_root):
            warnings.append("Ignoring canonical topic directory outside root: %s" % directory)
            directory = canonical_root / priority / topic_id
        elif not directory.is_dir():
            directory = canonical_root / priority / topic_id
        if directory.is_dir() and _is_inside(directory, canonical_root):
            discovered[topic_id] = (directory, priority, topic_id)
    if canonical_root.is_dir():
        for priority_dir in sorted(canonical_root.iterdir(), key=lambda item: item.name.lower()):
            if not priority_dir.is_dir() or not re.match(r"^P[0-9]+$", priority_dir.name):
                continue
            for topic_dir in sorted(priority_dir.iterdir(), key=lambda item: item.name.lower()):
                if topic_dir.is_dir() and _is_safe_topic_id(topic_dir.name):
                    discovered.setdefault(topic_dir.name, (topic_dir, priority_dir.name, topic_dir.name))
    return sorted(discovered.values(), key=lambda item: (_priority_rank(item[1]), item[2]))


def _build_topic_entry(
    topic_dir: Path,
    fallback_priority: str,
    fallback_topic_id: str,
    pack_manifest: dict[str, Any],
    canonical_index: dict[str, Any],
    quality_by_topic: dict[str, dict[str, Any]],
    decisions: dict[str, dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    manifest = _read_json_object(topic_dir / "manifest.json", warnings)
    topic_payload = manifest.get("topic", {}) if isinstance(manifest.get("topic"), dict) else {}
    topic_id = str(topic_payload.get("id", "") or fallback_topic_id)
    if not _is_safe_topic_id(topic_id):
        warnings.append("Canonical manifest topic id is not safe; using directory topic id: %s" % topic_dir)
        topic_id = fallback_topic_id
    priority = str(topic_payload.get("priority", "") or fallback_priority)
    evidence = _read_json_object(topic_dir / "evidence-pack.json", warnings)
    trace = _read_json_object(topic_dir / "trace.json", warnings)
    validation = _read_json_object(topic_dir / "validation.json", warnings)
    quality, quality_source = _topic_quality(topic_dir, topic_id, quality_by_topic, warnings)
    quality_status = str(quality.get("status", "missing") or "missing")
    if quality_status not in QUALITY_ORDER:
        quality_status = "missing"
    source_mismatches = _source_mismatches(manifest, pack_manifest, canonical_index)
    decision = _decision_for_topic(decisions.get(topic_id), manifest, source_mismatches)
    entry = {
        "topic_id": topic_id,
        "priority": priority,
        "mode": str(topic_payload.get("mode", "") or quality.get("mode", "")),
        "title": str(topic_payload.get("title", "") or topic_id),
        "question": str(topic_payload.get("question", "")),
        "directory": _path_payload(topic_dir),
        "quality_status": quality_status,
        "quality_source": quality_source,
        "score": _optional_int(quality.get("score")),
        "validation_warning_count": _int_value(
            quality.get("validation_warning_count"),
            _int_value(validation.get("warning_count"), 0),
        ),
        "gap_count": _int_value(quality.get("gap_count"), _gap_count(evidence, topic_dir)),
        "selected_function_count": _int_value(
            quality.get("selected_function_count"),
            _int_value(evidence.get("summary", {}).get("selected_function_count") if isinstance(evidence.get("summary"), dict) else None, 0),
        ),
        "edge_count": _int_value(
            quality.get("edge_count"),
            _int_value(evidence.get("summary", {}).get("edge_count") if isinstance(evidence.get("summary"), dict) else None, 0),
        ),
        "selected_major_functions": _major_functions(evidence, trace)[:12],
        "artifact_paths": _artifact_paths(topic_dir),
        "source_identity": {
            "source_index_sha256": str(manifest.get("source_index_sha256", "")),
            "pack_generated_at": str(manifest.get("pack_generated_at", "")),
        },
        "source_mismatches": source_mismatches,
        "review_decision": decision,
    }
    entry["review_state"] = _review_state(decision)
    entry["suggested_review_action"] = _suggested_action(entry)
    return entry


def _topic_quality(
    topic_dir: Path,
    topic_id: str,
    quality_by_topic: dict[str, dict[str, Any]],
    warnings: list[str],
) -> tuple[dict[str, Any], str]:
    local_path = topic_dir / "quality.json"
    local = _read_json_object(local_path, warnings)
    if local:
        return local, "topic_quality_json"
    if topic_id in quality_by_topic:
        return quality_by_topic[topic_id], "root_quality_report"
    return {"topic_id": topic_id, "status": "missing", "score": None}, "missing"


def _quality_by_topic(root_quality: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for item in root_quality.get("topics", []) if isinstance(root_quality.get("topics"), list) else []:
        if not isinstance(item, dict):
            continue
        topic_id = str(item.get("topic_id", "") or "")
        if _is_safe_topic_id(topic_id):
            result[topic_id] = item
    return result


def _load_decisions(
    decision_file: Path,
    canonical_root: Path,
    warnings: list[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    _require_inside(decision_file, canonical_root, "Review decision file")
    if not decision_file.is_file():
        return {}, {"schema": "", "loaded_count": 0, "effective_count": 0}
    data = _read_json_object(decision_file, warnings)
    schema = str(data.get("schema", "") or "")
    if schema and schema != REVIEW_DECISIONS_SCHEMA_VERSION:
        warnings.append("Unsupported review decision schema: %s" % schema)
    decisions = data.get("decisions", [])
    if not isinstance(decisions, list):
        warnings.append("Review decision file decisions must be a list: %s" % decision_file)
        return {}, {"schema": schema, "loaded_count": 0, "effective_count": 0}
    normalized = []
    for item in decisions:
        decision = _normalize_decision(item, warnings)
        if decision:
            normalized.append(decision)
    normalized.sort(
        key=lambda item: (
            item["topic_id"],
            item.get("reviewed_at", ""),
            item.get("decision", ""),
            item.get("reviewer", ""),
            item.get("notes", ""),
        )
    )
    effective = {}
    for item in normalized:
        effective[item["topic_id"]] = item
    return effective, {"schema": schema, "loaded_count": len(normalized), "effective_count": len(effective)}


def _normalize_decision(item: Any, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warnings.append("Ignoring non-object review decision entry.")
        return None
    topic_id = str(item.get("topic_id", "") or "")
    decision = str(item.get("decision", "") or "")
    if not _is_safe_topic_id(topic_id):
        warnings.append("Ignoring review decision with invalid topic id: %s" % topic_id)
        return None
    if decision not in VALID_DECISIONS:
        warnings.append("Ignoring review decision with invalid decision for %s: %s" % (topic_id, decision))
        return None
    return {
        "topic_id": topic_id,
        "decision": decision,
        "reviewer": str(item.get("reviewer", "") or ""),
        "reviewed_at": str(item.get("reviewed_at", "") or ""),
        "source_index_sha256": str(item.get("source_index_sha256", item.get("source_manifest_hash", "")) or ""),
        "pack_generated_at": str(item.get("pack_generated_at", item.get("generated_at", "")) or ""),
        "notes": str(item.get("notes", "") or ""),
    }


def _decision_for_topic(
    decision: dict[str, Any] | None,
    manifest: dict[str, Any],
    source_mismatches: list[str],
) -> dict[str, Any]:
    if not decision:
        return {
            "decision": "unreviewed",
            "stale": False,
            "stale_reasons": [],
        }
    stale_reasons = []
    topic_hash = str(manifest.get("source_index_sha256", "") or "")
    topic_generated_at = str(manifest.get("pack_generated_at", "") or "")
    decision_hash = str(decision.get("source_index_sha256", "") or "")
    decision_generated_at = str(decision.get("pack_generated_at", "") or "")
    if source_mismatches:
        stale_reasons.append("topic_source_mismatch")
    if decision_hash:
        if topic_hash and decision_hash != topic_hash:
            stale_reasons.append("decision_source_hash_mismatch")
    elif decision_generated_at:
        if topic_generated_at and decision_generated_at != topic_generated_at:
            stale_reasons.append("decision_pack_generated_at_mismatch")
    else:
        stale_reasons.append("decision_missing_source_identity")
    result = dict(decision)
    result["stale"] = bool(stale_reasons)
    result["stale_reasons"] = sorted(set(stale_reasons))
    return result


def _review_state(decision: dict[str, Any]) -> str:
    value = str(decision.get("decision", "unreviewed") or "unreviewed")
    if value == "unreviewed":
        return "unreviewed"
    if decision.get("stale"):
        return "stale_%s" % value
    return value


def _suggested_action(entry: dict[str, Any]) -> str:
    decision = entry.get("review_decision", {}) if isinstance(entry.get("review_decision"), dict) else {}
    if decision.get("stale"):
        return "re_review_source_changed"
    review_state = str(entry.get("review_state", ""))
    if review_state == "approved" and entry.get("quality_status") == "pass" and int(entry.get("validation_warning_count", 0) or 0) == 0:
        return "ready_for_agent_preference"
    if review_state == "rejected":
        return "do_not_use_until_regenerated"
    if review_state == "superseded":
        return "use_superseding_topic_or_regenerate"
    if int(entry.get("validation_warning_count", 0) or 0) > 0:
        return "fix_validation_warnings"
    status = str(entry.get("quality_status", "missing") or "missing")
    if status == "fail":
        return "fix_generation_or_expectations"
    if status == "degraded":
        return "manual_review_verify_gaps"
    if status == "missing":
        return "run_canonical_audit"
    if review_state == "needs_review":
        return "complete_human_review"
    return "human_review_before_promotion"


def _source_identity(
    pack_manifest: dict[str, Any],
    pack_manifest_path: Path,
    canonical_index: dict[str, Any],
    canonical_root: Path,
) -> dict[str, Any]:
    return {
        "target_path": str(pack_manifest.get("target_path", "")),
        "source_corpus_root": str(pack_manifest.get("source_corpus_root", "")),
        "source_index_sha256": str(pack_manifest.get("source_index_sha256", canonical_index.get("source_index_sha256", ""))),
        "pack_generated_at": str(pack_manifest.get("generated_at", canonical_index.get("pack_generated_at", ""))),
        "function_count": _int_value(pack_manifest.get("function_count"), 0),
        "skipped_count": _int_value(pack_manifest.get("skipped_count"), 0),
        "pack_manifest_path": _path_payload(pack_manifest_path),
        "canonical_index_path": _path_payload(canonical_root / "index.json"),
    }


def _source_mismatches(
    manifest: dict[str, Any],
    pack_manifest: dict[str, Any],
    canonical_index: dict[str, Any],
) -> list[str]:
    mismatches = []
    topic_hash = str(manifest.get("source_index_sha256", "") or "")
    pack_hash = str(pack_manifest.get("source_index_sha256", canonical_index.get("source_index_sha256", "")) or "")
    if topic_hash and pack_hash and topic_hash != pack_hash:
        mismatches.append("source_index_sha256")
    topic_generated_at = str(manifest.get("pack_generated_at", "") or "")
    pack_generated_at = str(pack_manifest.get("generated_at", canonical_index.get("pack_generated_at", "")) or "")
    if topic_generated_at and pack_generated_at and topic_generated_at != pack_generated_at:
        mismatches.append("pack_generated_at")
    return mismatches


def _filter_entries(
    entries: list[dict[str, Any]],
    *,
    priority: str | list[str] | tuple[str, ...] | None,
    status: str | list[str] | tuple[str, ...] | None,
) -> list[dict[str, Any]]:
    priority_filter = _value_filter(priority, upper=True)
    status_filter = _value_filter(status, upper=False)
    result = []
    for entry in entries:
        if priority_filter and str(entry.get("priority", "")).upper() not in priority_filter:
            continue
        if status_filter and str(entry.get("quality_status", "")).lower() not in status_filter:
            continue
        result.append(entry)
    return result


def _queue_sort_key(entry: dict[str, Any]) -> tuple[int, int, int, int, str]:
    score = entry.get("score")
    score_value = int(score) if isinstance(score, int) else 999
    warning_count = _int_value(entry.get("validation_warning_count"), 0)
    return (
        _priority_rank(str(entry.get("priority", ""))),
        QUALITY_ORDER.get(str(entry.get("quality_status", "missing")), 99),
        -warning_count,
        score_value,
        str(entry.get("topic_id", "")),
    )


def _queue_counts(entries: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "fail": 0,
        "degraded": 0,
        "missing": 0,
        "pass": 0,
        "approved": 0,
        "pass_unreviewed": 0,
        "stale_decision": 0,
    }
    for entry in entries:
        status = str(entry.get("quality_status", "missing"))
        if status in counts:
            counts[status] += 1
        if entry.get("review_state") == "approved":
            counts["approved"] += 1
        if status == "pass" and entry.get("review_state") != "approved":
            counts["pass_unreviewed"] += 1
        decision = entry.get("review_decision", {}) if isinstance(entry.get("review_decision"), dict) else {}
        if decision.get("stale"):
            counts["stale_decision"] += 1
    return counts


def _artifact_paths(topic_dir: Path) -> dict[str, str]:
    return {key: _path_payload(topic_dir / filename) for key, filename in IMPORTANT_ARTIFACTS}


def _major_functions(evidence: dict[str, Any], trace: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for item in _function_items(evidence):
        name = str(item.get("name", "") or "")
        ea = str(item.get("ea", "") or "")
        if name:
            result.append({"ea": ea, "name": name})
    for item in trace.get("selected_candidates", []) if isinstance(trace.get("selected_candidates"), list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "") or "")
        ea = str(item.get("ea", "") or "")
        if name:
            result.append({"ea": ea, "name": name})
    return _unique_functions(result)


def _function_items(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    if isinstance(evidence.get("functions"), list):
        result.extend(item for item in evidence["functions"] if isinstance(item, dict))
    if isinstance(evidence.get("phases"), list):
        for phase in evidence["phases"]:
            if isinstance(phase, dict) and isinstance(phase.get("functions"), list):
                result.extend(item for item in phase["functions"] if isinstance(item, dict))
    return result


def _unique_functions(values: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    seen = set()
    for item in values:
        key = (item.get("ea", ""), item.get("name", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _gap_count(evidence: dict[str, Any], topic_dir: Path) -> int:
    gaps = evidence.get("gaps")
    if isinstance(gaps, list):
        return len(gaps)
    gaps_path = topic_dir / "gaps.md"
    if not gaps_path.is_file():
        return 0
    return sum(1 for line in gaps_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip().startswith("-"))


def _read_json_object(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append("Could not read JSON file %s: %s" % (path, exc))
        return {}
    if not isinstance(data, dict):
        warnings.append("JSON file is not an object: %s" % path)
        return {}
    return data


def _markdown_topic_line(topic: dict[str, Any]) -> str:
    paths = topic.get("artifact_paths", {}) if isinstance(topic.get("artifact_paths"), dict) else {}
    functions = topic.get("selected_major_functions", [])
    function_names = []
    for item in functions[:4] if isinstance(functions, list) else []:
        if isinstance(item, dict) and item.get("name"):
            function_names.append("`%s`" % item.get("name"))
    return (
        "- `%s` `%s` quality=`%s` review=`%s` score=`%s` warnings=`%s` gaps=`%s` action=`%s` answer=`%s` functions=%s"
        % (
            topic.get("priority", ""),
            topic.get("topic_id", ""),
            topic.get("quality_status", ""),
            topic.get("review_state", ""),
            topic.get("score", ""),
            topic.get("validation_warning_count", 0),
            topic.get("gap_count", 0),
            topic.get("suggested_review_action", ""),
            paths.get("answer", ""),
            ", ".join(function_names) if function_names else "`none`",
        )
    )


def _bounded_int(value: Any, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _value_filter(value: str | list[str] | tuple[str, ...] | None, *, upper: bool) -> set[str]:
    if value in (None, ""):
        return set()
    raw_values = [value] if isinstance(value, str) else list(value)
    result = set()
    for item in raw_values:
        text = str(item or "").strip()
        if not text:
            continue
        result.add(text.upper() if upper else text.lower())
    return result


def _priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(priority, 99)


def _path_payload(path: Path) -> str:
    return str(path.resolve())


def _is_safe_topic_id(topic_id: str) -> bool:
    return bool(SAFE_TOPIC_RE.match(str(topic_id or "")))


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _require_inside(path: Path, root: Path, label: str) -> None:
    if not _is_inside(path, root):
        raise QueryError("%s must stay under %s: %s" % (label, root, path))


if __name__ == "__main__":
    raise SystemExit(main())
