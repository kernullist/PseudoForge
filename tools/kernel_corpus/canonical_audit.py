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

from tools.kernel_corpus.errors import KernelCorpusError, QueryError

EXPECTATIONS_SCHEMA_VERSION = "kernel_corpus_canonical_expectations_v1"
AUDIT_SCHEMA_VERSION = "kernel_corpus_canonical_quality_report_v1"
DEFAULT_EXPECTATIONS_PATH = Path(__file__).with_name("canonical_expectations.json")
PRIORITY_ORDER = {"P0": 0, "P1": 1}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = audit_canonical_root(
            args.canonical_root,
            expectations_path=args.expectations,
            topic_ids=args.topic,
            priorities=args.priority,
            report_out=args.report_out or None,
            write_topic_reports=bool(args.report_out),
        )
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError, re.error) as exc:
        print("Kernel canonical quality audit failed: %s" % exc, file=sys.stderr)
        return 1
    if args.format == "text":
        print(render_text_report(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def audit_canonical_root(
    canonical_root: str | Path,
    *,
    expectations_path: str | Path = DEFAULT_EXPECTATIONS_PATH,
    topic_ids: list[str] | tuple[str, ...] | None = None,
    priorities: list[str] | tuple[str, ...] | None = None,
    report_out: str | Path | None = None,
    write_topic_reports: bool = False,
) -> dict[str, Any]:
    root = Path(canonical_root)
    if not root.is_dir():
        raise QueryError("Canonical answer root is missing: %s" % root)
    expectations = load_expectations(expectations_path)
    topic_filter = {str(item) for item in (topic_ids or []) if str(item)}
    priority_filter = {str(item).upper() for item in (priorities or []) if str(item)}
    topic_dirs = _discover_topic_dirs(root)
    entries = []
    for topic in topic_dirs:
        topic_id = topic["id"]
        priority = topic["priority"]
        if topic_filter and topic_id not in topic_filter:
            continue
        if priority_filter and priority not in priority_filter:
            continue
        entries.append(_audit_topic(root, topic, expectations))
    missing = topic_filter - {entry["topic_id"] for entry in entries}
    if missing:
        raise QueryError("Unknown canonical topic id(s): %s" % ", ".join(sorted(missing)))
    entries = sorted(entries, key=lambda item: (_priority_rank(item["priority"]), item["topic_id"]))
    report = _report_payload(root, expectations_path, entries)
    if report_out:
        paths = write_quality_reports(report, report_out, write_topic_reports=write_topic_reports)
        report["report_paths"] = paths
    return report


def load_expectations(path: str | Path = DEFAULT_EXPECTATIONS_PATH) -> dict[str, Any]:
    expectation_path = Path(path)
    data = json.loads(expectation_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise QueryError("Canonical expectation manifest must be a JSON object: %s" % expectation_path)
    if data.get("schema") != EXPECTATIONS_SCHEMA_VERSION:
        raise QueryError("Unsupported canonical expectation schema: %s" % data.get("schema"))
    defaults = data.get("defaults")
    topics = data.get("topics")
    if not isinstance(defaults, dict):
        raise QueryError("Canonical expectation defaults must be a JSON object.")
    if not isinstance(topics, dict) or not topics:
        raise QueryError("Canonical expectation manifest has no topics.")
    for topic_id, expectation in topics.items():
        if not isinstance(topic_id, str) or not re.match(r"^[a-z0-9][a-z0-9_]*$", topic_id):
            raise QueryError("Canonical expectation topic id is invalid: %s" % topic_id)
        if not isinstance(expectation, dict):
            raise QueryError("Canonical expectation entry is not a JSON object: %s" % topic_id)
        for key in (
            "required_name_regexes",
            "bonus_name_regexes",
            "forbidden_name_regexes",
            "suspicious_name_regexes",
        ):
            for pattern in _strings(expectation.get(key)) + _strings(defaults.get(key)):
                re.compile(pattern)
    return data


def expectations_cover_topics(expectations: dict[str, Any], topic_ids: list[str] | tuple[str, ...]) -> bool:
    topics = expectations.get("topics", {}) if isinstance(expectations.get("topics"), dict) else {}
    return all(str(topic_id) in topics for topic_id in topic_ids)


def write_quality_reports(
    report: dict[str, Any],
    report_out: str | Path,
    *,
    write_topic_reports: bool = True,
) -> dict[str, str]:
    json_path = _json_report_path(Path(report_out))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path = json_path.with_suffix(".md")
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    written = {
        "json": str(json_path.resolve()),
        "markdown": str(md_path.resolve()),
    }
    if write_topic_reports:
        for topic in report.get("topics", []):
            if not isinstance(topic, dict):
                continue
            topic_dir = Path(str(topic.get("directory", "") or ""))
            if not topic_dir.is_dir():
                continue
            topic_json = topic_dir / "quality.json"
            topic_md = topic_dir / "quality.md"
            topic_json.write_text(json.dumps(topic, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
            topic_md.write_text(render_topic_markdown(topic), encoding="utf-8")
    return written


def render_text_report(report: dict[str, Any]) -> str:
    lines = [
        "Canonical quality audit",
        "canonical_root: %s" % report.get("canonical_root", ""),
        "topics: %s pass: %s degraded: %s fail: %s" % (
            report.get("topic_count", 0),
            report.get("pass_count", 0),
            report.get("degraded_count", 0),
            report.get("fail_count", 0),
        ),
        "",
    ]
    for topic in report.get("topics", []):
        if not isinstance(topic, dict):
            continue
        lines.append(
            "%s %s score=%s status=%s functions=%s edges=%s warnings=%s gaps=%s"
            % (
                topic.get("priority", ""),
                topic.get("topic_id", ""),
                topic.get("score", ""),
                topic.get("status", ""),
                topic.get("selected_function_count", 0),
                topic.get("edge_count", 0),
                topic.get("validation_warning_count", 0),
                topic.get("gap_count", 0),
            )
        )
        actions = _strings(topic.get("recommended_actions"))
        if actions:
            lines.append("  actions: %s" % "; ".join(actions[:3]))
    return "\n".join(lines).rstrip()


def render_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Canonical Quality Report",
        "",
        "- Schema: `%s`" % report.get("schema", ""),
        "- Created: `%s`" % report.get("created_at", ""),
        "- Canonical root: `%s`" % report.get("canonical_root", ""),
        "- Topics: `%s`" % report.get("topic_count", 0),
        "- Pass: `%s`" % report.get("pass_count", 0),
        "- Degraded: `%s`" % report.get("degraded_count", 0),
        "- Fail: `%s`" % report.get("fail_count", 0),
        "",
        "## Topics",
        "",
    ]
    for topic in report.get("topics", []):
        if not isinstance(topic, dict):
            continue
        lines.append(
            "- `%s` `%s` status=`%s` score=`%s` functions=`%s` edges=`%s` warnings=`%s` gaps=`%s`"
            % (
                topic.get("priority", ""),
                topic.get("topic_id", ""),
                topic.get("status", ""),
                topic.get("score", ""),
                topic.get("selected_function_count", 0),
                topic.get("edge_count", 0),
                topic.get("validation_warning_count", 0),
                topic.get("gap_count", 0),
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def render_topic_markdown(topic: dict[str, Any]) -> str:
    lines = [
        "# Canonical Topic Quality",
        "",
        "- Topic: `%s`" % topic.get("topic_id", ""),
        "- Priority: `%s`" % topic.get("priority", ""),
        "- Status: `%s`" % topic.get("status", ""),
        "- Score: `%s`" % topic.get("score", ""),
        "- Selected functions: `%s`" % topic.get("selected_function_count", 0),
        "- Edges: `%s`" % topic.get("edge_count", 0),
        "- Validation warnings: `%s`" % topic.get("validation_warning_count", 0),
        "- Gaps: `%s`" % topic.get("gap_count", 0),
        "",
        "## Findings",
        "",
    ]
    finding_keys = [
        ("missing_required_functions", "Missing required regexes"),
        ("forbidden_selected_functions", "Forbidden selected functions"),
        ("suspicious_selected_functions", "Suspicious selected functions"),
        ("missing_phases", "Missing phases"),
        ("weak_edge_coverage", "Weak edge coverage"),
        ("source_identity_warnings", "Source identity warnings"),
    ]
    wrote = False
    for key, title in finding_keys:
        values = topic.get(key)
        if not values:
            continue
        wrote = True
        lines.append("- %s: `%s`" % (title, _single_line(values, 240)))
    if not wrote:
        lines.append("- No blocking quality findings were recorded.")
    lines.extend(["", "## Recommended Actions", ""])
    actions = _strings(topic.get("recommended_actions"))
    if not actions:
        lines.append("- No tuning action is required by the current audit.")
    for action in actions:
        lines.append("- %s" % action)
    return "\n".join(lines).rstrip() + "\n"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit generated canonical Kernel Corpus answer artifacts.")
    parser.add_argument("--canonical-root", required=True, help="Root containing canonical answer topic directories.")
    parser.add_argument("--expectations", default=str(DEFAULT_EXPECTATIONS_PATH), help="Expectation manifest JSON path.")
    parser.add_argument("--topic", action="append", default=[], help="Topic id to audit. Can be repeated.")
    parser.add_argument("--priority", action="append", default=[], choices=("P0", "P1"), help="Priority to include.")
    parser.add_argument("--format", choices=("json", "text"), default="json", help="Output format.")
    parser.add_argument("--report-out", default="", help="Optional JSON report output path.")
    return parser


def _discover_topic_dirs(root: Path) -> list[dict[str, str]]:
    index_path = root / "index.json"
    topics = []
    if index_path.is_file():
        index = _read_json_object(index_path)
        for item in index.get("topics", []) if isinstance(index.get("topics"), list) else []:
            if not isinstance(item, dict):
                continue
            topic_id = str(item.get("id", "") or "")
            priority = str(item.get("priority", "") or "")
            directory = Path(str(item.get("directory", "") or ""))
            if not directory.is_dir():
                directory = root / priority / topic_id
            if topic_id:
                topics.append({"id": topic_id, "priority": priority, "directory": str(directory.resolve())})
    if not topics:
        for priority_dir in sorted(root.iterdir(), key=lambda item: item.name.lower()):
            if not priority_dir.is_dir() or priority_dir.name not in PRIORITY_ORDER:
                continue
            for topic_dir in sorted(priority_dir.iterdir(), key=lambda item: item.name.lower()):
                if topic_dir.is_dir():
                    topics.append(
                        {
                            "id": topic_dir.name,
                            "priority": priority_dir.name,
                            "directory": str(topic_dir.resolve()),
                        }
                    )
    return sorted(topics, key=lambda item: (_priority_rank(item["priority"]), item["id"]))


def _audit_topic(root: Path, topic: dict[str, str], expectations: dict[str, Any]) -> dict[str, Any]:
    topic_dir = Path(topic["directory"])
    manifest_path = topic_dir / "manifest.json"
    manifest = _read_json_object(manifest_path) if manifest_path.is_file() else {}
    topic_payload = manifest.get("topic", {}) if isinstance(manifest.get("topic"), dict) else {}
    topic_id = str(topic_payload.get("id", "") or topic["id"])
    priority = str(topic_payload.get("priority", "") or topic["priority"])
    mode = str(topic_payload.get("mode", "") or "")
    expectation, missing_expectation = _merged_expectation(expectations, topic_id)
    files = _artifact_files(topic_dir, manifest)
    evidence_pack = _read_json_object(files["evidence_pack"]["path"]) if files["evidence_pack"]["exists"] else {}
    trace = _read_json_object(files["trace"]["path"]) if files["trace"]["exists"] else {}
    validation = _read_json_object(files["validation"]["path"]) if files["validation"]["exists"] else {}
    source_map = files["source_map"]["path"].read_text(encoding="utf-8", errors="replace") if files["source_map"]["exists"] else ""
    candidate_review = files["candidate_review"]["path"].read_text(encoding="utf-8", errors="replace") if files["candidate_review"]["exists"] else ""
    gaps_text = files["gaps"]["path"].read_text(encoding="utf-8", errors="replace") if files["gaps"]["exists"] else ""

    functions = _collect_functions(evidence_pack)
    edges = _edges(evidence_pack)
    phases = sorted({str(function.get("phase", "") or "") for function in functions if str(function.get("phase", "") or "")})
    selected_names = [str(function.get("name", "") or "") for function in functions]
    required_matches, missing_required = _match_required(selected_names, _strings(expectation.get("required_name_regexes")))
    bonus_matches = _match_patterns(selected_names, _strings(expectation.get("bonus_name_regexes")))
    forbidden = _match_function_patterns(functions, _strings(expectation.get("forbidden_name_regexes")))
    suspicious = _match_function_patterns(functions, _strings(expectation.get("suspicious_name_regexes")))
    suspicious.extend(_match_long_names(functions, _int_value(expectation.get("max_name_length"), 0)))
    suspicious = sorted(suspicious, key=lambda item: (_ea_sort_key(item["ea"]), item["pattern"], item["name"].lower()))
    suspicious_tags = _match_suspicious_tags(functions, _strings(expectation.get("suspicious_tags")))
    preferred_tag_hits = _match_preferred_tags(functions, _strings(expectation.get("preferred_tags")))
    required_phases = _strings(expectation.get("required_lifecycle_phases"))
    missing_phases = [phase for phase in required_phases if phase not in phases]
    selected_count = len(functions)
    edge_count = len(edges)
    min_selected = _int_value(expectation.get("min_selected_functions"), 0)
    min_edges = _int_value(expectation.get("min_edge_count"), 0)
    warning_count = _int_value(validation.get("warning_count"), 0)
    max_warnings = _int_value(expectation.get("max_validation_warnings"), 0)
    source_ref_count = _source_ref_count(source_map, evidence_pack)
    min_source_refs = _int_value(expectation.get("min_source_refs"), 0)
    gap_count = _gap_count(evidence_pack, gaps_text)
    source_identity = _source_identity(root, manifest, evidence_pack)
    missing_files = [key for key, value in files.items() if not value["exists"]]
    candidate_review_empty = not candidate_review.strip()
    weak_edge_coverage = edge_count < min_edges

    score = _score_topic(
        missing_expectation=missing_expectation,
        missing_files=missing_files,
        missing_required=missing_required,
        forbidden=forbidden,
        suspicious=suspicious,
        suspicious_tags=suspicious_tags,
        preferred_tag_hits=preferred_tag_hits,
        preferred_tags=_strings(expectation.get("preferred_tags")),
        selected_count=selected_count,
        min_selected=min_selected,
        edge_count=edge_count,
        min_edges=min_edges,
        missing_phases=missing_phases,
        warning_count=warning_count,
        max_warnings=max_warnings,
        source_ref_count=source_ref_count,
        min_source_refs=min_source_refs,
        gap_count=gap_count,
        source_mismatch=bool(source_identity["warnings"]),
        candidate_review_empty=candidate_review_empty,
        bonus_count=len(bonus_matches),
    )
    status = _status(score, expectation, missing_expectation, missing_required, forbidden, warning_count, max_warnings, source_identity["warnings"])
    entry = {
        "topic_id": topic_id,
        "priority": priority,
        "mode": mode,
        "directory": str(topic_dir.resolve()),
        "status": status,
        "score": score,
        "missing_expectation": missing_expectation,
        "selected_function_count": selected_count,
        "min_selected_function_count": min_selected,
        "edge_count": edge_count,
        "min_edge_count": min_edges,
        "weak_edge_coverage": weak_edge_coverage,
        "observed_phases": phases,
        "required_lifecycle_phases": required_phases,
        "missing_phases": missing_phases,
        "matched_required_functions": required_matches,
        "missing_required_functions": missing_required,
        "matched_bonus_functions": bonus_matches,
        "forbidden_selected_functions": forbidden,
        "suspicious_selected_functions": suspicious,
        "preferred_tag_hits": preferred_tag_hits,
        "suspicious_tag_hits": suspicious_tags,
        "validation_warning_count": warning_count,
        "max_validation_warnings": max_warnings,
        "validation_warnings": validation.get("warnings", []) if isinstance(validation.get("warnings"), list) else [],
        "gap_count": gap_count,
        "source_ref_count": source_ref_count,
        "min_source_refs": min_source_refs,
        "source_identity": source_identity,
        "source_identity_warnings": source_identity["warnings"],
        "file_status": {key: {"path": str(value["path"].resolve()), "exists": value["exists"]} for key, value in files.items()},
        "trace_selected_count": len(trace.get("selected_candidates", [])) if isinstance(trace.get("selected_candidates"), list) else 0,
        "candidate_review_empty": candidate_review_empty,
        "recommended_actions": _recommended_actions(
            missing_expectation,
            missing_files,
            missing_required,
            forbidden,
            suspicious,
            suspicious_tags,
            preferred_tag_hits,
            _strings(expectation.get("preferred_tags")),
            selected_count,
            min_selected,
            edge_count,
            min_edges,
            missing_phases,
            warning_count,
            max_warnings,
            source_ref_count,
            min_source_refs,
            source_identity["warnings"],
            gap_count,
            candidate_review_empty,
        ),
    }
    return entry


def _report_payload(root: Path, expectations_path: str | Path, entries: list[dict[str, Any]]) -> dict[str, Any]:
    pass_count = sum(1 for item in entries if item["status"] == "pass")
    degraded_count = sum(1 for item in entries if item["status"] == "degraded")
    fail_count = sum(1 for item in entries if item["status"] == "fail")
    return {
        "schema": AUDIT_SCHEMA_VERSION,
        "ok": fail_count == 0,
        "created_at": _utc_now(),
        "canonical_root": str(root.resolve()),
        "expectations_path": str(Path(expectations_path).resolve()),
        "topic_count": len(entries),
        "pass_count": pass_count,
        "degraded_count": degraded_count,
        "fail_count": fail_count,
        "average_score": round(sum(item["score"] for item in entries) / len(entries), 2) if entries else 0.0,
        "topics": entries,
    }


def _merged_expectation(expectations: dict[str, Any], topic_id: str) -> tuple[dict[str, Any], bool]:
    defaults = expectations.get("defaults", {}) if isinstance(expectations.get("defaults"), dict) else {}
    topics = expectations.get("topics", {}) if isinstance(expectations.get("topics"), dict) else {}
    specific = topics.get(topic_id)
    missing = not isinstance(specific, dict)
    result = dict(defaults)
    if isinstance(specific, dict):
        for key, value in specific.items():
            if key in (
                "required_name_regexes",
                "bonus_name_regexes",
                "forbidden_name_regexes",
                "suspicious_name_regexes",
                "preferred_tags",
                "suspicious_tags",
                "required_lifecycle_phases",
            ):
                default_values = _strings(defaults.get(key))
                specific_values = _strings(value)
                if key in {"suspicious_name_regexes", "suspicious_tags", "forbidden_name_regexes"}:
                    result[key] = _unique(default_values + specific_values)
                else:
                    result[key] = specific_values
            else:
                result[key] = value
    return result, missing


def _artifact_files(topic_dir: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    file_map = manifest.get("files", {}) if isinstance(manifest.get("files"), dict) else {}
    names = {
        "manifest": "manifest.json",
        "evidence_pack": "evidence-pack.json",
        "trace": "trace.json",
        "validation": "validation.json",
        "candidate_review": "candidate-review.md",
        "gaps": "gaps.md",
        "source_map": "source-map.md",
    }
    result = {}
    for key, filename in names.items():
        raw_value = str(file_map.get(key, "") or "")
        candidate = Path(raw_value)
        if not raw_value:
            candidate = topic_dir / filename
        elif not candidate.is_absolute():
            candidate = topic_dir / candidate
        fallback = topic_dir / filename
        if not candidate.exists() and fallback.exists():
            candidate = fallback
        result[key] = {
            "path": candidate,
            "exists": candidate.is_file(),
        }
    return result


def _collect_functions(pack: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    if isinstance(pack.get("functions"), list):
        result.extend(item for item in pack["functions"] if isinstance(item, dict))
    if isinstance(pack.get("phases"), list):
        for phase in pack["phases"]:
            if not isinstance(phase, dict):
                continue
            phase_id = str(phase.get("id", "") or "")
            functions = phase.get("functions") if isinstance(phase.get("functions"), list) else []
            for function in functions:
                if not isinstance(function, dict):
                    continue
                item = dict(function)
                item.setdefault("phase", phase_id)
                result.append(item)
    seen = set()
    deduped = []
    for item in result:
        ea = str(item.get("ea", "") or "")
        name = str(item.get("name", "") or "")
        key = ea or name
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return sorted(deduped, key=lambda item: (_ea_sort_key(str(item.get("ea", "") or "")), str(item.get("name", "") or "").lower()))


def _edges(pack: dict[str, Any]) -> list[dict[str, Any]]:
    edges = pack.get("edges") if isinstance(pack.get("edges"), list) else []
    return [edge for edge in edges if isinstance(edge, dict)]


def _match_required(names: list[str], patterns: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    matches = []
    missing = []
    for pattern in patterns:
        matched = [name for name in names if re.search(pattern, name)]
        if matched:
            matches.append({"pattern": pattern, "names": sorted(matched)})
        else:
            missing.append(pattern)
    return matches, missing


def _match_patterns(names: list[str], patterns: list[str]) -> list[dict[str, Any]]:
    matches = []
    for pattern in patterns:
        matched = [name for name in names if re.search(pattern, name)]
        if matched:
            matches.append({"pattern": pattern, "names": sorted(matched)})
    return matches


def _match_function_patterns(functions: list[dict[str, Any]], patterns: list[str]) -> list[dict[str, str]]:
    result = []
    for function in functions:
        name = str(function.get("name", "") or "")
        for pattern in patterns:
            if re.search(pattern, name):
                result.append(
                    {
                        "ea": str(function.get("ea", "") or ""),
                        "name": name,
                        "pattern": pattern,
                    }
                )
    return sorted(result, key=lambda item: (_ea_sort_key(item["ea"]), item["pattern"], item["name"].lower()))


def _match_long_names(functions: list[dict[str, Any]], max_name_length: int) -> list[dict[str, str]]:
    if max_name_length <= 0:
        return []
    result = []
    for function in functions:
        name = str(function.get("name", "") or "")
        if len(name) > max_name_length:
            result.append(
                {
                    "ea": str(function.get("ea", "") or ""),
                    "name": name,
                    "pattern": "max_name_length:%d" % max_name_length,
                }
            )
    return result


def _match_suspicious_tags(functions: list[dict[str, Any]], tags: list[str]) -> list[dict[str, str]]:
    suspicious = set(tags)
    result = []
    if not suspicious:
        return result
    for function in functions:
        function_tags = {str(item) for item in function.get("tags", []) if str(item)} if isinstance(function.get("tags"), list) else set()
        for tag in sorted(function_tags.intersection(suspicious)):
            result.append(
                {
                    "ea": str(function.get("ea", "") or ""),
                    "name": str(function.get("name", "") or ""),
                    "tag": tag,
                }
            )
    return result


def _match_preferred_tags(functions: list[dict[str, Any]], tags: list[str]) -> list[str]:
    preferred = set(tags)
    hits = set()
    if not preferred:
        return []
    for function in functions:
        function_tags = {str(item) for item in function.get("tags", []) if str(item)} if isinstance(function.get("tags"), list) else set()
        hits.update(function_tags.intersection(preferred))
    return sorted(hits)


def _source_ref_count(source_map: str, pack: dict[str, Any]) -> int:
    summary = pack.get("summary", {}) if isinstance(pack.get("summary"), dict) else {}
    source_ref_count = _int_value(summary.get("source_ref_count"), -1)
    if source_ref_count >= 0:
        return source_ref_count
    count = 0
    in_public_refs = False
    for line in source_map.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            in_public_refs = "Public Contract References" in stripped
            continue
        if in_public_refs and stripped.startswith("- [") and "](" in stripped:
            count += 1
    return count


def _gap_count(pack: dict[str, Any], gaps_text: str) -> int:
    gaps = _strings(pack.get("gaps")) + _strings(pack.get("uncertainty_notes"))
    if gaps:
        return len(gaps)
    count = 0
    for line in gaps_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- Gap:") or stripped.startswith("- Uncertainty:"):
            count += 1
    return count


def _source_identity(root: Path, manifest: dict[str, Any], pack: dict[str, Any]) -> dict[str, Any]:
    index_path = root / "index.json"
    index = _read_json_object(index_path) if index_path.is_file() else {}
    index_hash = str(index.get("source_index_sha256", "") or "")
    topic_hash = str(manifest.get("source_index_sha256", "") or "")
    index_generated = str(index.get("pack_generated_at", "") or "")
    topic_generated = str(manifest.get("pack_generated_at", "") or "")
    warnings = []
    if index_hash and topic_hash and index_hash != topic_hash:
        warnings.append("Topic source_index_sha256 differs from canonical index.")
    if index_generated and topic_generated and index_generated != topic_generated:
        warnings.append("Topic pack_generated_at differs from canonical index.")
    status = pack.get("status", {}) if isinstance(pack.get("status"), dict) else {}
    return {
        "index_source_index_sha256": index_hash,
        "topic_source_index_sha256": topic_hash,
        "index_pack_generated_at": index_generated,
        "topic_pack_generated_at": topic_generated,
        "pack_root": str(pack.get("pack_root", "") or ""),
        "status_schema_version": str(status.get("schema_version", "") or ""),
        "warnings": warnings,
    }


def _score_topic(
    *,
    missing_expectation: bool,
    missing_files: list[str],
    missing_required: list[str],
    forbidden: list[dict[str, str]],
    suspicious: list[dict[str, str]],
    suspicious_tags: list[dict[str, str]],
    preferred_tag_hits: list[str],
    preferred_tags: list[str],
    selected_count: int,
    min_selected: int,
    edge_count: int,
    min_edges: int,
    missing_phases: list[str],
    warning_count: int,
    max_warnings: int,
    source_ref_count: int,
    min_source_refs: int,
    gap_count: int,
    source_mismatch: bool,
    candidate_review_empty: bool,
    bonus_count: int,
) -> int:
    score = 100
    if missing_expectation:
        score -= 35
    score -= min(30, len(missing_files) * 8)
    score -= min(45, len(missing_required) * 12)
    score -= min(40, len(forbidden) * 20)
    score -= min(25, len(suspicious) * 4)
    score -= min(15, len(suspicious_tags) * 5)
    if preferred_tags and not preferred_tag_hits:
        score -= 8
    if selected_count < min_selected:
        score -= min(24, (min_selected - selected_count) * 2)
    if edge_count < min_edges:
        score -= min(18, (min_edges - edge_count) * 3)
    score -= min(36, len(missing_phases) * 8)
    if warning_count > max_warnings:
        score -= min(32, (warning_count - max_warnings) * 8)
    if source_ref_count < min_source_refs:
        score -= min(16, (min_source_refs - source_ref_count) * 8)
    score -= min(12, gap_count * 2)
    if source_mismatch:
        score -= 25
    if candidate_review_empty:
        score -= 6
    score += min(8, bonus_count * 2)
    return max(0, min(100, score))


def _status(
    score: int,
    expectation: dict[str, Any],
    missing_expectation: bool,
    missing_required: list[str],
    forbidden: list[dict[str, str]],
    warning_count: int,
    max_warnings: int,
    source_warnings: list[str],
) -> str:
    pass_score = _int_value(expectation.get("pass_score"), 80)
    degraded_score = _int_value(expectation.get("degraded_score"), 60)
    if missing_expectation or missing_required or forbidden or warning_count > max_warnings or source_warnings:
        return "fail"
    if score >= pass_score:
        return "pass"
    if score >= degraded_score:
        return "degraded"
    return "fail"


def _recommended_actions(
    missing_expectation: bool,
    missing_files: list[str],
    missing_required: list[str],
    forbidden: list[dict[str, str]],
    suspicious: list[dict[str, str]],
    suspicious_tags: list[dict[str, str]],
    preferred_tag_hits: list[str],
    preferred_tags: list[str],
    selected_count: int,
    min_selected: int,
    edge_count: int,
    min_edges: int,
    missing_phases: list[str],
    warning_count: int,
    max_warnings: int,
    source_ref_count: int,
    min_source_refs: int,
    source_warnings: list[str],
    gap_count: int,
    candidate_review_empty: bool,
) -> list[str]:
    actions = []
    if missing_expectation:
        actions.append("Add this topic to canonical_expectations.json before treating the artifact as reviewed.")
    if missing_files:
        actions.append("Regenerate the topic bundle because required files are missing: %s." % ", ".join(sorted(missing_files)))
    if missing_required:
        actions.append("Tune seeds, queries, tags, or lifecycle ontology until required function regexes match: %s." % ", ".join(missing_required[:5]))
    if forbidden:
        actions.append("Remove forbidden candidates from retrieval or narrow the topic expectation.")
    if suspicious or suspicious_tags:
        actions.append("Review suspicious selected functions and tags for FTS or subsystem noise.")
    if preferred_tags and not preferred_tag_hits:
        actions.append("Adjust topic tags or candidate scoring so preferred subsystem tags are represented.")
    if selected_count < min_selected:
        actions.append("Increase retrieval breadth or fix seed misses; selected functions are below expectation.")
    if edge_count < min_edges:
        actions.append("Inspect callgraph expansion depth and exact seed connectivity; selected edge coverage is weak.")
    if missing_phases:
        actions.append("Review lifecycle phase hints and seed coverage for missing phases: %s." % ", ".join(missing_phases))
    if warning_count > max_warnings:
        actions.append("Fix answer-harness citation warnings before using this canonical answer as a baseline.")
    if source_ref_count < min_source_refs:
        actions.append("Refresh source-map references or topic source_refs; public reference coverage is below expectation.")
    if source_warnings:
        actions.append("Regenerate canonical answers from a single fresh pack because source identity differs.")
    if gap_count > 0:
        actions.append("Review gaps.md before promoting this artifact to a polished answer.")
    if candidate_review_empty:
        actions.append("Regenerate candidate-review.md so selection reasons are reviewable.")
    return actions


def _read_json_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise QueryError("JSON file is not an object: %s" % path)
    return data


def _json_report_path(path: Path) -> Path:
    if path.suffix.lower() == ".json":
        return path
    if path.exists() and path.is_dir():
        return path / "quality-report.json"
    if not path.suffix:
        return path / "quality-report.json"
    return path.with_suffix(".json")


def _priority_rank(priority: str) -> int:
    return PRIORITY_ORDER.get(str(priority), 99)


def _ea_sort_key(value: str) -> int:
    try:
        return int(str(value), 0)
    except ValueError:
        return 0


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    return []


def _unique(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _single_line(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", json.dumps(value, ensure_ascii=True, sort_keys=True)).strip()[:limit]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
