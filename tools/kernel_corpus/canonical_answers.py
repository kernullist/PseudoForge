from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.answer_harness import build_prompt, validate_answer
from tools.kernel_corpus.errors import KernelCorpusError, QueryError
from tools.kernel_corpus.lifecycle import trace_lifecycle
from tools.kernel_corpus.query import build_evidence_pack, corpus_status, find_functions_by_name, search_functions

TOPICS_SCHEMA_VERSION = "kernel_corpus_canonical_topics_v1"
RUN_SCHEMA_VERSION = "kernel_corpus_canonical_answer_run_v1"
ARTIFACT_SCHEMA_VERSION = "kernel_corpus_canonical_answer_artifact_v1"
TRACE_SCHEMA_VERSION = "kernel_corpus_canonical_trace_v1"
DEFAULT_MANIFEST_PATH = Path(__file__).with_name("canonical_topics.json")
DEFAULT_QUERY_LIMIT = 24
DEFAULT_MAX_FUNCTIONS = 40
MAX_GENERATED_FUNCTION_BULLETS = 64


@dataclass(frozen=True)
class CanonicalTopic:
    topic_id: str
    priority: str
    title: str
    question: str
    mode: str
    raw: dict[str, Any]
    source_refs: list[dict[str, str]]


@dataclass
class Candidate:
    ea: str
    name: str
    score: int
    reasons: set[str]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            payload = list_topics(
                manifest_path=args.manifest,
                priorities=args.priority,
                topic_ids=args.topic,
            )
        elif args.command == "build":
            payload = build_canonical_answers(
                args.pack_root,
                output_root=args.output_root or None,
                manifest_path=args.manifest,
                priorities=args.priority,
                topic_ids=args.topic,
                force=args.force,
            )
        else:
            raise QueryError("Unsupported command: %s" % args.command)
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel canonical answer generation failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def list_topics(
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    priorities: list[str] | tuple[str, ...] | None = None,
    topic_ids: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    topics = select_topics(manifest, priorities=priorities, topic_ids=topic_ids)
    return {
        "schema": RUN_SCHEMA_VERSION,
        "ok": True,
        "manifest_path": str(Path(manifest_path).resolve()),
        "topic_count": len(topics),
        "topics": [
            {
                "id": topic.topic_id,
                "priority": topic.priority,
                "title": topic.title,
                "mode": topic.mode,
                "question": topic.question,
            }
            for topic in topics
        ],
    }


def build_canonical_answers(
    pack_root: str | Path,
    *,
    output_root: str | Path | None = None,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    priorities: list[str] | tuple[str, ...] | None = None,
    topic_ids: list[str] | tuple[str, ...] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    topics = select_topics(manifest, priorities=priorities, topic_ids=topic_ids)
    status = corpus_status(pack_root)
    manifest_payload = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    root = Path(output_root) if output_root else Path(pack_root) / "canonical-answers"
    root.mkdir(parents=True, exist_ok=True)

    built = []
    for topic in topics:
        built.append(_build_one_topic(topic, pack_root, status, root, force=force))

    index = {
        "schema": RUN_SCHEMA_VERSION,
        "ok": all(item["validation_passed"] for item in built),
        "created_at": _utc_now(),
        "pack_root": str(Path(pack_root).resolve()),
        "manifest_path": str(Path(manifest_path).resolve()),
        "output_root": str(root.resolve()),
        "target_path": str(manifest_payload.get("target_path", "")),
        "pack_generated_at": str(manifest_payload.get("generated_at", "")),
        "source_index_sha256": str(manifest_payload.get("source_index_sha256", "")),
        "topic_count": len(built),
        "passed_count": sum(1 for item in built if item["validation_passed"]),
        "failed_count": sum(1 for item in built if not item["validation_passed"]),
        "topics": built,
    }
    (root / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    (root / "README.md").write_text(_render_index_readme(index), encoding="utf-8")
    return index


def load_manifest(path: str | Path = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise QueryError("Canonical topics manifest must be a JSON object: %s" % manifest_path)
    if data.get("schema") != TOPICS_SCHEMA_VERSION:
        raise QueryError("Unsupported canonical topics schema: %s" % data.get("schema"))
    topics = data.get("topics")
    refs = data.get("references")
    if not isinstance(topics, list) or not topics:
        raise QueryError("Canonical topics manifest has no topics.")
    if not isinstance(refs, dict):
        raise QueryError("Canonical topics manifest references must be a JSON object.")
    seen = set()
    for item in topics:
        if not isinstance(item, dict):
            raise QueryError("Canonical topic entry is not a JSON object.")
        topic_id = str(item.get("id", "") or "")
        if not _safe_id(topic_id):
            raise QueryError("Canonical topic id is invalid: %s" % topic_id)
        if topic_id in seen:
            raise QueryError("Duplicate canonical topic id: %s" % topic_id)
        seen.add(topic_id)
        priority = str(item.get("priority", "") or "")
        if priority not in {"P0", "P1"}:
            raise QueryError("Unsupported canonical topic priority for %s: %s" % (topic_id, priority))
        mode = str(item.get("mode", "") or "")
        if mode not in {"lifecycle", "focused"}:
            raise QueryError("Unsupported canonical topic mode for %s: %s" % (topic_id, mode))
        if mode == "lifecycle" and not str(item.get("lifecycle_topic", "") or ""):
            raise QueryError("Lifecycle topic is required for %s." % topic_id)
        for key in item.get("source_refs", []):
            if str(key) not in refs:
                raise QueryError("Unknown source reference key for %s: %s" % (topic_id, key))
    return data


def select_topics(
    manifest: dict[str, Any],
    *,
    priorities: list[str] | tuple[str, ...] | None = None,
    topic_ids: list[str] | tuple[str, ...] | None = None,
) -> list[CanonicalTopic]:
    priority_filter = {str(item).upper() for item in (priorities or []) if str(item)}
    topic_filter = {str(item) for item in (topic_ids or []) if str(item)}
    refs = manifest["references"]
    selected = []
    for item in manifest["topics"]:
        priority = str(item["priority"])
        topic_id = str(item["id"])
        if priority_filter and priority not in priority_filter:
            continue
        if topic_filter and topic_id not in topic_filter:
            continue
        selected.append(
            CanonicalTopic(
                topic_id=topic_id,
                priority=priority,
                title=str(item.get("title", "") or topic_id),
                question=str(item.get("question", "") or topic_id),
                mode=str(item.get("mode", "") or ""),
                raw=item,
                source_refs=[_reference_payload(refs[str(key)]) for key in item.get("source_refs", [])],
            )
        )
    missing = topic_filter - {topic.topic_id for topic in selected}
    if missing:
        raise QueryError("Unknown canonical topic id(s): %s" % ", ".join(sorted(missing)))
    return selected


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build canonical Kernel Corpus answer artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List canonical answer topics.")
    _add_manifest_and_filters(list_parser)

    build_parser = subparsers.add_parser("build", help="Build canonical answer artifacts.")
    _add_manifest_and_filters(build_parser)
    build_parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    build_parser.add_argument("--output-root", default="", help="Output root. Default is <pack-root>\\canonical-answers.")
    build_parser.add_argument("--force", action="store_true", help="Overwrite existing topic artifact directories.")
    return parser


def _add_manifest_and_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH), help="Canonical topics manifest path.")
    parser.add_argument("--priority", action="append", default=[], choices=("P0", "P1"), help="Priority to include.")
    parser.add_argument("--topic", action="append", default=[], help="Topic id to include. Can be repeated.")


def _build_one_topic(
    topic: CanonicalTopic,
    pack_root: str | Path,
    status: dict[str, Any],
    output_root: Path,
    *,
    force: bool,
) -> dict[str, Any]:
    topic_dir = output_root / topic.priority / topic.topic_id
    if topic_dir.exists() and not force:
        raise QueryError("Topic output directory already exists. Use --force: %s" % topic_dir)
    topic_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = topic_dir / "evidence-pack.json"
    trace_path = topic_dir / "trace.json"
    if topic.mode == "lifecycle":
        evidence_pack = trace_lifecycle(
            pack_root,
            str(topic.raw.get("lifecycle_topic", "")),
            max_seeds=int(topic.raw.get("max_seeds", DEFAULT_MAX_FUNCTIONS)),
            depth=int(topic.raw.get("depth", 2)),
            output_path=evidence_path,
        )
        trace = dict(evidence_pack)
        trace["schema"] = TRACE_SCHEMA_VERSION
        trace["canonical_mode"] = "lifecycle"
        trace["canonical_topic"] = topic.topic_id
        trace_path.write_text(json.dumps(trace, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    else:
        evidence_pack, trace = _build_focused_pack(topic, pack_root)
        evidence_path.write_text(json.dumps(evidence_pack, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
        trace_path.write_text(json.dumps(trace, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")

    source_map_path = topic_dir / "source-map.md"
    candidate_review_path = topic_dir / "candidate-review.md"
    gaps_path = topic_dir / "gaps.md"
    answer_path = topic_dir / "answer.md"
    prompt_path = topic_dir / "prompt.md"
    validation_path = topic_dir / "validation.json"
    manifest_path = topic_dir / "manifest.json"

    source_map_path.write_text(_render_source_map(topic, evidence_path), encoding="utf-8")
    candidate_review_path.write_text(_render_candidate_review(topic, evidence_pack, trace), encoding="utf-8")
    gaps_path.write_text(_render_gaps(topic, evidence_pack), encoding="utf-8")
    prompt = build_prompt(
        pack_root,
        evidence_path,
        topic.question,
        atlas_page=_existing_atlas_page(pack_root, str(topic.raw.get("atlas_page", "") or "")),
    )
    prompt_path.write_text(prompt["prompt"], encoding="utf-8")
    answer_text = _render_answer(topic, evidence_pack, evidence_path, source_map_path, candidate_review_path, gaps_path)
    answer_path.write_text(answer_text, encoding="utf-8")
    validation = validate_answer(evidence_pack, answer_text, answer_path=answer_path)
    validation_path.write_text(json.dumps(validation, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")

    artifact_manifest = {
        "schema": ARTIFACT_SCHEMA_VERSION,
        "created_at": _utc_now(),
        "topic": {
            "id": topic.topic_id,
            "priority": topic.priority,
            "title": topic.title,
            "mode": topic.mode,
            "question": topic.question,
        },
        "pack_root": str(Path(pack_root).resolve()),
        "pack_schema": str(status.get("schema_version", "")),
        "target_path": str(status.get("manifest", {}).get("target_path", "")),
        "pack_generated_at": str(status.get("manifest", {}).get("generated_at", "")),
        "source_index_sha256": str(status.get("manifest", {}).get("source_index_sha256", "")),
        "function_count": int(status.get("manifest", {}).get("function_count", 0) or 0),
        "skipped_count": int(status.get("manifest", {}).get("skipped_count", 0) or 0),
        "files": {
            "answer": str(answer_path.resolve()),
            "evidence_pack": str(evidence_path.resolve()),
            "trace": str(trace_path.resolve()),
            "prompt": str(prompt_path.resolve()),
            "validation": str(validation_path.resolve()),
            "candidate_review": str(candidate_review_path.resolve()),
            "source_map": str(source_map_path.resolve()),
            "gaps": str(gaps_path.resolve()),
        },
        "validation": {
            "passed": bool(validation.get("passed")),
            "warning_count": int(validation.get("warning_count", 0) or 0),
        },
    }
    manifest_path.write_text(json.dumps(artifact_manifest, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    return {
        "id": topic.topic_id,
        "priority": topic.priority,
        "mode": topic.mode,
        "directory": str(topic_dir.resolve()),
        "selected_function_count": _selected_function_count(evidence_pack),
        "edge_count": len(evidence_pack.get("edges", [])) if isinstance(evidence_pack.get("edges"), list) else 0,
        "gap_count": len(_strings(evidence_pack.get("gaps"))) + len(_strings(evidence_pack.get("uncertainty_notes"))),
        "validation_passed": bool(validation.get("passed")),
        "validation_warning_count": int(validation.get("warning_count", 0) or 0),
    }


def _build_focused_pack(topic: CanonicalTopic, pack_root: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    max_functions = int(topic.raw.get("max_functions", DEFAULT_MAX_FUNCTIONS) or DEFAULT_MAX_FUNCTIONS)
    candidates: dict[str, Candidate] = {}
    discovery_events = []
    gaps = []

    for name in _strings(topic.raw.get("seed_names")) + _strings(topic.raw.get("extra_seed_names")):
        exact = find_functions_by_name(pack_root, name, limit=DEFAULT_QUERY_LIMIT)
        if exact:
            for function in exact:
                _add_candidate(candidates, function, 100, "exact seed name: %s" % name)
                discovery_events.append(_event("exact_name", name, function))
        else:
            gaps.append("Seed name did not resolve exactly: %s" % name)
        for function in search_functions(pack_root, query=name, limit=8, include_excerpt=True):
            _add_candidate(candidates, function, 50, "seed name search: %s" % name)

    for query in _strings(topic.raw.get("queries")):
        results = search_functions(pack_root, query=query, limit=DEFAULT_QUERY_LIMIT, include_excerpt=True)
        if not results:
            gaps.append("Query returned no candidates: %s" % query)
        for function in results:
            _add_candidate(candidates, function, 30, "query: %s" % query)
            discovery_events.append(_event("query", query, function))

    for tag in _strings(topic.raw.get("tags")):
        results = search_functions(pack_root, tags=[tag], limit=DEFAULT_QUERY_LIMIT)
        if not results:
            gaps.append("Tag returned no candidates: %s" % tag)
        for function in results:
            _add_candidate(candidates, function, 12, "tag: %s" % tag)
            discovery_events.append(_event("tag", tag, function))

    selected = sorted(candidates.values(), key=lambda item: (-item.score, item.name.lower(), int(item.ea, 0)))[:max_functions]
    if not selected:
        fallback = search_functions(pack_root, query=topic.title, limit=max_functions, include_excerpt=True)
        for function in fallback:
            _add_candidate(candidates, function, 5, "fallback title query")
        selected = sorted(candidates.values(), key=lambda item: (-item.score, item.name.lower(), int(item.ea, 0)))[:max_functions]
        if not selected:
            gaps.append("No selected functions were found for this canonical topic.")

    pack = build_evidence_pack(pack_root, [item.ea for item in selected], topic.topic_id)
    _annotate_focused_functions(pack, selected, topic)
    pack["created_at"] = _utc_now()
    pack["canonical_topic"] = {
        "id": topic.topic_id,
        "priority": topic.priority,
        "title": topic.title,
        "mode": topic.mode,
        "question": topic.question,
    }
    pack["summary"] = {
        "artifact_kind": "focused_canonical_answer",
        "candidate_count": len(candidates),
        "selected_function_count": len(pack.get("functions", [])),
        "edge_count": len(pack.get("edges", [])) if isinstance(pack.get("edges"), list) else 0,
        "source_ref_count": len(topic.source_refs),
    }
    pack["gaps"] = _unique_strings(_strings(pack.get("gaps")) + gaps + ["Focused retrieval is heuristic and must be reviewed before treating transitions as proven."])
    pack["uncertainty_notes"] = [
        "Focused canonical artifacts combine exact-name, text, tag, and graph evidence; they are not lifecycle proof by themselves.",
        "Official Microsoft references define public contracts, while the corpus evidence identifies this build's internal implementation candidates.",
    ]
    trace = {
        "schema": TRACE_SCHEMA_VERSION,
        "canonical_mode": "focused",
        "canonical_topic": topic.topic_id,
        "created_at": _utc_now(),
        "queries": _strings(topic.raw.get("queries")),
        "seed_names": _strings(topic.raw.get("seed_names")) + _strings(topic.raw.get("extra_seed_names")),
        "tags": _strings(topic.raw.get("tags")),
        "max_functions": max_functions,
        "candidate_count": len(candidates),
        "selected_eas": [item.ea for item in selected],
        "selected_candidates": [
            {
                "ea": item.ea,
                "name": item.name,
                "score": item.score,
                "reasons": sorted(item.reasons),
            }
            for item in selected
        ],
        "discovery_events": discovery_events[:200],
        "gaps": pack["gaps"],
    }
    return pack, trace


def _annotate_focused_functions(pack: dict[str, Any], selected: list[Candidate], topic: CanonicalTopic) -> None:
    by_ea = {item.ea: item for item in selected}
    for function in pack.get("functions", []) if isinstance(pack.get("functions"), list) else []:
        if not isinstance(function, dict):
            continue
        candidate = by_ea.get(str(function.get("ea", "") or ""))
        if candidate is None:
            continue
        function["phase"] = "focused"
        function["role"] = "Canonical evidence candidate for %s" % topic.title
        function["confidence"] = round(min(0.99, 0.45 + (candidate.score / 250.0)), 2)
        function["why_selected"] = sorted(candidate.reasons)


def _add_candidate(candidates: dict[str, Candidate], function: dict[str, Any], score: int, reason: str) -> None:
    ea = str(function.get("ea", "") or "")
    name = str(function.get("name", "") or "")
    if not ea or not name:
        return
    existing = candidates.get(ea)
    if existing is None:
        existing = Candidate(ea=ea, name=name, score=0, reasons=set())
        candidates[ea] = existing
    existing.score += score
    existing.reasons.add(reason)
    for selected_reason in _strings(function.get("why_selected")):
        existing.reasons.add(selected_reason)


def _render_answer(
    topic: CanonicalTopic,
    pack: dict[str, Any],
    evidence_path: Path,
    source_map_path: Path,
    candidate_review_path: Path,
    gaps_path: Path,
) -> str:
    functions = _functions_from_pack(pack)
    edges = pack.get("edges", []) if isinstance(pack.get("edges"), list) else []
    phase_lines = _phase_flow_lines(pack, functions)
    lines = [
        "# %s" % topic.title,
        "",
        "Question: %s" % topic.question,
        "",
        "Overall Flow:",
    ]
    if phase_lines:
        lines.extend(phase_lines)
    else:
        lines.append("This artifact is a corpus-grounded baseline built from selected functions, local call edges, and artifact paths.")
        lines.append("Use it as a reviewed starting point for deeper manual or model-assisted analysis.")
    lines.extend(
        [
            "",
            "Major Functions:",
        ]
    )
    if not functions:
        lines.append("- No selected functions were found. Artifact: `%s`. Inference: gap." % evidence_path.resolve())
    for function in functions[:MAX_GENERATED_FUNCTION_BULLETS]:
        artifact = _best_artifact(function)
        phase = str(function.get("phase", "") or "focused")
        role = str(function.get("role", "") or "Selected corpus evidence candidate")
        why = "; ".join(_strings(function.get("why_selected"))[:4])
        if not why:
            why = "selected by canonical topic retrieval"
        lines.append(
            "- `%s` `%s`: phase `%s`; role: %s. Artifact: `%s`. Inference: confirmed corpus evidence. Why: %s."
            % (function.get("ea", ""), function.get("name", ""), phase, _single_line(role, 180), artifact, _single_line(why, 220))
        )
    if len(functions) > MAX_GENERATED_FUNCTION_BULLETS:
        lines.append("- Additional selected functions are present in `%s`." % evidence_path.resolve())
    lines.extend(
        [
            "",
            "Confirmed From This Corpus:",
            "- Evidence pack: `%s`" % evidence_path.resolve(),
            "- Candidate review: `%s`" % candidate_review_path.resolve(),
            "- Source map: `%s`" % source_map_path.resolve(),
            "- Selected function count: `%d`" % len(functions),
            "- Selected edge count: `%d`" % len(edges),
            "",
            "Inference:",
            "- Treat selected functions as implementation candidates for this exact kernel corpus, not as generic Windows guarantees.",
            "- Treat public documentation as the contract layer and this corpus as build-specific implementation evidence.",
            "",
            "Gaps And Uncertainty:",
        ]
    )
    gaps = _strings(pack.get("gaps")) + _strings(pack.get("uncertainty_notes"))
    if not gaps:
        lines.append("- No explicit gaps were recorded by the generator.")
    for gap in gaps:
        lines.append("- %s" % gap)
    lines.append("- Detailed gap file: `%s`" % gaps_path.resolve())
    return "\n".join(lines).rstrip() + "\n"


def _render_candidate_review(topic: CanonicalTopic, pack: dict[str, Any], trace: dict[str, Any]) -> str:
    lines = [
        "# Candidate Review: %s" % topic.title,
        "",
        "- Topic id: `%s`" % topic.topic_id,
        "- Priority: `%s`" % topic.priority,
        "- Mode: `%s`" % topic.mode,
        "",
        "## Selection Inputs",
        "",
    ]
    if topic.mode == "lifecycle":
        lines.append("- Lifecycle topic: `%s`" % topic.raw.get("lifecycle_topic", ""))
        lines.append("- Max seeds: `%s`" % topic.raw.get("max_seeds", ""))
        lines.append("- Depth: `%s`" % topic.raw.get("depth", ""))
    else:
        for key in ("seed_names", "queries", "tags"):
            values = _strings(topic.raw.get(key))
            lines.append("- `%s`: %s" % (key, ", ".join("`%s`" % item for item in values) if values else "none"))
    lines.extend(["", "## Selected Candidates", ""])
    candidates = trace.get("selected_candidates") if isinstance(trace.get("selected_candidates"), list) else None
    if candidates is None:
        candidates = pack.get("candidates") if isinstance(pack.get("candidates"), list) else []
    if not candidates:
        candidates = _functions_from_pack(pack)
    for item in candidates:
        if not isinstance(item, dict):
            continue
        reasons = _strings(item.get("reasons")) or _strings(item.get("why_selected"))
        lines.append(
            "- `%s` `%s` score=`%s` phase=`%s` reasons=%s"
            % (
                item.get("ea", ""),
                item.get("name", ""),
                item.get("score", item.get("confidence", "")),
                item.get("phase", ""),
                "; ".join(reasons[:6]) if reasons else "selected",
            )
        )
    lines.extend(["", "## Review Notes", ""])
    lines.append("- Include decisions are generated from deterministic corpus retrieval and should be reviewed before publishing a polished narrative.")
    lines.append("- Exclusion is implicit: candidates not present in the selected list were not high enough under this topic's bounded retrieval settings.")
    return "\n".join(lines).rstrip() + "\n"


def _render_source_map(topic: CanonicalTopic, evidence_path: Path) -> str:
    lines = [
        "# Source Map: %s" % topic.title,
        "",
        "## Corpus Evidence",
        "",
        "- Evidence pack: `%s`" % evidence_path.resolve(),
        "- Corpus evidence provides EA, function name, call-edge, tag, warning, and artifact-path facts for this build.",
        "",
        "## Public Contract References",
        "",
    ]
    if not topic.source_refs:
        lines.append("- No public references are attached to this topic.")
    for ref in topic.source_refs:
        lines.append("- [%s](%s): %s" % (ref["title"], ref["url"], ref["scope"]))
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "- Public references define documented contracts and terminology.",
            "- The Kernel Corpus pack defines build-specific implementation candidates.",
            "- Claims in `answer.md` must stay inside the evidence chain: claim -> EA -> function name -> artifact path -> inference level.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _render_gaps(topic: CanonicalTopic, pack: dict[str, Any]) -> str:
    lines = [
        "# Gaps: %s" % topic.title,
        "",
        "- Topic id: `%s`" % topic.topic_id,
        "- Priority: `%s`" % topic.priority,
        "",
    ]
    gaps = _strings(pack.get("gaps"))
    notes = _strings(pack.get("uncertainty_notes"))
    if not gaps and not notes:
        lines.append("- No explicit gaps or uncertainty notes were recorded.")
    for gap in gaps:
        lines.append("- Gap: %s" % gap)
    for note in notes:
        lines.append("- Uncertainty: %s" % note)
    return "\n".join(lines).rstrip() + "\n"


def _render_index_readme(index: dict[str, Any]) -> str:
    lines = [
        "# Canonical Kernel Corpus Answers",
        "",
        "- Schema: `%s`" % index.get("schema", ""),
        "- Created: `%s`" % index.get("created_at", ""),
        "- Pack root: `%s`" % index.get("pack_root", ""),
        "- Topic count: `%s`" % index.get("topic_count", ""),
        "- Passed: `%s`" % index.get("passed_count", ""),
        "- Failed: `%s`" % index.get("failed_count", ""),
        "",
        "## Topics",
        "",
    ]
    for topic in index.get("topics", []):
        lines.append(
            "- `%s` `%s` mode=`%s` functions=`%s` validation=`%s`"
            % (
                topic.get("priority", ""),
                topic.get("id", ""),
                topic.get("mode", ""),
                topic.get("selected_function_count", ""),
                "passed" if topic.get("validation_passed") else "failed",
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def _phase_flow_lines(pack: dict[str, Any], functions: list[dict[str, Any]]) -> list[str]:
    phases = pack.get("phases")
    if not isinstance(phases, list):
        return []
    lines = []
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase_functions = phase.get("functions")
        if not isinstance(phase_functions, list) or not phase_functions:
            continue
        names = [
            "%s(%s)" % (item.get("name", ""), item.get("ea", ""))
            for item in phase_functions[:5]
            if isinstance(item, dict)
        ]
        if names:
            lines.append("Phase `%s`: %s." % (phase.get("id", ""), ", ".join(names)))
    if not lines and functions:
        names = ["%s(%s)" % (item.get("name", ""), item.get("ea", "")) for item in functions[:8]]
        lines.append("Focused evidence candidates: %s." % ", ".join(names))
    return lines


def _functions_from_pack(pack: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    if isinstance(pack.get("functions"), list):
        result.extend(item for item in pack["functions"] if isinstance(item, dict))
    if isinstance(pack.get("phases"), list):
        for phase in pack["phases"]:
            if not isinstance(phase, dict):
                continue
            for function in phase.get("functions", []) if isinstance(phase.get("functions"), list) else []:
                if not isinstance(function, dict):
                    continue
                item = dict(function)
                item.setdefault("phase", str(phase.get("id", "")))
                result.append(item)
    seen = set()
    deduped = []
    for item in result:
        ea = str(item.get("ea", "") or "")
        if not ea or ea in seen:
            continue
        seen.add(ea)
        deduped.append(item)
    return deduped


def _best_artifact(function: dict[str, Any]) -> str:
    artifacts = function.get("artifacts", {}) if isinstance(function.get("artifacts"), dict) else {}
    for key in ("summary", "cleaned_pseudocode", "raw_pseudocode", "raw_vs_cleaned_diff"):
        value = str(artifacts.get(key, "") or "")
        if value:
            return value
    evidence = function.get("evidence", []) if isinstance(function.get("evidence"), list) else []
    for item in evidence:
        if isinstance(item, dict) and str(item.get("path", "") or ""):
            return str(item["path"])
    return ""


def _existing_atlas_page(pack_root: str | Path, atlas_page: str) -> str:
    name = str(atlas_page or "").strip()
    if not name:
        return ""
    candidate = Path(name)
    if candidate.is_file():
        return str(candidate)
    filename = name if name.lower().endswith(".md") else "%s.md" % name
    pack_candidate = Path(pack_root) / "reports" / "atlas" / filename
    if pack_candidate.is_file():
        return name
    return ""


def _selected_function_count(pack: dict[str, Any]) -> int:
    return len(_functions_from_pack(pack))


def _event(kind: str, value: str, function: dict[str, Any]) -> dict[str, str]:
    return {
        "kind": kind,
        "value": value,
        "ea": str(function.get("ea", "") or ""),
        "name": str(function.get("name", "") or ""),
    }


def _reference_payload(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {"title": "", "url": "", "scope": ""}
    return {
        "title": str(value.get("title", "") or ""),
        "url": str(value.get("url", "") or ""),
        "scope": str(value.get("scope", "") or ""),
    }


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    return []


def _unique_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _safe_id(value: str) -> bool:
    return bool(re.match(r"^[a-z0-9][a-z0-9_]*$", value or ""))


def _single_line(text: str, limit: int) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
