from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError, QueryError
from tools.kernel_corpus.query import corpus_status, get_function, get_neighbors, search_functions
from tools.kernel_corpus.schema import EVIDENCE_PACK_SCHEMA_VERSION

ONTOLOGY_SCHEMA_VERSION = "kernel_corpus_lifecycle_ontology_v1"
DEFAULT_MAX_SEEDS = 32
MAX_MAX_SEEDS = 200
DEFAULT_DEPTH = 2
MAX_DEPTH = 4
EXCERPT_LIMIT = 700
PHASE_ORDER = (
    "entry",
    "allocate",
    "initialize",
    "publish",
    "notify",
    "steady_state",
    "exit",
    "rundown",
    "delete",
)
KERNEL_PREFIXES = ("Psp", "Nt", "Zw", "Ps", "Ob", "Mm", "Se")
OBJECT_TOPIC_TOKEN_GROUPS = {
    "process_object": ("process", "eprocess"),
    "thread_object": ("thread", "ethread", "kthread"),
    "file_object": ("file",),
    "driver_object": ("driver",),
    "device_object": ("device",),
    "registry_key": ("registry", "key", "hive"),
    "section_object": ("section",),
    "module_image": ("module", "image"),
}


@dataclass
class Candidate:
    ea: str
    name: str
    tags: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    cleaned_excerpt: str = ""
    warning_count: int = 0
    buffer_contract_count: int = 0
    why_selected: set[str] = field(default_factory=set)
    discovery_kinds: set[str] = field(default_factory=set)
    phase_hints: dict[str, float] = field(default_factory=dict)
    distances: list[int] = field(default_factory=list)
    bridge_degree: int = 0
    confidence: float = 0.0
    phase: str = "steady_state"
    phase_confidence: float = 0.0
    phase_reason: str = ""


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = trace_lifecycle(
            args.pack_root,
            args.topic,
            max_seeds=args.max_seeds,
            depth=args.depth,
            output_path=args.output or None,
        )
    except KernelCorpusError as exc:
        print("Kernel lifecycle trace failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def trace_lifecycle(
    pack_root: str | Path,
    topic: str,
    max_seeds: int = DEFAULT_MAX_SEEDS,
    depth: int = DEFAULT_DEPTH,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    bounded_max_seeds = _bounded_int(max_seeds, DEFAULT_MAX_SEEDS, MAX_MAX_SEEDS)
    bounded_depth = _bounded_int(depth, DEFAULT_DEPTH, MAX_DEPTH)
    ontology, ontology_path = load_ontology(topic)
    status = corpus_status(pack_root)
    candidates: dict[str, Candidate] = {}
    graph_edges: dict[tuple[str, str, str], dict[str, str]] = {}
    missing_exact_seeds: list[str] = []

    seed_names = _ontology_seed_names(ontology)
    for seed_name in seed_names:
        exact_found = _discover_seed_name(
            pack_root,
            ontology,
            candidates,
            seed_name,
            limit=_discovery_limit(bounded_max_seeds),
        )
        if not exact_found:
            missing_exact_seeds.append(seed_name)

    for term, phase_id in _ontology_seed_terms(ontology):
        _discover_seed_term(
            pack_root,
            ontology,
            candidates,
            term,
            phase_id,
            limit=_discovery_limit(bounded_max_seeds),
        )

    for tag, phase_id in _ontology_tags(ontology):
        _discover_tag(
            pack_root,
            candidates,
            tag,
            phase_id,
            limit=_discovery_limit(bounded_max_seeds),
        )

    _score_candidates(candidates, ontology, graph_edges)
    roots = _expansion_roots(candidates, bounded_max_seeds)
    _expand_graph(
        pack_root,
        candidates,
        graph_edges,
        roots,
        depth=bounded_depth,
        limit=max(40, min(MAX_MAX_SEEDS, bounded_max_seeds * 8)),
    )
    _score_candidates(candidates, ontology, graph_edges)
    selected = _select_candidates(candidates, bounded_max_seeds)
    selected_eas = {candidate.ea for candidate in selected}
    _refresh_selected_functions(pack_root, selected)
    _assign_phases(selected, ontology)
    selected_edges = _edges_among_selected(graph_edges, selected_eas)

    gaps = _build_gaps(
        ontology,
        selected,
        missing_exact_seeds,
        status,
        selected_edges,
        candidate_count=len(candidates),
        max_seeds=bounded_max_seeds,
    )
    uncertainty_notes = _uncertainty_notes(bounded_depth, bounded_max_seeds)
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    evidence_pack = {
        "schema": EVIDENCE_PACK_SCHEMA_VERSION,
        "topic": str(topic),
        "ontology_schema": str(ontology.get("schema", "")),
        "ontology_path": str(ontology_path.resolve()),
        "pack_root": str(status.get("pack_root", Path(pack_root).resolve())),
        "created_at": created_at,
        "parameters": {
            "max_seeds": bounded_max_seeds,
            "depth": bounded_depth,
        },
        "status": _status_payload(status),
        "summary": _summary_payload(selected, selected_edges),
        "phases": _phase_payloads(selected, ontology),
        "edges": selected_edges,
        "candidates": _candidate_summary(selected),
        "gaps": gaps,
        "uncertainty_notes": uncertainty_notes,
        "output_path": "",
    }
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        evidence_pack["output_path"] = str(out.resolve())
        out.write_text(json.dumps(evidence_pack, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    return evidence_pack


def load_ontology(topic: str) -> tuple[dict[str, Any], Path]:
    safe_topic = re.sub(r"[^A-Za-z0-9_]+", "", str(topic or ""))
    if not safe_topic:
        raise QueryError("Lifecycle topic is required")
    path = Path(__file__).with_name("ontology") / ("%s.json" % safe_topic)
    if not path.is_file():
        raise QueryError("Lifecycle ontology is missing: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QueryError("Lifecycle ontology could not be read: %s" % exc) from exc
    if not isinstance(data, dict):
        raise QueryError("Lifecycle ontology is not a JSON object: %s" % path)
    if str(data.get("schema", "")) != ONTOLOGY_SCHEMA_VERSION:
        raise QueryError("Unsupported lifecycle ontology schema: %s" % data.get("schema", ""))
    if str(data.get("topic", "")) != safe_topic:
        raise QueryError("Lifecycle ontology topic mismatch: %s" % path)
    return data, path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trace a lifecycle over a Kernel Corpus pack.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--topic", required=True, help="Lifecycle topic, such as process_object.")
    parser.add_argument("--max-seeds", type=int, default=DEFAULT_MAX_SEEDS, help="Maximum selected functions.")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH, help="Caller/callee expansion depth.")
    parser.add_argument("--output", default="", help="Optional evidence-pack JSON output path.")
    return parser


def _discover_seed_name(
    pack_root: str | Path,
    ontology: dict[str, Any],
    candidates: dict[str, Candidate],
    seed_name: str,
    *,
    limit: int,
) -> bool:
    exact_found = False
    for function in search_functions(pack_root, query=seed_name, limit=limit):
        candidate = _candidate_from_function(function)
        existing = candidates.setdefault(candidate.ea, candidate)
        _merge_candidate(existing, candidate)
        if candidate.name.lower() == seed_name.lower():
            exact_found = True
            existing.discovery_kinds.add("exact_name")
            existing.why_selected.add("exact seed name: %s" % seed_name)
            _add_phase_hint(existing, _phase_for_name_seed(ontology, seed_name), 0.75)
        elif seed_name.lower() in candidate.name.lower():
            existing.discovery_kinds.add("seed_name_text")
            existing.why_selected.add("seed name text match: %s" % seed_name)
    return exact_found


def _discover_seed_term(
    pack_root: str | Path,
    ontology: dict[str, Any],
    candidates: dict[str, Candidate],
    term: str,
    phase_id: str,
    *,
    limit: int,
) -> None:
    term_text = str(term or "").strip()
    if not term_text:
        return
    for function in search_functions(pack_root, query=term_text, limit=limit):
        candidate = _candidate_from_function(function)
        if not _term_matches_candidate(candidate, term_text):
            try:
                function = get_function(pack_root, candidate.ea, include_excerpt=True, include_artifacts=True)
                candidate = _candidate_from_function(function)
            except QueryError:
                continue
        if not _term_matches_candidate(candidate, term_text):
            continue
        existing = candidates.setdefault(candidate.ea, candidate)
        _merge_candidate(existing, candidate)
        name_matched = _term_matches_name(candidate, term_text)
        existing.discovery_kinds.add("seed_term_name" if name_matched else "seed_term_evidence")
        existing.why_selected.add("seed term match: %s" % term_text)
        _add_phase_hint(existing, phase_id, 0.35 if name_matched else 0.18)
        _add_phase_hint(existing, _phase_for_text(ontology, term_text), 0.20 if name_matched else 0.10)


def _discover_tag(
    pack_root: str | Path,
    candidates: dict[str, Candidate],
    tag: str,
    phase_id: str,
    *,
    limit: int,
) -> None:
    tag_text = str(tag or "").strip()
    if not tag_text:
        return
    for function in search_functions(pack_root, tags=[tag_text], limit=limit):
        candidate = _candidate_from_function(function)
        existing = candidates.setdefault(candidate.ea, candidate)
        _merge_candidate(existing, candidate)
        existing.discovery_kinds.add("tag")
        existing.why_selected.add("tag match: %s" % tag_text)
        _add_phase_hint(existing, phase_id, 0.18)


def _expand_graph(
    pack_root: str | Path,
    candidates: dict[str, Candidate],
    graph_edges: dict[tuple[str, str, str], dict[str, str]],
    roots: list[Candidate],
    *,
    depth: int,
    limit: int,
) -> None:
    for root in roots:
        try:
            neighbors = get_neighbors(pack_root, root.ea, direction="both", depth=depth, limit=limit)
        except QueryError:
            continue
        for node in neighbors.get("nodes", []):
            if not isinstance(node, dict):
                continue
            candidate = _candidate_from_function(node)
            existing = candidates.setdefault(candidate.ea, candidate)
            _merge_candidate(existing, candidate)
            node_depth = _int_value(node.get("depth"), 0)
            existing.distances.append(node_depth)
            if node_depth > 0:
                existing.discovery_kinds.add("graph")
                existing.why_selected.add("graph neighbor of %s depth %d" % (root.name, node_depth))
        for edge in neighbors.get("edges", []):
            if not isinstance(edge, dict):
                continue
            src_ea = str(edge.get("src_ea", ""))
            dst_ea = str(edge.get("dst_ea", ""))
            edge_kind = str(edge.get("edge_kind", "calls") or "calls")
            if src_ea and dst_ea:
                graph_edges[(src_ea, dst_ea, edge_kind)] = {
                    "src_ea": src_ea,
                    "dst_ea": dst_ea,
                    "edge_kind": edge_kind,
                }


def _score_candidates(
    candidates: dict[str, Candidate],
    ontology: dict[str, Any],
    graph_edges: dict[tuple[str, str, str], dict[str, str]],
) -> None:
    degree = _bridge_degrees(graph_edges)
    ontology_tags = {tag for tag, _phase_id in _ontology_tags(ontology)}
    for candidate in candidates.values():
        candidate.bridge_degree = degree.get(candidate.ea, 0)
        score = 0.05
        if "exact_name" in candidate.discovery_kinds:
            score += 0.45
        if "seed_name_text" in candidate.discovery_kinds:
            score += 0.16
        if "seed_term_name" in candidate.discovery_kinds:
            score += 0.16
        if "seed_term_evidence" in candidate.discovery_kinds:
            score += 0.06
        if "tag" in candidate.discovery_kinds:
            score += 0.08
        if "graph" in candidate.discovery_kinds:
            distance = min((item for item in candidate.distances if item > 0), default=1)
            score += max(0.04, 0.16 - (0.04 * max(0, distance - 1)))
        prefix = _kernel_prefix(candidate.name)
        if prefix:
            score += _prefix_score(prefix)
        if ontology_tags.intersection(candidate.tags):
            score += 0.08
        if candidate.phase_hints:
            score += min(0.12, max(candidate.phase_hints.values()) * 0.16)
        topic_adjustment, topic_reason = _topic_relevance_adjustment(candidate, ontology)
        if topic_adjustment:
            score += topic_adjustment
            candidate.why_selected.add(topic_reason)
        score += min(0.10, candidate.bridge_degree * 0.025)
        if candidate.buffer_contract_count > 0:
            score += 0.02
        if candidate.warning_count > 0:
            score -= min(0.06, candidate.warning_count * 0.01)
        candidate.confidence = _clamp(score, 0.03, 0.99)


def _refresh_selected_functions(pack_root: str | Path, selected: list[Candidate]) -> None:
    for candidate in selected:
        try:
            function = get_function(pack_root, candidate.ea, include_excerpt=True, include_artifacts=True)
        except QueryError:
            continue
        refreshed = _candidate_from_function(function)
        _merge_candidate(candidate, refreshed)


def _assign_phases(selected: list[Candidate], ontology: dict[str, Any]) -> None:
    phases = _phase_map(ontology)
    for candidate in selected:
        best_phase = "steady_state"
        best_score = 0.0
        best_reason = "fallback phase"
        for phase_id in PHASE_ORDER:
            phase = phases.get(phase_id, {})
            score, reason = _phase_score(candidate, phase_id, phase)
            if score > best_score:
                best_phase = phase_id
                best_score = score
                best_reason = reason
        fallback_phase, fallback_reason = _fallback_phase(candidate)
        if best_score < 0.18 and fallback_phase:
            best_phase = fallback_phase
            best_score = 0.24
            best_reason = fallback_reason
        if best_phase not in PHASE_ORDER:
            best_phase = "steady_state"
        candidate.phase = best_phase
        candidate.phase_reason = best_reason
        candidate.phase_confidence = _clamp((candidate.confidence * 0.70) + (min(best_score, 1.0) * 0.30), 0.01, 0.99)
        candidate.why_selected.add("phase %s: %s" % (candidate.phase, candidate.phase_reason))


def _phase_score(candidate: Candidate, phase_id: str, phase: dict[str, Any]) -> tuple[float, str]:
    score = candidate.phase_hints.get(phase_id, 0.0)
    reason = "ontology hint"
    names = {item.lower() for item in _strings(phase.get("seed_names"))}
    if candidate.name.lower() in names:
        score += 0.70
        reason = "phase exact seed name"
    name_terms = _strings(phase.get("name_terms"))
    for term in name_terms:
        if term.lower() in candidate.name.lower():
            score += 0.35
            reason = "phase name term: %s" % term
            break
    evidence_text = " ".join([candidate.name, candidate.cleaned_excerpt, " ".join(candidate.tags)]).lower()
    for term in _strings(phase.get("terms")):
        if term.lower() in evidence_text:
            score += 0.16
            reason = "phase evidence term: %s" % term
            break
    phase_tags = set(_strings(phase.get("tags")))
    if phase_tags.intersection(candidate.tags):
        score += 0.12
        reason = "phase tag match"
    return score, reason


def _fallback_phase(candidate: Candidate) -> tuple[str, str]:
    name = candidate.name.lower()
    if name.startswith("ntcreate") or name.startswith("zwcreate"):
        return "entry", "syscall-style create entry name"
    if "alloc" in name:
        return "allocate", "allocation name"
    if "init" in name:
        return "initialize", "initialization name"
    if "insert" in name or "publish" in name:
        return "publish", "publish or insert name"
    if "notify" in name or "callback" in name:
        return "notify", "notification name"
    if "exit" in name or "terminate" in name:
        return "exit", "exit or terminate name"
    if "rundown" in name:
        return "rundown", "rundown name"
    if "delete" in name or "dereference" in name or "destroy" in name:
        return "delete", "delete or dereference name"
    return "steady_state", "no stronger phase signal"


def _candidate_from_function(function: dict[str, Any]) -> Candidate:
    artifacts = function.get("artifacts", {}) if isinstance(function.get("artifacts"), dict) else {}
    tags = [str(item) for item in function.get("tags", []) if str(item)]
    why = {str(item) for item in function.get("why_selected", []) if str(item)}
    return Candidate(
        ea=str(function.get("ea", "")),
        name=str(function.get("name", "")),
        tags=tags,
        artifacts={str(key): str(value) for key, value in artifacts.items()},
        cleaned_excerpt=str(function.get("cleaned_excerpt", "") or ""),
        warning_count=_int_value(function.get("warning_count"), 0),
        buffer_contract_count=_int_value(function.get("buffer_contract_count"), 0),
        why_selected=why,
    )


def _merge_candidate(target: Candidate, source: Candidate) -> None:
    if not target.name and source.name:
        target.name = source.name
    target.tags = sorted(set(target.tags).union(source.tags))
    target.artifacts.update({key: value for key, value in source.artifacts.items() if value})
    if source.cleaned_excerpt and len(source.cleaned_excerpt) > len(target.cleaned_excerpt):
        target.cleaned_excerpt = source.cleaned_excerpt
    target.warning_count = max(target.warning_count, source.warning_count)
    target.buffer_contract_count = max(target.buffer_contract_count, source.buffer_contract_count)
    target.why_selected.update(source.why_selected)
    target.discovery_kinds.update(source.discovery_kinds)
    for phase_id, score in source.phase_hints.items():
        _add_phase_hint(target, phase_id, score)


def _select_candidates(candidates: dict[str, Candidate], max_seeds: int) -> list[Candidate]:
    return sorted(
        candidates.values(),
        key=lambda item: (-item.confidence, _phase_sort_hint(item), int(item.ea, 0) if item.ea.startswith("0x") else 0),
    )[:max_seeds]


def _expansion_roots(candidates: dict[str, Candidate], max_seeds: int) -> list[Candidate]:
    roots = [
        candidate
        for candidate in candidates.values()
        if candidate.discovery_kinds.intersection({"exact_name", "seed_name_text", "seed_term_name", "seed_term_evidence"})
    ]
    return sorted(
        roots,
        key=lambda item: (
            0 if "exact_name" in item.discovery_kinds else 1,
            -item.confidence,
            int(item.ea, 0) if item.ea.startswith("0x") else 0,
        ),
    )[:max(1, min(max_seeds, DEFAULT_MAX_SEEDS))]


def _phase_payloads(selected: list[Candidate], ontology: dict[str, Any]) -> list[dict[str, Any]]:
    phases = _phase_map(ontology)
    by_phase: dict[str, list[Candidate]] = {phase_id: [] for phase_id in PHASE_ORDER}
    for candidate in selected:
        by_phase.setdefault(candidate.phase, []).append(candidate)
    payloads = []
    for phase_id in PHASE_ORDER:
        phase = phases.get(phase_id, {})
        payloads.append(
            {
                "id": phase_id,
                "title": str(phase.get("title", phase_id.replace("_", " ").title())),
                "functions": [_function_payload(candidate, phase) for candidate in by_phase.get(phase_id, [])],
            }
        )
    return payloads


def _function_payload(candidate: Candidate, phase: dict[str, Any]) -> dict[str, Any]:
    return {
        "ea": candidate.ea,
        "name": candidate.name,
        "phase": candidate.phase,
        "role": _role(candidate, phase),
        "confidence": round(candidate.confidence, 3),
        "phase_confidence": round(candidate.phase_confidence, 3),
        "tags": candidate.tags,
        "why_selected": sorted(candidate.why_selected),
        "evidence": _evidence(candidate),
        "artifacts": candidate.artifacts,
        "inference_notes": _inference_notes(candidate),
    }


def _role(candidate: Candidate, phase: dict[str, Any]) -> str:
    role_by_name = phase.get("role_by_name", {}) if isinstance(phase.get("role_by_name"), dict) else {}
    role = str(role_by_name.get(candidate.name, "") or "")
    if role:
        return role
    title = str(phase.get("title", candidate.phase))
    return "%s candidate selected from corpus evidence" % title


def _evidence(candidate: Candidate) -> list[dict[str, str]]:
    evidence = []
    cleaned_path = candidate.artifacts.get("cleaned_pseudocode", "")
    if candidate.cleaned_excerpt:
        evidence.append(
            {
                "kind": "cleaned_excerpt",
                "path": cleaned_path,
                "text": _truncate(candidate.cleaned_excerpt, EXCERPT_LIMIT),
            }
        )
    summary_path = candidate.artifacts.get("summary", "")
    if summary_path:
        evidence.append(
            {
                "kind": "summary",
                "path": summary_path,
                "text": "",
            }
        )
    return evidence


def _inference_notes(candidate: Candidate) -> list[str]:
    notes = []
    if candidate.phase_confidence < 0.50:
        notes.append("Phase assignment is low confidence.")
    if "graph" not in candidate.discovery_kinds and "exact_name" not in candidate.discovery_kinds:
        notes.append("Selected without direct exact-name or graph evidence.")
    if candidate.warning_count:
        notes.append("Function artifact reports warnings; inspect raw artifacts before relying on details.")
    return notes


def _edges_among_selected(
    graph_edges: dict[tuple[str, str, str], dict[str, str]],
    selected_eas: set[str],
) -> list[dict[str, str]]:
    edges = [
        edge
        for edge in graph_edges.values()
        if edge["src_ea"] in selected_eas and edge["dst_ea"] in selected_eas
    ]
    return sorted(edges, key=lambda edge: (int(edge["src_ea"], 0), int(edge["dst_ea"], 0), edge["edge_kind"]))


def _candidate_summary(selected: list[Candidate]) -> list[dict[str, Any]]:
    return [
        {
            "ea": candidate.ea,
            "name": candidate.name,
            "phase": candidate.phase,
            "confidence": round(candidate.confidence, 3),
            "phase_confidence": round(candidate.phase_confidence, 3),
            "why_selected": sorted(candidate.why_selected),
        }
        for candidate in selected
    ]


def _summary_payload(selected: list[Candidate], edges: list[dict[str, str]]) -> dict[str, Any]:
    phase_counts = {phase_id: 0 for phase_id in PHASE_ORDER}
    for candidate in selected:
        phase_counts[candidate.phase] = phase_counts.get(candidate.phase, 0) + 1
    return {
        "selected_function_count": len(selected),
        "edge_count": len(edges),
        "phase_counts": phase_counts,
        "top_functions": [
            {
                "ea": candidate.ea,
                "name": candidate.name,
                "phase": candidate.phase,
                "confidence": round(candidate.confidence, 3),
            }
            for candidate in selected[:10]
        ],
    }


def _status_payload(status: dict[str, Any]) -> dict[str, Any]:
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    return {
        "corpus_complete": True,
        "function_count": int(manifest.get("function_count", 0) or 0),
        "skipped_count": int(manifest.get("skipped_count", 0) or 0),
        "schema_version": str(status.get("schema_version", "")),
        "manifest_path": str(status.get("manifest_path", "")),
        "sqlite_path": str(status.get("sqlite_path", "")),
        "warnings": [str(item) for item in status.get("warnings", []) if str(item)],
    }


def _build_gaps(
    ontology: dict[str, Any],
    selected: list[Candidate],
    missing_exact_seeds: list[str],
    status: dict[str, Any],
    selected_edges: list[dict[str, str]],
    *,
    candidate_count: int,
    max_seeds: int,
) -> list[str]:
    gaps = []
    for seed_name in missing_exact_seeds:
        gaps.append("Exact seed not found: %s" % seed_name)
    selected_phases = {candidate.phase for candidate in selected}
    for phase_id in PHASE_ORDER:
        phase = _phase_map(ontology).get(phase_id, {})
        if phase.get("required", True) and phase_id not in selected_phases:
            gaps.append("No selected functions assigned to phase: %s" % phase_id)
    if not selected_edges:
        gaps.append("No caller/callee edges among selected functions within requested depth.")
    if candidate_count > max_seeds:
        gaps.append("Candidate list was capped at max_seeds=%d." % max_seeds)
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    skipped_count = int(manifest.get("skipped_count", 0) or 0)
    if skipped_count:
        gaps.append("Source corpus reports skipped functions: %d." % skipped_count)
    return gaps


def _uncertainty_notes(depth: int, max_seeds: int) -> list[str]:
    return [
        "Lifecycle tracing is heuristic retrieval, not a proof engine.",
        "Phase labels are inferred from ontology hints, names, tags, FTS matches, and callgraph proximity.",
        "Only edges present among selected functions should be treated as target-specific transition evidence.",
        "Increase --depth or --max-seeds when object-manager or callback transitions look incomplete.",
    ]


def _ontology_seed_names(ontology: dict[str, Any]) -> list[str]:
    names = _strings(ontology.get("seed_names"))
    for phase in _phase_map(ontology).values():
        names.extend(_strings(phase.get("seed_names")))
    return _unique(names)


def _ontology_seed_terms(ontology: dict[str, Any]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for term in _strings(ontology.get("seed_terms")):
        result.append((term, _phase_for_text(ontology, term)))
    for phase_id, phase in _phase_map(ontology).items():
        for term in _strings(phase.get("terms")) + _strings(phase.get("name_terms")):
            result.append((term, phase_id))
    return _unique_pairs(result)


def _ontology_tags(ontology: dict[str, Any]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for tag in _strings(ontology.get("tags")):
        result.append((tag, "steady_state"))
    for phase_id, phase in _phase_map(ontology).items():
        for tag in _strings(phase.get("tags")):
            result.append((tag, phase_id))
    return _unique_pairs(result)


def _phase_for_name_seed(ontology: dict[str, Any], seed_name: str) -> str:
    target = seed_name.lower()
    for phase_id, phase in _phase_map(ontology).items():
        if target in {item.lower() for item in _strings(phase.get("seed_names"))}:
            return phase_id
    return _phase_for_text(ontology, seed_name)


def _phase_for_text(ontology: dict[str, Any], text: str) -> str:
    lowered = text.lower()
    for phase_id, phase in _phase_map(ontology).items():
        haystack = _strings(phase.get("terms")) + _strings(phase.get("name_terms")) + _strings(phase.get("seed_names"))
        if any(item.lower() == lowered or item.lower() in lowered for item in haystack if item):
            return phase_id
    return _fallback_phase(Candidate(ea="", name=text))[0]


def _phase_map(ontology: dict[str, Any]) -> dict[str, dict[str, Any]]:
    phases = ontology.get("phases", {})
    if not isinstance(phases, dict):
        return {}
    return {str(key): value for key, value in phases.items() if isinstance(value, dict)}


def _phase_sort_hint(candidate: Candidate) -> int:
    if not candidate.phase_hints:
        return len(PHASE_ORDER)
    phase_id = max(candidate.phase_hints.items(), key=lambda item: item[1])[0]
    return PHASE_ORDER.index(phase_id) if phase_id in PHASE_ORDER else len(PHASE_ORDER)


def _add_phase_hint(candidate: Candidate, phase_id: str, score: float) -> None:
    if phase_id not in PHASE_ORDER:
        return
    candidate.phase_hints[phase_id] = max(candidate.phase_hints.get(phase_id, 0.0), score)


def _bridge_degrees(graph_edges: dict[tuple[str, str, str], dict[str, str]]) -> dict[str, int]:
    degree: dict[str, int] = {}
    for edge in graph_edges.values():
        src = edge["src_ea"]
        dst = edge["dst_ea"]
        degree[src] = degree.get(src, 0) + 1
        degree[dst] = degree.get(dst, 0) + 1
    return degree


def _kernel_prefix(name: str) -> str:
    for prefix in KERNEL_PREFIXES:
        if name.startswith(prefix):
            return prefix
    return ""


def _prefix_score(prefix: str) -> float:
    return {
        "Psp": 0.12,
        "Nt": 0.10,
        "Zw": 0.10,
        "Ps": 0.09,
        "Ob": 0.08,
        "Mm": 0.05,
        "Se": 0.05,
    }.get(prefix, 0.0)


def _topic_relevance_adjustment(candidate: Candidate, ontology: dict[str, Any]) -> tuple[float, str]:
    if candidate.discovery_kinds.intersection({"exact_name", "seed_name_text"}):
        return 0.0, ""
    target_tokens = set(_target_topic_tokens(ontology))
    conflicting_tokens = set(_conflicting_topic_tokens(ontology))
    if not target_tokens or not conflicting_tokens:
        return 0.0, ""
    name_tokens = set(_identifier_tokens(candidate.name))
    if not name_tokens:
        return 0.0, ""
    if name_tokens.intersection(target_tokens):
        return 0.0, ""
    conflicts = sorted(name_tokens.intersection(conflicting_tokens))
    if not conflicts:
        return 0.0, ""
    return -0.24, "topic relevance penalty: conflicting name token(s) %s" % ", ".join(conflicts)


def _target_topic_tokens(ontology: dict[str, Any]) -> tuple[str, ...]:
    topic = str(ontology.get("topic", "") or "")
    if topic in OBJECT_TOPIC_TOKEN_GROUPS:
        return OBJECT_TOPIC_TOKEN_GROUPS[topic]
    tokens = []
    for value in [topic] + _strings(ontology.get("labels")):
        tokens.extend(_identifier_tokens(value))
    return tuple(item for item in _unique(tokens) if item not in {"object", "lifecycle"})


def _conflicting_topic_tokens(ontology: dict[str, Any]) -> tuple[str, ...]:
    target = set(_target_topic_tokens(ontology))
    tokens = []
    for group in OBJECT_TOPIC_TOKEN_GROUPS.values():
        tokens.extend(group)
    return tuple(item for item in _unique(tokens) if item not in target)


def _identifier_tokens(value: str) -> list[str]:
    parts = []
    for chunk in re.findall(r"[A-Za-z0-9]+", str(value or "")):
        parts.extend(
            item.lower()
            for item in re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|[0-9]+", chunk)
            if item
        )
    expanded = []
    for part in parts:
        expanded.append(part)
        if len(part) > 3 and part.endswith("s"):
            expanded.append(part[:-1])
    return expanded


def _term_matches_candidate(candidate: Candidate, term: str) -> bool:
    lowered = str(term or "").lower()
    evidence_text = " ".join([candidate.name, candidate.cleaned_excerpt, " ".join(candidate.tags)]).lower()
    if lowered and lowered in evidence_text:
        return True
    tokens = _required_term_tokens(lowered)
    return bool(tokens) and all(token in evidence_text for token in tokens)


def _term_matches_name(candidate: Candidate, term: str) -> bool:
    lowered = str(term or "").lower()
    name_text = candidate.name.lower()
    if lowered and lowered in name_text:
        return True
    tokens = _required_term_tokens(lowered)
    return bool(tokens) and all(token in name_text for token in tokens)


def _term_tokens(value: str) -> list[str]:
    return [item.lower() for item in re.findall(r"[A-Za-z0-9_]+", value) if item]


def _required_term_tokens(value: str) -> list[str]:
    tokens = _term_tokens(value)
    if len(tokens) > 1:
        return tokens
    significant = [token for token in tokens if token not in {"process", "thread", "object", "routine", "kernel"}]
    return significant or tokens


def _discovery_limit(max_seeds: int) -> int:
    return max(20, min(MAX_MAX_SEEDS, max_seeds * 4))


def _bounded_int(value: int, default: int, maximum: int) -> int:
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


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _unique(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        item = str(value)
        key = item.lower()
        if item and key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _unique_pairs(values: list[tuple[str, str]]) -> list[tuple[str, str]]:
    result = []
    seen = set()
    for value, phase_id in values:
        key = (value.lower(), phase_id)
        if value and key not in seen:
            seen.add(key)
            result.append((value, phase_id))
    return result


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


if __name__ == "__main__":
    raise SystemExit(main())
