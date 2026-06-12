from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError, QueryError
from tools.kernel_corpus.query import corpus_status

REPORT_SCHEMA_VERSION = "kernel_corpus_answer_harness_report_v1"
DEFAULT_PROMPT_CHARS = 30000
DEFAULT_ATLAS_CHARS = 6000
MAX_FUNCTIONS_IN_PROMPT = 40
MAX_EDGES_IN_PROMPT = 80
FUNCTION_EXCERPT_CHARS = 320
ATLAS_DIR = Path("reports") / "atlas"


@dataclass(frozen=True)
class FunctionEvidence:
    ea: str
    name: str
    phase: str
    role: str
    confidence: str
    phase_confidence: str
    artifacts: dict[str, str]
    evidence: list[dict[str, str]]
    inference_notes: list[str]
    why_selected: list[str]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = run_harness(
            args.pack_root,
            args.evidence_pack,
            args.question,
            atlas_page=args.atlas_page or "",
            prompt_out=args.prompt_out or "",
            answer_in=args.answer_in or "",
            report_out=args.report_out or "",
        )
    except (OSError, KernelCorpusError, ValueError, json.JSONDecodeError) as exc:
        print("Kernel corpus answer harness failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def run_harness(
    pack_root: str | Path,
    evidence_pack: str | Path,
    question: str,
    *,
    atlas_page: str | Path = "",
    prompt_out: str | Path = "",
    answer_in: str | Path = "",
    report_out: str | Path = "",
) -> dict[str, Any]:
    prompt_result = build_prompt(
        pack_root,
        evidence_pack,
        question,
        atlas_page=atlas_page,
    )
    prompt_path = ""
    if prompt_out:
        path = Path(prompt_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(prompt_result["prompt"], encoding="utf-8")
        prompt_path = str(path.resolve())

    validation: dict[str, Any] | None = None
    if answer_in:
        answer_path = Path(answer_in)
        validation = validate_answer(
            prompt_result["evidence_pack"],
            answer_path.read_text(encoding="utf-8", errors="replace"),
            answer_path=answer_path,
        )

    report = {
        "schema": REPORT_SCHEMA_VERSION,
        "ok": True,
        "pack_root": str(Path(pack_root).resolve()),
        "evidence_pack_path": str(Path(evidence_pack).resolve()),
        "question": str(question),
        "prompt_path": prompt_path,
        "prompt_char_count": len(prompt_result["prompt"]),
        "prompt_truncated": prompt_result["truncated"],
        "atlas_page": prompt_result["atlas"],
        "validation": validation,
    }
    report_path = ""
    if report_out:
        path = Path(report_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
        report_path = str(path.resolve())
    payload = dict(report)
    payload["report_path"] = report_path
    if not prompt_path:
        payload["prompt"] = prompt_result["prompt"]
    return payload


def build_prompt(
    pack_root: str | Path,
    evidence_pack: str | Path,
    question: str,
    *,
    atlas_page: str | Path = "",
    max_chars: int = DEFAULT_PROMPT_CHARS,
) -> dict[str, Any]:
    if not str(question or "").strip():
        raise QueryError("Question is required")
    pack_status = corpus_status(pack_root)
    evidence_path = Path(evidence_pack)
    pack = _read_json_object(evidence_path, "evidence pack")
    functions = _collect_functions(pack)
    edges = _edges(pack)
    gaps = _strings(pack.get("gaps"))
    uncertainty_notes = _strings(pack.get("uncertainty_notes"))
    atlas = _read_atlas_page(pack_root, atlas_page)
    lines = _prompt_lines(
        pack_root,
        evidence_path,
        str(question),
        pack,
        pack_status,
        functions,
        edges,
        gaps,
        uncertainty_notes,
        atlas,
    )
    prompt = "\n".join(lines).rstrip() + "\n"
    truncated = len(prompt) > max_chars
    if truncated:
        prompt = prompt[:max_chars].rstrip() + "\n\n[TRUNCATED: prompt exceeded %d characters]\n" % max_chars
    return {
        "prompt": prompt,
        "truncated": truncated,
        "evidence_pack": pack,
        "functions": [function.__dict__ for function in functions],
        "atlas": atlas,
    }


def validate_answer(
    evidence_pack: dict[str, Any],
    answer_text: str,
    *,
    answer_path: str | Path | None = None,
) -> dict[str, Any]:
    functions = _collect_functions(evidence_pack)
    lines = str(answer_text or "").splitlines()
    warnings: list[dict[str, Any]] = []
    checked_bullets = 0
    cited_function_keys: set[str] = set()
    for index, line in enumerate(lines):
        if not _is_bullet(line):
            continue
        matches = _matching_functions(line, functions)
        if not matches:
            continue
        checked_bullets += 1
        window = "\n".join(lines[index : min(len(lines), index + 3)])
        for function in matches:
            cited_function_keys.add(function.ea)
            line_has_ea = _contains_ea(line, function.ea)
            line_has_name = function.name in line
            if not line_has_ea:
                warnings.append(
                    _warning(
                        "missing_ea",
                        "Major-function bullet mentions %s without its EA %s." % (function.name, function.ea),
                        line=index + 1,
                        function=function,
                    )
                )
            if not line_has_name:
                warnings.append(
                    _warning(
                        "missing_function_name",
                        "Major-function bullet cites %s without function name %s." % (function.ea, function.name),
                        line=index + 1,
                        function=function,
                    )
                )
            if not _contains_artifact_path(window, _artifact_paths(function)):
                warnings.append(
                    _warning(
                        "missing_nearby_artifact_path",
                        "Major-function bullet for %s %s lacks a nearby artifact path." % (function.ea, function.name),
                        line=index + 1,
                        function=function,
                    )
                )
    if functions and checked_bullets == 0:
        warnings.append(
            _warning(
                "missing_major_function_bullets",
                "No Markdown bullet cites a known evidence-pack function.",
            )
        )
    gaps = _strings(evidence_pack.get("gaps")) + _strings(evidence_pack.get("uncertainty_notes"))
    gap_section_present = _has_gap_or_uncertainty_section(answer_text)
    if gaps and not gap_section_present:
        warnings.append(
            _warning(
                "missing_gaps_section",
                "Evidence pack has gaps or uncertainty notes, but answer lacks a gaps/uncertainty section.",
            )
        )
    return {
        "ok": True,
        "answer_path": str(Path(answer_path).resolve()) if answer_path else "",
        "passed": not warnings,
        "warning_count": len(warnings),
        "warnings": warnings,
        "checked_major_function_bullets": checked_bullets,
        "cited_function_count": len(cited_function_keys),
        "evidence_function_count": len(functions),
        "gap_section_present": gap_section_present,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and validate evidence-grounded Kernel Corpus answer prompts.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root containing manifest.json and corpus.sqlite.")
    parser.add_argument("--evidence-pack", required=True, help="Evidence-pack JSON path.")
    parser.add_argument("--question", required=True, help="User question to place in the generated prompt.")
    parser.add_argument("--atlas-page", default="", help="Optional atlas page path or filename under <pack-root>\\reports\\atlas.")
    parser.add_argument("--prompt-out", default="", help="Optional path for the generated prompt Markdown.")
    parser.add_argument("--answer-in", default="", help="Optional answer Markdown file to validate.")
    parser.add_argument("--report-out", default="", help="Optional JSON report output path.")
    return parser


def _prompt_lines(
    pack_root: str | Path,
    evidence_path: Path,
    question: str,
    pack: dict[str, Any],
    pack_status: dict[str, Any],
    functions: list[FunctionEvidence],
    edges: list[dict[str, str]],
    gaps: list[str],
    uncertainty_notes: list[str],
    atlas: dict[str, Any],
) -> list[str]:
    manifest = pack_status.get("manifest", {}) if isinstance(pack_status.get("manifest"), dict) else {}
    status = pack.get("status", {}) if isinstance(pack.get("status"), dict) else {}
    summary = pack.get("summary", {}) if isinstance(pack.get("summary"), dict) else {}
    lines = [
        "# Kernel Corpus Evidence-Grounded Answer Prompt",
        "",
        "## Question",
        "",
        question.strip(),
        "",
        "## Corpus Identity",
        "",
        "- Pack root: `%s`" % Path(pack_root).resolve(),
        "- Evidence pack: `%s`" % evidence_path.resolve(),
        "- Evidence schema: `%s`" % pack.get("schema", ""),
        "- Topic: `%s`" % pack.get("topic", ""),
        "- Evidence created: `%s`" % pack.get("created_at", ""),
        "- Pack schema: `%s`" % pack_status.get("schema_version", status.get("schema_version", "")),
        "- Target: `%s`" % manifest.get("target_path", ""),
        "- Function count: `%s`" % (manifest.get("function_count", status.get("function_count", ""))),
        "- Skipped count: `%s`" % (manifest.get("skipped_count", status.get("skipped_count", ""))),
        "",
        "## Evidence Pack Summary",
        "",
    ]
    if summary:
        for key in sorted(summary):
            lines.append("- `%s`: `%s`" % (key, summary.get(key)))
    else:
        lines.append("- Selected functions: `%d`" % len(functions))
        lines.append("- Edge count: `%d`" % len(edges))
    lines.extend(["", "## Selected Functions", ""])
    if not functions:
        lines.append("- No selected functions are present in the evidence pack.")
    else:
        for function in functions[:MAX_FUNCTIONS_IN_PROMPT]:
            lines.extend(_function_prompt_lines(function))
        if len(functions) > MAX_FUNCTIONS_IN_PROMPT:
            lines.append("- Additional functions omitted from prompt: `%d`" % (len(functions) - MAX_FUNCTIONS_IN_PROMPT))
    lines.extend(["", "## Edges", ""])
    name_by_ea = {function.ea: function.name for function in functions}
    if not edges:
        lines.append("- No selected edges are present in the evidence pack.")
    else:
        for edge in edges[:MAX_EDGES_IN_PROMPT]:
            src = str(edge.get("src_ea", ""))
            dst = str(edge.get("dst_ea", ""))
            lines.append(
                "- `%s` `%s` -> `%s` `%s` kind=`%s`"
                % (src, name_by_ea.get(src, ""), dst, name_by_ea.get(dst, ""), edge.get("edge_kind", ""))
            )
        if len(edges) > MAX_EDGES_IN_PROMPT:
            lines.append("- Additional edges omitted from prompt: `%d`" % (len(edges) - MAX_EDGES_IN_PROMPT))
    lines.extend(["", "## Gaps And Uncertainty", ""])
    if not gaps and not uncertainty_notes:
        lines.append("- No gaps or uncertainty notes are recorded in the evidence pack.")
    for gap in gaps:
        lines.append("- Gap: %s" % gap)
    for note in uncertainty_notes:
        lines.append("- Uncertainty: %s" % note)
    if atlas.get("text"):
        lines.extend(
            [
                "",
                "## Atlas Context",
                "",
                "- Atlas page: `%s`" % atlas.get("path", ""),
                "- Atlas truncated: `%s`" % atlas.get("truncated", False),
                "",
                "```markdown",
                str(atlas.get("text", "")),
                "```",
            ]
        )
    lines.extend(
        [
            "",
            "## Answer Contract",
            "",
            "Use concise reverse-engineering prose grounded in this pack.",
            "For every major claim, preserve this chain:",
            "",
            "```text",
            "Claim -> EA -> function name -> artifact path -> inference level",
            "```",
            "",
            "Required answer shape:",
            "",
            "1. Direct answer / overall flow.",
            "2. Major functions as Markdown bullets. Each bullet must include EA, function name, role, inference level, and at least one artifact path from this prompt.",
            "3. Confirmed from this corpus.",
            "4. Inference.",
            "5. Gaps / uncertainty when this prompt lists any gaps or uncertainty notes.",
            "",
            "Do not answer from generic Windows internals alone. Do not claim a transition is proven unless the edge or function evidence above supports it.",
        ]
    )
    return lines


def _function_prompt_lines(function: FunctionEvidence) -> list[str]:
    tags = ", ".join(function.artifacts.get("tags", "").split(",")) if function.artifacts.get("tags") else ""
    lines = [
        "- `%s` `%s` phase=`%s` confidence=`%s` phase_confidence=`%s`"
        % (function.ea, function.name, function.phase, function.confidence, function.phase_confidence),
        "  - Role: %s" % (function.role or "Selected function from evidence pack."),
    ]
    if tags:
        lines.append("  - Tags: %s" % tags)
    paths = _artifact_paths(function)
    if paths:
        lines.append("  - Artifact paths:")
        for path in paths[:5]:
            lines.append("    - `%s`" % path)
    if function.why_selected:
        lines.append("  - Why selected: %s" % "; ".join(function.why_selected[:6]))
    if function.inference_notes:
        lines.append("  - Inference notes: %s" % "; ".join(function.inference_notes[:4]))
    excerpt = _best_evidence_excerpt(function)
    if excerpt:
        lines.append("  - Evidence excerpt: %s" % _single_line(excerpt, FUNCTION_EXCERPT_CHARS))
    return lines


def _collect_functions(pack: dict[str, Any]) -> list[FunctionEvidence]:
    collected: list[dict[str, Any]] = []
    if isinstance(pack.get("functions"), list):
        collected.extend(item for item in pack["functions"] if isinstance(item, dict))
    for phase in pack.get("phases", []) if isinstance(pack.get("phases"), list) else []:
        if not isinstance(phase, dict):
            continue
        for function in phase.get("functions", []) if isinstance(phase.get("functions"), list) else []:
            if not isinstance(function, dict):
                continue
            item = dict(function)
            item.setdefault("phase", str(phase.get("id", "")))
            item.setdefault("phase_title", str(phase.get("title", "")))
            collected.append(item)
    result: list[FunctionEvidence] = []
    seen: set[str] = set()
    for item in collected:
        ea = str(item.get("ea", "") or "")
        name = str(item.get("name", "") or "")
        if not ea or not name or ea in seen:
            continue
        seen.add(ea)
        artifacts = item.get("artifacts", {}) if isinstance(item.get("artifacts"), dict) else {}
        if item.get("tags") and "tags" not in artifacts:
            artifacts = dict(artifacts)
            artifacts["tags"] = ",".join(_strings(item.get("tags")))
        result.append(
            FunctionEvidence(
                ea=ea,
                name=name,
                phase=str(item.get("phase", "") or ""),
                role=str(item.get("role", "") or ""),
                confidence=str(item.get("confidence", "") if item.get("confidence", "") is not None else ""),
                phase_confidence=str(item.get("phase_confidence", "") if item.get("phase_confidence", "") is not None else ""),
                artifacts={str(key): str(value) for key, value in artifacts.items() if str(value)},
                evidence=[
                    {str(key): str(value) for key, value in evidence.items() if str(value)}
                    for evidence in (item.get("evidence", []) if isinstance(item.get("evidence"), list) else [])
                    if isinstance(evidence, dict)
                ],
                inference_notes=_strings(item.get("inference_notes")),
                why_selected=_strings(item.get("why_selected")),
            )
        )
    return result


def _edges(pack: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for edge in pack.get("edges", []) if isinstance(pack.get("edges"), list) else []:
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("src_ea", "") or "")
        dst = str(edge.get("dst_ea", "") or "")
        if not src or not dst:
            continue
        result.append(
            {
                "src_ea": src,
                "dst_ea": dst,
                "edge_kind": str(edge.get("edge_kind", "") or ""),
            }
        )
    return result


def _read_atlas_page(pack_root: str | Path, atlas_page: str | Path) -> dict[str, Any]:
    if not atlas_page:
        return {"path": "", "text": "", "truncated": False}
    candidate = Path(atlas_page)
    if not candidate.is_file():
        name = str(atlas_page)
        if not name.lower().endswith(".md"):
            name = "%s.md" % name
        candidate = Path(pack_root) / ATLAS_DIR / name
    if not candidate.is_file():
        raise QueryError("Atlas page was not found: %s" % atlas_page)
    text = candidate.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > DEFAULT_ATLAS_CHARS
    if truncated:
        text = text[:DEFAULT_ATLAS_CHARS].rstrip() + "\n[TRUNCATED: atlas page excerpt]\n"
    return {
        "path": str(candidate.resolve()),
        "text": text,
        "truncated": truncated,
    }


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise QueryError("%s is not a JSON object: %s" % (label, path))
    return data


def _best_evidence_excerpt(function: FunctionEvidence) -> str:
    for evidence in function.evidence:
        text = str(evidence.get("text", "") or "")
        if text:
            return text
    return ""


def _artifact_paths(function: FunctionEvidence) -> list[str]:
    paths = []
    for key, value in function.artifacts.items():
        if key == "directory" or key == "tags":
            continue
        if value:
            paths.append(value)
    for evidence in function.evidence:
        path = str(evidence.get("path", "") or "")
        if path:
            paths.append(path)
    return _unique_strings(paths)


def _matching_functions(line: str, functions: list[FunctionEvidence]) -> list[FunctionEvidence]:
    lowered = line.lower()
    ea_matches = [function for function in functions if function.ea and function.ea.lower() in lowered]
    if ea_matches:
        return ea_matches
    result = []
    for function in functions:
        if function.name and function.name in line:
            result.append(function)
            continue
        if function.ea and function.ea.lower() in lowered:
            result.append(function)
    return result


def _contains_ea(text: str, ea: str) -> bool:
    return ea.lower() in text.lower()


def _contains_artifact_path(text: str, paths: list[str]) -> bool:
    if not paths:
        return False
    variants = []
    for path in paths:
        variants.extend([path, path.replace("\\", "/"), path.replace("/", "\\")])
    return any(variant and variant in text for variant in variants)


def _has_gap_or_uncertainty_section(answer_text: str) -> bool:
    pattern = re.compile(
        r"(?im)^\s{0,3}(#{1,6}\s*)?(gaps?|unknowns?|uncertainty|limitations?|"
        r"제한|불확실|공백|미확인|한계)\b"
    )
    return bool(pattern.search(answer_text or ""))


def _is_bullet(line: str) -> bool:
    return bool(re.match(r"^\s*[-*]\s+", line))


def _warning(
    code: str,
    message: str,
    *,
    line: int | None = None,
    function: FunctionEvidence | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if line is not None:
        payload["line"] = line
    if function is not None:
        payload["ea"] = function.ea
        payload["name"] = function.name
    return payload


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    return []


def _single_line(text: str, limit: int) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]


def _unique_strings(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
