from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus.canonical_answers import CanonicalTopic, load_manifest, select_topics
from tools.kernel_corpus.canonical_audit import (
    AUDIT_SCHEMA_VERSION,
    EXPECTATIONS_SCHEMA_VERSION,
    audit_canonical_root,
    expectations_cover_topics,
    load_expectations,
    render_text_report,
)
from tools.kernel_corpus import canonical_answers


class KernelCorpusCanonicalAuditTests(unittest.TestCase):
    def test_default_expectations_cover_default_canonical_topics(self) -> None:
        topics = select_topics(load_manifest())
        expectations = load_expectations()

        topic_ids = [topic.topic_id for topic in topics]
        expected_topics = expectations["topics"]

        self.assertEqual(EXPECTATIONS_SCHEMA_VERSION, expectations["schema"])
        self.assertEqual(39, len(expected_topics))
        self.assertTrue(expectations_cover_topics(expectations, topic_ids))
        self.assertEqual([], sorted(set(topic_ids) - set(expected_topics)))
        self.assertEqual([], sorted(set(expected_topics) - set(topic_ids)))

    def test_audit_passes_and_writes_quality_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "canonical-answers"
            topic_dir = root / "P0" / "good_flow"
            expectation_path = Path(temp_dir) / "expectations.json"
            _write_expectations(expectation_path, "good_flow")
            _write_index(root, "good_flow", topic_dir)
            _write_topic(
                topic_dir,
                topic_id="good_flow",
                priority="P0",
                mode="lifecycle",
                functions=[
                    {"ea": "0x1", "name": "GoodCreate", "phase": "entry", "tags": ["process_thread"]},
                    {"ea": "0x2", "name": "GoodDelete", "phase": "delete", "tags": ["process_thread"]},
                ],
                edges=[{"src_ea": "0x1", "dst_ea": "0x2", "edge_kind": "callee"}],
                validation_warnings=[],
                source_hash="source-a",
                source_ref_count=1,
            )

            report_path = root / "quality-report.json"
            report = audit_canonical_root(
                root,
                expectations_path=expectation_path,
                report_out=report_path,
                write_topic_reports=True,
            )

            self.assertEqual(AUDIT_SCHEMA_VERSION, report["schema"])
            self.assertTrue(report["ok"])
            self.assertEqual(1, report["pass_count"])
            self.assertEqual("pass", report["topics"][0]["status"])
            self.assertEqual(100, report["topics"][0]["score"])
            self.assertTrue(report_path.is_file())
            self.assertTrue((root / "quality-report.md").is_file())
            self.assertTrue((topic_dir / "quality.json").is_file())
            self.assertTrue((topic_dir / "quality.md").is_file())
            self.assertIn("good_flow", render_text_report(report))

            second = audit_canonical_root(root, expectations_path=expectation_path)
            self.assertEqual(
                [(topic["priority"], topic["topic_id"], topic["status"], topic["score"]) for topic in report["topics"]],
                [(topic["priority"], topic["topic_id"], topic["status"], topic["score"]) for topic in second["topics"]],
            )

    def test_audit_detects_forbidden_suspicious_missing_phase_and_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "canonical-answers"
            topic_dir = root / "P1" / "bad_flow"
            expectation_path = Path(temp_dir) / "expectations.json"
            _write_expectations(
                expectation_path,
                "bad_flow",
                required=["^MissingRequired$"],
                forbidden=["^ForbiddenFunc$"],
                suspicious=["^\\?\\?\\$"],
                suspicious_tags=["telemetry_noise"],
                preferred_tags=["security"],
                min_selected=3,
                min_edges=2,
            )
            _write_index(root, "bad_flow", topic_dir, priority="P1", source_hash="source-a")
            _write_topic(
                topic_dir,
                topic_id="bad_flow",
                priority="P1",
                mode="lifecycle",
                functions=[
                    {"ea": "0x10", "name": "ForbiddenFunc", "phase": "entry", "tags": ["telemetry_noise"]},
                    {"ea": "0x20", "name": "??$BadTemplate", "phase": "entry", "tags": []},
                    {"ea": "0x30", "name": "VeryLong" + ("A" * 150), "phase": "entry", "tags": []},
                ],
                edges=[],
                validation_warnings=[{"code": "missing_ea", "message": "fixture warning"}],
                source_hash="source-b",
                source_ref_count=0,
                gaps=["fixture gap"],
            )

            report = audit_canonical_root(root, expectations_path=expectation_path)
            topic = report["topics"][0]

            self.assertFalse(report["ok"])
            self.assertEqual("fail", topic["status"])
            self.assertIn("^MissingRequired$", topic["missing_required_functions"])
            self.assertEqual("ForbiddenFunc", topic["forbidden_selected_functions"][0]["name"])
            self.assertEqual("??$BadTemplate", topic["suspicious_selected_functions"][0]["name"])
            self.assertTrue(any(item["pattern"].startswith("max_name_length") for item in topic["suspicious_selected_functions"]))
            self.assertEqual("telemetry_noise", topic["suspicious_tag_hits"][0]["tag"])
            self.assertEqual(["delete"], topic["missing_phases"])
            self.assertTrue(topic["weak_edge_coverage"])
            self.assertEqual(1, topic["validation_warning_count"])
            self.assertTrue(topic["source_identity_warnings"])
            self.assertGreater(len(topic["recommended_actions"]), 3)

    def test_focused_scoring_demotes_unrelated_telemetry_noise(self) -> None:
        topic = CanonicalTopic(
            topic_id="remote_process_access_flow",
            priority="P1",
            title="Remote Process Access Flow",
            question="Explain open process and memory access paths.",
            mode="focused",
            raw={
                "seed_names": ["NtOpenProcess"],
                "queries": ["open process"],
                "tags": ["process_thread", "security"],
            },
            source_refs=[],
        )
        candidates: dict[str, canonical_answers.Candidate] = {}
        canonical_answers._add_candidate(
            candidates,
            {"ea": "0x1", "name": "NtOpenProcess", "tags": ["process_thread"], "why_selected": []},
            10,
            "query: open process",
        )
        canonical_answers._add_candidate(
            candidates,
            {"ea": "0x2", "name": "EtwpTraceProcessTelemetry", "tags": ["callback"], "why_selected": []},
            35,
            "query: open process",
        )

        canonical_answers._adjust_focused_candidate_scores(candidates, topic)
        ordered = sorted(candidates.values(), key=lambda item: -item.score)

        self.assertEqual("NtOpenProcess", ordered[0].name)
        self.assertTrue(any("score exact seed-name boost" in reason for reason in candidates["0x1"].reasons))
        self.assertTrue(any("telemetry wrapper" in reason for reason in candidates["0x2"].reasons))


def _write_expectations(
    path: Path,
    topic_id: str,
    *,
    required: list[str] | None = None,
    forbidden: list[str] | None = None,
    suspicious: list[str] | None = None,
    suspicious_tags: list[str] | None = None,
    preferred_tags: list[str] | None = None,
    min_selected: int = 2,
    min_edges: int = 1,
) -> None:
    payload = {
        "schema": EXPECTATIONS_SCHEMA_VERSION,
        "defaults": {
            "max_validation_warnings": 0,
            "min_source_refs": 1,
            "pass_score": 80,
            "degraded_score": 60,
            "max_name_length": 140,
            "forbidden_name_regexes": [],
            "suspicious_name_regexes": [],
            "suspicious_tags": [],
        },
        "topics": {
            topic_id: {
                "priority": "P0",
                "mode": "lifecycle",
                "required_name_regexes": required or ["^GoodCreate$"],
                "bonus_name_regexes": ["^GoodDelete$"],
                "forbidden_name_regexes": forbidden or [],
                "suspicious_name_regexes": suspicious or [],
                "suspicious_tags": suspicious_tags or [],
                "preferred_tags": preferred_tags or ["process_thread"],
                "min_selected_functions": min_selected,
                "min_edge_count": min_edges,
                "required_lifecycle_phases": ["entry", "delete"],
            }
        },
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")


def _write_index(root: Path, topic_id: str, topic_dir: Path, *, priority: str = "P0", source_hash: str = "source-a") -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "kernel_corpus_canonical_answer_run_v1",
        "source_index_sha256": source_hash,
        "pack_generated_at": "2026-06-13T00:00:00+00:00",
        "topics": [
            {
                "id": topic_id,
                "priority": priority,
                "mode": "lifecycle",
                "directory": str(topic_dir.resolve()),
            }
        ],
    }
    (root / "index.json").write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")


def _write_topic(
    topic_dir: Path,
    *,
    topic_id: str,
    priority: str,
    mode: str,
    functions: list[dict[str, object]],
    edges: list[dict[str, str]],
    validation_warnings: list[dict[str, str]],
    source_hash: str,
    source_ref_count: int,
    gaps: list[str] | None = None,
) -> None:
    topic_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "answer": topic_dir / "answer.md",
        "evidence_pack": topic_dir / "evidence-pack.json",
        "trace": topic_dir / "trace.json",
        "prompt": topic_dir / "prompt.md",
        "validation": topic_dir / "validation.json",
        "candidate_review": topic_dir / "candidate-review.md",
        "source_map": topic_dir / "source-map.md",
        "gaps": topic_dir / "gaps.md",
    }
    phases = []
    for phase_id in ("entry", "delete"):
        phase_functions = [function for function in functions if function.get("phase") == phase_id]
        phases.append({"id": phase_id, "functions": phase_functions})
    evidence = {
        "schema": "kernel_corpus_evidence_pack_v1",
        "topic": topic_id,
        "pack_root": "fixture-pack",
        "summary": {"selected_function_count": len(functions), "edge_count": len(edges), "source_ref_count": source_ref_count},
        "phases": phases,
        "edges": edges,
        "gaps": gaps or [],
        "uncertainty_notes": [],
    }
    validation = {
        "ok": True,
        "passed": not validation_warnings,
        "warning_count": len(validation_warnings),
        "warnings": validation_warnings,
    }
    manifest = {
        "schema": "kernel_corpus_canonical_answer_artifact_v1",
        "topic": {"id": topic_id, "priority": priority, "mode": mode, "title": topic_id},
        "source_index_sha256": source_hash,
        "pack_generated_at": "2026-06-13T00:00:00+00:00",
        "files": {key: str(value.resolve()) for key, value in paths.items()},
    }
    paths["answer"].write_text("# fixture\n", encoding="utf-8")
    paths["evidence_pack"].write_text(json.dumps(evidence, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    paths["trace"].write_text(json.dumps({"selected_candidates": functions}, indent=2, ensure_ascii=True), encoding="utf-8")
    paths["prompt"].write_text("fixture prompt\n", encoding="utf-8")
    paths["validation"].write_text(json.dumps(validation, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
    paths["candidate_review"].write_text("- candidate review fixture\n", encoding="utf-8")
    paths["source_map"].write_text("## Public Contract References\n\n- [Fixture](https://example.invalid): fixture\n", encoding="utf-8")
    paths["gaps"].write_text("\n".join("- Gap: %s" % item for item in (gaps or [])), encoding="utf-8")
    (topic_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
