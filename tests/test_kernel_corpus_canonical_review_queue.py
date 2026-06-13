from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus.canonical_review_queue import (
    REVIEW_QUEUE_SCHEMA_VERSION,
    build_review_queue,
    render_markdown_report,
    write_review_queue_reports,
)
from tools.kernel_corpus.errors import QueryError


class CanonicalReviewQueueTests(unittest.TestCase):
    def test_review_queue_sorts_statuses_and_keeps_missing_quality_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            canonical_root = _write_review_fixture(pack_root)

            payload = build_review_queue(pack_root, max_topics=10)

            self.assertEqual(REVIEW_QUEUE_SCHEMA_VERSION, payload["schema"])
            self.assertTrue(payload["ok"])
            self.assertEqual(7, payload["topic_count"])
            self.assertEqual(
                [
                    "p0_fail_heavy",
                    "p0_fail",
                    "p0_fail_clean",
                    "p0_degraded",
                    "p0_missing",
                    "p0_pass",
                    "p1_fail",
                ],
                [topic["topic_id"] for topic in payload["topics"]],
            )
            self.assertEqual(4, payload["counts"]["fail"])
            self.assertEqual(1, payload["counts"]["degraded"])
            self.assertEqual(1, payload["counts"]["missing"])
            self.assertEqual(1, payload["counts"]["pass"])
            missing = _topic(payload, "p0_missing")
            self.assertEqual("missing", missing["quality_status"])
            self.assertEqual("missing", missing["quality_source"])
            self.assertEqual("run_canonical_audit", missing["suggested_review_action"])
            passing = _topic(payload, "p0_pass")
            self.assertEqual("human_review_before_promotion", passing["suggested_review_action"])
            self.assertTrue(Path(passing["artifact_paths"]["answer"]).is_absolute())
            self.assertTrue(Path(payload["source_identity"]["pack_manifest_path"]).is_absolute())
            self.assertEqual("NtCreateUserProcess", passing["selected_major_functions"][0]["name"])
            self.assertEqual(str(canonical_root.resolve()), payload["canonical_root"])

    def test_decision_file_merge_is_deterministic_and_stale_approval_is_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            canonical_root = _write_review_fixture(pack_root)
            decision_file = canonical_root / "review-decisions.json"
            decision_file.write_text(
                json.dumps(
                    {
                        "schema": "kernel_corpus_canonical_review_decisions_v1",
                        "decisions": [
                            {
                                "topic_id": "p0_pass",
                                "decision": "needs_review",
                                "reviewer": "analyst",
                                "reviewed_at": "2026-06-12T00:00:00Z",
                                "source_index_sha256": "fixture-source",
                                "notes": "older decision",
                            },
                            {
                                "topic_id": "p0_pass",
                                "decision": "approved",
                                "reviewer": "analyst",
                                "reviewed_at": "2026-06-13T00:00:00Z",
                                "source_index_sha256": "fixture-source",
                                "notes": "current approval",
                            },
                            {
                                "topic_id": "p0_degraded",
                                "decision": "approved",
                                "reviewer": "analyst",
                                "reviewed_at": "2026-06-13T00:00:00Z",
                                "source_index_sha256": "old-source",
                                "notes": "stale approval",
                            },
                            {
                                "topic_id": "..\\escape",
                                "decision": "approved",
                                "reviewer": "ignored",
                                "reviewed_at": "2026-06-13T00:00:00Z",
                                "source_index_sha256": "fixture-source",
                            },
                            {
                                "topic_id": "p0_fail",
                                "decision": "maybe",
                                "reviewer": "ignored",
                                "reviewed_at": "2026-06-13T00:00:00Z",
                                "source_index_sha256": "fixture-source",
                            },
                        ],
                    },
                    indent=2,
                    ensure_ascii=True,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            payload = build_review_queue(pack_root, decision_file=decision_file)

            self.assertEqual(3, payload["decision_file"]["loaded_count"])
            self.assertEqual(2, payload["decision_file"]["effective_count"])
            passing = _topic(payload, "p0_pass")
            self.assertEqual("approved", passing["review_state"])
            self.assertEqual("ready_for_agent_preference", passing["suggested_review_action"])
            self.assertEqual("approved", passing["review_decision"]["decision"])
            degraded = _topic(payload, "p0_degraded")
            self.assertEqual("stale_approved", degraded["review_state"])
            self.assertTrue(degraded["review_decision"]["stale"])
            self.assertIn("decision_source_hash_mismatch", degraded["review_decision"]["stale_reasons"])
            self.assertEqual("re_review_source_changed", degraded["suggested_review_action"])
            self.assertEqual(1, payload["counts"]["approved"])
            self.assertEqual(1, payload["counts"]["stale_decision"])
            self.assertTrue(any("invalid topic id" in warning for warning in payload["warnings"]))
            self.assertTrue(any("invalid decision" in warning for warning in payload["warnings"]))

    def test_markdown_and_report_writes_group_topics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            canonical_root = _write_review_fixture(pack_root)
            (canonical_root / "review-decisions.json").write_text(
                json.dumps(
                    {
                        "schema": "kernel_corpus_canonical_review_decisions_v1",
                        "decisions": [
                            {
                                "topic_id": "p0_pass",
                                "decision": "approved",
                                "reviewer": "analyst",
                                "reviewed_at": "2026-06-13T00:00:00Z",
                                "source_index_sha256": "fixture-source",
                                "notes": "approved",
                            }
                        ],
                    },
                    indent=2,
                    ensure_ascii=True,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            payload = build_review_queue(pack_root)
            markdown = render_markdown_report(payload)

            self.assertIn("## Failing Topics", markdown)
            self.assertIn("## Degraded Topics", markdown)
            self.assertIn("## Missing Quality Topics", markdown)
            self.assertIn("## Passing But Unreviewed Topics", markdown)
            self.assertIn("## Approved Topics", markdown)
            self.assertIn("p0_pass", markdown)
            paths = write_review_queue_reports(payload, canonical_root / "review-queue.md")
            self.assertTrue(Path(paths["json"]).is_file())
            self.assertTrue(Path(paths["markdown"]).is_file())
            written = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            self.assertEqual(REVIEW_QUEUE_SCHEMA_VERSION, written["schema"])

    def test_external_paths_are_rejected_and_index_escape_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pack_root = root / "pack"
            canonical_root = _write_review_fixture(pack_root)
            outside_topic = root / "outside_topic"
            _write_topic(outside_topic, _topic_spec("outside_topic", "P0", "pass", 99, ["OutsideFunction"]))
            index_path = canonical_root / "index.json"
            index_payload = json.loads(index_path.read_text(encoding="utf-8"))
            index_payload["topics"].append(
                {
                    "id": "outside_topic",
                    "priority": "P0",
                    "directory": str(outside_topic.resolve()),
                }
            )
            index_path.write_text(json.dumps(index_payload, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")

            payload = build_review_queue(pack_root)

            self.assertNotIn("outside_topic", [topic["topic_id"] for topic in payload["topics"]])
            self.assertTrue(any("outside root" in warning for warning in payload["warnings"]))
            with self.assertRaises(QueryError):
                build_review_queue(pack_root, canonical_root=root / "external_canonical")
            with self.assertRaises(QueryError):
                build_review_queue(pack_root, decision_file=root / "external-decisions.json")
            with self.assertRaises(QueryError):
                write_review_queue_reports(payload, root / "external-review.md")


def _topic(payload: dict[str, object], topic_id: str) -> dict[str, object]:
    for item in payload["topics"]:
        if item["topic_id"] == topic_id:
            return item
    raise AssertionError("missing topic %s" % topic_id)


def _write_review_fixture(pack_root: Path) -> Path:
    canonical_root = pack_root / "canonical-answers"
    pack_root.mkdir(parents=True, exist_ok=True)
    (pack_root / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_manifest_v1",
                "target_path": "D:\\bin\\fixture\\ntoskrnl.exe.i64",
                "source_corpus_root": "F:\\fixture\\corpus",
                "source_index_sha256": "fixture-source",
                "generated_at": "2026-06-13T00:00:00+00:00",
                "function_count": 10,
                "skipped_count": 0,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    specs = [
        _topic_spec("p0_pass", "P0", "pass", 95, ["NtCreateUserProcess"]),
        _topic_spec("p0_degraded", "P0", "degraded", 70, ["NtOpenProcess"]),
        _topic_spec("p0_fail_heavy", "P0", "fail", 55, ["EtwTraceProcess"], warnings=2),
        _topic_spec("p0_fail", "P0", "fail", 35, ["EtwWrite"], warnings=1),
        _topic_spec("p0_fail_clean", "P0", "fail", 10, ["EtwCleanFailure"]),
        _topic_spec("p0_missing", "P0", "missing", None, ["MissingQualityFunction"], write_quality=False),
        _topic_spec("p1_fail", "P1", "fail", 20, ["IoCancelIrp"], warnings=2),
    ]
    index_topics = []
    report_topics = []
    for spec in specs:
        topic_dir = canonical_root / spec["priority"] / spec["topic_id"]
        _write_topic(topic_dir, spec)
        index_topics.append(
            {
                "id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str(topic_dir.resolve()),
            }
        )
        if spec["write_quality"]:
            report_topics.append(
                {
                    "topic_id": spec["topic_id"],
                    "priority": spec["priority"],
                    "mode": spec["mode"],
                    "directory": str(topic_dir.resolve()),
                    "status": spec["status"],
                    "score": spec["score"],
                    "selected_function_count": len(spec["functions"]),
                    "edge_count": max(0, len(spec["functions"]) - 1),
                    "validation_warning_count": spec["warnings"],
                    "gap_count": 1,
                }
            )
    canonical_root.mkdir(parents=True, exist_ok=True)
    (canonical_root / "index.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_run_v1",
                "pack_root": str(pack_root.resolve()),
                "target_path": "D:\\bin\\fixture\\ntoskrnl.exe.i64",
                "source_index_sha256": "fixture-source",
                "pack_generated_at": "2026-06-13T00:00:00+00:00",
                "topics": list(reversed(index_topics)),
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (canonical_root / "quality-report.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_quality_report_v1",
                "topics": report_topics,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return canonical_root


def _topic_spec(
    topic_id: str,
    priority: str,
    status: str,
    score: int | None,
    functions: list[str],
    *,
    warnings: int = 0,
    write_quality: bool = True,
) -> dict[str, object]:
    return {
        "topic_id": topic_id,
        "priority": priority,
        "mode": "focused",
        "title": topic_id.replace("_", " ").title(),
        "question": "Explain %s." % topic_id,
        "status": status,
        "score": score,
        "warnings": warnings,
        "functions": functions,
        "write_quality": write_quality,
    }


def _write_topic(topic_dir: Path, spec: dict[str, object]) -> None:
    topic_dir.mkdir(parents=True, exist_ok=True)
    topic_id = str(spec["topic_id"])
    functions = [
        {
            "ea": "0x%X" % (0x140000000 + (index * 0x1000)),
            "name": name,
            "artifact_paths": {"cleaned": str((topic_dir / "answer.md").resolve())},
        }
        for index, name in enumerate(spec["functions"], start=1)
    ]
    (topic_dir / "answer.md").write_text("# %s\n\nfixture answer\n" % spec["title"], encoding="utf-8")
    (topic_dir / "candidate-review.md").write_text("- review\n", encoding="utf-8")
    (topic_dir / "gaps.md").write_text("- fixture gap\n", encoding="utf-8")
    (topic_dir / "source-map.md").write_text("- source\n", encoding="utf-8")
    (topic_dir / "evidence-pack.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_evidence_pack_v1",
                "topic": topic_id,
                "summary": {
                    "selected_function_count": len(functions),
                    "edge_count": max(0, len(functions) - 1),
                },
                "functions": functions,
                "gaps": ["fixture gap"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "trace.json").write_text(
        json.dumps({"schema": "kernel_corpus_canonical_trace_v1", "selected_candidates": functions}, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    (topic_dir / "validation.json").write_text(
        json.dumps(
            {
                "passed": int(spec["warnings"]) == 0,
                "warning_count": spec["warnings"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    if spec.get("write_quality", True):
        (topic_dir / "quality.md").write_text("# Quality\n\nstatus=%s\n" % spec["status"], encoding="utf-8")
        (topic_dir / "quality.json").write_text(
            json.dumps(
                {
                    "topic_id": topic_id,
                    "priority": spec["priority"],
                    "mode": spec["mode"],
                    "status": spec["status"],
                    "score": spec["score"],
                    "selected_function_count": len(functions),
                    "edge_count": max(0, len(functions) - 1),
                    "validation_warning_count": spec["warnings"],
                    "gap_count": 1,
                },
                indent=2,
                ensure_ascii=True,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    (topic_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_artifact_v1",
                "topic": {
                    "id": topic_id,
                    "priority": spec["priority"],
                    "title": spec["title"],
                    "mode": spec["mode"],
                    "question": spec["question"],
                },
                "source_index_sha256": "fixture-source",
                "pack_generated_at": "2026-06-13T00:00:00+00:00",
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
