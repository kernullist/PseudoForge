from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.kernel_corpus import builder
from tools.kernel_corpus.canonical_compare import (
    CANONICAL_DRIFT_SCHEMA_VERSION,
    _has_evidence_changes,
    compare_canonical_answers,
    render_markdown_report,
    write_report,
)
from tools.kernel_corpus.errors import QueryError
from tools.kernel_corpus.mcp_server import KernelCorpusMcpServer


class KernelCorpusCanonicalCompareTests(unittest.TestCase):
    def test_topic_compare_reports_ea_quality_function_phase_and_edge_drift(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            payload = compare_canonical_answers(
                pack_a,
                pack_b,
                topic_id="process_object_lifecycle",
                label_a="old",
                label_b="new",
            )

            self.assertEqual(CANONICAL_DRIFT_SCHEMA_VERSION, payload["schema"])
            self.assertEqual(1, payload["returned_count"])
            topic = payload["topics"][0]
            self.assertEqual("process_object_lifecycle", topic["topic_id"])
            self.assertEqual("both", topic["presence"])
            self.assertTrue(topic["changed"])
            self.assertEqual("degraded", topic["catalog_changes"]["quality_status"]["a"])
            self.assertEqual("pass", topic["catalog_changes"]["quality_status"]["b"])
            self.assertEqual(22, topic["catalog_changes"]["score"]["delta"])
            self.assertEqual(-2, topic["catalog_changes"]["validation_warning_count"]["delta"])
            self.assertEqual(-1, topic["catalog_changes"]["gap_count"]["delta"])

            evidence = topic["evidence_changes"]
            ea_drift = {item["name"]: item for item in evidence["same_name_different_ea"]}
            self.assertEqual(["0x140001000"], ea_drift["NtCreateUserProcess"]["a_eas"])
            self.assertEqual(["0x150001000"], ea_drift["NtCreateUserProcess"]["b_eas"])
            self.assertIn("EA differs", ea_drift["NtCreateUserProcess"]["note"])
            self.assertIn("PsSetCreateProcessNotifyRoutine", [item["name"] for item in evidence["functions_added"]])
            self.assertIn("PspProcessDelete", [item["name"] for item in evidence["functions_removed"]])
            phase_drift = {item["name"]: item for item in evidence["phase_assignment_changes"]}
            self.assertEqual(["allocate"], phase_drift["PspAllocateProcess"]["a_phases"])
            self.assertEqual(["initialize"], phase_drift["PspAllocateProcess"]["b_phases"])
            self.assertIn(
                ("NtCreateUserProcess", "PsSetCreateProcessNotifyRoutine"),
                {(item["src_name"], item["dst_name"]) for item in evidence["call_edges_added"]},
            )
            self.assertIn(
                ("PspAllocateProcess", "PspProcessDelete"),
                {(item["src_name"], item["dst_name"]) for item in evidence["call_edges_removed"]},
            )
            self.assertTrue(evidence["artifact_path_pairs"])

    def test_catalog_reports_missing_topic_and_metadata_changes_in_stable_order(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            payload = compare_canonical_answers(pack_a, pack_b, max_topics=10)

            self.assertEqual(
                ["process_object_lifecycle", "new_topic", "process_identity_lookup", "obsolete_topic"],
                [topic["topic_id"] for topic in payload["topics"]],
            )
            self.assertIn("new_topic", payload["catalog_summary"]["missing_in_a"])
            self.assertIn("obsolete_topic", payload["catalog_summary"]["missing_in_b"])
            identity_topic = next(topic for topic in payload["topics"] if topic["topic_id"] == "process_identity_lookup")
            self.assertEqual("P1", identity_topic["catalog_changes"]["priority"]["a"])
            self.assertEqual("P2", identity_topic["catalog_changes"]["priority"]["b"])
            self.assertEqual("Process Identity Lookup", identity_topic["catalog_changes"]["title"]["a"])
            self.assertEqual("Process ID Lookup", identity_topic["catalog_changes"]["title"]["b"])

    def test_same_pack_compare_keeps_artifact_pairs_from_becoming_drift(self) -> None:
        with _built_drift_packs() as (pack_a, _pack_b):
            payload = compare_canonical_answers(pack_a, pack_a, topic_id="process_object_lifecycle")

            topic = payload["topics"][0]
            self.assertFalse(topic["changed"])
            self.assertTrue(topic["evidence_changes"]["artifact_path_pairs"])
            self.assertFalse(any(item["changed"] for item in topic["evidence_changes"]["artifact_path_pairs"]))

    def test_artifact_pair_truncation_is_not_drift_by_itself(self) -> None:
        self.assertFalse(
            _has_evidence_changes(
                {
                    "same_name_different_ea": [],
                    "functions_added": [],
                    "functions_removed": [],
                    "phase_assignment_changes": [],
                    "call_edges_added": [],
                    "call_edges_removed": [],
                    "artifact_path_pairs": [{"name": "A", "changed": False}],
                    "artifact_path_pairs_truncated": True,
                }
            )
        )

    def test_filters_bounded_output_and_topic_path_validation(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            payload = compare_canonical_answers(pack_a, pack_b, priority="P1", max_topics=1)

            self.assertEqual(2, payload["topic_count"])
            self.assertEqual(1, payload["returned_count"])
            self.assertTrue(payload["topics_truncated"])
            self.assertEqual("new_topic", payload["topics"][0]["topic_id"])
            with self.assertRaises(QueryError):
                compare_canonical_answers(pack_a, pack_b, topic_id="..\\manifest")

    def test_report_out_rejects_pack_mutation_and_parent_traversal(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            payload = compare_canonical_answers(pack_a, pack_b, topic_id="process_object_lifecycle")
            with tempfile.TemporaryDirectory() as report_dir:
                out_path = Path(report_dir) / "drift.md"

                written = write_report(payload, out_path, requested_format="markdown")

                self.assertEqual(str(out_path.resolve()), written)
                self.assertIn("# Kernel Canonical Drift Report", out_path.read_text(encoding="utf-8"))
            with self.assertRaises(QueryError):
                write_report(payload, pack_a / "drift.md", requested_format="markdown")
            with self.assertRaises(QueryError):
                write_report(payload, Path("..") / "drift.md", requested_format="markdown")

    def test_markdown_rendering_is_bounded(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            payload = compare_canonical_answers(pack_a, pack_b, max_topics=10)

            markdown = render_markdown_report(payload, max_chars=300)

            self.assertLessEqual(len(markdown), 300)
            self.assertIn("[truncated]", markdown)

    def test_missing_quality_report_is_visible(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            (pack_b / "canonical-answers" / "quality-report.json").unlink()

            payload = compare_canonical_answers(pack_a, pack_b, topic_id="process_object_lifecycle")

            self.assertTrue(any("quality-report.json is missing" in warning for warning in payload["warnings"]))

    def test_mcp_compare_tools_return_compact_drift_payloads(self) -> None:
        with _built_drift_packs() as (pack_a, pack_b):
            server = KernelCorpusMcpServer(pack_a)

            compare_payload = server.call_tool(
                "compare_canonical_answers",
                {
                    "pack_root_a": str(pack_a),
                    "pack_root_b": str(pack_b),
                    "topic_id": "process_object_lifecycle",
                },
            )
            report_payload = server.call_tool(
                "get_canonical_drift_report",
                {
                    "pack_root_a": str(pack_a),
                    "pack_root_b": str(pack_b),
                    "topic_id": "process_object_lifecycle",
                    "max_chars": 500,
                },
            )

            self.assertTrue(compare_payload["ok"])
            self.assertEqual(CANONICAL_DRIFT_SCHEMA_VERSION, compare_payload["schema_version"])
            self.assertEqual("process_object_lifecycle", compare_payload["topics"][0]["topic_id"])
            self.assertIn("same_name_different_ea", compare_payload["topics"][0]["evidence_changes"])
            self.assertTrue(report_payload["ok"])
            self.assertIn("Kernel Canonical Drift Report", report_payload["markdown"])
            self.assertLessEqual(len(report_payload["markdown"]), 500)


@contextlib.contextmanager
def _built_drift_packs():
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        corpus_a = root / "corpus-a"
        corpus_b = root / "corpus-b"
        pack_a = root / "pack-a"
        pack_b = root / "pack-b"
        _write_corpus(
            corpus_a,
            "ntoskrnl-old.i64",
            [
                _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create"], ["0x140002000"]),
                _function("0x140002000", "PspAllocateProcess", ["process_thread"], ["allocate"], ["0x140003000"]),
                _function("0x140003000", "PspProcessDelete", ["process_thread"], ["delete"], []),
                _function("0x140004000", "PsLookupProcessByProcessId", ["process_thread"], ["identity"], []),
                _function("0x140005000", "ObsoleteEvidence", ["legacy"], ["obsolete"], []),
            ],
        )
        _write_corpus(
            corpus_b,
            "ntoskrnl-new.i64",
            [
                _function("0x150001000", "NtCreateUserProcess", ["process_thread"], ["create"], ["0x150002000", "0x150003000"]),
                _function("0x150002000", "PspAllocateProcess", ["process_thread"], ["initialize"], []),
                _function("0x150003000", "PsSetCreateProcessNotifyRoutine", ["process_thread"], ["callback"], []),
                _function("0x150004000", "PsLookupProcessByProcessId", ["process_thread"], ["identity"], []),
                _function("0x150005000", "NewEvidence", ["new"], ["new"], []),
            ],
        )
        builder.build_pack(corpus_a, pack_a)
        builder.build_pack(corpus_b, pack_b)
        _write_canonical_fixture(
            pack_a,
            [
                _topic_spec(
                    "process_object_lifecycle",
                    "P0",
                    "lifecycle",
                    "Process Object Lifecycle",
                    "degraded",
                    70,
                    2,
                    2,
                    [
                        _selected("0x140001000", "NtCreateUserProcess", "entry"),
                        _selected("0x140002000", "PspAllocateProcess", "allocate"),
                        _selected("0x140003000", "PspProcessDelete", "teardown"),
                    ],
                    [
                        ("NtCreateUserProcess", "PspAllocateProcess"),
                        ("PspAllocateProcess", "PspProcessDelete"),
                    ],
                ),
                _topic_spec(
                    "process_identity_lookup",
                    "P1",
                    "focused",
                    "Process Identity Lookup",
                    "pass",
                    88,
                    0,
                    0,
                    [_selected("0x140004000", "PsLookupProcessByProcessId", "focused")],
                    [],
                ),
                _topic_spec(
                    "obsolete_topic",
                    "P2",
                    "focused",
                    "Obsolete Topic",
                    "pass",
                    60,
                    0,
                    0,
                    [_selected("0x140005000", "ObsoleteEvidence", "focused")],
                    [],
                ),
            ],
        )
        _write_canonical_fixture(
            pack_b,
            [
                _topic_spec(
                    "process_object_lifecycle",
                    "P0",
                    "lifecycle",
                    "Process Object Lifecycle",
                    "pass",
                    92,
                    0,
                    1,
                    [
                        _selected("0x150001000", "NtCreateUserProcess", "entry"),
                        _selected("0x150002000", "PspAllocateProcess", "initialize"),
                        _selected("0x150003000", "PsSetCreateProcessNotifyRoutine", "callback"),
                    ],
                    [
                        ("NtCreateUserProcess", "PspAllocateProcess"),
                        ("NtCreateUserProcess", "PsSetCreateProcessNotifyRoutine"),
                    ],
                ),
                _topic_spec(
                    "new_topic",
                    "P1",
                    "focused",
                    "New Topic",
                    "pass",
                    80,
                    0,
                    0,
                    [_selected("0x150005000", "NewEvidence", "focused")],
                    [],
                ),
                _topic_spec(
                    "process_identity_lookup",
                    "P2",
                    "focused",
                    "Process ID Lookup",
                    "pass",
                    86,
                    0,
                    0,
                    [_selected("0x150004000", "PsLookupProcessByProcessId", "focused")],
                    [],
                ),
            ],
        )
        yield pack_a, pack_b


def _write_corpus(corpus_root: Path, target_path: str, functions: list[dict[str, Any]]) -> None:
    (corpus_root / "functions").mkdir(parents=True)
    index = {
        "schema": "pseudoforge_corpus_index_v1",
        "pseudoforge_version": "test",
        "generated_at": "2026-06-13T00:00:00+00:00",
        "functions": [],
        "overview": {"functions": len(functions), "report_status_counts": {"ok": len(functions)}},
        "metadata": {"target_path": target_path},
        "report_summary": {"status_counts": {"ok": len(functions)}},
    }
    for function in functions:
        stem = "%016x_%s" % (int(function["ea"], 0), function["name"])
        function_dir = corpus_root / "functions" / stem
        function_dir.mkdir(parents=True)
        cleaned = function_dir / "function.cleaned.cpp"
        raw = function_dir / "function.raw.cpp"
        summary = function_dir / "function.ida-batch-summary.json"
        cleaned.write_text("%s cleaned evidence" % function["name"], encoding="utf-8")
        raw.write_text("%s raw evidence" % function["name"], encoding="utf-8")
        summary.write_text(json.dumps({"ea": function["ea"], "name": function["name"]}, ensure_ascii=True), encoding="utf-8")
        item = dict(function)
        item["directory"] = str(Path("functions") / stem)
        item["summary_path"] = str(Path("functions") / stem / "function.ida-batch-summary.json")
        item["artifacts"] = {
            "cleaned_pseudocode": str(Path("functions") / stem / "function.cleaned.cpp"),
            "raw_pseudocode": str(Path("functions") / stem / "function.raw.cpp"),
            "summary": str(Path("functions") / stem / "function.ida-batch-summary.json"),
        }
        index["functions"].append(item)
    (corpus_root / "pseudoforge-corpus-index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )


def _write_canonical_fixture(pack_root: Path, specs: list[dict[str, Any]]) -> None:
    root = pack_root / "canonical-answers"
    manifest = json.loads((pack_root / "manifest.json").read_text(encoding="utf-8"))
    index_topics = []
    report_topics = []
    for spec in specs:
        topic_dir = root / spec["priority"] / spec["topic_id"]
        _write_canonical_topic(topic_dir, spec, manifest)
        index_topics.append(
            {
                "id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str(topic_dir.resolve()),
            }
        )
        report_topics.append(_quality_payload(spec, topic_dir))
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_run_v1",
                "source_index_sha256": manifest["source_index_sha256"],
                "pack_generated_at": manifest["generated_at"],
                "topics": index_topics,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (root / "quality-report.json").write_text(
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
    (root / "quality-report.md").write_text("# Canonical Quality Report\n", encoding="utf-8")


def _write_canonical_topic(topic_dir: Path, spec: dict[str, Any], pack_manifest: dict[str, Any]) -> None:
    topic_dir.mkdir(parents=True, exist_ok=True)
    name_to_ea = {function["name"]: function["ea"] for function in spec["functions"]}
    edges = [
        {
            "src_ea": name_to_ea[src],
            "dst_ea": name_to_ea[dst],
            "edge_kind": "callee",
        }
        for src, dst in spec["edges"]
    ]
    for function in spec["functions"]:
        function["artifacts"] = {
            "summary": str((topic_dir / ("%s-summary.json" % function["name"])).resolve()),
            "cleaned_pseudocode": str((topic_dir / ("%s.cleaned.cpp" % function["name"])).resolve()),
        }
    (topic_dir / "answer.md").write_text("# %s\n\nfixture answer\n" % spec["title"], encoding="utf-8")
    (topic_dir / "quality.md").write_text("# Quality\n\nstatus=%s\n" % spec["status"], encoding="utf-8")
    (topic_dir / "gaps.md").write_text("- fixture gap\n", encoding="utf-8")
    (topic_dir / "source-map.md").write_text("- fixture source\n", encoding="utf-8")
    (topic_dir / "evidence-pack.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_evidence_pack_v1",
                "topic": spec["topic_id"],
                "summary": {
                    "selected_function_count": len(spec["functions"]),
                    "edge_count": len(edges),
                },
                "functions": spec["functions"],
                "edges": edges,
                "gaps": ["fixture gap"] * int(spec["gap_count"]),
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "trace.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_trace_v1",
                "selected_candidates": spec["functions"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "validation.json").write_text(
        json.dumps(
            {
                "passed": spec["status"] == "pass",
                "warning_count": spec["warnings"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (topic_dir / "quality.json").write_text(
        json.dumps(_quality_payload(spec, topic_dir), indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )
    (topic_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_artifact_v1",
                "topic": {
                    "id": spec["topic_id"],
                    "priority": spec["priority"],
                    "title": spec["title"],
                    "mode": spec["mode"],
                    "question": "Explain %s." % spec["title"],
                },
                "source_index_sha256": pack_manifest["source_index_sha256"],
                "pack_generated_at": pack_manifest["generated_at"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _function(ea: str, name: str, tags: list[str], terms: list[str], callees: list[str]) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "tags": tags,
        "terms": terms,
        "mode": "synthetic",
        "counts": {"warnings": 0, "buffer_contracts": 0},
        "llm_status": "ok",
        "callee_eas": callees,
        "caller_eas": [],
        "imports_called": [],
        "strings_referenced": [],
        "interesting_lines": terms,
        "cleaned_excerpt": "%s synthetic evidence: %s" % (name, " ".join(terms)),
    }


def _topic_spec(
    topic_id: str,
    priority: str,
    mode: str,
    title: str,
    status: str,
    score: int,
    warnings: int,
    gap_count: int,
    functions: list[dict[str, Any]],
    edges: list[tuple[str, str]],
) -> dict[str, Any]:
    return {
        "topic_id": topic_id,
        "priority": priority,
        "mode": mode,
        "title": title,
        "status": status,
        "score": score,
        "warnings": warnings,
        "gap_count": gap_count,
        "functions": functions,
        "edges": edges,
    }


def _selected(ea: str, name: str, phase: str) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "phase": phase,
        "role": "%s role" % phase,
        "tags": ["process_thread"],
    }


def _quality_payload(spec: dict[str, Any], topic_dir: Path) -> dict[str, Any]:
    return {
        "topic_id": spec["topic_id"],
        "priority": spec["priority"],
        "mode": spec["mode"],
        "directory": str(topic_dir.resolve()),
        "status": spec["status"],
        "score": spec["score"],
        "selected_function_count": len(spec["functions"]),
        "edge_count": len(spec["edges"]),
        "validation_warning_count": spec["warnings"],
        "gap_count": spec["gap_count"],
    }


if __name__ == "__main__":
    unittest.main()
