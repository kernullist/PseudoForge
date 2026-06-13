from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.mcp_server import (
    DEFAULT_ANSWER_PLAN_MAX_TOPICS,
    DEFAULT_ATLAS_LIMIT,
    DEFAULT_CANONICAL_DRIFT_MAX_TOPICS,
    DEFAULT_CANONICAL_DRIFT_REPORT_CHARS,
    DEFAULT_CANONICAL_MAX_TOPICS,
    DEFAULT_CANONICAL_TEXT_CHARS,
    DEFAULT_LIMIT,
    DEFAULT_LIFECYCLE_DEPTH,
    DEFAULT_LIFECYCLE_MAX_SEEDS,
    DEFAULT_NEIGHBOR_DEPTH,
    DEFAULT_PAGE_CHARS,
    MAX_ANSWER_PLAN_TOPICS,
    MAX_ATLAS_LIMIT,
    MAX_CANONICAL_DRIFT_REPORT_CHARS,
    MAX_CANONICAL_DRIFT_TOPICS,
    MAX_CANONICAL_TEXT_CHARS,
    MAX_CANONICAL_TOPICS,
    MAX_LIMIT,
    MAX_LIFECYCLE_DEPTH,
    MAX_LIFECYCLE_MAX_SEEDS,
    MAX_NEIGHBOR_DEPTH,
    MAX_PAGE_CHARS,
    KernelCorpusMcpServer,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"
EXPECTED_TOOLS = {
    "corpus_status",
    "search_functions",
    "get_function",
    "get_neighbors",
    "search_by_import",
    "search_by_string",
    "trace_lifecycle",
    "build_evidence_pack",
    "generate_atlas",
    "list_atlas_pages",
    "get_atlas_page",
    "list_canonical_answers",
    "get_canonical_answer",
    "get_canonical_quality_report",
    "find_canonical_answers",
    "plan_kernel_answer",
    "compare_canonical_answers",
    "get_canonical_drift_report",
}


class KernelCorpusMcpContractTests(unittest.TestCase):
    def test_list_tools_exposes_expected_schemas_and_defaults(self) -> None:
        with _built_pack() as pack_root:
            server = KernelCorpusMcpServer(pack_root)
            tools = {item["name"]: item for item in server.list_tools()}

            self.assertEqual(EXPECTED_TOOLS, set(tools))
            search_limit = tools["search_functions"]["inputSchema"]["properties"]["limit"]
            neighbor_depth = tools["get_neighbors"]["inputSchema"]["properties"]["depth"]
            neighbor_limit = tools["get_neighbors"]["inputSchema"]["properties"]["limit"]
            lifecycle_max_seeds = tools["trace_lifecycle"]["inputSchema"]["properties"]["max_seeds"]
            lifecycle_depth = tools["trace_lifecycle"]["inputSchema"]["properties"]["depth"]
            atlas_limit = tools["generate_atlas"]["inputSchema"]["properties"]["limit"]
            atlas_page_chars = tools["get_atlas_page"]["inputSchema"]["properties"]["max_chars"]
            canonical_max_topics = tools["list_canonical_answers"]["inputSchema"]["properties"]["max_topics"]
            canonical_get_chars = tools["get_canonical_answer"]["inputSchema"]["properties"]["max_chars"]
            canonical_report_chars = tools["get_canonical_quality_report"]["inputSchema"]["properties"]["max_chars"]
            answer_plan_max_topics = tools["plan_kernel_answer"]["inputSchema"]["properties"]["max_topics"]
            drift_max_topics = tools["compare_canonical_answers"]["inputSchema"]["properties"]["max_topics"]
            drift_report_chars = tools["get_canonical_drift_report"]["inputSchema"]["properties"]["max_chars"]
            self.assertEqual(DEFAULT_LIMIT, search_limit["default"])
            self.assertEqual(MAX_LIMIT, search_limit["maximum"])
            self.assertEqual(DEFAULT_NEIGHBOR_DEPTH, neighbor_depth["default"])
            self.assertEqual(MAX_NEIGHBOR_DEPTH, neighbor_depth["maximum"])
            self.assertEqual(MAX_LIMIT, neighbor_limit["maximum"])
            self.assertEqual(DEFAULT_LIFECYCLE_MAX_SEEDS, lifecycle_max_seeds["default"])
            self.assertEqual(MAX_LIFECYCLE_MAX_SEEDS, lifecycle_max_seeds["maximum"])
            self.assertEqual(DEFAULT_LIFECYCLE_DEPTH, lifecycle_depth["default"])
            self.assertEqual(MAX_LIFECYCLE_DEPTH, lifecycle_depth["maximum"])
            self.assertEqual(DEFAULT_ATLAS_LIMIT, atlas_limit["default"])
            self.assertEqual(MAX_ATLAS_LIMIT, atlas_limit["maximum"])
            self.assertEqual(DEFAULT_PAGE_CHARS, atlas_page_chars["default"])
            self.assertEqual(MAX_PAGE_CHARS, atlas_page_chars["maximum"])
            self.assertEqual(DEFAULT_CANONICAL_MAX_TOPICS, canonical_max_topics["default"])
            self.assertEqual(MAX_CANONICAL_TOPICS, canonical_max_topics["maximum"])
            self.assertEqual(DEFAULT_CANONICAL_TEXT_CHARS, canonical_get_chars["default"])
            self.assertEqual(MAX_CANONICAL_TEXT_CHARS, canonical_get_chars["maximum"])
            self.assertEqual(DEFAULT_CANONICAL_TEXT_CHARS, canonical_report_chars["default"])
            self.assertEqual(DEFAULT_ANSWER_PLAN_MAX_TOPICS, answer_plan_max_topics["default"])
            self.assertEqual(MAX_ANSWER_PLAN_TOPICS, answer_plan_max_topics["maximum"])
            self.assertEqual(DEFAULT_CANONICAL_DRIFT_MAX_TOPICS, drift_max_topics["default"])
            self.assertEqual(MAX_CANONICAL_DRIFT_TOPICS, drift_max_topics["maximum"])
            self.assertEqual(DEFAULT_CANONICAL_DRIFT_REPORT_CHARS, drift_report_chars["default"])
            self.assertEqual(MAX_CANONICAL_DRIFT_REPORT_CHARS, drift_report_chars["maximum"])

    def test_corpus_status_returns_stable_json_shape(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool("corpus_status", {})

            self.assertTrue(payload["ok"])
            self.assertEqual(str(pack_root.resolve()), payload["pack_root"])
            self.assertIn("schema_version", payload)
            self.assertEqual(3, payload["manifest"]["function_count"])
            self.assertEqual(3, payload["counts"]["functions"])
            self.assertTrue(Path(payload["paths"]["manifest"]).is_file())
            self.assertTrue(Path(payload["paths"]["sqlite"]).is_file())
            self.assertEqual([], payload["warnings"])

    def test_search_functions_enforces_limit_cap(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "search_functions",
                {
                    "query": "process",
                    "limit": 999,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual(MAX_LIMIT, payload["limit"])
            self.assertIsInstance(payload["results"], list)
            self.assertGreaterEqual(len(payload["results"]), 1)

    def test_get_function_normalizes_ea_and_returns_artifact_paths(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool("get_function", {"ea": "0X140002000"})

            self.assertTrue(payload["ok"])
            function = payload["function"]
            self.assertEqual("0x140002000", function["ea"])
            self.assertEqual("PspAllocateProcess", function["name"])
            self.assertIn("PspAllocateProcess", function["cleaned_excerpt"])
            self.assertTrue(Path(function["artifacts"]["summary"]).is_absolute())
            self.assertTrue(Path(function["artifacts"]["summary"]).is_file())

    def test_get_neighbors_enforces_depth_and_limit_caps(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "get_neighbors",
                {
                    "ea": "0x140001000",
                    "direction": "callees",
                    "depth": 99,
                    "limit": 999,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual("0x140001000", payload["root_ea"])
            self.assertEqual("callees", payload["direction"])
            self.assertEqual(MAX_NEIGHBOR_DEPTH, payload["depth"])
            self.assertEqual(MAX_LIMIT, payload["limit"])
            self.assertEqual([("0x140001000", "0x140002000")], _edge_pairs(payload))

    def test_search_by_import_and_string_return_compact_results(self) -> None:
        with _built_pack() as pack_root:
            server = KernelCorpusMcpServer(pack_root)
            import_payload = server.call_tool("search_by_import", {"query": "ExAllocate"})
            string_payload = server.call_tool("search_by_string", {"query": "ProcessDelete"})

            self.assertTrue(import_payload["ok"])
            self.assertEqual(DEFAULT_LIMIT, import_payload["limit"])
            self.assertEqual(["PspAllocateProcess"], [item["name"] for item in import_payload["results"]])
            self.assertTrue(string_payload["ok"])
            self.assertEqual(["PspProcessDelete"], [item["name"] for item in string_payload["results"]])

    def test_build_evidence_pack_returns_gaps_as_warnings_without_writing(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "build_evidence_pack",
                {
                    "eas": ["0x140001000", "0x140002000", "0xDEADBEEF"],
                    "topic": "process_object",
                },
            )

            self.assertTrue(payload["ok"])
            pack = payload["evidence_pack"]
            self.assertEqual("process_object", pack["topic"])
            self.assertEqual(["NtCreateUserProcess", "PspAllocateProcess"], [item["name"] for item in pack["functions"]])
            self.assertEqual([("0x140001000", "0x140002000")], _edge_pairs(pack))
            self.assertEqual("", pack["output_path"])
            self.assertEqual(["Function not found in pack: 0xDEADBEEF"], pack["gaps"])
            self.assertIn("gap:Function not found in pack: 0xDEADBEEF", payload["warnings"])

    def test_trace_lifecycle_returns_in_memory_evidence_pack(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "trace_lifecycle",
                {
                    "topic": "process_object",
                    "depth": 99,
                    "max_seeds": 999,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual("process_object", payload["topic"])
            self.assertEqual(MAX_LIFECYCLE_DEPTH, payload["depth"])
            self.assertEqual(MAX_LIFECYCLE_MAX_SEEDS, payload["max_seeds"])
            pack = payload["evidence_pack"]
            self.assertEqual("kernel_corpus_evidence_pack_v1", pack["schema"])
            self.assertEqual("", pack["output_path"])
            self.assertGreaterEqual(payload["selected_function_count"], 1)
            phase_names = {
                function["name"]: phase["id"]
                for phase in pack["phases"]
                for function in phase["functions"]
            }
            self.assertEqual("entry", phase_names["NtCreateUserProcess"])
            self.assertEqual("allocate", phase_names["PspAllocateProcess"])

    def test_generate_atlas_writes_pages_with_explicit_output_dir(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "generate_atlas",
                {
                    "pack_root": str(pack_root),
                    "output_dir": str(output_dir),
                    "limit": 999,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual(MAX_ATLAS_LIMIT, payload["limit"])
            self.assertEqual(str(pack_root.resolve()), payload["pack_root"])
            self.assertEqual(str(output_dir.resolve()), payload["output_dir"])
            self.assertEqual(9, payload["page_count"])
            self.assertTrue((output_dir / "process.md").is_file())
            self.assertIn("process.md", {item["filename"] for item in payload["pages"]})

    def test_generate_atlas_rejects_output_dir_outside_pack_root(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "generate_atlas",
                {
                    "output_dir": str(pack_root.parent / "outside-atlas"),
                },
            )

            self.assertFalse(payload["ok"])
            self.assertEqual("QueryError", payload["error"]["type"])
            self.assertIn("must stay under pack_root", payload["error"]["message"])

    def test_list_atlas_pages_returns_metadata(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            server = KernelCorpusMcpServer(pack_root)
            server.call_tool("generate_atlas", {"output_dir": str(output_dir), "limit": 8})

            payload = server.call_tool("list_atlas_pages", {})

            self.assertTrue(payload["ok"])
            self.assertEqual(9, payload["page_count"])
            process_page = next(item for item in payload["pages"] if item["filename"] == "process.md")
            self.assertEqual(str((output_dir / "process.md").resolve()), process_page["path"])
            self.assertGreater(process_page["size"], 0)
            self.assertIn("T", process_page["last_write_time"])
            self.assertTrue(process_page["is_kernel_corpus_atlas_page"])

    def test_get_atlas_page_returns_bounded_markdown(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            server = KernelCorpusMcpServer(pack_root)
            server.call_tool("generate_atlas", {"output_dir": str(output_dir), "limit": 8})

            payload = server.call_tool(
                "get_atlas_page",
                {
                    "page": "process.md",
                    "max_chars": 80,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual("process.md", payload["page"]["filename"])
            self.assertTrue(payload["page"]["is_kernel_corpus_atlas_page"])
            self.assertLessEqual(len(payload["markdown"]), 80)
            self.assertTrue(payload["truncated"])
            self.assertEqual(80, payload["max_chars"])

    def test_get_atlas_page_rejects_path_traversal(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "get_atlas_page",
                {
                    "page": "..\\manifest.json",
                },
            )

            self.assertFalse(payload["ok"])
            self.assertEqual("QueryError", payload["error"]["type"])
            self.assertIn("must be a filename", payload["error"]["message"])

    def test_list_canonical_answers_filters_quality_and_returns_absolute_paths(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            server = KernelCorpusMcpServer(pack_root)

            payload = server.call_tool("list_canonical_answers", {"max_topics": 999})
            pass_payload = server.call_tool("list_canonical_answers", {"status": "pass"})
            degraded_payload = server.call_tool(
                "list_canonical_answers",
                {
                    "priority": "P1",
                    "status": "degraded",
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual(MAX_CANONICAL_TOPICS, payload["max_topics"])
            self.assertEqual(3, payload["topic_count"])
            self.assertEqual(
                ["process_object_lifecycle", "remote_process_access_flow", "p2_review_topic"],
                [topic["topic_id"] for topic in payload["topics"]],
            )
            self.assertTrue(Path(payload["canonical_root"]).is_absolute())
            self.assertTrue(Path(payload["topics"][0]["paths"]["answer"]).is_absolute())
            self.assertEqual(["process_object_lifecycle"], [topic["topic_id"] for topic in pass_payload["topics"]])
            self.assertEqual(["remote_process_access_flow"], [topic["topic_id"] for topic in degraded_payload["topics"]])

    def test_get_canonical_answer_returns_bounded_text_and_rejects_path_traversal(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            server = KernelCorpusMcpServer(pack_root)

            payload = server.call_tool(
                "get_canonical_answer",
                {
                    "topic_id": "process_object_lifecycle",
                    "max_chars": 80,
                },
            )
            traversal = server.call_tool("get_canonical_answer", {"topic_id": "..\\manifest"})

            self.assertTrue(payload["ok"])
            self.assertEqual("process_object_lifecycle", payload["metadata"]["topic_id"])
            self.assertEqual("pass", payload["metadata"]["quality"]["status"])
            self.assertLessEqual(payload["returned_chars"], 80)
            self.assertTrue(payload["truncated"])
            self.assertTrue(payload["content"]["answer"]["truncated"])
            self.assertTrue(payload["content"]["quality"]["omitted_due_to_limit"])
            self.assertTrue(Path(payload["content"]["answer"]["path"]).is_absolute())
            self.assertFalse(traversal["ok"])
            self.assertEqual("QueryError", traversal["error"]["type"])
            self.assertIn("not a path", traversal["error"]["message"])

    def test_canonical_index_directory_outside_root_is_not_read(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            canonical_root = pack_root / "canonical-answers"
            outside_dir = pack_root / "outside_canonical_topic"
            _write_canonical_topic(
                outside_dir,
                {
                    "topic_id": "outside_topic",
                    "priority": "P0",
                    "mode": "focused",
                    "title": "Outside Topic",
                    "question": "This topic must not be read through index directory escape.",
                    "status": "pass",
                    "score": 100,
                    "warnings": 0,
                    "functions": ["OutsideFunction"],
                },
            )
            index_path = canonical_root / "index.json"
            index_payload = json.loads(index_path.read_text(encoding="utf-8"))
            index_payload["topics"].append(
                {
                    "id": "outside_topic",
                    "priority": "P0",
                    "mode": "focused",
                    "directory": str(outside_dir.resolve()),
                }
            )
            index_path.write_text(
                json.dumps(index_payload, indent=2, ensure_ascii=True, sort_keys=True),
                encoding="utf-8",
            )

            server = KernelCorpusMcpServer(pack_root)
            list_payload = server.call_tool("list_canonical_answers", {"max_topics": 10})
            get_payload = server.call_tool("get_canonical_answer", {"topic_id": "outside_topic"})

            self.assertTrue(list_payload["ok"])
            self.assertNotIn("outside_topic", [topic["topic_id"] for topic in list_payload["topics"]])
            self.assertFalse(get_payload["ok"])
            self.assertEqual("QueryError", get_payload["error"]["type"])

    def test_get_canonical_quality_report_filters_status_and_bounds_markdown(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)

            payload = KernelCorpusMcpServer(pack_root).call_tool(
                "get_canonical_quality_report",
                {
                    "status": "pass",
                    "max_chars": 40,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual(1, payload["report"]["topic_count"])
            self.assertEqual(1, payload["report"]["pass_count"])
            self.assertEqual(["process_object_lifecycle"], [topic["topic_id"] for topic in payload["topics"]])
            self.assertLessEqual(len(payload["markdown"]), 40)
            self.assertTrue(payload["truncated"])
            self.assertTrue(Path(payload["report"]["path"]).is_absolute())

    def test_find_canonical_answers_searches_major_functions_and_status(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            server = KernelCorpusMcpServer(pack_root)

            process_payload = server.call_tool("find_canonical_answers", {"query": "process object"})
            remote_payload = server.call_tool("find_canonical_answers", {"query": "NtOpenProcess"})
            degraded_payload = server.call_tool(
                "find_canonical_answers",
                {
                    "query": "remote process access",
                    "status": "degraded",
                },
            )

            self.assertTrue(process_payload["ok"])
            self.assertEqual("process_object_lifecycle", process_payload["results"][0]["topic_id"])
            self.assertEqual("pass", process_payload["results"][0]["quality"]["status"])
            self.assertTrue(remote_payload["ok"])
            self.assertEqual("remote_process_access_flow", remote_payload["results"][0]["topic_id"])
            self.assertIn("major_functions", remote_payload["results"][0]["match_fields"])
            self.assertEqual(["remote_process_access_flow"], [topic["topic_id"] for topic in degraded_payload["results"]])

    def test_plan_kernel_answer_returns_read_only_retrieval_plan(self) -> None:
        with _built_pack() as pack_root:
            _write_canonical_fixture(pack_root)
            server = KernelCorpusMcpServer(pack_root)

            payload = server.call_tool(
                "plan_kernel_answer",
                {
                    "question": "process object lifecycle",
                    "max_topics": 1,
                },
            )

            self.assertTrue(payload["ok"])
            self.assertEqual("kernel_corpus_answer_plan_v1", payload["schema_version"])
            self.assertEqual("process_object_lifecycle", payload["canonical_candidates"][0]["topic_id"])
            self.assertIn("live_retrieval_steps", payload)
            self.assertNotIn("answer", payload)

    def test_missing_canonical_root_returns_warning(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool("list_canonical_answers", {})

            self.assertTrue(payload["ok"])
            self.assertEqual(0, payload["topic_count"])
            self.assertIn("Canonical answer root does not exist", payload["warnings"][0])

    def test_invalid_ea_returns_structured_error(self) -> None:
        with _built_pack() as pack_root:
            payload = KernelCorpusMcpServer(pack_root).call_tool("get_function", {"ea": "0xDEADBEEF"})

            self.assertFalse(payload["ok"])
            self.assertEqual(str(pack_root.resolve()), payload["pack_root"])
            self.assertEqual("QueryError", payload["error"]["type"])
            self.assertIn("0xDEADBEEF", payload["error"]["message"])
            self.assertEqual([], payload["results"])

    def test_missing_pack_root_returns_structured_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_root = Path(temp_dir) / "missing"
            payload = KernelCorpusMcpServer(missing_root).call_tool("corpus_status", {})

            self.assertFalse(payload["ok"])
            self.assertEqual(str(missing_root), payload["pack_root"])
            self.assertEqual("QueryError", payload["error"]["type"])
            self.assertIn("Pack root does not exist", payload["error"]["message"])

    def test_jsonrpc_tools_list_and_call_shapes(self) -> None:
        with _built_pack() as pack_root:
            server = KernelCorpusMcpServer(pack_root)
            listed = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            called = server.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "search_by_string",
                        "arguments": {"query": "ProcessDelete"},
                    },
                }
            )

            self.assertEqual("2.0", listed["jsonrpc"])
            self.assertEqual(1, listed["id"])
            self.assertEqual(EXPECTED_TOOLS, {item["name"] for item in listed["result"]["tools"]})
            self.assertFalse(called["result"]["isError"])
            content = called["result"]["content"]
            self.assertEqual("text", content[0]["type"])
            payload = json.loads(content[0]["text"])
            self.assertTrue(payload["ok"])
            self.assertEqual(["PspProcessDelete"], [item["name"] for item in payload["results"]])

    def test_serve_reads_line_delimited_jsonrpc(self) -> None:
        with _built_pack() as pack_root:
            server = KernelCorpusMcpServer(pack_root)
            request = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}) + "\n"
            output = io.StringIO()

            server.serve(io.StringIO(request), output)

            response = json.loads(output.getvalue())
            self.assertEqual(7, response["id"])
            self.assertEqual(EXPECTED_TOOLS, {item["name"] for item in response["result"]["tools"]})


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


def _edge_pairs(payload: dict[str, object]) -> list[tuple[str, str]]:
    return [(edge["src_ea"], edge["dst_ea"]) for edge in payload["edges"]]


def _write_canonical_fixture(pack_root: Path) -> None:
    root = pack_root / "canonical-answers"
    specs = [
        {
            "topic_id": "process_object_lifecycle",
            "priority": "P0",
            "mode": "lifecycle",
            "title": "Process Object Lifecycle",
            "question": "Explain process object lifecycle from canonical evidence.",
            "status": "pass",
            "score": 94,
            "warnings": 0,
            "functions": ["NtCreateUserProcess", "PspAllocateProcess", "PspProcessDelete"],
        },
        {
            "topic_id": "remote_process_access_flow",
            "priority": "P1",
            "mode": "focused",
            "title": "Remote Process Access Flow",
            "question": "Explain remote process access through NtOpenProcess and memory operations.",
            "status": "degraded",
            "score": 70,
            "warnings": 0,
            "functions": ["NtOpenProcess", "MmCopyVirtualMemory"],
        },
        {
            "topic_id": "p2_review_topic",
            "priority": "P2",
            "mode": "focused",
            "title": "P2 Review Topic",
            "question": "Explain a broad P2 review topic.",
            "status": "fail",
            "score": 45,
            "warnings": 1,
            "functions": ["EtwWrite"],
        },
    ]
    topics = []
    for spec in specs:
        topic_dir = root / spec["priority"] / spec["topic_id"]
        _write_canonical_topic(topic_dir, spec)
        topics.append(
            {
                "id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str(topic_dir.resolve()),
                "selected_function_count": len(spec["functions"]),
                "edge_count": max(0, len(spec["functions"]) - 1),
                "validation_passed": spec["warnings"] == 0,
                "validation_warning_count": spec["warnings"],
            }
        )
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_answer_run_v1",
                "source_index_sha256": "fixture-source",
                "pack_generated_at": "2026-06-13T00:00:00+00:00",
                "topics": list(reversed(topics)),
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    report_topics = []
    for spec in specs:
        report_topics.append(
            {
                "topic_id": spec["topic_id"],
                "priority": spec["priority"],
                "mode": spec["mode"],
                "directory": str((root / spec["priority"] / spec["topic_id"]).resolve()),
                "status": spec["status"],
                "score": spec["score"],
                "selected_function_count": len(spec["functions"]),
                "edge_count": max(0, len(spec["functions"]) - 1),
                "validation_warning_count": spec["warnings"],
                "gap_count": 1,
            }
        )
    (root / "quality-report.json").write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_quality_report_v1",
                "topic_count": len(report_topics),
                "pass_count": 1,
                "degraded_count": 1,
                "fail_count": 1,
                "topics": report_topics,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (root / "quality-report.md").write_text("# Canonical Quality Report\n\n" + ("report body " * 20), encoding="utf-8")


def _write_canonical_topic(topic_dir: Path, spec: dict[str, object]) -> None:
    topic_dir.mkdir(parents=True, exist_ok=True)
    topic_id = str(spec["topic_id"])
    functions = [
        {
            "ea": "0x%X" % (0x140000000 + (index * 0x1000)),
            "name": name,
            "tags": ["process_thread"],
            "artifact_paths": {"cleaned": str((topic_dir / "answer.md").resolve())},
        }
        for index, name in enumerate(spec["functions"], start=1)
    ]
    edges = [
        {"src_ea": functions[index]["ea"], "dst_ea": functions[index + 1]["ea"], "edge_kind": "callee"}
        for index in range(max(0, len(functions) - 1))
    ]
    paths = {
        "answer": topic_dir / "answer.md",
        "candidate_review": topic_dir / "candidate-review.md",
        "evidence_pack": topic_dir / "evidence-pack.json",
        "gaps": topic_dir / "gaps.md",
        "manifest": topic_dir / "manifest.json",
        "prompt": topic_dir / "prompt.md",
        "quality": topic_dir / "quality.md",
        "source_map": topic_dir / "source-map.md",
        "trace": topic_dir / "trace.json",
        "validation": topic_dir / "validation.json",
    }
    answer = "# %s\n\n" % spec["title"] + ("Canonical answer body with artifact path and EA evidence. " * 20)
    paths["answer"].write_text(answer, encoding="utf-8")
    paths["candidate_review"].write_text("- candidate review\n", encoding="utf-8")
    paths["gaps"].write_text("- Gap: fixture gap\n", encoding="utf-8")
    paths["prompt"].write_text("fixture prompt\n", encoding="utf-8")
    paths["quality"].write_text("# Quality\n\nstatus=%s\n" % spec["status"], encoding="utf-8")
    paths["source_map"].write_text("## Public Contract References\n\n- NtOpenProcess source map fixture\n", encoding="utf-8")
    paths["evidence_pack"].write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_evidence_pack_v1",
                "topic": topic_id,
                "summary": {
                    "selected_function_count": len(functions),
                    "edge_count": len(edges),
                    "source_ref_count": 1,
                },
                "functions": functions,
                "edges": edges,
                "gaps": ["fixture gap"],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    paths["trace"].write_text(
        json.dumps(
            {
                "schema": "kernel_corpus_canonical_trace_v1",
                "selected_candidates": functions,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    paths["validation"].write_text(
        json.dumps(
            {
                "passed": int(spec["warnings"]) == 0,
                "warning_count": spec["warnings"],
                "warnings": [{"code": "fixture"}] if int(spec["warnings"]) else [],
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    paths["quality"].with_suffix(".json").write_text(
        json.dumps(
            {
                "topic_id": topic_id,
                "priority": spec["priority"],
                "mode": spec["mode"],
                "status": spec["status"],
                "score": spec["score"],
                "selected_function_count": len(functions),
                "edge_count": len(edges),
                "validation_warning_count": spec["warnings"],
                "gap_count": 1,
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    paths["manifest"].write_text(
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
                "files": {key: str(value.resolve()) for key, value in paths.items() if key != "manifest"},
                "validation": {
                    "passed": int(spec["warnings"]) == 0,
                    "warning_count": spec["warnings"],
                },
            },
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
