from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.mcp_server import (
    DEFAULT_LIMIT,
    DEFAULT_LIFECYCLE_DEPTH,
    DEFAULT_LIFECYCLE_MAX_SEEDS,
    DEFAULT_NEIGHBOR_DEPTH,
    MAX_LIMIT,
    MAX_LIFECYCLE_DEPTH,
    MAX_LIFECYCLE_MAX_SEEDS,
    MAX_NEIGHBOR_DEPTH,
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
            self.assertEqual(DEFAULT_LIMIT, search_limit["default"])
            self.assertEqual(MAX_LIMIT, search_limit["maximum"])
            self.assertEqual(DEFAULT_NEIGHBOR_DEPTH, neighbor_depth["default"])
            self.assertEqual(MAX_NEIGHBOR_DEPTH, neighbor_depth["maximum"])
            self.assertEqual(MAX_LIMIT, neighbor_limit["maximum"])
            self.assertEqual(DEFAULT_LIFECYCLE_MAX_SEEDS, lifecycle_max_seeds["default"])
            self.assertEqual(MAX_LIFECYCLE_MAX_SEEDS, lifecycle_max_seeds["maximum"])
            self.assertEqual(DEFAULT_LIFECYCLE_DEPTH, lifecycle_depth["default"])
            self.assertEqual(MAX_LIFECYCLE_DEPTH, lifecycle_depth["maximum"])

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


if __name__ == "__main__":
    unittest.main()
