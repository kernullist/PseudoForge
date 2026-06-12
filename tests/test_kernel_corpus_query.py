from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus import query
from tools.kernel_corpus.schema import EVIDENCE_PACK_SCHEMA_VERSION
from tools.kernel_corpus.store import connect_database


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusQueryTests(unittest.TestCase):
    def test_corpus_status_reports_manifest_and_counts(self) -> None:
        with _built_pack() as pack_root:
            status = query.corpus_status(pack_root)

            self.assertTrue(status["ok"])
            self.assertEqual(3, status["manifest"]["function_count"])
            self.assertEqual(3, status["counts"]["functions"])
            self.assertEqual(4, status["counts"]["function_tags"])
            self.assertEqual(1, status["counts"]["call_edges"])
            self.assertEqual([], status["warnings"])

    def test_search_functions_finds_by_name(self) -> None:
        with _built_pack() as pack_root:
            results = query.search_functions(pack_root, query="NtCreateUserProcess", limit=5)

            self.assertGreaterEqual(len(results), 1)
            self.assertEqual("0x140001000", results[0]["ea"])
            self.assertEqual("NtCreateUserProcess", results[0]["name"])
            self.assertIn("process_thread", results[0]["tags"])

    def test_find_functions_by_name_uses_exact_case_insensitive_lookup(self) -> None:
        with _built_pack() as pack_root:
            results = query.find_functions_by_name(pack_root, "ntcreateuserprocess", limit=5)

            self.assertEqual(["NtCreateUserProcess"], [item["name"] for item in results])
            self.assertEqual(["0x140001000"], [item["ea"] for item in results])
            self.assertIn("exact_name", results[0]["why_selected"])

    def test_search_functions_filters_by_tag(self) -> None:
        with _built_pack() as pack_root:
            results = query.search_functions(pack_root, tags=["memory"], limit=10)

            self.assertEqual(["PspAllocateProcess"], [item["name"] for item in results])
            self.assertIn("tag:memory", results[0]["why_selected"])

    def test_search_functions_uses_fts_term_when_available(self) -> None:
        with _built_pack() as pack_root:
            if not _fts_available(pack_root):
                self.skipTest("SQLite FTS5 is not available")

            results = query.search_functions(pack_root, query="allocate", limit=10)

            self.assertEqual("PspAllocateProcess", results[0]["name"])
            self.assertTrue({"fts", "text"} & set(results[0]["why_selected"]))

    def test_get_function_normalizes_ea_and_returns_artifacts(self) -> None:
        with _built_pack() as pack_root:
            function = query.get_function(pack_root, "0X140002000")

            self.assertEqual("0x140002000", function["ea"])
            self.assertEqual("PspAllocateProcess", function["name"])
            self.assertIn("PspAllocateProcess", function["cleaned_excerpt"])
            self.assertTrue(Path(function["artifacts"]["summary"]).is_file())
            self.assertEqual([], function["warnings"])

    def test_get_function_reports_missing_artifact_as_warning(self) -> None:
        with _built_pack() as pack_root:
            sqlite_path = pack_root / "corpus.sqlite"
            with connect_database(sqlite_path) as connection:
                connection.execute(
                    "UPDATE functions SET cleaned_path = ? WHERE ea = ?",
                    (str(pack_root / "missing.cleaned.cpp"), "0x140002000"),
                )
                connection.commit()

            function = query.get_function(pack_root, "0x140002000")

            self.assertIn("missing.cleaned.cpp", function["artifacts"]["cleaned_pseudocode"])
            self.assertEqual(1, len(function["warnings"]))
            self.assertIn("Missing artifact cleaned_pseudocode", function["warnings"][0])

    def test_get_neighbors_traverses_callees_and_callers(self) -> None:
        with _built_pack() as pack_root:
            callees = query.get_neighbors(pack_root, "0x140001000", direction="callees", depth=1)
            callers = query.get_neighbors(pack_root, "0x140002000", direction="callers", depth=1)

            self.assertEqual(["0x140001000", "0x140002000"], [item["ea"] for item in callees["nodes"]])
            self.assertEqual([("0x140001000", "0x140002000")], _edge_pairs(callees))
            self.assertEqual(["0x140002000", "0x140001000"], [item["ea"] for item in callers["nodes"]])
            self.assertEqual([("0x140001000", "0x140002000")], _edge_pairs(callers))

    def test_search_by_import_and_string(self) -> None:
        with _built_pack() as pack_root:
            import_results = query.search_by_import(pack_root, "ExAllocate", limit=5)
            string_results = query.search_by_string(pack_root, "ProcessDelete", limit=5)

            self.assertEqual(["PspAllocateProcess"], [item["name"] for item in import_results])
            self.assertIn("import:ExAllocatePool2", import_results[0]["why_selected"])
            self.assertEqual(["PspProcessDelete"], [item["name"] for item in string_results])
            self.assertIn("string:ProcessDelete", string_results[0]["why_selected"])

    def test_build_evidence_pack_returns_functions_edges_and_writes_output(self) -> None:
        with _built_pack() as pack_root:
            output_path = pack_root / "evidence-packs" / "process.json"
            pack = query.build_evidence_pack(
                pack_root,
                ["0x140001000", "0x140002000", "0xDEADBEEF"],
                "process_object",
                output_path=output_path,
            )

            written = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(EVIDENCE_PACK_SCHEMA_VERSION, pack["schema"])
            self.assertEqual("process_object", pack["topic"])
            self.assertEqual(["NtCreateUserProcess", "PspAllocateProcess"], [item["name"] for item in pack["functions"]])
            self.assertEqual([("0x140001000", "0x140002000")], _edge_pairs(pack))
            self.assertEqual(["Function not found in pack: 0xDEADBEEF"], pack["gaps"])
            self.assertEqual(pack["schema"], written["schema"])

    def test_cli_search_outputs_json(self) -> None:
        with _built_pack() as pack_root:
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = query.main(
                    [
                        "search",
                        "--pack-root",
                        str(pack_root),
                        "--query",
                        "process",
                        "--limit",
                        "2",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertTrue(payload["ok"])
            self.assertLessEqual(len(payload["results"]), 2)


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


def _fts_available(pack_root: Path) -> bool:
    with connect_database(pack_root / "corpus.sqlite") as connection:
        try:
            connection.execute("SELECT 1 FROM function_fts LIMIT 1")
        except sqlite3.Error:
            return False
    return True


def _edge_pairs(payload: dict[str, object]) -> list[tuple[str, str]]:
    return [(edge["src_ea"], edge["dst_ea"]) for edge in payload["edges"]]


if __name__ == "__main__":
    unittest.main()
