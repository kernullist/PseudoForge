from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.errors import KernelCorpusError
from tools.kernel_corpus.schema import MANIFEST_SCHEMA_VERSION, PACK_SCHEMA_VERSION
from tools.kernel_corpus.store import connect_database, read_manifest_rows


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusBuilderTests(unittest.TestCase):
    def test_build_pack_imports_minimal_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"

            result = builder.build_pack(FIXTURE_ROOT, pack_root, max_cleaned_chars=24)

            manifest_path = Path(result["manifest_path"])
            sqlite_path = Path(result["sqlite_path"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(MANIFEST_SCHEMA_VERSION, manifest["schema"])
            self.assertEqual(PACK_SCHEMA_VERSION, manifest["pack_schema"])
            self.assertEqual("0.1.2", manifest["pseudoforge_version"])
            self.assertEqual("minimal.i64", manifest["target_path"])
            self.assertEqual(3, manifest["function_count"])
            self.assertEqual(3, manifest["unique_ea_count"])
            self.assertEqual(0, manifest["skipped_count"])
            self.assertEqual(24, manifest["max_cleaned_chars"])
            self.assertEqual(_sha256(FIXTURE_ROOT / "pseudoforge-corpus-index.json"), manifest["source_index_sha256"])
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(sqlite_path.is_file())

            with connect_database(sqlite_path) as connection:
                self.assertEqual(3, _count(connection, "functions"))
                self.assertEqual(4, _count(connection, "function_tags"))
                self.assertEqual(1, _count(connection, "call_edges"))
                self.assertEqual(2, _count(connection, "function_imports"))
                self.assertEqual(1, _count(connection, "function_strings"))
                rows = read_manifest_rows(connection)
                self.assertEqual(MANIFEST_SCHEMA_VERSION, rows["schema"])
                self.assertEqual("3", rows["function_count"])

    def test_build_pack_preserves_tags_edges_and_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            result = builder.build_pack(FIXTURE_ROOT, pack_root)

            with connect_database(result["sqlite_path"]) as connection:
                tags = {
                    row["tag"]
                    for row in connection.execute(
                        "SELECT tag FROM function_tags WHERE ea = ?",
                        ("0x140002000",),
                    )
                }
                self.assertEqual({"memory", "process_thread"}, tags)
                edge = connection.execute(
                    "SELECT src_ea, dst_ea, edge_kind FROM call_edges"
                ).fetchone()
                self.assertEqual(("0x140001000", "0x140002000", "calls"), tuple(edge))
                function = connection.execute(
                    "SELECT summary_path, cleaned_path, raw_path, cleaned_excerpt FROM functions WHERE ea = ?",
                    ("0x140002000",),
                ).fetchone()
                self.assertTrue(Path(function["summary_path"]).is_absolute())
                self.assertTrue(Path(function["summary_path"]).is_file())
                self.assertTrue(Path(function["cleaned_path"]).is_file())
                self.assertTrue(Path(function["raw_path"]).is_file())
                self.assertIn("PspAllocateProcess", function["cleaned_excerpt"])

    def test_build_pack_refuses_existing_pack_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            builder.build_pack(FIXTURE_ROOT, pack_root)

            with self.assertRaisesRegex(KernelCorpusError, "overwrite"):
                builder.build_pack(FIXTURE_ROOT, pack_root)

            result = builder.build_pack(FIXTURE_ROOT, pack_root, overwrite=True)
            self.assertTrue(Path(result["sqlite_path"]).is_file())

    def test_builder_cli_writes_json_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = builder.main(
                    [
                        "--corpus-root",
                        str(FIXTURE_ROOT),
                        "--pack-root",
                        str(pack_root),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual(3, payload["manifest"]["function_count"])
            self.assertTrue((pack_root / "manifest.json").is_file())
            self.assertTrue((pack_root / "corpus.sqlite").is_file())

    def test_fts_search_returns_expected_rows_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            result = builder.build_pack(FIXTURE_ROOT, pack_root)
            if not result["manifest"]["fts5_enabled"]:
                self.skipTest("SQLite FTS5 is not available")

            with connect_database(result["sqlite_path"]) as connection:
                rows = list(
                    connection.execute(
                        "SELECT ea FROM function_fts WHERE function_fts MATCH ? ORDER BY ea",
                        ("allocate",),
                    )
                )

            self.assertEqual(["0x140002000"], [row["ea"] for row in rows])


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
