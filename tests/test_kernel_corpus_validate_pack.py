from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.atlas import generate_atlas
from tools.kernel_corpus.lifecycle import trace_lifecycle
from tools.kernel_corpus.validate_pack import format_text_report, main, validate_pack


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusValidatePackTests(unittest.TestCase):
    def test_fresh_pack_with_derived_artifacts_passes(self) -> None:
        with _built_pack_from_copy() as (_source_root, pack_root):
            trace_lifecycle(
                pack_root,
                "process_object",
                max_seeds=8,
                depth=1,
                output_path=pack_root / "evidence-packs" / "process_object.json",
            )
            generate_atlas(pack_root, pack_root / "reports" / "atlas", limit=8)

            report = validate_pack(pack_root, include_derived=True)

            self.assertTrue(report["ok"], report["issues"])
            self.assertEqual("pass", report["status"])
            self.assertEqual(0, report["summary"]["error_count"])
            self.assertEqual(1, len(report["derived"]["evidence_packs"]))
            self.assertGreaterEqual(len(report["derived"]["atlas_pages"]), 1)

    def test_stale_source_index_hash_fails(self) -> None:
        with _built_pack_from_copy() as (source_root, pack_root):
            index_path = source_root / "pseudoforge-corpus-index.json"
            data = json.loads(index_path.read_text(encoding="utf-8"))
            data["functions"].append(
                {
                    "ea": "0x140004000",
                    "name": "NewFunctionAfterBuild",
                    "directory": "functions/missing",
                    "summary_path": "functions/missing/function.ida-batch-summary.json",
                }
            )
            index_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

            report = validate_pack(pack_root)

            self.assertFalse(report["ok"])
            self.assertIn("source_index_hash_mismatch", _issue_codes(report))

    def test_missing_pack_root_fails_without_throwing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "missing-pack"

            report = validate_pack(pack_root)

            self.assertFalse(report["ok"])
            self.assertEqual("fail", report["status"])
            self.assertIn("pack_root_missing", _issue_codes(report))

    def test_partial_pack_missing_sqlite_fails(self) -> None:
        with _built_pack_from_copy() as (_source_root, pack_root):
            (pack_root / "corpus.sqlite").unlink()

            report = validate_pack(pack_root)

            self.assertFalse(report["ok"])
            self.assertIn("sqlite_missing", _issue_codes(report))

    def test_manifest_and_sqlite_count_mismatch_fails(self) -> None:
        with _built_pack_from_copy() as (_source_root, pack_root):
            with contextlib.closing(sqlite3.connect(pack_root / "corpus.sqlite")) as connection:
                connection.execute("DELETE FROM functions WHERE ea = ?", ("0x140003000",))
                connection.commit()

            report = validate_pack(pack_root)

            codes = _issue_codes(report)
            self.assertFalse(report["ok"])
            self.assertIn("count_mismatch", codes)

    def test_stale_derived_artifacts_fail(self) -> None:
        with _built_pack_from_copy() as (_source_root, pack_root):
            evidence_path = pack_root / "evidence-packs" / "process_object.json"
            trace_lifecycle(
                pack_root,
                "process_object",
                max_seeds=8,
                depth=1,
                output_path=evidence_path,
            )
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["created_at"] = "2000-01-01T00:00:00+00:00"
            evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")

            atlas_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, atlas_dir, limit=8)
            atlas_path = atlas_dir / "process.md"
            atlas_text = atlas_path.read_text(encoding="utf-8")
            atlas_path.write_text(
                re.sub(r"^Generated: `[^`]+`", "Generated: `2000-01-01T00:00:00+00:00`", atlas_text, count=1, flags=re.MULTILINE),
                encoding="utf-8",
            )

            report = validate_pack(
                pack_root,
                evidence_packs=[str(evidence_path)],
                atlas_pages=[str(atlas_path)],
            )

            codes = _issue_codes(report)
            self.assertFalse(report["ok"])
            self.assertIn("evidence_pack_stale", codes)
            self.assertIn("atlas_page_stale", codes)

    def test_cli_outputs_json_and_text(self) -> None:
        with _built_pack_from_copy() as (_source_root, pack_root):
            json_stdout = io.StringIO()
            with contextlib.redirect_stdout(json_stdout):
                json_exit = main(["--pack-root", str(pack_root), "--format", "json"])

            payload = json.loads(json_stdout.getvalue())
            self.assertEqual(0, json_exit)
            self.assertTrue(payload["ok"])

            text_stdout = io.StringIO()
            with contextlib.redirect_stdout(text_stdout):
                text_exit = main(["--pack-root", str(pack_root), "--format", "text"])

            self.assertEqual(0, text_exit)
            self.assertIn("Kernel Corpus pack validation: PASS", text_stdout.getvalue())

    def test_text_report_includes_issues(self) -> None:
        report = {
            "status": "warn",
            "pack_root": "C:\\pack",
            "summary": {"error_count": 0, "warning_count": 1},
            "issues": [
                {
                    "severity": "warning",
                    "code": "source_index_unverifiable",
                    "message": "not accessible",
                    "path": "C:\\missing.json",
                }
            ],
        }

        text = format_text_report(report)

        self.assertIn("WARN", text)
        self.assertIn("source_index_unverifiable", text)


@contextlib.contextmanager
def _built_pack_from_copy():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        source_root = temp_path / "source"
        pack_root = temp_path / "pack"
        shutil.copytree(FIXTURE_ROOT, source_root)
        builder.build_pack(source_root, pack_root)
        yield source_root, pack_root


def _issue_codes(report: dict[str, object]) -> set[str]:
    return {
        str(issue.get("code", ""))
        for issue in report.get("issues", [])
        if isinstance(issue, dict)
    }


if __name__ == "__main__":
    unittest.main()
