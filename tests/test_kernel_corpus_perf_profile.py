from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus.perf_profile import PROFILE_SCHEMA, main, run_profile


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusPerfProfileTests(unittest.TestCase):
    def test_profile_covers_build_and_retrieval_paths_on_fixture_pack(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            report = run_profile(
                pack_root=None,
                build_corpus_root=FIXTURE_ROOT,
                build_pack_root=temp_root / "pack",
                overwrite_build=True,
                lifecycle_max_seeds=8,
                lifecycle_depth=1,
                atlas_output_dir=temp_root / "atlas",
                atlas_limit=8,
            )

            self.assertEqual(PROFILE_SCHEMA, report["schema"])
            self.assertEqual(
                [
                    "pack_build",
                    "status",
                    "text_search",
                    "tag_search",
                    "neighbor_traversal",
                    "lifecycle_tracing",
                    "atlas_generation",
                ],
                [operation["name"] for operation in report["operations"]],
            )
            for operation in report["operations"]:
                self.assertNotIn("_payload", operation)
                self.assertTrue(operation["ok"], operation)
                self.assertGreaterEqual(operation["duration_ms"], 0.0)
                self.assertIsInstance(operation["summary"], dict)
            summaries = {operation["name"]: operation["summary"] for operation in report["operations"]}
            self.assertEqual(3, summaries["pack_build"]["function_count"])
            self.assertEqual(3, summaries["status"]["function_count"])
            self.assertGreaterEqual(summaries["text_search"]["result_count"], 1)
            self.assertGreaterEqual(summaries["tag_search"]["result_count"], 1)
            self.assertGreaterEqual(summaries["neighbor_traversal"]["node_count"], 1)
            self.assertEqual("process_object", summaries["lifecycle_tracing"]["topic"])
            self.assertGreaterEqual(summaries["atlas_generation"]["page_count"], 1)

    def test_cli_outputs_profile_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--build-corpus-root",
                        str(FIXTURE_ROOT),
                        "--build-pack-root",
                        str(pack_root),
                        "--overwrite-build",
                        "--lifecycle-max-seeds",
                        "8",
                        "--lifecycle-depth",
                        "1",
                        "--skip-atlas",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual(PROFILE_SCHEMA, payload["schema"])
            self.assertEqual(
                [
                    "pack_build",
                    "status",
                    "text_search",
                    "tag_search",
                    "neighbor_traversal",
                    "lifecycle_tracing",
                ],
                [operation["name"] for operation in payload["operations"]],
            )


if __name__ == "__main__":
    unittest.main()
