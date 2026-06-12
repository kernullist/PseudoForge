from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import write_export_bundle as legacy_render_write_export_bundle
from ida_pseudoforge.profiles import loader as profile_loader


SAMPLE = """
__int64 __fastcall ExportBundleSample(int a1)
{
  int status;

  status = 0;
  if ( a1 )
  {
    status = -1073741823;
  }
  return status;
}
"""


class ExportBundleTests(unittest.TestCase):
    def test_write_export_bundle_includes_parity_artifacts(self) -> None:
        profile_loader.clear_profile_caches()
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
                plan = build_clean_plan(capture)
                self.assertTrue(profile_loader.get_status_name(-1073741823))

                artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

                for key in (
                    "cleaned_pseudocode",
                    "switch_outline",
                    "rename_map",
                    "flow_report",
                    "rule_report",
                    "raw_pseudocode",
                    "warnings",
                    "raw_vs_cleaned_diff",
                    "summary",
                ):
                    self.assertIn(key, artifacts)
                    self.assertTrue(Path(artifacts[key]).exists(), key)

                self.assertEqual(
                    Path(artifacts["raw_pseudocode"]).read_text(encoding="utf-8"),
                    capture.pseudocode.rstrip() + "\n",
                )
                diff_text = Path(artifacts["raw_vs_cleaned_diff"]).read_text(encoding="utf-8")
                self.assertTrue(diff_text.startswith("--- raw/ExportBundleSample.cpp\n"))
                self.assertIn("+++ cleaned/ExportBundleSample.cpp\n", diff_text)
                self.assertIsInstance(json.loads(Path(artifacts["warnings"]).read_text(encoding="utf-8")), list)

                summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
                self.assertEqual(summary["mode"], "ida_interactive")
                self.assertEqual(summary["function"], "ExportBundleSample")
                self.assertEqual(summary["function_ea"], "0x140001000")
                self.assertEqual(summary["source_path"], "sample.bin")
                self.assertIn("raw_vs_cleaned_diff", summary["artifacts"])
                self.assertEqual(artifacts["summary"], summary["artifacts"]["summary"])
                self.assertEqual(summary["profile_root"], profile_loader.active_profile_root())
                self.assertIn("status_codes.json", summary["active_profiles"])
                self.assertTrue(
                    any(item["name"] == "status_codes.json" for item in summary["profile_manifests"])
                )
            finally:
                profile_loader.clear_profile_caches()

    def test_write_export_bundle_allows_summary_suffix_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(
                temp_dir,
                capture,
                plan,
                entrypoint="ida_free_offline",
                summary_suffix="ida-free-summary",
            )

            summary_path = Path(artifacts["summary"])
            self.assertEqual("ExportBundleSample.ida-free-summary.json", summary_path.name)
            self.assertTrue(summary_path.exists())
            self.assertFalse((Path(temp_dir) / "ExportBundleSample.summary.json").exists())

    def test_write_export_bundle_limits_long_artifact_stems(self) -> None:
        long_name = (
            "?BTreeRedistribute@?$B_TREE@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY@?"
            "$SMKM_STORE_MGR@USM_TRAITS@@@@$0BAAA@UB_TREE_DUMMY_NODE_POOL@@"
            "U?$B_TREE_KEY_COMPARATOR@T_SM_PAGE_KEY@@@@@@SAPEAUNODE@?"
            "$B_TREE_HEADER@T_SM_PAGE_KEY@@USMKM_FRONTEND_ENTRY@?"
            "$SMKM_STORE_MGR@USM_TRAITS@@@@@@PEAU1@PEAUSEARCH_RESULT@1@@Z"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                SAMPLE,
                name=long_name,
                ea=0x140291E88,
                source_path="sample.bin",
            )
            plan = build_clean_plan(capture)

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            cleaned_path = Path(artifacts["cleaned_pseudocode"])
            artifact_stem = cleaned_path.name[: -len(".cleaned.cpp")]
            self.assertLessEqual(len(artifact_stem), 96)
            self.assertRegex(artifact_stem, r"_[0-9a-f]{12}$")
            for path in artifacts.values():
                self.assertTrue(Path(path).exists(), path)

            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            self.assertEqual(long_name, summary["function"])

    def test_write_export_bundle_includes_rule_diagnostics_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)
            plan.rule_report = {
                "matched_rules": [{"rule_id": "one"}, {"rule_id": "two"}],
                "rewrite_emissions": [
                    {"kind": "call_arg_rewrite", "status": "applied"},
                    {"kind": "text_rewrite", "status": "rejected"},
                ],
                "load_errors": [{"path": "project/broken.json", "error": "invalid json"}],
                "validation_errors": [{"path": "project/invalid.json", "error": "bad phase"}],
            }

            artifacts = write_export_bundle(temp_dir, capture, plan, entrypoint="ida_interactive")

            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            diagnostics = summary["rule_diagnostics"]
            self.assertEqual(2, diagnostics["matched_rules"])
            self.assertEqual(2, diagnostics["rewrite_emissions"]["total"])
            self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["applied"])
            self.assertEqual(1, diagnostics["rewrite_emissions"]["by_status"]["rejected"])
            self.assertEqual(1, diagnostics["load_errors"])
            self.assertEqual(1, diagnostics["validation_errors"])
            self.assertEqual("project/broken.json", summary["rule_load_errors"][0]["path"])
            self.assertEqual("project/invalid.json", summary["rule_validation_errors"][0]["path"])

    def test_legacy_render_export_import_remains_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(SAMPLE, ea=0x140001000, source_path="sample.bin")
            plan = build_clean_plan(capture)

            artifacts = legacy_render_write_export_bundle(temp_dir, capture, plan)

            self.assertTrue(Path(artifacts["cleaned_pseudocode"]).exists())
            self.assertTrue(Path(artifacts["summary"]).exists())


if __name__ == "__main__":
    unittest.main()
