from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tools.pseudoforge_ida_batch import (
    _apply_runtime_helper_aliases_to_batch_outputs,
    _batch_progress_record,
    _build_plan_with_optional_llm,
    _cancel_file_requested,
    _function_file_stem,
    _write_compare_artifacts,
)
from tools.summarize_pseudoforge_ida_batch import summarize_records


BATCH_BOOLEAN_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(void *NotifyRoutine)
{
  PsSetCreateProcessNotifyRoutine(NotifyRoutine, 1u);
  return 0;
}
"""


class IdaBatchTests(unittest.TestCase):
    def test_ida_batch_report_summary_groups_statuses(self) -> None:
        records = [
            {"event": "start", "selected_functions": 3, "compare_dir": r"C:\tmp\compare"},
            {
                "event": "progress",
                "phase": "function_start",
                "index": 1,
                "selected_functions": 3,
                "ea": "0x1000",
                "name": "A",
            },
            {
                "event": "function",
                "status": "ok",
                "ea": "0x1000",
                "name": "A",
                "elapsed_seconds": 0.1,
                "comparison": {"raw_path": "raw.cpp", "diff_path": "raw.diff"},
                "llm_status": "ok",
            },
            {
                "event": "function",
                "status": "skipped",
                "ea": "0x2000",
                "name": "B",
                "reason": "Hex-Rays returned no cfunc",
                "elapsed_seconds": 0.2,
            },
            {
                "event": "function",
                "status": "ok",
                "ea": "0x3000",
                "name": "C",
                "warning_samples": ["review"],
                "warnings": 1,
                "elapsed_seconds": 0.3,
            },
            {"event": "stop", "reason": "cancel_file", "processed": 3},
            {"event": "summary", "processed": 3, "succeeded": 2, "skipped": 1, "failed": 0},
        ]

        summary = summarize_records(records, top=2)

        self.assertEqual(summary["status_counts"]["ok"], 2)
        self.assertEqual(summary["status_counts"]["skipped"], 1)
        self.assertEqual(summary["warning_groups"][0]["name"], "review")
        self.assertEqual(summary["skip_reasons"][0]["count"], 1)
        self.assertEqual(summary["slow_functions"][0]["name"], "C")
        self.assertEqual(summary["comparison_records"], 1)
        self.assertEqual(summary["llm_status_counts"]["ok"], 1)

    def test_ida_batch_optional_llm_plan_records_ok_status(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return '{"renames":[{"old":"v1","new":"computedValue","confidence":0.95,"reason":"return value"}]}'

        capture = capture_from_pseudocode(
            """
__int64 __fastcall LlmBatchSample(int a1)
{
  int v1;

  v1 = a1 + 1;
  return v1;
}
"""
        )
        plan, status, error = _build_plan_with_optional_llm(capture, FakeProvider())

        self.assertEqual(status, "ok")
        self.assertEqual(error, "")
        self.assertTrue(any(item.source == "llm" and item.old == "v1" for item in plan.renames))

    def test_ida_batch_optional_llm_falls_back_on_provider_failure(self) -> None:
        class FailingProvider:
            def suggest_renames(self, capture):
                raise RuntimeError("provider unavailable")

        capture = capture_from_pseudocode(BATCH_BOOLEAN_SAMPLE)
        plan, status, error = _build_plan_with_optional_llm(capture, FailingProvider())

        self.assertEqual(status, "fallback")
        self.assertIn("provider unavailable", error)
        self.assertIn("LLM rename assist failed; deterministic fallback used", plan.warnings[0])

    def test_ida_batch_compare_artifacts_include_raw_cleaned_and_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                BATCH_BOOLEAN_SAMPLE,
                name="Nt:Set<SystemInformation>?",
                ea=0x140AE1320,
            )
            plan = build_clean_plan(capture)
            cleaned = render_cleaned_pseudocode(capture, plan)
            section = render_forge_function_section(capture, plan, cleaned)

            comparison = _write_compare_artifacts(
                Path(temp_dir),
                capture.ea,
                capture.name,
                capture.pseudocode,
                cleaned,
                section,
                context_lines=1,
            )

            diff_text = Path(comparison["diff_path"]).read_text(encoding="utf-8")

            self.assertTrue(Path(comparison["raw_path"]).exists())
            self.assertTrue(Path(comparison["cleaned_path"]).exists())
            self.assertTrue(Path(comparison["forge_path"]).exists())
            self.assertTrue(Path(comparison["diff_path"]).exists())
            self.assertEqual("ida_batch", comparison["mode"])
            self.assertEqual("ida_batch_compare_v2", comparison["schema"])
            self.assertEqual(comparison["raw_path"], comparison["artifacts"]["raw_pseudocode"])
            self.assertEqual(comparison["cleaned_path"], comparison["artifacts"]["cleaned_pseudocode"])
            self.assertEqual(comparison["diff_path"], comparison["artifacts"]["raw_vs_cleaned_diff"])
            self.assertIn("raw/0000000140AE1320_Nt_Set_SystemInformation", diff_text)
            self.assertIn("+  PsSetCreateProcessNotifyRoutine(NotifyRoutine, TRUE);", diff_text)
            self.assertGreater(comparison["diff_lines"], 0)
            self.assertEqual(len(comparison["raw_sha256"]), 64)

    def test_ida_batch_compare_file_stem_is_windows_safe(self) -> None:
        stem = _function_file_stem(0x1234, "bad:name<with>|chars?and spaces")

        self.assertEqual(stem, "0000000000001234_bad_name_with_chars_and_spaces")

    def test_ida_batch_postprocess_aliases_runtime_memory_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            compare_dir = root / "compare"
            raw_dir = compare_dir / "raw"
            cleaned_dir = compare_dir / "cleaned"
            diff_dir = compare_dir / "diff"
            raw_dir.mkdir(parents=True)
            cleaned_dir.mkdir(parents=True)
            diff_dir.mkdir(parents=True)
            helper_name = "0000000180001000_sub_180001000.cpp"
            caller_name = "0000000180001100_Caller.cpp"
            helper_text = """
__int64 __fastcall sub_180001000(char *destination, unsigned __int8 fillByte, unsigned __int64 byteCount)
{
  __int64 result;
  __int64 fillPattern;

  result = (__int64)destination;
  fillPattern = 0x101010101010101LL * fillByte;
  if ( byteCount >= 4 )
  {
    *(_DWORD *)destination = fillPattern;
    *(_DWORD *)&destination[byteCount - 4] = fillPattern;
  }
  return result;
}
""".strip() + "\n"
            caller_text = """
void __fastcall Caller(char *buffer)
{
  sub_180001000(buffer, 0, 64LL);
}
""".strip() + "\n"
            (raw_dir / helper_name).write_text(helper_text, encoding="utf-8")
            (raw_dir / caller_name).write_text(caller_text, encoding="utf-8")
            (cleaned_dir / helper_name).write_text(helper_text, encoding="utf-8")
            (cleaned_dir / caller_name).write_text(caller_text, encoding="utf-8")

            result = _apply_runtime_helper_aliases_to_batch_outputs(root / "missing.forge", compare_dir, 1)

            updated_caller = (cleaned_dir / caller_name).read_text(encoding="utf-8")
            updated_diff = (diff_dir / caller_name.replace(".cpp", ".diff")).read_text(encoding="utf-8")
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["aliases"][0]["alias_name"], "memset")
            self.assertIn("memset(buffer, 0, 64LL);", updated_caller)
            self.assertIn("+  memset(buffer, 0, 64LL);", updated_diff)

    def test_ida_batch_progress_record_identifies_next_function(self) -> None:
        record = _batch_progress_record(0x140001000, "NtOpenProcess", 4, 25)

        self.assertEqual("progress", record["event"])
        self.assertEqual("function_start", record["phase"])
        self.assertEqual(4, record["index"])
        self.assertEqual(25, record["selected_functions"])
        self.assertEqual("0x140001000", record["ea"])
        self.assertEqual("NtOpenProcess", record["name"])

    def test_ida_batch_cancel_file_requested_after_sentinel_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cancel_file = Path(temp_dir) / "cancel.flag"

            self.assertFalse(_cancel_file_requested(cancel_file))
            cancel_file.write_text("stop\n", encoding="utf-8")

            self.assertTrue(_cancel_file_requested(cancel_file))


if __name__ == "__main__":
    unittest.main()
