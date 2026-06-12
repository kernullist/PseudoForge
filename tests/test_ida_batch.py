from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.config import LlmConfig, ProviderCredential, PseudoForgeConfig
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tools.pseudoforge_ida_batch import (
    _apply_runtime_helper_aliases_to_batch_outputs,
    _batch_progress_record,
    _build_corpus_metadata,
    _build_plan_with_optional_llm,
    _cancel_file_requested,
    _function_file_stem,
    _render_cleaned_with_ida_postprocess,
    _write_compare_artifacts,
    _write_export_artifacts,
)
from tools import pseudoforge_ida_batch as ida_batch_module
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

    def test_ida_batch_corpus_metadata_degrades_without_ida_modules(self) -> None:
        metadata = _build_corpus_metadata(
            idb_path=None,
            target_path=Path("sample.i64"),
            selected_eas=[],
            max_strings=10,
            max_names=10,
        )

        self.assertEqual("pseudoforge_corpus_metadata_v1", metadata["schema"])
        self.assertEqual([], metadata["functions"])
        self.assertIn("imports", metadata)
        self.assertIn("segments", metadata)

    def test_ida_batch_exact_ea_file_limits_selection(self) -> None:
        class FakeFunc:
            def __init__(self, start_ea: int, flags: int = 0) -> None:
                self.start_ea = start_ea
                self.flags = flags

        class FakeIdaFuncs:
            @staticmethod
            def get_func(ea):
                if ea == 0x140200010:
                    return FakeFunc(0x140200008)
                return FakeFunc(int(ea))

            @staticmethod
            def get_func_name(ea):
                names = {
                    0x140200008: "LongTemplateSymbol",
                    0x140291E88: "BTreeRedistribute",
                }
                return names.get(int(ea), "")

        class FakeIdaUtils:
            @staticmethod
            def Functions():
                raise AssertionError("explicit EA selection should not enumerate all functions")

        old_ida_funcs = ida_batch_module.ida_funcs
        old_idautils = ida_batch_module.idautils
        ida_batch_module.ida_funcs = FakeIdaFuncs
        ida_batch_module.idautils = FakeIdaUtils
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                ea_file = Path(temp_dir) / "failed-eas.txt"
                ea_file.write_text(
                    "0x140200010 # normalizes to function start\n0x140291E88, 0x140291E88\n",
                    encoding="utf-8",
                )
                args = argparse.Namespace(
                    ea=[],
                    ea_file=str(ea_file),
                    start_ea="",
                    end_ea="",
                    name_regex="",
                    skip_lib_thunk=False,
                )

                selected = list(ida_batch_module._iter_function_eas(args, skip_eas={0x140291E88}))
        finally:
            ida_batch_module.ida_funcs = old_ida_funcs
            ida_batch_module.idautils = old_idautils

        self.assertEqual([0x140200008], selected)

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
        plan, status, error, error_class, error_summary = _build_plan_with_optional_llm(capture, FakeProvider())

        self.assertEqual(status, "ok")
        self.assertEqual(error, "")
        self.assertEqual(error_class, "")
        self.assertEqual(error_summary, "")
        self.assertTrue(any(item.source == "llm" and item.old == "v1" for item in plan.renames))

    def test_ida_batch_optional_llm_falls_back_on_provider_failure(self) -> None:
        class FailingProvider:
            def suggest_renames(self, capture):
                raise RuntimeError("provider unavailable")

        capture = capture_from_pseudocode(BATCH_BOOLEAN_SAMPLE)
        plan, status, error, error_class, error_summary = _build_plan_with_optional_llm(capture, FailingProvider())

        self.assertEqual(status, "fallback")
        self.assertIn("provider unavailable", error)
        self.assertEqual(error_class, "provider_failure")
        self.assertIn("provider unavailable", error_summary)
        self.assertIn("LLM rename assist failed; deterministic fallback used", plan.warnings[0])

    def test_ida_batch_optional_llm_reports_provider_cyber_policy_block(self) -> None:
        class FailingProvider:
            def suggest_renames(self, capture):
                raise RuntimeError(
                    "API Error: request violates Usage Policy and triggered cyber-related safeguards. "
                    "Request ID: req_policy_123"
                )

        capture = capture_from_pseudocode(BATCH_BOOLEAN_SAMPLE)
        plan, status, error, error_class, error_summary = _build_plan_with_optional_llm(capture, FailingProvider())

        self.assertEqual(status, "fallback")
        self.assertIn("Usage Policy", error)
        self.assertEqual(error_class, "cyber_policy_block")
        self.assertEqual(error_summary, "provider cyber policy block request_id=req_policy_123")
        self.assertIn("blocked by provider cyber policy", plan.warnings[0])

    def test_ida_batch_llm_context_drops_saved_local_key_but_keeps_explicit_override(self) -> None:
        old_load = ida_batch_module.load_config
        old_provider = ida_batch_module.build_rename_provider
        provider_calls = []

        ida_batch_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="ollama",
                base_url="http://localhost:11434/v1",
                model="llama3.2",
            ),
            credentials={
                "ollama": ProviderCredential(api_key="stale-local-key"),
            },
        )
        ida_batch_module.build_rename_provider = (
            lambda config, api_key="": provider_calls.append(api_key) or object()
        )
        try:
            args = argparse.Namespace(
                llm_renames=True,
                llm_provider="",
                llm_api_key="",
                llm_base_url="",
                llm_model="",
                llm_command="",
                llm_timeout=0,
            )
            provider, info = ida_batch_module._build_llm_context(args)
            self.assertIsNotNone(provider)
            self.assertEqual(info["provider"], "ollama")

            args.llm_api_key = "explicit-local-key"
            provider, info = ida_batch_module._build_llm_context(args)
            self.assertIsNotNone(provider)
            self.assertEqual(info["provider"], "ollama")
        finally:
            ida_batch_module.load_config = old_load
            ida_batch_module.build_rename_provider = old_provider

        self.assertEqual(provider_calls, ["", "explicit-local-key"])

    def test_ida_batch_llm_context_auto_uses_enabled_plugin_config(self) -> None:
        old_load = ida_batch_module.load_config
        old_provider = ida_batch_module.build_rename_provider
        provider_configs = []

        ida_batch_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="lm_studio",
                base_url="http://localhost:1234/v1",
                model="local-test-model",
                timeout_seconds=77,
            )
        )
        ida_batch_module.build_rename_provider = (
            lambda config, api_key="": provider_configs.append(config) or object()
        )
        try:
            args = argparse.Namespace(
                llm_renames=False,
                llm_renames_auto=True,
                require_configured_llm=True,
                llm_provider="",
                llm_api_key="",
                llm_base_url="",
                llm_model="",
                llm_command="",
                llm_timeout=0,
            )

            provider, info = ida_batch_module._build_llm_context(args)
        finally:
            ida_batch_module.load_config = old_load
            ida_batch_module.build_rename_provider = old_provider

        self.assertIsNotNone(provider)
        self.assertEqual(info["provider"], "lm_studio")
        self.assertEqual(info["model"], "local-test-model")
        self.assertEqual(info["timeout_seconds"], 77)
        self.assertEqual(provider_configs[0].base_url, "http://localhost:1234/v1")

    def test_ida_batch_llm_context_auto_fails_when_required_and_disabled(self) -> None:
        old_load = ida_batch_module.load_config
        ida_batch_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        try:
            args = argparse.Namespace(
                llm_renames=False,
                llm_renames_auto=True,
                require_configured_llm=True,
            )

            with self.assertRaisesRegex(RuntimeError, "disabled"):
                ida_batch_module._build_llm_context(args)
        finally:
            ida_batch_module.load_config = old_load

    def test_ida_batch_llm_context_auto_can_be_optional_when_disabled(self) -> None:
        old_load = ida_batch_module.load_config
        ida_batch_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        try:
            args = argparse.Namespace(
                llm_renames=False,
                llm_renames_auto=True,
                require_configured_llm=False,
            )

            provider, info = ida_batch_module._build_llm_context(args)
        finally:
            ida_batch_module.load_config = old_load

        self.assertIsNone(provider)
        self.assertFalse(info["enabled"])
        self.assertEqual(info["reason"], "plugin_llm_disabled")

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

    def test_ida_batch_export_artifacts_include_full_bundle_and_llm_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                BATCH_BOOLEAN_SAMPLE,
                name="BatchExport",
                ea=0x140001000,
            )
            plan = build_clean_plan(capture)
            cleaned = render_cleaned_pseudocode(capture, plan).replace("BatchExport", "BatchExportEdited")

            export = _write_export_artifacts(
                Path(temp_dir),
                capture,
                plan,
                cleaned,
                aliases={},
                llm_status="ok",
                llm_error="",
                llm_error_class="",
                llm_error_summary="",
                llm_info={"enabled": True, "provider": "ollama", "model": "llama3.2", "timeout_seconds": 60},
            )

            artifacts = export["artifacts"]
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            cleaned_text = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")

            self.assertEqual("ida_batch_export", export["mode"])
            self.assertTrue(Path(artifacts["rename_map"]).exists())
            self.assertTrue(Path(artifacts["raw_vs_cleaned_diff"]).exists())
            self.assertIn("BatchExportEdited", cleaned_text)
            self.assertEqual(summary["llm_status"], "ok")
            self.assertEqual(summary["llm_provider"], "ollama")

    def test_ida_batch_export_uses_short_paths_for_long_mangled_symbols(self) -> None:
        long_name = (
            "??$Write@U?$_tlgWrapperByVal@$07@@U?$_tlgWrapperByVal@$03@@"
            "U2@U?$_tlgWrapperByVal@$00@@U?$_tlgWrapperByRef@$0BA@@@"
            "U_tlgWrapperBinary@@U1@U3@U5@U1@U3@U5@U1@U3@U5@U1@"
            "U3@U5@U1@U3@U5@U1@U3@U5@U1@U3@U5@U1@U3@U5@U2@U3@@"
            "?$_tlgWriteTemplate@$$A6AJPEBU_tlgProvider_t@@PEBXPEBU_GUID@@"
            "2IPEAU_EVENT_DATA_DESCRIPTOR@@@Z$1?_tlgWriteTransfer_EtwWriteTransfer@@"
            "YAJ0122I3@ZPEBU2@PEBU2@@@SAJPEBU_tlgProvider_t@@PEBXPEBU_GUID@@"
            "2AEBU?$_tlgWrapperByVal@$07@@AEBU?$_tlgWrapperByVal@$03@@"
            "4AEBU?$_tlgWrapperByVal@$00@@AEBU?$_tlgWrapperByRef@$0BA@@@"
            "AEBU_tlgWrapperBinary@@35735735735735735735735745@Z"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                BATCH_BOOLEAN_SAMPLE,
                name=long_name,
                ea=0x140200008,
            )
            plan = build_clean_plan(capture)
            cleaned = render_cleaned_pseudocode(capture, plan)

            export = _write_export_artifacts(
                Path(temp_dir),
                capture,
                plan,
                cleaned,
                aliases={},
                llm_status="ok",
                llm_error="",
                llm_error_class="",
                llm_error_summary="",
                llm_info={"enabled": False},
            )

            function_dir = Path(export["directory"])
            self.assertTrue(function_dir.name.startswith("0000000140200008_"))
            self.assertLessEqual(len(function_dir.name), 81)
            self.assertEqual("function.cleaned.cpp", Path(export["artifacts"]["cleaned_pseudocode"]).name)
            self.assertEqual("function.ida-batch-summary.json", Path(export["artifacts"]["summary"]).name)
            for path in export["artifacts"].values():
                self.assertTrue(Path(path).exists(), path)
                self.assertLess(len(str(path)), 240)

            summary = json.loads(Path(export["artifacts"]["summary"]).read_text(encoding="utf-8"))
            self.assertEqual(long_name, summary["function"])

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

    def test_ida_batch_postprocess_updates_export_bundle_cleaned_and_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_dir = root / "functions"
            helper_dir = export_dir / "0000000180001000_sub_180001000"
            caller_dir = export_dir / "0000000180001100_Caller"
            helper_dir.mkdir(parents=True)
            caller_dir.mkdir(parents=True)
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
            (helper_dir / "sub_180001000.cleaned.cpp").write_text(helper_text, encoding="utf-8")
            (caller_dir / "Caller.cleaned.cpp").write_text(caller_text, encoding="utf-8")
            (caller_dir / "Caller.raw.cpp").write_text(caller_text, encoding="utf-8")

            result = _apply_runtime_helper_aliases_to_batch_outputs(
                root / "missing.forge",
                compare_dir=None,
                context_lines=1,
                export_dir=export_dir,
            )

            updated_caller = (caller_dir / "Caller.cleaned.cpp").read_text(encoding="utf-8")
            updated_diff = (caller_dir / "Caller.raw-vs-cleaned.diff").read_text(encoding="utf-8")
            self.assertEqual(result["status"], "ok")
            self.assertIn("memset(buffer, 0, 64LL);", updated_caller)
            self.assertIn("+  memset(buffer, 0, 64LL);", updated_diff)

    def test_ida_batch_render_uses_direct_helper_alias_postprocess(self) -> None:
        capture = capture_from_pseudocode(
            """
void __fastcall Caller()
{
  _BYTE localBuffer[64];

  sub_180001000(localBuffer, 0LL, 64LL);
}
""",
            name="Caller",
            ea=0x180001100,
            source_path=r"F:\target\driver.sys",
        )
        plan = build_clean_plan(capture)
        plan.warnings.append("sub_180001000 behaves like memset (dst,0,len)")
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
"""

        result = _render_cleaned_with_ida_postprocess(
            capture,
            plan,
            helper_text_loader=lambda name: helper_text if name == "sub_180001000" else None,
        )

        self.assertEqual([], result.plan.warnings)
        self.assertEqual("memset", result.aliases["sub_180001000"].alias_name)
        self.assertIn("Warnings: 0", result.cleaned)
        self.assertNotIn("behaves like memset", result.cleaned)
        self.assertIn("memset(localBuffer, 0, sizeof(localBuffer));", result.cleaned)
        self.assertNotIn("sub_180001000(localBuffer", result.cleaned)

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
