from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.config import LlmConfig, ProviderCredential, PseudoForgeConfig
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.corpus_evidence import load_corpus_evidence
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import IrEvidence, IrLocalTypeSnapshot
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tools.pseudoforge_ida_batch import (
    _apply_runtime_helper_aliases_to_batch_outputs,
    _batch_progress_record,
    _batch_profile_context,
    _build_corpus_metadata,
    _build_plan_with_optional_llm,
    _cancel_file_requested,
    _function_file_stem,
    _llm_candidate_artifacts,
    _render_cleaned_with_ida_postprocess,
    _run_batch_type_assisted_preview,
    _write_compare_artifacts,
    _write_export_artifacts,
    _write_ida_replay_corpus_manifest,
)
from tools import pseudoforge_ida_batch as ida_batch_module
from tools.summarize_pseudoforge_ida_batch import summarize_records
from ida_pseudoforge.ida import actions as actions_module


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

    def test_ida_batch_function_metadata_records_data_refs(self) -> None:
        originals = {
            "_func_items": ida_batch_module._func_items,
            "_code_refs_from": ida_batch_module._code_refs_from,
            "_data_refs_from": ida_batch_module._data_refs_from,
            "_segment_name": ida_batch_module._segment_name,
            "_function_name": ida_batch_module._function_name,
            "_disasm_line_for_ea": ida_batch_module._disasm_line_for_ea,
            "_name_for_ea": ida_batch_module._name_for_ea,
        }
        try:
            ida_batch_module._func_items = lambda _ea: [0x140002010]
            ida_batch_module._code_refs_from = lambda _ea: []
            ida_batch_module._data_refs_from = lambda _ea: [0x140020000]
            ida_batch_module._segment_name = lambda ea: ".rdata" if ea == 0x140020000 else ".text"
            ida_batch_module._function_name = lambda _ea: "DeviceControlDispatch"
            ida_batch_module._disasm_line_for_ea = lambda _ea: "lea rcx, aDevicePseudoForge"
            ida_batch_module._name_for_ea = lambda _ea: "aDevicePseudoForge"

            metadata = ida_batch_module._collect_function_metadata(
                0x140002000,
                imports_by_ea={},
                strings_by_ea={0x140020000: {"ea": "0x140020000", "value": "\\Device\\PseudoForge"}},
                names_by_ea={0x140020000: {"ea": "0x140020000", "name": "aDevicePseudoForge"}},
            )
        finally:
            for name, value in originals.items():
                setattr(ida_batch_module, name, value)

        self.assertEqual(1, metadata["data_ref_count"])
        self.assertEqual("aDevicePseudoForge", metadata["data_refs"][0]["target_name"])
        self.assertEqual("string", metadata["data_refs"][0]["ref_kind"])
        self.assertEqual("\\Device\\PseudoForge", metadata["data_refs"][0]["value"])

    def test_ida_batch_profile_context_preserves_idb_arch_for_target_binary(self) -> None:
        context = _batch_profile_context(
            Path(r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"),
            Path(r"D:\bin\os\26200.8457\ntoskrnl.exe"),
        )

        self.assertEqual("ntoskrnl.exe", context["image"])
        self.assertEqual("26200.8457", context["build"])
        self.assertEqual("x64", context["arch"])

    def test_ida_batch_profile_context_uses_target_binary_version_build(self) -> None:
        def fake_profile_context(path_text: str) -> dict[str, object]:
            path = Path(path_text)
            if path.suffix.lower() == ".i64":
                return {"image": "ntoskrnl.exe", "arch": "x64"}
            return {"image": "ntoskrnl.exe", "build": "26100.8457"}

        original = ida_batch_module.profile_context_from_source_path
        ida_batch_module.profile_context_from_source_path = fake_profile_context
        try:
            context = _batch_profile_context(
                Path(r"F:\scratch\ntoskrnl.exe.i64"),
                Path(r"F:\scratch\ntoskrnl.exe"),
            )
        finally:
            ida_batch_module.profile_context_from_source_path = original

        self.assertEqual("ntoskrnl.exe", context["image"])
        self.assertEqual("26100.8457", context["build"])
        self.assertEqual("x64", context["arch"])

    def test_ida_batch_target_binary_context_keeps_domain_parameter_renames(self) -> None:
        context = _batch_profile_context(
            Path(r"D:\bin\os\26200.8457\ntoskrnl.exe.i64"),
            Path(r"D:\bin\os\26200.8457\ntoskrnl.exe"),
        )
        capture = capture_from_pseudocode(
            """
char __fastcall ExpReleaseResourceForThreadLite(ULONG_PTR BugCheckParameter1, ULONG_PTR BugCheckParameter3, __int64 a3, _DWORD *a4)
{
  KeGetCurrentIrql();
  *(_DWORD *)(BugCheckParameter1 + 56) = 1;
  *a4 = 0;
  return BugCheckParameter3 != 0;
}
""",
            source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe",
            profile_context=context,
        )

        plan = build_clean_plan(capture)
        active = {(item.old, item.new, item.source) for item in plan.active_renames()}

        self.assertIn(("BugCheckParameter1", "resource", "domain-profile"), active)
        self.assertIn(("BugCheckParameter3", "resourceThread", "domain-profile"), active)
        self.assertIn(("a4", "releaseState", "domain-profile"), active)

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

    def test_ida_batch_timeout_fallback_does_not_reuse_previous_candidate_artifact(self) -> None:
        class MixedProvider:
            def suggest_renames(self, capture):
                if capture.name == "TimeoutCandidate":
                    raise TimeoutError("LLM request timed out after 7 seconds")
                return '{"renames":[{"old":"v1","new":"cachedValue","confidence":0.95,"reason":"fixture"}]}'

        ok_capture = capture_from_pseudocode(
            """
__int64 __fastcall OkCandidate(int a1)
{
  int v1;

  v1 = a1 + 1;
  return v1;
}
""",
            name="OkCandidate",
            ea=0x140001000,
        )
        timeout_capture = capture_from_pseudocode(
            """
__int64 __fastcall TimeoutCandidate(int a1)
{
  int v1;

  v1 = a1 + 2;
  return v1;
}
""",
            name="TimeoutCandidate",
            ea=0x140002000,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            provider = ida_batch_module.LlmCandidateRecordingProvider(
                MixedProvider(),
                Path(temp_dir) / "llm-cache",
                provider_info={"provider": "fixture", "timeout_seconds": 7},
            )
            ok_plan, ok_status, _ok_error, _ok_error_class, _ok_error_summary = _build_plan_with_optional_llm(
                ok_capture,
                provider,
            )
            ok_artifacts = _llm_candidate_artifacts(provider, ok_capture)

            timeout_plan, timeout_status, timeout_error, timeout_error_class, timeout_error_summary = (
                _build_plan_with_optional_llm(timeout_capture, provider)
            )
            timeout_artifacts = _llm_candidate_artifacts(provider, timeout_capture)
            cleaned = render_cleaned_pseudocode(timeout_capture, timeout_plan)
            export = _write_export_artifacts(
                Path(temp_dir) / "functions",
                timeout_capture,
                timeout_plan,
                cleaned,
                aliases={},
                llm_status=timeout_status,
                llm_error=timeout_error,
                llm_error_class=timeout_error_class,
                llm_error_summary=timeout_error_summary,
                llm_info={"enabled": True, "provider": "fixture", "model": "test", "timeout_seconds": 7},
                llm_candidate_artifacts=timeout_artifacts,
            )

            summary = json.loads(Path(export["artifacts"]["summary"]).read_text(encoding="utf-8"))
            ok_cache_exists = Path(ok_artifacts["llm_candidate_cache"]).exists()

        self.assertEqual("ok", ok_status)
        self.assertTrue(ok_plan.active_renames())
        self.assertIn("llm_candidate_cache", ok_artifacts)
        self.assertTrue(ok_cache_exists)
        self.assertEqual("fallback", timeout_status)
        self.assertIn("timed out", timeout_error)
        self.assertEqual("timeout", timeout_error_class)
        self.assertIn("timed out", timeout_error_summary)
        self.assertIn("LLM rename assist failed; deterministic fallback used", timeout_plan.warnings[0])
        self.assertEqual({}, timeout_artifacts)
        self.assertEqual("fallback", summary["llm_status"])
        self.assertEqual("timeout", summary["llm_error_class"])
        self.assertEqual(7, summary["llm_timeout_seconds"])
        self.assertNotIn("llm_candidate_artifacts", summary)
        self.assertNotIn("llm_candidate_cache", summary["artifacts"])

    def test_ida_batch_replay_missing_candidate_cache_is_strict(self) -> None:
        capture = capture_from_pseudocode(BATCH_BOOLEAN_SAMPLE, name="MissingReplay", ea=0x140001000)
        with tempfile.TemporaryDirectory() as temp_dir:
            provider = ida_batch_module.LlmCandidateReplayProvider(temp_dir)

            with self.assertRaisesRegex(FileNotFoundError, "replay cache"):
                _build_plan_with_optional_llm(capture, provider)

    def test_ida_batch_llm_context_replay_bypasses_saved_config_requirement(self) -> None:
        old_load = ida_batch_module.load_config
        ida_batch_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                args = argparse.Namespace(
                    llm_renames=False,
                    llm_renames_auto=True,
                    require_configured_llm=True,
                    llm_candidate_replay_dir=temp_dir,
                    llm_candidate_cache_dir="",
                )

                provider, info = ida_batch_module._build_llm_context(args)
        finally:
            ida_batch_module.load_config = old_load

        self.assertIsNotNone(provider)
        self.assertTrue(getattr(provider, "strict_replay", False))
        self.assertEqual(info["mode"], "replay")
        self.assertEqual(info["provider"], "candidate_replay")

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

    def test_ida_batch_llm_context_clamps_reported_provider_timeout(self) -> None:
        old_load = ida_batch_module.load_config
        old_provider = ida_batch_module.build_rename_provider
        provider_configs = []

        ida_batch_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(
                enabled=True,
                provider="ollama",
                timeout_seconds=77,
            )
        )
        ida_batch_module.build_rename_provider = (
            lambda config, api_key="": provider_configs.append(config) or object()
        )
        try:
            args = argparse.Namespace(
                llm_renames=True,
                llm_renames_auto=False,
                require_configured_llm=False,
                llm_provider="",
                llm_api_key="",
                llm_base_url="",
                llm_model="",
                llm_command="",
                llm_timeout=999,
                llm_candidate_cache_dir="",
                llm_candidate_replay_dir="",
            )

            provider, info = ida_batch_module._build_llm_context(args)
        finally:
            ida_batch_module.load_config = old_load
            ida_batch_module.build_rename_provider = old_provider

        self.assertIsNotNone(provider)
        self.assertEqual(600, info["timeout_seconds"])
        self.assertEqual(600, provider_configs[0].timeout_seconds)

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
                llm_candidate_artifacts={"llm_candidate_cache": str(Path(temp_dir) / "cache.json")},
            )

            artifacts = export["artifacts"]
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            cleaned_text = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")

            self.assertEqual("ida_batch_export", export["mode"])
            self.assertTrue(Path(artifacts["rename_map"]).exists())
            self.assertTrue(Path(artifacts["raw_vs_cleaned_diff"]).exists())
            self.assertTrue(Path(artifacts["warning_diagnostics"]).exists())
            self.assertIn("BatchExportEdited", cleaned_text)
            self.assertEqual(summary["llm_status"], "ok")
            self.assertEqual(summary["llm_provider"], "ollama")
            self.assertEqual(summary["artifacts"]["llm_candidate_cache"], str(Path(temp_dir) / "cache.json"))
            self.assertEqual(summary["artifacts"]["warning_diagnostics"], artifacts["warning_diagnostics"])

    def test_ida_batch_export_can_write_full_disassembly_artifact(self) -> None:
        original = ida_batch_module._function_disassembly_text
        ida_batch_module._function_disassembly_text = (
            lambda _ea, _name: "; test disassembly\n0000000140001000  ret"
        )
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                capture = capture_from_pseudocode(
                    BATCH_BOOLEAN_SAMPLE,
                    name="BatchDisasmExport",
                    ea=0x140001000,
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

                artifacts = export["artifacts"]
                summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
                self.assertIn("disassembly", artifacts)
                self.assertIn("test disassembly", Path(artifacts["disassembly"]).read_text(encoding="utf-8"))
                self.assertEqual(artifacts["disassembly"], summary["artifacts"]["disassembly"])
        finally:
            ida_batch_module._function_disassembly_text = original

    def test_ida_batch_type_assisted_preview_writes_separate_artifacts(self) -> None:
        class FakeProposal:
            prototype = "void __stdcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)"
            profile_ids = ("windows.io_manager.delete_device",)
            evidence = ("function_identity:windows.io_manager.delete_device:exact_function_name",)
            blockers = ()
            corrections = ("param0 a1->deviceObject __int64->PDEVICE_OBJECT",)

        capture = capture_from_pseudocode(
            "__int64 __fastcall IoDeleteDevice(__int64 a1)\n{\n  return a1;\n}\n",
            name="IoDeleteDevice",
            ea=0x140002000,
            source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe",
        )
        plan = build_clean_plan(capture)
        current_type = {"value": "__int64 __fastcall IoDeleteDevice(__int64 a1);"}
        calls: list[tuple[str, str]] = []

        old_build = actions_module._build_type_assisted_prototype_proposal
        old_get = actions_module._get_ida_function_type
        old_apply = actions_module._apply_ida_function_type
        old_restore = actions_module._restore_ida_function_type
        old_refresh = actions_module._refresh_function_type_state
        old_decompile = actions_module._decompile_function_pseudocode
        old_equal = actions_module._ida_type_text_equal
        old_runner = actions_module.run_on_main_thread

        def fake_apply(ea: int, type_text: str) -> None:
            calls.append(("apply", type_text))
            current_type["value"] = type_text.rstrip(";") + ";"

        def fake_restore(ea: int, original_type: str) -> None:
            calls.append(("restore", original_type))
            current_type["value"] = original_type.rstrip(";") + ";"

        actions_module._build_type_assisted_prototype_proposal = lambda captured, built_plan: FakeProposal()
        actions_module._get_ida_function_type = lambda ea: current_type["value"]
        actions_module._apply_ida_function_type = fake_apply
        actions_module._restore_ida_function_type = fake_restore
        actions_module._refresh_function_type_state = lambda ea: None
        actions_module._decompile_function_pseudocode = (
            lambda ea: "void __stdcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)\n{\n  IopCompleteUnloadOrDelete((ULONG_PTR)deviceObject);\n}\n"
        )
        actions_module._ida_type_text_equal = (
            lambda left, right: left.rstrip(";") == right.rstrip(";")
        )
        actions_module.run_on_main_thread = lambda func, write=False: func()
        try:
            preview = _run_batch_type_assisted_preview(
                capture,
                plan,
                enabled=True,
                apply_validated_layout_rewrites=True,
            )
        finally:
            actions_module._build_type_assisted_prototype_proposal = old_build
            actions_module._get_ida_function_type = old_get
            actions_module._apply_ida_function_type = old_apply
            actions_module._restore_ida_function_type = old_restore
            actions_module._refresh_function_type_state = old_refresh
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._ida_type_text_equal = old_equal
            actions_module.run_on_main_thread = old_runner

        self.assertIsNotNone(preview)
        assert preview is not None
        self.assertEqual("ok", preview.status)
        self.assertTrue(preview.restore_succeeded)
        self.assertIn("PDEVICE_OBJECT deviceObject", preview.improved_pseudocode)
        self.assertIn("IoDeleteDevice", preview.cleaned_pseudocode)
        self.assertEqual(
            [
                ("apply", "void __stdcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)"),
                ("restore", "__int64 __fastcall IoDeleteDevice(__int64 a1);"),
            ],
            calls,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            export = _write_export_artifacts(
                Path(temp_dir),
                capture,
                plan,
                render_cleaned_pseudocode(capture, plan),
                aliases={},
                llm_status="disabled",
                llm_error="",
                llm_error_class="",
                llm_error_summary="",
                llm_info={"enabled": False},
                type_assisted_preview=preview,
            )
            artifacts = export["artifacts"]
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            primary_cleaned = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")
            deterministic_cleaned = Path(artifacts["deterministic_cleaned_pseudocode"]).read_text(
                encoding="utf-8"
            )

        self.assertIn("type_assisted_preview_summary", artifacts)
        self.assertIn("type_assisted_raw_pseudocode", artifacts)
        self.assertIn("type_assisted_cleaned_pseudocode", artifacts)
        self.assertIn("deterministic_cleaned_pseudocode", artifacts)
        self.assertIn("PDEVICE_OBJECT deviceObject", primary_cleaned)
        self.assertIn("__int64 __fastcall IoDeleteDevice(__int64 deviceObject)", deterministic_cleaned)
        self.assertEqual("type-assisted-preview", summary["primary_cleaned_source"])
        self.assertEqual("ok", summary["type_assisted_preview"]["status"])
        self.assertTrue(summary["type_assisted_preview"]["restore_succeeded"])

    def test_ida_batch_rejects_type_assisted_primary_quality_regression(self) -> None:
        deterministic_text = """
NTSTATUS __fastcall SeQuerySecurityAttributesToken(
        PACCESS_TOKEN token,
        PUNICODE_STRING attributeNames,
        ULONG attributeCount,
        PVOID attributeBuffer,
        SIZE_T inputLength,
        PULONG returnLength)
{
  ExAcquireResourceSharedLite(*(PERESOURCE *)(token + 48), TRUE);
  return SepInternalQuerySecurityAttributesTokenEx(token, attributeNames, attributeCount, attributeBuffer, inputLength, returnLength);
}
"""
        preview_text = """
NTSTATUS __fastcall SeQuerySecurityAttributesToken(
        PACCESS_TOKEN token,
        PUNICODE_STRING argument1,
        ULONG inputLength,
        PVOID argument3,
        SIZE_T attributeBufferLength,
        PULONG returnLength)
{
  ExAcquireResourceSharedLite(*((PERESOURCE *)token + 6), TRUE);
  return SepInternalQuerySecurityAttributesTokenEx(token, argument1, inputLength, argument3, attributeBufferLength, returnLength);
}
"""
        capture = capture_from_pseudocode(deterministic_text, name="SeQuerySecurityAttributesToken", ea=0x1409E0E90)
        plan = build_clean_plan(capture, rename_provider=None)
        preview = ida_batch_module._BatchTypeAssistedPreview(
            status="ok",
            proposal={"prototype": "NTSTATUS __fastcall SeQuerySecurityAttributesToken(PACCESS_TOKEN token)"},
            original_type="NTSTATUS __fastcall(PACCESS_TOKEN token)",
            restored_type="NTSTATUS __fastcall(PACCESS_TOKEN token)",
            restore_succeeded=True,
            improved_pseudocode=preview_text,
            cleaned_pseudocode=preview_text,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            export = _write_export_artifacts(
                Path(temp_dir),
                capture,
                plan,
                deterministic_text,
                aliases={},
                llm_status="disabled",
                llm_error="",
                llm_error_class="",
                llm_error_summary="",
                llm_info={"enabled": False},
                type_assisted_preview=preview,
            )
            artifacts = export["artifacts"]
            summary = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
            primary_cleaned = Path(artifacts["cleaned_pseudocode"]).read_text(encoding="utf-8")

        self.assertIn("type_assisted_cleaned_pseudocode", artifacts)
        self.assertNotIn("deterministic_cleaned_pseudocode", artifacts)
        self.assertEqual("deterministic", summary["primary_cleaned_source"])
        self.assertFalse(summary["type_assisted_primary_decision"]["selected"])
        self.assertEqual("quality_regression", summary["type_assisted_primary_decision"]["reason"])
        self.assertIn(
            "generic_parameter_name_regression",
            summary["type_assisted_primary_decision"]["regressions"],
        )
        self.assertIn(
            "pointer_indexed_offset_regression",
            summary["type_assisted_primary_decision"]["regressions"],
        )
        self.assertIn("attributeNames", primary_cleaned)
        self.assertNotIn("argument1", primary_cleaned)

    def test_ida_batch_type_assisted_preview_blocks_unrealized_temporary_type(self) -> None:
        class FakeProposal:
            prototype = "void __fastcall MiLockPageListAndLastPage(PMMPFN lastPage)"
            profile_ids = ("windows.memory_manager.lock_page_list_and_last_page",)
            evidence = ("function_identity:windows.memory_manager.lock_page_list_and_last_page:function_name",)
            blockers = ()
            corrections = ("param0 a1->lastPage __int64->PMMPFN",)

        capture = capture_from_pseudocode(
            "void __fastcall MiLockPageListAndLastPage(__int64 a1)\n{\n  *(_BYTE *)(a1 + 24) = 0;\n}\n",
            name="MiLockPageListAndLastPage",
            ea=0x1400219C30,
            source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe",
        )
        plan = build_clean_plan(capture)
        current_type = {"value": "void __fastcall(__int64)"}

        old_build = actions_module._build_type_assisted_prototype_proposal
        old_get = actions_module._get_ida_function_type
        old_apply = actions_module._apply_ida_function_type
        old_restore = actions_module._restore_ida_function_type
        old_refresh = actions_module._refresh_function_type_state
        old_decompile = actions_module._decompile_function_pseudocode
        old_equal = actions_module._ida_type_text_equal
        old_runner = actions_module.run_on_main_thread
        actions_module._build_type_assisted_prototype_proposal = lambda captured, built_plan: FakeProposal()
        actions_module._get_ida_function_type = lambda ea: current_type["value"]
        actions_module._apply_ida_function_type = lambda ea, type_text: current_type.update(
            {"value": type_text}
        )
        actions_module._restore_ida_function_type = lambda ea, original_type: current_type.update(
            {"value": original_type}
        )
        actions_module._refresh_function_type_state = lambda ea: None
        actions_module._decompile_function_pseudocode = (
            lambda ea: "void __fastcall MiLockPageListAndLastPage(__int64 a1)\n{\n  *(_BYTE *)(a1 + 24) = 0;\n}\n"
        )
        actions_module._ida_type_text_equal = lambda left, right: left == right
        actions_module.run_on_main_thread = lambda func, write=False: func()
        try:
            preview = _run_batch_type_assisted_preview(
                capture,
                plan,
                enabled=True,
                apply_validated_layout_rewrites=True,
            )
        finally:
            actions_module._build_type_assisted_prototype_proposal = old_build
            actions_module._get_ida_function_type = old_get
            actions_module._apply_ida_function_type = old_apply
            actions_module._restore_ida_function_type = old_restore
            actions_module._refresh_function_type_state = old_refresh
            actions_module._decompile_function_pseudocode = old_decompile
            actions_module._ida_type_text_equal = old_equal
            actions_module.run_on_main_thread = old_runner

        self.assertIsNotNone(preview)
        assert preview is not None
        self.assertEqual("blocked", preview.status)
        self.assertTrue(preview.restore_succeeded)
        self.assertIn("temporary prototype was not reflected", preview.error)
        self.assertIn("temporary_prototype_not_reflected", preview.proposal["blockers"])
        self.assertEqual("void __fastcall(__int64)", current_type["value"])

    def test_ida_batch_type_assisted_preview_blocks_unstable_unknown_original_type(self) -> None:
        class FakeProposal:
            prototype = "_UNKNOWN **__fastcall VmpFillGpnRanges(ULONG partitionId)"
            profile_ids = ("windows.memory_manager.vmp_fill_gpn_ranges",)
            evidence = ("function_identity:windows.memory_manager.vmp_fill_gpn_ranges:function_name",)
            blockers = ()
            corrections = ("param0 a1->partitionId int->ULONG",)

        capture = capture_from_pseudocode(
            "_UNKNOWN **__fastcall VmpFillGpnRanges(int a1)\n{\n  return 0;\n}\n",
            name="VmpFillGpnRanges",
            ea=0x1403A1450,
            source_path=r"D:\bin\os\26200.8457\ntoskrnl.exe",
        )
        plan = build_clean_plan(capture)
        calls: list[str] = []

        old_build = actions_module._build_type_assisted_prototype_proposal
        old_get = actions_module._get_ida_function_type
        old_apply = actions_module._apply_ida_function_type
        old_runner = actions_module.run_on_main_thread
        actions_module._build_type_assisted_prototype_proposal = lambda captured, built_plan: FakeProposal()
        actions_module._get_ida_function_type = (
            lambda ea: "_UNKNOWN **__fastcall(int, __int64, __int64, __int64 *, __int64, __int64)"
        )
        actions_module._apply_ida_function_type = (
            lambda ea, type_text: calls.append(type_text)
        )
        actions_module.run_on_main_thread = lambda func, write=False: func()
        try:
            preview = _run_batch_type_assisted_preview(
                capture,
                plan,
                enabled=True,
                apply_validated_layout_rewrites=True,
            )
        finally:
            actions_module._build_type_assisted_prototype_proposal = old_build
            actions_module._get_ida_function_type = old_get
            actions_module._apply_ida_function_type = old_apply
            actions_module.run_on_main_thread = old_runner

        self.assertIsNotNone(preview)
        assert preview is not None
        self.assertEqual("blocked", preview.status)
        self.assertTrue(preview.restore_succeeded)
        self.assertIn("unstable_original_type_unknown", preview.error)
        self.assertIn(
            "original_type_restore_blocked:unstable_original_type_unknown",
            preview.proposal["blockers"],
        )
        self.assertEqual([], calls)

    def test_ida_batch_summary_preserves_available_capture_ir_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            capture = capture_from_pseudocode(
                BATCH_BOOLEAN_SAMPLE,
                name="NtSetSystemInformation",
                ea=0x140001000,
            )
            capture.ir_evidence = IrEvidence(
                adapter="hexrays_cfunc_v1",
                source="hexrays_cfunc",
                available=True,
                local_type_snapshots=[
                    IrLocalTypeSnapshot(
                        name="NotifyRoutine",
                        type_text="PVOID",
                        source="hexrays_lvar_arg",
                        confidence=0.9,
                        evidence="fixture",
                    )
                ],
            )
            plan = build_clean_plan(capture)
            cleaned = render_cleaned_pseudocode(capture, plan)

            export = _write_export_artifacts(
                Path(temp_dir),
                capture,
                plan,
                cleaned,
                aliases={},
                llm_status="disabled",
                llm_error="",
                llm_error_class="",
                llm_error_summary="",
                llm_info={"enabled": False},
            )
            summary = json.loads(Path(export["artifacts"]["summary"]).read_text(encoding="utf-8"))

        self.assertEqual("hexrays_cfunc_v1", summary["ir_evidence_summary"]["adapter"])
        self.assertEqual("hexrays_cfunc", summary["ir_evidence_summary"]["source"])
        self.assertTrue(summary["ir_evidence_summary"]["available"])
        self.assertEqual(1, summary["ir_evidence_summary"]["local_type_snapshots"])

    def test_ida_batch_capture_function_by_name_attaches_hexrays_ir_evidence(self) -> None:
        class FakeLine:
            def __init__(self, line: str) -> None:
                self.line = line

        class FakeLvar:
            name = "fileHandle"
            type = "HANDLE"

            def is_arg_var(self) -> bool:
                return False

        class FakeCfunc:
            lvars = [FakeLvar()]

            def get_pseudocode(self):
                return [
                    FakeLine("__int64 __fastcall OpenFile(wchar_t *path)"),
                    FakeLine("{"),
                    FakeLine("  HANDLE fileHandle;"),
                    FakeLine("  fileHandle = CreateFileW(path, 0, 0, 0, 3, 0, 0);"),
                    FakeLine("  return fileHandle != 0;"),
                    FakeLine("}"),
                ]

        class FakeFunc:
            start_ea = 0x140001000

        class FakeIdaFuncs:
            @staticmethod
            def get_func(ea):
                return FakeFunc()

            @staticmethod
            def get_func_name(ea):
                return "OpenFile"

        class FakeHexrays:
            @staticmethod
            def decompile(func):
                return FakeCfunc()

        old_funcs = ida_batch_module.ida_funcs
        old_hexrays = ida_batch_module.ida_hexrays
        old_lookup = ida_batch_module._function_ea_by_name
        ida_batch_module.ida_funcs = FakeIdaFuncs
        ida_batch_module.ida_hexrays = FakeHexrays
        ida_batch_module._function_ea_by_name = lambda name: 0x140001000
        try:
            capture = ida_batch_module._capture_function_by_name("OpenFile", r"C:\bin\client.exe")
        finally:
            ida_batch_module.ida_funcs = old_funcs
            ida_batch_module.ida_hexrays = old_hexrays
            ida_batch_module._function_ea_by_name = old_lookup

        self.assertIsNotNone(capture)
        assert capture is not None
        self.assertTrue(capture.ir_evidence.available)
        self.assertEqual("hexrays_cfunc_v1", capture.ir_evidence.adapter)
        self.assertEqual("hexrays_cfunc", capture.ir_evidence.source)
        self.assertGreaterEqual(len(capture.ir_evidence.local_type_snapshots), 1)

    def test_ida_batch_writes_replay_corpus_manifest_from_export_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_dir = root / "functions"
            function_dir = export_dir / "0000000140001000_OpenFile"
            function_dir.mkdir(parents=True)
            (function_dir / "function.ida-batch-summary.json").write_text(
                json.dumps(
                    {
                        "mode": "ida_batch_export",
                        "function": "OpenFile",
                        "function_ea": "0x140001000",
                        "target_context": {"target_family": "windows_user_pe"},
                        "ir_evidence_summary": {
                            "schema": "pseudoforge_ir_evidence_v1",
                            "adapter": "hexrays_cfunc_v1",
                            "source": "hexrays_cfunc",
                            "available": True,
                            "use_def_chains": 1,
                            "value_ranges": 0,
                            "local_type_snapshots": 1,
                            "constant_origins": 0,
                            "call_site_signatures": 1,
                            "diagnostics": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            manifest_path = root / "pseudoforge-general-corpus-manifest.json"

            record = _write_ida_replay_corpus_manifest(
                manifest_path,
                export_dir,
                source_reference="ida-batch://unit-run",
                claim_eligible=True,
            )
            evidence = load_corpus_evidence([manifest_path])

        self.assertEqual("corpus_manifest", record["event"])
        self.assertEqual(1, record["corpora"])
        self.assertEqual(1, record["functions"])
        self.assertEqual(1, record["ir_evidence_functions"])
        self.assertEqual(1, evidence["real_corpus_count"])
        self.assertEqual(1, evidence["real_corpus_function_count"])
        self.assertEqual(1, evidence["ir_evidence_function_count"])
        self.assertEqual(0, evidence["qualified_ground_truth_pair_count"])

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
            self.assertIn("target_context", summary)
            self.assertEqual("", summary["target_context"]["source_path"])
            self.assertEqual("unknown", summary["target_context"]["format"])
            self.assertEqual(
                [
                    "cxx_runtime",
                    "firmware_uefi",
                    "generic_core",
                    "linux_elf_user",
                    "macos_macho_user",
                    "win_user_pe",
                    "windows_kernel",
                ],
                summary["active_domain_packs"],
            )
            self.assertEqual(
                summary["active_domain_packs"],
                summary["target_context"]["active_domain_packs"],
            )
            self.assertIn("generic_core", summary["eligible_domain_packs"])
            self.assertIn("domain_pack_activation_report", summary)

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
