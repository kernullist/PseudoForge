import tempfile
import threading
import time
import unittest
from pathlib import Path

from ida_pseudoforge.config import (
    LlmConfig,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
    PreviewConfig,
    PseudoForgeConfig,
)
from ida_pseudoforge.core.plan_schema import (
    CleanPlan,
    FunctionCapture,
    LocalVariable,
    RenameSuggestion,
    make_lvar_identity,
)
from ida_pseudoforge.ida import actions as actions_module
from ida_pseudoforge.ida import apply_changes as apply_module
from ida_pseudoforge.ida import async_runner
from ida_pseudoforge.ida import decompiler as decompiler_module
from ida_pseudoforge.ida import llm_config_dialog
from ida_pseudoforge.ida import plugin as plugin_module
from ida_pseudoforge.ida import ui_preview as ui_preview_module
from ida_pseudoforge.ida.action_registry import ActionRegistry
from ida_pseudoforge.ida.analysis_state import PluginAnalysisSession, PluginAnalysisState, normalize_source_identity
from ida_pseudoforge.models.provider_registry import PROVIDER_CODEX_CLI
from ida_pseudoforge.version import VERSION


def _capture() -> FunctionCapture:
    return FunctionCapture(
        ea=0x140001000,
        name="sub_140001000",
        prototype="__int64 __fastcall sub_140001000(int a1)",
        pseudocode="__int64 __fastcall sub_140001000(int a1)\n{\n  int v1;\n  return v1;\n}",
        lvars=[
            LocalVariable("a1", "int", True, 0),
            LocalVariable("v1", "int", False, 1),
            LocalVariable("v2", "int", False, 2),
            LocalVariable("v3", "int", False, 3),
            LocalVariable("v4", "int", False, 4),
            LocalVariable("v5", "int", False, 5),
            LocalVariable("v6", "int", False, 6),
        ],
        source_path=r"F:\target\driver.sys",
    )


def _plan(capture: FunctionCapture) -> CleanPlan:
    return CleanPlan(
        function_ea=capture.ea,
        function_name=capture.name,
        input_fingerprint=capture.input_fingerprint(),
        renames=[
            RenameSuggestion("lvar", "v1", "renamedLocal", 0.95, "rule", "safe"),
            RenameSuggestion("lvar", "v2", "disabledLocal", 0.95, "rule", "disabled", apply=False),
            RenameSuggestion("comment", "v3", "commentText", 0.95, "rule", "not an IDB rename"),
            RenameSuggestion("lvar", "v4", "bad-name", 0.95, "rule", "invalid"),
            RenameSuggestion("lvar", "v5", "duplicateTarget", 0.95, "rule", "first duplicate"),
            RenameSuggestion("lvar", "v6", "duplicateTarget", 0.95, "rule", "second duplicate"),
        ],
    )


class FakeHexrays:
    def __init__(self) -> None:
        self.calls = []

    def rename_lvar(self, ea, old, new):
        self.calls.append((ea, old, new))
        return True


class FakeIdaApi:
    PLUGIN_KEEP = 1
    PLUGIN_SKIP = 0
    SETMENU_APP = 1

    def __init__(self) -> None:
        self.registered = []
        self.attached = []
        self.unregistered = []

    def action_desc_t(self, action_name, label, handler, hotkey, tooltip, icon):
        return {
            "name": action_name,
            "label": label,
            "handler": handler,
            "hotkey": hotkey,
            "tooltip": tooltip,
            "icon": icon,
        }

    def register_action(self, desc):
        self.registered.append(desc["name"])
        return True

    def attach_action_to_menu(self, menu_path, action_name, flags):
        self.attached.append((menu_path, action_name, flags))
        return True

    def unregister_action(self, action_name):
        self.unregistered.append(action_name)
        return True


class FakeHexraysPlugin:
    def init_hexrays_plugin(self):
        return True


class FakeKernwinPlugin:
    def __init__(self):
        self.created_menus = []

    def is_idaq(self):
        return True

    def create_menu(self, name, label, menupath=None):
        self.created_menus.append((name, label, menupath))
        return True


class FakeContextMenuHooks:
    def hook(self):
        return True

    def unhook(self):
        return True


class IdaPluginSafetyTests(unittest.TestCase):
    def tearDown(self):
        async_runner._ACTIVE_TASKS.clear()
        async_runner._ACTIVE_GROUPS.clear()
        actions_module._ANALYSIS_STATE.clear()

    def test_plugin_analysis_session_records_identity_and_fingerprint(self):
        capture = _capture()
        plan = _plan(capture)
        session = PluginAnalysisSession.from_capture_plan(
            capture,
            plan,
            target_path=capture.source_path,
            forge_path=r"F:\target\driver.forge",
            forge_text="forge text",
        )

        self.assertEqual(session.target_path, normalize_source_identity(capture.source_path))
        self.assertEqual(session.function_ea, capture.ea)
        self.assertEqual(session.function_name, capture.name)
        self.assertEqual(session.fingerprint, plan.input_fingerprint)
        self.assertTrue(session.matches_current(capture.source_path, capture.ea))
        self.assertFalse(session.matches_current(capture.source_path, capture.ea + 0x10))

        state = PluginAnalysisState()
        self.assertIs(state.set(session), session)
        self.assertIs(state.get(), session)
        state.clear()
        self.assertIsNone(state.get())

    def test_plugin_analysis_session_normalizes_windows_path_identity(self):
        capture = _capture()
        plan = _plan(capture)
        session = PluginAnalysisSession.from_capture_plan(
            capture,
            plan,
            target_path=r"F:/target/driver.sys",
        )

        self.assertTrue(session.matches_current(r"F:\target\driver.sys", capture.ea))
        self.assertFalse(session.matches_current(r"F:\target\other.sys", capture.ea))

    def test_preflight_rejects_invalid_colliding_and_unselected_renames(self):
        capture = _capture()
        plan = _plan(capture)
        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1", "v2", "v3", "v4", "v5", "v6", "missing"],
            known_lvar_names=[var.name for var in capture.lvars],
        )

        self.assertEqual([rename.old for rename in accepted], ["v1", "v5"])
        joined = "\n".join(rejected)
        self.assertIn("not marked apply-safe", joined)
        self.assertIn("cannot modify IDB", joined)
        self.assertIn("not a valid C identifier", joined)
        self.assertIn("duplicated", joined)
        self.assertIn("not in the plan", joined)

    def test_preflight_rejects_same_name_different_lvar_identity(self):
        capture = _capture()
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[
                RenameSuggestion(
                    "lvar",
                    "v1",
                    "renamedLocal",
                    0.95,
                    "rule",
                    "safe",
                    identity=make_lvar_identity("v1", "int", False, 1, "stack:-4"),
                )
            ],
        )
        captured_lvars = [
            LocalVariable("v1", "int", False, 1, "stack:-4", make_lvar_identity("v1", "int", False, 1, "stack:-4"))
        ]
        current_lvars = [
            LocalVariable("v1", "int", False, 2, "stack:-8", make_lvar_identity("v1", "int", False, 2, "stack:-8"))
        ]

        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1"],
            captured_lvars=captured_lvars,
            current_lvars=current_lvars,
        )

        self.assertEqual(accepted, [])
        self.assertEqual(rejected, ["Current local variable identity changed: v1"])

    def test_preflight_allows_matching_lvar_identity(self):
        capture = _capture()
        identity = make_lvar_identity("v1", "int", False, 1, "stack:-4")
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[
                RenameSuggestion(
                    "lvar",
                    "v1",
                    "renamedLocal",
                    0.95,
                    "rule",
                    "safe",
                    identity=identity,
                )
            ],
        )
        lvars = [LocalVariable("v1", "int", False, 1, "stack:-4", identity)]

        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1"],
            captured_lvars=lvars,
            current_lvars=lvars,
        )

        self.assertEqual([rename.old for rename in accepted], ["v1"])
        self.assertEqual(rejected, [])

    def test_preflight_uses_legacy_name_fallback_without_lvar_identity(self):
        capture = _capture()
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[RenameSuggestion("lvar", "v1", "renamedLocal", 0.95, "rule", "safe")],
        )
        legacy_lvars = [LocalVariable("v1", "int", False, 1)]

        accepted, rejected = apply_module.preflight_selected_renames(
            plan,
            ["v1"],
            captured_lvars=legacy_lvars,
            current_lvars=legacy_lvars,
        )

        self.assertEqual([rename.old for rename in accepted], ["v1"])
        self.assertEqual(rejected, [])

    def test_decompiler_lvar_identity_uses_stable_stack_location_anchor(self):
        class FakeLocation:
            def get_stkoff(self):
                return -16

            def __str__(self):
                return "<ida_hexrays.lvar_locator_t object at 0x1234>"

        class FakeLvar:
            name = "v1"
            type = "int"
            location = FakeLocation()

            def is_arg_var(self):
                return False

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        expected_identity = make_lvar_identity("v1", "int", False, 0, "stkoff:-16")
        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "stkoff:-16")
        self.assertEqual(lvars[0].identity, expected_identity)

    def test_decompiler_lvar_location_falls_back_to_lvar_scalar_anchor(self):
        class FakeLocation:
            def __str__(self):
                return "<ida_hexrays.lvar_locator_t object at 0x1234>"

        class FakeLvar:
            name = "v1"
            type = "int"
            location = FakeLocation()

            def is_arg_var(self):
                return False

            def get_reg(self):
                return 3

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "reg:3")

    def test_decompiler_lvar_location_ignores_unstable_object_address_text(self):
        class FakeLocation:
            def __str__(self):
                return "<ida_hexrays.lvar_locator_t object at 0x1234>"

        class FakeLvar:
            name = "v1"
            type = "int"
            location = FakeLocation()

            def is_arg_var(self):
                return False

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "")

    def test_decompiler_lvar_location_formats_definition_ea_anchor(self):
        class FakeLvar:
            name = "v1"
            type = "int"

            def is_arg_var(self):
                return False

            def get_defea(self):
                return 0x140001020

        class FakeCfunc:
            lvars = [FakeLvar()]

        lvars = decompiler_module._extract_lvars_from_cfunc(FakeCfunc())

        self.assertEqual(len(lvars), 1)
        self.assertEqual(lvars[0].location, "defea:0x140001020")

    def test_analysis_summary_includes_rule_report_diagnostics(self):
        capture = _capture()
        plan = _plan(capture)
        plan.rule_report = {
            "matched_rules": [{"rule_id": "one"}, {"rule_id": "two"}],
            "rewrite_emissions": [
                {"status": "applied"},
                {"status": "shadowed"},
                {"status": "rejected"},
            ],
            "load_errors": [{"path": "bad.json"}],
            "validation_errors": [{"path": "invalid.json"}],
        }

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn(
            "Rules: 2 matched, 1 rewrite(s) applied, 1 shadowed, 1 rejected, 1 load error(s), 1 validation error(s)",
            summary,
        )
        self.assertIn("Rule load errors:", summary)
        self.assertIn("- bad.json", summary)
        self.assertIn("Rule validation errors:", summary)
        self.assertIn("- invalid.json", summary)

    def test_analysis_summary_ignores_malformed_rule_report_rewrites(self):
        capture = _capture()
        plan = _plan(capture)
        plan.rule_report = {
            "matched_rules": [{"rule_id": "one"}],
            "rewrite_emissions": None,
        }

        summary = actions_module._format_analysis_summary(capture, plan)

        self.assertIn(
            "Rules: 1 matched, 0 rewrite(s) applied, 0 shadowed, 0 rejected, 0 load error(s), 0 validation error(s)",
            summary,
        )

    def test_apply_calls_rename_lvar_only_after_preflight_passes(self):
        capture = _capture()
        plan = _plan(capture)
        fake_hexrays = FakeHexrays()
        old_hexrays = apply_module.ida_hexrays
        old_run_on_main_thread = apply_module.run_on_main_thread
        apply_module.ida_hexrays = fake_hexrays
        apply_module.run_on_main_thread = lambda func, write=False: func()
        try:
            result = apply_module.apply_selected_renames(
                capture.ea,
                plan,
                ["v1", "v4", "v5", "v6"],
                known_lvar_names=[var.name for var in capture.lvars],
            )
        finally:
            apply_module.ida_hexrays = old_hexrays
            apply_module.run_on_main_thread = old_run_on_main_thread

        self.assertEqual(
            fake_hexrays.calls,
            [
                (capture.ea, "v1", "renamedLocal"),
                (capture.ea, "v5", "duplicateTarget"),
            ],
        )
        self.assertEqual(
            result.applied,
            [
                {"old": "v1", "new": "renamedLocal"},
                {"old": "v5", "new": "duplicateTarget"},
            ],
        )
        self.assertEqual(len(result.rejected), 2)

    def test_apply_refuses_stale_current_function_session(self):
        capture = _capture()
        session = PluginAnalysisSession.from_capture_plan(
            capture,
            _plan(capture),
            target_path=capture.source_path,
        )
        actions_module._ANALYSIS_STATE.set(session)
        warnings = []
        choose_calls = []
        old_current = actions_module._current_function_identity
        old_warning = actions_module.warning
        old_choose = actions_module.choose_renames
        old_apply = actions_module.apply_selected_renames
        actions_module._current_function_identity = lambda: (capture.ea + 0x20, "other_function")
        actions_module.warning = warnings.append
        actions_module.choose_renames = lambda plan: choose_calls.append(plan) or ["v1"]
        actions_module.apply_selected_renames = lambda *args, **kwargs: self.fail("stale apply reached IDB path")
        try:
            actions_module._apply_selected_renames_from_session()
        finally:
            actions_module._current_function_identity = old_current
            actions_module.warning = old_warning
            actions_module.choose_renames = old_choose
            actions_module.apply_selected_renames = old_apply

        self.assertFalse(choose_calls)
        self.assertEqual(len(warnings), 1)
        self.assertIn("current function no longer matches", warnings[0])

    def test_apply_refuses_identity_backed_rename_when_current_identity_unavailable(self):
        capture = _capture()
        identity = make_lvar_identity("v1", "int", False, 1, "stack:-4")
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[RenameSuggestion("lvar", "v1", "renamedLocal", 0.95, "rule", "safe", identity=identity)],
        )
        session = PluginAnalysisSession.from_capture_plan(capture, plan, target_path=capture.source_path)
        actions_module._ANALYSIS_STATE.set(session)
        warnings = []
        old_current = actions_module._current_function_identity
        old_target = actions_module._target_file_path
        old_warning = actions_module.warning
        old_info = actions_module.info
        old_choose = actions_module.choose_renames
        old_capture_lvars = actions_module.capture_current_lvars
        old_apply = actions_module.apply_selected_renames
        actions_module._current_function_identity = lambda: (capture.ea, capture.name)
        actions_module._target_file_path = lambda: Path(capture.source_path)
        actions_module.warning = warnings.append
        actions_module.info = lambda message: None
        actions_module.choose_renames = lambda plan: ["v1"]
        actions_module.capture_current_lvars = lambda: (_ for _ in ()).throw(RuntimeError("no lvars"))
        actions_module.apply_selected_renames = lambda *args, **kwargs: self.fail("identity-backed fallback reached IDB path")
        try:
            actions_module._apply_selected_renames_from_session()
        finally:
            actions_module._current_function_identity = old_current
            actions_module._target_file_path = old_target
            actions_module.warning = old_warning
            actions_module.info = old_info
            actions_module.choose_renames = old_choose
            actions_module.capture_current_lvars = old_capture_lvars
            actions_module.apply_selected_renames = old_apply

        self.assertEqual(len(warnings), 1)
        self.assertIn("identity could not be verified", warnings[0])

    def test_analyzed_functions_action_reads_cached_forge_without_opening_full_preview(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            forge_path.write_text("cached forge text", encoding="utf-8")
            old_paths = actions_module._target_and_forge_paths
            old_show = actions_module.show_analyzed_functions_from_text
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module.show_analyzed_functions_from_text = (
                lambda text, source_path=None, target_stem=None, source_title="": calls.append(
                    (text, source_path, target_stem, source_title)
                )
                or True
            )
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_analyzed_functions_for_current_target())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module.show_analyzed_functions_from_text = old_show
                actions_module.warning = old_warning

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "cached forge text")
        self.assertEqual(calls[0][1], forge_path)
        self.assertEqual(calls[0][2], "driver")
        self.assertFalse(warnings)

    def test_current_function_preview_reports_not_opened_without_cached_forge(self):
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (0x140001000, "sub_140001000")
            actions_module.warning = warnings.append
            try:
                self.assertFalse(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.warning = old_warning

        self.assertEqual(len(warnings), 1)
        self.assertIn("Run Analyze current function first", warnings[0])

    def test_current_function_preview_uses_active_session_for_side_by_side(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            capture = _capture()
            capture.source_path = str(target_path)
            plan = _plan(capture)
            cleaned_text = "__int64 __fastcall sub_140001000(int argument)\n{\n    return renamedLocal;\n}\n"
            forge_text = actions_module.write_forge_function(forge_path, target_path, capture, plan, cleaned_text)
            session = PluginAnalysisSession.from_capture_plan(
                capture,
                plan,
                target_path=target_path,
                forge_path=forge_path,
                forge_text=forge_text,
            )
            actions_module._ANALYSIS_STATE.set(session)
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_side_by_side = actions_module.side_by_side_preview_enabled
            old_show = actions_module.show_text_view
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (capture.ea, capture.name)
            actions_module.side_by_side_preview_enabled = lambda: True

            def fake_show(title, text, **kwargs):
                calls.append((title, text, kwargs))
                return "dockable_side_by_side"

            actions_module.show_text_view = fake_show
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.side_by_side_preview_enabled = old_side_by_side
                actions_module.show_text_view = old_show
                actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual(len(calls), 1)
        self.assertIn("PseudoForge: driver!sub_140001000 0x140001000", calls[0][0])
        self.assertEqual(calls[0][2]["reference_text"], capture.pseudocode)
        self.assertEqual(calls[0][2]["reference_title"], "Raw Hex-Rays pseudocode")
        self.assertEqual(calls[0][2]["content_title"], "PseudoForge cleaned pseudocode")
        self.assertIn("PseudoForge analyzed 0x140001000", calls[0][2]["summary_text"])

    def test_current_function_preview_uses_persisted_raw_for_side_by_side_without_active_session(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            capture = _capture()
            capture.source_path = str(target_path)
            plan = _plan(capture)
            actions_module.write_forge_function(
                forge_path,
                target_path,
                capture,
                plan,
                "__int64 __fastcall sub_140001000(int argument)\n{\n    return renamedLocal;\n}\n",
            )
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_side_by_side = actions_module.side_by_side_preview_enabled
            old_show = actions_module.show_text_view
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (capture.ea, capture.name)
            actions_module.side_by_side_preview_enabled = lambda: True
            actions_module.show_text_view = lambda title, text, **kwargs: calls.append((title, text, kwargs)) or "simple"
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.side_by_side_preview_enabled = old_side_by_side
                actions_module.show_text_view = old_show
                actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2]["reference_text"], capture.pseudocode.rstrip() + "\n")
        self.assertIn("raw pseudocode loaded from .forge", calls[0][2]["summary_text"])

    def test_current_function_preview_warns_when_side_by_side_has_no_stored_raw(self):
        calls = []
        warnings = []
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = Path(temp_dir) / "driver.sys"
            forge_path = Path(temp_dir) / "driver.forge"
            forge_path.write_text(
                """// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Target: driver.sys

// PSEUDOFORGE FUNCTION BEGIN ea=0x140001000 name=sub_140001000 fingerprint=legacy
__int64 __fastcall sub_140001000(int argument)
{
    return renamedLocal;
}
// PSEUDOFORGE FUNCTION END ea=0x140001000
""",
                encoding="utf-8",
            )
            old_paths = actions_module._target_and_forge_paths
            old_current = actions_module._current_function_identity
            old_side_by_side = actions_module.side_by_side_preview_enabled
            old_show = actions_module.show_text_view
            old_warning = actions_module.warning
            actions_module._target_and_forge_paths = lambda: (target_path, forge_path)
            actions_module._current_function_identity = lambda: (0x140001000, "sub_140001000")
            actions_module.side_by_side_preview_enabled = lambda: True
            actions_module.show_text_view = lambda title, text, **kwargs: calls.append((title, text, kwargs)) or "simple"
            actions_module.warning = warnings.append
            try:
                self.assertTrue(actions_module._show_cached_forge_for_current_function())
            finally:
                actions_module._target_and_forge_paths = old_paths
                actions_module._current_function_identity = old_current
                actions_module.side_by_side_preview_enabled = old_side_by_side
                actions_module.show_text_view = old_show
                actions_module.warning = old_warning

        self.assertEqual(len(warnings), 1)
        self.assertIn("stored raw Hex-Rays pseudocode", warnings[0])
        self.assertEqual(len(calls), 1)
        self.assertNotIn("reference_text", calls[0][2])

    def test_background_group_prevents_shared_state_overlap_and_cleans_up(self):
        started = threading.Event()
        release = threading.Event()

        def work():
            started.set()
            release.wait(5)

        self.assertTrue(async_runner.run_background("analyze", work, group_name="plugin_state"))
        self.assertTrue(started.wait(2))
        self.assertFalse(async_runner.run_background("export", lambda: None, group_name="plugin_state"))
        release.set()

        deadline = time.time() + 2
        while async_runner.active_group_task("plugin_state") and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(async_runner.active_group_task("plugin_state"), "")

    def test_background_cancel_request_stops_task_at_cooperative_checkpoint(self):
        task_name = "cancel_test"
        started = threading.Event()
        cancelled = threading.Event()

        def work():
            started.set()
            deadline = time.time() + 2
            while time.time() < deadline and not async_runner.cancel_requested(task_name):
                time.sleep(0.01)
            try:
                async_runner.raise_if_cancelled(task_name)
            except async_runner.CancellationRequested:
                cancelled.set()
                raise
            self.fail("cancelled background task should not continue past the checkpoint")

        self.assertTrue(async_runner.run_background(task_name, work, group_name="cancel_group"))
        self.assertTrue(started.wait(2))
        self.assertTrue(async_runner.request_group_cancel("cancel_group"))

        deadline = time.time() + 2
        while async_runner.active_group_task("cancel_group") and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(async_runner.active_group_task("cancel_group"), "")
        self.assertTrue(cancelled.is_set())
        self.assertFalse(async_runner.cancel_requested(task_name))

    def test_background_cancel_after_work_skips_success_callback(self):
        task_name = "cancel_after_work_test"
        started = threading.Event()
        requested = threading.Event()
        successes = []

        def work():
            started.set()
            self.assertTrue(async_runner.request_cancel(task_name))
            requested.set()
            return "done"

        self.assertTrue(async_runner.run_background(task_name, work, successes.append))
        self.assertTrue(started.wait(2))
        self.assertTrue(requested.wait(2))

        deadline = time.time() + 2
        while async_runner.cancel_requested(task_name) and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(successes, [])
        self.assertFalse(async_runner.cancel_requested(task_name))

    def test_analysis_cancellation_is_not_swallowed_by_forge_write_warning_path(self):
        old_capture = actions_module.capture_current_function
        old_set_source = actions_module._set_capture_source_path
        old_build = actions_module._build_plan_with_config
        old_write = actions_module._write_forge_snapshot
        capture = _capture()
        plan = _plan(capture)
        actions_module.capture_current_function = lambda: (capture, object())
        actions_module._set_capture_source_path = lambda captured: None
        actions_module._build_plan_with_config = lambda captured, task_name="": plan
        actions_module._write_forge_snapshot = lambda captured, built_plan: (_ for _ in ()).throw(
            async_runner.CancellationRequested("stop before forge write")
        )
        try:
            with self.assertRaises(async_runner.CancellationRequested):
                actions_module.analyze_current_function("direct_cancel_test")
        finally:
            actions_module.capture_current_function = old_capture
            actions_module._set_capture_source_path = old_set_source
            actions_module._build_plan_with_config = old_build
            actions_module._write_forge_snapshot = old_write

    def test_cancel_current_task_handler_requests_active_group_cancel(self):
        handler = actions_module.CancelCurrentTaskHandler()
        old_request = actions_module.request_group_cancel
        old_info = actions_module.info
        requested = []
        messages = []
        actions_module.request_group_cancel = lambda group: requested.append(group) or "analyze"
        actions_module.info = messages.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.request_group_cancel = old_request
            actions_module.info = old_info

        self.assertEqual(requested, [actions_module.PLUGIN_STATE_GROUP])
        self.assertEqual(len(messages), 1)
        self.assertIn("cancellation requested for analyze", messages[0])

    def test_action_registry_tracks_and_unregisters_actions(self):
        fake_idaapi = FakeIdaApi()
        registry = ActionRegistry(fake_idaapi)

        self.assertTrue(registry.register("pseudoforge:test", "Test", object(), "", "Test action"))
        self.assertTrue(registry.attach_menu("Edit/PseudoForge/Test", "pseudoforge:test"))
        registry.unregister_all()

        self.assertEqual(fake_idaapi.registered, ["pseudoforge:test"])
        self.assertEqual(fake_idaapi.attached, [("Edit/PseudoForge/Test", "pseudoforge:test", fake_idaapi.SETMENU_APP)])
        self.assertEqual(fake_idaapi.unregistered, ["pseudoforge:test", "pseudoforge:test"])
        self.assertEqual(registry.registered_actions, ())

    def test_plugin_menu_replaces_full_forge_preview_with_function_actions(self):
        fake_idaapi = FakeIdaApi()
        old_idaapi = plugin_module.idaapi
        old_kernwin = plugin_module.ida_kernwin
        old_hexrays = plugin_module.ida_hexrays
        old_start = plugin_module.start_output_logger
        old_stop = plugin_module.stop_output_logger
        old_hooks = plugin_module.ContextMenuHooks
        plugin_module.idaapi = fake_idaapi
        fake_kernwin = FakeKernwinPlugin()
        plugin_module.ida_kernwin = fake_kernwin
        plugin_module.ida_hexrays = FakeHexraysPlugin()
        plugin_module.start_output_logger = lambda: None
        plugin_module.stop_output_logger = lambda: None
        plugin_module.ContextMenuHooks = FakeContextMenuHooks
        plugin = plugin_module.PseudoForgePlugin()
        try:
            self.assertEqual(plugin.init(), fake_idaapi.PLUGIN_KEEP)
            attached_paths = [item[0] for item in fake_idaapi.attached]
            self.assertIn(plugin_module.PseudoForgePlugin.preview_current_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.analyzed_functions_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.cancel_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.configure_preview_action_name, fake_idaapi.registered)
            self.assertIn(plugin_module.PseudoForgePlugin.configure_profile_action_name, fake_idaapi.registered)
            self.assertNotIn(plugin_module.PseudoForgePlugin.legacy_preview_action_name, fake_idaapi.registered)
            attached_menu_actions = [(path, action_name) for path, action_name, _flags in fake_idaapi.attached]
            self.assertIn(("pseudoforge_menu", "PseudoForge", "Edit/"), fake_kernwin.created_menus)
            self.assertIn(("pseudoforge_advanced_menu", "Advanced", "Edit/PseudoForge/"), fake_kernwin.created_menus)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.analyze_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.preview_current_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.analyzed_functions_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.cancel_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.configure_preview_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/", plugin_module.PseudoForgePlugin.configure_profile_action_name), attached_menu_actions)
            self.assertIn(("Edit/PseudoForge/Advanced/", plugin_module.PseudoForgePlugin.apply_renames_action_name), attached_menu_actions)
            self.assertNotIn("Edit/PseudoForge/Preview cleaned pseudocode", attached_paths)
        finally:
            plugin.term()
            plugin_module.idaapi = old_idaapi
            plugin_module.ida_kernwin = old_kernwin
            plugin_module.ida_hexrays = old_hexrays
            plugin_module.start_output_logger = old_start
            plugin_module.stop_output_logger = old_stop
            plugin_module.ContextMenuHooks = old_hooks

    def test_plugin_run_opens_preview_configuration_fallback(self):
        old_handler = plugin_module.ConfigurePreviewModeHandler
        activated = []

        class FakeConfigurePreviewModeHandler:
            def activate(self, ctx):
                activated.append(ctx)
                return 1

        plugin_module.ConfigurePreviewModeHandler = FakeConfigurePreviewModeHandler
        try:
            self.assertEqual(plugin_module.PseudoForgePlugin().run(None), 1)
        finally:
            plugin_module.ConfigurePreviewModeHandler = old_handler

        self.assertEqual(activated, [None])

    def test_preview_cleanup_unregisters_preview_actions(self):
        fake_idaapi = FakeIdaApi()
        old_idaapi = ui_preview_module.idaapi
        ui_preview_module.idaapi = fake_idaapi
        ui_preview_module._ACTIONS_REGISTERED = True
        try:
            ui_preview_module.cleanup_preview_actions()
        finally:
            ui_preview_module.idaapi = old_idaapi

        self.assertIn("pseudoforge:preview_copy_all", fake_idaapi.unregistered)
        self.assertIn("pseudoforge:preview_save_as", fake_idaapi.unregistered)
        self.assertIn("pseudoforge:preview_functions", fake_idaapi.unregistered)
        self.assertFalse(ui_preview_module._ACTIONS_REGISTERED)

    def test_model_discovery_exception_uses_static_fallback(self):
        old_discover = llm_config_dialog.discover_provider_models
        llm_config_dialog.discover_provider_models = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            result = llm_config_dialog._safe_discover_models(PROVIDER_CODEX_CLI)
        finally:
            llm_config_dialog.discover_provider_models = old_discover

        self.assertIn("gpt-5", result.models)
        self.assertEqual(result.source, "static fallback")
        self.assertIn("model discovery failed", result.warning)

    def test_model_discovery_dialog_uses_nonblocking_background_refresh(self):
        old_discover = llm_config_dialog.discover_provider_models
        started = threading.Event()
        release = threading.Event()
        calls = []

        def fake_discover(*args, **kwargs):
            calls.append((args, kwargs))
            started.set()
            release.wait(2.0)
            return llm_config_dialog.ModelDiscoveryResult(
                models=["fresh-codex-model"],
                source="test catalog",
            )

        llm_config_dialog._reset_model_discovery_cache_for_tests()
        llm_config_dialog.discover_provider_models = fake_discover
        try:
            first = llm_config_dialog._model_options_for_dialog(PROVIDER_CODEX_CLI)
            self.assertIn("gpt-5", first.models)
            self.assertEqual("static fallback (background refresh pending)", first.source)
            self.assertTrue(started.wait(1.0))

            second = llm_config_dialog._model_options_for_dialog(PROVIDER_CODEX_CLI)
            self.assertEqual("static fallback (background refresh pending)", second.source)
            self.assertEqual(1, len(calls))

            release.set()
            deadline = time.time() + 2.0
            refreshed = None
            while time.time() < deadline:
                candidate = llm_config_dialog._model_options_for_dialog(PROVIDER_CODEX_CLI)
                if candidate.models == ["fresh-codex-model"]:
                    refreshed = candidate
                    break
                time.sleep(0.01)

            self.assertIsNotNone(refreshed)
            self.assertEqual("test catalog", refreshed.source)
        finally:
            release.set()
            llm_config_dialog.discover_provider_models = old_discover
            llm_config_dialog._reset_model_discovery_cache_for_tests()

    def test_configure_handler_does_not_save_when_dialog_fails(self):
        handler = actions_module.ConfigureLlmHandler()
        old_load = actions_module.load_config
        old_save = actions_module.save_config
        old_ask = actions_module.ask_llm_config
        old_warning = actions_module.warning
        warnings = []
        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=True))
        actions_module.save_config = lambda config: self.fail("save_config should not be called")
        actions_module.ask_llm_config = lambda config, warn: (_ for _ in ()).throw(RuntimeError("discovery failed"))
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.save_config = old_save
            actions_module.ask_llm_config = old_ask
            actions_module.warning = old_warning

        self.assertEqual(len(warnings), 1)
        self.assertIn("configuration failed", warnings[0])

    def test_configure_profile_directory_handler_saves_and_applies_selection(self):
        handler = actions_module.ConfigureProfileDirectoryHandler()
        old_load = actions_module.load_config
        old_save = actions_module.save_config
        old_ask = actions_module.ask_profile_dir
        old_configure = actions_module.configure_profile_dir
        old_summary = actions_module.format_profile_summary
        old_info = actions_module.info
        old_warning = actions_module.warning
        saved_configs = []
        configured = []
        messages = []
        warnings = []
        selected = r"F:\profiles\wdk26100"
        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        actions_module.save_config = lambda config: saved_configs.append(config) or Path(r"F:\ida\pseudoforge_config.json")
        actions_module.ask_profile_dir = lambda current, warn: selected
        actions_module.configure_profile_dir = lambda profile_dir: configured.append(profile_dir) or Path(profile_dir)
        actions_module.format_profile_summary = lambda profile_dir: "Profile directory: %s" % profile_dir
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.save_config = old_save
            actions_module.ask_profile_dir = old_ask
            actions_module.configure_profile_dir = old_configure
            actions_module.format_profile_summary = old_summary
            actions_module.info = old_info
            actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual([config.profile_dir for config in saved_configs], [selected])
        self.assertEqual(configured, [selected])
        self.assertEqual(len(messages), 1)
        self.assertIn("Profile directory: %s" % selected, messages[0])

    def test_configure_preview_mode_handler_saves_selection(self):
        handler = actions_module.ConfigurePreviewModeHandler()
        old_load = actions_module.load_config
        old_save = actions_module.save_config
        old_ask = actions_module.ask_preview_config
        old_summary = actions_module.format_preview_summary
        old_info = actions_module.info
        old_warning = actions_module.warning
        saved_configs = []
        messages = []
        warnings = []

        def fake_ask(config, warn):
            config.preview = PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE)
            return config

        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        actions_module.save_config = lambda config: saved_configs.append(config) or Path(r"F:\ida\pseudoforge_config.json")
        actions_module.ask_preview_config = fake_ask
        actions_module.format_preview_summary = lambda preview: "Preview mode: %s" % preview.backend
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.save_config = old_save
            actions_module.ask_preview_config = old_ask
            actions_module.format_preview_summary = old_summary
            actions_module.info = old_info
            actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual([config.preview.backend for config in saved_configs], [PREVIEW_BACKEND_SIDE_BY_SIDE])
        self.assertEqual(len(messages), 1)
        self.assertIn("Preview mode: %s" % PREVIEW_BACKEND_SIDE_BY_SIDE, messages[0])

    def test_build_plan_applies_configured_profile_dir_before_analysis(self):
        capture = _capture()
        old_load = actions_module.load_config
        old_configure = actions_module.configure_profile_dir
        old_build = actions_module.build_clean_plan
        configured = []
        selected = r"F:\profiles\wdk26100"
        actions_module.load_config = lambda: PseudoForgeConfig(
            llm=LlmConfig(enabled=False),
            profile_dir=selected,
        )
        actions_module.configure_profile_dir = lambda profile_dir: configured.append(profile_dir) or Path(profile_dir)
        actions_module.build_clean_plan = lambda captured: _plan(captured)
        try:
            plan = actions_module._build_plan_with_config(capture)
        finally:
            actions_module.load_config = old_load
            actions_module.configure_profile_dir = old_configure
            actions_module.build_clean_plan = old_build

        self.assertEqual(configured, [selected])
        self.assertEqual(plan.function_ea, capture.ea)

    def test_show_settings_includes_plugin_version(self):
        handler = actions_module.ShowSettingsHandler()
        old_load = actions_module.load_config
        old_info = actions_module.info
        old_warning = actions_module.warning
        messages = []
        warnings = []
        actions_module.load_config = lambda: PseudoForgeConfig(llm=LlmConfig(enabled=False))
        actions_module.info = messages.append
        actions_module.warning = warnings.append
        try:
            self.assertEqual(handler.activate(None), 1)
        finally:
            actions_module.load_config = old_load
            actions_module.info = old_info
            actions_module.warning = old_warning

        self.assertFalse(warnings)
        self.assertEqual(len(messages), 1)
        self.assertIn("Version: %s" % VERSION, messages[0])
        self.assertIn("Profile directory:", messages[0])
        self.assertIn("Preview mode:", messages[0])


if __name__ == "__main__":
    unittest.main()
