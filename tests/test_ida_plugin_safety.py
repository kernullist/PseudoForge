import tempfile
import threading
import time
import unittest
from pathlib import Path

from ida_pseudoforge.config import LlmConfig, PseudoForgeConfig
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
    def is_idaq(self):
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
        plugin_module.ida_kernwin = FakeKernwinPlugin()
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
            self.assertIn(plugin_module.PseudoForgePlugin.configure_profile_action_name, fake_idaapi.registered)
            self.assertNotIn(plugin_module.PseudoForgePlugin.legacy_preview_action_name, fake_idaapi.registered)
            self.assertIn("Edit/PseudoForge/Show current analysis result", attached_paths)
            self.assertIn("Edit/PseudoForge/Analyzed functions...", attached_paths)
            self.assertIn("Edit/PseudoForge/Configure profile directory", attached_paths)
            self.assertNotIn("Edit/PseudoForge/Preview cleaned pseudocode", attached_paths)
        finally:
            plugin.term()
            plugin_module.idaapi = old_idaapi
            plugin_module.ida_kernwin = old_kernwin
            plugin_module.ida_hexrays = old_hexrays
            plugin_module.start_output_logger = old_start
            plugin_module.stop_output_logger = old_stop
            plugin_module.ContextMenuHooks = old_hooks

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


if __name__ == "__main__":
    unittest.main()
