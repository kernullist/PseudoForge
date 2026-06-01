from __future__ import annotations

import os
import re
from pathlib import Path

from ida_pseudoforge.config import (
    get_provider_api_key,
    load_config,
    save_config,
)
from ida_pseudoforge.core.export_bundle import write_export_bundle
from ida_pseudoforge.core.forge_store import (
    ForgeFunctionSection,
    find_forge_function_section,
    write_forge_function,
)
from ida_pseudoforge.core.helper_aliases import (
    RuntimeHelperAlias,
    apply_runtime_helper_aliases,
    infer_runtime_helper_aliases_from_texts,
    runtime_helper_alias_summary,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.normalize import extract_calls
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.rule_diagnostics import format_rule_report_summary
from ida_pseudoforge.ida.apply_changes import apply_selected_renames
from ida_pseudoforge.ida.analysis_state import PluginAnalysisSession, PluginAnalysisState
from ida_pseudoforge.ida.async_runner import (
    CancellationRequested,
    active_group_task,
    raise_if_cancelled,
    request_group_cancel,
    run_background,
)
from ida_pseudoforge.ida.decompiler import capture_current_function, capture_current_lvars, capture_function_by_name
from ida_pseudoforge.ida.llm_config_dialog import ask_llm_config, format_llm_summary
from ida_pseudoforge.ida.preview_config_dialog import ask_preview_config, format_preview_summary
from ida_pseudoforge.ida.profile_config_dialog import ask_profile_dir, format_profile_summary
from ida_pseudoforge.ida.thread_helpers import run_on_main_thread
from ida_pseudoforge.ida.ui_preview import (
    build_save_as_filename,
    choose_renames,
    info,
    side_by_side_preview_enabled,
    show_analyzed_functions_from_text,
    show_text_view,
    warning,
)
from ida_pseudoforge.logging import log_checkpoint, log_event, log_output, trace_scope
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    normalize_provider,
    provider_label,
)
from ida_pseudoforge.profiles.loader import DEFAULT_PROFILE_DIR, active_profile_root, configure_profile_dir
from ida_pseudoforge.version import VERSION

try:
    import ida_nalt  # type: ignore
    import ida_kernwin  # type: ignore
    import idaapi  # type: ignore
    import ida_funcs  # type: ignore
except Exception:
    ida_nalt = None
    ida_kernwin = None
    idaapi = None
    ida_funcs = None


PLUGIN_STATE_GROUP = "plugin_state"
_ANALYSIS_STATE = PluginAnalysisState()
_DIRECT_HELPER_ALIAS_MAX_CALLEES = 8
_DECOMPILER_HELPER_RE = re.compile(r"^(?:sub|j_sub)_[0-9A-Fa-f]+$")


def analyze_current_function(purpose: str = "analyze") -> tuple[FunctionCapture, CleanPlan]:
    with trace_scope("analysis", purpose=purpose):
        log_event("analysis.start purpose=%s" % _ascii_for_log(purpose))
        _raise_if_task_cancelled(purpose, "before capture")
        with trace_scope("analysis.capture", purpose=purpose):
            capture, _cfunc = capture_current_function()
        _raise_if_task_cancelled(purpose, "after capture")
        _set_capture_source_path(capture)
        log_event(
            "capture.ok function=\"%s\" ea=0x%X lvars=%d calls=%d"
            % (_ascii_for_log(capture.name), capture.ea, len(capture.lvars), len(capture.calls))
        )
        with trace_scope("analysis.build_plan", function=capture.name, ea="0x%X" % capture.ea):
            plan = _build_plan_with_config(capture, task_name=purpose)
        _raise_if_task_cancelled(purpose, "after build plan")
        forge_path: Path | None = None
        forge_text = ""
        try:
            with trace_scope("analysis.forge_write", function=capture.name, ea="0x%X" % capture.ea):
                _raise_if_task_cancelled(purpose, "before forge write")
                forge_path, forge_text = _write_forge_snapshot(capture, plan)
        except CancellationRequested:
            raise
        except Exception as exc:
            log_checkpoint("analysis.forge_write.warning", function=capture.name, ea="0x%X" % capture.ea, error=str(exc))
            log_event(
                "forge.write.failed function=\"%s\" ea=0x%X error=\"%s\""
                % (_ascii_for_log(capture.name), capture.ea, _ascii_for_log(str(exc)))
            )
            plan.warnings.insert(0, "Forge file write failed: %s" % exc)
        session = _store_analysis_session(capture, plan, forge_path, forge_text)
        log_event(
            "analysis.done function=\"%s\" ea=0x%X fingerprint=%s renames=%d flow_rewrites=%d warnings=%d"
            % (
                _ascii_for_log(capture.name),
                capture.ea,
                session.fingerprint[:16],
                len(plan.active_renames()),
                len(plan.flow_rewrites),
                len(plan.warnings),
            )
        )
        return capture, plan


def export_current_function() -> dict[str, str]:
    with trace_scope("export_current_function"):
        capture, plan = analyze_current_function(purpose="export")
        _raise_if_task_cancelled("export", "before output directory")
        with trace_scope("export.output_dir"):
            output_dir = run_on_main_thread(_default_output_dir, write=False)
        _raise_if_task_cancelled("export", "before bundle write")
        with trace_scope("export.write_bundle", function=capture.name, output_dir=str(output_dir)):
            paths = write_export_bundle(output_dir, capture, plan, entrypoint="ida_interactive")
        log_event("export.done function=\"%s\" output_dir=\"%s\"" % (_ascii_for_log(capture.name), output_dir))
        return paths


def _store_analysis_session(
    capture: FunctionCapture,
    plan: CleanPlan,
    forge_path: Path | None,
    forge_text: str,
) -> PluginAnalysisSession:
    target_path = capture.source_path
    if not target_path:
        try:
            target_path = str(run_on_main_thread(_target_file_path, write=False))
        except Exception:
            target_path = ""
    session = PluginAnalysisSession.from_capture_plan(
        capture,
        plan,
        target_path=target_path,
        forge_path=forge_path,
        forge_text=forge_text,
    )
    _ANALYSIS_STATE.set(session)
    return session


def _session_matches_current_function(session: PluginAnalysisSession) -> bool:
    current = _current_function_identity()
    if current is None:
        log_checkpoint("analysis.session.current_missing", function=session.function_name, ea="0x%X" % session.function_ea)
        return False
    current_ea, current_name = current
    try:
        target_path = run_on_main_thread(_target_file_path, write=False)
    except Exception:
        target_path = None
    matches = session.matches_current(target_path, current_ea)
    log_checkpoint(
        "analysis.session.match",
        session_function=session.function_name,
        current_function=current_name,
        session_ea="0x%X" % session.function_ea,
        current_ea="0x%X" % current_ea,
        matched=matches,
    )
    return matches


class AnalyzeCurrentFunctionHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.analyze.activate.before")
        log_output("PseudoForge analysis is running. Please wait...")
        def on_success(result):
            log_checkpoint("action.analyze.on_success.before")
            capture, plan = result
            log_output(
                "PseudoForge analysis completed: 0x%X, %d rename(s), %d flow rewrite(s), %d warning(s)."
                % (capture.ea, len(plan.renames), len(plan.flow_rewrites), len(plan.warnings))
            )
            info(_format_analysis_summary(capture, plan))
            log_output("PseudoForge opening analysis preview.")
            _show_analysis_preview(capture, plan)
            log_checkpoint("action.analyze.on_success.after")

        run_background("analyze", analyze_current_function, on_success, group_name=PLUGIN_STATE_GROUP)
        log_checkpoint("action.analyze.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class PreviewCurrentAnalyzedFunctionHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.preview_current_cached.activate.before")
        log_output("PseudoForge current analysis result requested. This does not call the LLM.")
        try:
            opened = _show_cached_forge_for_current_function()
        except Exception as exc:
            log_checkpoint("action.preview_current_cached.activate.failed", error=str(exc))
            warning("PseudoForge current analysis result failed: %s" % exc)
        else:
            if opened:
                log_output("PseudoForge current analysis result opened.")
            else:
                log_output("PseudoForge current analysis result was not opened.")
            log_checkpoint("action.preview_current_cached.activate.after", opened=opened)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ShowAnalyzedFunctionsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.analyzed_functions.activate.before")
        log_output("PseudoForge analyzed functions chooser requested. This does not call the LLM.")
        try:
            opened = _show_analyzed_functions_for_current_target()
        except Exception as exc:
            log_checkpoint("action.analyzed_functions.activate.failed", error=str(exc))
            warning("PseudoForge analyzed functions chooser failed: %s" % exc)
        else:
            if opened:
                log_output("PseudoForge analyzed function preview opened.")
            else:
                log_output("PseudoForge analyzed functions chooser closed.")
            log_checkpoint("action.analyzed_functions.activate.after", opened=opened)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ExportCleanedPseudocodeHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.export.activate.before")
        log_output("PseudoForge export is running. Please wait...")
        def on_success(paths):
            log_checkpoint("action.export.on_success.before")
            log_output("PseudoForge export completed.")
            info("PseudoForge exported:\n" + "\n".join(paths.values()))
            log_checkpoint("action.export.on_success.after")

        run_background("export", export_current_function, on_success, group_name=PLUGIN_STATE_GROUP)
        log_checkpoint("action.export.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class CancelCurrentTaskHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.cancel.activate.before")
        task_name = request_group_cancel(PLUGIN_STATE_GROUP)
        if task_name:
            info(
                "PseudoForge cancellation requested for %s. "
                "The current decompiler or provider call may finish before the task stops."
                % task_name
            )
            log_checkpoint("action.cancel.activate.after", cancelled=task_name)
        else:
            info("No PseudoForge analyze/export/apply task is running.")
            log_checkpoint("action.cancel.activate.after", cancelled="")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ApplySelectedRenamesHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.apply.activate.before")
        try:
            running_task = active_group_task(PLUGIN_STATE_GROUP)
            if running_task:
                log_output("PseudoForge %s is already running. Please wait..." % running_task)
                log_checkpoint("action.apply.activate.skipped", running=running_task)
                return 1
            if _ANALYSIS_STATE.get() is None:
                log_checkpoint("action.apply.prepare_queued.before")
                log_output("PseudoForge apply requires analysis. Analysis is running. Please wait...")

                def on_success(result):
                    log_checkpoint("action.apply.prepare_success.before")
                    _apply_selected_renames_from_session()
                    log_checkpoint("action.apply.prepare_success.after")

                run_background(
                    "apply",
                    lambda: analyze_current_function(purpose="apply"),
                    on_success,
                    group_name=PLUGIN_STATE_GROUP,
                )
                log_checkpoint("action.apply.prepare_queued.after")
                return 1

            _apply_selected_renames_from_session()
        except Exception as exc:
            log_checkpoint("action.apply.activate.failed", error=str(exc))
            warning(f"PseudoForge apply failed: {exc}")
        else:
            log_checkpoint("action.apply.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


def _apply_selected_renames_from_session() -> None:
    session = _ANALYSIS_STATE.get()
    if session is None:
        raise RuntimeError("No PseudoForge analysis result is available")
    if not _session_matches_current_function(session):
        message = (
            "PseudoForge apply refused: the current function no longer matches the analyzed function. "
            "Run Analyze current function again before applying renames."
        )
        warning(message)
        log_checkpoint("action.apply.stale_session", function=session.function_name, ea="0x%X" % session.function_ea)
        return

    log_checkpoint("action.apply.choose.before")
    selected = choose_renames(session.plan)
    log_checkpoint("action.apply.choose.after", selected=len(selected))
    if not selected:
        info("PseudoForge rename apply cancelled.")
        log_checkpoint("action.apply.cancelled")
        return

    log_checkpoint("action.apply.rename.before", selected=len(selected))
    current_lvars = None
    try:
        current_lvars = capture_current_lvars()
        known_lvar_names = [var.name for var in current_lvars if var.name] or None
    except Exception as exc:
        log_checkpoint("action.apply.current_lvars.warning", error=str(exc))
        if _selected_renames_have_identity(session.plan, selected):
            warning(
                "PseudoForge apply refused: current local variable identity could not be verified. "
                "Run Analyze current function again before applying identity-backed renames."
            )
            return
        known_lvar_names = [var.name for var in session.capture.lvars if var.name] or None
    result = apply_selected_renames(
        session.function_ea,
        session.plan,
        selected,
        known_lvar_names=known_lvar_names,
        captured_lvars=session.capture.lvars,
        current_lvars=current_lvars,
    )
    log_checkpoint("action.apply.rename.after", applied=len(result.applied), rejected=len(result.rejected))
    if result.rejected:
        log_output("PseudoForge rejected %d rename(s) during apply preflight." % len(result.rejected))
        warning("PseudoForge rejected rename(s):\n" + "\n".join(result.rejected[:8]))
    log_output("PseudoForge applied %d rename(s)." % len(result.applied))
    info("PseudoForge applied %d rename(s)." % len(result.applied))


def _selected_renames_have_identity(plan: CleanPlan, selected_old_names: list[str]) -> bool:
    selected = set(selected_old_names)
    return any(rename.old in selected and bool(rename.identity) for rename in plan.renames)


class ConfigureLlmHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.configure.activate.before")
        log_output("PseudoForge LLM configuration requested.")
        try:
            config = load_config()
            log_checkpoint("action.configure.ask.before")
            updated = ask_llm_config(config, warning)
            log_checkpoint("action.configure.ask.after", changed=updated is not None)
            if updated is None:
                info("PseudoForge LLM configuration unchanged.")
                log_output("PseudoForge LLM configuration unchanged.")
                log_checkpoint("action.configure.activate.after", changed=False)
                return 1
            log_checkpoint("action.configure.save.before")
            path = save_config(updated)
            log_checkpoint("action.configure.save.after", path=str(path))
            state = "enabled" if updated.llm.enabled else "disabled"
            info(
                "PseudoForge LLM rename assist %s.\nConfig: %s\n%s"
                % (state, path, format_llm_summary(updated.llm, updated))
            )
            log_output("PseudoForge LLM configuration saved.")
        except Exception as exc:
            log_checkpoint("action.configure.activate.failed", error=str(exc))
            warning(f"PseudoForge LLM configuration failed: {exc}")
        else:
            log_checkpoint("action.configure.activate.after", changed=True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ConfigureProfileDirectoryHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.configure_profile.activate.before")
        log_output("PseudoForge profile directory configuration requested.")
        try:
            config = load_config()
            log_checkpoint("action.configure_profile.ask.before")
            selected = ask_profile_dir(config.profile_dir, warning)
            log_checkpoint("action.configure_profile.ask.after", changed=selected is not None)
            if selected is None:
                info("PseudoForge profile directory unchanged.")
                log_output("PseudoForge profile directory unchanged.")
                log_checkpoint("action.configure_profile.activate.after", changed=False)
                return 1
            config.profile_dir = selected
            log_checkpoint("action.configure_profile.apply.before", profile_dir=selected or "(default/env)")
            configure_profile_dir(config.profile_dir)
            log_checkpoint("action.configure_profile.save.before")
            path = save_config(config)
            log_checkpoint("action.configure_profile.save.after", path=str(path))
            info(
                "PseudoForge profile directory configured.\nConfig: %s\n%s"
                % (path, format_profile_summary(config.profile_dir))
            )
            log_output("PseudoForge profile directory configuration saved.")
        except Exception as exc:
            log_checkpoint("action.configure_profile.activate.failed", error=str(exc))
            warning(f"PseudoForge profile directory configuration failed: {exc}")
        else:
            log_checkpoint("action.configure_profile.activate.after", changed=True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ConfigurePreviewModeHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.configure_preview.activate.before")
        log_output("PseudoForge preview mode configuration requested.")
        try:
            config = load_config()
            log_checkpoint("action.configure_preview.ask.before")
            updated = ask_preview_config(config, warning)
            log_checkpoint("action.configure_preview.ask.after", changed=updated is not None)
            if updated is None:
                info("PseudoForge preview mode unchanged.")
                log_output("PseudoForge preview mode unchanged.")
                log_checkpoint("action.configure_preview.activate.after", changed=False)
                return 1
            log_checkpoint("action.configure_preview.save.before")
            path = save_config(updated)
            log_checkpoint("action.configure_preview.save.after", path=str(path))
            info(
                "PseudoForge preview mode configured.\nConfig: %s\n%s"
                % (path, format_preview_summary(updated.preview))
            )
            log_output("PseudoForge preview mode configuration saved.")
        except Exception as exc:
            log_checkpoint("action.configure_preview.activate.failed", error=str(exc))
            warning(f"PseudoForge preview mode configuration failed: {exc}")
        else:
            log_checkpoint("action.configure_preview.activate.after", changed=True)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


class ShowSettingsHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        log_checkpoint("action.show_settings.activate.before")
        log_output("PseudoForge settings requested.")
        try:
            config = load_config()
            state = "enabled" if config.llm.enabled else "disabled"
            info(
                "PseudoForge settings\n"
                "Version: %s\n"
                "Config: %s\n"
                "%s\n"
                "%s\n"
                "LLM rename assist: %s\n"
                "%s"
                % (
                    VERSION,
                    _safe_config_path_text(),
                    format_profile_summary(config.profile_dir),
                    format_preview_summary(config.preview),
                    state,
                    format_llm_summary(config.llm, config),
                )
            )
        except Exception as exc:
            log_checkpoint("action.show_settings.activate.failed", error=str(exc))
            warning(f"PseudoForge settings display failed: {exc}")
        else:
            log_checkpoint("action.show_settings.activate.after")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


def _default_output_dir() -> Path:
    if idaapi is not None:
        try:
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            if idb_path:
                return Path(idb_path).with_suffix("").parent / "pseudoforge_out"
        except Exception:
            pass
    return Path.cwd() / "pseudoforge_out"


def _write_forge_snapshot(capture: FunctionCapture, plan: CleanPlan) -> tuple[Path, str]:
    target_path, forge_path = run_on_main_thread(_target_and_forge_paths, write=False)
    cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
    forge_text = write_forge_function(forge_path, target_path, capture, plan, cleaned)
    log_event(
        "forge.write path=\"%s\" function=\"%s\" ea=0x%X chars=%d"
        % (_ascii_for_log(str(forge_path)), _ascii_for_log(capture.name), capture.ea, len(forge_text))
    )
    return forge_path, forge_text


def _render_cleaned_with_direct_helper_aliases(capture: FunctionCapture, plan: CleanPlan) -> str:
    cleaned = render_cleaned_pseudocode(capture, plan)
    aliases = _direct_runtime_helper_aliases(cleaned, capture)
    if not aliases:
        return cleaned
    log_event(
        "analysis.helper_aliases function=\"%s\" ea=0x%X aliases=%s"
        % (_ascii_for_log(capture.name), capture.ea, _ascii_for_log(str(runtime_helper_alias_summary(aliases))))
    )
    return apply_runtime_helper_aliases(cleaned, aliases)


def _direct_runtime_helper_aliases(cleaned: str, capture: FunctionCapture) -> dict[str, RuntimeHelperAlias]:
    helper_texts = []
    for call_name in _direct_decompiler_helper_calls(cleaned, capture.name):
        if len(helper_texts) >= _DIRECT_HELPER_ALIAS_MAX_CALLEES:
            break
        try:
            helper_capture = capture_function_by_name(call_name)
        except Exception as exc:
            log_event(
                "analysis.helper_alias.capture_failed caller=\"%s\" callee=\"%s\" error=\"%s\""
                % (_ascii_for_log(capture.name), _ascii_for_log(call_name), _ascii_for_log(str(exc)))
            )
            continue
        if helper_capture is None or helper_capture.ea == capture.ea:
            continue
        try:
            helper_plan = build_clean_plan(helper_capture)
            helper_texts.append(render_cleaned_pseudocode(helper_capture, helper_plan))
        except Exception as exc:
            log_event(
                "analysis.helper_alias.render_failed caller=\"%s\" callee=\"%s\" error=\"%s\""
                % (_ascii_for_log(capture.name), _ascii_for_log(call_name), _ascii_for_log(str(exc)))
            )
    return infer_runtime_helper_aliases_from_texts(helper_texts)


def _direct_decompiler_helper_calls(text: str, current_name: str) -> list[str]:
    result = []
    seen = set()
    for call_name in extract_calls(text):
        if call_name == current_name or not _DECOMPILER_HELPER_RE.match(call_name):
            continue
        if call_name in seen:
            continue
        seen.add(call_name)
        result.append(call_name)
    return result


def _set_capture_source_path(capture: FunctionCapture) -> None:
    if capture.source_path:
        return
    try:
        capture.source_path = str(run_on_main_thread(_target_file_path, write=False))
    except Exception:
        capture.source_path = ""


def _target_and_forge_paths() -> tuple[Path, Path]:
    target_path = _target_file_path()
    return target_path, target_path.with_suffix(".forge")


def _target_file_path() -> Path:
    raw_path = ""
    if ida_nalt is not None:
        try:
            raw_path = ida_nalt.get_input_file_path() or ""
        except Exception:
            raw_path = ""
    if not raw_path and idaapi is not None:
        getter = getattr(idaapi, "get_input_file_path", None)
        if callable(getter):
            try:
                raw_path = getter() or ""
            except Exception:
                raw_path = ""

    idb_path = _idb_path()
    if raw_path:
        target_path = Path(raw_path)
        if target_path.is_absolute():
            return target_path
        if idb_path is not None:
            return idb_path.parent / target_path.name
        return Path.cwd() / target_path.name
    if idb_path is not None:
        return idb_path
    return Path.cwd() / "pseudoforge.bin"


def _show_analyzed_functions_for_current_target() -> bool:
    log_event("preview.functions_menu.enter")
    try:
        _target_path, forge_path = _target_and_forge_paths()
    except Exception as exc:
        log_event("preview.functions_menu.unavailable error=\"%s\"" % _ascii_for_log(str(exc)))
        return False

    log_event(
        "preview.functions_menu.path path=\"%s\" exists=%d"
        % (_ascii_for_log(str(forge_path)), int(forge_path.exists()))
    )
    if not forge_path.exists():
        warning(
            "No cached PseudoForge analysis file was found for %s. Run Analyze current function first."
            % _target_path.name
        )
        log_event("preview.functions_menu.no_forge path=\"%s\"" % _ascii_for_log(str(forge_path)))
        return False

    try:
        text = forge_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        warning("PseudoForge failed to read cached analysis: %s" % exc)
        log_event(
            "preview.functions_menu.read_failed path=\"%s\" error=\"%s\""
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(str(exc)))
        )
        return False

    opened = show_analyzed_functions_from_text(
        text,
        source_path=forge_path,
        target_stem=_target_path.stem,
        source_title="PseudoForge: %s analyzed functions" % forge_path.name,
    )
    log_event(
        "preview.functions_menu.show path=\"%s\" chars=%d opened=%d"
        % (_ascii_for_log(str(forge_path)), len(text), int(opened))
    )
    return opened


def _show_analysis_preview(capture: FunctionCapture, plan: CleanPlan) -> None:
    try:
        target_path, forge_path = _target_and_forge_paths()
    except Exception as exc:
        log_event("preview.analysis.unavailable error=\"%s\"" % _ascii_for_log(str(exc)))
        cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
        show_text_view(
            "PseudoForge: %s 0x%X" % (capture.name, capture.ea),
            cleaned,
            suggested_filename=build_save_as_filename("pseudoforge", capture.name, capture.ea),
            copy_from_source=False,
            reference_text=capture.pseudocode,
            reference_title="Raw Hex-Rays pseudocode",
            content_title="PseudoForge cleaned pseudocode",
            summary_text=_format_analysis_summary(capture, plan),
        )
        return

    if side_by_side_preview_enabled():
        cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
        target_stem = target_path.stem
        show_text_view(
            "PseudoForge: %s!%s 0x%X" % (target_stem, capture.name, capture.ea),
            cleaned,
            source_path=forge_path if forge_path.exists() else None,
            suggested_filename=build_save_as_filename(target_stem, capture.name, capture.ea),
            copy_from_source=False,
            target_stem=target_stem,
            reference_text=capture.pseudocode,
            reference_title="Raw Hex-Rays pseudocode",
            content_title="PseudoForge cleaned pseudocode",
            summary_text=_format_analysis_summary(capture, plan),
        )
        return

    session = _ANALYSIS_STATE.get()
    if (
        session is not None
        and session.function_ea == capture.ea
        and session.forge_text
        and _show_forge_section_text(target_path, forge_path, session.forge_text, capture.ea, capture.name)
    ):
        return

    if forge_path.exists():
        try:
            forge_text = forge_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            log_event(
                "preview.analysis.read_failed path=\"%s\" error=\"%s\""
                % (_ascii_for_log(str(forge_path)), _ascii_for_log(str(exc)))
            )
        else:
            if _show_forge_section_text(target_path, forge_path, forge_text, capture.ea, capture.name):
                return

    cleaned = _render_cleaned_with_direct_helper_aliases(capture, plan)
    target_stem = target_path.stem
    show_text_view(
        "PseudoForge: %s!%s 0x%X" % (target_stem, capture.name, capture.ea),
        cleaned,
        source_path=forge_path if forge_path.exists() else None,
        suggested_filename=build_save_as_filename(target_stem, capture.name, capture.ea),
        copy_from_source=False,
        target_stem=target_stem,
        reference_text=capture.pseudocode,
        reference_title="Raw Hex-Rays pseudocode",
        content_title="PseudoForge cleaned pseudocode",
        summary_text=_format_analysis_summary(capture, plan),
    )
    log_event(
        "preview.analysis.fallback function=\"%s\" ea=0x%X"
        % (_ascii_for_log(capture.name), capture.ea)
    )


def _show_cached_forge_for_current_function() -> bool:
    log_event("preview.cached_function.enter")
    try:
        target_path, forge_path = _target_and_forge_paths()
    except Exception as exc:
        log_event("preview.cached_function.unavailable error=\"%s\"" % _ascii_for_log(str(exc)))
        return False

    current = _current_function_identity()
    if current is None:
        warning("PseudoForge could not identify the current function.")
        log_event("preview.cached_function.no_current_function")
        return False

    current_ea, current_name = current
    if not forge_path.exists():
        warning(
            "No cached PseudoForge analysis file was found for %s. Run Analyze current function first."
            % target_path.name
        )
        log_event(
            "preview.cached_function.no_forge path=\"%s\" function=\"%s\" ea=0x%X"
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(current_name), current_ea)
        )
        return False

    try:
        forge_text = forge_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        warning("PseudoForge failed to read cached analysis: %s" % exc)
        log_event(
            "preview.cached_function.read_failed path=\"%s\" error=\"%s\""
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(str(exc)))
        )
        return False

    section = find_forge_function_section(forge_text, current_ea)
    if section is None:
        warning(
            "No cached PseudoForge analysis exists for %s 0x%X. Run Analyze current function first."
            % (current_name, current_ea)
        )
        log_event(
            "preview.cached_function.miss path=\"%s\" function=\"%s\" ea=0x%X"
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(current_name), current_ea)
        )
        return False

    if _show_cached_side_by_side_section(
        target_path,
        forge_path,
        section,
        _ANALYSIS_STATE.get(),
        "preview.cached_function",
    ):
        return True

    _show_forge_section(target_path, forge_path, section, "preview.cached_function")
    return True


def _show_forge_section_text(
    target_path: Path,
    forge_path: Path,
    forge_text: str,
    function_ea: int,
    function_name: str,
) -> bool:
    section = find_forge_function_section(forge_text, function_ea)
    if section is None:
        log_event(
            "preview.section.miss path=\"%s\" function=\"%s\" ea=0x%X"
            % (_ascii_for_log(str(forge_path)), _ascii_for_log(function_name), function_ea)
        )
        return False
    _show_forge_section(target_path, forge_path, section, "preview.section")
    return True


def _show_forge_section(
    target_path: Path,
    forge_path: Path,
    section: ForgeFunctionSection,
    event_prefix: str,
) -> None:
    target_stem = target_path.stem
    title = "PseudoForge: %s!%s 0x%X" % (target_stem, section.name, section.ea)
    log_event(
        "%s.show.before title=\"%s\" function=\"%s\" ea=0x%X chars=%d"
        % (event_prefix, _ascii_for_log(title), _ascii_for_log(section.name), section.ea, len(section.text))
    )
    show_text_view(
        title,
        section.text,
        source_path=forge_path,
        suggested_filename=build_save_as_filename(target_stem, section.name, section.ea),
        copy_from_source=False,
        target_stem=target_stem,
    )
    log_event(
        "%s.show.after title=\"%s\" function=\"%s\" ea=0x%X"
        % (event_prefix, _ascii_for_log(title), _ascii_for_log(section.name), section.ea)
    )


def _show_cached_side_by_side_section(
    target_path: Path,
    forge_path: Path,
    section: ForgeFunctionSection,
    session: PluginAnalysisSession | None,
    event_prefix: str,
) -> bool:
    if not side_by_side_preview_enabled():
        return False
    raw_pseudocode = ""
    summary_text = ""
    raw_source = "none"
    if session is not None and session.matches_current(target_path, section.ea) and session.capture.pseudocode:
        raw_pseudocode = session.capture.pseudocode
        summary_text = _format_analysis_summary(session.capture, session.plan)
        raw_source = "session"
    elif section.raw_pseudocode:
        raw_pseudocode = section.raw_pseudocode
        summary_text = "PseudoForge cached analysis 0x%X: raw pseudocode loaded from .forge." % section.ea
        raw_source = "forge"

    if not raw_pseudocode:
        warning(
            "PseudoForge side-by-side preview needs stored raw Hex-Rays pseudocode. "
            "Opening the cached cleaned section only. Run Analyze current function once "
            "with this PseudoForge version to refresh the cached raw-vs-cleaned preview."
        )
        log_event(
            "%s.side_by_side.unavailable reason=\"missing_stored_raw_pseudocode\" function=\"%s\" ea=0x%X"
            % (event_prefix, _ascii_for_log(section.name), section.ea)
        )
        return False

    target_stem = target_path.stem
    title = "PseudoForge: %s!%s 0x%X" % (target_stem, section.name, section.ea)
    log_event(
        "%s.side_by_side.show.before title=\"%s\" function=\"%s\" ea=0x%X chars=%d raw_source=%s"
        % (
            event_prefix,
            _ascii_for_log(title),
            _ascii_for_log(section.name),
            section.ea,
            len(section.text),
            raw_source,
        )
    )
    show_text_view(
        title,
        section.text,
        source_path=forge_path,
        suggested_filename=build_save_as_filename(target_stem, section.name, section.ea),
        copy_from_source=False,
        target_stem=target_stem,
        reference_text=raw_pseudocode,
        reference_title="Raw Hex-Rays pseudocode",
        content_title="PseudoForge cleaned pseudocode",
        summary_text=summary_text,
    )
    log_event(
        "%s.side_by_side.show.after title=\"%s\" function=\"%s\" ea=0x%X"
        % (event_prefix, _ascii_for_log(title), _ascii_for_log(section.name), section.ea)
    )
    return True


def _idb_path() -> Path | None:
    if idaapi is None:
        return None
    try:
        path_text = idaapi.get_path(idaapi.PATH_TYPE_IDB)
    except Exception:
        return None
    if not path_text:
        return None
    return Path(path_text)


def _current_function_identity() -> tuple[int, str] | None:
    if ida_kernwin is None or ida_funcs is None:
        return None
    try:
        ea = ida_kernwin.get_screen_ea()
        function = ida_funcs.get_func(ea)
        if function is None:
            return None
        name = ida_funcs.get_func_name(function.start_ea) or "function"
        return int(function.start_ea), name
    except Exception:
        return None


def _build_plan_with_config(capture: FunctionCapture, task_name: str = "") -> CleanPlan:
    log_checkpoint("build_plan.load_config.before", function=capture.name, ea="0x%X" % capture.ea)
    config = load_config()
    profile_root = _configure_profile_dir_for_analysis(config.profile_dir)
    log_checkpoint("build_plan.load_config.after", llm_enabled=config.llm.enabled, profile_root=str(profile_root))
    _raise_if_task_cancelled(task_name, "after config load")
    if not config.llm.enabled:
        log_output("PseudoForge LLM rename assist is disabled. Running deterministic analysis only.")
        log_event(
            "llm.disabled function=\"%s\" ea=0x%X deterministic=true"
            % (_ascii_for_log(capture.name), capture.ea)
        )
        with trace_scope("build_plan.deterministic", function=capture.name, ea="0x%X" % capture.ea):
            plan = build_clean_plan(capture)
        _raise_if_task_cancelled(task_name, "after deterministic plan")
        return plan

    provider_name = normalize_provider(config.llm.provider)
    log_output(
        "PseudoForge requesting LLM rename assist: %s model=%s."
        % (provider_label(provider_name), _ascii_for_log(config.llm.model))
    )
    log_event(
        "llm.request provider=%s model=\"%s\" function=\"%s\" ea=0x%X timeout=%d"
        % (
            provider_name,
            _ascii_for_log(config.llm.model),
            _ascii_for_log(capture.name),
            capture.ea,
            config.llm.timeout_seconds,
        )
    )
    with trace_scope("build_plan.provider_factory", provider=provider_name, model=config.llm.model):
        provider = build_rename_provider(
            config.llm,
            api_key=get_provider_api_key(config, config.llm.provider),
        )
    _raise_if_task_cancelled(task_name, "before llm provider")

    try:
        with trace_scope("build_plan.llm", provider=provider_name, model=config.llm.model, function=capture.name):
            plan = build_clean_plan(capture, rename_provider=provider)
        _raise_if_task_cancelled(task_name, "after llm provider")
        log_event(
            "llm.plan.done provider=%s model=\"%s\" renames=%d warnings=%d"
            % (
                provider_name,
                _ascii_for_log(config.llm.model),
                len(plan.active_renames()),
                len(plan.warnings),
            )
        )
        log_output(
            "PseudoForge LLM rename assist completed: %d rename(s), %d warning(s)."
            % (len(plan.active_renames()), len(plan.warnings))
        )
        return plan
    except CancellationRequested:
        raise
    except Exception as exc:
        log_event(
            "llm.failed provider=%s model=\"%s\" function=\"%s\" error=\"%s\""
            % (
                provider_name,
                _ascii_for_log(config.llm.model),
                _ascii_for_log(capture.name),
                _ascii_for_log(str(exc)),
            )
        )
        log_output("PseudoForge LLM rename assist failed; deterministic fallback will be used.")
        with trace_scope("build_plan.fallback", function=capture.name, ea="0x%X" % capture.ea):
            plan = build_clean_plan(capture)
        _raise_if_task_cancelled(task_name, "after fallback plan")
        plan.warnings.insert(0, f"LLM rename assist failed; deterministic fallback used: {exc}")
        return plan


def _configure_profile_dir_for_analysis(profile_dir: str) -> Path:
    selected = _resolve_configured_profile_dir(profile_dir)
    if str(selected) == active_profile_root():
        return selected
    return configure_profile_dir(profile_dir)


def _resolve_configured_profile_dir(profile_dir: str) -> Path:
    path_text = str(profile_dir or "").strip()
    raw_path = path_text if path_text else os.environ.get("PSEUDOFORGE_PROFILE_DIR", "").strip()
    return Path(raw_path).expanduser() if raw_path else DEFAULT_PROFILE_DIR


def _format_analysis_summary(capture: FunctionCapture, plan: CleanPlan) -> str:
    lines = [
        "PseudoForge analyzed 0x%X: %d rename(s), %d flow rewrite(s), %d warning(s)"
        % (capture.ea, len(plan.renames), len(plan.flow_rewrites), len(plan.warnings))
    ]
    rule_summary = format_rule_report_summary(plan.rule_report, include_error_details=True)
    if rule_summary:
        lines.append(rule_summary)
    if plan.warnings:
        lines.append("")
        lines.append("Warnings:")
        for item in plan.warnings[:8]:
            lines.append("- %s" % _format_warning(item))
        if len(plan.warnings) > 8:
            lines.append("- ... %d more warning(s)" % (len(plan.warnings) - 8))
    return "\n".join(lines)


def _format_warning(item: object) -> str:
    if isinstance(item, dict):
        message = str(item.get("message", "")).strip()
        if message:
            return message
        old = str(item.get("old", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if old and reason:
            return "Potential bad call target %s: %s" % (old, reason)
    return str(item)


def _raise_if_task_cancelled(task_name: str, phase: str) -> None:
    if not task_name:
        return
    try:
        raise_if_cancelled(task_name)
    except CancellationRequested:
        log_checkpoint("task.cancelled", task=task_name, phase=phase)
        raise


def _ascii_for_log(message: str) -> str:
    return message.encode("ascii", errors="replace").decode("ascii")


def _safe_config_path_text() -> str:
    try:
        from ida_pseudoforge.config import get_config_path

        return str(get_config_path())
    except Exception:
        return "(unavailable)"
