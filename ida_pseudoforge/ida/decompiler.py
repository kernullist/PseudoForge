from __future__ import annotations

from typing import Any

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable, make_lvar_identity
from ida_pseudoforge.ida.thread_helpers import run_on_main_thread
from ida_pseudoforge.logging import log_checkpoint, log_event, trace_scope

try:
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_kernwin  # type: ignore
    import idaapi  # type: ignore
except Exception:
    ida_funcs = None
    ida_hexrays = None
    ida_kernwin = None
    idaapi = None


_LVAR_LOCATION_SCALAR_MEMBERS = (
    ("stkoff", "stkoff"),
    ("get_stkoff", "stkoff"),
    ("reg", "reg"),
    ("get_reg", "reg"),
    ("ea", "ea"),
    ("get_ea", "ea"),
    ("defea", "defea"),
    ("get_defea", "defea"),
    ("defblk", "defblk"),
    ("get_defblk", "defblk"),
)

_LVAR_LOCATION_TEXT_MEMBERS = (
    "dstr",
    "print",
)


def hexrays_available() -> bool:
    if ida_hexrays is None:
        return False

    def do_init() -> bool:
        try:
            return bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            return False

    return bool(run_on_main_thread(do_init, write=False))


def capture_current_function() -> tuple[FunctionCapture, Any]:
    if ida_kernwin is None or ida_hexrays is None or ida_funcs is None:
        raise RuntimeError("IDA Hex-Rays APIs are not available")

    def do_capture() -> tuple[FunctionCapture, Any]:
        log_checkpoint("decompiler.capture.do_capture.before")
        current = _capture_from_current_pseudocode_view()
        if current is not None:
            log_checkpoint("decompiler.capture.do_capture.after", source="vdui")
            return current

        ea = ida_kernwin.get_screen_ea()
        if idaapi is not None and ea == idaapi.BADADDR:
            raise RuntimeError("No current EA")

        func = ida_funcs.get_func(ea)
        if func is None:
            raise RuntimeError(f"EA 0x{ea:X} is not inside a function")

        log_event("capture.decompile.start ea=0x%X" % int(func.start_ea))
        with trace_scope("decompiler.decompile", ea="0x%X" % int(func.start_ea)):
            cfunc = ida_hexrays.decompile(func)
        if cfunc is None:
            raise RuntimeError(f"Hex-Rays failed to decompile function at 0x{func.start_ea:X}")
        log_event("capture.decompile.done ea=0x%X" % int(func.start_ea))

        with trace_scope("decompiler.extract_text", ea="0x%X" % int(func.start_ea)):
            pseudocode = _cfunc_text(cfunc)
        name = ida_funcs.get_func_name(func.start_ea) or ""
        capture = capture_from_pseudocode(pseudocode, name=name, ea=int(func.start_ea))
        with trace_scope("decompiler.extract_lvars", ea="0x%X" % int(func.start_ea)):
            capture.lvars = merge_lvars_from_text_and_cfunc(capture.lvars, _extract_lvars_from_cfunc(cfunc))
        log_checkpoint("decompiler.capture.do_capture.after", source="decompile", function=name, ea="0x%X" % int(func.start_ea))
        return capture, cfunc

    with trace_scope("decompiler.capture.run_on_main_thread"):
        return run_on_main_thread(do_capture, write=False)


def capture_current_lvars() -> list[LocalVariable]:
    if ida_kernwin is None or ida_hexrays is None or ida_funcs is None:
        raise RuntimeError("IDA Hex-Rays APIs are not available")

    def do_capture() -> list[LocalVariable]:
        cfunc = _current_view_cfunc()
        if cfunc is None:
            ea = ida_kernwin.get_screen_ea()
            if idaapi is not None and ea == idaapi.BADADDR:
                raise RuntimeError("No current EA")
            func = ida_funcs.get_func(ea)
            if func is None:
                raise RuntimeError(f"EA 0x{ea:X} is not inside a function")
            cfunc = ida_hexrays.decompile(func)
        if cfunc is None:
            raise RuntimeError("Hex-Rays failed to decompile current function")
        return _extract_lvars_from_cfunc(cfunc)

    with trace_scope("decompiler.capture_lvars.run_on_main_thread"):
        return run_on_main_thread(do_capture, write=False)


def _capture_from_current_pseudocode_view() -> tuple[FunctionCapture, Any] | None:
    cfunc = _current_view_cfunc()
    if cfunc is None:
        return None

    ea = _cfunc_entry_ea(cfunc)
    if ea is None:
        return None

    name = ida_funcs.get_func_name(ea) or ""
    pseudocode = _cfunc_text(cfunc)
    capture = capture_from_pseudocode(pseudocode, name=name, ea=int(ea))
    capture.lvars = merge_lvars_from_text_and_cfunc(capture.lvars, _extract_lvars_from_cfunc(cfunc))
    log_event("capture.vdui.reuse function=\"%s\" ea=0x%X" % (_ascii_for_log(name), int(ea)))
    return capture, cfunc


def _current_view_cfunc() -> Any | None:
    get_widget_vdui = getattr(ida_hexrays, "get_widget_vdui", None)
    get_current_widget = getattr(ida_kernwin, "get_current_widget", None)
    if not callable(get_widget_vdui) or not callable(get_current_widget):
        return None

    try:
        widget = get_current_widget()
        vdui = get_widget_vdui(widget)
        return getattr(vdui, "cfunc", None)
    except Exception:
        return None


def _cfunc_entry_ea(cfunc: Any) -> int | None:
    for attr in ("entry_ea", "entry"):
        value = getattr(cfunc, attr, None)
        if value is None:
            continue
        try:
            return int(value)
        except Exception:
            pass
    try:
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is not None:
            return int(func.start_ea)
    except Exception:
        pass
    return None


def _cfunc_text(cfunc: Any) -> str:
    lines = []
    try:
        pseudocode = cfunc.get_pseudocode()
        for line in pseudocode:
            raw = getattr(line, "line", str(line))
            if idaapi is not None:
                try:
                    raw = idaapi.tag_remove(raw)
                except Exception:
                    pass
            lines.append(str(raw))
    except Exception:
        return str(cfunc)
    return "\n".join(lines)


def _extract_lvars_from_cfunc(cfunc: Any) -> list[LocalVariable]:
    result = []
    try:
        lvars = list(cfunc.lvars)
    except Exception:
        return result

    for index, lvar in enumerate(lvars):
        name = str(getattr(lvar, "name", "") or "")
        if not name:
            continue
        type_text = ""
        for attr in ("type", "tif"):
            value = getattr(lvar, attr, None)
            if callable(value):
                try:
                    type_text = str(value())
                    break
                except Exception:
                    pass
            elif value is not None:
                type_text = str(value)
                break
        is_arg = False
        method = getattr(lvar, "is_arg_var", None)
        if callable(method):
            try:
                is_arg = bool(method())
            except Exception:
                is_arg = False
        location = _extract_lvar_location(lvar)
        identity = make_lvar_identity(name, type_text, is_arg, index, location)
        result.append(
            LocalVariable(
                name=name,
                type=type_text,
                is_arg=is_arg,
                index=index,
                location=location,
                identity=identity,
            )
        )
    return result


def _extract_lvar_location(lvar: Any) -> str:
    for attr in ("location", "loc", "lvloc"):
        value = _read_zero_arg_member(lvar, attr)
        text = _stable_lvar_location_anchor(value)
        if text:
            return text
    text = _stable_lvar_location_anchor(lvar, allow_direct_object_text=False)
    if text:
        return text
    return ""


def _stable_lvar_location_anchor(value: Any, *, allow_direct_object_text: bool = True) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, bool)):
        return _stable_identity_text(value)

    for member, label in _LVAR_LOCATION_SCALAR_MEMBERS:
        text = _format_location_scalar(label, _read_zero_arg_member(value, member))
        if text:
            return text

    for member in _LVAR_LOCATION_TEXT_MEMBERS:
        text = _stable_identity_text(_read_zero_arg_member(value, member))
        if text:
            return text

    if allow_direct_object_text:
        return _stable_identity_text(value)
    return ""


def _read_zero_arg_member(owner: Any, member: str) -> Any:
    try:
        value = getattr(owner, member, None)
    except Exception:
        return None
    if not callable(value):
        return value
    try:
        return value()
    except Exception:
        return None


def _format_location_scalar(label: str, value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, int):
        number = value
    else:
        try:
            number = int(str(value), 0)
        except Exception:
            text = _stable_identity_text(value)
            if not text:
                return ""
            return "%s:%s" % (label, text)

    if label in ("ea", "defea"):
        if number in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            return ""
        if number >= 0:
            return "%s:0x%X" % (label, number)
    return "%s:%d" % (label, number)


def _stable_identity_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, bool)):
        return str(value)
    text = str(value)
    lowered = text.lower()
    if (
        " object at " in lowered
        or " at 0x" in lowered
        or "swig object" in lowered
        or text.startswith("<") and text.endswith(">")
    ):
        return ""
    return text


def merge_lvars_from_text_and_cfunc(
    text_lvars: list[LocalVariable],
    cfunc_lvars: list[LocalVariable],
) -> list[LocalVariable]:
    result: list[LocalVariable] = []
    by_name: dict[str, LocalVariable] = {}

    for var in text_lvars + cfunc_lvars:
        if not var.name:
            continue
        existing = by_name.get(var.name)
        if existing is None:
            by_name[var.name] = LocalVariable(
                name=var.name,
                type=var.type,
                is_arg=var.is_arg,
                index=var.index,
                location=var.location,
                identity=var.identity,
            )
            result.append(by_name[var.name])
            continue
        if not existing.type and var.type:
            existing.type = var.type
        if var.is_arg:
            existing.is_arg = True
        if existing.index < 0 and var.index >= 0:
            existing.index = var.index
        if not existing.location and var.location:
            existing.location = var.location
        if not existing.identity and var.identity:
            existing.identity = var.identity

    return result


def _ascii_for_log(value: str) -> str:
    return value.encode("ascii", errors="replace").decode("ascii")
