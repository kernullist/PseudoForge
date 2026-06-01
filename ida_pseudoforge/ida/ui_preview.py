from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import importlib
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Callable

from ida_pseudoforge.config import PREVIEW_BACKEND_SIDE_BY_SIDE, load_config, normalize_preview_backend
from ida_pseudoforge.core.forge_store import ForgeFunctionSection, parse_forge_function_sections
from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.core.render import _finalize_rendered_c_like_text
from ida_pseudoforge.logging import append_bounded_log_line, log_checkpoint, log_event

try:
    import ida_kernwin  # type: ignore
    import idaapi  # type: ignore
except Exception:
    ida_kernwin = None
    idaapi = None

try:
    import ida_lines  # type: ignore
except Exception:
    ida_lines = None


_VIEWERS: dict[str, "_ForgeTextViewer"] = {}
_SIDE_BY_SIDE_FORMS: dict[str, object] = {}
_SIDE_BY_SIDE_FALLBACK_WARNINGS: set[str] = set()
_ACTIVE_VIEWER: "_ForgeTextViewer | None" = None
_MAX_PREVIEW_CHARS = 512 * 1024
_MAX_PREVIEW_LINES = 12000
_MAX_HIGHLIGHT_CHARS = 256 * 1024
_MAX_HIGHLIGHT_LINES = 8000
_SIDE_BY_SIDE_STATUS_MAX_HEIGHT = 18
_SIDE_BY_SIDE_SUMMARY_MAX_HEIGHT = 44
_SIDE_BY_SIDE_SEARCH_MAX_HEIGHT = 28
_SIDE_BY_SIDE_MAX_SEARCH_HIGHLIGHTS = 1000
_SIDE_BY_SIDE_SEARCH_BG = (86, 74, 28)
_SIDE_BY_SIDE_SEARCH_FG = (255, 255, 255)
_SIDE_BY_SIDE_SEARCH_CURRENT_BG = (255, 213, 79)
_SIDE_BY_SIDE_SEARCH_CURRENT_FG = (0, 0, 0)
_DISABLE_HIGHLIGHT_ENV = "PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"
_PREVIEW_BACKEND_ENV = "PSEUDOFORGE_PREVIEW_BACKEND"
_ACTIONS_REGISTERED = False
_COPY_ACTION = "pseudoforge:preview_copy_all"
_SAVE_ACTION = "pseudoforge:preview_save_as"
_FUNCTIONS_ACTION = "pseudoforge:preview_functions"
_COPY_RETRY_COUNT = 20
_COPY_RETRY_DELAY_SECONDS = 0.05
_C_KEYWORDS = {
    "break",
    "case",
    "continue",
    "default",
    "do",
    "else",
    "for",
    "goto",
    "if",
    "return",
    "sizeof",
    "switch",
    "while",
}
_C_TYPE_WORDS = {
    "BOOLEAN",
    "BYTE",
    "CHAR",
    "DWORD",
    "HANDLE",
    "INT",
    "LIST_ENTRY",
    "LONG",
    "LONGLONG",
    "NTSTATUS",
    "PCHAR",
    "PCSTR",
    "PCWSTR",
    "PVOID",
    "SIZE_T",
    "UCHAR",
    "UINT",
    "ULONG",
    "ULONGLONG",
    "USHORT",
    "VOID",
    "WCHAR",
    "WORD",
    "_BYTE",
    "_DWORD",
    "_QWORD",
    "__fastcall",
    "__int16",
    "__int32",
    "__int64",
    "__int8",
    "char",
    "const",
    "enum",
    "int",
    "long",
    "short",
    "signed",
    "static",
    "struct",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
}
_C_CONSTANT_WORDS = {
    "FALSE",
    "NULL",
    "TRUE",
    "false",
    "nullptr",
    "true",
}
_TOKEN_RE = re.compile(
    r"\"(?:\\.|[^\"\\])*\""
    r"|\'(?:\\.|[^\'\\])*\'"
    r"|0[xX][0-9A-Fa-f]+(?:[uUlL]*)"
    r"|\b\d+(?:[uUlL]*)\b"
    r"|[A-Za-z_][A-Za-z0-9_]*"
)
_Colorizer = Callable[[str, str], str]


def choose_renames(plan: CleanPlan) -> list[str]:
    items = [rename for rename in plan.renames if rename.apply and rename.kind in {"arg", "lvar"}]
    if ida_kernwin is None:
        return [rename.old for rename in items]

    class RenameChooser(ida_kernwin.Choose):
        def __init__(self):
            super().__init__(
                "PseudoForge rename plan",
                [
                    ["Old", 18],
                    ["New", 28],
                    ["Kind", 8],
                    ["Conf", 8],
                    ["Evidence", 64],
                ],
                flags=ida_kernwin.Choose.CH_MULTI,
            )
            self.selected_indices: list[int] = []

        def OnGetLine(self, index):
            rename = items[index]
            return [
                rename.old,
                rename.new,
                rename.kind,
                f"{rename.confidence:.2f}",
                rename.evidence,
            ]

        def OnGetSize(self):
            return len(items)

        def OnSelectionChange(self, selected):
            self.selected_indices = list(selected or [])

    chooser = RenameChooser()
    if chooser.Show(modal=True) < 0:
        return []
    if not chooser.selected_indices:
        return []
    return [items[index].old for index in chooser.selected_indices]


def show_text_view(
    title: str,
    text: str,
    source_path: str | Path | None = None,
    suggested_filename: str | None = None,
    copy_from_source: bool = True,
    target_stem: str | None = None,
    reference_text: str | None = None,
    reference_title: str = "Raw Hex-Rays pseudocode",
    content_title: str = "PseudoForge preview",
    summary_text: str = "",
) -> str:
    text = _finalize_rendered_c_like_text(text)
    if reference_text is not None:
        reference_text = _finalize_rendered_c_like_text(reference_text)
    _trace_checkpoint("show_text_view.enter", title=title, chars=len(text), source=source_path)
    if ida_kernwin is None:
        _trace_checkpoint("show_text_view.no_ida", title=title)
        print(text)
        return "stdout"

    if reference_text is not None and _try_show_side_by_side_view(
        title,
        reference_text,
        text,
        source_path=source_path,
        suggested_filename=suggested_filename,
        target_stem=target_stem,
        reference_title=reference_title,
        content_title=content_title,
        summary_text=summary_text,
    ):
        log_event("preview.show title=\"%s\" chars=%d backend=dockable_side_by_side" % (_ascii_for_log(title), len(text)))
        _trace_checkpoint("show_text_view.exit", title=title, backend="dockable_side_by_side")
        return "dockable_side_by_side"

    _ensure_preview_actions()
    display_text = _bounded_preview_text(text, source_path)
    viewer = _VIEWERS.get(title)
    if viewer is None:
        _trace_checkpoint("simple_viewer.new.before", title=title)
        viewer = _ForgeTextViewer(title)
        if not viewer.Create(title):
            raise RuntimeError("Failed to create PseudoForge preview viewer")
        _VIEWERS[title] = viewer
        _trace_checkpoint("simple_viewer.new.after", title=title)

    _trace_checkpoint("simple_viewer.update.before", title=title, chars=len(display_text))
    viewer.update_content(
        display_text,
        text,
        source_path,
        suggested_filename=suggested_filename,
        copy_from_source=copy_from_source,
        target_stem=target_stem,
    )
    _trace_checkpoint("simple_viewer.update.after", title=title)
    _trace_checkpoint("simple_viewer.show.before", title=title)
    viewer.Show()
    _trace_checkpoint("simple_viewer.show.after", title=title)
    log_event("preview.show title=\"%s\" chars=%d backend=simplecustviewer" % (_ascii_for_log(title), len(text)))
    _trace_checkpoint("show_text_view.exit", title=title, backend="simplecustviewer")
    return "simplecustviewer"


def info(message: str) -> None:
    log_event("info %s" % _single_line_for_log(message))
    if ida_kernwin is not None:
        try:
            ida_kernwin.info(message)
            return
        except Exception:
            pass
    print(message)


def warning(message: str) -> None:
    log_event("warning %s" % _single_line_for_log(message))
    if ida_kernwin is not None:
        try:
            ida_kernwin.warning(message)
            return
        except Exception:
            pass
    print(message)


def _try_show_side_by_side_view(
    title: str,
    reference_text: str,
    content_text: str,
    source_path: str | Path | None = None,
    suggested_filename: str | None = None,
    target_stem: str | None = None,
    reference_title: str = "Raw Hex-Rays pseudocode",
    content_title: str = "PseudoForge preview",
    summary_text: str = "",
) -> bool:
    if not _side_by_side_preview_enabled():
        return False
    if ida_kernwin is None:
        return False
    plugin_form_cls = getattr(ida_kernwin, "PluginForm", None)
    if plugin_form_cls is None:
        reason = "IDA PluginForm is unavailable"
        _trace_checkpoint("side_by_side.unavailable", title=title, reason=reason)
        _warn_side_by_side_fallback(title, reason)
        return False
    qt_modules = _load_qt_modules()
    if qt_modules is None:
        reason = "Qt widgets are unavailable; tried PyQt5, PyQt6, PySide6, and PySide2"
        _trace_checkpoint("side_by_side.unavailable", title=title, reason=reason)
        _warn_side_by_side_fallback(title, reason)
        return False

    try:
        form_cls = _side_by_side_form_class(plugin_form_cls, qt_modules)
        form = form_cls(
            title,
            _bounded_panel_text(reference_text, source_path),
            _bounded_panel_text(content_text, source_path),
            reference_title=reference_title,
            content_title=content_title,
            suggested_filename=suggested_filename or "",
            target_stem=target_stem or "",
            summary_text=_side_by_side_summary_text(reference_text, content_text, summary_text),
        )
        options = int(getattr(plugin_form_cls, "WOPN_TAB", 0)) | int(getattr(plugin_form_cls, "WOPN_RESTORE", 0))
        shown = form.Show(title, options=options)
        if shown is False or (isinstance(shown, int) and shown < 0):
            reason = "IDA refused to show the dockable PluginForm"
            _trace_checkpoint("side_by_side.show.failed", title=title, result=shown, reason=reason)
            _warn_side_by_side_fallback(title, reason)
            return False
        _SIDE_BY_SIDE_FORMS[title] = form
        _trace_checkpoint("side_by_side.show.after", title=title)
        return True
    except Exception as exc:
        _trace_checkpoint("side_by_side.failed", title=title, error=str(exc))
        _warn_side_by_side_fallback(title, "dockable preview creation failed: %s" % exc)
        return False


def _side_by_side_preview_enabled() -> bool:
    backend = os.environ.get(_PREVIEW_BACKEND_ENV, "").strip().lower()
    if backend:
        return normalize_preview_backend(backend) == PREVIEW_BACKEND_SIDE_BY_SIDE
    try:
        config = load_config()
    except Exception:
        return False
    return normalize_preview_backend(config.preview.backend) == PREVIEW_BACKEND_SIDE_BY_SIDE


def side_by_side_preview_enabled() -> bool:
    return _side_by_side_preview_enabled()


def _warn_side_by_side_fallback(title: str, reason: str) -> None:
    key = reason
    if key in _SIDE_BY_SIDE_FALLBACK_WARNINGS:
        return
    _SIDE_BY_SIDE_FALLBACK_WARNINGS.add(key)
    warning(
        "PseudoForge side-by-side preview is enabled, but the dockable view fell back to the simple viewer: %s"
        % reason
    )


def _load_qt_modules():
    for module_name in ("PyQt5", "PyQt6", "PySide6", "PySide2"):
        try:
            qt_core = importlib.import_module("%s.QtCore" % module_name)
            qt_gui = importlib.import_module("%s.QtGui" % module_name)
            qt_widgets = importlib.import_module("%s.QtWidgets" % module_name)
            return qt_core, qt_gui, qt_widgets
        except Exception:
            pass
    return None


def _qt_horizontal_orientation(qt_core):
    orientation_cls = getattr(getattr(qt_core, "Qt", object()), "Orientation", None)
    if orientation_cls is not None:
        horizontal = getattr(orientation_cls, "Horizontal", None)
        if horizontal is not None:
            return horizontal
    return getattr(qt_core.Qt, "Horizontal")


def _plain_text_no_wrap(qt_widgets):
    no_wrap = getattr(qt_widgets.QPlainTextEdit, "NoWrap", None)
    if no_wrap is not None:
        return no_wrap
    line_wrap_mode = getattr(qt_widgets.QPlainTextEdit, "LineWrapMode", None)
    if line_wrap_mode is not None:
        return getattr(line_wrap_mode, "NoWrap", None)
    return None


def _text_cursor_move_operation(qt_gui, name: str):
    cursor_cls = qt_gui.QTextCursor
    value = getattr(cursor_cls, name, None)
    if value is not None:
        return value
    move_operation_cls = getattr(cursor_cls, "MoveOperation", None)
    if move_operation_cls is None:
        raise AttributeError("QTextCursor move operation is unavailable: %s" % name)
    return getattr(move_operation_cls, name)


def _text_cursor_move_mode(qt_gui, name: str):
    cursor_cls = qt_gui.QTextCursor
    value = getattr(cursor_cls, name, None)
    if value is not None:
        return value
    move_mode_cls = getattr(cursor_cls, "MoveMode", None)
    if move_mode_cls is None:
        raise AttributeError("QTextCursor move mode is unavailable: %s" % name)
    return getattr(move_mode_cls, name)


def _fixed_width_system_font(qt_gui):
    font_database_cls = qt_gui.QFontDatabase
    fixed_font = getattr(font_database_cls, "FixedFont", None)
    if fixed_font is None:
        system_font_cls = getattr(font_database_cls, "SystemFont", None)
        fixed_font = getattr(system_font_cls, "FixedFont", None) if system_font_cls is not None else None
    if fixed_font is None:
        raise AttributeError("QFontDatabase fixed-width system font enum is unavailable")
    return font_database_cls.systemFont(fixed_font)


def _size_policy_value(qt_widgets, name: str):
    policy_cls = qt_widgets.QSizePolicy
    value = getattr(policy_cls, name, None)
    if value is not None:
        return value
    policy_enum_cls = getattr(policy_cls, "Policy", None)
    if policy_enum_cls is None:
        raise AttributeError("QSizePolicy enum is unavailable: %s" % name)
    return getattr(policy_enum_cls, name)


def _side_by_side_form_class(plugin_form_cls, qt_modules):
    QtCore, QtGui, QtWidgets = qt_modules

    class _SideBySidePreviewForm(plugin_form_cls):
        def __init__(
            self,
            title: str,
            reference_text: str,
            content_text: str,
            reference_title: str,
            content_title: str,
            suggested_filename: str,
            target_stem: str,
            summary_text: str,
        ) -> None:
            super().__init__()
            self.title = title
            self.reference_text = reference_text
            self.content_text = content_text
            self.reference_title = reference_title
            self.content_title = content_title
            self.suggested_filename = suggested_filename
            self.target_stem = target_stem
            self.summary_text = summary_text
            self._widget = None
            self._search_matches: list[tuple[int, int, int, int]] = []
            self._search_index = 0
            self._editors: list[object] = []
            self._highlighters: list[object] = []
            self._search_box = None
            self._search_status = None

        def OnCreate(self, form) -> None:
            parent = self._form_to_widget(form)
            layout = QtWidgets.QVBoxLayout(parent)
            layout.setContentsMargins(6, 6, 6, 6)
            layout.setSpacing(4)
            status = QtWidgets.QLabel("Preview only. IDB was not modified.")
            status.setMaximumHeight(_SIDE_BY_SIDE_STATUS_MAX_HEIGHT)
            status.setSizePolicy(
                _size_policy_value(QtWidgets, "Preferred"),
                _size_policy_value(QtWidgets, "Fixed"),
            )
            layout.addWidget(status, 0)

            summary = QtWidgets.QLabel(self.summary_text)
            summary.setMaximumHeight(_SIDE_BY_SIDE_SUMMARY_MAX_HEIGHT)
            summary.setSizePolicy(
                _size_policy_value(QtWidgets, "Preferred"),
                _size_policy_value(QtWidgets, "Fixed"),
            )
            layout.addWidget(summary, 0)

            search_widget = QtWidgets.QWidget()
            search_widget.setMaximumHeight(_SIDE_BY_SIDE_SEARCH_MAX_HEIGHT)
            search_widget.setSizePolicy(
                _size_policy_value(QtWidgets, "Preferred"),
                _size_policy_value(QtWidgets, "Fixed"),
            )
            search_row = QtWidgets.QHBoxLayout(search_widget)
            search_row.setContentsMargins(0, 0, 0, 0)
            search_row.setSpacing(6)
            search_row.addWidget(QtWidgets.QLabel("Search"))
            self._search_box = QtWidgets.QLineEdit()
            self._search_box.setPlaceholderText("Text")
            search_row.addWidget(self._search_box)
            previous_button = QtWidgets.QPushButton("Prev")
            next_button = QtWidgets.QPushButton("Next")
            self._search_status = QtWidgets.QLabel("0 matches")
            search_row.addWidget(previous_button)
            search_row.addWidget(next_button)
            search_row.addWidget(self._search_status)
            layout.addWidget(search_widget, 0)

            splitter = QtWidgets.QSplitter(_qt_horizontal_orientation(QtCore))
            splitter.addWidget(self._make_panel(self.reference_title, self.reference_text))
            splitter.addWidget(self._make_panel(self.content_title, self.content_text))
            splitter.setSizes([1, 1])
            layout.addWidget(splitter, 1)
            self._search_box.textChanged.connect(lambda _value: self._update_search())
            previous_button.clicked.connect(lambda _checked=False: self._jump_to_search_match(-1))
            next_button.clicked.connect(lambda _checked=False: self._jump_to_search_match(1))
            self._widget = parent

        def OnClose(self, form) -> None:
            _SIDE_BY_SIDE_FORMS.pop(self.title, None)

        def _form_to_widget(self, form):
            pyqt_adapter = getattr(self, "FormToPyQtWidget", None)
            if pyqt_adapter is not None:
                return pyqt_adapter(form)
            pyside_adapter = getattr(self, "FormToPySideWidget", None)
            if pyside_adapter is not None:
                return pyside_adapter(form)
            raise RuntimeError("IDA PluginForm widget adapter is unavailable")

        def _make_panel(self, title: str, text: str):
            panel = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(panel)
            layout.setContentsMargins(0, 0, 0, 0)
            label = QtWidgets.QLabel(title)
            editor = QtWidgets.QPlainTextEdit()
            editor.setReadOnly(True)
            editor.setPlainText(text)
            no_wrap = _plain_text_no_wrap(QtWidgets)
            if no_wrap is not None:
                editor.setLineWrapMode(no_wrap)
            fixed_font = _fixed_width_system_font(QtGui)
            editor.setFont(fixed_font)
            highlighter = _apply_side_by_side_syntax_highlighting(editor, QtGui)
            if highlighter is not None:
                self._highlighters.append(highlighter)
            layout.addWidget(label)
            layout.addWidget(editor)
            self._editors.append(editor)
            return panel

        def _update_search(self) -> None:
            query = self._search_box.text() if self._search_box is not None else ""
            self._search_matches = _search_text_matches([self.reference_text, self.content_text], query)
            self._search_index = 0
            self._update_search_status(query)
            self._show_search_match()

        def _jump_to_search_match(self, step: int) -> None:
            if not self._search_matches:
                return
            self._search_index = (self._search_index + step) % len(self._search_matches)
            self._update_search_status(self._search_box.text() if self._search_box is not None else "")
            self._show_search_match()

        def _update_search_status(self, query: str) -> None:
            if self._search_status is None:
                return
            if not query:
                self._search_status.setText("0 matches")
                return
            if not self._search_matches:
                self._search_status.setText("0 matches")
                return
            self._search_status.setText("%d/%d matches" % (self._search_index + 1, len(self._search_matches)))

        def _show_search_match(self) -> None:
            _apply_search_highlights(self._editors, self._search_matches, self._search_index, QtGui, QtWidgets)
            _scroll_editors_to_search_match(self._editors, self._search_matches, self._search_index, QtGui)

    return _SideBySidePreviewForm


def _side_by_side_summary_text(reference_text: str, content_text: str, summary_text: str = "") -> str:
    summary_parts = [
        "Raw lines: %d" % _line_count(reference_text),
        "Cleaned lines: %d" % _line_count(content_text),
    ]
    warning_count = _marker_count(content_text, "warning")
    rule_count = _marker_count(content_text, "rule")
    if warning_count:
        summary_parts.append("Warning markers: %d" % warning_count)
    if rule_count:
        summary_parts.append("Rule markers: %d" % rule_count)
    normalized_summary = (summary_text or "").strip()
    if normalized_summary:
        first_summary_line = normalized_summary.splitlines()[0].strip()
        if first_summary_line:
            summary_parts.append(first_summary_line)
    return " | ".join(summary_parts)


def _apply_side_by_side_syntax_highlighting(editor, qt_gui):
    highlighter_cls = _side_by_side_highlighter_class(qt_gui)
    if highlighter_cls is None:
        return None
    try:
        highlighter = highlighter_cls(editor.document())
        rehighlight = getattr(highlighter, "rehighlight", None)
        if rehighlight is not None:
            rehighlight()
        return highlighter
    except Exception:
        return None


def _side_by_side_highlighter_class(qt_gui):
    highlighter_base = getattr(qt_gui, "QSyntaxHighlighter", None)
    text_format_cls = getattr(qt_gui, "QTextCharFormat", None)
    color_cls = getattr(qt_gui, "QColor", None)
    if highlighter_base is None or text_format_cls is None or color_cls is None:
        return None

    class _SideBySideSyntaxHighlighter(highlighter_base):
        def __init__(self, document) -> None:
            super().__init__(document)
            self._formats = _side_by_side_text_formats(qt_gui)

        def highlightBlock(self, text: str) -> None:
            plain_format = self._formats.get("plain")
            if plain_format is not None and text:
                self.setFormat(0, len(text), plain_format)
            for start_index, length, role in _side_by_side_highlight_spans(text):
                text_format = self._formats.get(role)
                if text_format is None:
                    continue
                self.setFormat(start_index, length, text_format)

    return _SideBySideSyntaxHighlighter


def _side_by_side_text_formats(qt_gui) -> dict[str, object]:
    palette = {
        "plain": (212, 212, 212),
        "char": (206, 145, 120),
        "comment": (106, 153, 85),
        "constant": (197, 134, 192),
        "function": (220, 220, 170),
        "keyword": (86, 156, 214),
        "number": (181, 206, 168),
        "preprocessor": (197, 134, 192),
        "string": (206, 145, 120),
        "type": (78, 201, 176),
    }
    formats: dict[str, object] = {}
    for role, rgb in palette.items():
        text_format = qt_gui.QTextCharFormat()
        text_format.setForeground(qt_gui.QColor(*rgb))
        formats[role] = text_format
    return formats


def _side_by_side_highlight_spans(text: str) -> list[tuple[int, int, str]]:
    if not text:
        return []
    spans: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        comment_index = _find_next_comment_start(text, index)
        if comment_index < 0:
            spans.extend(_side_by_side_code_spans(text, index, len(text)))
            break
        if comment_index > index:
            spans.extend(_side_by_side_code_spans(text, index, comment_index))
        if text.startswith("//", comment_index):
            spans.append((comment_index, len(text) - comment_index, "comment"))
            break
        end_index = text.find("*/", comment_index + 2)
        if end_index < 0:
            spans.append((comment_index, len(text) - comment_index, "comment"))
            break
        spans.append((comment_index, end_index - comment_index + 2, "comment"))
        index = end_index + 2
    return spans


def _side_by_side_code_spans(text: str, start_index: int, end_index: int) -> list[tuple[int, int, str]]:
    segment = text[start_index:end_index]
    if not segment:
        return []
    if segment.lstrip().startswith("#"):
        return [(start_index, len(segment), "preprocessor")]

    spans: list[tuple[int, int, str]] = []
    for match in _TOKEN_RE.finditer(segment):
        token = match.group(0)
        role = _token_role(segment, match.start(), match.end(), token)
        if not role:
            continue
        spans.append((start_index + match.start(), match.end() - match.start(), role))
    return spans


def _line_count(text: str) -> int:
    if not text:
        return 0
    return len(text.splitlines())


def _marker_count(text: str, marker: str) -> int:
    pattern = re.compile(r"\b%s(?:s|ing)?\b" % re.escape(marker), re.IGNORECASE)
    return len(pattern.findall(text or ""))


def _search_line_matches(panel_texts: list[str], query: str) -> list[tuple[int, int]]:
    needle = (query or "").strip().lower()
    if not needle:
        return []
    result: list[tuple[int, int]] = []
    for panel_index, text in enumerate(panel_texts):
        for line_index, line in enumerate((text or "").splitlines()):
            if needle in line.lower():
                result.append((panel_index, line_index))
    return result


def _search_text_matches(panel_texts: list[str], query: str) -> list[tuple[int, int, int, int]]:
    needle = (query or "").strip()
    if not needle:
        return []
    needle_lower = needle.lower()
    result: list[tuple[int, int, int, int]] = []
    for panel_index, text in enumerate(panel_texts):
        offset = 0
        for line_index, line in enumerate((text or "").splitlines(keepends=True)):
            line_body = line.rstrip("\r\n")
            line_lower = line_body.lower()
            column = 0
            while True:
                found = line_lower.find(needle_lower, column)
                if found < 0:
                    break
                result.append((panel_index, line_index, offset + found, len(needle)))
                column = found + max(1, len(needle))
            offset += len(line)
    return result


def _apply_search_highlights(editors, search_matches, search_index: int, qt_gui, qt_widgets) -> None:
    if not editors:
        return
    if not search_matches:
        for editor in editors:
            _set_editor_extra_selections(editor, [])
        return

    current_index = search_index % len(search_matches)
    current_match = search_matches[current_index]
    normal_format = _search_highlight_format(
        qt_gui,
        _SIDE_BY_SIDE_SEARCH_BG,
        _SIDE_BY_SIDE_SEARCH_FG,
    )
    current_format = _search_highlight_format(
        qt_gui,
        _SIDE_BY_SIDE_SEARCH_CURRENT_BG,
        _SIDE_BY_SIDE_SEARCH_CURRENT_FG,
    )
    for panel_index, editor in enumerate(editors):
        selections = []
        highlighted = 0
        current_selection = None
        for match_index, match in enumerate(search_matches):
            if highlighted >= _SIDE_BY_SIDE_MAX_SEARCH_HIGHLIGHTS and match_index != current_index:
                continue
            match_panel, _line_index, position, length = match
            if match_panel != panel_index:
                continue
            text_format = current_format if match_index == current_index else normal_format
            selection = _make_search_extra_selection(editor, position, length, text_format, qt_gui, qt_widgets)
            if selection is None:
                continue
            if match_index == current_index:
                current_selection = selection
            else:
                selections.append(selection)
                highlighted += 1
        if current_selection is not None:
            selections.append(current_selection)
        elif current_match[0] == panel_index:
            selection = _make_search_extra_selection(
                editor,
                current_match[2],
                current_match[3],
                current_format,
                qt_gui,
                qt_widgets,
            )
            if selection is not None:
                selections.append(selection)
        _set_editor_extra_selections(editor, selections)


def _search_highlight_format(qt_gui, background_rgb: tuple[int, int, int], foreground_rgb: tuple[int, int, int]):
    text_format = qt_gui.QTextCharFormat()
    set_background = getattr(text_format, "setBackground", None)
    if set_background is not None:
        set_background(qt_gui.QColor(*background_rgb))
    set_foreground = getattr(text_format, "setForeground", None)
    if set_foreground is not None:
        set_foreground(qt_gui.QColor(*foreground_rgb))
    return text_format


def _make_search_extra_selection(editor, position: int, length: int, text_format, qt_gui, qt_widgets):
    selection_cls = _extra_selection_class(qt_widgets)
    if selection_cls is None:
        return None
    try:
        cursor = qt_gui.QTextCursor(editor.document())
        cursor.setPosition(max(0, int(position)))
        cursor.setPosition(max(0, int(position)) + max(0, int(length)), _text_cursor_move_mode(qt_gui, "KeepAnchor"))
        selection = selection_cls()
        selection.cursor = cursor
        selection.format = text_format
        return selection
    except Exception:
        return None


def _extra_selection_class(qt_widgets):
    for owner_name in ("QTextEdit", "QPlainTextEdit"):
        owner = getattr(qt_widgets, owner_name, None)
        if owner is None:
            continue
        selection_cls = getattr(owner, "ExtraSelection", None)
        if selection_cls is not None:
            return selection_cls
    return None


def _set_editor_extra_selections(editor, selections: list[object]) -> None:
    setter = getattr(editor, "setExtraSelections", None)
    if setter is None:
        return
    try:
        setter(selections)
    except Exception:
        pass


def _scroll_editors_to_search_match(editors, search_matches, search_index: int, qt_gui) -> None:
    if not search_matches:
        return
    match = search_matches[search_index % len(search_matches)]
    line_index = match[1]
    for editor in editors:
        _scroll_editor_to_line(editor, line_index, qt_gui)


def _scroll_editor_to_line(editor, line_index: int, qt_gui) -> None:
    cursor = editor.textCursor()
    cursor.movePosition(_text_cursor_move_operation(qt_gui, "Start"))
    down_operation = _text_cursor_move_operation(qt_gui, "Down")
    for _index in range(max(0, int(line_index))):
        if not cursor.movePosition(down_operation):
            break
    editor.setTextCursor(cursor)
    editor.centerCursor()


def _bounded_panel_text(text: str, source_path: str | Path | None) -> str:
    lines = text.splitlines()
    truncated_by_lines = len(lines) > _MAX_PREVIEW_LINES
    if truncated_by_lines:
        body = "\n".join(lines[:_MAX_PREVIEW_LINES])
    else:
        body = text

    truncated_by_chars = len(body) > _MAX_PREVIEW_CHARS
    if truncated_by_chars:
        body = body[:_MAX_PREVIEW_CHARS]

    header = "// PseudoForge preview panel. IDB was not modified.\n"
    if not truncated_by_lines and not truncated_by_chars:
        return header + "\n" + body

    source = str(source_path) if source_path else "(not saved)"
    notice = (
        "// Panel text truncated for IDA UI responsiveness.\n"
        "// Use the simple preview fallback or export path for full content.\n"
        "// Source: %s\n"
        "// Preview limit: %d chars, %d lines\n"
        % (source, _MAX_PREVIEW_CHARS, _MAX_PREVIEW_LINES)
    )
    return header + notice + "\n" + body


class _ForgeTextViewer(ida_kernwin.simplecustviewer_t if ida_kernwin else object):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.title = title
        self.full_text = ""
        self.source_path: Path | None = None
        self.suggested_filename = ""
        self.copy_from_source = True
        self.target_stem = ""

    def update_content(
        self,
        display_text: str,
        full_text: str,
        source_path: str | Path | None,
        suggested_filename: str | None = None,
        copy_from_source: bool = True,
        target_stem: str | None = None,
    ) -> None:
        self.full_text = full_text
        self.source_path = Path(source_path) if source_path else self.source_path
        self.suggested_filename = suggested_filename or self.suggested_filename
        self.copy_from_source = copy_from_source
        self.target_stem = target_stem or self.target_stem
        self.ClearLines()
        lines = display_text.splitlines() or [""]
        _trace_checkpoint("simple_viewer.highlight.before", title=self.title, lines=len(lines))
        highlighted_lines = _highlight_preview_lines(lines)
        _trace_checkpoint("simple_viewer.highlight.after", title=self.title, lines=len(highlighted_lines))
        _trace_checkpoint("simple_viewer.add_lines.before", title=self.title, lines=len(highlighted_lines))
        for line in highlighted_lines:
            self.AddLine(line)
        _trace_checkpoint("simple_viewer.add_lines.after", title=self.title)
        _trace_checkpoint("simple_viewer.refresh.before", title=self.title)
        self.Refresh()
        _trace_checkpoint("simple_viewer.refresh.after", title=self.title)

    def OnPopup(self, form, popup_handle):
        global _ACTIVE_VIEWER
        _ACTIVE_VIEWER = self
        try:
            idaapi.attach_action_to_popup(form, popup_handle, _COPY_ACTION, "PseudoForge/")
            idaapi.attach_action_to_popup(form, popup_handle, _SAVE_ACTION, "PseudoForge/")
            idaapi.attach_action_to_popup(form, popup_handle, _FUNCTIONS_ACTION, "PseudoForge/")
        except Exception as exc:
            log_checkpoint("preview.popup.failed", error=str(exc))
        return True


class _PreviewActionHandler(idaapi.action_handler_t if idaapi else object):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def activate(self, ctx):
        _trace_checkpoint("preview_action.activate.before", callback=getattr(self.callback, "__name__", "callback"))
        viewer = _active_viewer()
        if viewer is None:
            _trace_checkpoint("preview_action.activate.no_viewer")
            return 1
        self.callback(viewer)
        _trace_checkpoint("preview_action.activate.after", title=viewer.title)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 1


def _copy_viewer_all(viewer: _ForgeTextViewer) -> None:
    _trace_checkpoint("copy_all.enter", title=viewer.title, source=viewer.source_path)
    try:
        text, source_path = _copy_source_text(viewer)
        _trace_checkpoint("copy_all.api.before", title=viewer.title, chars=len(text), source=source_path)
        byte_count = _set_windows_clipboard_text(text)
        _write_copy_status("ok api chars=%d bytes=%d source=%s" % (len(text), byte_count, source_path))
        _trace_checkpoint("copy_all.api.after", title=viewer.title, chars=len(text), bytes=byte_count)
    except Exception as exc:
        _write_copy_status("failed api %s" % _ascii_for_log(str(exc)))
        _trace_checkpoint("copy_all.failed", title=viewer.title, error=str(exc))
        warning("PseudoForge Copy all failed: %s" % exc)


def _save_viewer_as(viewer: _ForgeTextViewer) -> None:
    default_name = viewer.suggested_filename or _safe_preview_filename(viewer.title)
    path = ida_kernwin.ask_file(True, default_name, "Save PseudoForge preview")
    if not path:
        return
    if viewer.copy_from_source and viewer.source_path is not None and viewer.source_path.exists():
        text = viewer.source_path.read_text(encoding="utf-8", errors="replace")
    else:
        text = viewer.full_text
    text = _finalize_rendered_c_like_text(text)
    Path(path).write_text(text, encoding="utf-8")
    log_event("preview.save title=\"%s\" path=\"%s\"" % (_ascii_for_log(viewer.title), _ascii_for_log(path)))


def _show_viewer_functions(viewer: _ForgeTextViewer) -> None:
    show_analyzed_functions_from_text(
        viewer.full_text,
        source_path=viewer.source_path,
        target_stem=_viewer_target_stem(viewer),
        source_title=viewer.title,
    )


def show_analyzed_functions_from_text(
    forge_text: str,
    source_path: str | Path | None = None,
    target_stem: str | None = None,
    source_title: str = "PseudoForge analyzed functions",
) -> bool:
    text = _finalize_rendered_c_like_text(forge_text)
    if source_path is not None:
        path = Path(source_path)
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                text = _finalize_rendered_c_like_text(forge_text)

    sections = parse_forge_function_sections(text)
    _trace_checkpoint("preview.functions.enter", title=source_title, count=len(sections))
    if not sections:
        warning("PseudoForge has no cached analyzed function sections.")
        return False

    selected = _choose_forge_function(sections)
    if selected is None:
        _trace_checkpoint("preview.functions.cancelled", title=source_title)
        return False

    resolved_target_stem = target_stem or _source_target_stem(source_path)
    title = "PseudoForge: %s!%s 0x%X" % (resolved_target_stem, selected.name, selected.ea)
    side_by_side_kwargs = {}
    if selected.raw_pseudocode:
        side_by_side_kwargs = {
            "reference_text": selected.raw_pseudocode,
            "reference_title": "Raw Hex-Rays pseudocode",
            "content_title": "PseudoForge cleaned pseudocode",
            "summary_text": "PseudoForge cached analysis 0x%X: raw pseudocode loaded from .forge." % selected.ea,
        }
    show_text_view(
        title,
        selected.text,
        source_path=source_path,
        suggested_filename=build_save_as_filename(resolved_target_stem, selected.name, selected.ea),
        copy_from_source=False,
        target_stem=resolved_target_stem,
        **side_by_side_kwargs,
    )
    _trace_checkpoint(
        "preview.functions.opened",
        title=source_title,
        function=selected.name,
        ea="0x%X" % selected.ea,
    )
    return True


def _choose_forge_function(sections: list[ForgeFunctionSection]) -> ForgeFunctionSection | None:
    if ida_kernwin is None:
        return sections[0] if sections else None

    class FunctionChooser(ida_kernwin.Choose):
        def __init__(self):
            super().__init__(
                "PseudoForge analyzed functions",
                [
                    ["EA", 18],
                    ["Name", 48],
                    ["Fingerprint", 32],
                ],
                flags=0,
            )

        def OnGetLine(self, index):
            section = sections[index]
            return [
                "0x%X" % section.ea,
                section.name,
                section.fingerprint[:32],
            ]

        def OnGetSize(self):
            return len(sections)

    chooser = FunctionChooser()
    selected_index = chooser.Show(modal=True)
    if selected_index < 0 or selected_index >= len(sections):
        return None
    return sections[selected_index]


def _viewer_target_stem(viewer: _ForgeTextViewer) -> str:
    if viewer.target_stem:
        return viewer.target_stem
    return _source_target_stem(viewer.source_path)


def _source_target_stem(source_path: str | Path | None) -> str:
    if source_path is not None:
        return Path(source_path).stem or "target"
    return "target"


def _ensure_preview_actions() -> None:
    global _ACTIONS_REGISTERED
    if _ACTIONS_REGISTERED or idaapi is None:
        return
    for action_name, label, callback in (
        (_COPY_ACTION, "Copy all", _copy_viewer_all),
        (_SAVE_ACTION, "Save as...", _save_viewer_as),
        (_FUNCTIONS_ACTION, "Analyzed functions...", _show_viewer_functions),
    ):
        try:
            idaapi.unregister_action(action_name)
        except Exception:
            pass
        desc = idaapi.action_desc_t(
            action_name,
            label,
            _PreviewActionHandler(callback),
            "",
            label,
            -1,
        )
        idaapi.register_action(desc)
    _ACTIONS_REGISTERED = True


def cleanup_preview_actions() -> None:
    global _ACTIONS_REGISTERED, _ACTIVE_VIEWER
    if idaapi is not None:
        for action_name in (
            _COPY_ACTION,
            _SAVE_ACTION,
            _FUNCTIONS_ACTION,
        ):
            try:
                idaapi.unregister_action(action_name)
            except Exception:
                pass
    _ACTIONS_REGISTERED = False
    _ACTIVE_VIEWER = None


def _active_viewer() -> _ForgeTextViewer | None:
    if _ACTIVE_VIEWER is not None:
        return _ACTIVE_VIEWER
    for viewer in _VIEWERS.values():
        try:
            if viewer.IsFocused():
                return viewer
        except Exception:
            pass
    return None


def _bounded_preview_text(text: str, source_path: str | Path | None) -> str:
    lines = text.splitlines()
    truncated_by_lines = len(lines) > _MAX_PREVIEW_LINES
    if truncated_by_lines:
        body = "\n".join(lines[:_MAX_PREVIEW_LINES])
    else:
        body = text

    truncated_by_chars = len(body) > _MAX_PREVIEW_CHARS
    if truncated_by_chars:
        body = body[:_MAX_PREVIEW_CHARS]

    header = (
        "// PseudoForge preview. IDB was not modified.\n"
        "// Right-click for Copy all, Save as, or Analyzed functions.\n"
    )
    if not truncated_by_lines and not truncated_by_chars:
        return header + "\n" + body

    source = str(source_path) if source_path else "(not saved)"
    notice = (
        "// Preview truncated for IDA UI responsiveness.\n"
        "// Copy all and Save as use the full content.\n"
        "// Source: %s\n"
        "// Preview limit: %d chars, %d lines\n"
        % (source, _MAX_PREVIEW_CHARS, _MAX_PREVIEW_LINES)
    )
    return header + notice + "\n" + body


def _highlight_preview_lines(lines: list[str]) -> list[str]:
    if os.environ.get(_DISABLE_HIGHLIGHT_ENV) == "1":
        return lines
    if len(lines) > _MAX_HIGHLIGHT_LINES:
        return lines
    if sum(len(line) for line in lines) > _MAX_HIGHLIGHT_CHARS:
        return lines
    colorizer = _ida_colorizer()
    if colorizer is None:
        return lines
    try:
        return _syntax_highlight_lines(lines, colorizer)
    except Exception as exc:
        log_checkpoint("preview.highlight.failed", error=str(exc))
        return lines


def _syntax_highlight_lines(lines: list[str], colorizer: _Colorizer) -> list[str]:
    highlighted: list[str] = []
    in_block_comment = False
    for line in lines:
        highlighted_line, in_block_comment = _syntax_highlight_line(line, colorizer, in_block_comment)
        highlighted.append(highlighted_line)
    return highlighted


def _syntax_highlight_line(line: str, colorizer: _Colorizer, in_block_comment: bool) -> tuple[str, bool]:
    if not line:
        return line, in_block_comment

    output: list[str] = []
    index = 0
    while index < len(line):
        if in_block_comment:
            end_index = line.find("*/", index)
            if end_index < 0:
                output.append(colorizer(line[index:], "comment"))
                return "".join(output), True
            output.append(colorizer(line[index : end_index + 2], "comment"))
            index = end_index + 2
            in_block_comment = False
            continue

        comment_index = _find_next_comment_start(line, index)
        if comment_index < 0:
            output.append(_highlight_code_segment(line[index:], colorizer))
            break

        if comment_index > index:
            output.append(_highlight_code_segment(line[index:comment_index], colorizer))

        if line.startswith("//", comment_index):
            output.append(colorizer(line[comment_index:], "comment"))
            break

        end_index = line.find("*/", comment_index + 2)
        if end_index < 0:
            output.append(colorizer(line[comment_index:], "comment"))
            in_block_comment = True
            break

        output.append(colorizer(line[comment_index : end_index + 2], "comment"))
        index = end_index + 2

    return "".join(output), in_block_comment


def _find_next_comment_start(line: str, start_index: int) -> int:
    quote = ""
    escaped = False
    index = start_index
    while index < len(line) - 1:
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if line.startswith("//", index) or line.startswith("/*", index):
            return index
        index += 1
    return -1


def _highlight_code_segment(segment: str, colorizer: _Colorizer) -> str:
    if not segment:
        return segment
    if segment.lstrip().startswith("#"):
        return colorizer(segment, "preprocessor")

    output: list[str] = []
    last_index = 0
    for match in _TOKEN_RE.finditer(segment):
        if match.start() > last_index:
            output.append(segment[last_index : match.start()])
        token = match.group(0)
        role = _token_role(segment, match.start(), match.end(), token)
        if role:
            output.append(colorizer(token, role))
        else:
            output.append(token)
        last_index = match.end()
    if last_index < len(segment):
        output.append(segment[last_index:])
    return "".join(output)


def _token_role(segment: str, start: int, end: int, token: str) -> str:
    if token.startswith('"'):
        return "string"
    if token.startswith("'"):
        return "char"
    if token[:1].isdigit() or token.lower().startswith("0x"):
        return "number"
    if token in _C_KEYWORDS:
        return "keyword"
    if token in _C_TYPE_WORDS or token.endswith("_t"):
        return "type"
    if token in _C_CONSTANT_WORDS or token.startswith(("STATUS_", "POOL_FLAG_", "FAST_FAIL_")):
        return "constant"
    if _is_function_like_identifier(segment, end):
        return "function"
    return ""


def _is_function_like_identifier(segment: str, end: int) -> bool:
    index = end
    while index < len(segment) and segment[index].isspace():
        index += 1
    return index < len(segment) and segment[index] == "("


def _ida_colorizer() -> _Colorizer | None:
    if ida_lines is None:
        return None
    colstr = getattr(ida_lines, "COLSTR", None)
    if not callable(colstr):
        return None

    def colorize(text: str, role: str) -> str:
        return colstr(text, _ida_color_for_role(role))

    return colorize


def _ida_color_for_role(role: str):
    if ida_lines is None:
        return 0
    color_names = {
        "char": ("SCOLOR_CHAR", "SCOLOR_STRING"),
        "comment": ("SCOLOR_REGCMT", "SCOLOR_RPTCMT"),
        "constant": ("SCOLOR_MACRO", "SCOLOR_KEYWORD"),
        "function": ("SCOLOR_CNAME", "SCOLOR_DNAME"),
        "keyword": ("SCOLOR_KEYWORD", "SCOLOR_SYMBOL"),
        "number": ("SCOLOR_DNUM", "SCOLOR_NUMBER"),
        "preprocessor": ("SCOLOR_MACRO", "SCOLOR_KEYWORD"),
        "string": ("SCOLOR_STRING", "SCOLOR_CHAR"),
        "type": ("SCOLOR_TYPE", "SCOLOR_KEYWORD"),
    }
    for color_name in color_names.get(role, ("SCOLOR_SYMBOL",)):
        if hasattr(ida_lines, color_name):
            return getattr(ida_lines, color_name)
    return 0


def _write_copy_temp_file(text: str) -> Path:
    temp_dir = Path(tempfile.gettempdir()) / "pseudoforge_clipboard"
    temp_dir.mkdir(parents=True, exist_ok=True)
    path = temp_dir / "copy_all.forge"
    text = _finalize_rendered_c_like_text(text)
    path.write_text(text, encoding="utf-8")
    return path


def _copy_source_text(viewer: _ForgeTextViewer) -> tuple[str, Path]:
    source_path = viewer.source_path
    if viewer.copy_from_source and source_path is not None and source_path.exists():
        text = source_path.read_text(encoding="utf-8", errors="replace")
        return _finalize_rendered_c_like_text(text), source_path

    _trace_checkpoint("copy_all.temp.before", title=viewer.title, chars=len(viewer.full_text))
    temp_path = _write_copy_temp_file(viewer.full_text)
    _trace_checkpoint("copy_all.temp.after", title=viewer.title, source=temp_path)
    return _finalize_rendered_c_like_text(viewer.full_text), temp_path


def _set_windows_clipboard_text(text: str) -> int:
    if os.name != "nt":
        raise RuntimeError("Copy all requires Windows clipboard support outside IDA")

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL

    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL

    cf_unicode_text = 13
    gmem_moveable = 0x0002
    gmem_zeroinit = 0x0040
    clipboard_bytes = _clipboard_text(text).encode("utf-16-le") + b"\x00\x00"

    hmem = kernel32.GlobalAlloc(gmem_moveable | gmem_zeroinit, len(clipboard_bytes))
    if not hmem:
        _raise_last_error("GlobalAlloc")

    locked = kernel32.GlobalLock(hmem)
    if not locked:
        kernel32.GlobalFree(hmem)
        _raise_last_error("GlobalLock")

    try:
        ctypes.memmove(locked, clipboard_bytes, len(clipboard_bytes))
    finally:
        kernel32.GlobalUnlock(hmem)

    opened = False
    for _attempt in range(_COPY_RETRY_COUNT):
        if user32.OpenClipboard(None):
            opened = True
            break
        time.sleep(_COPY_RETRY_DELAY_SECONDS)

    if not opened:
        kernel32.GlobalFree(hmem)
        _raise_last_error("OpenClipboard")

    try:
        if not user32.EmptyClipboard():
            _raise_last_error("EmptyClipboard")
        if not user32.SetClipboardData(cf_unicode_text, hmem):
            _raise_last_error("SetClipboardData")
        hmem = None
    finally:
        user32.CloseClipboard()
        if hmem:
            kernel32.GlobalFree(hmem)

    return len(clipboard_bytes)


def _clipboard_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.replace("\n", "\r\n")


def _write_copy_status(status: str) -> None:
    path = _copy_log_path()
    try:
        path.write_text(status, encoding="utf-8")
    except Exception:
        pass


def _copy_log_path() -> Path:
    temp_dir = Path(tempfile.gettempdir()) / "pseudoforge_clipboard"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir / "copy_all.log"


def _raise_last_error(api_name: str) -> None:
    error = ctypes.get_last_error()
    raise OSError(error, "%s failed: %s" % (api_name, ctypes.FormatError(error)))


def _safe_preview_filename(title: str) -> str:
    stem = "".join(char if char.isalnum() or char in "._-" else "_" for char in title)
    if stem.lower().endswith(".forge"):
        stem = stem[:-6]
    return (stem.strip("._") or "pseudoforge_preview") + ".cpp"


def build_save_as_filename(target_stem: str, function_name: str, function_ea: int) -> str:
    return "PseudoForge__%s__%s_0x%X.cpp" % (
        _safe_filename_part(target_stem or "target"),
        _safe_filename_part(function_name or "function"),
        function_ea,
    )


def _safe_filename_part(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
    return cleaned.strip("._") or "item"


def _single_line_for_log(message: str) -> str:
    return _ascii_for_log(message).replace("\r", " ").replace("\n", " | ")


def _ascii_for_log(message: str) -> str:
    return message.encode("ascii", errors="replace").decode("ascii")


def _trace_checkpoint(event: str, **fields) -> None:
    parts = ["preview.trace", event]
    for key, value in fields.items():
        parts.append("%s=%s" % (key, _ascii_for_log(str(value))))
    message = " ".join(parts)
    log_checkpoint(message)
    try:
        path = Path(tempfile.gettempdir()) / "pseudoforge_preview_trace.log"
        append_bounded_log_line(path, "%0.3f %s" % (time.time(), message))
    except Exception:
        pass
