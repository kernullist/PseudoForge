from __future__ import annotations

import os
import tempfile
import unittest

from ida_pseudoforge.config import (
    LlmConfig,
    PREVIEW_BACKEND_SIDE_BY_SIDE,
    PreviewConfig,
    PseudoForgeConfig,
    save_config,
)
from ida_pseudoforge.ida import ui_preview as ui_preview_module
from ida_pseudoforge.ida.ui_preview import (
    _MAX_HIGHLIGHT_LINES,
    _SIDE_BY_SIDE_SEARCH_CURRENT_BG,
    _SIDE_BY_SIDE_SEARCH_BG,
    _SIDE_BY_SIDE_SEARCH_MAX_HEIGHT,
    _SIDE_BY_SIDE_STATUS_MAX_HEIGHT,
    _SIDE_BY_SIDE_SUMMARY_MAX_HEIGHT,
    _apply_search_highlights,
    _bounded_panel_text,
    _fixed_width_system_font,
    _highlight_preview_lines,
    _plain_text_no_wrap,
    _qt_horizontal_orientation,
    _search_line_matches,
    _search_text_matches,
    _side_by_side_highlight_spans,
    _side_by_side_summary_text,
    _side_by_side_text_formats,
    _scroll_editors_to_search_match,
    _size_policy_value,
    _syntax_highlight_lines,
    _text_cursor_move_mode,
    _text_cursor_move_operation,
    show_text_view,
    side_by_side_preview_enabled,
)


class UiPreviewTests(unittest.TestCase):
    def test_preview_syntax_highlighting_marks_cpp_tokens(self) -> None:
        lines = [
            "if ( status == STATUS_SUCCESS )",
            "  return ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, POOL_TAG('A', 'R', 'F', 'T'));",
            "  // comment",
            "name = \"http://example//not-comment\"; /* block */",
        ]

        def colorize(text: str, role: str) -> str:
            return "<%s>%s</%s>" % (role, text, role)

        rendered = "\n".join(_syntax_highlight_lines(lines, colorize))

        self.assertIn("<keyword>if</keyword>", rendered)
        self.assertIn("<constant>STATUS_SUCCESS</constant>", rendered)
        self.assertIn("<keyword>return</keyword>", rendered)
        self.assertIn("<function>ExAllocatePool2</function>", rendered)
        self.assertIn("<constant>POOL_FLAG_PAGED</constant>", rendered)
        self.assertIn("<number>0x28uLL</number>", rendered)
        self.assertIn("<char>'A'</char>", rendered)
        self.assertIn("<comment>// comment</comment>", rendered)
        self.assertIn("<string>\"http://example//not-comment\"</string>", rendered)
        self.assertIn("<comment>/* block */</comment>", rendered)

    def test_preview_syntax_highlighting_falls_back_for_large_views(self) -> None:
        lines = ["if ( status == STATUS_SUCCESS )"] * (_MAX_HIGHLIGHT_LINES + 1)

        self.assertEqual(_highlight_preview_lines(lines), lines)

    def test_preview_syntax_highlighting_can_be_disabled(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT")
        os.environ["PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"] = "1"
        try:
            self.assertEqual(_highlight_preview_lines(["if ( STATUS_SUCCESS )"]), ["if ( STATUS_SUCCESS )"])
        finally:
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT", None)
            else:
                os.environ["PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"] = old_value

    def test_preview_syntax_highlighting_accepts_ida_color_tags(self) -> None:
        class FakeIdaLines:
            SCOLOR_KEYWORD = "\x01"
            SCOLOR_REGCMT = "\x02"
            SCOLOR_STRING = "\x03"
            SCOLOR_CHAR = "\x04"
            SCOLOR_DNUM = "\x05"
            SCOLOR_MACRO = "\x06"
            SCOLOR_CNAME = "\x07"
            SCOLOR_TYPE = "\x08"

            @staticmethod
            def COLSTR(text, color):
                return "<%s>%s</>" % (repr(color), text)

        old_ida_lines = ui_preview_module.ida_lines
        ui_preview_module.ida_lines = FakeIdaLines
        try:
            highlighted = ui_preview_module._highlight_preview_lines(["if ( STATUS_SUCCESS ) // comment"])
        finally:
            ui_preview_module.ida_lines = old_ida_lines

        self.assertIn("<'\\x01'>if</>", highlighted[0])
        self.assertIn("<'\\x06'>STATUS_SUCCESS</>", highlighted[0])
        self.assertIn("<'\\x02'>// comment</>", highlighted[0])

    def test_side_by_side_preview_feature_flag_values(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        try:
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
            self.assertTrue(side_by_side_preview_enabled())
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "dockable"
            self.assertTrue(side_by_side_preview_enabled())
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "simple"
            self.assertFalse(side_by_side_preview_enabled())
        finally:
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

    def test_side_by_side_preview_uses_saved_preview_config_without_env(self) -> None:
        old_backend = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            save_config(
                PseudoForgeConfig(
                    llm=LlmConfig(enabled=False),
                    preview=PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE),
                )
            )
            try:
                self.assertTrue(side_by_side_preview_enabled())
            finally:
                if old_backend is None:
                    os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
                else:
                    os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_backend
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_side_by_side_preview_env_overrides_saved_preview_config(self) -> None:
        old_backend = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "simple"
            save_config(
                PseudoForgeConfig(
                    llm=LlmConfig(enabled=False),
                    preview=PreviewConfig(backend=PREVIEW_BACKEND_SIDE_BY_SIDE),
                )
            )
            try:
                self.assertFalse(side_by_side_preview_enabled())
            finally:
                if old_backend is None:
                    os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
                else:
                    os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_backend
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_show_text_view_uses_feature_flagged_side_by_side_backend(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_ida_kernwin = ui_preview_module.ida_kernwin
        old_try = ui_preview_module._try_show_side_by_side_view
        calls = []

        def fake_try(*args, **kwargs):
            calls.append((args, kwargs))
            return True

        os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
        ui_preview_module.ida_kernwin = object()
        ui_preview_module._try_show_side_by_side_view = fake_try
        try:
            backend = show_text_view(
                "PseudoForge: sample",
                "cleaned text",
                reference_text="raw text",
                reference_title="Raw",
                content_title="Cleaned",
            )
        finally:
            ui_preview_module.ida_kernwin = old_ida_kernwin
            ui_preview_module._try_show_side_by_side_view = old_try
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

        self.assertEqual("dockable_side_by_side", backend)
        self.assertEqual(1, len(calls))
        self.assertEqual("PseudoForge: sample", calls[0][0][0])
        self.assertEqual("raw text", calls[0][0][1])
        self.assertEqual("cleaned text", calls[0][0][2])
        self.assertEqual("Raw", calls[0][1]["reference_title"])
        self.assertEqual("Cleaned", calls[0][1]["content_title"])

    def test_side_by_side_panel_text_does_not_advertise_simple_viewer_actions(self) -> None:
        rendered = _bounded_panel_text("int status = 0;", None)

        self.assertIn("PseudoForge preview panel", rendered)
        self.assertNotIn("Right-click", rendered)
        self.assertNotIn("Copy all", rendered)
        self.assertNotIn("Save as", rendered)

    def test_side_by_side_summary_includes_counts_and_analysis_summary(self) -> None:
        summary = _side_by_side_summary_text(
            "int raw;\nreturn raw;",
            "// Warnings\n// Rule diagnostics\nint cleaned;",
            "PseudoForge analyzed 0x1400: 1 rename(s), 0 flow rewrite(s), 1 warning(s)",
        )

        self.assertIn("Raw lines: 2", summary)
        self.assertIn("Cleaned lines: 3", summary)
        self.assertIn("Warning markers: 1", summary)
        self.assertIn("Rule markers: 1", summary)
        self.assertIn("PseudoForge analyzed 0x1400", summary)
        self.assertNotIn("\n", summary)

    def test_side_by_side_summary_pane_height_stays_compact(self) -> None:
        self.assertLessEqual(_SIDE_BY_SIDE_STATUS_MAX_HEIGHT, 20)
        self.assertLessEqual(_SIDE_BY_SIDE_SUMMARY_MAX_HEIGHT, 48)
        self.assertLessEqual(_SIDE_BY_SIDE_SEARCH_MAX_HEIGHT, 30)

    def test_side_by_side_search_line_matches_are_case_insensitive_by_panel(self) -> None:
        matches = _search_line_matches(
            [
                "alpha\nNeedle raw\nbeta",
                "clean\nneedle cleaned\nneedle again",
            ],
            "NEEDLE",
        )

        self.assertEqual(matches, [(0, 1), (1, 1), (1, 2)])

    def test_side_by_side_search_text_matches_include_offsets(self) -> None:
        matches = _search_text_matches(
            [
                "Needle one\nneedle two\nnone",
                "clean needle and needle",
            ],
            "NEEDLE",
        )

        self.assertEqual(
            matches,
            [
                (0, 0, 0, 6),
                (0, 1, 11, 6),
                (1, 0, 6, 6),
                (1, 0, 17, 6),
            ],
        )

    def test_side_by_side_search_scroll_does_not_steal_focus(self) -> None:
        class FakeQtGui:
            class QTextCursor:
                Start = "start"
                Down = "down"

        class FakeCursor:
            def __init__(self) -> None:
                self.moves = []

            def movePosition(self, position):
                self.moves.append(position)
                return True

        class FakeEditor:
            def __init__(self) -> None:
                self.cursor = FakeCursor()
                self.centered = False

            def textCursor(self):
                return self.cursor

            def setTextCursor(self, cursor) -> None:
                self.cursor = cursor

            def centerCursor(self) -> None:
                self.centered = True

            def setFocus(self) -> None:
                raise AssertionError("search scrolling must not steal focus")

        editors = [FakeEditor(), FakeEditor()]

        _scroll_editors_to_search_match(editors, [(1, 2)], 0, FakeQtGui)

        for editor in editors:
            self.assertTrue(editor.centered)
            self.assertEqual(editor.cursor.moves, ["start", "down", "down"])

    def test_side_by_side_qt_compat_helpers_accept_modern_enums(self) -> None:
        class FakeQtCore:
            class Qt:
                class Orientation:
                    Horizontal = "horizontal"

        class FakeQtWidgets:
            class QSizePolicy:
                class Policy:
                    Preferred = "preferred"
                    Fixed = "fixed"

            class QPlainTextEdit:
                class LineWrapMode:
                    NoWrap = "no_wrap"

        class FakeQtGui:
            class QTextCursor:
                class MoveOperation:
                    Start = "start"
                    Down = "down"

                class MoveMode:
                    KeepAnchor = "keep_anchor"

            class QFontDatabase:
                class SystemFont:
                    FixedFont = "fixed_font"

                @staticmethod
                def systemFont(value):
                    return "font:%s" % value

        self.assertEqual(_qt_horizontal_orientation(FakeQtCore), "horizontal")
        self.assertEqual(_plain_text_no_wrap(FakeQtWidgets), "no_wrap")
        self.assertEqual(_text_cursor_move_operation(FakeQtGui, "Start"), "start")
        self.assertEqual(_text_cursor_move_operation(FakeQtGui, "Down"), "down")
        self.assertEqual(_text_cursor_move_mode(FakeQtGui, "KeepAnchor"), "keep_anchor")
        self.assertEqual(_fixed_width_system_font(FakeQtGui), "font:fixed_font")
        self.assertEqual(_size_policy_value(FakeQtWidgets, "Preferred"), "preferred")
        self.assertEqual(_size_policy_value(FakeQtWidgets, "Fixed"), "fixed")

    def test_side_by_side_search_highlights_all_and_current_matches(self) -> None:
        class FakeColor:
            def __init__(self, red, green, blue) -> None:
                self.rgb = (red, green, blue)

        class FakeTextCharFormat:
            def __init__(self) -> None:
                self.background = None
                self.foreground = None

            def setBackground(self, color) -> None:
                self.background = color

            def setForeground(self, color) -> None:
                self.foreground = color

        class FakeCursor:
            KeepAnchor = "keep_anchor"

            def __init__(self, document) -> None:
                self.document = document
                self.positions = []

            def setPosition(self, position, mode=None) -> None:
                self.positions.append((position, mode))

        class FakeQtGui:
            QColor = FakeColor
            QTextCharFormat = FakeTextCharFormat
            QTextCursor = FakeCursor

        class FakeExtraSelection:
            def __init__(self) -> None:
                self.cursor = None
                self.format = None

        class FakeQtWidgets:
            class QTextEdit:
                ExtraSelection = FakeExtraSelection

        class FakeEditor:
            def __init__(self, document) -> None:
                self._document = document
                self.selections = []

            def document(self):
                return self._document

            def setExtraSelections(self, selections) -> None:
                self.selections = selections

        editors = [FakeEditor("raw"), FakeEditor("cleaned")]
        matches = [(0, 0, 2, 6), (1, 0, 4, 6), (1, 2, 20, 6)]

        _apply_search_highlights(editors, matches, 1, FakeQtGui, FakeQtWidgets)

        self.assertEqual(len(editors[0].selections), 1)
        self.assertEqual(len(editors[1].selections), 2)
        self.assertEqual(editors[0].selections[0].format.background.rgb, _SIDE_BY_SIDE_SEARCH_BG)
        self.assertEqual(editors[1].selections[-1].format.background.rgb, _SIDE_BY_SIDE_SEARCH_CURRENT_BG)
        self.assertEqual(editors[1].selections[-1].cursor.positions, [(4, None), (10, "keep_anchor")])

    def test_side_by_side_formats_define_plain_foreground(self) -> None:
        class FakeColor:
            def __init__(self, red, green, blue) -> None:
                self.rgb = (red, green, blue)

        class FakeTextCharFormat:
            def __init__(self) -> None:
                self.foreground = None

            def setForeground(self, color) -> None:
                self.foreground = color

        class FakeQtGui:
            QColor = FakeColor
            QTextCharFormat = FakeTextCharFormat

        formats = _side_by_side_text_formats(FakeQtGui)

        self.assertIn("plain", formats)
        self.assertEqual(formats["plain"].foreground.rgb, (212, 212, 212))
        self.assertEqual(formats["constant"].foreground.rgb, (197, 134, 192))
        self.assertEqual(formats["type"].foreground.rgb, (78, 201, 176))

    def test_side_by_side_highlight_spans_reuse_preview_token_roles(self) -> None:
        spans = []
        for line in [
            "NTSTATUS status = STATUS_SUCCESS;",
            "return DriverEntry('A', 0x10); // comment",
        ]:
            spans.extend(_side_by_side_highlight_spans(line))
        roles = [role for _start, _length, role in spans]

        self.assertIn("type", roles)
        self.assertIn("constant", roles)
        self.assertIn("keyword", roles)
        self.assertIn("function", roles)
        self.assertIn("char", roles)
        self.assertIn("number", roles)
        self.assertIn("comment", roles)

    def test_side_by_side_highlight_spans_keep_comments_line_local(self) -> None:
        self.assertEqual(_side_by_side_highlight_spans("code /* one */ tail"), [(5, 9, "comment")])
        self.assertEqual(_side_by_side_highlight_spans("code /* unterminated")[-1], (5, 15, "comment"))
        self.assertEqual(_side_by_side_highlight_spans("code only"), [])

    def test_side_by_side_highlight_spans_match_preview_preprocessor_range(self) -> None:
        self.assertEqual(_side_by_side_highlight_spans("  #define STATUS_SUCCESS 0"), [(0, 26, "preprocessor")])

    def test_side_by_side_highlight_spans_cover_cpp_roles(self) -> None:
        role_matches = set()
        for line in [
            "#define STATUS_SUCCESS 0",
            "if ( NT_SUCCESS(status) )",
            "status = STATUS_SUCCESS;",
            "return 0xC0000001;",
            "DbgPrint(\"status\", 'x'); // comment",
        ]:
            role_matches.update(role for _start, _length, role in _side_by_side_highlight_spans(line))

        self.assertIn("preprocessor", role_matches)
        self.assertIn("constant", role_matches)
        self.assertIn("keyword", role_matches)
        self.assertIn("number", role_matches)
        self.assertIn("string", role_matches)
        self.assertIn("char", role_matches)
        self.assertIn("function", role_matches)
        self.assertIn("comment", role_matches)

    def test_side_by_side_backend_treats_false_show_result_as_failure(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_ida_kernwin = ui_preview_module.ida_kernwin
        old_load_qt_modules = ui_preview_module._load_qt_modules
        old_form_class = ui_preview_module._side_by_side_form_class
        old_warning = ui_preview_module.warning

        class FakePluginForm:
            WOPN_TAB = 1
            WOPN_RESTORE = 2

        class FakeKernwin:
            PluginForm = FakePluginForm

        class FakeForm:
            def __init__(self, *args, **kwargs) -> None:
                pass

            def Show(self, title, options=0):
                return False

        os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
        ui_preview_module.ida_kernwin = FakeKernwin
        ui_preview_module._load_qt_modules = lambda: object()
        ui_preview_module._side_by_side_form_class = lambda plugin_form_cls, qt_modules: FakeForm
        ui_preview_module.warning = lambda message: None
        try:
            shown = ui_preview_module._try_show_side_by_side_view("PseudoForge: fake", "raw", "clean")
        finally:
            ui_preview_module.ida_kernwin = old_ida_kernwin
            ui_preview_module._load_qt_modules = old_load_qt_modules
            ui_preview_module._side_by_side_form_class = old_form_class
            ui_preview_module.warning = old_warning
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

        self.assertFalse(shown)
        self.assertNotIn("PseudoForge: fake", ui_preview_module._SIDE_BY_SIDE_FORMS)

    def test_side_by_side_backend_warns_when_dockable_prerequisite_is_missing(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_PREVIEW_BACKEND")
        old_ida_kernwin = ui_preview_module.ida_kernwin
        old_warning = ui_preview_module.warning
        warnings = []

        class FakeKernwin:
            pass

        os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = "side_by_side"
        ui_preview_module.ida_kernwin = FakeKernwin
        ui_preview_module.warning = warnings.append
        ui_preview_module._SIDE_BY_SIDE_FALLBACK_WARNINGS.clear()
        try:
            shown = ui_preview_module._try_show_side_by_side_view("PseudoForge: missing form", "raw", "clean")
        finally:
            ui_preview_module.ida_kernwin = old_ida_kernwin
            ui_preview_module.warning = old_warning
            ui_preview_module._SIDE_BY_SIDE_FALLBACK_WARNINGS.clear()
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_PREVIEW_BACKEND", None)
            else:
                os.environ["PSEUDOFORGE_PREVIEW_BACKEND"] = old_value

        self.assertFalse(shown)
        self.assertEqual(len(warnings), 1)
        self.assertIn("fell back to the simple viewer", warnings[0])
        self.assertIn("PluginForm", warnings[0])


if __name__ == "__main__":
    unittest.main()
