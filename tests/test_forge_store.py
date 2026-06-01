from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import (
    find_forge_function_section,
    parse_forge_function_sections,
    upsert_forge_section,
    write_forge_function,
)
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.ida import actions as actions_module
from ida_pseudoforge.ida.ui_preview import build_save_as_filename
from ida_pseudoforge.version import VERSION


FORGE_SAMPLE = r"""
__int64 __fastcall ForgeSample(int a1)
{
  int v1;

  v1 = a1;
  if ( v1 )
    return 1;
  return 0;
}
"""


class ForgeStoreTests(unittest.TestCase):
    def test_forge_store_upserts_multiple_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = os.path.join(temp_dir, "a.exe")
            forge_path = os.path.join(temp_dir, "a.forge")
            first_capture = capture_from_pseudocode(FORGE_SAMPLE, name="FirstFunction", ea=0x140001000)
            first_plan = build_clean_plan(first_capture)
            second_capture = capture_from_pseudocode(
                FORGE_SAMPLE.replace("ForgeSample", "SecondFunction"),
                name="SecondFunction",
                ea=0x140002000,
            )
            second_plan = build_clean_plan(second_capture)

            write_forge_function(
                forge_path,
                target_path,
                first_capture,
                first_plan,
                render_cleaned_pseudocode(first_capture, first_plan),
            )
            combined = write_forge_function(
                forge_path,
                target_path,
                second_capture,
                second_plan,
                render_cleaned_pseudocode(second_capture, second_plan),
            )
            updated_first = render_cleaned_pseudocode(first_capture, first_plan) + "\n// updated"
            final_text = write_forge_function(
                forge_path,
                target_path,
                first_capture,
                first_plan,
                updated_first,
            )

            self.assertIn("// Target: " + target_path, combined)
            self.assertIn("ea=0x140001000", final_text)
            self.assertIn("ea=0x140002000", final_text)
            self.assertIn("// updated", final_text)
            self.assertEqual(final_text.count("ea=0x140001000"), 2)

    def test_forge_store_finalizes_c_like_literals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = os.path.join(temp_dir, "ntoskrnl.exe")
            forge_path = os.path.join(temp_dir, "ntoskrnl.forge")
            capture = capture_from_pseudocode(FORGE_SAMPLE, name="FunctionA", ea=0x100)
            plan = build_clean_plan(capture)
            dirty_cleaned = r"""
void FunctionA()
{
  path = L"\Registry\Machine\System";
  image = "\SystemRoot\System32\win32k.sys";
  normal = "line\nnot_a_path";
}
"""

            forge_text = write_forge_function(forge_path, target_path, capture, plan, dirty_cleaned)

            self.assertIn(r'path = L"\\Registry\\Machine\\System";', forge_text)
            self.assertIn(r'image = "\\SystemRoot\\System32\\win32k.sys";', forge_text)
            self.assertIn(r'normal = "line\nnot_a_path";', forge_text)

    def test_forge_store_finalizes_existing_aggregate_on_upsert(self) -> None:
        existing = r"""// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Target: D:\bin\ntoskrnl.exe

// PSEUDOFORGE FUNCTION BEGIN ea=0x200 name=Other fingerprint=old
void Other()
{
  path = L"\Registry\Machine\System";
}
// PSEUDOFORGE FUNCTION END ea=0x200
"""
        section = r"""// PSEUDOFORGE FUNCTION BEGIN ea=0x100 name=FunctionA fingerprint=new
void FunctionA()
{
  path = "\SystemRoot\System32\win32k.sys";
}
// PSEUDOFORGE FUNCTION END ea=0x100
"""

        updated = upsert_forge_section(existing, r"D:\bin\ntoskrnl.exe", 0x100, section)

        self.assertIn("// Version: %s" % VERSION, updated)
        self.assertIn(r'path = L"\\Registry\\Machine\\System";', updated)
        self.assertIn(r'path = "\\SystemRoot\\System32\\win32k.sys";', updated)

    def test_forge_store_updates_existing_aggregate_version_header(self) -> None:
        existing = r"""// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Version: 0.0.1
// Target: D:\bin\ntoskrnl.exe

// PSEUDOFORGE FUNCTION BEGIN ea=0x200 name=Other fingerprint=old
void Other()
{
}
// PSEUDOFORGE FUNCTION END ea=0x200
"""
        section = r"""// PSEUDOFORGE FUNCTION BEGIN ea=0x100 name=FunctionA fingerprint=new
void FunctionA()
{
}
// PSEUDOFORGE FUNCTION END ea=0x100
"""

        updated = upsert_forge_section(existing, r"D:\bin\ntoskrnl.exe", 0x100, section)

        self.assertIn("// Version: %s" % VERSION, updated)
        self.assertNotIn("// Version: 0.0.1", updated)
        self.assertEqual(updated.count("// Version:"), 1)

    def test_forge_store_warns_on_aggregate_call_arity_mismatch(self) -> None:
        existing = r"""// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Target: D:\bin\ntoskrnl.exe

// PSEUDOFORGE FUNCTION BEGIN ea=0x200 name=Helper fingerprint=old
NTSTATUS __fastcall Helper(int a, int b, int c)
{
  return 0;
}
// PSEUDOFORGE FUNCTION END ea=0x200
"""
        section = r"""// PSEUDOFORGE FUNCTION BEGIN ea=0x100 name=Caller fingerprint=new
NTSTATUS __fastcall Caller()
{
  return Helper(1, 2, 3, 4);
}
// PSEUDOFORGE FUNCTION END ea=0x100
"""

        updated = upsert_forge_section(existing, r"D:\bin\ntoskrnl.exe", 0x100, section)
        updated_again = upsert_forge_section(updated, r"D:\bin\ntoskrnl.exe", 0x100, section)

        expected = (
            "// PseudoForge warning: call arity mismatch Helper: "
            "definition has 3 parameter(s), call has 4 argument(s)."
        )
        self.assertIn(expected, updated)
        self.assertEqual(updated_again.count(expected), 1)

    def test_analysis_preview_uses_current_section_not_full_aggregate(self) -> None:
        existing = r"""// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Target: D:\bin\ntoskrnl.exe

// PSEUDOFORGE FUNCTION BEGIN ea=0x100 name=ExpRegisterFirmwareTableInformationHandler fingerprint=old
NTSTATUS __fastcall ExpRegisterFirmwareTableInformationHandler()
{
  return 0;
}
// PSEUDOFORGE FUNCTION END ea=0x100
"""
        section = r"""// PSEUDOFORGE FUNCTION BEGIN ea=0x200 name=NtSetSystemInformation fingerprint=new
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        ULONG systemInformationLength)
{
  return 0;
}
// PSEUDOFORGE FUNCTION END ea=0x200
"""
        aggregate = upsert_forge_section(existing, r"D:\bin\ntoskrnl.exe", 0x200, section)
        calls = []
        original_show = actions_module.show_text_view

        def fake_show(*args, **kwargs):
            calls.append((args, kwargs))

        actions_module.show_text_view = fake_show
        try:
            shown = actions_module._show_forge_section_text(
                Path(r"D:\bin\ntoskrnl.exe"),
                Path(r"D:\bin\ntoskrnl.forge"),
                aggregate,
                0x200,
                "NtSetSystemInformation",
            )
        finally:
            actions_module.show_text_view = original_show

        self.assertTrue(shown)
        self.assertEqual(len(calls), 1)
        title = calls[0][0][0]
        text = calls[0][0][1]
        kwargs = calls[0][1]
        self.assertIn("NtSetSystemInformation", title)
        self.assertIn("PSEUDOFORGE FUNCTION BEGIN ea=0x200", text)
        self.assertIn("NTSTATUS NTAPI NtSetSystemInformation", text)
        self.assertNotIn("ExpRegisterFirmwareTableInformationHandler", text)
        self.assertFalse(kwargs["copy_from_source"])

    def test_forge_sections_and_save_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = os.path.join(temp_dir, "ntoskrnl.exe")
            forge_path = os.path.join(temp_dir, "ntoskrnl.forge")
            capture = capture_from_pseudocode(FORGE_SAMPLE, name="FunctionA", ea=0x100)
            plan = build_clean_plan(capture)
            forge_text = write_forge_function(
                forge_path,
                target_path,
                capture,
                plan,
                render_cleaned_pseudocode(capture, plan),
            )
            sections = parse_forge_function_sections(forge_text)
            section = find_forge_function_section(forge_text, 0x100)

            self.assertEqual(len(sections), 1)
            self.assertEqual(sections[0].name, "FunctionA")
            self.assertEqual(sections[0].ea, 0x100)
            self.assertIsNotNone(section)
            self.assertEqual(section.name, "FunctionA")
            self.assertIsNone(find_forge_function_section(forge_text, 0x200))
            self.assertIn("// Version: %s" % VERSION, forge_text)
            self.assertIn("// PseudoForge version: %s" % VERSION, sections[0].text)
            self.assertIn("PSEUDOFORGE FUNCTION BEGIN", sections[0].text)
            self.assertEqual(
                build_save_as_filename("ntoskrnl", sections[0].name, sections[0].ea),
                "PseudoForge__ntoskrnl__FunctionA_0x100.cpp",
            )

    def test_forge_section_persists_raw_pseudocode_for_cached_side_by_side(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            target_path = os.path.join(temp_dir, "ntoskrnl.exe")
            forge_path = os.path.join(temp_dir, "ntoskrnl.forge")
            capture = capture_from_pseudocode(FORGE_SAMPLE, name="FunctionA", ea=0x100)
            plan = build_clean_plan(capture)

            forge_text = write_forge_function(
                forge_path,
                target_path,
                capture,
                plan,
                render_cleaned_pseudocode(capture, plan),
            )
            section = find_forge_function_section(forge_text, 0x100)

            self.assertIsNotNone(section)
            self.assertIn("PSEUDOFORGE RAW PSEUDOCODE BEGIN", forge_text)
            self.assertIn("PSEUDOFORGE RAW PSEUDOCODE END", forge_text)
            self.assertEqual(section.raw_pseudocode, capture.pseudocode.rstrip() + "\n")
            self.assertNotIn("PSEUDOFORGE RAW PSEUDOCODE BEGIN", section.text)
            self.assertNotIn("PSEUDOFORGE RAW PSEUDOCODE END", section.text)

    def test_legacy_forge_section_without_raw_pseudocode_still_parses(self) -> None:
        forge_text = r"""// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
// Target: D:\bin\ntoskrnl.exe

// PSEUDOFORGE FUNCTION BEGIN ea=0x100 name=FunctionA fingerprint=old
void FunctionA()
{
  return;
}
// PSEUDOFORGE FUNCTION END ea=0x100
"""

        section = find_forge_function_section(forge_text, 0x100)

        self.assertIsNotNone(section)
        self.assertEqual(section.raw_pseudocode, "")
        self.assertIn("void FunctionA()", section.text)


if __name__ == "__main__":
    unittest.main()
