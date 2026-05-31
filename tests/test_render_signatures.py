from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.core.render import _find_signature_end as legacy_find_signature_end
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_signatures import apply_known_function_signature, find_signature_end


NTSET_TYPED_ACCESS_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  int v5;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  UNICODE_STRING DriverServiceName;
  void *Buf1[2];
  char *v6;
  char *v7;
  char *v8;

  v4 = a2;
  v5 = (int)a1;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = 0;
  DriverServiceName.Buffer = L"\Registry\Machine\System";
  v6 = "\SystemRoot\System32\ntoskrnl.exe";
  v7 = "C:\Windows\Temp\driver.sys";
  v8 = "line\nnot_a_path";
  if ( (_DWORD)a3 )
    a1 = &a2->m128i_i8[(unsigned int)a3];
  *(__m128i *)Buf1 = *a2;
  if ( !memcmp((const void *)a2->m128i_i64[1], L"\SystemRoot\System32\win32k.sys", 0x3EuLL) )
    updated = 1;
  LOBYTE(a3) = PreviousMode;
  updated += PsSetCpuQuotaInformation(a2, (unsigned int)v5, a3, 1LL);
  LOBYTE(a2) = PreviousMode;
  updated += MmIssueMemoryListCommand(v5, a2, -1LL, 1LL);
  updated = a2->m128i_i32[0];
  updated += a2[1].m128i_i32[0];
  return updated;
}
"""


class RenderSignatureTests(unittest.TestCase):
    def test_apply_known_function_signature_uses_prototype_name_when_capture_name_is_empty(self) -> None:
        prototype = "__int64 __fastcall DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)"
        text = "\n".join(
            [
                prototype,
                "{",
                "  Irp->IoStatus.Status = 0;",
                "  IofCompleteRequest(Irp, 0);",
                "  return 0;",
                "}",
            ]
        )
        capture = FunctionCapture(name="", prototype=prototype, pseudocode=text)

        rendered = apply_known_function_signature(text, capture)

        self.assertIn("NTSTATUS __fastcall DispatchDeviceControl(", rendered)
        self.assertIn("        PDEVICE_OBJECT deviceObject,", rendered)
        self.assertIn("        PIRP irp)", rendered)

    def test_known_pvoid_signature_keeps_typed_body_alias(self) -> None:
        capture = capture_from_pseudocode(NTSET_TYPED_ACCESS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("PVOID systemInformation,", rendered)
        self.assertIn("__m128i *systemInfo128;", rendered)
        self.assertIn("PVOID userProbeEnd;", rendered)
        self.assertIn("systemInfo128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("userProbeEnd = &systemInfo128->m128i_i8[(unsigned int)systemInformationLength];", rendered)
        self.assertIn("status = systemInfo128->m128i_i32[0];", rendered)
        self.assertIn("status += systemInfo128[1].m128i_i32[0];", rendered)
        self.assertIn("= *systemInfo128;", rendered)
        self.assertIn('driverServiceName.Buffer = L"\\\\Registry\\\\Machine\\\\System";', rendered)
        self.assertIn('"\\\\SystemRoot\\\\System32\\\\ntoskrnl.exe"', rendered)
        self.assertIn('"C:\\\\Windows\\\\Temp\\\\driver.sys"', rendered)
        self.assertIn('"line\\nnot_a_path"', rendered)
        self.assertIn('L"\\\\SystemRoot\\\\System32\\\\win32k.sys"', rendered)
        self.assertIn("PsSetCpuQuotaInformation(systemInformation, (unsigned int)infoClass, (unsigned __int8)previousMode, 1LL);", rendered)
        self.assertIn("MmIssueMemoryListCommand(infoClass, (unsigned __int8)previousMode, -1LL, 1LL);", rendered)
        self.assertNotIn("LOBYTE(systemInformationLength)", rendered)
        self.assertNotIn("LOBYTE(systemInformation)", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)
        self.assertNotIn("systemInformation[1]", rendered)
        self.assertNotIn("*systemInformation", rendered)
        self.assertNotIn("systemInformationClass = &", rendered)

    def test_find_signature_end_handles_multiline_signatures(self) -> None:
        lines = [
            "NTSTATUS Sample(",
            "        PVOID input,",
            "        ULONG length)",
            "{",
        ]

        self.assertEqual(find_signature_end(lines, 0), 2)
        self.assertEqual(legacy_find_signature_end(lines, 0), 2)


if __name__ == "__main__":
    unittest.main()
