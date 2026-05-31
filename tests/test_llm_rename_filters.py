from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.forge_store import render_forge_function_section
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from tests.llm_test_helpers import JsonRenameProvider


BAD_INVARIANT_RENAME_SAMPLE = r"""
__int64 __fastcall BadInvariantRenameSample(int a1)
{
  int v7;
  __int64 v8;
  KPROCESSOR_MODE PreviousMode;

  PreviousMode = KeGetCurrentThread()->PreviousMode;
  v7 = 1;
  v8 = 1LL;
  if ( a1 )
    v7 = a1;
  LOBYTE(v8) = PreviousMode;
  return v7 + v8;
}
"""


WEAK_LLM_DISPATCHER_SAMPLE = (
    r"""
__int64 __fastcall LargeDispatcherSample(int a1, void *a2)
{
  int v5;
  void *Buf1[2];
  void *Src[2];
  _DWORD v118[2];
  int v126;
  void *v200;
  __int64 result;
  ULONG v38;
  int v113;
  HANDLE v138;
  HANDLE v146;

  v5 = a1;
  Buf1[0] = 0LL;
  Src[0] = a2;
  v118[0] = 0;
  v126 = 0;
  v200 = a2;
  result = VfProbeAndCaptureUnicodeString(Buf1, a2, 1LL);
  v38 = VfAddVerifierEntry((PCUNICODE_STRING)a2);
  v113 = v5 - 219;
  v138 = (HANDLE)a2;
  v146 = (HANDLE)Src[0];
  VfProbeAndCaptureUnicodeString(Buf1, a2, 1LL);
"""
    + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
    + r"""
  Buf1[1] = Src[0];
  v118[1] = v126;
  if ( v113 == 1 )
    v38 = VfRemoveVerifierEntry(Buf1, a2, v5, 1LL);
  ObReferenceObjectByHandle(v138, 2u, 0LL, 1, &v146, 0LL);
  result = ExSetLeapSecondEnabled();
  if ( v200 )
    return v118[0];
  return v126 + v38 + result;
}
"""
)


POINTER_BOUND_RENAME_SAMPLE = r"""
__int64 __fastcall PointerBoundRenameSample(void *a1, unsigned __int16 a2)
{
  void *Src[2];
  char *v93;

  Src[1] = a1;
  v93 = (char *)Src[1] + a2;
  if ( (unsigned __int64)v93 > 0x7FFFFFFF0000LL || v93 < Src[1] )
    return 0;
  return a2;
}
"""


class LlmRenameFilterTests(unittest.TestCase):
    def test_llm_invariant_names_are_rejected_when_values_change(self) -> None:
        capture = capture_from_pseudocode(BAD_INVARIANT_RENAME_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v7",
                        "new": "booleanTrue",
                        "confidence": 0.90,
                        "reason": "initialized to one",
                    },
                    {
                        "old": "v8",
                        "new": "one",
                        "confidence": 0.90,
                        "reason": "initialized to one",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v7", rename_map)
        self.assertNotIn("v8", rename_map)
        self.assertIn("Skipped value-invariant rename v7->booleanTrue", plan.warnings)
        self.assertIn("Skipped value-invariant rename v8->one", plan.warnings)
        self.assertNotIn("int booleanTrue", rendered)
        self.assertNotIn("__int64 one", rendered)
        self.assertNotIn("LOBYTE(one)", rendered)

    def test_weak_llm_context_names_are_rejected_in_large_dispatchers(self) -> None:
        capture = capture_from_pseudocode(WEAK_LLM_DISPATCHER_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "Buf1",
                        "new": "capturedUnicodeString",
                        "confidence": 0.90,
                        "reason": "temporary captured unicode string",
                    },
                    {
                        "old": "Src",
                        "new": "capturedUnicodeStringBuffer",
                        "confidence": 0.90,
                        "reason": "temporary captured unicode string buffer",
                    },
                    {
                        "old": "v118",
                        "new": "flagsScratch",
                        "confidence": 0.90,
                        "reason": "temporary flags",
                    },
                    {
                        "old": "v126",
                        "new": "scratchFlags",
                        "confidence": 0.90,
                        "reason": "temporary flags",
                    },
                    {
                        "old": "result",
                        "new": "statusResult",
                        "confidence": 0.90,
                        "reason": "status returned by helper calls",
                    },
                    {
                        "old": "v38",
                        "new": "verifierStatus",
                        "confidence": 0.90,
                        "reason": "verifier helper status",
                    },
                    {
                        "old": "v113",
                        "new": "difVerificationOperation",
                        "confidence": 0.90,
                        "reason": "operation selector",
                    },
                    {
                        "old": "v138",
                        "new": "inputHandle",
                        "confidence": 0.90,
                        "reason": "input handle",
                    },
                    {
                        "old": "v146",
                        "new": "targetHandle",
                        "confidence": 0.90,
                        "reason": "target handle",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        normalized_body = rendered.split("PseudoForge normalized original pseudocode.", 1)[-1]
        section = render_forge_function_section(capture, plan, rendered)

        self.assertNotIn("Buf1", rename_map)
        self.assertNotIn("Src", rename_map)
        self.assertNotIn("v118", rename_map)
        self.assertNotIn("v126", rename_map)
        self.assertNotIn("result", rename_map)
        self.assertNotIn("v38", rename_map)
        self.assertNotIn("v113", rename_map)
        self.assertNotIn("v138", rename_map)
        self.assertNotIn("v146", rename_map)
        self.assertIn("Skipped reused dispatcher rename Buf1->capturedUnicodeString", plan.warnings)
        self.assertIn("Skipped reused dispatcher rename Src->capturedUnicodeStringBuffer", plan.warnings)
        self.assertIn("Skipped weak dispatcher rename v118->flagsScratch", plan.warnings)
        self.assertIn("Skipped weak dispatcher rename v126->scratchFlags", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename result->statusResult", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v38->verifierStatus", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v113->difVerificationOperation", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v138->inputHandle", plan.warnings)
        self.assertIn("Skipped unsupported dispatcher rename v146->targetHandle", plan.warnings)
        self.assertNotIn("Skipped weak dispatcher rename", rendered)
        self.assertNotIn("Skipped unsupported dispatcher rename", rendered)
        self.assertNotIn("Skipped reused dispatcher rename", rendered)
        self.assertIn("void *Buf1[2];", rendered)
        self.assertIn("void *Src[2];", rendered)
        self.assertIn("_DWORD v118[2];", rendered)
        self.assertIn("int v126;", rendered)
        self.assertIn("__int64 result;", rendered)
        self.assertIn("ULONG v38;", rendered)
        self.assertIn("int v113;", rendered)
        self.assertIn("HANDLE v138;", rendered)
        self.assertIn("HANDLE v146;", rendered)
        self.assertNotIn("void *capturedUnicodeString", rendered)
        self.assertNotIn("void *capturedUnicodeStringBuffer", rendered)
        self.assertNotIn("_DWORD flagsScratch", rendered)
        self.assertNotIn("int scratchFlags", rendered)
        self.assertNotIn("statusResult", normalized_body)
        self.assertNotIn("verifierStatus", normalized_body)
        self.assertNotIn("difVerificationOperation", normalized_body)
        self.assertNotIn("inputHandle", normalized_body)
        self.assertNotIn("targetHandle", normalized_body)
        self.assertIn("// Warnings: 0", section)
        self.assertIn("    Warnings: 0", section)

    def test_shadowed_llm_skip_warning_is_removed_when_stronger_rename_wins(self) -> None:
        capture = capture_from_pseudocode(
            WEAK_LLM_DISPATCHER_SAMPLE.replace(
                "int v5;\n",
                "int v5;\n  struct _KPROCESS *Process;\n",
            ).replace(
                "v5 = a1;\n",
                "v5 = a1;\n  Process = KeGetCurrentThread()->ApcState.Process;\n",
            ).replace(
                "HANDLE v146;",
                "HANDLE v146;\n  UNICODE_STRING DriverServiceName;",
            )
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "DriverServiceName",
                        "new": "driverServiceName",
                        "confidence": 0.90,
                        "reason": "driver service name",
                    }
                ],
                "warnings": [
                    "Skipped reused dispatcher rename DriverServiceName->driverServiceName",
                    "Skipped reused dispatcher rename Process->process",
                ],
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["DriverServiceName"], "driverServiceName")
        self.assertNotIn("Skipped reused dispatcher rename DriverServiceName->driverServiceName", plan.warnings)
        self.assertNotIn("Skipped unsupported dispatcher rename DriverServiceName->driverServiceName", plan.warnings)
        self.assertEqual(rename_map["Process"], "currentProcess")
        self.assertNotIn("Skipped reused dispatcher rename Process->process", plan.warnings)

    def test_pointer_bound_llm_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(POINTER_BOUND_RENAME_SAMPLE)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v93",
                        "new": "destinationBuffer",
                        "confidence": 0.90,
                        "reason": "computed destination buffer",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("v93", rename_map)
        self.assertIn("Skipped pointer-bound rename v93->destinationBuffer", plan.warnings)
        self.assertIn("char *v93;", rendered)
        self.assertNotIn("destinationBuffer", body)

    def test_pascalcase_llm_local_renames_are_rejected(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall PascalCaseKernelSample(__int64 *a1)
{
  __int64 v3;
  int v5;
  void *v7;

  v3 = *a1;
  v5 = *(_DWORD *)(v3 + 56);
  v7 = (void *)a1[1];
  ExFreePoolWithTag(v7, 0);
  return v5;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a1",
                        "new": "Subsection",
                        "confidence": 0.96,
                        "reason": "inferred structure role",
                    },
                    {
                        "old": "v3",
                        "new": "ControlArea",
                        "confidence": 0.96,
                        "reason": "inferred from offset use",
                    },
                    {
                        "old": "v5",
                        "new": "ControlAreaFlags",
                        "confidence": 0.92,
                        "reason": "flags field value",
                    },
                    {
                        "old": "v7",
                        "new": "subsectionBase",
                        "confidence": 0.90,
                        "reason": "lower camel local name",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertNotIn("a1", rename_map)
        self.assertNotIn("v3", rename_map)
        self.assertNotIn("v5", rename_map)
        self.assertEqual(rename_map["v7"], "subsectionBase")
        self.assertIn("Skipped PascalCase LLM rename a1->Subsection", plan.warnings)
        self.assertIn("Skipped PascalCase LLM rename v3->ControlArea", plan.warnings)
        self.assertIn("Skipped PascalCase LLM rename v5->ControlAreaFlags", plan.warnings)

    def test_llm_path_suppresses_generic_prototype_argument_renames(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall GenericArgumentSample(__int64 a1, int a2)
{
  if ( a2 )
  {
    return a1;
  }
  return 0LL;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=JsonRenameProvider('{"renames":[]}'))
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("a1", rename_map)
        self.assertNotIn("a2", rename_map)
        self.assertIn("__int64 a1, int a2", rendered)
        self.assertNotIn("argument0", rendered)

    def test_generic_llm_argument_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall GenericArgumentSample(__int64 a1)
{
  return a1;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a1",
                        "new": "argument0",
                        "confidence": 0.95,
                        "reason": "generic LLM placeholder",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a1", rename_map)
        self.assertIn("Skipped generic argument rename a1->argument0", plan.warnings)
        self.assertNotIn("argument0", body)

    def test_weak_llm_argument_rename_is_rejected(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall WeakArgumentSample(__int64 a1, int a2, int a3, unsigned int a4)
{
  return a4;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a4",
                        "new": "alignmentPages",
                        "confidence": 0.72,
                        "reason": "uncertain forwarded argument role",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a4", rename_map)
        self.assertIn("Skipped weak argument rename a4->alignmentPages", plan.warnings)
        self.assertNotIn("alignmentPages", body)

    def test_saved_argument_copy_rename_requires_supported_argument_name(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall SavedArgumentCopySample(__int64 a1, int a2, int a3, unsigned int a4)
{
  unsigned int v29;

  v29 = a4;
  return v29;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a4",
                        "new": "allocationFlags",
                        "confidence": 0.62,
                        "reason": "uncertain forwarded flag role",
                    },
                    {
                        "old": "v29",
                        "new": "savedAllocationFlags",
                        "confidence": 0.91,
                        "reason": "saved copy of a4",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a4", rename_map)
        self.assertNotIn("v29", rename_map)
        self.assertIn("Skipped LLM rename a4->allocationFlags: low confidence 0.62", plan.warnings)
        self.assertIn("Skipped unsupported saved-argument rename v29->savedAllocationFlags", plan.warnings)
        self.assertNotIn("savedAllocationFlags", body)

    def test_saved_argument_copy_rename_is_allowed_when_argument_name_is_supported(self) -> None:
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall SavedArgumentCopySample(__int64 a1, int a2, int a3, unsigned int a4)
{
  unsigned int v29;

  v29 = a4;
  return v29;
}
"""
        )
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "a4",
                        "new": "allocationFlags",
                        "confidence": 0.90,
                        "reason": "forwarded flag role",
                    },
                    {
                        "old": "v29",
                        "new": "savedAllocationFlags",
                        "confidence": 0.91,
                        "reason": "saved copy of a4",
                    },
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["a4"], "allocationFlags")
        self.assertEqual(rename_map["v29"], "savedAllocationFlags")

    def test_numeric_dispatcher_llm_rename_is_rejected(self) -> None:
        sample = WEAK_LLM_DISPATCHER_SAMPLE.replace("  int v113;\n", "  int v113;\n  int v115;\n")
        capture = capture_from_pseudocode(sample)
        provider = JsonRenameProvider(
            {
                "renames": [
                    {
                        "old": "v115",
                        "new": "classMinus235",
                        "confidence": 0.90,
                        "reason": "derived from dispatcher class delta",
                    }
                ]
            }
        )
        plan = build_clean_plan(capture, rename_provider=provider)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v115", rename_map)
        self.assertIn("Skipped numeric dispatcher rename v115->classMinus235", plan.warnings)
        self.assertIn("int v115;", rendered)
        self.assertNotIn("classMinus235", rendered.rsplit("*/", 1)[-1])


if __name__ == "__main__":
    unittest.main()
