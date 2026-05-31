import unittest
import json
import re
from pathlib import Path

from ida_pseudoforge.core.forge_store import (
    render_forge_function_section,
)
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import LocalVariable
from ida_pseudoforge.core.render import (
    _hoist_embedded_semantic_tail_labels,
    render_cleaned_pseudocode,
    render_switch_outline,
)
from ida_pseudoforge.ida.decompiler import merge_lvars_from_text_and_cfunc
from ida_pseudoforge.ida import actions as actions_module
from ida_pseudoforge.version import VERSION

SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  size_t v3;
  __m128i *v4;
  int v5;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  PVOID Object;

  v3 = (unsigned int)a3;
  v4 = a2;
  v5 = (int)a1;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = 0;
  if ( v5 > 113 )
  {
    if ( v5 == 194 )
      return IoProvisionCrashDumpKey();
    v115 = v5 - 235;
    if ( !v115 )
      return HvlQuerySetBootPagesInfo(a2, 0LL);
    v116 = v115 - 8;
    if ( !v116 )
      return (ULONG)-1073741637;
  }
  if ( v5 == 9 )
    return 3221225476LL;
LABEL_214:
  ObfDereferenceObject(Object);
  return updated;
LABEL_421:
  VfFreeCapturedUnicodeString(v4);
  return updated;
  return (ULONG)-1073741821;
}
"""


FIRMWARE_SAMPLE = r"""
__int64 __fastcall ExpRegisterFirmwareTableInformationHandler(
        SYSTEM_FIRMWARE_TABLE_HANDLER *pTableHandler,
        unsigned int tableHandlerSize,
        KPROCESSOR_MODE previousMode)
{
  unsigned int v3;
  struct _KTHREAD *CurrentThread;
  _DWORD *i;
  _DWORD *v7;
  __int64 v8;
  _QWORD *v9;
  __int64 Pool2;
  _QWORD *v11;
  _QWORD *v12;

  v3 = 0;
  if ( previousMode )
    return (unsigned int)-1073741727;
  if ( !pTableHandler || tableHandlerSize < 0x18 )
    return (unsigned int)-1073741820;
  CurrentThread = KeGetCurrentThread();
  --CurrentThread->KernelApcDisable;
  ExAcquireResourceExclusiveLite(&ExpFirmwareTableResource, 1u);
  for ( i = (_DWORD *)(ExpFirmwareTableProviderListHead - 24); ; i = (_DWORD *)(*(_QWORD *)v7 - 24LL) )
  {
    v7 = i + 6;
    if ( &ExpFirmwareTableProviderListHead == (__int64 *)(i + 6) )
      break;
    if ( *i == pTableHandler->ProviderSignature )
    {
      if ( pTableHandler->Register )
      {
        v3 = 0x40000000;
        goto LABEL_22;
      }
      if ( (PVOID)*((_QWORD *)i + 2) == pTableHandler->DriverObject )
      {
        v8 = *(_QWORD *)v7;
        if ( *(_DWORD **)(*(_QWORD *)v7 + 8LL) == v7 )
        {
          v9 = (_QWORD *)*((_QWORD *)i + 4);
          if ( (_DWORD *)*v9 == v7 )
          {
            *v9 = v8;
            *(_QWORD *)(v8 + 8) = v9;
            ObfDereferenceObject(*((PVOID *)i + 2));
            ExFreePoolWithTag(i, 0x54465241u);
            goto LABEL_22;
          }
        }
LABEL_19:
        __fastfail(3u);
      }
      goto LABEL_21;
    }
  }
  if ( !pTableHandler->Register )
  {
LABEL_21:
    v3 = -1073741811;
    goto LABEL_22;
  }
  Pool2 = ExAllocatePool2(0x100uLL, 0x28uLL, 0x54465241u);
  if ( Pool2 )
  {
    v11 = (_QWORD *)(Pool2 + 24);
    *(_DWORD *)Pool2 = pTableHandler->ProviderSignature;
    *(_QWORD *)(Pool2 + 8) = pTableHandler->FirmwareTableHandler;
    *(_QWORD *)(Pool2 + 16) = pTableHandler->DriverObject;
    *(_QWORD *)(Pool2 + 32) = Pool2 + 24;
    *(_QWORD *)(Pool2 + 24) = Pool2 + 24;
    PsReferenceSiloContext(*(_QWORD *)(Pool2 + 16));
    v12 = (_QWORD *)qword_140EFEDD8;
    if ( *(__int64 **)qword_140EFEDD8 != &ExpFirmwareTableProviderListHead )
      goto LABEL_19;
    *v11 = &ExpFirmwareTableProviderListHead;
    v11[1] = v12;
    *v12 = v11;
    qword_140EFEDD8 = (__int64)v11;
  }
  else
  {
    v3 = -1073741670;
  }
LABEL_22:
  ExReleaseResourceLite(&ExpFirmwareTableResource);
  KeLeaveCriticalRegion();
  return v3;
}
"""


MEMBER_RENAME_SAMPLE = r"""
__int64 __fastcall MemberRenameSample(int a1)
{
  KPROCESSOR_MODE PreviousMode;
  _KPROCESS *Process;
  ULONG ActiveProcessorCount;
  ULONG updated;

  PreviousMode = KeGetCurrentThread()->PreviousMode;
  Process = KeGetCurrentThread()->ApcState.Process;
  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  updated = 0;
  return updated + ActiveProcessorCount;
}
"""


POOL_ALLOCATION_SAMPLE = r"""
__int64 __fastcall PoolAllocationSample()
{
  void *Pool2;

  Pool2 = (void *)ExAllocatePool2(0x101uLL, 64, 0x50535845u);
  if ( Pool2 )
  {
    return 1;
  }
  return 0;
}
"""


MULTILINE_CONDITION_SAMPLE = r"""
__int64 __fastcall MultiLineConditionSample(int a1, int a2, int a3)
{
  int v1;

  v1 = 0;
  if ( a1 == 1
    || (a2 = a1 - 2, a1 == 2)
    || (a3 = a1 - 3, a1 == 3) )
    return 0;
  if ( a1 && a2 >= 4
    || a3 )
  {
    return 1;
  }
  return v1;
}
"""


SINGLE_LINE_IF_SAMPLE = r"""
__int64 __fastcall SingleLineIfSample(int a1)
{
  int v1;

  v1 = 0;
  if ( a1 )
    *(_BYTE *)(v1 + 10) = 1;
  v1 = ZwLoadDriver(&DriverServiceName);
  return v1;
}
"""


NTSET_REUSED_M128_ALIAS_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  void *Buf1[2];
  __m128i v148;

  v4 = a2;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = a2->m128i_i32[0];
  if ( (_DWORD)a3 )
    a1 = &a2->m128i_i8[(unsigned int)a3];
  v4 = (__m128i *)Buf1;
  updated += v4->m128i_i32[0];
  v4 = &v148;
  updated += a2[1].m128i_i32[0];
  return updated;
}
"""


NTSET_PRENORMALIZED_REUSED_M128_ALIAS_SAMPLE = r"""
NTSTATUS NTAPI NtSetSystemInformation(
        SYSTEM_INFORMATION_CLASS systemInformationClass,
        PVOID systemInformation,
        ULONG systemInformationLength)
{
  __m128i *systemInfo128 = (__m128i *)systemInformation;
  NTSTATUS status;
  __m128i capturedBlock0;

  status = systemInfo128->m128i_i32[0];
  systemInfo128 = &capturedBlock0;
  status += systemInfo128->m128i_i32[0];
  return status;
}
"""


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


CPU_SET_MASK_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  int v5;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  unsigned int v110;
  unsigned __int64 v111;
  unsigned int v98;
  int v99;
  _BYTE *v100;
  unsigned int v101;
  __int64 v102;
  _BYTE v151[256];
  _BYTE v152[256];
  _BYTE v153[256];

  v4 = a2;
  v5 = (int)a1;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = 0;
  v110 = a3 - 8;
  v111 = a2->m128i_i64[0];
  memmove(v153, &a2->m128i_u64[1], v110);
  if ( v111 >= 2 )
    return 3221225485LL;
  v98 = v110 >> 3;
  v99 = v111;
  v100 = v153;
  memmove(v151, a2, (unsigned int)a3);
  KeModifySystemAllowedCpuSets((unsigned int)a3 >> 3, (_DWORD)v151, 0, 0);
  v101 = a3 - 8;
  v102 = a2->m128i_i64[0];
  memmove(v152, &a2->m128i_u64[1], v101);
  KeSetTagCpuSets(v101 >> 3, v152, v102);
  return (unsigned int)KeModifySystemAllowedCpuSets(v98, (_DWORD)v100, 0, v99);
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


PREVIOUS_MODE_COPY_SAMPLE = r"""
__int64 __fastcall PreviousModeCopySample()
{
  KPROCESSOR_MODE PreviousMode;
  KPROCESSOR_MODE v119;

  PreviousMode = KeGetCurrentThread()->PreviousMode;
  v119 = PreviousMode;
  return v119;
}
"""


DUPLICATE_SEMANTIC_LABEL_SAMPLE = r"""
NTSTATUS __fastcall DuplicateSemanticLabelSample(int a1, int a2)
{
  int status;

  if ( a1 )
  {
    status = -1073741592;
LABEL_40:
    goto LABEL_41;
  }
  if ( a2 )
  {
LABEL_17:
    status = -1073741820;
    goto LABEL_40;
  }
LABEL_21:
  status = -1073741811;
  goto LABEL_40;
LABEL_41:
  return status;
}
"""


class CoreEngineTests(unittest.TestCase):
    def test_build_clean_plan(self):
        capture = capture_from_pseudocode(SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["a1"], "systemInformationClass")
        self.assertEqual(rename_map["a2"], "systemInformation")
        self.assertEqual(rename_map["a3"], "systemInformationLength")
        self.assertEqual(rename_map["v5"], "infoClass")
        self.assertEqual(rename_map["PreviousMode"], "previousMode")
        self.assertTrue(plan.flow_rewrites)
        self.assertIn(235, plan.flow_rewrites[0].recovered_cases)
        self.assertIn(243, plan.flow_rewrites[0].recovered_cases)
        self.assertIn(235, plan.flow_rewrites[0].case_bodies)
        self.assertEqual(
            plan.flow_rewrites[0].case_names[235],
            "SystemHypervisorBootPagesInformation",
        )
        classifications = {label.label: label.classification for label in plan.cleanup_labels}
        self.assertEqual(classifications["LABEL_214"], "dereference_object_and_return")
        self.assertEqual(
            classifications["LABEL_421"],
            "cleanup_captured_unicode_string_and_return",
        )

    def test_render_cleaned_pseudocode(self):
        capture = capture_from_pseudocode(SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("Version: %s" % VERSION, rendered)
        self.assertIn("infoClass", rendered)
        self.assertIn("systemInformationLength", rendered)
        self.assertIn("NTSTATUS NTAPI NtSetSystemInformation(", rendered)
        self.assertIn("SYSTEM_INFORMATION_CLASS systemInformationClass,", rendered)
        self.assertIn("PVOID systemInformation,", rendered)
        self.assertIn("ULONG systemInformationLength)", rendered)
        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("previousMode = KeGetCurrentThread()->PreviousMode;", rendered)
        self.assertNotIn("KeGetCurrentThread()->previousMode", rendered)
        self.assertIn("STATUS_INFO_LENGTH_MISMATCH", rendered)
        self.assertIn("STATUS_INVALID_INFO_CLASS", rendered)
        self.assertIn("PseudoForge recovered switch view", rendered)
        self.assertIn("switch (infoClass)", rendered)
        self.assertIn("infoClass == SystemFlagsInformation", rendered)
        self.assertIn("infoClass - SystemHypervisorBootPagesInformation", rendered)
        self.assertIn("v116 = infoClass - SystemTrustedAppsRuntimeInformation;", rendered)
        self.assertIn("if ( !v115 )", rendered)
        self.assertIn("if ( !v116 )", rendered)
        self.assertNotIn("v116 = v115 - 8;", rendered)
        self.assertNotIn("infoClass == 9", rendered)
        self.assertLess(
            rendered.index("NTSTATUS NTAPI NtSetSystemInformation("),
            rendered.index("PseudoForge recovered switch view"),
        )

    def test_render_switch_outline(self):
        capture = capture_from_pseudocode(SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_switch_outline(capture, plan)

        self.assertIn("switch (infoClass)", rendered)
        self.assertIn("// SystemHypervisorBootPagesInformation", rendered)
        self.assertIn("case 235:", rendered)
        self.assertIn("return HvlQuerySetBootPagesInfo(systemInformation, 0LL);", rendered)
        self.assertIn("case 243:", rendered)

    def test_identifier_renames_do_not_touch_struct_members(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "Process",
                                "new": "targetProcess",
                                "confidence": 0.95,
                                "reason": "local holds current process",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(MEMBER_RENAME_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("previousMode = KeGetCurrentThread()->PreviousMode;", rendered)
        self.assertIn("currentProcess = KeGetCurrentThread()->ApcState.Process;", rendered)
        self.assertIn("activeProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);", rendered)
        self.assertNotIn("KeGetCurrentThread()->previousMode", rendered)
        self.assertNotIn("ApcState.targetProcess", rendered)
        self.assertNotIn("ULONG ActiveProcessorCount;", rendered)

    def test_pool_allocation_result_gets_stable_pattern_name(self):
        capture = capture_from_pseudocode(POOL_ALLOCATION_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["Pool2"], "allocatedBuffer")
        self.assertIn("void *allocatedBuffer;", rendered)
        self.assertIn("allocatedBuffer = (void *)ExAllocatePool2(", rendered)
        self.assertNotIn("void *Pool2;", rendered)
        self.assertNotIn("Pool2 = (void *)", rendered)

    def test_text_lvars_survive_cfunc_lvar_merge(self):
        sample = r"""
__int64 __fastcall TextLvarMergeSample()
{
  ULONG ActiveProcessorCount;
  void *Pool2;

  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  Pool2 = (void *)ExAllocatePool2(0x101uLL, 64, 0x50535845u);
  if ( Pool2 )
  {
    return ActiveProcessorCount;
  }
  return 0;
}
"""
        capture = capture_from_pseudocode(sample)
        capture.lvars = merge_lvars_from_text_and_cfunc(
            capture.lvars,
            [
                LocalVariable(name="v13", type="__int64 *", index=0),
                LocalVariable(name="v14", type="__int64", index=1),
            ],
        )
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["ActiveProcessorCount"], "activeProcessorCount")
        self.assertEqual(rename_map["Pool2"], "allocatedBuffer")
        self.assertIn("activeProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);", rendered)
        self.assertIn("allocatedBuffer = (void *)ExAllocatePool2(", rendered)

    def test_shadowed_duplicate_target_warnings_are_removed(self):
        sample = r"""
__int64 __fastcall DuplicateInputLengthSample(int a1, void *a2, ULONG a3)
{
  size_t v3;

  v3 = (unsigned int)a3;
  return v3;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)

        self.assertFalse(any("Skipped duplicate target inputLength" in warning for warning in plan.warnings))

    def test_reused_m128_alias_splits_original_view_from_mutable_alias(self):
        capture = capture_from_pseudocode(NTSET_REUSED_M128_ALIAS_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v4"], "infoBuffer128")
        self.assertIn("__m128i *infoBuffer128;", rendered)
        self.assertIn("__m128i *systemInformation128;", rendered)
        self.assertIn("systemInformation128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("infoBuffer128 = systemInformation128;", rendered)
        self.assertIn("infoBuffer128 = (__m128i *)Buf1;", rendered)
        self.assertIn("infoBuffer128 = &v148;", rendered)
        self.assertIn("status = systemInformation128->m128i_i32[0];", rendered)
        self.assertIn(
            "userProbeEnd = &systemInformation128->m128i_i8[(unsigned int)systemInformationLength];",
            rendered,
        )
        self.assertIn("status += systemInformation128[1].m128i_i32[0];", rendered)
        self.assertNotIn("__m128i *systemInfo128;", rendered)
        self.assertNotIn("systemInfo128 = (__m128i *)systemInformation;", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)
        self.assertNotIn("((__m128i *)systemInformation)->", rendered)

    def test_prenormalized_reused_m128_alias_is_neutralized(self):
        capture = capture_from_pseudocode(NTSET_PRENORMALIZED_REUSED_M128_ALIAS_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("__m128i *systemInformation128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("__m128i *infoBuffer128 = systemInformation128;", rendered)
        self.assertIn("status = infoBuffer128->m128i_i32[0];", rendered)
        self.assertIn("infoBuffer128 = &capturedBlock0;", rendered)
        self.assertNotIn("systemInfo128", rendered)

    def test_llm_invariant_names_are_rejected_when_values_change(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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

        capture = capture_from_pseudocode(BAD_INVARIANT_RENAME_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v7", rename_map)
        self.assertNotIn("v8", rename_map)
        self.assertIn("Skipped value-invariant rename v7->booleanTrue", plan.warnings)
        self.assertIn("Skipped value-invariant rename v8->one", plan.warnings)
        self.assertNotIn("int booleanTrue", rendered)
        self.assertNotIn("__int64 one", rendered)
        self.assertNotIn("LOBYTE(one)", rendered)

    def test_cpu_set_mask_stack_buffer_pattern_beats_vague_llm_name(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v153",
                                "new": "localInputCopy",
                                "confidence": 0.95,
                                "reason": "local stack copy",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(CPU_SET_MASK_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v153"], "cpuSetMaskStackBuffer")
        self.assertEqual(rename_map["v151"], "cpuSetAllowedMaskStackBuffer")
        self.assertEqual(rename_map["v152"], "cpuSetTagMaskStackBuffer")
        self.assertEqual(rename_map["v101"], "cpuSetTagMaskBytes")
        self.assertEqual(rename_map["v111"], "cpuSetOperation")
        self.assertEqual(rename_map["v99"], "cpuSetOperation32")
        self.assertIn("_BYTE cpuSetMaskStackBuffer[256];", rendered)
        self.assertIn("_BYTE cpuSetAllowedMaskStackBuffer[256];", rendered)
        self.assertIn("_BYTE cpuSetTagMaskStackBuffer[256];", rendered)
        self.assertIn("memmove(cpuSetMaskStackBuffer, &systemInfo128->m128i_u64[1], cpuSetMaskBytes);", rendered)
        self.assertIn(
            "memmove(cpuSetAllowedMaskStackBuffer, systemInformation, (unsigned int)systemInformationLength);",
            rendered,
        )
        self.assertIn("memmove(cpuSetTagMaskStackBuffer, &systemInfo128->m128i_u64[1], cpuSetTagMaskBytes);", rendered)
        self.assertIn("if ( cpuSetOperation >= 2 )", rendered)
        self.assertIn("cpuSetOperation32 = cpuSetOperation;", rendered)
        self.assertIn("cpuSetMaskBuffer = cpuSetMaskStackBuffer;", rendered)
        self.assertNotIn("localInputCopy", rendered)

    def test_weak_llm_context_names_are_rejected_in_large_dispatchers(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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

        capture = capture_from_pseudocode(WEAK_LLM_DISPATCHER_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
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

    def test_shadowed_llm_skip_warning_is_removed_when_stronger_rename_wins(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["DriverServiceName"], "driverServiceName")
        self.assertNotIn("Skipped reused dispatcher rename DriverServiceName->driverServiceName", plan.warnings)
        self.assertNotIn("Skipped unsupported dispatcher rename DriverServiceName->driverServiceName", plan.warnings)
        self.assertEqual(rename_map["Process"], "currentProcess")
        self.assertNotIn("Skipped reused dispatcher rename Process->process", plan.warnings)

    def test_pointer_bound_llm_rename_is_rejected(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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

        capture = capture_from_pseudocode(POINTER_BOUND_RENAME_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("v93", rename_map)
        self.assertIn("Skipped pointer-bound rename v93->destinationBuffer", plan.warnings)
        self.assertIn("char *v93;", rendered)
        self.assertNotIn("destinationBuffer", body)

    def test_pascalcase_llm_local_renames_are_rejected(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertNotIn("a1", rename_map)
        self.assertNotIn("v3", rename_map)
        self.assertNotIn("v5", rename_map)
        self.assertEqual(rename_map["v7"], "subsectionBase")
        self.assertIn("Skipped PascalCase LLM rename a1->Subsection", plan.warnings)
        self.assertIn("Skipped PascalCase LLM rename v3->ControlArea", plan.warnings)
        self.assertIn("Skipped PascalCase LLM rename v5->ControlAreaFlags", plan.warnings)

    def test_llm_path_suppresses_generic_prototype_argument_renames(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return '{"renames":[]}'

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
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("a1", rename_map)
        self.assertNotIn("a2", rename_map)
        self.assertIn("__int64 a1, int a2", rendered)
        self.assertNotIn("argument0", rendered)

    def test_generic_llm_argument_rename_is_rejected(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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

        capture = capture_from_pseudocode(
            """
__int64 __fastcall GenericArgumentSample(__int64 a1)
{
  return a1;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a1", rename_map)
        self.assertIn("Skipped generic argument rename a1->argument0", plan.warnings)
        self.assertNotIn("argument0", body)

    def test_weak_llm_argument_rename_is_rejected(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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

        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall WeakArgumentSample(__int64 a1, int a2, int a3, unsigned int a4)
{
  return a4;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a4", rename_map)
        self.assertIn("Skipped weak argument rename a4->alignmentPages", plan.warnings)
        self.assertNotIn("alignmentPages", body)

    def test_saved_argument_copy_rename_requires_supported_argument_name(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertNotIn("a4", rename_map)
        self.assertNotIn("v29", rename_map)
        self.assertIn("Skipped LLM rename a4->allocationFlags: low confidence 0.62", plan.warnings)
        self.assertIn("Skipped unsupported saved-argument rename v29->savedAllocationFlags", plan.warnings)
        self.assertNotIn("savedAllocationFlags", body)

    def test_saved_argument_copy_rename_is_allowed_when_argument_name_is_supported(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["a4"], "allocationFlags")
        self.assertEqual(rename_map["v29"], "savedAllocationFlags")

    def test_success_accounting_label_is_not_cleanup_dispatch_tail(self):
        capture = capture_from_pseudocode(
            """
unsigned __int64 __fastcall SuccessAccountingTailSample(unsigned int a1)
{
  unsigned __int64 result;

  result = 0x1000LL;
  if ( a1 )
    goto LABEL_36;
LABEL_36:
  GlobalPageCount += a1;
  return result;
  v2 = *(_QWORD *)a1;
  if ( v2 )
    goto LABEL_36;
LABEL_34:
  __fastfail(3u);
}
"""
        )
        plan = build_clean_plan(capture)
        roles = {item.label: item.classification for item in plan.cleanup_labels}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(roles["LABEL_36"], "success_accounting_return_tail")
        self.assertEqual(roles["LABEL_34"], "failfast_corrupt_list_entry")
        self.assertIn("LABEL_36: success_accounting_return_tail", rendered)
        self.assertNotIn("LABEL_36: cleanup_dispatch_tail", rendered)

    def test_previous_mode_copy_pattern_beats_captured_llm_name(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v119",
                                "new": "capturedPreviousMode",
                                "confidence": 0.95,
                                "reason": "copy of previous mode",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(PREVIOUS_MODE_COPY_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v119"], "savedPreviousMode")
        self.assertIn("savedPreviousMode = previousMode;", rendered)
        self.assertNotIn("capturedPreviousMode", rendered)

    def test_numeric_dispatcher_llm_rename_is_rejected(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
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

        sample = WEAK_LLM_DISPATCHER_SAMPLE.replace("  int v113;\n", "  int v113;\n  int v115;\n")
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v115", rename_map)
        self.assertIn("Skipped numeric dispatcher rename v115->classMinus235", plan.warnings)
        self.assertIn("int v115;", rendered)
        self.assertNotIn("classMinus235", rendered.rsplit("*/", 1)[-1])

    def test_multiline_conditions_keep_braces_after_complete_header(self):
        capture = capture_from_pseudocode(MULTILINE_CONDITION_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "if ( argument0 == 1\n"
            "    || (argument1 = argument0 - 2, argument0 == 2)\n"
            "    || (argument2 = argument0 - 3, argument0 == 3) )\n"
            "  {\n"
            "    return 0;\n"
            "  }",
            rendered,
        )
        self.assertIn(
            "if ( argument0 && argument1 >= 4\n"
            "    || argument2 )\n"
            "  {",
            rendered,
        )
        self.assertNotIn("if ( argument0 == 1\n  {", rendered)
        self.assertNotIn("if ( argument0 && argument1 >= 4\n  {", rendered)

    def test_single_line_if_body_wrapping_preserves_following_statement(self):
        capture = capture_from_pseudocode(SINGLE_LINE_IF_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "  if ( argument0 )\n"
            "  {\n"
            "    *(_BYTE *)(v1 + 10) = 1;\n"
            "  }\n"
            "  v1 = ZwLoadDriver(&DriverServiceName);",
            rendered,
        )

    def test_kernel_driver_semantics(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "i",
                                "new": "providerEntry",
                                "confidence": 0.99,
                                "reason": "LLM generic list entry name",
                            },
                            {
                                "old": "v7",
                                "new": "providerListEntry",
                                "confidence": 0.99,
                                "reason": "LLM generic link name",
                            },
                            {
                                "old": "Pool2",
                                "new": "newProviderEntry",
                                "confidence": 0.99,
                                "reason": "LLM generic allocation name",
                            },
                        ],
                        "warnings": [
                            {
                                "message": (
                                    "PsReferenceSiloContext is likely a bad import/name recovery "
                                    "for an object reference routine."
                                )
                            },
                            {
                                "old": "BadReferenceName",
                                "reason": "operand and paired release routine do not match",
                            }
                        ],
                    }
                )

        capture = capture_from_pseudocode(FIRMWARE_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v3"], "status")
        self.assertEqual(rename_map["i"], "providerRecord")
        self.assertEqual(rename_map["v7"], "providerLink")
        self.assertEqual(rename_map["v8"], "nextLink")
        self.assertEqual(rename_map["v9"], "previousLink")
        self.assertEqual(rename_map["Pool2"], "newProviderRecord")
        self.assertEqual(rename_map["v11"], "newProviderLink")
        self.assertEqual(rename_map["v12"], "tailLink")

        self.assertIn("status = STATUS_SUCCESS;", rendered)
        self.assertIn("return STATUS_PRIVILEGE_NOT_HELD;", rendered)
        self.assertIn("return STATUS_INFO_LENGTH_MISMATCH;", rendered)
        self.assertIn("status = STATUS_OBJECT_NAME_EXISTS;", rendered)
        self.assertIn("status = STATUS_INVALID_PARAMETER;", rendered)
        self.assertIn("status = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("Kernel semantic rewrites:", rendered)
        self.assertIn("Kernel insights:", rendered)
        self.assertIn("Inline critical region entry can be normalized to KeEnterCriticalRegion", rendered)
        self.assertIn("LIST_ENTRY unlink pattern detected", rendered)
        self.assertIn("LIST_ENTRY tail insertion pattern detected", rendered)
        self.assertIn("Inferred provider record layout", rendered)
        self.assertIn("Pool tag 0x54465241 decodes to 'ARFT'", rendered)
        self.assertIn("providerRecord owns providerLink at Link offset +0x18", rendered)
        self.assertIn("validated RemoveEntryList(providerLink)", rendered)
        self.assertIn("validated InsertTailList(providerListHead, newProviderLink)", rendered)
        self.assertIn("PseudoForge: inferred record layout", rendered)
        self.assertIn("PDRIVER_OBJECT DriverObject;", rendered)
        self.assertIn("INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD *providerRecord", rendered)
        self.assertIn("NTSTATUS __fastcall ExpRegisterFirmwareTableInformationHandler", rendered)
        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("KeEnterCriticalRegion();", rendered)
        self.assertNotIn("--CurrentThread->KernelApcDisable", rendered)
        self.assertNotIn("--currentThread->KernelApcDisable", rendered)
        self.assertNotIn("struct _KTHREAD *CurrentThread", rendered)
        self.assertIn("LIST_ENTRY *providerListHead;", rendered)
        self.assertIn("providerListHead = (LIST_ENTRY *)&ExpFirmwareTableProviderListHead;", rendered)
        self.assertIn(
            "for ( providerLink = providerListHead->Flink; providerLink != providerListHead; providerLink = providerLink->Flink )",
            rendered,
        )
        self.assertIn("providerRecord = CONTAINING_RECORD(providerLink, INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link);", rendered)
        self.assertIn("if ( providerRecord->DriverObject == pTableHandler->DriverObject )", rendered)
        self.assertIn("goto InvalidParameter;", rendered)
        self.assertIn("goto CorruptListEntry;", rendered)
        self.assertIn("if ( nextLink->Blink == providerLink )", rendered)
        self.assertIn("RemoveEntryList(providerLink);", rendered)
        self.assertIn("InitializeListHead(newProviderLink);", rendered)
        self.assertIn("tailLink = providerListHead->Blink;", rendered)
        self.assertIn("InsertTailList(providerListHead, newProviderLink);", rendered)
        self.assertIn("likely object reference paired with ObfDereferenceObject", rendered)
        self.assertIn("original recovered call target was PsReferenceSiloContext", rendered)
        self.assertIn("PsReferenceSiloContext(newProviderRecord->DriverObject);", rendered)
        self.assertNotIn("ObfReferenceObject(newProviderRecord->DriverObject);", rendered)
        self.assertIn("ExAcquireResourceExclusiveLite(&ExpFirmwareTableResource, TRUE);", rendered)
        self.assertIn(
            "newProviderRecord = ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, POOL_TAG('A', 'R', 'F', 'T'));",
            rendered,
        )
        self.assertIn("ExFreePoolWithTag(providerRecord, POOL_TAG('A', 'R', 'F', 'T'));", rendered)
        self.assertNotIn("providerRecord = (_DWORD *)(*(_QWORD *)providerLink - 24LL)", rendered)
        self.assertNotIn("CONTAINING_RECORD(providerLink->Flink", rendered)
        self.assertNotIn("qword_140EFEDD8 = (__int64)newProviderLink", rendered)
        self.assertNotIn("previousLink = (_QWORD *)", rendered)
        self.assertNotIn("PSEUDOFORGE_FIRMWARE_TABLE_PROVIDER_RECORD", rendered)
        self.assertNotIn("ExAllocatePool2(0x100uLL", rendered)
        self.assertIn("LABEL_19 -> CorruptListEntry: failfast_corrupt_list_entry", rendered)
        self.assertIn("LABEL_21 -> InvalidParameter: set_error_status_and_cleanup", rendered)
        self.assertIn("LABEL_22 -> Cleanup: release_resource_and_leave_critical_region", rendered)
        self.assertRegex(rendered, r"(?m)^CorruptListEntry:$")
        self.assertRegex(rendered, r"(?m)^InvalidParameter:$")
        self.assertRegex(rendered, r"(?m)^Cleanup:$")
        self.assertRegex(
            rendered,
            r"(?ms)^Cleanup:\n"
            r"  // PseudoForge: release_resource_and_leave_critical_region[^\n]*\n"
            r"  ExReleaseResourceLite\(&ExpFirmwareTableResource\);\n"
            r"  KeLeaveCriticalRegion\(\);\n"
            r"  return status;\n"
            r"InvalidParameter:",
        )
        self.assertRegex(
            rendered,
            r"(?m)^InvalidParameter:\n"
            r"  // PseudoForge: set_error_status_and_cleanup[^\n]*\n"
            r"  status = STATUS_INVALID_PARAMETER;\n"
            r"  goto Cleanup;",
        )
        self.assertRegex(
            rendered,
            r"(?m)^CorruptListEntry:\n"
            r"  // PseudoForge: failfast_corrupt_list_entry[^\n]*\n"
            r"  __fastfail\(3u\);",
        )
        self.assertNotRegex(rendered, r"(?m)^CorruptListEntry:\n[^\n]*\n\s{8,}__fastfail")
        self.assertNotRegex(rendered, r"(?m)^InvalidParameter:\n[^\n]*\n\s{4,}status = STATUS_INVALID_PARAMETER;")
        self.assertNotIn("  goto Cleanup;\nInvalidParameter:", rendered)
        self.assertIn("PsReferenceSiloContext is likely a bad import/name recovery", rendered)
        self.assertIn("Potential bad call target PsReferenceSiloContext", rendered)
        self.assertIn("Potential bad call target BadReferenceName", rendered)
        self.assertNotIn("{'message':", rendered)
        self.assertNotIn('{"old":', rendered)
        self.assertIn("if ( !pTableHandler->Register )\n  {\n    goto InvalidParameter;\n  }", rendered)

    def test_embedded_semantic_label_fallback_hoists_stale_layout(self):
        capture = capture_from_pseudocode(FIRMWARE_SAMPLE)
        plan = build_clean_plan(capture)
        stale_text = "\n".join(
            [
                "  if ( providerRecord->DriverObject == pTableHandler->DriverObject )",
                "  {",
                "        CorruptListEntry:",
                "  // PseudoForge: failfast_corrupt_list_entry confidence=0.96; Calls __fastfail(3)",
                "        __fastfail(3u);",
                "      }",
                "      goto InvalidParameter;",
                "  }",
                "  if ( !pTableHandler->Register )",
                "  {",
                "InvalidParameter:",
                "  // PseudoForge: set_error_status_and_cleanup confidence=0.84; Sets an NTSTATUS-style error",
                "    status = STATUS_INVALID_PARAMETER;",
                "    goto Cleanup;",
                "  }",
                "  status = STATUS_INSUFFICIENT_RESOURCES;",
                "Cleanup:",
                "  ExReleaseResourceLite(&ExpFirmwareTableResource);",
            ]
        )

        rendered = _hoist_embedded_semantic_tail_labels(stale_text, plan)

        self.assertIn("        goto CorruptListEntry;", rendered)
        self.assertIn("    goto InvalidParameter;", rendered)
        self.assertIn("Cleanup:\n  ExReleaseResourceLite(&ExpFirmwareTableResource);\nInvalidParameter:", rendered)
        self.assertNotIn("  goto Cleanup;\nInvalidParameter:", rendered)
        self.assertRegex(
            rendered,
            r"(?m)^InvalidParameter:\n"
            r"  // PseudoForge: set_error_status_and_cleanup[^\n]*\n"
            r"  status = STATUS_INVALID_PARAMETER;\n"
            r"  goto Cleanup;",
        )
        self.assertRegex(
            rendered,
            r"(?m)^CorruptListEntry:\n"
            r"  // PseudoForge: failfast_corrupt_list_entry[^\n]*\n"
            r"  __fastfail\(3u\);",
        )
        self.assertNotRegex(rendered, r"(?m)^CorruptListEntry:\n[^\n]*\n\s{8,}__fastfail")

    def test_duplicate_semantic_labels_keep_unique_targets(self):
        capture = capture_from_pseudocode(DUPLICATE_SEMANTIC_LABEL_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("LABEL_17 -> InvalidParameter: set_error_status_and_cleanup", rendered)
        self.assertIn("LABEL_21 -> InvalidParameter_21: set_error_status_and_cleanup", rendered)
        self.assertEqual(len(re.findall(r"(?m)^InvalidParameter:$", rendered)), 1)
        self.assertEqual(len(re.findall(r"(?m)^InvalidParameter_21:$", rendered)), 1)
        self.assertIn("goto LABEL_40;", rendered)
        self.assertNotRegex(rendered, r"(?ms)^InvalidParameter_21:.*?goto InvalidParameter_21;")

if __name__ == "__main__":
    unittest.main()
