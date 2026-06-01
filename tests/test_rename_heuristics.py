from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import LocalVariable
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.ida.decompiler import merge_lvars_from_text_and_cfunc


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


SAME_NAMED_FIELD_LOCAL_SAMPLE = r"""
__int64 __fastcall SameNamedFieldLocalSample(struct _GENERIC_OBJECT *object)
{
  PVOID MappedSystemVa;
  PVOID mappedSystemVaCandidate;

  MappedSystemVa = object->MappedSystemVa;
  mappedSystemVaCandidate = MappedSystemVa;
  return (__int64)mappedSystemVaCandidate;
}
"""


SAME_NAMED_FIELD_CONFLICT_SAMPLE = r"""
__int64 __fastcall SameNamedFieldConflictSample(struct _GENERIC_OBJECT *object)
{
  PVOID MappedSystemVa;
  PVOID mappedSystemVa;

  MappedSystemVa = object->MappedSystemVa;
  mappedSystemVa = MappedSystemVa;
  return (__int64)mappedSystemVa;
}
"""


LIST_ENTRY_HEAD_PARAMETER_SAMPLE = r"""
__int64 __fastcall ListEntryHeadParameterSample(__int64 context, _QWORD *a2, __int64 value)
{
  _QWORD *v1;
  _QWORD *v2;

  v1 = (_QWORD *)*a2;
  if ( (_QWORD *)*a2 == a2 )
  {
    v2 = (_QWORD *)a2[1];
    if ( (_QWORD *)*v2 != a2 )
    {
      __fastfail(3u);
    }
    *v1 = a2;
    a2[1] = v1;
  }
  return value;
}
"""


LIST_ENTRY_HEAD_FALSE_POSITIVE_SAMPLE = r"""
__int64 __fastcall PointerArraySample(_QWORD *a1)
{
  if ( a1[1] )
  {
    return a1[1];
  }
  return 0;
}
"""


LIST_ENTRY_HEAD_LOCAL_SAMPLE = r"""
void __fastcall ListEntryHeadLocalSample(__int64 context)
{
  _QWORD **v11;
  _QWORD *v14;
  _QWORD *v15;

  v11 = (_QWORD **)(context + 136);
  while ( *(_DWORD *)(context + 740) > *(_DWORD *)(context + 736) )
  {
    v14 = *v11;
    if ( *v11 == v11 )
    {
      break;
    }
    if ( (_QWORD **)v14[1] != v11 )
    {
      __fastfail(3u);
    }
    v15 = (_QWORD *)*v14;
    *v11 = v15;
    v15[1] = v11;
  }
}
"""


LOOKASIDE_ENTRY_ALLOCATION_SAMPLE = r"""
void __fastcall LookasideEntryAllocationSample(__int64 context)
{
  _OWORD *v9;

  v9 = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(context + 192));
  if ( v9 )
  {
    *v9 = 0LL;
    *((_QWORD *)v9 + 5) = _InterlockedIncrement((volatile signed __int32 *)(context + 740));
  }
}
"""


LOOKASIDE_ENTRY_ALLOCATION_AMBIGUOUS_SAMPLE = r"""
void __fastcall AmbiguousLookasideEntryAllocationSample(__int64 context)
{
  _OWORD *v9;
  _OWORD *v10;

  v9 = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(context + 192));
  v10 = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(context + 320));
  if ( v9 && v10 )
  {
    *v9 = 0LL;
    *v10 = 0LL;
  }
}
"""


API_OUT_PARAMETER_LOCAL_SAMPLE = r"""
void __fastcall ApiOutParameterLocalSample()
{
  __int64 v16; // [rsp+50h] [rbp+8h] BYREF

  KeQuerySystemTimePrecise(&v16);
  Sink(v16);
}
"""


API_RESULT_LOCAL_SAMPLE = r"""
void __fastcall ApiResultLocalSample(__int64 context)
{
  KIRQL v23;
  HANDLE v24;

  v23 = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(context + 128));
  v24 = PsGetCurrentThreadId();
  KeReleaseSpinLock((PKSPIN_LOCK)(context + 128), v23);
  Sink(v24);
}
"""


API_RESULT_PASCAL_LOCAL_SAMPLE = r"""
void __fastcall ApiResultPascalLocalSample(PVOID object)
{
  HANDLE CurrentThreadId;
  HANDLE ProcessId;
  PIO_WORKITEM WorkItem;

  CurrentThreadId = PsGetCurrentThreadId();
  ProcessId = PsGetProcessId((PEPROCESS)object);
  WorkItem = IoAllocateWorkItem((PDEVICE_OBJECT)object);
  Sink(CurrentThreadId, ProcessId, WorkItem);
}
"""


API_ARGUMENT_LOCAL_SAMPLE = r"""
void __fastcall ApiArgumentLocalSample(__int64 context, void *entry)
{
  struct _NPAGED_LOOKASIDE_LIST *v8;

  v8 = (struct _NPAGED_LOOKASIDE_LIST *)(context + 192);
  ExFreeToNPagedLookasideList(v8, entry);
}
"""


API_ARGUMENT_AMBIGUOUS_SAMPLE = r"""
void __fastcall ApiArgumentAmbiguousSample(void *entry)
{
  struct _NPAGED_LOOKASIDE_LIST *v8;
  struct _NPAGED_LOOKASIDE_LIST *v9;

  ExFreeToNPagedLookasideList(v8, entry);
  ExFreeToNPagedLookasideList(v9, entry);
}
"""


API_ARGUMENT_CASE_VARIANT_SAMPLE = r"""
void __fastcall ApiArgumentCaseVariantSample()
{
  struct _MDL *Mdl;
  struct _MDL *v6;

  IoFreeMdl(v6);
  Sink(Mdl);
}
"""


STRUCTURE_BASE_PARAMETER_SAMPLE = r"""
void __fastcall StructureBaseParameterSample(__int64 a1)
{
  if ( !_InterlockedCompareExchange((volatile signed __int32 *)(a1 + 812), 0, 0) )
  {
    ExAcquireFastMutex((PFAST_MUTEX)(a1 + 72));
    KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(a1 + 128));
    *(_DWORD *)(a1 + 784) = STATUS_INSUFFICIENT_RESOURCES;
  }
}
"""


STRUCTURE_BASE_FALSE_POSITIVE_SAMPLE = r"""
__int64 __fastcall ScalarArithmeticSample(__int64 a1)
{
  __int64 v1;

  v1 = a1 + 8;
  return v1 + a1 + 16;
}
"""


OPTIMIZED_MEMMOVE_PARAMETER_SAMPLE = r"""
void *__fastcall OptimizedMoveSample(char *a1, char *a2, unsigned __int64 a3)
{
  void *result;
  signed __int64 v4;
  char *v5;
  char v6;

  result = a1;
  if ( a3 )
  {
    v4 = a2 - a1;
    if ( a2 < a1 )
    {
      v5 = &a1[a3];
      do
      {
        v6 = v5[v4 - 1];
        --v5;
        --a3;
        *v5 = v6;
      }
      while ( a3 );
    }
    else
    {
      do
      {
        v6 = a1[v4];
        ++a1;
        --a3;
        *(a1 - 1) = v6;
      }
      while ( a3 );
    }
  }
  return result;
}
"""


OPTIMIZED_MEMSET_PARAMETER_SAMPLE = r"""
__int64 __fastcall OptimizedFillSample(char *a1, unsigned __int8 a2, unsigned __int64 a3)
{
  __int64 result;
  __int64 v4;

  result = (__int64)a1;
  v4 = 0x101010101010101LL * a2;
  if ( a3 >= 4 )
  {
    *(_DWORD *)a1 = v4;
    *(_DWORD *)&a1[a3 - 4] = v4;
  }
  else
  {
    if ( a3 )
    {
      *a1 = v4;
    }
  }
  return result;
}
"""


RUNTIME_MEMORY_FALSE_POSITIVE_SAMPLE = r"""
__int64 __fastcall ThreeArgumentArithmeticSample(char *a1, unsigned __int8 a2, unsigned __int64 a3)
{
  __int64 result;

  result = (__int64)a1;
  if ( a3 > 4 )
  {
    return result + a2 + a3;
  }
  return result;
}
"""


RUNTIME_MEMORY_REASSIGNED_RESULT_SAMPLE = r"""
void *__fastcall ReassignedResultSample(char *a1, char *a2, unsigned __int64 a3)
{
  void *result;
  signed __int64 v4;

  result = a1;
  v4 = a2 - a1;
  if ( a2 < a1 && a3 )
  {
    a1[a3 - 1] = a2[a3 - 1];
  }
  result = a2;
  return result;
}
"""


RUNTIME_MEMORY_MUTATED_RESULT_SAMPLE = r"""
void *__fastcall MutatedResultSample(char *a1, char *a2, unsigned __int64 a3)
{
  char *result;
  signed __int64 v4;

  result = a1;
  v4 = a2 - a1;
  if ( a2 < a1 && a3 )
  {
    a1[a3 - 1] = a2[a3 - 1];
  }
  ++result;
  return result;
}
"""


OUTPUT_BUFFER_CONTRACT_SAMPLE = r"""
__int64 __fastcall OutputBufferContractSample(__int64 a1, _DWORD *a2, unsigned int a3, _QWORD *a4)
{
  __int64 **v1;

  if ( a3 < 0x18 )
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  v1 = (__int64 **)(a1 + 136);
  *a2 = 24;
  a2[1] = 1;
  a2[4] = *(_DWORD *)(a1 + 740);
  *(_OWORD *)&a2[6] = *((_OWORD *)*v1 + 1);
  *a4 = 24LL;
  KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(a1 + 128));
  return 0LL;
}
"""


OUTPUT_BUFFER_CONTRACT_FALSE_POSITIVE_SAMPLE = r"""
__int64 __fastcall LengthCheckedInputSample(_DWORD *a1, _DWORD *a2, unsigned int a3, _QWORD *a4)
{
  if ( a3 < 0x18 )
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  *a4 = a3;
  return *a1 + *a2;
}
"""


class RenameHeuristicTests(unittest.TestCase):
    def test_identifier_renames_do_not_touch_struct_members(self) -> None:
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

    def test_pool_allocation_result_gets_stable_pattern_name(self) -> None:
        capture = capture_from_pseudocode(POOL_ALLOCATION_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["Pool2"], "allocatedBuffer")
        self.assertIn("void *allocatedBuffer;", rendered)
        self.assertIn("allocatedBuffer = (void *)ExAllocatePool2(", rendered)
        self.assertNotIn("void *Pool2;", rendered)
        self.assertNotIn("Pool2 = (void *)", rendered)

    def test_text_lvars_survive_cfunc_lvar_merge(self) -> None:
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

    def test_cpu_set_mask_stack_buffer_pattern_beats_vague_llm_name(self) -> None:
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
                            },
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

    def test_previous_mode_copy_pattern_beats_captured_llm_name(self) -> None:
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

    def test_same_named_field_local_gets_lower_camel_name(self) -> None:
        capture = capture_from_pseudocode(SAME_NAMED_FIELD_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["MappedSystemVa"], "mappedSystemVa")
        self.assertIn("PVOID mappedSystemVa;", rendered)
        self.assertIn("mappedSystemVa = object->MappedSystemVa;", rendered)
        self.assertIn("return (__int64)mappedSystemVa;", rendered)
        self.assertNotIn("mappedSystemVaCandidate", rendered)
        self.assertNotIn("object->mappedSystemVa", rendered)

    def test_same_named_field_local_skips_existing_target_name(self) -> None:
        capture = capture_from_pseudocode(SAME_NAMED_FIELD_CONFLICT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("MappedSystemVa", rename_map)
        self.assertIn("PVOID MappedSystemVa;", rendered)
        self.assertIn("MappedSystemVa = object->MappedSystemVa;", rendered)

    def test_same_named_field_local_yields_to_stronger_suggestion(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "MappedSystemVa", "new": "mappedAddress", "confidence": 0.90},
                        ]
                    }
                )

        capture = capture_from_pseudocode(SAME_NAMED_FIELD_LOCAL_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["MappedSystemVa"], "mappedAddress")
        self.assertIn("mappedAddress = object->MappedSystemVa;", rendered)
        self.assertNotIn("object->mappedAddress", rendered)

    def test_list_entry_head_parameter_gets_dataflow_name(self) -> None:
        capture = capture_from_pseudocode(LIST_ENTRY_HEAD_PARAMETER_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a2"], "listHead")
        self.assertIn("_QWORD *listHead", rendered)
        self.assertIn("(_QWORD *)*listHead == listHead", rendered)
        self.assertNotIn("argument1", rendered)

    def test_list_entry_head_parameter_requires_self_referential_use(self) -> None:
        capture = capture_from_pseudocode(LIST_ENTRY_HEAD_FALSE_POSITIVE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("listHead", rename_map.values())
        self.assertIn("argument0[1]", rendered)

    def test_structure_base_parameter_gets_context_name(self) -> None:
        capture = capture_from_pseudocode(STRUCTURE_BASE_PARAMETER_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "context")
        self.assertIn("StructureBaseParameterSample(__int64 context)", rendered)
        self.assertIn("(volatile signed __int32 *)(context + 812)", rendered)
        self.assertIn("(PFAST_MUTEX)(context + 72)", rendered)

    def test_structure_base_parameter_requires_pointer_offset_evidence(self) -> None:
        capture = capture_from_pseudocode(STRUCTURE_BASE_FALSE_POSITIVE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("context", rename_map.values())
        self.assertIn("argument0 + 8", rendered)

    def test_list_entry_head_local_gets_dataflow_name(self) -> None:
        capture = capture_from_pseudocode(LIST_ENTRY_HEAD_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v11"], "listHead")
        self.assertIn("_QWORD **listHead;", rendered)
        self.assertIn("if ( *listHead == listHead )", rendered)
        self.assertIn("v15[1] = listHead;", rendered)

    def test_single_lookaside_allocation_result_gets_entry_name(self) -> None:
        capture = capture_from_pseudocode(LOOKASIDE_ENTRY_ALLOCATION_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v9"], "lookasideEntry")
        self.assertIn("_OWORD *lookasideEntry;", rendered)
        self.assertIn("lookasideEntry = ExAllocateFromNPagedLookasideList", rendered)
        self.assertNotIn("*v9 = 0LL;", rendered)

    def test_lookaside_allocation_rename_skips_ambiguous_multiple_allocations(self) -> None:
        capture = capture_from_pseudocode(LOOKASIDE_ENTRY_ALLOCATION_AMBIGUOUS_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("lookasideEntry", rename_map.values())
        self.assertIn("v9 = ExAllocateFromNPagedLookasideList", rendered)
        self.assertIn("v10 = ExAllocateFromNPagedLookasideList", rendered)

    def test_api_out_parameter_local_gets_profile_parameter_name(self) -> None:
        capture = capture_from_pseudocode(API_OUT_PARAMETER_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v16"], "currentTime")
        self.assertIn("KeQuerySystemTimePrecise(&currentTime);", rendered)
        self.assertIn("Sink(currentTime);", rendered)

    def test_api_result_locals_get_profile_backed_names(self) -> None:
        capture = capture_from_pseudocode(API_RESULT_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v23"], "oldIrql")
        self.assertEqual(rename_map["v24"], "currentThreadId")
        self.assertIn("oldIrql = KeAcquireSpinLockRaiseToDpc", rendered)
        self.assertIn("currentThreadId = PsGetCurrentThreadId();", rendered)
        self.assertIn("KeReleaseSpinLock((PKSPIN_LOCK)(context + 128), oldIrql);", rendered)

    def test_api_result_pascal_locals_get_lower_camel_names(self) -> None:
        capture = capture_from_pseudocode(API_RESULT_PASCAL_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["CurrentThreadId"], "currentThreadId")
        self.assertEqual(rename_map["ProcessId"], "processId")
        self.assertEqual(rename_map["WorkItem"], "workItem")
        self.assertIn("currentThreadId = PsGetCurrentThreadId();", rendered)
        self.assertIn("processId = PsGetProcessId((PEPROCESS)object);", rendered)
        self.assertIn("workItem = IoAllocateWorkItem((PDEVICE_OBJECT)object);", rendered)

    def test_api_argument_local_gets_profile_parameter_name(self) -> None:
        capture = capture_from_pseudocode(API_ARGUMENT_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v8"], "lookasideList")
        self.assertIn("lookasideList = (struct _NPAGED_LOOKASIDE_LIST *)(context + 192);", rendered)
        self.assertIn("ExFreeToNPagedLookasideList(lookasideList, entry);", rendered)

    def test_api_argument_local_skips_ambiguous_same_target(self) -> None:
        capture = capture_from_pseudocode(API_ARGUMENT_AMBIGUOUS_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("lookasideList", rename_map.values())
        self.assertIn("ExFreeToNPagedLookasideList(v8, entry);", rendered)
        self.assertIn("ExFreeToNPagedLookasideList(v9, entry);", rendered)

    def test_api_argument_local_skips_case_variant_existing_local(self) -> None:
        capture = capture_from_pseudocode(API_ARGUMENT_CASE_VARIANT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("mdl", rename_map.values())
        self.assertIn("IoFreeMdl(v6);", rendered)
        self.assertIn("Sink(Mdl);", rendered)

    def test_optimized_memmove_parameters_get_dataflow_names(self) -> None:
        capture = capture_from_pseudocode(OPTIMIZED_MEMMOVE_PARAMETER_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "destination")
        self.assertEqual(rename_map["a2"], "source")
        self.assertEqual(rename_map["a3"], "byteCount")
        self.assertIn("OptimizedMoveSample(char *destination, char *source, unsigned __int64 byteCount)", rendered)
        self.assertIn("v4 = source - destination;", rendered)
        self.assertIn("v5 = &destination[byteCount];", rendered)

    def test_optimized_memset_parameters_get_dataflow_names(self) -> None:
        capture = capture_from_pseudocode(OPTIMIZED_MEMSET_PARAMETER_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "destination")
        self.assertEqual(rename_map["a2"], "fillByte")
        self.assertEqual(rename_map["a3"], "byteCount")
        self.assertIn(
            "OptimizedFillSample(char *destination, unsigned __int8 fillByte, unsigned __int64 byteCount)",
            rendered,
        )
        self.assertIn("v4 = 0x101010101010101LL * fillByte;", rendered)

    def test_runtime_memory_parameter_rename_requires_copy_or_fill_evidence(self) -> None:
        capture = capture_from_pseudocode(RUNTIME_MEMORY_FALSE_POSITIVE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("destination", rename_map.values())
        self.assertNotIn("fillByte", rename_map.values())
        self.assertIn("argument2 > 4", rendered)

    def test_runtime_memory_parameter_rename_rejects_reassigned_result_alias(self) -> None:
        capture = capture_from_pseudocode(RUNTIME_MEMORY_REASSIGNED_RESULT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("destination", rename_map.values())
        self.assertIn("result = argument0;", rendered)
        self.assertIn("result = argument1;", rendered)

    def test_runtime_memory_parameter_rename_rejects_mutated_result_alias(self) -> None:
        capture = capture_from_pseudocode(RUNTIME_MEMORY_MUTATED_RESULT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("destination", rename_map.values())
        self.assertIn("result = argument0;", rendered)
        self.assertIn("++result;", rendered)

    def test_output_buffer_contract_parameters_get_dataflow_names(self) -> None:
        capture = capture_from_pseudocode(OUTPUT_BUFFER_CONTRACT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "context")
        self.assertEqual(rename_map["a2"], "outputBuffer")
        self.assertEqual(rename_map["a3"], "outputBufferLength")
        self.assertEqual(rename_map["a4"], "returnLength")
        self.assertIn("_DWORD *outputBuffer", rendered)
        self.assertIn("outputBufferLength < 0x18", rendered)
        self.assertIn("*returnLength = 24LL;", rendered)

    def test_output_buffer_contract_requires_structured_output_writes(self) -> None:
        capture = capture_from_pseudocode(OUTPUT_BUFFER_CONTRACT_FALSE_POSITIVE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("outputBuffer", rename_map.values())
        self.assertNotIn("returnLength", rename_map.values())
        self.assertIn("argument2 < 0x18", rendered)


if __name__ == "__main__":
    unittest.main()
