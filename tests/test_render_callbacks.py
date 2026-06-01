from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.core.render import display_warning_count, render_cleaned_pseudocode
from ida_pseudoforge.core.render_callbacks import (
    apply_known_callback_signature,
    normalize_callback_registration_toggle_body,
    normalize_registry_callback_registration_body,
)


def _single_line_signature_end(_lines: list[str], index: int) -> int:
    return index


CALLBACK_REGISTRATION_TOGGLE_SAMPLE = r"""
__int64 __fastcall sub_140002E00(__int64 a1, char a2)
{
  NTSTATUS ProcessNotifyRoutine; // [rsp+20h] [rbp-98h]
  NTSTATUS ImageNotifyRoutine; // [rsp+24h] [rbp-94h]
  NTSTATUS ThreadNotifyRoutine; // [rsp+28h] [rbp-90h]
  NTSTATUS v6; // [rsp+2Ch] [rbp-8Ch]
  _QWORD v8[4]; // [rsp+48h] [rbp-70h] BYREF
  _OB_CALLBACK_REGISTRATION CallbackRegistration; // [rsp+68h] [rbp-50h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+90h] [rbp-28h] BYREF

  ProcessNotifyRoutine = 0;
  memset(&CallbackRegistration, 0, sizeof(CallbackRegistration));
  memset(v8, 0, sizeof(v8));
  RtlInitUnicodeString(&DestinationString, L"370030");
  ExAcquireFastMutex((PFAST_MUTEX)(a1 + 16));
  if ( a2 )
  {
    if ( !_InterlockedCompareExchange((volatile signed __int32 *)(a1 + 804), 1, 0) )
    {
      v8[0] = PsProcessType;
      LODWORD(v8[1]) = 3;
      v8[2] = sub_140002350;
      v8[3] = 0LL;
      CallbackRegistration.Version = 256;
      CallbackRegistration.OperationRegistrationCount = 1;
      qmemcpy(&CallbackRegistration.Altitude, &DestinationString, sizeof(CallbackRegistration.Altitude));
      CallbackRegistration.RegistrationContext = (PVOID)a1;
      CallbackRegistration.OperationRegistration = (OB_OPERATION_REGISTRATION *)v8;
      ProcessNotifyRoutine = PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, 0);
      ImageNotifyRoutine = PsSetLoadImageNotifyRoutine(sub_140002280);
      ThreadNotifyRoutine = PsSetCreateThreadNotifyRoutine(sub_140003130);
      v6 = ObRegisterCallbacks(&CallbackRegistration, (PVOID *)(a1 + 792));
      if ( ProcessNotifyRoutine < 0 || ImageNotifyRoutine < 0 || ThreadNotifyRoutine < 0 || v6 < 0 )
      {
        if ( v6 >= 0 && *(_QWORD *)(a1 + 792) )
        {
          ObUnRegisterCallbacks(*(PVOID *)(a1 + 792));
          *(_QWORD *)(a1 + 792) = 0LL;
        }
        if ( ProcessNotifyRoutine >= 0 )
          PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, 1);
        if ( ImageNotifyRoutine >= 0 )
          PsRemoveLoadImageNotifyRoutine(sub_140002280);
        if ( ThreadNotifyRoutine >= 0 )
          PsRemoveCreateThreadNotifyRoutine(sub_140003130);
        _InterlockedExchange((volatile __int32 *)(a1 + 804), 0);
      }
    }
  }
  else
  {
    if ( _InterlockedCompareExchange((volatile signed __int32 *)(a1 + 804), 0, 1) == 1 )
    {
      if ( *(_QWORD *)(a1 + 792) )
      {
        ObUnRegisterCallbacks(*(PVOID *)(a1 + 792));
        *(_QWORD *)(a1 + 792) = 0LL;
      }
      PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, 1);
      PsRemoveLoadImageNotifyRoutine(sub_140002280);
      PsRemoveCreateThreadNotifyRoutine(sub_140003130);
    }
  }
  ExReleaseFastMutex((PFAST_MUTEX)(a1 + 16));
  return (unsigned int)ProcessNotifyRoutine;
}
"""


REGISTRY_CALLBACK_REGISTRATION_SAMPLE = r"""
void __fastcall sub_140003DE0(PVOID *a1)
{
  NTSTATUS v1; // [rsp+30h] [rbp-38h]
  NTSTATUS v2; // [rsp+30h] [rbp-38h]
  ULONG Major; // [rsp+34h] [rbp-34h] BYREF
  ULONG Minor; // [rsp+38h] [rbp-30h] BYREF
  LARGE_INTEGER Cookie; // [rsp+40h] [rbp-28h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+48h] [rbp-20h] BYREF

  CmGetCallbackVersion(&Major, &Minor);
  sub_140003DB0(Major);
  sub_140003DB0(Minor);
  if ( a1 )
  {
    Cookie.QuadPart = 0LL;
    RtlInitUnicodeString(&DestinationString, L"385123.9000");
    v1 = CmRegisterCallbackEx(Function, &DestinationString, a1[1], a1, &Cookie, 0LL);
    DbgSetWaitTimeout(v1);
    if ( v1 >= 0 )
    {
      CmUnRegisterCallback(Cookie);
    }
    v2 = CmRegisterCallback(Function, a1, &Cookie);
    DbgSetWaitTimeout(v2);
    if ( v2 >= 0 )
    {
      CmUnRegisterCallback(Cookie);
    }
  }
}
"""


PACKED_CALLBACK_REGISTRATION_TOGGLE_SAMPLE = r"""
__int64 __fastcall CallbackToggleNoPdb(__int64 a1, char a2)
{
  NTSTATUS ProcessNotifyRoutine; // esi
  NTSTATUS ImageNotifyRoutine; // r14d
  NTSTATUS ThreadNotifyRoutine; // r15d
  NTSTATUS v8; // eax
  struct _UNICODE_STRING DestinationString; // [rsp+20h] [rbp-60h] BYREF
  __int128 v13; // [rsp+30h] [rbp-50h] BYREF
  __int128 v14; // [rsp+40h] [rbp-40h]
  _OB_CALLBACK_REGISTRATION CallbackRegistration; // [rsp+50h] [rbp-30h] BYREF

  ProcessNotifyRoutine = 0;
  memset(&CallbackRegistration, 0, sizeof(CallbackRegistration));
  v13 = 0LL;
  v14 = 0LL;
  RtlInitUnicodeString(&DestinationString, L"500001.1000");
  ExAcquireFastMutex((PFAST_MUTEX)(a1 + 16));
  if ( a2 )
  {
    if ( !_InterlockedCompareExchange((volatile signed __int32 *)(a1 + 804), 1, 0) )
    {
      *(_QWORD *)&v13 = PsProcessType;
      DWORD2(v13) = 3;
      *(_QWORD *)&v14 = ObjectPreOperation;
      CallbackRegistration.OperationRegistration = (OB_OPERATION_REGISTRATION *)&v13;
      *((_QWORD *)&v14 + 1) = 0LL;
      *(_DWORD *)&CallbackRegistration.Version = 65792;
      CallbackRegistration.Altitude = DestinationString;
      CallbackRegistration.RegistrationContext = (PVOID)a1;
      ProcessNotifyRoutine = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)NotifyRoutine, 0);
      ImageNotifyRoutine = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
      ThreadNotifyRoutine = PsSetCreateThreadNotifyRoutine(ThreadNotify);
      v8 = ObRegisterCallbacks(&CallbackRegistration, (PVOID *)(a1 + 792));
    }
  }
  else
  {
    if ( _InterlockedCompareExchange((volatile signed __int32 *)(a1 + 804), 0, 1) == 1 )
    {
      if ( *(_QWORD *)(a1 + 792) )
      {
        ObUnRegisterCallbacks(*(PVOID *)(a1 + 792));
        *(_QWORD *)(a1 + 792) = 0LL;
      }
      PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)NotifyRoutine, 1u);
      PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotify);
      PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
    }
  }
  ExReleaseFastMutex((PFAST_MUTEX)(a1 + 16));
  return (unsigned int)ProcessNotifyRoutine;
}
"""


class RenderCallbacksTests(unittest.TestCase):
    def test_apply_known_callback_signature_rewrites_ob_pre_operation_callback(self) -> None:
        text = "\n".join(
            [
                "__int64 __fastcall PfkpObjectPreOperation(__int64 a1, __int64 a2)",
                "{",
                "  return 0LL;",
                "}",
            ]
        )
        capture = FunctionCapture(
            name="PfkpObjectPreOperation",
            prototype="__int64 __fastcall PfkpObjectPreOperation(__int64 a1, __int64 a2)",
            pseudocode=text,
        )

        rendered = apply_known_callback_signature(text, capture, _single_line_signature_end)

        self.assertIn("OB_PREOP_CALLBACK_STATUS __fastcall PfkpObjectPreOperation(", rendered)
        self.assertIn("PVOID registrationContext,", rendered)
        self.assertIn("POB_PRE_OPERATION_INFORMATION preOperationInfo)", rendered)
        self.assertIn("return OB_PREOP_SUCCESS;", rendered)

    def test_normalize_callback_registration_toggle_body_rewrites_status_signature(self) -> None:
        text = "\n".join(
            [
                "__int64 __fastcall ToggleNotifyCallbacks(__int64 deviceExtension, char enable)",
                "{",
                "  NTSTATUS callbackStatus;",
                "  return (unsigned int)callbackStatus;",
                "}",
            ]
        )
        capture = FunctionCapture(name="ToggleNotifyCallbacks")

        rendered = normalize_callback_registration_toggle_body(text, capture)

        self.assertIn("NTSTATUS __fastcall ToggleNotifyCallbacks", rendered)
        self.assertIn("BOOLEAN enable", rendered)
        self.assertIn("return callbackStatus;", rendered)

    def test_normalize_registry_callback_registration_body_uses_nt_success(self) -> None:
        text = "\n".join(
            [
                "if ( registerExStatus >= 0 )",
                "  CmUnRegisterCallback(callbackCookie);",
                "if ( registerStatus >= 0 )",
                "  CmUnRegisterCallback(callbackCookie);",
            ]
        )

        rendered = normalize_registry_callback_registration_body(text)

        self.assertIn("if ( NT_SUCCESS(registerExStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(registerStatus) )", rendered)

    def test_ob_pre_operation_raw_field_loads_are_rewritten(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall PfkpObjectPreOperation(__int64 a1, __int64 a2)
{
  unsigned int desiredAccess;

  desiredAccess = 0;
  if ( *(_DWORD *)a2 == 1 )
  {
    desiredAccess = *(_DWORD *)(*(_QWORD *)(a2 + 32) + 4LL);
  }
  else
  {
    if ( *(_DWORD *)a2 == 2 )
    {
      desiredAccess = *(_DWORD *)(*(_QWORD *)(a2 + 32) + 4LL);
    }
  }
  return 0LL;
}
"""
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("PVOID registrationContext,", rendered)
        self.assertIn("POB_PRE_OPERATION_INFORMATION preOperationInfo)", rendered)
        self.assertIn("preOperationInfo->Operation == 1", rendered)
        self.assertIn("preOperationInfo->Operation == 2", rendered)
        self.assertIn(
            "desiredAccess = preOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;",
            rendered,
        )
        self.assertIn(
            "desiredAccess = preOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;",
            rendered,
        )
        self.assertNotIn("*(_DWORD *)(*(_QWORD *)(preOperationInfo + 32) + 4LL)", rendered)
        self.assertNotIn("*(_DWORD *)preOperationInfo", rendered)

    def test_no_pdb_ob_pre_operation_signature_keeps_body_parameter_consistent(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall sub_140002350(__int64 a1, __int64 a2)
{
  int desiredAccess;
  HANDLE targetProcessId;
  PVOID objectType;
  PVOID callContext;

  targetProcessId = PsGetProcessId(*(PEPROCESS *)(a2 + 8));
  objectType = *(PVOID *)(a2 + 16);
  callContext = *(PVOID *)(a2 + 24);
  desiredAccess = 0;
  if ( *(_DWORD *)a2 == 1 )
  {
    desiredAccess = *(_DWORD *)(*(_QWORD *)(a2 + 32) + 4LL);
  }
  if ( (*(_DWORD *)(a2 + 4) & 1) != 0 )
  {
    desiredAccess = 0;
  }
  ExAcquireFastMutex((PFAST_MUTEX)(a1 + 72));
  *(_DWORD *)(a1 + 784) = 0xC000009A;
  ExReleaseFastMutex((PFAST_MUTEX)(a1 + 72));
  return 0LL;
}
"""
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        body = rendered.rsplit("*/", 1)[-1]

        self.assertIn("OB_PREOP_CALLBACK_STATUS __fastcall sub_140002350(", rendered)
        self.assertIn("PVOID registrationContext,", rendered)
        self.assertIn("POB_PRE_OPERATION_INFORMATION preOperationInfo)", rendered)
        self.assertIn("ExAcquireFastMutex((PFAST_MUTEX)(registrationContext + 72));", body)
        self.assertIn("*(_DWORD *)(registrationContext + 784) = STATUS_INSUFFICIENT_RESOURCES;", body)
        self.assertIn("targetProcessId = PsGetProcessId((PEPROCESS)preOperationInfo->Object);", body)
        self.assertIn("objectType = preOperationInfo->ObjectType;", body)
        self.assertIn("callContext = preOperationInfo->CallContext;", body)
        self.assertIn("if ( (*(_DWORD *)(preOperationInfo + 4) & 1) != 0 )", body)
        self.assertNotIn("preOperationInfo->Flags", body)
        self.assertIn("preOperationInfo->Operation == 1", body)
        self.assertNotRegex(body, r"\ba1\b")
        self.assertNotRegex(body, r"\ba2\b")

    def test_preinfo_name_alone_does_not_rewrite_generic_offsets_as_ob_fields(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall GenericPreInfoSample(__int64 preInfo)
{
  PVOID objectType;
  unsigned int flags;

  objectType = *(PVOID *)(preInfo + 16);
  flags = *(_DWORD *)(preInfo + 4);
  if ( *(_DWORD *)preInfo == 1 )
  {
    flags += 1;
  }
  return flags + (__int64)objectType;
}
"""
        )
        rendered = render_cleaned_pseudocode(capture, build_clean_plan(capture))
        body = rendered.rsplit("*/", 1)[-1]

        self.assertIn("objectType = *(PVOID *)(preInfo + 16);", body)
        self.assertIn("flags = *(_DWORD *)(preInfo + 4);", body)
        self.assertIn("if ( *(_DWORD *)preInfo == 1 )", body)
        self.assertNotIn("preInfo->Operation", body)
        self.assertNotIn("preInfo->ObjectType", body)
        self.assertNotIn("preInfo->Flags", body)

    def test_ob_pre_operation_no_symbol_typed_offset_loads_are_rewritten(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "a1",
                                "new": "deviceContext",
                                "confidence": 0.86,
                                "reason": "context pointer is used for fixed-offset state",
                            },
                            {
                                "old": "a2",
                                "new": "preInfo",
                                "confidence": 0.98,
                                "reason": "object callback pre-operation information",
                            },
                        ]
                    }
                )

        capture = capture_from_pseudocode(
            """
__int64 __fastcall sub_140002350(__int64 a1, POB_PRE_OPERATION_CALLBACK a2)
{
  int desiredAccess;
  PVOID eventRecord;
  __int64 *callerListEntry;
  __int64 *blockedListEntry;
  char *newCallerEntry;
  unsigned int operationStatus;
  HANDLE callerProcessId;
  HANDLE targetProcessId;
  __int64 eventTimestamp;

  targetProcessId = PsGetProcessId(*((PEPROCESS *)a2 + 1));
  callerProcessId = PsGetCurrentProcessId();
  LOBYTE(desiredAccess) = 0;
  operationStatus = 0;
  if ( *(_DWORD *)a2 == 1 )
  {
    desiredAccess = *(_DWORD *)(*((_QWORD *)a2 + 4) + 4LL);
  }
  else
  {
    if ( *(_DWORD *)a2 == 2 )
    {
      desiredAccess = *(_DWORD *)(*((_QWORD *)a2 + 4) + 4LL);
    }
  }
  if ( (*((_DWORD *)a2 + 1) & 1) == 0 && (desiredAccess & 0x7B) != 0 )
  {
    for ( callerListEntry = *(__int64 **)(a1 + 152); callerListEntry != (__int64 *)(a1 + 152); callerListEntry = (__int64 *)*callerListEntry )
    {
      if ( (__int64 *)callerListEntry[2] == callerProcessId )
      {
        ++*((_DWORD *)callerListEntry + 6);
        KeQuerySystemTimePrecise(callerListEntry + 4);
      }
    }
    blockedListEntry = *(__int64 **)(a1 + 168);
    if ( blockedListEntry != (__int64 *)(a1 + 168) )
    {
      while ( (HANDLE)blockedListEntry[2] != targetProcessId )
      {
        blockedListEntry = (__int64 *)*blockedListEntry;
        if ( blockedListEntry == (__int64 *)(a1 + 168) )
        {
          break;
        }
      }
      ++*((_DWORD *)blockedListEntry + 6);
      KeQuerySystemTimePrecise(blockedListEntry + 4);
    }
    newCallerEntry = (char *)ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(a1 + 320));
    if ( newCallerEntry )
    {
      memset(newCallerEntry, 0, 0x28uLL);
      *((_QWORD *)newCallerEntry + 2) = callerProcessId;
      *((_DWORD *)newCallerEntry + 6) = 1;
      newCallerEntry[28] = 1;
      KeQuerySystemTimePrecise(newCallerEntry + 32);
    }
    else
    {
      operationStatus = 0xC000009A;
      *(_DWORD *)(a1 + 784) = 0xC000009A;
    }
  }
  eventRecord = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(a1 + 192));
  if ( eventRecord )
  {
    memset(eventRecord, 0, 0x38uLL);
    *((_DWORD *)eventRecord + 4) = 40;
    *((_DWORD *)eventRecord + 5) = 7;
    *((_DWORD *)eventRecord + 6) = 0x1234;
    *((_DWORD *)eventRecord + 7) = 0x5678;
    *((_DWORD *)eventRecord + 8) = 0x9ABC;
    *((_DWORD *)eventRecord + 9) = operationStatus;
    *((_QWORD *)eventRecord + 5) = _InterlockedIncrement((volatile signed __int32 *)(a1 + 740));
    *((_QWORD *)eventRecord + 6) = eventTimestamp;
  }
  return 0LL;
}
"""
        )
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("OB_PREOP_CALLBACK_STATUS __fastcall sub_140002350(", rendered)
        self.assertIn("PVOID deviceContext,", rendered)
        self.assertIn("POB_PRE_OPERATION_INFORMATION preOperationInfo)", rendered)
        self.assertIn("targetProcessId = PsGetProcessId((PEPROCESS)preOperationInfo->Object);", rendered)
        self.assertIn("desiredAccess = 0;", rendered)
        self.assertIn("preOperationInfo->Operation == 1", rendered)
        self.assertIn("preOperationInfo->Operation == 2", rendered)
        self.assertIn(
            "desiredAccess = preOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;",
            rendered,
        )
        self.assertIn(
            "desiredAccess = preOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;",
            rendered,
        )
        self.assertIn("(*((_DWORD *)preOperationInfo + 1) & 1) == 0", rendered)
        self.assertNotIn("preOperationInfo->Flags", rendered)
        self.assertIn("*(_DWORD *)(deviceContext + 784) = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("typedef struct _INFERRED_OB_PROCESS_RULE_RECORD", rendered)
        self.assertIn("INFERRED_OB_PROCESS_RULE_RECORD *callerListEntry;", rendered)
        self.assertIn("LIST_ENTRY *callerListLink;", rendered)
        self.assertIn("callerListEntry = CONTAINING_RECORD(callerListLink, INFERRED_OB_PROCESS_RULE_RECORD, Link);", rendered)
        self.assertIn("callerListEntry->ProcessId == callerProcessId", rendered)
        self.assertIn("++callerListEntry->HitCount;", rendered)
        self.assertIn("KeQuerySystemTimePrecise(&callerListEntry->LastSeenTime);", rendered)
        self.assertIn("INFERRED_OB_PROCESS_RULE_RECORD *blockedListEntry;", rendered)
        self.assertIn("blockedListEntry->ProcessId != targetProcessId", rendered)
        self.assertIn("++blockedListEntry->HitCount;", rendered)
        self.assertIn("KeQuerySystemTimePrecise(&blockedListEntry->LastSeenTime);", rendered)
        self.assertIn("INFERRED_OB_PROCESS_RULE_RECORD *newCallerEntry;", rendered)
        self.assertIn("newCallerEntry->ProcessId = callerProcessId;", rendered)
        self.assertIn("newCallerEntry->AutoAdded = 1;", rendered)
        self.assertIn("typedef struct _INFERRED_OB_CALLBACK_EVENT_RECORD", rendered)
        self.assertIn("INFERRED_OB_CALLBACK_EVENT_RECORD *eventRecord;", rendered)
        self.assertIn("eventRecord->RecordSize = 40;", rendered)
        self.assertIn("eventRecord->Status = operationStatus;", rendered)
        self.assertIn("return OB_PREOP_SUCCESS;", rendered)
        self.assertNotIn("POB_PRE_OPERATION_CALLBACK preInfo", rendered)
        self.assertNotIn("LOBYTE(desiredAccess)", rendered)
        self.assertNotIn("callerListEntry[2]", rendered)
        self.assertNotIn("blockedListEntry[2]", rendered)
        self.assertNotIn("callerListEntry = (INFERRED_OB_PROCESS_RULE_RECORD *)callerListEntry->Link.Flink", rendered)
        self.assertNotIn("*((_DWORD *)callerListEntry + 6)", rendered)
        self.assertNotIn("*((_DWORD *)blockedListEntry + 6)", rendered)
        self.assertNotIn("*((_DWORD *)eventRecord + 9)", rendered)
        self.assertNotIn("*((_QWORD *)preOperationInfo + 4)", rendered)

    def test_callback_registration_toggle_rewrites_ob_operation_registration(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "a1", "new": "DeviceContext", "confidence": 0.99},
                            {"old": "a2", "new": "Enable", "confidence": 0.99},
                            {"old": "sub_140002E00", "new": "ToggleNotifyCallbacks", "confidence": 0.99},
                            {"old": "v8", "new": "operationRegistration", "confidence": 0.85},
                        ],
                        "warnings": [
                            "NotifyRoutine in pseudocode does not match locals list; left unrenamed",
                            (
                                "v8 is typed _QWORD[4] but used as OB_OPERATION_REGISTRATION; "
                                "field assignments are approximate"
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(CALLBACK_REGISTRATION_TOGGLE_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceExtension")
        self.assertEqual(rename_map["a2"], "enable")
        self.assertEqual(rename_map["ProcessNotifyRoutine"], "processStatus")
        self.assertEqual(rename_map["ImageNotifyRoutine"], "imageStatus")
        self.assertEqual(rename_map["ThreadNotifyRoutine"], "threadStatus")
        self.assertEqual(rename_map["v6"], "obStatus")
        self.assertEqual(rename_map["v8"], "operationRegistration")
        self.assertEqual(rename_map["DestinationString"], "altitudeString")
        self.assertIn("callback registration toggle detected", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertIn("NTSTATUS __fastcall sub_140002E00(__int64 deviceExtension, BOOLEAN enable)", rendered)
        self.assertIn("OB_OPERATION_REGISTRATION operationRegistration;", rendered)
        self.assertIn("memset(&operationRegistration, 0, sizeof(operationRegistration));", rendered)
        self.assertIn("operationRegistration.ObjectType = PsProcessType;", rendered)
        self.assertIn(
            "operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;",
            rendered,
        )
        self.assertIn("operationRegistration.PreOperation = sub_140002350;", rendered)
        self.assertIn("operationRegistration.PostOperation = NULL;", rendered)
        self.assertIn("CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;", rendered)
        self.assertIn("CallbackRegistration.Altitude = altitudeString;", rendered)
        self.assertIn("CallbackRegistration.RegistrationContext = (PVOID)deviceExtension;", rendered)
        self.assertIn("CallbackRegistration.OperationRegistration = &operationRegistration;", rendered)
        self.assertIn("PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, FALSE)", rendered)
        self.assertIn("PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, TRUE)", rendered)
        self.assertIn("return processStatus;", rendered)
        self.assertNotIn("return (unsigned int)processStatus;", rendered)
        self.assertNotIn("_QWORD operationRegistration[4]", rendered)
        self.assertNotIn("LODWORD(operationRegistration[1])", rendered)
        self.assertNotIn("(OB_OPERATION_REGISTRATION *)operationRegistration", rendered)
        self.assertNotIn("qmemcpy(&CallbackRegistration.Altitude", rendered)

        partial_sample = CALLBACK_REGISTRATION_TOGGLE_SAMPLE.replace(
            "ImageNotifyRoutine = PsSetLoadImageNotifyRoutine(sub_140002280);",
            "ImageNotifyRoutine = 0;",
        )
        partial_plan = build_clean_plan(capture_from_pseudocode(partial_sample))
        self.assertFalse(any(comment.get("kind") == "callback_registration" for comment in partial_plan.comments))

        pointer_sample = CALLBACK_REGISTRATION_TOGGLE_SAMPLE.replace("_QWORD v8[4];", "_QWORD *v8;", 1)
        pointer_capture = capture_from_pseudocode(pointer_sample)
        pointer_rendered = render_cleaned_pseudocode(
            pointer_capture,
            build_clean_plan(pointer_capture),
        )
        self.assertIn("_QWORD *operationRegistration;", pointer_rendered)
        self.assertIn("operationRegistration[0] = PsProcessType;", pointer_rendered)
        self.assertNotIn("operationRegistration.ObjectType = PsProcessType;", pointer_rendered)

    def test_packed_callback_registration_rewrites_ob_operation_registration(self) -> None:
        capture = capture_from_pseudocode(PACKED_CALLBACK_REGISTRATION_TOGGLE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceExtension")
        self.assertEqual(rename_map["a2"], "enable")
        self.assertEqual(rename_map["v13"], "operationRegistration")
        self.assertEqual(rename_map["v8"], "obStatus")
        self.assertIn("OB_OPERATION_REGISTRATION operationRegistration;", rendered)
        self.assertIn("memset(&operationRegistration, 0, sizeof(operationRegistration));", rendered)
        self.assertIn("operationRegistration.ObjectType = PsProcessType;", rendered)
        self.assertIn(
            "operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;",
            rendered,
        )
        self.assertIn("operationRegistration.PreOperation = ObjectPreOperation;", rendered)
        self.assertIn("operationRegistration.PostOperation = NULL;", rendered)
        self.assertIn("CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;", rendered)
        self.assertIn("CallbackRegistration.OperationRegistrationCount = 1;", rendered)
        self.assertIn("CallbackRegistration.OperationRegistration = &operationRegistration;", rendered)
        self.assertNotIn("__int128 operationRegistration", rendered)
        self.assertNotIn("__int128 v14", rendered)
        self.assertNotIn("*(_DWORD *)&CallbackRegistration.Version", rendered)

    def test_registry_callback_registration_probe_gets_cm_semantics(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "DestinationString", "new": "Altitude", "confidence": 0.95},
                            {"old": "Cookie", "new": "Cookie", "confidence": 0.95},
                            {"old": "a1", "new": "context", "confidence": 0.60},
                            {"old": "v1", "new": "statusEx", "confidence": 0.90},
                            {"old": "v2", "new": "status", "confidence": 0.90},
                        ],
                        "warnings": [
                            "Function symbol used as callback routine is not in locals; cannot rename",
                            (
                                "sub_140003DB0 appears to be a debug/print helper on Major/Minor "
                                "version; not enough evidence to rename precisely"
                            ),
                            (
                                "v1 and v2 share the same stack slot [rbp-38h]; renames assume "
                                "distinct logical roles per IDA listing"
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(REGISTRY_CALLBACK_REGISTRATION_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "callbackContext")
        self.assertEqual(rename_map["v1"], "registerExStatus")
        self.assertEqual(rename_map["v2"], "registerStatus")
        self.assertEqual(rename_map["Major"], "majorVersion")
        self.assertEqual(rename_map["Minor"], "minorVersion")
        self.assertEqual(rename_map["Cookie"], "callbackCookie")
        self.assertEqual(rename_map["DestinationString"], "altitudeString")
        self.assertIn("registry_callback_registration", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertIn("CmGetCallbackVersion(&majorVersion, &minorVersion);", rendered)
        self.assertIn("sub_140003DB0(majorVersion);", rendered)
        self.assertIn("sub_140003DB0(minorVersion);", rendered)
        self.assertIn("callbackCookie.QuadPart = 0LL;", rendered)
        self.assertIn("RtlInitUnicodeString(&altitudeString, L\"385123.9000\");", rendered)
        self.assertIn(
            "registerExStatus = CmRegisterCallbackEx(Function, &altitudeString, callbackContext[1], callbackContext, &callbackCookie, 0LL);",
            rendered,
        )
        self.assertIn("if ( NT_SUCCESS(registerExStatus) )", rendered)
        self.assertIn("registerStatus = CmRegisterCallback(Function, callbackContext, &callbackCookie);", rendered)
        self.assertIn("if ( NT_SUCCESS(registerStatus) )", rendered)
        self.assertIn("CmUnRegisterCallback(callbackCookie);", rendered)
        self.assertNotIn("statusEx", rendered)
        self.assertNotIn("DestinationString", rendered.rsplit("*/", 1)[-1])

        partial_sample = REGISTRY_CALLBACK_REGISTRATION_SAMPLE.replace(
            "  CmGetCallbackVersion(&Major, &Minor);\n",
            "",
        )
        partial_plan = build_clean_plan(capture_from_pseudocode(partial_sample))
        self.assertFalse(
            any(comment.get("kind") == "registry_callback_registration" for comment in partial_plan.comments)
        )


if __name__ == "__main__":
    unittest.main()
