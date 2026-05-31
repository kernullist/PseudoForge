import unittest
import json
import os
import re
import tempfile
from pathlib import Path

import ida_pseudoforge
from ida_pseudoforge.core.forge_store import (
    render_forge_function_section,
)
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import LocalVariable
from ida_pseudoforge.core.render import (
    _hoist_embedded_semantic_tail_labels,
    display_warning_count,
    render_cleaned_pseudocode,
    render_switch_outline,
)
from ida_pseudoforge.ida.decompiler import merge_lvars_from_text_and_cfunc
from ida_pseudoforge.ida import actions as actions_module
from ida_pseudoforge.logging import append_bounded_log_line
from ida_pseudoforge.version import PLUGIN_NAME, VERSION, plugin_title

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


DRIVER_ENTRY_SAMPLE = r"""
__int64 __fastcall sub_140003530(struct _DRIVER_OBJECT *a1, __int64 a2)
{
  NTSTATUS v3; // [rsp+40h] [rbp-38h]
  unsigned int i; // [rsp+44h] [rbp-34h]
  _DWORD *DeferredContext; // [rsp+48h] [rbp-30h]
  PDEVICE_OBJECT DeviceObject; // [rsp+50h] [rbp-28h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+58h] [rbp-20h] BYREF

  DeviceObject = 0LL;
  DeferredContext = 0LL;
  RtlInitUnicodeString(&DestinationString, L"\\Device\\PfKernelPattern");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\PfKernelPattern");
  for ( i = 0; i <= 0x1B; ++i )
    a1->MajorFunction[i] = (PDRIVER_DISPATCH)sub_140003430;
  a1->MajorFunction[0] = (PDRIVER_DISPATCH)sub_1400011D0;
  a1->MajorFunction[2] = (PDRIVER_DISPATCH)sub_1400011D0;
  a1->MajorFunction[14] = (PDRIVER_DISPATCH)sub_1400013F0;
  a1->DriverUnload = (PDRIVER_UNLOAD)sub_140003270;
  v3 = IoCreateDevice(a1, 0x340u, &DestinationString, 0x8337u, 0x100u, 0, &DeviceObject);
  if ( v3 >= 0 )
  {
    DeviceObject->Flags |= 4u;
    DeferredContext = DeviceObject->DeviceExtension;
    memset(DeferredContext, 0, 0x340uLL);
    *DeferredContext = 1883981392;
    *((_QWORD *)DeferredContext + 1) = DeviceObject;
    DeferredContext[184] = 64;
    qword_140005010 = (__int64)DeviceObject;
    sub_1400039D0(DeferredContext + 4);
    sub_1400039D0(DeferredContext + 18);
    KeInitializeSpinLock((PKSPIN_LOCK)DeferredContext + 16);
    sub_140003A70(DeferredContext + 34);
    sub_140003A70(DeferredContext + 38);
    sub_140003A70(DeferredContext + 42);
    ExInitializeNPagedLookasideList(
      (PNPAGED_LOOKASIDE_LIST)(DeferredContext + 48),
      0LL,
      0LL,
      0,
      0x38uLL,
      0x724B4650u,
      0);
    ExInitializeNPagedLookasideList(
      (PNPAGED_LOOKASIDE_LIST)(DeferredContext + 80),
      0LL,
      0LL,
      0,
      0x28uLL,
      0x6C4B4650u,
      0);
    KeInitializeTimerEx((PKTIMER)DeferredContext + 7, NotificationTimer);
    KeInitializeDpc((PRKDPC)DeferredContext + 8, DeferredRoutine, DeferredContext);
    KeInitializeEvent((PRKEVENT)(DeferredContext + 146), NotificationEvent, 1u);
    ExInitializeRundownProtection((PEX_RUNDOWN_REF)DeferredContext + 76);
    ExInitializeResourceLite((PERESOURCE)(DeferredContext + 154));
    v3 = sub_140002D60(DeferredContext);
    if ( v3 >= 0 )
    {
      v3 = sub_1400010D0(DeferredContext + 180, a2);
      if ( v3 >= 0 )
      {
        sub_140002950(DeferredContext);
        *((_QWORD *)DeferredContext + 72) = IoAllocateWorkItem(DeviceObject);
        if ( *((_QWORD *)DeferredContext + 72) )
        {
          v3 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
          if ( v3 >= 0 )
            DeviceObject->Flags &= ~0x80u;
        }
        else
        {
          v3 = -1073741670;
        }
      }
    }
  }
  if ( v3 < 0 )
  {
    if ( DeferredContext )
    {
      if ( *((_QWORD *)DeferredContext + 72) )
      {
        IoFreeWorkItem(*((PIO_WORKITEM *)DeferredContext + 72));
        *((_QWORD *)DeferredContext + 72) = 0LL;
      }
      if ( *((_QWORD *)DeferredContext + 91) )
      {
        ExFreePoolWithTag(*((PVOID *)DeferredContext + 91), 0x704B4650u);
        memset(DeferredContext + 180, 0, 0x10uLL);
      }
      ExDeleteResourceLite((PERESOURCE)(DeferredContext + 154));
      sub_140001310(DeferredContext);
      ExDeleteNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(DeferredContext + 80));
      ExDeleteNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(DeferredContext + 48));
    }
    if ( DeviceObject )
    {
      IoDeleteDevice(DeviceObject);
      qword_140005010 = 0LL;
    }
  }
  return (unsigned int)v3;
}
"""


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


MEMORY_MANAGER_PROBE_SAMPLE = r"""
void sub_1400047F0()
{
  BOOLEAN IsAddressValid; // al
  __int64 v1; // rax
  PVOID VirtualAddress; // [rsp+30h] [rbp-118h]
  PVOID VirtualAddressa; // [rsp+30h] [rbp-118h]
  PMDL MemoryDescriptorList; // [rsp+38h] [rbp-110h]
  PVOID BaseAddress; // [rsp+40h] [rbp-108h]
  __int64 v6; // [rsp+48h] [rbp-100h] BYREF
  PVOID SystemRoutineAddress; // [rsp+50h] [rbp-F8h]
  PHYSICAL_ADDRESS PhysicalAddress; // [rsp+58h] [rbp-F0h]
  PVOID v10; // [rsp+68h] [rbp-E0h]
  PHYSICAL_ADDRESS BoundaryAddressMultiple; // [rsp+70h] [rbp-D8h]
  PHYSICAL_ADDRESS HighestAcceptableAddress; // [rsp+78h] [rbp-D0h]
  PHYSICAL_ADDRESS LowestAcceptableAddress; // [rsp+80h] [rbp-C8h]
  struct _UNICODE_STRING DestinationString; // [rsp+88h] [rbp-C0h] BYREF
  _BYTE v15[64]; // [rsp+A0h] [rbp-A8h] BYREF
  _BYTE v16[64]; // [rsp+E0h] [rbp-68h] BYREF

  v6 = 0LL;
  memset(v15, 0, sizeof(v15));
  memset(v16, 0, sizeof(v16));
  RtlInitUnicodeString(&DestinationString, L"ZwClose");
  SystemRoutineAddress = MmGetSystemRoutineAddress(&DestinationString);
  sub_140003DB0(SystemRoutineAddress);
  VirtualAddress = (PVOID)ExAllocatePool2(0x40uLL, 64LL, 0x744B4650u);
  sub_140003DB0(VirtualAddress);
  if ( VirtualAddress )
  {
    qmemcpy(VirtualAddress, v15, 0x40uLL);
    IsAddressValid = MmIsAddressValid(VirtualAddress);
    sub_140003DB0(IsAddressValid);
    PhysicalAddress = MmGetPhysicalAddress(VirtualAddress);
    sub_140003DB0(PhysicalAddress.QuadPart);
    v10 = VirtualAddress;
    MmCopyMemory(v16, VirtualAddress, 64LL, 2LL, &v6);
    sub_140003DB0(v6);
    MemoryDescriptorList = IoAllocateMdl(VirtualAddress, 0x40u, 0, 0, 0LL);
    sub_140003DB0(MemoryDescriptorList);
    if ( MemoryDescriptorList )
    {
      MmBuildMdlForNonPagedPool(MemoryDescriptorList);
      v1 = sub_140004AB0(MemoryDescriptorList, 16LL);
      sub_140003DB0(v1);
      sub_140003DB0(MemoryDescriptorList->ByteCount);
      sub_140003DB0(MemoryDescriptorList->ByteOffset);
      IoFreeMdl(MemoryDescriptorList);
    }
    ExFreePoolWithTag(VirtualAddress, 0x744B4650u);
  }
  BaseAddress = MmAllocateNonCachedMemory(0x40uLL);
  sub_140003DB0(BaseAddress);
  if ( BaseAddress )
  {
    MmFreeNonCachedMemory(BaseAddress, 0x40uLL);
  }
  LowestAcceptableAddress.QuadPart = 0LL;
  HighestAcceptableAddress.QuadPart = 0x7FFFFFFFFFFFFFFFLL;
  BoundaryAddressMultiple.QuadPart = 0LL;
  VirtualAddressa = MmAllocateContiguousMemorySpecifyCache(
                      0x1000uLL,
                      0LL,
                      (PHYSICAL_ADDRESS)0x7FFFFFFFFFFFFFFFLL,
                      0LL,
                      MmCached);
  sub_140003DB0(VirtualAddressa);
  if ( VirtualAddressa )
  {
    MmFreeContiguousMemory(VirtualAddressa);
  }
}
"""


ZW_API_PROBE_SAMPLE = r"""
void sub_1400059F0()
{
  NTSTATUS v0; // eax
  NTSTATUS v1; // eax
  NTSTATUS v2; // eax
  NTSTATUS v3; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v4; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v5; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v6; // [rsp+60h] [rbp-1A8h]
  NTSTATUS v7; // [rsp+60h] [rbp-1A8h]
  void *EventHandle; // [rsp+68h] [rbp-1A0h] BYREF
  ULONG ReturnLength; // [rsp+70h] [rbp-198h] BYREF
  void *TokenHandle; // [rsp+78h] [rbp-190h] BYREF
  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-188h] BYREF
  union _LARGE_INTEGER Timeout; // [rsp+B0h] [rbp-158h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+B8h] [rbp-150h] BYREF
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+C8h] [rbp-140h] BYREF
  struct _UNICODE_STRING ValueName; // [rsp+D8h] [rbp-130h] BYREF
  _BYTE KeyValueInformation[256]; // [rsp+F0h] [rbp-118h] BYREF

  EventHandle = 0LL;
  TokenHandle = 0LL;
  ReturnLength = 0;
  Timeout.QuadPart = 0LL;
  memset(KeyValueInformation, 0, sizeof(KeyValueInformation));
  memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));
  v0 = ZwClose(0LL);
  DbgSetWaitTimeout(v0);
  v1 = ZwWaitForSingleObject(0LL, 0, &Timeout);
  DbgSetWaitTimeout(v1);
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 512;
  ObjectAttributes.ObjectName = 0LL;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  v3 = ZwCreateEvent(&EventHandle, 0x1F0003u, &ObjectAttributes, NotificationEvent, 0);
  DbgSetWaitTimeout(v3);
  if ( v3 >= 0 )
  {
    ZwSetEvent(EventHandle, 0LL);
    ZwWaitForSingleObject(EventHandle, 0, &Timeout);
    ZwClose(EventHandle);
    EventHandle = 0LL;
  }
  RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  v4 = ZwOpenKey(&EventHandle, 0x20019u, &ObjectAttributes);
  DbgSetWaitTimeout(v4);
  if ( v4 >= 0 )
  {
    RtlInitUnicodeString(&ValueName, L"SystemStartOptions");
    ZwQueryValueKey(EventHandle, &ValueName, KeyValuePartialInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwQueryKey(EventHandle, KeyBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(EventHandle);
    EventHandle = 0LL;
  }
  v5 = ZwOpenProcessTokenEx((HANDLE)0xFFFFFFFFFFFFFFFFLL, 8u, 0x200u, &TokenHandle);
  DbgSetWaitTimeout(v5);
  if ( v5 >= 0 )
  {
    ZwQueryInformationToken(TokenHandle, TokenUser, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(TokenHandle);
  }
  v6 = ZwOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFELL, 8u, 1u, 0x200u, &TokenHandle);
  DbgSetWaitTimeout(v6);
  if ( v6 >= 0 )
  {
    ZwClose(TokenHandle);
  }
  v2 = ZwQueryObject(0LL, ObjectBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
  DbgSetWaitTimeout(v2);
  RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\Temp\\PfkpApiCorpus.tmp");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  v7 = ZwCreateFile(&EventHandle, 0x100080u, &ObjectAttributes, &IoStatusBlock, 0LL, 0x100u, 7u, 1u, 0x20u, 0LL, 0);
  DbgSetWaitTimeout(v7);
  if ( v7 >= 0 )
  {
    ZwQueryInformationFile(EventHandle, &IoStatusBlock, KeyValueInformation, 0x100u, FileBasicInformation);
    ZwClose(EventHandle);
  }
}
"""


ZW_REUSED_STATUS_SLOT_SAMPLE = r"""
int ZwProbeNoPdbSample()
{
  NTSTATUS v0; // eax
  int result; // eax
  void *EventHandle; // [rsp+60h] [rbp-A0h] BYREF
  ULONG ReturnLength; // [rsp+68h] [rbp-98h] BYREF
  void *TokenHandle; // [rsp+70h] [rbp-90h] BYREF
  union _LARGE_INTEGER Timeout; // [rsp+78h] [rbp-88h] BYREF
  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-80h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+B0h] [rbp-50h] BYREF
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+C0h] [rbp-40h] BYREF
  struct _UNICODE_STRING ValueName; // [rsp+D0h] [rbp-30h] BYREF
  _BYTE KeyValueInformation[256]; // [rsp+E0h] [rbp-20h] BYREF

  EventHandle = 0LL;
  TokenHandle = 0LL;
  ReturnLength = 0;
  Timeout.QuadPart = 0LL;
  memset(KeyValueInformation, 0, sizeof(KeyValueInformation));
  IoStatusBlock = 0LL;
  g_ReusedZwStatus = ZwClose(0LL);
  v0 = ZwWaitForSingleObject(0LL, 0, &Timeout);
  ObjectAttributes.Length = 48;
  g_ReusedZwStatus = v0;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 512;
  ObjectAttributes.ObjectName = 0LL;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  g_ReusedZwStatus = ZwCreateEvent(&EventHandle, 0x1F0003u, &ObjectAttributes, NotificationEvent, 0);
  if ( g_ReusedZwStatus >= 0 )
  {
    ZwSetEvent(EventHandle, 0LL);
    ZwWaitForSingleObject(EventHandle, 0, &Timeout);
    ZwClose(EventHandle);
  }
  RtlInitUnicodeString(&DestinationString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  g_ReusedZwStatus = ZwOpenKey(&EventHandle, 0x20019u, &ObjectAttributes);
  if ( g_ReusedZwStatus >= 0 )
  {
    RtlInitUnicodeString(&ValueName, L"SystemStartOptions");
    ZwQueryValueKey(EventHandle, &ValueName, KeyValuePartialInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwQueryKey(EventHandle, KeyBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(EventHandle);
  }
  g_ReusedZwStatus = ZwOpenProcessTokenEx((HANDLE)0xFFFFFFFFFFFFFFFFLL, 8u, 0x200u, &TokenHandle);
  if ( g_ReusedZwStatus >= 0 )
  {
    ZwQueryInformationToken(TokenHandle, TokenUser, KeyValueInformation, 0x100u, &ReturnLength);
    ZwClose(TokenHandle);
  }
  g_ReusedZwStatus = ZwOpenThreadTokenEx((HANDLE)0xFFFFFFFFFFFFFFFELL, 8u, 1u, 0x200u, &TokenHandle);
  if ( g_ReusedZwStatus >= 0 )
  {
    ZwClose(TokenHandle);
  }
  g_ReusedZwStatus = ZwQueryObject(0LL, ObjectBasicInformation, KeyValueInformation, 0x100u, &ReturnLength);
  RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\Temp\\Any.tmp");
  ObjectAttributes.Length = 48;
  ObjectAttributes.RootDirectory = 0LL;
  ObjectAttributes.Attributes = 576;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.SecurityDescriptor = 0LL;
  ObjectAttributes.SecurityQualityOfService = 0LL;
  result = ZwCreateFile(&EventHandle, 0x100080u, &ObjectAttributes, &IoStatusBlock, 0LL, 0x100u, 7u, 1u, 0x20u, 0LL, 0);
  g_ReusedZwStatus = result;
  if ( result >= 0 )
  {
    ZwQueryInformationFile(EventHandle, &IoStatusBlock, KeyValueInformation, 0x100u, FileBasicInformation);
    return ZwClose(EventHandle);
  }
  return result;
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


TRACELOGGING_TEMPLATE_SAMPLE = r"""
__int64 __fastcall _tlgWriteTemplate_Write(__int64 a1)
{
  int _tlgWrapperByVal;

  _tlgWrapperByVal = *(_DWORD *)a1;
  if ( _tlgWrapperByVal == 1 )
    return write_bool();
  if ( _tlgWrapperByVal == 4 )
    return write_int32();
  if ( _tlgWrapperByVal == 8 )
    return write_int64();
  return write_default();
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
    def test_plugin_version_matches_manifest(self):
        manifest_path = Path(__file__).resolve().parents[1] / "ida-plugin.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(VERSION, manifest["plugin"]["version"])
        self.assertEqual(VERSION, ida_pseudoforge.__version__)
        self.assertEqual("PseudoForge", PLUGIN_NAME)
        self.assertEqual("PseudoForge %s" % VERSION, plugin_title())

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

    def test_tracelogging_template_is_not_recovered_as_system_information_switch(self):
        capture = capture_from_pseudocode(TRACELOGGING_TEMPLATE_SAMPLE, name="_tlgWriteTemplate_Write")
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertFalse(plan.flow_rewrites)
        self.assertNotIn("PseudoForge recovered switch view", rendered)
        self.assertNotIn("SystemBasicInformation", rendered)
        self.assertNotIn("SystemBasicPerformanceInformation", rendered)
        self.assertNotIn("SystemProcessorPerformanceInformation", rendered)

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

    def test_known_pvoid_signature_keeps_typed_body_alias(self):
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

    def test_ob_pre_operation_raw_field_loads_are_rewritten(self):
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

    def test_ob_pre_operation_no_symbol_typed_offset_loads_are_rewritten(self):
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
      if ( (HANDLE)callerListEntry[2] == callerProcessId )
      {
        ++*((_DWORD *)callerListEntry + 6);
        KeQuerySystemTimePrecise(callerListEntry + 4);
      }
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
        self.assertIn("(preOperationInfo->Flags & 1) == 0", rendered)
        self.assertIn("*(_DWORD *)(deviceContext + 784) = STATUS_INSUFFICIENT_RESOURCES;", rendered)
        self.assertIn("typedef struct _INFERRED_OB_PROCESS_RULE_RECORD", rendered)
        self.assertIn("INFERRED_OB_PROCESS_RULE_RECORD *callerListEntry;", rendered)
        self.assertIn("LIST_ENTRY *callerListLink;", rendered)
        self.assertIn("callerListEntry = CONTAINING_RECORD(callerListLink, INFERRED_OB_PROCESS_RULE_RECORD, Link);", rendered)
        self.assertIn("callerListEntry->ProcessId == callerProcessId", rendered)
        self.assertIn("++callerListEntry->HitCount;", rendered)
        self.assertIn("KeQuerySystemTimePrecise(&callerListEntry->LastSeenTime);", rendered)
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
        self.assertNotIn("callerListEntry = (INFERRED_OB_PROCESS_RULE_RECORD *)callerListEntry->Link.Flink", rendered)
        self.assertNotIn("*((_DWORD *)callerListEntry + 6)", rendered)
        self.assertNotIn("*((_DWORD *)eventRecord + 9)", rendered)
        self.assertNotIn("*((_QWORD *)preOperationInfo + 4)", rendered)
        self.assertNotIn("*((_DWORD *)preOperationInfo + 1)", rendered)

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

    def test_driver_entry_device_extension_semantics(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "a1", "new": "DriverObject", "confidence": 0.99},
                            {"old": "a2", "new": "RegistryPath", "confidence": 0.99},
                            {"old": "sub_140003530", "new": "DriverEntry", "confidence": 0.99},
                            {"old": "sub_1400011D0", "new": "DispatchCreateClose", "confidence": 0.99},
                            {"old": "sub_1400013F0", "new": "DispatchDeviceControl", "confidence": 0.99},
                            {"old": "sub_140003430", "new": "DispatchDefault", "confidence": 0.99},
                            {"old": "sub_140003270", "new": "DriverUnload", "confidence": 0.99},
                            {"old": "sub_1400010D0", "new": "LoadConfiguration", "confidence": 0.60},
                            {"old": "DeferredContext", "new": "devExt", "confidence": 0.95},
                        ],
                        "warnings": [
                            (
                                "DeferredContext is IDA-misnamed; it is the DeviceObject->DeviceExtension, "
                                "not a DPC deferred context"
                            ),
                            (
                                "Field offsets into deviceExtension (e.g. +4,+18,+72,+91,+180) "
                                "suggest a struct should be defined for DeviceExtension"
                            ),
                            (
                                "Sub-function renames (sub_1400039D0, sub_140003A70, sub_140002D60, "
                                "sub_1400010D0, sub_140002950, sub_140001310) are inferred from call "
                                "context only; verify by inspecting each callee"
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(DRIVER_ENTRY_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)
        forge_section = render_forge_function_section(capture, plan, rendered)

        self.assertEqual(rename_map["a1"], "driverObject")
        self.assertEqual(rename_map["a2"], "registryPath")
        self.assertEqual(rename_map["v3"], "status")
        self.assertEqual(rename_map["DeferredContext"], "extension")
        self.assertEqual(rename_map["DeviceObject"], "deviceObject")
        self.assertEqual(rename_map["DestinationString"], "deviceName")
        self.assertEqual(rename_map["i"], "majorIndex")

        self.assertIn("NTSTATUS __fastcall DriverEntry(", rendered)
        self.assertIn("PDRIVER_OBJECT driverObject", rendered)
        self.assertIn("PUNICODE_STRING registryPath", rendered)
        self.assertIn("Kernel semantic rewrites: 4", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertIn("// Warnings: 0", forge_section)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertIn("DriverEntry-style dispatch table", rendered)
        self.assertIn("typedef struct _INFERRED_DRIVER_DEVICE_EXTENSION", rendered)
        self.assertIn("} INFERRED_DRIVER_DEVICE_EXTENSION;\n\nNTSTATUS __fastcall DriverEntry", rendered)
        self.assertIn("INFERRED_DRIVER_DEVICE_EXTENSION *extension", rendered)
        self.assertIn("majorIndex <= IRP_MJ_MAXIMUM_FUNCTION", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_CREATE]", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_CLOSE]", rendered)
        self.assertIn("driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]", rendered)
        self.assertIn(
            "IoCreateDevice(driverObject, 0x340u, &deviceName, 0x8337u, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject)",
            rendered,
        )
        self.assertIn("0x8337u, FILE_DEVICE_SECURE_OPEN", rendered)
        self.assertIn("FILE_DEVICE_SECURE_OPEN", rendered)
        self.assertNotIn("PFKP_DEVICE_TYPE", rendered)
        self.assertNotIn("sizeof(INFERRED_DRIVER_DEVICE_EXTENSION)", rendered)
        self.assertIn("deviceObject->Flags |= DO_BUFFERED_IO;", rendered)
        self.assertIn("deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;", rendered)
        self.assertIn("memset(extension, 0, 0x340uLL);", rendered)
        self.assertIn("extension->Signature = POOL_TAG('P', 'F', 'K', 'p');", rendered)
        self.assertIn("extension->DeviceObject = deviceObject;", rendered)
        self.assertIn("extension->MaxRecords = 64;", rendered)
        self.assertIn("ExInitializeFastMutex(&extension->StateLock);", rendered)
        self.assertIn("InitializeListHead(&extension->ProcessBlacklist);", rendered)
        self.assertIn("KeInitializeSpinLock(&extension->EventLock);", rendered)
        self.assertIn("ExInitializeNPagedLookasideList(&extension->RecordLookaside", rendered)
        self.assertIn("POOL_TAG('P', 'F', 'K', 'r')", rendered)
        self.assertIn("POOL_TAG('P', 'F', 'K', 'l')", rendered)
        self.assertIn("KeInitializeTimerEx(&extension->Timer, NotificationTimer);", rendered)
        self.assertIn("KeInitializeDpc(&extension->TimerDpc, DeferredRoutine, extension);", rendered)
        self.assertIn("KeInitializeEvent(&extension->WorkItemIdleEvent, NotificationEvent, TRUE);", rendered)
        self.assertIn("ExInitializeRundownProtection(&extension->Rundown);", rendered)
        self.assertIn("ExInitializeResourceLite(&extension->Resource);", rendered)
        self.assertIn("status = sub_1400010D0(&extension->RegistryPath, registryPath);", rendered)
        self.assertIn("extension->WorkItem = IoAllocateWorkItem(deviceObject);", rendered)
        self.assertIn("IoFreeWorkItem(extension->WorkItem);", rendered)
        self.assertIn("ExFreePoolWithTag(extension->RegistryPath.Buffer, POOL_TAG('P', 'F', 'K', 'p'));", rendered)
        self.assertIn("memset(&extension->RegistryPath, 0, sizeof(extension->RegistryPath));", rendered)
        self.assertIn("ExDeleteNPagedLookasideList(&extension->ProcessRuleLookaside);", rendered)
        self.assertIn("if ( NT_SUCCESS(status) )", rendered)
        self.assertIn("if ( !NT_SUCCESS(status) )", rendered)
        self.assertIn("return status;", rendered)
        self.assertNotIn("Skipped PascalCase LLM rename", rendered)
        self.assertNotIn("Warning detail:", rendered)
        self.assertNotIn("DeferredContext is IDA-misnamed", rendered)
        self.assertNotIn("Field offsets into deviceExtension", rendered)
        self.assertNotIn("Sub-function renames", rendered)
        self.assertNotIn("devExt", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("MajorFunction[14]", rendered)
        self.assertNotIn("Flags |= 4u", rendered)
        self.assertNotIn("Flags &= ~0x80u", rendered)
        self.assertNotIn("DeferredContext + 180", rendered)

    def test_driver_entry_extension_rewrite_requires_dword_scaled_offsets(self):
        sample = DRIVER_ENTRY_SAMPLE.replace("_DWORD *DeferredContext", "_QWORD *DeferredContext", 1)
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("typedef struct _INFERRED_DRIVER_DEVICE_EXTENSION", rendered)
        self.assertNotIn("INFERRED_DRIVER_DEVICE_EXTENSION *extension", rendered)
        self.assertNotIn("extension->StateLock", rendered)
        self.assertIn("memset(extension, 0, 0x340uLL);", rendered)

    def test_callback_registration_toggle_rewrites_ob_operation_registration(self):
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
        pointer_rendered = render_cleaned_pseudocode(
            capture_from_pseudocode(pointer_sample),
            build_clean_plan(capture_from_pseudocode(pointer_sample)),
        )
        self.assertIn("_QWORD *operationRegistration;", pointer_rendered)
        self.assertIn("operationRegistration[0] = PsProcessType;", pointer_rendered)
        self.assertNotIn("operationRegistration.ObjectType = PsProcessType;", pointer_rendered)

    def test_packed_callback_registration_rewrites_ob_operation_registration(self):
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

    def test_registry_callback_registration_probe_gets_cm_semantics(self):
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

    def test_memory_manager_probe_gets_mm_semantics(self):
        capture = capture_from_pseudocode(MEMORY_MANAGER_PROBE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["DestinationString"], "systemRoutineName")
        self.assertEqual(rename_map["SystemRoutineAddress"], "systemRoutineAddress")
        self.assertEqual(rename_map["VirtualAddress"], "poolBuffer")
        self.assertEqual(rename_map["VirtualAddressa"], "contiguousMemory")
        self.assertEqual(rename_map["MemoryDescriptorList"], "mdl")
        self.assertEqual(rename_map["BaseAddress"], "nonCachedMemory")
        self.assertEqual(rename_map["v6"], "bytesCopied")
        self.assertEqual(rename_map["v15"], "sourceBuffer")
        self.assertEqual(rename_map["v16"], "copyBuffer")
        self.assertEqual(rename_map["IsAddressValid"], "isAddressValid")
        self.assertEqual(rename_map["PhysicalAddress"], "physicalAddress")
        self.assertEqual(rename_map["LowestAcceptableAddress"], "lowestAcceptableAddress")
        self.assertEqual(rename_map["HighestAcceptableAddress"], "highestAcceptableAddress")
        self.assertEqual(rename_map["BoundaryAddressMultiple"], "boundaryAddressMultiple")
        self.assertIn("memory_manager_probe", rendered)
        self.assertIn("RtlInitUnicodeString(&systemRoutineName, L\"ZwClose\");", rendered)
        self.assertIn("systemRoutineAddress = MmGetSystemRoutineAddress(&systemRoutineName);", rendered)
        self.assertIn("poolBuffer = (PVOID)ExAllocatePool2(POOL_FLAG_NON_PAGED, 64LL, POOL_TAG('P', 'F', 'K', 't'));", rendered)
        self.assertIn("qmemcpy(poolBuffer, sourceBuffer, 0x40uLL);", rendered)
        self.assertIn("isAddressValid = MmIsAddressValid(poolBuffer);", rendered)
        self.assertIn("physicalAddress = MmGetPhysicalAddress(poolBuffer);", rendered)
        self.assertIn("MmCopyMemory(copyBuffer, poolBuffer, 64LL, MM_COPY_MEMORY_VIRTUAL, &bytesCopied);", rendered)
        self.assertIn("mdl = IoAllocateMdl(poolBuffer, 0x40u, FALSE, FALSE, 0LL);", rendered)
        self.assertIn("MmBuildMdlForNonPagedPool(mdl);", rendered)
        self.assertIn("IoFreeMdl(mdl);", rendered)
        self.assertIn("ExFreePoolWithTag(poolBuffer, POOL_TAG('P', 'F', 'K', 't'));", rendered)
        self.assertIn("nonCachedMemory = MmAllocateNonCachedMemory(0x40uLL);", rendered)
        self.assertIn("MmFreeNonCachedMemory(nonCachedMemory, 0x40uLL);", rendered)
        self.assertIn("contiguousMemory = MmAllocateContiguousMemorySpecifyCache", rendered)
        self.assertIn("MmFreeContiguousMemory(contiguousMemory);", rendered)
        self.assertNotIn("MmCopyMemory(copyBuffer, poolBuffer, 64LL, 2LL", rendered)
        self.assertNotIn("VirtualAddress", rendered.rsplit("*/", 1)[-1])

        partial_sample = MEMORY_MANAGER_PROBE_SAMPLE.replace(
            "    MmCopyMemory(v16, VirtualAddress, 64LL, 2LL, &v6);\n",
            "",
        )
        partial_plan = build_clean_plan(capture_from_pseudocode(partial_sample))
        self.assertFalse(any(comment.get("kind") == "memory_manager_probe" for comment in partial_plan.comments))

    def test_zw_api_probe_gets_deterministic_names_and_status_checks(self):
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "DestinationString", "new": "objectPath", "confidence": 0.70},
                            {"old": "EventHandle", "new": "genericHandle", "confidence": 0.80},
                            {"old": "KeyValueInformation", "new": "infoBuffer", "confidence": 0.85},
                            {"old": "v0", "new": "closeStatus", "confidence": 0.85},
                            {"old": "v1", "new": "waitStatus", "confidence": 0.85},
                            {"old": "v2", "new": "queryObjectStatus", "confidence": 0.85},
                            {"old": "v3", "new": "createEventStatus", "confidence": 0.95},
                            {"old": "v4", "new": "openKeyStatus", "confidence": 0.95},
                            {"old": "v5", "new": "openProcessTokenStatus", "confidence": 0.95},
                            {"old": "v6", "new": "openThreadTokenStatus", "confidence": 0.95},
                            {"old": "v7", "new": "createFileStatus", "confidence": 0.95},
                        ],
                        "warnings": [
                            (
                                "Function exercises many Zw* APIs and writes results to PfkpApiCorpus.tmp; "
                                "likely an API-probing/corpus routine."
                            ),
                            (
                                "infoBuffer is reused across heterogeneous query types "
                                "(KeyValuePartialInformation, TokenUser, ObjectBasicInformation, "
                                "FileBasicInformation); name is intentionally generic."
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(ZW_API_PROBE_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v0"], "closeStatus")
        self.assertEqual(rename_map["v1"], "waitStatus")
        self.assertEqual(rename_map["v2"], "queryObjectStatus")
        self.assertEqual(rename_map["v3"], "createEventStatus")
        self.assertEqual(rename_map["v4"], "openKeyStatus")
        self.assertEqual(rename_map["v5"], "openProcessTokenStatus")
        self.assertEqual(rename_map["v6"], "openThreadTokenStatus")
        self.assertEqual(rename_map["v7"], "createFileStatus")
        self.assertEqual(rename_map["EventHandle"], "genericHandle")
        self.assertEqual(rename_map["TokenHandle"], "tokenHandle")
        self.assertEqual(rename_map["DestinationString"], "objectPath")
        self.assertEqual(rename_map["KeyValueInformation"], "infoBuffer")
        self.assertEqual(rename_map["ReturnLength"], "returnLength")
        self.assertEqual(rename_map["ObjectAttributes"], "objectAttributes")
        self.assertEqual(rename_map["Timeout"], "timeout")
        self.assertEqual(rename_map["IoStatusBlock"], "ioStatusBlock")
        self.assertEqual(rename_map["ValueName"], "valueName")
        self.assertIn("zw_api_probe", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;", rendered)
        self.assertIn("createEventStatus = ZwCreateEvent(&genericHandle", rendered)
        self.assertIn("ZwWaitForSingleObject(0LL, FALSE, &timeout);", rendered)
        self.assertIn("ZwWaitForSingleObject(genericHandle, FALSE, &timeout);", rendered)
        self.assertIn("if ( NT_SUCCESS(createEventStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(openKeyStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(openProcessTokenStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(openThreadTokenStatus) )", rendered)
        self.assertIn("if ( NT_SUCCESS(createFileStatus) )", rendered)
        self.assertIn("ZwOpenProcessTokenEx(NtCurrentProcess(), 8u, 0x200u, &tokenHandle);", rendered)
        self.assertIn("ZwOpenThreadTokenEx(NtCurrentThread(), 8u, TRUE, 0x200u, &tokenHandle);", rendered)
        self.assertIn("ZwQueryValueKey(genericHandle, &valueName, KeyValuePartialInformation, infoBuffer", rendered)
        self.assertIn("ZwQueryInformationToken(tokenHandle, TokenUser, infoBuffer", rendered)
        self.assertIn("ZwQueryObject(0LL, ObjectBasicInformation, infoBuffer", rendered)
        self.assertIn("ZwQueryInformationFile(genericHandle, &ioStatusBlock, infoBuffer", rendered)
        self.assertNotIn("ObjectAttributes.Length = 48", rendered)
        self.assertNotIn("(HANDLE)0xFFFFFFFFFFFFFFFF", rendered)
        self.assertNotIn("KeyValueInformation", rendered.rsplit("*/", 1)[-1])

        partial_sample = ZW_API_PROBE_SAMPLE.replace(
            "  v7 = ZwCreateFile(&EventHandle, 0x100080u, &ObjectAttributes, &IoStatusBlock, 0LL, 0x100u, 7u, 1u, 0x20u, 0LL, 0);\n",
            "",
        )
        partial_plan = build_clean_plan(capture_from_pseudocode(partial_sample))
        self.assertFalse(any(comment.get("kind") == "zw_api_probe" for comment in partial_plan.comments))

        generic_sample = (
            ZW_API_PROBE_SAMPLE.replace("ObjectAttributes", "vAttr")
            .replace("ReturnLength", "vReturnLength")
            .replace("Timeout", "vTimeout")
            .replace("IoStatusBlock", "vIoStatus")
            .replace("ValueName", "vValueName")
            .replace("KeyValueInformation", "vInfoBuffer")
            .replace("0x100u", "0x40u")
            .replace("vAttr.Length = 48;", "vAttr.Length = 0x30u;")
            .replace("vAttr.Attributes = 512;", "vAttr.Attributes = 0x200u;")
            .replace("vAttr.Attributes = 576;", "vAttr.Attributes = 0x240u;")
            .replace("(HANDLE)0xFFFFFFFFFFFFFFFFLL", "(HANDLE)0xFFFFFFFFFFFFFFFFui64")
            .replace(
                'L"\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Control"',
                'L"\\\\BaseNamedObjects\\\\PfkpObject"',
            )
        )
        generic_capture = capture_from_pseudocode(generic_sample)
        generic_plan = build_clean_plan(generic_capture)
        generic_map = {item.old: item.new for item in generic_plan.renames if item.apply}
        generic_rendered = render_cleaned_pseudocode(generic_capture, generic_plan)
        self.assertEqual(generic_map["vAttr"], "objectAttributes")
        self.assertEqual(generic_map["vReturnLength"], "returnLength")
        self.assertEqual(generic_map["vTimeout"], "timeout")
        self.assertEqual(generic_map["vIoStatus"], "ioStatusBlock")
        self.assertEqual(generic_map["vValueName"], "valueName")
        self.assertEqual(generic_map["vInfoBuffer"], "infoBuffer")
        self.assertIn("objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);", generic_rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_KERNEL_HANDLE;", generic_rendered)
        self.assertIn("objectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;", generic_rendered)
        self.assertIn("ZwQueryValueKey(genericHandle, &valueName, KeyValuePartialInformation, infoBuffer, 0x40u", generic_rendered)
        self.assertIn("ZwOpenProcessTokenEx(NtCurrentProcess(), 8u, 0x200u, &tokenHandle);", generic_rendered)
        self.assertIn("RtlInitUnicodeString(&objectPath, L\"\\\\BaseNamedObjects\\\\PfkpObject\");", generic_rendered)

        guard_sample = ZW_API_PROBE_SAMPLE.replace(
            "  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-188h] BYREF\n",
            (
                "  _OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+80h] [rbp-188h] BYREF\n"
                "  _SOME_HEADER OtherHeader; // [rsp+88h] [rbp-180h]\n"
            ),
            1,
        ).replace(
            "  ObjectAttributes.Length = 48;\n",
            "  ObjectAttributes.Length = 48;\n  OtherHeader.Length = 48;\n",
            1,
        )
        guard_capture = capture_from_pseudocode(guard_sample)
        guard_rendered = render_cleaned_pseudocode(guard_capture, build_clean_plan(guard_capture))
        self.assertIn("OtherHeader.Length = 48;", guard_rendered)

    def test_zw_reused_status_slot_is_not_given_routine_specific_name(self):
        capture = capture_from_pseudocode(ZW_REUSED_STATUS_SLOT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("g_ReusedZwStatus", rename_map)
        self.assertEqual(rename_map["v0"], "waitStatus")
        self.assertEqual(rename_map["result"], "createFileStatus")
        self.assertIn("g_ReusedZwStatus = ZwCreateEvent", rendered)
        self.assertIn("g_ReusedZwStatus = ZwOpenKey", rendered)
        self.assertIn("g_ReusedZwStatus = ZwOpenProcessTokenEx", rendered)
        self.assertNotIn("closeStatus = ZwCreateEvent", rendered)
        self.assertNotIn("closeStatus = ZwOpenKey", rendered)
        self.assertNotIn("closeStatus = ZwOpenProcessTokenEx", rendered)

    def test_mm_get_system_routine_address_indirect_call_uses_profile_metadata(self):
        sample = r"""
__int64 __fastcall sub_140004000()
{
  NTSTATUS status; // [rsp+30h] [rbp-48h]
  UNICODE_STRING routineName; // [rsp+38h] [rbp-40h] BYREF
  PVOID pZwCreateEvent; // [rsp+48h] [rbp-30h]
  HANDLE eventHandle; // [rsp+50h] [rbp-28h] BYREF
  OBJECT_ATTRIBUTES objectAttributes; // [rsp+58h] [rbp-20h] BYREF

  pZwCreateEvent = 0LL;
  RtlInitUnicodeString(&routineName, L"ZwCreateEvent");
  pZwCreateEvent = (PVOID)MmGetSystemRoutineAddress((PUNICODE_STRING)&routineName);
  status = pZwCreateEvent(&eventHandle, 0x1F0003u, &objectAttributes, NotificationEvent, 1u);
  return (unsigned int)status;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "PseudoForge: resolved indirect call pZwCreateEvent as ZwCreateEvent via MmGetSystemRoutineAddress "
            'confidence=0.95; routine string L"ZwCreateEvent"',
            rendered,
        )
        self.assertIn(
            "status = pZwCreateEvent(&eventHandle, 0x1F0003u, &objectAttributes, NotificationEvent, TRUE);",
            rendered,
        )
        self.assertNotIn("status = ZwCreateEvent(", rendered)

    def test_mm_get_system_routine_address_indirect_call_can_use_variable_name_hint(self):
        sample = r"""
void __fastcall sub_140004100()
{
  UNICODE_STRING routineName; // [rsp+30h] [rbp-58h] BYREF
  PVOID pExInitializeNPagedLookasideList; // [rsp+40h] [rbp-48h]
  NPAGED_LOOKASIDE_LIST lookaside; // [rsp+48h] [rbp-40h] BYREF

  pExInitializeNPagedLookasideList = MmGetSystemRoutineAddress(&routineName);
  pExInitializeNPagedLookasideList(&lookaside, 0LL, 0LL, 0, 0x38uLL, 0x724B4650u, 0);
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn(
            "PseudoForge: resolved indirect call pExInitializeNPagedLookasideList as "
            "ExInitializeNPagedLookasideList via MmGetSystemRoutineAddress confidence=0.70; "
            "inferred from function pointer variable name",
            rendered,
        )
        self.assertIn(
            "pExInitializeNPagedLookasideList(&lookaside, 0LL, 0LL, 0, 0x38uLL, "
            "POOL_TAG('P', 'F', 'K', 'r'), 0);",
            rendered,
        )

    def test_mm_get_system_routine_address_indirect_call_requires_matching_arity(self):
        sample = r"""
__int64 __fastcall sub_140004200()
{
  NTSTATUS status; // [rsp+30h] [rbp-48h]
  UNICODE_STRING routineName; // [rsp+38h] [rbp-40h] BYREF
  PVOID pZwCreateEvent; // [rsp+48h] [rbp-30h]
  HANDLE eventHandle; // [rsp+50h] [rbp-28h] BYREF

  RtlInitUnicodeString(&routineName, L"ZwCreateEvent");
  pZwCreateEvent = MmGetSystemRoutineAddress(&routineName);
  status = pZwCreateEvent(&eventHandle, 1u);
  return (unsigned int)status;
}
"""
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("PseudoForge: resolved indirect call", rendered)
        self.assertIn("status = pZwCreateEvent(&eventHandle, 1u);", rendered)
        self.assertNotIn("TRUE", rendered)

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

    def test_bounded_log_line_rotates_at_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = os.path.join(temp_dir, "pseudoforge_trace.log")
            for index in range(20):
                append_bounded_log_line(log_path, "line-%02d-%s" % (index, "X" * 20), max_bytes=160)

            rotated_path = log_path + ".1"

            self.assertTrue(os.path.exists(log_path))
            self.assertTrue(os.path.exists(rotated_path))
            self.assertLessEqual(os.path.getsize(log_path), 160)
            self.assertLessEqual(os.path.getsize(rotated_path), 160)
            with open(log_path, "r", encoding="utf-8") as file:
                current_text = file.read()
            self.assertIn("line-19", current_text)


if __name__ == "__main__":
    unittest.main()
