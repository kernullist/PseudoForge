from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.ioctl import format_ctl_code, format_ctl_code_from_literal
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, FunctionCapture
from ida_pseudoforge.core.render import display_warning_count, render_cleaned_pseudocode
from ida_pseudoforge.core.render_ioctl import (
    annotate_ioctl_code_switch_cases,
    irp_dispatch_signature_override,
    normalize_irp_dispatch_body,
    rewrite_device_control_system_buffer,
    rewrite_irp_stack_location_fields,
)


def _ioctl_plan(case_value: int, dispatcher: str = "ioControlCode") -> CleanPlan:
    return CleanPlan(
        function_ea=0x140001000,
        function_name="DispatchDeviceControl",
        input_fingerprint="test",
        flow_rewrites=[
            FlowRewrite(
                kind="ioctl_dispatch",
                dispatcher=dispatcher,
                recovered_cases=[case_value],
                confidence=0.95,
            )
        ],
    )


def _irp_capture(text: str) -> FunctionCapture:
    return FunctionCapture(
        ea=0x140001000,
        name="DispatchDeviceControl",
        prototype="NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)",
        pseudocode=text,
    )


IOCTL_DISPATCH_SAMPLE = r"""
__int64 __fastcall sub_1400013F0(__int64 a1, IRP *a2)
{
  int status; // [rsp+30h] [rbp-58h]
  __int64 v4; // [rsp+38h] [rbp-50h]
  unsigned int v5; // [rsp+44h] [rbp-44h]
  unsigned int v6; // [rsp+48h] [rbp-40h]
  struct _IRP *MasterIrp; // [rsp+58h] [rbp-30h]
  unsigned int v9; // [rsp+60h] [rbp-28h]
  _DWORD *v10; // [rsp+68h] [rbp-20h]

  v4 = *(_QWORD *)(a1 + 64);
  v10 = (_DWORD *)sub_140003B30(a2);
  MasterIrp = a2->AssociatedIrp.MasterIrp;
  v6 = v10[4];
  v5 = v10[2];
  v9 = v10[6];
  switch ( v9 )
  {
    case 0x83376004:
      status = 0;
      break;
    case 0x8337A008:
      status = 0;
      break;
    case 0x8337E00C:
      status = 0;
      break;
    case 0x8337E010:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  switch ( status )
  {
    case 0x83376004:
      status = 1;
      break;
  }
  a2->IoStatus.Status = status;
  IofCompleteRequest(a2, 0);
  return (unsigned int)status;
}
"""


IOCTL_COMPLETION_LABEL_SAMPLE = r"""
__int64 __fastcall sub_1400013F0(__int64 a1, IRP *a2)
{
  int status; // [rsp+30h] [rbp-58h]
  ULONG_PTR v7; // [rsp+50h] [rbp-38h] BYREF
  struct _IRP *MasterIrp; // [rsp+58h] [rbp-30h]
  unsigned int v9; // [rsp+60h] [rbp-28h]
  _DWORD *v10; // [rsp+68h] [rbp-20h]
  __int64 v11; // [rsp+70h] [rbp-18h]

  v10 = (_DWORD *)sub_140003B30(a2);
  MasterIrp = a2->AssociatedIrp.MasterIrp;
  v9 = v10[6];
  v7 = 0LL;
  switch ( v9 )
  {
    case 0x83376004:
      status = 0;
      goto LABEL_27;
    case 0x8337A008:
      status = 0;
      goto LABEL_27;
    case 0x8337E00C:
      status = 0;
      goto LABEL_27;
    case 0x8337E010:
      status = 0;
      goto LABEL_27;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      goto LABEL_27;
  }
LABEL_27:
  a2->IoStatus.Status = status;
  a2->IoStatus.Information = v7;
  IofCompleteRequest(a2, 0);
  return (unsigned int)status;
}
"""


IOCTL_DISPATCH_WITHOUT_DEVICE_EXTENSION_SAMPLE = r"""
__int64 __fastcall sub_1400013F0(__int64 a1, IRP *a2)
{
  int status; // [rsp+30h] [rbp-58h]
  unsigned int v5; // [rsp+44h] [rbp-44h]
  unsigned int v6; // [rsp+48h] [rbp-40h]
  unsigned int v9; // [rsp+60h] [rbp-28h]
  _DWORD *v10; // [rsp+68h] [rbp-20h]

  v10 = (_DWORD *)sub_140003B30(a2);
  v6 = v10[4];
  v5 = v10[2];
  v9 = v10[6];
  switch ( v9 )
  {
    case 0x83376004:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  a2->IoStatus.Status = status;
  IofCompleteRequest(a2, 0);
  return (unsigned int)status;
}
"""


NO_PDB_IOCTL_DISPATCH_SAMPLE = r"""
__int64 __fastcall NoPdbDeviceControl(__int64 a1, __int64 a2)
{
  unsigned int *v2; // rax
  __int64 v3; // rdi
  IRP *v4; // rbp
  __m128i *v5; // rbx
  unsigned int v6; // r10d
  __int64 v7; // r8
  unsigned int v8; // ecx
  unsigned int v9; // ebx
  int v12; // eax
  __int64 v15; // [rsp+60h] [rbp+8h] BYREF

  v2 = *(unsigned int **)(a2 + 184);
  v3 = *(_QWORD *)(a1 + 64);
  v4 = (IRP *)a2;
  v5 = *(__m128i **)(a2 + 24);
  v15 = 0LL;
  v6 = v2[4];
  v7 = v2[2];
  v8 = v2[6];
  if ( !v5 && (v6 || (_DWORD)v7) )
  {
    v9 = -1073741592;
    goto LABEL_41;
  }
  switch ( v8 )
  {
    case 0x91234D14:
      v12 = QueryRecords(v3, v5, v7, &v15);
      break;
    case 0x9123DD18:
      v12 = UpdateRules(v3, (_DWORD)v5, v6, v7, (__int64)&v15);
      break;
    default:
      v9 = -1073741808;
      goto LABEL_41;
  }
  v9 = v12;
LABEL_41:
  v4->IoStatus.Information = v15;
  v4->IoStatus.Status = v9;
  IofCompleteRequest(v4, 0);
  return v9;
}
"""


NON_DEVICE_CONTROL_IRP_STACK_SAMPLE = r"""
__int64 __fastcall CreateCloseDispatch(__int64 deviceObject, IRP *irp)
{
  int status; // [rsp+30h] [rbp-38h]
  unsigned int transferLength; // [rsp+34h] [rbp-34h]
  _DWORD *ioStackLocation; // [rsp+38h] [rbp-30h]

  ioStackLocation = (_DWORD *)sub_140003B30(irp);
  transferLength = ioStackLocation[2];
  if ( transferLength )
  {
    status = 0;
  }
  else
  {
    status = STATUS_INVALID_DEVICE_REQUEST;
  }
  irp->IoStatus.Status = status;
  return (unsigned int)status;
}
"""


NO_PDB_CREATE_CLOSE_DISPATCH_SAMPLE = r"""
__int64 __fastcall NoPdbCreateClose(__int64 a1, __int64 a2)
{
  int status; // [rsp+30h] [rbp-38h]
  unsigned int transferLength; // [rsp+34h] [rbp-34h]
  _DWORD *ioStackLocation; // [rsp+38h] [rbp-30h]

  ioStackLocation = (_DWORD *)GetCurrentStack(a2);
  transferLength = ioStackLocation[2];
  if ( transferLength )
  {
    status = 0;
  }
  else
  {
    status = STATUS_INVALID_DEVICE_REQUEST;
  }
  IofCompleteRequest((IRP *)a2, 0);
  return (unsigned int)status;
}
"""


IRP_COMPLETION_HELPER_SAMPLE = r"""
__int64 __fastcall CompleteIrpHelper(int a1, __int64 a2)
{
  IofCompleteRequest((IRP *)a2, 0);
  return (unsigned int)a1;
}
"""


IRP_IOCTL_LIKE_SWITCH_WITHOUT_STACK_SAMPLE = r"""
__int64 __fastcall sub_140004100(__int64 a1, IRP *a2)
{
  int status; // [rsp+30h] [rbp-48h]
  struct _IRP *MasterIrp; // [rsp+38h] [rbp-40h]
  unsigned int v9; // [rsp+40h] [rbp-38h]

  MasterIrp = a2->AssociatedIrp.MasterIrp;
  v9 = *(_DWORD *)(a1 + 80);
  switch ( v9 )
  {
    case 0x83376004:
      status = 0;
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  a2->IoStatus.Status = status;
  IofCompleteRequest(a2, 0);
  return (unsigned int)status;
}
"""


NON_IRP_IOCTL_LIKE_SWITCH_SAMPLE = r"""
__int64 __fastcall sub_140004000(__int64 a1, int a2)
{
  int status; // [rsp+30h] [rbp-38h]
  unsigned int v5; // [rsp+34h] [rbp-34h]
  unsigned int v6; // [rsp+38h] [rbp-30h]
  unsigned int v9; // [rsp+3Ch] [rbp-2Ch]
  _DWORD *v10; // [rsp+40h] [rbp-28h]

  v10 = *(_DWORD **)(a1 + 16);
  v6 = v10[4];
  v5 = v10[2];
  v9 = v10[6];
  switch ( v9 )
  {
    case 0x83376004:
      status = 0;
      break;
    default:
      status = -1;
      break;
  }
  return (unsigned int)status;
}
"""


class RenderIoctlTests(unittest.TestCase):
    def test_irp_dispatch_signature_override_uses_canonical_parameters(self) -> None:
        self.assertEqual(
            irp_dispatch_signature_override("DispatchDeviceControl"),
            [
                "NTSTATUS __fastcall DispatchDeviceControl(",
                "        PDEVICE_OBJECT deviceObject,",
                "        PIRP irp)",
            ],
        )

    def test_normalize_irp_dispatch_body_rewrites_alias_and_status_types(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)",
                "{",
                "  int status;",
                "  __int64 inputBufferLength;",
                "  unsigned __int64 outputBufferLength;",
                "  int ioControlCode;",
                "  __int64 information;",
                "  IRP *irpAlias;",
                "  PVOID deviceExtension;",
                "",
                "  deviceExtension = *(_QWORD *)(deviceObject + 64);",
                "  irpAlias = (IRP *)irp;",
                "  irpAlias->IoStatus.Status = status;",
                "  IofCompleteRequest((IRP *)irp, 0);",
                "  return (unsigned int)status;",
                "}",
            ]
        )

        rendered = normalize_irp_dispatch_body(text)

        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("ULONG inputBufferLength;", rendered)
        self.assertIn("ULONG outputBufferLength;", rendered)
        self.assertIn("ULONG ioControlCode;", rendered)
        self.assertIn("ULONG_PTR information;", rendered)
        self.assertIn("deviceExtension = deviceObject->DeviceExtension;", rendered)
        self.assertIn("irp->IoStatus.Status = status;", rendered)
        self.assertIn("IofCompleteRequest(irp, 0);", rendered)
        self.assertIn("return status;", rendered)
        self.assertNotIn("IRP *irpAlias;", rendered)
        self.assertNotIn("irpAlias = (IRP *)irp;", rendered)

    def test_normalize_irp_dispatch_body_keeps_conditional_irp_alias(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)",
                "{",
                "  IRP *irpAlias;",
                "",
                "  if ( deviceObject )",
                "  {",
                "    irpAlias = (IRP *)irp;",
                "  }",
                "  IofCompleteRequest(irpAlias, 0);",
                "}",
            ]
        )

        rendered = normalize_irp_dispatch_body(text)

        self.assertIn("IRP *irpAlias;", rendered)
        self.assertIn("irpAlias = (IRP *)irp;", rendered)
        self.assertIn("IofCompleteRequest(irpAlias, 0);", rendered)

    def test_annotate_ioctl_code_switch_cases_only_updates_ioctl_dispatcher(self) -> None:
        text = "\n".join(
            [
                "switch ( ioControlCode )",
                "{",
                "case 0x83376004:",
                "  break;",
                "}",
                "switch ( otherCode )",
                "{",
                "case 0x8337A008:",
                "  break;",
                "}",
            ]
        )

        rendered = annotate_ioctl_code_switch_cases(text, _ioctl_plan(0x83376004))

        self.assertIn(
            "case 0x83376004: // CTL_CODE(0x8337, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)",
            rendered,
        )
        self.assertNotIn("0x8337A008: // CTL_CODE", rendered)

    def test_rewrite_irp_stack_location_fields_requires_irp_dispatch_evidence(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)",
                "{",
                "  _DWORD *ioStackLocation;",
                "  ULONG outputBufferLength;",
                "  ULONG inputBufferLength;",
                "  ULONG ioControlCode;",
                "  NTSTATUS status;",
                "",
                "  ioStackLocation = (_DWORD *)IoGetCurrentIrpStackLocation(irp);",
                "  outputBufferLength = ioStackLocation[2];",
                "  inputBufferLength = ioStackLocation[4];",
                "  ioControlCode = ioStackLocation[6];",
                "  irp->IoStatus.Status = status;",
                "  switch ( ioControlCode )",
                "  {",
                "  case 0x83376004:",
                "    break;",
                "  }",
                "}",
            ]
        )

        rendered = rewrite_irp_stack_location_fields(text, _ioctl_plan(0x83376004), _irp_capture(text))

        self.assertIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertIn("ioStackLocation = (PIO_STACK_LOCATION)IoGetCurrentIrpStackLocation(irp);", rendered)
        self.assertIn(
            "outputBufferLength = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;",
            rendered,
        )
        self.assertIn(
            "inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;",
            rendered,
        )
        self.assertIn("ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;", rendered)

        generic_capture = FunctionCapture(
            ea=0x140001000,
            name="Helper",
            prototype="NTSTATUS __fastcall Helper(PVOID context, ULONG value)",
            pseudocode=text,
        )
        unchanged = rewrite_irp_stack_location_fields(text, _ioctl_plan(0x83376004), generic_capture)
        self.assertEqual(unchanged, text)

    def test_rewrite_system_buffer_requires_buffered_ioctl_cases(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS __fastcall DispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)",
                "{",
                "  _DWORD *ioStackLocation;",
                "  PIRP systemBuffer;",
                "  ULONG ioControlCode;",
                "  NTSTATUS status;",
                "",
                "  ioStackLocation = (_DWORD *)IoGetCurrentIrpStackLocation(irp);",
                "  ioControlCode = ioStackLocation[6];",
                "  systemBuffer = irp->AssociatedIrp.MasterIrp;",
                "  irp->IoStatus.Status = status;",
                "  switch ( ioControlCode )",
                "  {",
                "  case 0x83376004:",
                "    break;",
                "  }",
                "}",
            ]
        )

        buffered = rewrite_device_control_system_buffer(text, _ioctl_plan(0x83376004), _irp_capture(text))
        self.assertIn("PVOID systemBuffer;", buffered)
        self.assertIn("systemBuffer = irp->AssociatedIrp.SystemBuffer;", buffered)

        neither_text = text.replace("case 0x83376004:", "case 0x83376007:")
        neither = rewrite_device_control_system_buffer(neither_text, _ioctl_plan(0x83376007), _irp_capture(neither_text))
        self.assertIn("PIRP systemBuffer;", neither)
        self.assertIn("systemBuffer = irp->AssociatedIrp.MasterIrp;", neither)
        self.assertNotIn("AssociatedIrp.SystemBuffer", neither)

    def test_ioctl_switch_case_labels_decode_ctl_code_bitfields(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "a1", "new": "DeviceObject", "confidence": 0.90},
                            {"old": "a2", "new": "Irp", "confidence": 0.90},
                            {"old": "v4", "new": "deviceContext", "confidence": 0.90},
                            {"old": "MasterIrp", "new": "systemBuffer", "confidence": 0.90},
                            {"old": "v5", "new": "inputBufferLength", "confidence": 0.90},
                            {"old": "v6", "new": "outputBufferLength", "confidence": 0.88},
                            {"old": "v9", "new": "ioControlCode", "confidence": 0.97},
                            {"old": "v10", "new": "ioStack", "confidence": 0.90},
                        ]
                    }
                )

        capture = capture_from_pseudocode(IOCTL_DISPATCH_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceObject")
        self.assertEqual(rename_map["a2"], "irp")
        self.assertEqual(rename_map["v4"], "deviceExtension")
        self.assertEqual(rename_map["MasterIrp"], "systemBuffer")
        self.assertEqual(rename_map["v5"], "outputBufferLength")
        self.assertEqual(rename_map["v6"], "inputBufferLength")
        self.assertEqual(rename_map["v9"], "ioControlCode")
        self.assertEqual(rename_map["v10"], "ioStackLocation")
        self.assertTrue(plan.flow_rewrites)
        self.assertEqual(plan.flow_rewrites[0].dispatcher, "ioControlCode")
        self.assertIn("cases=[0x83376004, 0x8337A008, 0x8337E00C, 0x8337E010]", rendered)
        self.assertIn("NTSTATUS __fastcall sub_1400013F0(", rendered)
        self.assertIn("PDEVICE_OBJECT deviceObject", rendered)
        self.assertIn("PIRP irp", rendered)
        self.assertIn("NTSTATUS status;", rendered)
        self.assertIn("deviceExtension = deviceObject->DeviceExtension;", rendered)
        self.assertNotIn("__int64 deviceObject", rendered)
        self.assertNotIn("deviceObject + 64", rendered)
        self.assertIn("PVOID systemBuffer;", rendered)
        self.assertIn("systemBuffer = irp->AssociatedIrp.SystemBuffer;", rendered)
        self.assertIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertIn("ioStackLocation = (PIO_STACK_LOCATION)sub_140003B30(irp);", rendered)
        self.assertIn(
            "inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;",
            rendered,
        )
        self.assertIn(
            "outputBufferLength = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;",
            rendered,
        )
        self.assertIn("ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;", rendered)
        self.assertNotIn("outputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength", rendered)
        self.assertNotIn("inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength", rendered)
        self.assertIn(
            "case 0x83376004: // CTL_CODE(0x8337, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)",
            rendered,
        )
        self.assertEqual(rendered.count("case 0x83376004:"), 2)
        self.assertEqual(
            rendered.count("case 0x83376004: // CTL_CODE(0x8337, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)"),
            1,
        )
        self.assertIn(
            "case 0x8337A008: // CTL_CODE(0x8337, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)",
            rendered,
        )
        self.assertIn(
            "case 0x8337E00C: // CTL_CODE(0x8337, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)",
            rendered,
        )
        self.assertNotIn("IOCTL_PFKP", rendered)
        self.assertNotIn("struct _IRP *systemBuffer;", rendered)
        self.assertNotIn("AssociatedIrp.MasterIrp", rendered)
        self.assertNotIn("_DWORD *ioStack", rendered)
        self.assertNotIn("ioStack[6]", rendered)
        self.assertNotIn("_DWORD *ioStackLocation", rendered)
        self.assertNotIn("ioStackLocation[6]", rendered)
        self.assertIn("return status;", rendered)
        self.assertNotIn("return (unsigned int)status;", rendered)

    def test_no_pdb_ioctl_dispatch_uses_body_evidence_for_irp_and_stack_roles(self) -> None:
        capture = capture_from_pseudocode(NO_PDB_IOCTL_DISPATCH_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceObject")
        self.assertEqual(rename_map["a2"], "irp")
        self.assertEqual(rename_map["v2"], "ioStackLocation")
        self.assertEqual(rename_map["v3"], "deviceExtension")
        self.assertEqual(rename_map["v5"], "systemBuffer")
        self.assertEqual(rename_map["v8"], "ioControlCode")
        self.assertEqual(rename_map["v15"], "information")
        self.assertIn("PDEVICE_OBJECT deviceObject", rendered)
        self.assertIn("PIRP irp", rendered)
        self.assertIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertIn("PVOID systemBuffer;", rendered)
        self.assertIn("ULONG inputBufferLength;", rendered)
        self.assertIn("ULONG outputBufferLength;", rendered)
        self.assertIn("ULONG_PTR information;", rendered)
        self.assertIn("ioStackLocation = irp->Tail.Overlay.CurrentStackLocation;", rendered)
        self.assertIn("systemBuffer = irp->AssociatedIrp.SystemBuffer;", rendered)
        self.assertIn("deviceExtension = deviceObject->DeviceExtension;", rendered)
        self.assertIn("ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;", rendered)
        self.assertIn("irp->IoStatus.Information = information;", rendered)
        self.assertIn("IofCompleteRequest(irp, 0);", rendered)
        self.assertNotIn("argument0", rendered)
        self.assertNotIn("argument1", rendered)
        self.assertNotIn("irp + 184", rendered)
        self.assertNotIn("irp + 24", rendered)
        self.assertNotIn("IRP *v4", rendered)

        conditional_alias_sample = NO_PDB_IOCTL_DISPATCH_SAMPLE.replace(
            "  v4 = (IRP *)a2;\n",
            "  if ( a1 )\n  {\n    v4 = (IRP *)a2;\n  }\n",
        )
        conditional_capture = capture_from_pseudocode(conditional_alias_sample)
        conditional_rendered = render_cleaned_pseudocode(
            conditional_capture,
            build_clean_plan(conditional_capture),
        )
        self.assertIn("IRP *v4;", conditional_rendered)
        self.assertIn("IofCompleteRequest(v4, 0);", conditional_rendered)

    def test_no_pdb_ioctl_system_buffer_rewrite_requires_buffered_methods(self) -> None:
        sample = NO_PDB_IOCTL_DISPATCH_SAMPLE.replace("case 0x91234D14:", "case 0x91234D17:", 1)
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceObject")
        self.assertEqual(rename_map["a2"], "irp")
        self.assertNotIn("v5", rename_map)
        self.assertIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertIn("case 0x91234D17: // CTL_CODE(0x9123, 0x345, METHOD_NEITHER, FILE_READ_ACCESS)", rendered)
        self.assertNotIn("AssociatedIrp.SystemBuffer", rendered)
        self.assertNotIn("PVOID systemBuffer;", rendered)

    def test_no_pdb_create_close_dispatch_uses_completion_call_evidence_for_irp(self) -> None:
        capture = capture_from_pseudocode(NO_PDB_CREATE_CLOSE_DISPATCH_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceObject")
        self.assertEqual(rename_map["a2"], "irp")
        self.assertFalse(plan.flow_rewrites)
        self.assertIn("NTSTATUS __fastcall NoPdbCreateClose(", rendered)
        self.assertIn("PDEVICE_OBJECT deviceObject", rendered)
        self.assertIn("PIRP irp", rendered)
        self.assertIn("IofCompleteRequest(irp, 0);", rendered)
        self.assertNotIn("(IRP *)irp", rendered)
        self.assertIn("_DWORD *ioStackLocation;", rendered)
        self.assertIn("transferLength = ioStackLocation[2];", rendered)
        self.assertNotIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertNotIn("Parameters.DeviceIoControl", rendered)

    def test_irp_completion_helper_is_not_promoted_to_driver_dispatch(self) -> None:
        capture = capture_from_pseudocode(IRP_COMPLETION_HELPER_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotEqual(rename_map.get("a1"), "deviceObject")
        self.assertNotEqual(rename_map.get("a2"), "irp")
        self.assertNotIn("PDEVICE_OBJECT deviceObject", rendered)
        self.assertNotIn("PIRP irp", rendered)
        self.assertIn("IofCompleteRequest((IRP *)argument1, 0);", rendered)

    def test_irp_completion_label_and_resolved_ioctl_warnings_are_display_clean(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "MasterIrp", "new": "systemBuffer", "confidence": 0.90},
                            {"old": "v9", "new": "ioControlCode", "confidence": 0.97},
                            {"old": "v10", "new": "ioStackLocation", "confidence": 0.90},
                            {"old": "v11", "new": "lockFieldPtr", "confidence": 0.60},
                        ],
                        "warnings": [
                            "a1->DeviceObject is inferred from dispatch signature; could be a custom context pointer",
                            "IOCTL handler subfunctions not renamed; recommend naming per IoControlCode case",
                            "MasterIrp->systemBuffer assumes buffered IOCTL; verify METHOD_BUFFERED for these codes",
                            (
                                "MasterIrp is renamed to systemBuffer because AssociatedIrp.MasterIrp and "
                                "SystemBuffer share the same union slot; confirm the device uses METHOD_BUFFERED "
                                "before relying on this"
                            ),
                            (
                                "v5/v6 input-vs-output length assignment is uncertain; ioStack field offsets do not "
                                "match the standard IO_STACK_LOCATION layout (IoControlCode resolves to v10[6]), so "
                                "length roles are inferred from the no-buffer size guard rather than offsets"
                            ),
                        ],
                    }
                )

        capture = capture_from_pseudocode(IOCTL_COMPLETION_LABEL_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        classifications = {label.label: label.classification for label in plan.cleanup_labels}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(classifications["LABEL_27"], "irp_complete_request_tail")
        self.assertIn("LABEL_27 -> CompleteIrp: irp_complete_request_tail", rendered)
        self.assertRegex(rendered, r"(?m)^CompleteIrp:$")
        self.assertIn("// PseudoForge: irp_complete_request_tail", rendered)
        self.assertNotIn("unknown_label_block", rendered)
        self.assertIn("goto CompleteIrp;", rendered)
        self.assertIn("PVOID systemBuffer;", rendered)
        self.assertIn("systemBuffer = irp->AssociatedIrp.SystemBuffer;", rendered)
        self.assertIn("Warnings: 0", rendered)
        self.assertEqual(display_warning_count(plan), 0)
        self.assertNotIn("Warning detail:", rendered)
        self.assertNotIn("could be a custom context pointer", rendered)
        self.assertNotIn("recommend naming per IoControlCode", rendered)
        self.assertNotIn("assumes buffered IOCTL", rendered)
        self.assertNotIn("share the same union slot", rendered)
        self.assertNotIn("input-vs-output length assignment is uncertain", rendered)
        self.assertNotIn("lockFieldPtr", rendered)

    def test_ioctl_stack_location_rewrite_does_not_require_device_extension_use(self) -> None:
        capture = capture_from_pseudocode(IOCTL_DISPATCH_WITHOUT_DEVICE_EXTENSION_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v5"], "outputBufferLength")
        self.assertEqual(rename_map["v6"], "inputBufferLength")
        self.assertEqual(rename_map["v9"], "ioControlCode")
        self.assertEqual(rename_map["v10"], "ioStackLocation")
        self.assertIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertIn(
            "inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;",
            rendered,
        )
        self.assertIn(
            "outputBufferLength = ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;",
            rendered,
        )
        self.assertIn("ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;", rendered)

    def test_master_irp_alias_rewrite_requires_all_buffered_ioctl_cases(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "MasterIrp", "new": "systemBuffer", "confidence": 0.90},
                            {"old": "v9", "new": "ioControlCode", "confidence": 0.97},
                            {"old": "v10", "new": "ioStackLocation", "confidence": 0.90},
                        ]
                    }
                )

        sample = IOCTL_DISPATCH_SAMPLE.replace("case 0x83376004:", "case 0x83376007:", 1)
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("case 0x83376007: // CTL_CODE(0x8337, 0x801, METHOD_NEITHER, FILE_READ_ACCESS)", rendered)
        self.assertIn("struct _IRP *systemBuffer;", rendered)
        self.assertIn("systemBuffer = irp->AssociatedIrp.MasterIrp;", rendered)
        self.assertNotIn("PVOID systemBuffer;", rendered)
        self.assertNotIn("AssociatedIrp.SystemBuffer", rendered)

    def test_master_irp_alias_rewrite_requires_device_control_stack_evidence(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "MasterIrp", "new": "systemBuffer", "confidence": 0.90},
                            {"old": "v9", "new": "ioControlCode", "confidence": 0.97},
                        ]
                    }
                )

        capture = capture_from_pseudocode(IRP_IOCTL_LIKE_SWITCH_WITHOUT_STACK_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["a1"], "deviceObject")
        self.assertEqual(rename_map["a2"], "irp")
        self.assertIn("case 0x83376004: // CTL_CODE(0x8337, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)", rendered)
        self.assertIn("struct _IRP *systemBuffer;", rendered)
        self.assertIn("systemBuffer = irp->AssociatedIrp.MasterIrp;", rendered)
        self.assertNotIn("PVOID systemBuffer;", rendered)
        self.assertNotIn("AssociatedIrp.SystemBuffer", rendered)

    def test_irp_stack_location_union_arm_is_not_forced_without_ioctl_evidence(self) -> None:
        capture = capture_from_pseudocode(NON_DEVICE_CONTROL_IRP_STACK_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertFalse(plan.flow_rewrites)
        self.assertIn("NTSTATUS __fastcall CreateCloseDispatch(", rendered)
        self.assertIn("PDEVICE_OBJECT deviceObject", rendered)
        self.assertIn("PIRP irp", rendered)
        self.assertIn("_DWORD *ioStackLocation;", rendered)
        self.assertIn("ioStackLocation = (_DWORD *)sub_140003B30(irp);", rendered)
        self.assertIn("transferLength = ioStackLocation[2];", rendered)
        self.assertNotIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertNotIn("Parameters.DeviceIoControl", rendered)
        self.assertIn("return status;", rendered)

    def test_irp_stack_location_roles_require_driver_dispatch_evidence(self) -> None:
        capture = capture_from_pseudocode(NON_IRP_IOCTL_LIKE_SWITCH_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("v9", rename_map)
        self.assertNotIn("v10", rename_map)
        self.assertIn("_DWORD *v10;", rendered)
        self.assertIn("v9 = v10[6];", rendered)
        self.assertNotIn("PIO_STACK_LOCATION", rendered)
        self.assertNotIn("Parameters.DeviceIoControl", rendered)

    def test_llm_ioctl_like_names_do_not_force_irp_union_arm_without_dispatch_evidence(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "v5", "new": "outputBufferLength", "confidence": 0.95},
                            {"old": "v6", "new": "inputBufferLength", "confidence": 0.95},
                            {"old": "v9", "new": "ioControlCode", "confidence": 0.95},
                            {"old": "v10", "new": "ioStackLocation", "confidence": 0.95},
                        ]
                    }
                )

        capture = capture_from_pseudocode(NON_IRP_IOCTL_LIKE_SWITCH_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("_DWORD *ioStackLocation;", rendered)
        self.assertIn("ioControlCode = ioStackLocation[6];", rendered)
        self.assertNotIn("PIO_STACK_LOCATION ioStackLocation;", rendered)
        self.assertNotIn("Parameters.DeviceIoControl", rendered)
        self.assertNotIn("PDEVICE_OBJECT", rendered)

    def test_ioctl_ctl_code_decode_handles_methods_and_access_bits(self) -> None:
        self.assertEqual(
            format_ctl_code(0x83376005),
            "CTL_CODE(0x8337, 0x801, METHOD_IN_DIRECT, FILE_READ_ACCESS)",
        )
        self.assertEqual(
            format_ctl_code(0x83376006),
            "CTL_CODE(0x8337, 0x801, METHOD_OUT_DIRECT, FILE_READ_ACCESS)",
        )
        self.assertEqual(
            format_ctl_code(0x83376007),
            "CTL_CODE(0x8337, 0x801, METHOD_NEITHER, FILE_READ_ACCESS)",
        )
        self.assertEqual(
            format_ctl_code_from_literal("0x83376004ui64"),
            "CTL_CODE(0x8337, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)",
        )

    def test_ioctl_case_labels_decode_hexrays_integer_suffixes(self) -> None:
        sample = IOCTL_DISPATCH_SAMPLE.replace("case 0x83376004:", "case 0x83376004ui64:", 1)
        capture = capture_from_pseudocode(sample)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("cases=[0x83376004, 0x8337A008, 0x8337E00C, 0x8337E010]", rendered)
        self.assertIn(
            "case 0x83376004ui64: // CTL_CODE(0x8337, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)",
            rendered,
        )


if __name__ == "__main__":
    unittest.main()
