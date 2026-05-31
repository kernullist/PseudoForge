from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, FunctionCapture
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


if __name__ == "__main__":
    unittest.main()
