from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import FunctionCapture
from ida_pseudoforge.core.render_callbacks import (
    apply_known_callback_signature,
    normalize_callback_registration_toggle_body,
    normalize_registry_callback_registration_body,
)


def _single_line_signature_end(_lines: list[str], index: int) -> int:
    return index


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


if __name__ == "__main__":
    unittest.main()
