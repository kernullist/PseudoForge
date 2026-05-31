from __future__ import annotations

import re
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, CleanupLabel
from ida_pseudoforge.core.render import (
    _hoist_embedded_semantic_tail_labels as legacy_hoist_embedded_semantic_tail_labels,
    render_cleaned_pseudocode,
)
from ida_pseudoforge.core.render_labels import (
    annotate_kernel_labels,
    hoist_embedded_semantic_tail_labels,
    rename_kernel_labels,
    semantic_label_display,
    semantic_label_map,
)
from tests.fixtures.kernel_samples import DUPLICATE_SEMANTIC_LABEL_SAMPLE, FIRMWARE_SAMPLE


def _plan(labels: list[CleanupLabel]) -> CleanPlan:
    return CleanPlan(
        function_ea=0x140001000,
        function_name="LabelSample",
        input_fingerprint="test",
        cleanup_labels=labels,
    )


def _label(name: str, classification: str, evidence: str = "test evidence") -> CleanupLabel:
    return CleanupLabel(
        label=name,
        classification=classification,
        start_line=1,
        end_line=2,
        confidence=0.90,
        evidence=evidence,
    )


class RenderLabelTests(unittest.TestCase):
    def test_semantic_label_rename_keeps_duplicate_targets_unique(self) -> None:
        plan = _plan(
            [
                _label("LABEL_17", "set_error_status_and_cleanup", "sets invalid parameter"),
                _label("LABEL_21", "set_error_status_and_cleanup", "sets invalid device state"),
            ]
        )
        text = "\n".join(
            [
                "  goto LABEL_17;",
                "LABEL_17:",
                "  status = STATUS_INVALID_PARAMETER;",
                "  goto LABEL_21;",
                "LABEL_21:",
                "  return status;",
            ]
        )

        labels = semantic_label_map(plan)
        renamed = rename_kernel_labels(text, plan)
        annotated = annotate_kernel_labels(renamed, plan)

        self.assertEqual(labels["LABEL_17"], "InvalidParameter")
        self.assertEqual(labels["LABEL_21"], "InvalidParameter_21")
        self.assertEqual(
            semantic_label_display("LABEL_21", "set_error_status_and_cleanup", labels),
            "LABEL_21 -> InvalidParameter_21",
        )
        self.assertIn("goto InvalidParameter;", annotated)
        self.assertIn("goto InvalidParameter_21;", annotated)
        self.assertIn("InvalidParameter:", annotated)
        self.assertIn("InvalidParameter_21:", annotated)
        self.assertIn("// PseudoForge: set_error_status_and_cleanup", annotated)

    def test_hoist_embedded_semantic_tail_label_after_cleanup_block(self) -> None:
        plan = _plan(
            [
                _label("LABEL_40", "release_resource_and_leave_critical_region"),
                _label("LABEL_17", "set_error_status_and_cleanup"),
            ]
        )
        text = "\n".join(
            [
                "  if ( badInput )",
                "  {",
                "InvalidParameter:",
                "    // PseudoForge: set_error_status_and_cleanup confidence=0.90; test evidence",
                "    status = STATUS_INVALID_PARAMETER;",
                "    goto Cleanup;",
                "  }",
                "Cleanup:",
                "  ExReleaseResourceLite(&Resource);",
                "  return status;",
            ]
        )

        rendered = hoist_embedded_semantic_tail_labels(text, plan)

        self.assertIn("    goto InvalidParameter;", rendered)
        self.assertIn(
            "Cleanup:\n"
            "  ExReleaseResourceLite(&Resource);\n"
            "  return status;\n"
            "InvalidParameter:\n"
            "  // PseudoForge: set_error_status_and_cleanup confidence=0.90; test evidence\n"
            "  status = STATUS_INVALID_PARAMETER;\n"
            "  goto Cleanup;",
            rendered,
        )

    def test_embedded_semantic_label_fallback_hoists_stale_layout(self) -> None:
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

        rendered = legacy_hoist_embedded_semantic_tail_labels(stale_text, plan)

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

    def test_duplicate_semantic_labels_keep_unique_targets(self) -> None:
        capture = capture_from_pseudocode(DUPLICATE_SEMANTIC_LABEL_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("LABEL_17 -> InvalidParameter: set_error_status_and_cleanup", rendered)
        self.assertIn("LABEL_21 -> InvalidParameter_21: set_error_status_and_cleanup", rendered)
        self.assertEqual(len(re.findall(r"(?m)^InvalidParameter:$", rendered)), 1)
        self.assertEqual(len(re.findall(r"(?m)^InvalidParameter_21:$", rendered)), 1)
        self.assertIn("goto LABEL_40;", rendered)
        self.assertNotRegex(rendered, r"(?ms)^InvalidParameter_21:.*?goto InvalidParameter_21;")

    def test_success_accounting_label_is_not_cleanup_dispatch_tail(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
