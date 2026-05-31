from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan, CleanupLabel
from ida_pseudoforge.core.render_labels import (
    annotate_kernel_labels,
    hoist_embedded_semantic_tail_labels,
    rename_kernel_labels,
    semantic_label_display,
    semantic_label_map,
)


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


if __name__ == "__main__":
    unittest.main()
