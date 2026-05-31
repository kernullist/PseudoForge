from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, FunctionCapture, RenameSuggestion
from ida_pseudoforge.core.render_flow import (
    is_safe_switch_outline_body,
    native_switch_dispatchers,
    render_flow_report,
    render_switch_outline,
)


def _capture() -> FunctionCapture:
    return FunctionCapture(
        ea=0x140001000,
        name="SampleDispatcher",
        pseudocode="__int64 __fastcall SampleDispatcher(int code)\n{\n  return code;\n}\n",
    )


def _plan(flow: FlowRewrite) -> CleanPlan:
    return CleanPlan(
        function_ea=0x140001000,
        function_name="SampleDispatcher",
        input_fingerprint="fp",
        flow_rewrites=[flow],
    )


class RenderFlowTests(unittest.TestCase):
    def test_render_flow_report_includes_case_metadata_and_warnings(self) -> None:
        flow = FlowRewrite(
            kind="switch",
            dispatcher="code",
            recovered_cases=[1, 2],
            case_body_states={1: "single_statement_body", 2: "shared_tail"},
            case_anchors={1: 6, 2: 12},
            case_labels={2: "LABEL_10"},
            confidence=0.91,
            evidence="linear if chain",
        )
        plan = _plan(flow)
        plan.warnings.append('{"message":"review manually"}')

        report = render_flow_report(_capture(), plan)

        self.assertIn("- Dispatcher: `code`", report)
        self.assertIn("`1` (body_state=`single_statement_body`, source_line=`6`)", report)
        self.assertIn("`2` (body_state=`shared_tail`, source_line=`12`, label=`LABEL_10`)", report)
        self.assertIn("- review manually", report)

    def test_render_switch_outline_expands_only_safe_single_return_body(self) -> None:
        flow = FlowRewrite(
            kind="switch",
            dispatcher="code",
            recovered_cases=[1, 2],
            case_bodies={
                1: ["return status;"],
                2: ["status = -1;", "goto LABEL_10;"],
            },
            case_body_states={1: "single_statement_body", 2: "shared_tail"},
            case_anchors={1: 6, 2: 12},
            case_labels={2: "LABEL_10"},
        )
        plan = _plan(flow)
        plan.renames.append(
            RenameSuggestion("local", "status", "operationStatus", 0.95, "test", "fixture")
        )

        outline = render_switch_outline(_capture(), plan)

        self.assertIn("switch (code)", outline)
        self.assertIn("return operationStatus;", outline)
        self.assertIn("// PseudoForge: body_state=shared_tail source_line=12 label=LABEL_10.", outline)
        self.assertIn("complex body not structurally sliced", outline)
        self.assertNotIn("status = -1;", outline)

    def test_native_switch_dispatchers_detects_existing_switch(self) -> None:
        flow = FlowRewrite(kind="switch", dispatcher="code", recovered_cases=[1])
        plan = _plan(flow)

        self.assertEqual(native_switch_dispatchers("switch ( (int)code )\n{", plan), {"code"})
        self.assertFalse(is_safe_switch_outline_body(["status = 0;", "break;"]))
        self.assertTrue(is_safe_switch_outline_body(["return STATUS_NOT_SUPPORTED;"]))


if __name__ == "__main__":
    unittest.main()
