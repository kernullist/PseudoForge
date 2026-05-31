from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.flow_recovery import recover_flow
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, FunctionCapture, RenameSuggestion
from ida_pseudoforge.core.render import render_cleaned_pseudocode
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


NATIVE_SWITCH_SAMPLE = r"""
__int64 __fastcall NativeSwitchSample(int a1)
{
  switch ( a1 )
  {
    case 4:
      return 4;
    case 5:
      return 5;
    case 7:
      return 7;
    case 11:
      return 11;
    default:
      return 0;
  }
}
"""


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

    def test_switch_outline_omits_goto_dependent_body(self) -> None:
        self.assertFalse(
            is_safe_switch_outline_body(
                [
                    "operationStatus = VfVolatileApplyDifVerification(systemInfo128);",
                    "goto LABEL_418;",
                ]
            )
        )
        self.assertFalse(is_safe_switch_outline_body(["v50 = 0;", "v129 = 0;", "break;"]))
        self.assertTrue(is_safe_switch_outline_body(["return STATUS_NOT_SUPPORTED;"]))

    def test_build_clean_plan_reports_shared_tail_case_metadata(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall SharedTailDispatcher(int code)
{
  int status;

  if ( code == 1 )
    return 1;
  if ( code == 2 )
  {
    status = -1;
    goto LABEL_10;
  }
  if ( code == 3 )
    goto LABEL_10;
  if ( code == 4 )
    return 4;
LABEL_10:
  return status;
}
"""
        )
        plan = build_clean_plan(capture)
        flow = plan.flow_rewrites[0]

        self.assertEqual("single_statement_body", flow.case_body_states[1])
        self.assertEqual("shared_tail", flow.case_body_states[2])
        self.assertEqual("shared_tail", flow.case_body_states[3])
        self.assertEqual("LABEL_10", flow.case_labels[2])
        self.assertEqual("LABEL_10", flow.case_labels[3])
        self.assertGreater(flow.case_anchors[2], 0)

        report = render_flow_report(capture, plan)
        self.assertIn("`2` (body_state=`shared_tail`, source_line=`8`, label=`LABEL_10`)", report)
        self.assertIn("`3` (body_state=`shared_tail`, source_line=`13`, label=`LABEL_10`)", report)

        outline = render_switch_outline(capture, plan)
        self.assertIn("// PseudoForge: body_state=shared_tail source_line=8 label=LABEL_10.", outline)
        self.assertIn("// PseudoForge: body_state=single_statement_body source_line=6.", outline)
        self.assertNotIn("status = -1;", outline)
        self.assertNotIn("goto LABEL_10;", outline)

    def test_rendered_native_switch_outline_is_suppressed(self) -> None:
        capture = capture_from_pseudocode(NATIVE_SWITCH_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        outline = render_switch_outline(capture, plan)

        self.assertTrue(plan.flow_rewrites)
        self.assertIn("source=native_switch outline=suppressed", rendered)
        self.assertIn("switch ( argument0 )", rendered)
        self.assertIn("Native switch (argument0) already exists", rendered)
        self.assertIn("Native switch (argument0) already exists", outline)
        self.assertNotIn("complex body not structurally sliced", rendered)
        self.assertNotIn("case 4:", outline)

    def test_recover_flow_handles_same_line_switch_fallthrough_and_nested_cases(self) -> None:
        capture = FunctionCapture(
            ea=0x140002000,
            name="NativeDispatcher",
            pseudocode="""
__int64 __fastcall NativeDispatcher(int code, int other)
{
  switch ( code ) {
  case 1:
    return 1;
  case 2:
    switch ( other )
    {
    case 7:
      return 7;
    }
    return 2;
  case 3:
  case 4:
    return 4;
  }
  return 0;
}
""",
        )

        flows = recover_flow(capture)
        flow = flows[0]
        report = render_flow_report(capture, _plan(flow))
        outline = render_switch_outline(capture, _plan(flow))

        self.assertEqual(flow.recovered_cases, [1, 2, 3, 4])
        self.assertNotIn(7, flow.recovered_cases)
        self.assertEqual(flow.case_body_states[1], "single_statement_body")
        self.assertEqual(flow.case_body_states[2], "complex_unsliced")
        self.assertEqual(flow.case_body_states[3], "fallthrough_or_join")
        self.assertEqual(flow.case_body_states[4], "single_statement_body")
        self.assertIn("`3` (body_state=`fallthrough_or_join`", report)
        self.assertIn("Native switch (code) already exists", outline)


if __name__ == "__main__":
    unittest.main()
