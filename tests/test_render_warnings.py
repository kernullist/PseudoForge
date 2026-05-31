from __future__ import annotations

import unittest

from ida_pseudoforge.core.plan_schema import CleanPlan, FlowRewrite, RenameSuggestion
from ida_pseudoforge.core.render_warnings import display_warning_count, display_warnings, format_warning
from ida_pseudoforge.profiles.loader import clear_profile_caches


def _plan(
    warnings: list[str],
    *,
    comments: list[dict[str, object]] | None = None,
    flow_rewrites: list[FlowRewrite] | None = None,
    renames: list[RenameSuggestion] | None = None,
) -> CleanPlan:
    return CleanPlan(
        function_ea=0x140001000,
        function_name="Sample",
        input_fingerprint="fp",
        warnings=warnings,
        comments=comments or [],
        flow_rewrites=flow_rewrites or [],
        renames=renames or [],
    )


class RenderWarningsTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_profile_caches()

    def tearDown(self) -> None:
        clear_profile_caches()

    def test_display_warnings_hides_routine_large_dispatcher_rename_noise(self) -> None:
        plan = _plan(
            [
                "Skipped LLM rename v1->scratchValue: low confidence 0.62",
                "Potential bad call target sub_140001000: unresolved indirect call",
            ],
            flow_rewrites=[
                FlowRewrite(kind="switch", dispatcher="SystemInformationClass", recovered_cases=list(range(16))),
            ],
        )

        warnings = display_warnings(plan)

        self.assertEqual(warnings, ["Potential bad call target sub_140001000: unresolved indirect call"])
        self.assertEqual(display_warning_count(plan), 1)

    def test_display_warnings_hides_driver_entry_subroutine_noise(self) -> None:
        plan = _plan(
            [
                "Skipped PascalCase LLM rename sub_140001000->InitializeDevice",
                "Manual review required",
            ],
            comments=[{"kind": "driver_entry"}],
        )

        self.assertEqual(display_warnings(plan), ["Manual review required"])

    def test_format_warning_handles_structured_and_json_warnings(self) -> None:
        self.assertEqual(
            format_warning({"old": "sub_140001000", "reason": "unresolved indirect call"}),
            "Potential bad call target sub_140001000: unresolved indirect call",
        )
        self.assertEqual(format_warning('{"message":"review manually"}'), "review manually")


if __name__ == "__main__":
    unittest.main()
