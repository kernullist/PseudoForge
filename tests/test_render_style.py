from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_style import enforce_generated_code_style
from tests.fixtures.snapshot_samples import SINGLE_LINE_IF_SAMPLE


STYLE_SAMPLE = r"""
__int64 __fastcall StyleSample(int a1)
{
  int v1;

  v1 = 0;
  if ( a1 )
    return 1;
  else if ( a1 == 2 )
    v1 = 2;
  else
    v1 = 3;
  while ( v1 )
    --v1;
  return v1;
}
"""


GUARD_INVERSION_SAMPLE = r"""
__int64 __fastcall GuardSample(int a1, int a2)
{
  int v1;

  v1 = 0;
  if ( a1 && a2 >= 4 )
  {
    v1 = a2 + 1;
  }
  else
  {
    return 3221225476LL;
  }
  return v1;
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


class RenderStyleTests(unittest.TestCase):
    def test_style_pass_splits_inline_braces_and_expands_else_if(self) -> None:
        styled = enforce_generated_code_style(
            "if ( x ) {\n"
            "  do_x();\n"
            "} else if ( y ) {\n"
            "  do_y();\n"
            "}\n"
        )

        self.assertNotIn("} else", styled)
        self.assertNotIn("else if", styled)
        self.assertIn("if ( x )\n{\n  do_x();\n}", styled)
        self.assertIn("else\n{\n  if ( y )\n  {\n    do_y();\n  }\n}", styled)

    def test_style_pass_wraps_bodies_and_inverts_terminal_else_guards(self) -> None:
        styled = enforce_generated_code_style(
            "if ( ready && count >= 4 )\n"
            "  do_work();\n"
            "else\n"
            "  return STATUS_INFO_LENGTH_MISMATCH;\n"
            "finish();\n"
        )

        self.assertIn("if ( !ready || count < 4 )\n{\n  return STATUS_INFO_LENGTH_MISMATCH;\n}", styled)
        self.assertIn("do_work();\nfinish();", styled)

    def test_generated_code_style(self) -> None:
        capture = capture_from_pseudocode(STYLE_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("else if", rendered)
        self.assertNotIn("while (false);", rendered)
        self.assertNotIn("pseudoForgeResult", rendered)
        self.assertIn("  if ( argument0 )\n  {\n    return 1;\n  }", rendered)
        self.assertIn("  if ( argument0 == 2 )\n  {", rendered)
        self.assertIn("  else\n  {", rendered)
        self.assertIn("  while ( v1 )\n  {\n    --v1;\n  }", rendered)

    def test_positive_guard_inversion(self) -> None:
        capture = capture_from_pseudocode(GUARD_INVERSION_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("if ( argument0 && argument1 >= 4 )", rendered)
        self.assertIn("if ( !argument0 || argument1 < 4 )", rendered)
        self.assertIn("return STATUS_INFO_LENGTH_MISMATCH;", rendered)
        self.assertIn("argument1 + 1;", rendered)

    def test_multiline_conditions_keep_braces_after_complete_header(self) -> None:
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

    def test_single_line_if_body_wrapping_preserves_following_statement(self) -> None:
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

    def test_nested_else_after_empty_if_is_repaired(self) -> None:
        styled = enforce_generated_code_style(
            "if ( flags != 0 )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    (void)Probe(buffer);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( flags == 0 )\n"
            "{\n"
            "  (void)Probe(buffer);\n"
            "}",
            styled,
        )
        self.assertNotIn("{\n  else", styled)

    def test_nested_else_after_empty_if_preserves_pointer_member_access(self) -> None:
        styled = enforce_generated_code_style(
            "if ( (mdl->MdlFlags & 5) != 0 )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    (void)MapPages(mdl);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( (mdl->MdlFlags & 5) == 0 )\n"
            "{\n"
            "  (void)MapPages(mdl);\n"
            "}",
            styled,
        )
        self.assertNotIn("mdl- <=", styled)
        self.assertNotIn("{\n  else", styled)

    def test_nested_else_after_empty_if_does_not_treat_shifts_as_comparisons(self) -> None:
        styled = enforce_generated_code_style(
            "if ( flags << 1 )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    Use(flags);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( !(flags << 1) )\n"
            "{\n"
            "  Use(flags);\n"
            "}",
            styled,
        )
        self.assertNotIn("flags <= 1", styled)
        self.assertNotIn("{\n  else", styled)

        styled = enforce_generated_code_style(
            "if ( flags >> 1 )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    Use(flags);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( !(flags >> 1) )\n"
            "{\n"
            "  Use(flags);\n"
            "}",
            styled,
        )
        self.assertNotIn("flags <= > 1", styled)
        self.assertNotIn("{\n  else", styled)

    def test_nested_else_after_empty_if_ignores_subscript_comparisons(self) -> None:
        styled = enforce_generated_code_style(
            "if ( table[index < limit] != 0 )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    Use(table);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( table[index < limit] == 0 )\n"
            "{\n"
            "  Use(table);\n"
            "}",
            styled,
        )
        self.assertNotIn("table[index >= limit]", styled)
        self.assertNotIn("{\n  else", styled)

    def test_nested_else_after_empty_if_ignores_subscript_logical_operators(self) -> None:
        styled = enforce_generated_code_style(
            "if ( ready && table[index || fallback] != 0 )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    Use(table);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( !ready || table[index || fallback] == 0 )\n"
            "{\n"
            "  Use(table);\n"
            "}",
            styled,
        )
        self.assertNotIn("!(ready && table[index || fallback] != 0)", styled)
        self.assertNotIn("{\n  else", styled)

    def test_nested_else_after_empty_if_with_complex_condition_is_repaired(self) -> None:
        styled = enforce_generated_code_style(
            "if ( Probe(buffer) && (flags & mask) )\n"
            "{\n"
            "  else\n"
            "  {\n"
            "    Use(buffer);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( !(Probe(buffer) && (flags & mask)) )\n"
            "{\n"
            "  Use(buffer);\n"
            "}",
            styled,
        )
        self.assertNotIn("{\n  else", styled)

    def test_nested_else_if_after_empty_if_is_repaired(self) -> None:
        styled = enforce_generated_code_style(
            "if ( flags != 0 )\n"
            "{\n"
            "  else if ( Probe(buffer) )\n"
            "  {\n"
            "    Use(buffer);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( flags == 0 )\n"
            "{\n"
            "  if ( Probe(buffer) )\n"
            "  {\n"
            "    Use(buffer);\n"
            "  }\n"
            "}",
            styled,
        )
        self.assertNotIn("{\n  else", styled)
        self.assertNotIn("else if", styled)

    def test_nested_multiline_else_if_after_empty_if_is_repaired(self) -> None:
        styled = enforce_generated_code_style(
            "if ( flags != 0 )\n"
            "{\n"
            "  else if ( Probe(buffer)\n"
            "    && Check(mask) )\n"
            "  {\n"
            "    Use(buffer);\n"
            "  }\n"
            "}\n"
        )

        self.assertIn(
            "if ( flags == 0 )\n"
            "{\n"
            "  if ( Probe(buffer)\n"
            "    && Check(mask) )\n"
            "  {\n"
            "    Use(buffer);\n"
            "  }\n"
            "}",
            styled,
        )
        self.assertNotIn("{\n  else", styled)
        self.assertNotIn("else if", styled)

    def test_nested_else_single_statement_after_empty_if_is_repaired(self) -> None:
        styled = enforce_generated_code_style(
            "if ( flags != 0 )\n"
            "{\n"
            "  else\n"
            "    Use(buffer);\n"
            "}\n"
        )

        self.assertIn(
            "if ( flags == 0 )\n"
            "{\n"
            "  Use(buffer);\n"
            "}",
            styled,
        )
        self.assertNotIn("{\n  else", styled)


if __name__ == "__main__":
    unittest.main()
