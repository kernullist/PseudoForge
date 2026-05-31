import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import (
    render_cleaned_pseudocode,
    render_switch_outline,
)
from ida_pseudoforge.version import VERSION

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


class CoreEngineTests(unittest.TestCase):
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

if __name__ == "__main__":
    unittest.main()
