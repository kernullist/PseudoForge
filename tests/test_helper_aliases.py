from __future__ import annotations

import unittest

from ida_pseudoforge.core.helper_aliases import (
    apply_runtime_helper_aliases,
    infer_runtime_helper_alias,
    infer_runtime_helper_aliases_from_texts,
)


OPTIMIZED_FILL_HELPER = r"""
__int64 __fastcall sub_180001000(char *destination, unsigned __int8 fillByte, unsigned __int64 byteCount)
{
  __int64 result;
  __int64 fillPattern;

  result = (__int64)destination;
  fillPattern = 0x101010101010101LL * fillByte;
  if ( byteCount >= 4 )
  {
    *(_DWORD *)destination = fillPattern;
    *(_DWORD *)&destination[byteCount - 4] = fillPattern;
  }
  else if ( byteCount )
  {
    *destination = fillPattern;
  }
  return result;
}
"""


OPTIMIZED_MOVE_HELPER = r"""
void *__fastcall sub_180002000(char *destination, char *source, unsigned __int64 byteCount)
{
  void *result;
  signed __int64 delta;
  char *tail;
  char value;

  result = destination;
  if ( byteCount )
  {
    delta = source - destination;
    if ( source < destination )
    {
      tail = &destination[byteCount];
      do
      {
        value = tail[delta - 1];
        --tail;
        --byteCount;
        *tail = value;
      }
      while ( byteCount );
    }
  }
  return result;
}
"""


FALSE_POSITIVE_HELPER = r"""
__int64 __fastcall sub_180003000(char *destination, unsigned __int8 fillByte, unsigned __int64 byteCount)
{
  __int64 result;

  result = (__int64)destination;
  if ( byteCount > 4 )
  {
    return result + fillByte + byteCount;
  }
  return result;
}
"""


CALLER_SAMPLE = r"""
void __fastcall Caller(char *buffer)
{
  sub_180001000(buffer, 0, 64LL);
}
"""


class RuntimeHelperAliasTests(unittest.TestCase):
    def test_infers_memory_fill_helper_from_role_and_body_evidence(self) -> None:
        alias = infer_runtime_helper_alias(OPTIMIZED_FILL_HELPER)

        self.assertIsNotNone(alias)
        self.assertEqual(alias.original_name, "sub_180001000")
        self.assertEqual(alias.base_alias, "memset")
        self.assertEqual(alias.role, "runtime-memory-fill")

    def test_infers_memory_move_helper_from_overlap_copy_evidence(self) -> None:
        alias = infer_runtime_helper_alias(OPTIMIZED_MOVE_HELPER)

        self.assertIsNotNone(alias)
        self.assertEqual(alias.original_name, "sub_180002000")
        self.assertEqual(alias.base_alias, "memmove")
        self.assertEqual(alias.role, "runtime-memory-move")

    def test_rejects_three_argument_arithmetic_helper_without_memory_writes(self) -> None:
        alias = infer_runtime_helper_alias(FALSE_POSITIVE_HELPER)

        self.assertIsNone(alias)

    def test_result_alias_comparison_does_not_look_like_mutation(self) -> None:
        helper = OPTIMIZED_FILL_HELPER.replace(
            "  return result;",
            "  if ( result == 0 )\n  {\n    return 0LL;\n  }\n  return result;",
        )

        alias = infer_runtime_helper_alias(helper)

        self.assertIsNotNone(alias)
        self.assertEqual(alias.original_name, "sub_180001000")

    def test_applies_inferred_alias_to_call_sites(self) -> None:
        aliases = infer_runtime_helper_aliases_from_texts([OPTIMIZED_FILL_HELPER])
        updated = apply_runtime_helper_aliases(CALLER_SAMPLE, aliases)

        self.assertIn("memset(buffer, 0, 64LL);", updated)
        self.assertNotIn("sub_180001000(buffer", updated)

    def test_keeps_standard_alias_when_role_has_multiple_helpers(self) -> None:
        second_helper = OPTIMIZED_FILL_HELPER.replace("sub_180001000", "sub_180001100")

        aliases = infer_runtime_helper_aliases_from_texts([second_helper, OPTIMIZED_FILL_HELPER])

        self.assertEqual(aliases["sub_180001000"].alias_name, "memset")
        self.assertEqual(aliases["sub_180001100"].alias_name, "memset")

    def test_alias_rewrite_keeps_helper_definition_name(self) -> None:
        aliases = infer_runtime_helper_aliases_from_texts([OPTIMIZED_FILL_HELPER])
        updated = apply_runtime_helper_aliases(OPTIMIZED_FILL_HELPER + CALLER_SAMPLE, aliases)

        self.assertIn("__int64 __fastcall sub_180001000(", updated)
        self.assertIn("memset(buffer, 0, 64LL);", updated)


if __name__ == "__main__":
    unittest.main()
