from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.plan_schema import CleanPlan, RenameSuggestion
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_cleanup import apply_generic_render_cleanups


class RenderCleanupTests(unittest.TestCase):
    def test_scalar_out_array_storage_rewrites_by_usage_pattern(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  ULONG outValue[2]; // [rsp+20h] BYREF",
                "  *(_QWORD *)outValue = 0LL;",
                "  GenericCopy(dst, src, 16LL, outValue);",
                "  sink = *(_QWORD *)outValue;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("SIZE_T outValue; // [rsp+20h] BYREF", rendered)
        self.assertIn("outValue = 0LL;", rendered)
        self.assertIn("GenericCopy(dst, src, 16LL, &outValue);", rendered)
        self.assertIn("sink = outValue;", rendered)

    def test_single_assignment_pointer_alias_fold_is_identifier_based(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  PVOID canonical;",
                "  void *alias;",
                "",
                "  alias = canonical;",
                "  Probe(alias);",
                "  sink = alias->Field;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertNotIn("void *alias;", rendered)
        self.assertNotIn("alias = canonical;", rendered)
        self.assertIn("Probe(canonical);", rendered)
        self.assertIn("sink = canonical->Field;", rendered)

    def test_pointer_alias_fold_skips_reassigned_aliases(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  PVOID first;",
                "  PVOID second;",
                "  void *alias;",
                "",
                "  alias = first;",
                "  Probe(alias);",
                "  alias = second;",
                "  Probe(alias);",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("void *alias;", rendered)
        self.assertIn("alias = first;", rendered)
        self.assertIn("alias = second;", rendered)

    def test_pointer_alias_fold_rewrites_indexed_alias_uses(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  _QWORD *canonical;",
                "  _QWORD *alias;",
                "",
                "  alias = canonical;",
                "  alias[1] = tail;",
                "  *alias = head;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertNotIn("_QWORD *alias;", rendered)
        self.assertNotIn("alias = canonical;", rendered)
        self.assertIn("canonical[1] = tail;", rendered)
        self.assertIn("*canonical = head;", rendered)

    def test_pointer_alias_fold_skips_address_taken_aliases(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  _QWORD *canonical;",
                "  _QWORD *alias;",
                "",
                "  alias = canonical;",
                "  Probe(&alias);",
                "  alias[1] = tail;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("_QWORD *alias;", rendered)
        self.assertIn("alias = canonical;", rendered)
        self.assertIn("Probe(&alias);", rendered)

    def test_pointer_alias_fold_skips_alias_used_before_assignment(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  _QWORD *canonical;",
                "  _QWORD *alias;",
                "",
                "  Probe(alias);",
                "  alias = canonical;",
                "  alias[1] = tail;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("_QWORD *alias;", rendered)
        self.assertIn("Probe(alias);", rendered)
        self.assertIn("alias = canonical;", rendered)
        self.assertIn("alias[1] = tail;", rendered)

    def test_pointer_alias_fold_skips_mutated_aliases(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  _BYTE *canonical;",
                "  _BYTE *alias;",
                "",
                "  alias = canonical;",
                "  ++alias;",
                "  Probe(alias);",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("_BYTE *alias;", rendered)
        self.assertIn("alias = canonical;", rendered)
        self.assertIn("++alias;", rendered)
        self.assertIn("Probe(alias);", rendered)

    def test_constant_pointer_expression_alias_reuses_existing_local(self) -> None:
        text = "\n".join(
            [
                "void sample(__int64 context)",
                "{",
                "  _QWORD **listHead;",
                "  _QWORD *tail;",
                "",
                "  listHead = (_QWORD **)(context + 136);",
                "  tail = *(_QWORD **)(context + 144);",
                "  if ( *tail != context + 136 )",
                "  {",
                "    __fastfail(3u);",
                "  }",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("listHead = (_QWORD **)(context + 136);", rendered)
        self.assertIn("if ( *tail != listHead )", rendered)

    def test_constant_pointer_expression_alias_preserves_call_cast(self) -> None:
        text = "\n".join(
            [
                "void sample(__int64 context)",
                "{",
                "  struct _NPAGED_LOOKASIDE_LIST *lookasideList;",
                "  void *entry;",
                "",
                "  lookasideList = (struct _NPAGED_LOOKASIDE_LIST *)(context + 192);",
                "  entry = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(context + 192));",
                "  ExFreeToNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)(context + 192), entry);",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("entry = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)lookasideList);", rendered)
        self.assertIn("ExFreeToNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)lookasideList, entry);", rendered)
        self.assertNotIn("(PNPAGED_LOOKASIDE_LIST)(context + 192)", rendered)

    def test_constant_pointer_expression_alias_skips_mutated_base(self) -> None:
        text = "\n".join(
            [
                "void sample(__int64 context, __int64 nextContext)",
                "{",
                "  _QWORD **listHead;",
                "",
                "  listHead = (_QWORD **)(context + 136);",
                "  context = nextContext;",
                "  Probe(context + 136);",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("Probe(context + 136);", rendered)

    def test_unrolled_wide_array_copy_rewrites_to_qmemcpy(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  _OWORD *destination;",
                "  __int128 tmp1;",
                "  __int128 tmp2;",
                "  __int128 tmp3;",
                "  _OWORD source[4];",
                "",
                "  tmp1 = source[1];",
                "  *destination = source[0];",
                "  tmp2 = source[2];",
                "  destination[1] = tmp1;",
                "  tmp3 = source[3];",
                "  destination[2] = tmp2;",
                "  destination[3] = tmp3;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("qmemcpy(destination, source, sizeof(source));", rendered)
        self.assertNotIn("__int128 tmp1;", rendered)
        self.assertNotIn("__int128 tmp2;", rendered)
        self.assertNotIn("__int128 tmp3;", rendered)
        self.assertNotIn("destination[1] = tmp1;", rendered)
        self.assertNotIn("tmp2 = source[2];", rendered)

    def test_unrolled_wide_array_copy_keeps_temp_used_after_block(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  _OWORD *destination;",
                "  __int128 tmp1;",
                "  _OWORD source[2];",
                "",
                "  tmp1 = source[1];",
                "  *destination = source[0];",
                "  destination[1] = tmp1;",
                "  Sink(tmp1);",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertNotIn("qmemcpy(destination, source, sizeof(source));", rendered)
        self.assertIn("destination[1] = tmp1;", rendered)
        self.assertIn("Sink(tmp1);", rendered)

    def test_scratch_sink_assignments_preserve_calls_and_drop_value_observations(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  __int64 sink;",
                "  void *buffer;",
                "",
                "  sink = (__int64)ProbeRoutine(buffer);",
                "  sink = MmGetPhysicalAddress(buffer).QuadPart;",
                "  sink = buffer;",
                "  sink = buffer->Length;",
                "  Consume(buffer);",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text, scratch_sinks={"sink"})

        self.assertIn("(void)ProbeRoutine(buffer);", rendered)
        self.assertIn("(void)MmGetPhysicalAddress(buffer);", rendered)
        self.assertIn("Consume(buffer);", rendered)
        self.assertNotIn("__int64 sink;", rendered)
        self.assertNotIn("sink =", rendered)
        self.assertNotIn("buffer->Length;", rendered)

    def test_scratch_sink_assignments_keep_read_sinks(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  __int64 sink;",
                "",
                "  sink = ProbeOne();",
                "  sink = ProbeTwo();",
                "  if ( sink )",
                "  {",
                "    Consume(sink);",
                "  }",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text, scratch_sinks={"sink"})

        self.assertIn("sink = ProbeOne();", rendered)
        self.assertIn("sink = ProbeTwo();", rendered)
        self.assertIn("Consume(sink);", rendered)

    def test_scratch_sink_cleanup_removes_followup_write_only_local(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  PVOID mappedValue;",
                "  __int64 sink;",
                "",
                "  if ( flags != 0 )",
                "  {",
                "    mappedValue = object->MappedValue;",
                "  }",
                "  else",
                "  {",
                "    mappedValue = MapObject(object);",
                "  }",
                "  sink = (__int64)mappedValue;",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text, scratch_sinks={"sink"})

        self.assertIn("if ( flags == 0 )", rendered)
        self.assertIn("(void)MapObject(object);", rendered)
        self.assertNotIn("PVOID mappedValue;", rendered)
        self.assertNotIn("mappedValue =", rendered)
        self.assertNotIn("sink =", rendered)
        self.assertNotIn("else", rendered)

    def test_write_only_assignments_are_not_suppressed_without_sink_metadata(self) -> None:
        text = "\n".join(
            [
                "void sample()",
                "{",
                "  __int64 sink;",
                "",
                "  sink = ProbeOne();",
                "  sink = ProbeTwo();",
                "}",
            ]
        )

        rendered = apply_generic_render_cleanups(text)

        self.assertIn("sink = ProbeOne();", rendered)
        self.assertIn("sink = ProbeTwo();", rendered)

    def test_header_omits_rename_removed_by_alias_cleanup(self) -> None:
        sample = "\n".join(
            [
                "void sample()",
                "{",
                "  void *Pool2;",
                "  void *v1;",
                "",
                "  Pool2 = Allocate();",
                "  v1 = Pool2;",
                "  Probe(v1);",
                "}",
            ]
        )
        capture = capture_from_pseudocode(sample)
        plan = CleanPlan(
            function_ea=capture.ea,
            function_name=capture.name,
            input_fingerprint=capture.input_fingerprint(),
            renames=[
                RenameSuggestion("lvar", "Pool2", "poolBuffer", 0.94, "test", "fixture"),
                RenameSuggestion("lvar", "v1", "poolPtr", 0.85, "llm", "fixture"),
            ],
        )

        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("Rename candidates: 1", rendered)
        self.assertIn("Renames: Pool2->poolBuffer(0.94,test)", rendered)
        self.assertNotIn("v1->poolPtr", rendered)
        self.assertNotIn("poolPtr", rendered.rsplit("*/", 1)[-1])
        self.assertIn("Probe(poolBuffer);", rendered)


if __name__ == "__main__":
    unittest.main()
