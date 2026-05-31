from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ida_pseudoforge.core.deterministic.validators import validate_rule_pack_file
from tests.rule_test_helpers import (
    _call_arg_gate_match,
    _call_arg_rewrite_rule,
    _rename_rule,
    _rule_pack,
)


class RulePackValidatorTests(unittest.TestCase):
    def test_rule_pack_validator_reports_invalid_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_path = temp_path / "valid.json"
            valid_path.write_text(json.dumps(_rule_pack([_rename_rule()])), encoding="utf-8")
            self.assertEqual(validate_rule_pack_file(valid_path), [])

            invalid_json_path = temp_path / "invalid_json.json"
            invalid_json_path.write_text("{", encoding="utf-8")
            self.assertTrue(any("invalid JSON" in error for error in validate_rule_pack_file(invalid_json_path)))

            duplicate_path = temp_path / "duplicate.json"
            duplicate_path.write_text(json.dumps(_rule_pack([_rename_rule(), _rename_rule()])), encoding="utf-8")
            self.assertTrue(any("duplicate rule id" in error for error in validate_rule_pack_file(duplicate_path)))

            invalid_phase = _rename_rule()
            invalid_phase["phase"] = "text_rewrite"
            invalid_phase_path = temp_path / "invalid_phase.json"
            invalid_phase_path.write_text(json.dumps(_rule_pack([invalid_phase])), encoding="utf-8")
            self.assertTrue(any("phase" in error for error in validate_rule_pack_file(invalid_phase_path)))

            invalid_confidence = _rename_rule()
            invalid_confidence["confidence"] = 2.0
            invalid_confidence_path = temp_path / "invalid_confidence.json"
            invalid_confidence_path.write_text(json.dumps(_rule_pack([invalid_confidence])), encoding="utf-8")
            self.assertTrue(any("confidence" in error for error in validate_rule_pack_file(invalid_confidence_path)))

            bool_confidence = _rename_rule()
            bool_confidence["confidence"] = True
            bool_confidence_path = temp_path / "bool_confidence.json"
            bool_confidence_path.write_text(json.dumps(_rule_pack([bool_confidence])), encoding="utf-8")
            self.assertTrue(any("confidence" in error for error in validate_rule_pack_file(bool_confidence_path)))

            bool_priority = _rename_rule()
            bool_priority["priority"] = True
            bool_priority_path = temp_path / "bool_priority.json"
            bool_priority_path.write_text(json.dumps(_rule_pack([bool_priority])), encoding="utf-8")
            self.assertTrue(any("priority" in error for error in validate_rule_pack_file(bool_priority_path)))

            invalid_regex = _rename_rule()
            invalid_regex["match"]["assignment_regex"] = "("
            invalid_regex_path = temp_path / "invalid_regex.json"
            invalid_regex_path.write_text(json.dumps(_rule_pack([invalid_regex])), encoding="utf-8")
            self.assertTrue(any("invalid regex" in error for error in validate_rule_pack_file(invalid_regex_path)))

            missing_emit = _rename_rule()
            del missing_emit["emit"]["new_name"]
            missing_emit_path = temp_path / "missing_emit.json"
            missing_emit_path.write_text(json.dumps(_rule_pack([missing_emit])), encoding="utf-8")
            self.assertTrue(any("new_name is required" in error for error in validate_rule_pack_file(missing_emit_path)))

            invalid_scope_regex = _rename_rule()
            invalid_scope_regex["scope"] = {"function_name_regex": "("}
            invalid_scope_regex_path = temp_path / "invalid_scope_regex.json"
            invalid_scope_regex_path.write_text(json.dumps(_rule_pack([invalid_scope_regex])), encoding="utf-8")
            self.assertTrue(
                any("function_name_regex invalid regex" in error for error in validate_rule_pack_file(invalid_scope_regex_path))
            )

            empty_match = _rename_rule()
            empty_match["match"] = {}
            empty_match_path = temp_path / "empty_match.json"
            empty_match_path.write_text(json.dumps(_rule_pack([empty_match])), encoding="utf-8")
            self.assertTrue(any("match must define at least one supported operator" in error for error in validate_rule_pack_file(empty_match_path)))

            empty_text_match = _rename_rule()
            empty_text_match["match"] = {"text_contains": ""}
            empty_text_match_path = temp_path / "empty_text_match.json"
            empty_text_match_path.write_text(json.dumps(_rule_pack([empty_text_match])), encoding="utf-8")
            self.assertTrue(any("text_contains must be a non-empty string" in error for error in validate_rule_pack_file(empty_text_match_path)))

            empty_scope_gate = _rename_rule()
            empty_scope_gate["scope"] = {"calls_any": []}
            empty_scope_gate_path = temp_path / "empty_scope_gate.json"
            empty_scope_gate_path.write_text(json.dumps(_rule_pack([empty_scope_gate])), encoding="utf-8")
            self.assertTrue(any("calls_any must be a non-empty string or non-empty string list" in error for error in validate_rule_pack_file(empty_scope_gate_path)))

            ambiguous_regex = _rename_rule()
            ambiguous_regex["match"]["regex"] = r"\bv1\b"
            ambiguous_regex_path = temp_path / "ambiguous_regex.json"
            ambiguous_regex_path.write_text(json.dumps(_rule_pack([ambiguous_regex])), encoding="utf-8")
            self.assertTrue(any("must not combine regex and assignment_regex" in error for error in validate_rule_pack_file(ambiguous_regex_path)))

            invalid_schema = _rule_pack([_rename_rule()])
            invalid_schema["schema_version"] = True
            invalid_schema_path = temp_path / "invalid_schema.json"
            invalid_schema_path.write_text(json.dumps(invalid_schema), encoding="utf-8")
            self.assertTrue(any("unsupported schema_version" in error for error in validate_rule_pack_file(invalid_schema_path)))

    def test_rule_pack_validator_accepts_v2_call_arg_rewrite_preview_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_path = temp_path / "valid_v2_call_arg.json"
            valid_path.write_text(json.dumps(_rule_pack([_call_arg_rewrite_rule()], schema_version=2)), encoding="utf-8")

            self.assertEqual(validate_rule_pack_file(valid_path), [])

            v1_path = temp_path / "v1_call_arg_rejected.json"
            v1_path.write_text(json.dumps(_rule_pack([_call_arg_rewrite_rule()])), encoding="utf-8")
            self.assertTrue(any("phase" in error for error in validate_rule_pack_file(v1_path)))

            not_preview = _call_arg_rewrite_rule()
            not_preview["emit"]["preview_only"] = False
            not_preview_path = temp_path / "not_preview.json"
            not_preview_path.write_text(json.dumps(_rule_pack([not_preview], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("preview_only must be true" in error for error in validate_rule_pack_file(not_preview_path)))

            bad_argument = _call_arg_rewrite_rule()
            bad_argument["emit"]["argument_index"] = -1
            bad_argument_path = temp_path / "bad_argument.json"
            bad_argument_path.write_text(json.dumps(_rule_pack([bad_argument], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("argument_index" in error for error in validate_rule_pack_file(bad_argument_path)))

            missing_call_gate = _call_arg_rewrite_rule()
            missing_call_gate["scope"] = {"text_contains": "ProbeForRead"}
            missing_call_gate_path = temp_path / "missing_call_gate.json"
            missing_call_gate_path.write_text(json.dumps(_rule_pack([missing_call_gate], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("must gate call_arg_rewrite" in error for error in validate_rule_pack_file(missing_call_gate_path)))

            binding_function = _call_arg_rewrite_rule()
            binding_function["emit"]["function_name"] = "$callee"
            binding_function["scope"] = {"text_contains": "ProbeForRead"}
            binding_function_path = temp_path / "binding_function.json"
            binding_function_path.write_text(json.dumps(_rule_pack([binding_function], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("must gate call_arg_rewrite" in error for error in validate_rule_pack_file(binding_function_path)))

    def test_rule_pack_validator_accepts_v2_call_arg_match_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            valid_rule = _call_arg_rewrite_rule()
            valid_rule["match"] = _call_arg_gate_match()
            valid_path = temp_path / "valid_call_arg_gates.json"
            valid_path.write_text(json.dumps(_rule_pack([valid_rule], schema_version=2)), encoding="utf-8")
            self.assertEqual(validate_rule_pack_file(valid_path), [])

            v1_rule = _rename_rule()
            v1_rule["match"] = {
                "call_arg_count": {
                    "function_name": "ProbeForRead",
                    "count": 3,
                }
            }
            v1_path = temp_path / "v1_call_arg_gate.json"
            v1_path.write_text(json.dumps(_rule_pack([v1_rule])), encoding="utf-8")
            self.assertTrue(any("call_arg_count is not supported" in error for error in validate_rule_pack_file(v1_path)))

            invalid_count = _call_arg_rewrite_rule()
            invalid_count["match"] = {
                "call_arg_count": {
                    "function_name": "ProbeForRead",
                    "count": True,
                }
            }
            invalid_count_path = temp_path / "invalid_count.json"
            invalid_count_path.write_text(json.dumps(_rule_pack([invalid_count], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("count must be a non-negative integer" in error for error in validate_rule_pack_file(invalid_count_path)))

            invalid_literal = _call_arg_rewrite_rule()
            invalid_literal["match"] = {
                "call_arg_literal": {
                    "function_name": "ProbeForRead",
                    "argument_index": -1,
                    "value": "1",
                }
            }
            invalid_literal_path = temp_path / "invalid_literal.json"
            invalid_literal_path.write_text(json.dumps(_rule_pack([invalid_literal], schema_version=2)), encoding="utf-8")
            self.assertTrue(any("argument_index must be a non-negative integer" in error for error in validate_rule_pack_file(invalid_literal_path)))


if __name__ == "__main__":
    unittest.main()
