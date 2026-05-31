from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ida_pseudoforge.core.plan_schema import LocalVariable
from tools.pseudoforge_ida_identity_apply_smoke import (
    _candidate_new_name,
    _drifted_lvar,
    _is_temp_path,
    _replace_lvar,
    _select_candidate,
)


class IdaIdentityApplySmokeTests(unittest.TestCase):
    def test_select_candidate_prefers_identity_backed_local_over_argument(self) -> None:
        argument = LocalVariable("a1", "int", True, 0, "reg:1", "arg-id")
        local = LocalVariable("v1", "int", False, 1, "stkoff:-4", "local-id")

        selected = _select_candidate([argument, local], "pfIdentitySmoke")

        self.assertEqual(selected, local)

    def test_candidate_new_name_avoids_existing_locals(self) -> None:
        name = _candidate_new_name("pfIdentitySmoke", ["pfIdentitySmoke00", "pfIdentitySmoke00_1"], 0)

        self.assertEqual(name, "pfIdentitySmoke00_2")

    def test_replace_lvar_swaps_only_first_matching_name(self) -> None:
        original = [
            LocalVariable("v1", "int", False, 1, "stkoff:-4", "old"),
            LocalVariable("v2", "int", False, 2, "stkoff:-8", "keep"),
        ]
        replacement = _drifted_lvar(original[0])

        updated = _replace_lvar(original, replacement)

        self.assertEqual(updated[0].identity, "old:drift")
        self.assertEqual(updated[1].identity, "keep")

    def test_temp_path_guard_accepts_only_temp_descendants(self) -> None:
        temp_root = str(Path(tempfile.gettempdir()).resolve())
        inside = str(Path(temp_root) / "pseudoforge" / "sample.exe")
        outside = str(Path(temp_root).parent / "not-temp" / "sample.exe")

        with mock.patch.dict(os.environ, {"TEMP": temp_root, "TMP": temp_root}):
            self.assertTrue(_is_temp_path(inside))
            self.assertFalse(_is_temp_path(outside))
            self.assertFalse(_is_temp_path(""))


if __name__ == "__main__":
    unittest.main()
