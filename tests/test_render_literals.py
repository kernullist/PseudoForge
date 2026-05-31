from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_literals import (
    escape_path_like_string_literals,
    finalize_rendered_c_like_text,
)


class RenderLiteralTests(unittest.TestCase):
    def test_escape_path_like_string_literals_escapes_rooted_paths(self) -> None:
        text = r'''
  path = L"\Registry\Machine\System";
  image = "\SystemRoot\System32\win32k.sys";
  normal = "line\nnot_a_path";
'''

        escaped = escape_path_like_string_literals(text)

        self.assertIn(r'path = L"\\Registry\\Machine\\System";', escaped)
        self.assertIn(r'image = "\\SystemRoot\\System32\\win32k.sys";', escaped)
        self.assertIn(r'normal = "line\nnot_a_path";', escaped)

    def test_escape_path_like_string_literals_keeps_already_escaped_paths_stable(self) -> None:
        text = r'path = "\\SystemRoot\\System32\\win32k.sys";'

        self.assertEqual(escape_path_like_string_literals(text), text)

    def test_finalize_rendered_c_like_text_escapes_drive_paths(self) -> None:
        text = r'const char *path = "C:\Windows\Temp\driver.sys";'

        finalized = finalize_rendered_c_like_text(text)

        self.assertEqual(finalized, r'const char *path = "C:\\Windows\\Temp\\driver.sys";')


if __name__ == "__main__":
    unittest.main()
