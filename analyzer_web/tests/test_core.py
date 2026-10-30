from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from analyzer_web.core import resolve_artifact


class CoreTests(unittest.TestCase):
    def test_artifact_path_must_remain_inside_project(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "browser" / "files" / "History"
            target.parent.mkdir(parents=True); target.write_bytes(b"test")
            output = r"C:\Temp\portable_1"
            saved = r"C:\Temp\portable_1\browser\files\History"
            self.assertEqual(resolve_artifact(root, output, saved), target)
            self.assertIsNone(resolve_artifact(root, output, r"C:\Temp\outside\secret.txt"))


if __name__ == "__main__":
    unittest.main()
