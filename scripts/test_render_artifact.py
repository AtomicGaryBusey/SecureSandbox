import importlib.util
import os
import unittest


SPEC = importlib.util.spec_from_file_location(
    "render_artifact", os.path.join(os.path.dirname(__file__), "render-artifact.py")
)
renderer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(renderer)


class ArtifactRendererTests(unittest.TestCase):
    def test_terminal_control_bytes_are_escaped(self):
        value = renderer.safe_text("safe\x1b]52;c;payload\x07\n")
        self.assertEqual(value, "safe\\x1b]52;c;payload\\x07\n")
        self.assertNotIn("\x1b", value)

    def test_newline_and_tab_remain_readable(self):
        self.assertEqual(renderer.safe_text("a\tb\nc"), "a\tb\nc")

    def test_bidi_formatting_controls_are_escaped(self):
        self.assertEqual(renderer.safe_text("left\u202eright"), "left\\u202eright")


if __name__ == "__main__":
    unittest.main()
