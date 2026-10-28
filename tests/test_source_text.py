from pathlib import Path
import subprocess
import tempfile
import unittest

from utils.source_text import latin1_comments_to_utf8, ngiflib_preparation


class SourceTextTests(unittest.TestCase):
    def test_latin1_conversion_preserves_code_literals_and_crlf(self):
        raw = b'/* image decod\xe9e */\r\nconst char *u = "https://example/a/*x*/";\r\nreturn 1; // decod\xe9e\r\n'
        self.assertEqual(latin1_comments_to_utf8(raw), raw.replace(b"\xe9", b"\xc3\xa9"))

    def test_already_utf8_source_is_byte_identical(self):
        raw = '// \u4e2d\u6587\nconst char *s = "\u00e9";\r\n'.encode("utf-8")
        self.assertEqual(latin1_comments_to_utf8(raw), raw)

    def test_legacy_bytes_in_code_or_literals_are_rejected(self):
        for raw in (b'const char *s = "http://a/\xe9";', b"char x = '\xe9';", b"int caf\xe9 = 1;"):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "outside C comments"):
                latin1_comments_to_utf8(raw)

    def test_embedded_container_preparation_runs_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source/ngiflib.c"
            source.parent.mkdir()
            source.write_bytes(b"/* Decod\xe9e */\nreturn 1;\n")
            script = 'set -euo pipefail\nPROJECT_DIR="$1"\n' + ngiflib_preparation()
            script += 'cp -a "$PROJECT_DIR/source" "$PROJECT_DIR/source_patched"\n'
            finished = subprocess.run(["bash", "-c", script, "test", str(root)], capture_output=True)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            self.assertEqual(source.read_bytes(), b"/* Decod\xc3\xa9e */\nreturn 1;\n")
            self.assertEqual((root / "source_patched/ngiflib.c").read_bytes(), source.read_bytes())
