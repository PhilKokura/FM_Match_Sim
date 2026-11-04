import unittest
from unittest import mock
from pathlib import Path

from fm_match_sim.live import compare_prefix, probe_live, SIGNATURE_LENGTH
from fm_match_sim.cli import build_parser


class LiveProbeTests(unittest.TestCase):
    def test_prefix_matching_requires_exact_length_and_content(self):
        original = bytes(range(SIGNATURE_LENGTH))
        self.assertTrue(compare_prefix(original, original))
        self.assertFalse(compare_prefix(original, original[:-1]))
        self.assertFalse(compare_prefix(original, original[:-1] + b"\xff"))
        self.assertFalse(compare_prefix(b"", b""))

    def test_cli_accepts_hex_base(self):
        parser = build_parser()
        args = parser.parse_args([
            "probe-live", "--pid", "7004", "--base", "0x7FFF7E230000",
            "--dll", "C:/game/game_plugin.dll",
        ])
        self.assertEqual(args.pid, 7004)
        self.assertEqual(args.base, 0x7FFF7E230000)

    @mock.patch("fm_match_sim.live.sys.platform", "linux")
    def test_not_supported_on_non_windows(self):
        with self.assertRaisesRegex(OSError, "Windows"):
            probe_live(Path("unused.dll"), pid=7004, module_base=0x7FFF7E230000)


if __name__ == "__main__":
    unittest.main()
