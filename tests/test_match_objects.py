import ctypes
from pathlib import Path
import unittest
from unittest import mock

from fm_match_sim.cli import build_parser
from fm_match_sim.match_objects import (
    MATCH_VTABLE_RVA,
    MemoryBasicInformation,
    _eligible,
    scan_bytes,
    scan_live_matches,
)


class MatchObjectTests(unittest.TestCase):
    def test_win64_memory_basic_information_layout(self):
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(MemoryBasicInformation), 48)
            self.assertEqual(MemoryBasicInformation.RegionSize.offset, 24)

    def test_exact_aligned_pointer_hits(self):
        target = (0x7FFF7E230000 + MATCH_VTABLE_RVA).to_bytes(8, "little")
        data = b"\x00" * 8 + target + b"\x00" * 8 + target
        self.assertEqual(scan_bytes(data, target, 0x2000), [0x2008, 0x2018])

    def test_unaligned_match_excluded(self):
        target = (0x7FFF7E230000 + MATCH_VTABLE_RVA).to_bytes(8, "little")
        self.assertEqual(scan_bytes(b"\x00" + target, target, 0x2000), [])

    def test_readable_private_committed_only(self):
        self.assertTrue(_eligible(0x1000, 0x04, 0x20000))
        self.assertFalse(_eligible(0x1000, 0x104, 0x20000))
        self.assertFalse(_eligible(0x1000, 0x01, 0x20000))
        self.assertFalse(_eligible(0x1000, 0x04, 0x40000))
        self.assertFalse(_eligible(0x2000, 0x04, 0x20000))

    @mock.patch("fm_match_sim.match_objects.sys.platform", "linux")
    def test_requires_windows(self):
        with self.assertRaisesRegex(OSError, "Windows"):
            scan_live_matches(Path("unused.dll"), pid=7004, module_base=0x7FFF7E230000)

    def test_cli_parses_memory_budget(self):
        args = build_parser().parse_args([
            "scan-live-matches", "--pid", "7004", "--base", "0x7FFF7E230000",
            "--dll", "C:/game/game_plugin.dll", "--scan-mib", "256",
        ])
        self.assertEqual(args.scan_mib, 256)
        self.assertEqual(args.base, 0x7FFF7E230000)


if __name__ == "__main__":
    unittest.main()
