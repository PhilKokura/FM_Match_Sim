import ctypes
from pathlib import Path
import unittest
from unittest import mock

from fm_match_sim.cli import build_parser
from fm_match_sim.match_objects import (
    MATCH_VTABLE_RVA,
    _region_window,
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

    def test_resume_offsets_cover_previous_scan_boundary(self):
        mib = 1024 * 1024
        # First 2 GiB of eligible allocations are skipped. A region spanning
        # that boundary must start reading at the correct byte, not at its base.
        skip = 2048 * mib
        spent = 0
        for region_size in (128 * mib, 1792 * mib, 512 * mib):
            region_skip, region_read = _region_window(
                region_size, skip, 6144 * mib - spent
            )
            skip -= region_skip
            spent += region_read
        self.assertEqual(skip, 0)
        self.assertEqual(spent, 384 * mib)
        self.assertEqual(_region_window(100, 30, 40), (30, 40))
        self.assertEqual(_region_window(100, 100, 40), (100, 0))
        self.assertEqual(_region_window(100, 0, 0), (0, 0))
        with self.assertRaises(ValueError):
            _region_window(100, -1, 50)

    def test_cli_can_skip_already_inspected_memory(self):
        args = build_parser().parse_args([
            "scan-live-matches", "--pid", "7004", "--base", "0x7FFF7E230000",
            "--dll", "C:/game/game_plugin.dll", "--skip-mib", "2048",
            "--scan-mib", "6144", "--max-seconds", "120",
        ])
        self.assertEqual(args.skip_mib, 2048)
        self.assertEqual(args.scan_mib, 6144)
        self.assertEqual(args.max_seconds, 120)

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
