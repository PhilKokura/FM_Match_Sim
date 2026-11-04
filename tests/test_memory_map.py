import unittest
from unittest import mock
from pathlib import Path

from fm_match_sim.cli import build_parser
from fm_match_sim.memory_map import map_live_memory, summarize_regions

MIB = 1024 * 1024
GIB = 1024 * MIB
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000


class MemoryMapTests(unittest.TestCase):
    def test_eligible_private_and_excluded_regions(self):
        rows = [
            (0x100000, 1 * GIB, MEM_COMMIT, 0x04, MEM_PRIVATE),
            (0x500000000, 2 * GIB, MEM_COMMIT, 0x04, MEM_PRIVATE),
            (0x900000000, 3 * MIB, MEM_COMMIT, 0x02, MEM_IMAGE),
            (0xA00000000, 4 * MIB, MEM_COMMIT, 0x04, MEM_MAPPED),
            (0xB00000000, 5 * MIB, MEM_COMMIT, 0x104, MEM_PRIVATE),
        ]
        result = summarize_regions(rows)
        self.assertEqual(result["readable_committed_private_mib"], 3072.0)
        self.assertEqual(result["eligible_mib_beyond_first_2gib"], 1024.0)
        self.assertEqual(result["eligible_regions_encountered_at_2gib_cap"], 2)
        self.assertEqual(result["readable_committed_private_region_count"], 2)
        self.assertEqual(result["largest_readable_private_regions"][0]["mib"], 2048.0)
        self.assertEqual(result["committed_by_type"]["mapped"]["mib"], 4.0)
        self.assertEqual(result["committed_by_type"]["image"]["mib"], 3.0)

    def test_empty_map(self):
        result = summarize_regions([])
        self.assertEqual(result["readable_committed_private_region_count"], 0)
        self.assertEqual(result["regions_enumerated"], 0)
        self.assertEqual(result["eligible_mib_beyond_first_2gib"], 0)

    def test_invalid_top_rejected(self):
        with self.assertRaisesRegex(ValueError, "top"):
            summarize_regions([], top=31)

    def test_parser_accepts_command(self):
        args = build_parser().parse_args([
            "map-live", "--pid", "7004", "--base", "0x7FFF7E230000",
            "--dll", "C:/game/game_plugin.dll", "--top", "8",
        ])
        self.assertEqual(args.pid, 7004)
        self.assertEqual(args.top, 8)

    @mock.patch("fm_match_sim.memory_map.sys.platform", "linux")
    def test_not_supported_on_non_windows(self):
        with self.assertRaisesRegex(OSError, "Windows"):
            map_live_memory(Path("unused.dll"), pid=7004, module_base=0x7FFF7E230000)


if __name__ == "__main__":
    unittest.main()
