import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fm_match_sim.cli import build_parser, main
from fm_match_sim.match_objects import MATCH_VTABLE_RVA
from fm_match_sim.snapshots import (
    FIELD_LAYOUT, diff_snapshots, parse_scan, snapshot_candidate, snapshot_live,
)


BASE = 0x7FFF7E230000
ADDRESS = 0x1AC97798DA0
VTABLE = BASE + MATCH_VTABLE_RVA


def fixture_scan(addresses=None):
    addresses = [ADDRESS] if addresses is None else addresses
    return {
        "pid": 7004,
        "module_base": f"0x{BASE:X}",
        "read_only": True,
        "match_vtable_rva": f"0x{MATCH_VTABLE_RVA:X}",
        "match_vtable_runtime_address": f"0x{VTABLE:X}",
        "candidate_count": len(addresses),
        "candidate_object_addresses": [f"0x{x:X}" for x in addresses],
    }


def fixture_candidate(clock=123, flags=0):
    memory = {
        ADDRESS: VTABLE.to_bytes(8, "little"),
        ADDRESS + 0x20: (42).to_bytes(4, "little"),
        ADDRESS + 0x15380: (0x12345678).to_bytes(8, "little"),
        ADDRESS + 0x15388: (0x87654321).to_bytes(8, "little"),
        ADDRESS + 0x154EC: clock.to_bytes(4, "little"),
        ADDRESS + 0x15500: flags.to_bytes(4, "little"),
    }

    def read(address, length):
        if address not in memory or len(memory[address]) != length:
            raise OSError(f"unavailable at {address:X}")
        return memory[address]

    return snapshot_candidate(ADDRESS, VTABLE, read)


def fixture_snapshot(candidate):
    return {
        "pid": 7004,
        "module_base": f"0x{BASE:X}",
        "dll_sha256": "knownhash",
        "match_vtable_runtime_address": f"0x{VTABLE:X}",
        "read_only": True,
        "candidates": [candidate],
    }


class SnapshotTests(unittest.TestCase):
    def test_parse_scan_safely_bounded(self):
        self.assertEqual(parse_scan(fixture_scan()), (7004, BASE, [ADDRESS]))
        with self.assertRaisesRegex(ValueError, "1-64"):
            parse_scan(fixture_scan([]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_scan(fixture_scan([ADDRESS, ADDRESS]))
        with self.assertRaisesRegex(ValueError, "vtable"):
            wrong = fixture_scan()
            wrong["match_vtable_runtime_address"] = "0x99"
            parse_scan(wrong)
        with self.assertRaisesRegex(ValueError, "not aligned"):
            parse_scan(fixture_scan([ADDRESS + 1]))

    def test_candidate_fields_and_bit(self):
        result = fixture_candidate(clock=999, flags=4)
        self.assertTrue(result["vtable_matches"])
        self.assertEqual(result["fields"]["seed_u32_candidate"], 42)
        self.assertEqual(result["fields"]["clock_u32_candidate"], 999)
        self.assertEqual(result["fields"]["home_team_ptr_candidate"], "0x12345678")
        self.assertTrue(result["fields"]["finished_bit2_candidate"])

    def test_vtable_mismatch_prevents_other_reads(self):
        seen = []

        def reader(address, length):
            seen.append((address, length))
            return b"\x00" * length

        result = snapshot_candidate(ADDRESS, VTABLE, reader)
        self.assertFalse(result["vtable_matches"])
        self.assertEqual(result["fields"], {})
        self.assertEqual(seen, [(ADDRESS, 8)])

    def test_individual_failed_field_is_reported(self):
        def reader(address, length):
            if address == ADDRESS:
                return VTABLE.to_bytes(8, "little")
            raise OSError("not readable")

        result = snapshot_candidate(ADDRESS, VTABLE, reader)
        self.assertEqual(len(result["read_errors"]), len(FIELD_LAYOUT))
        self.assertIsNone(result["fields"]["finished_bit2_candidate"])

    def test_diff_identifies_candidate_clock_change(self):
        before = fixture_snapshot(fixture_candidate(clock=100))
        after = fixture_snapshot(fixture_candidate(clock=200))
        report = diff_snapshots(before, after)
        self.assertEqual(report["candidate_count"], 1)
        self.assertEqual(report["candidates_with_changes"], 1)
        self.assertEqual(
            report["changes"][0]["changed_fields"]["clock_u32_candidate"],
            {"before": 100, "after": 200},
        )
        self.assertNotIn("seed_u32_candidate", report["changes"][0]["changed_fields"])

    def test_diff_rejects_different_process(self):
        before = fixture_snapshot(fixture_candidate())
        after = fixture_snapshot(fixture_candidate())
        after["pid"] = 17
        with self.assertRaisesRegex(ValueError, "pid"):
            diff_snapshots(before, after)

    def test_parser_and_offline_diff_cli(self):
        parser = build_parser()
        args = parser.parse_args([
            "snapshot-matches", "--from-scan", "match-objects-remainder.json",
            "--dll", "C:/game_plugin.dll", "--out", "snapshot-1.json",
        ])
        self.assertEqual(args.from_scan, "match-objects-remainder.json")
        with tempfile.TemporaryDirectory() as folder:
            a = Path(folder) / "snap-1.json"
            b = Path(folder) / "snap-2.json"
            report = Path(folder) / "diff.json"
            a.write_text(json.dumps(fixture_snapshot(fixture_candidate(10))), encoding="utf-8")
            b.write_text(json.dumps(fixture_snapshot(fixture_candidate(11))), encoding="utf-8")
            with mock.patch("builtins.print"):
                status = main([
                    "diff-match-snapshots", "--first", str(a),
                    "--second", str(b), "--out", str(report),
                ])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(report.read_text())["candidates_with_changes"], 1)

    @mock.patch("fm_match_sim.snapshots.sys.platform", "linux")
    def test_live_snapshots_require_windows(self):
        with self.assertRaisesRegex(OSError, "Windows"):
            snapshot_live(Path("unused.dll"), Path("scan.json"))


if __name__ == "__main__":
    unittest.main()
