import base64
import json
from pathlib import Path
import unittest
from unittest import mock
import zlib

from fm_match_sim.cli import build_parser, main
from fm_match_sim.match_objects import MATCH_VTABLE_RVA
from fm_match_sim.score_probe import (
    _pack, _unpack, _score_transitions,
    analyze_score_change, capture_one_match, capture_live_score_data,
)


BASE = 0x7FFF7E230000
MATCH = 0x1ACCBD6B610
HOME = 0x1AC92960F00
AWAY = 0x1AC92961640
VTABLE = BASE + MATCH_VTABLE_RVA


def fake_process(home_goals: int, away_goals: int, match_tick: int = 1000):
    """Simulate a fixed heap with separate match, home and away structures."""
    match_data = bytearray(0x16000)
    home_data = bytearray(0x2000)
    away_data = bytearray(0x2000)
    match_data[0:8] = VTABLE.to_bytes(8, "little")
    match_data[0x20:0x24] = (123456).to_bytes(4, "little")
    match_data[0x15380:0x15388] = HOME.to_bytes(8, "little")
    match_data[0x15388:0x15390] = AWAY.to_bytes(8, "little")
    match_data[0x154EC:0x154F0] = match_tick.to_bytes(4, "little")
    match_data[0x400:0x404] = home_goals.to_bytes(4, "little")
    # Deliberate confounder: a non-score counter changed too.
    match_data[0x500:0x504] = home_goals.to_bytes(4, "little")
    home_data[0x100:0x104] = home_goals.to_bytes(4, "little")
    away_data[0x120:0x124] = away_goals.to_bytes(4, "little")
    memory = {MATCH: match_data, HOME: home_data, AWAY: away_data}

    def read(address, size):
        for start, data in memory.items():
            if start <= address and address + size <= start + len(data):
                return bytes(data[address - start:address - start + size])
        raise OSError(f"memory unavailable at {address:X}")

    return read


def score_capture(home, away, tick=1000):
    match = capture_one_match(MATCH, VTABLE, fake_process(home, away, tick))
    return {
        "schema_version": 1, "pid": 7004,
        "module_base": f"0x{BASE:X}",
        "dll_sha256": "test_sha",
        "match_vtable_runtime_address": f"0x{VTABLE:X}",
        "visible_score": {"home": home, "away": away},
        "tag": f"{home}-{away}",
        "read_only": True,
        "matches": [match],
    }


class ScoreProbeTests(unittest.TestCase):
    def test_pack_unpack_checksum(self):
        data = bytes(range(256)) * 16
        payload = _pack(data)
        self.assertEqual(_unpack(payload), data)
        payload["sha256"] = "bad"
        with self.assertRaisesRegex(ValueError, "checksum"):
            _unpack(payload)

    def test_decompression_rejects_invalid_length_and_trailing_data(self):
        payload = _pack(b"abcd")
        payload["byte_length"] = 999999
        with self.assertRaisesRegex(ValueError, "size"):
            _unpack(payload)
        payload = _pack(b"abcd")
        compressed = zlib.compress(b"abcd") + b"suffix"
        payload["data"] = base64.b64encode(compressed).decode("ascii")
        with self.assertRaisesRegex(ValueError, "compressed"):
            _unpack(payload)

    def test_capture_one_match_only_reads_selected_windows(self):
        result = capture_one_match(MATCH, VTABLE, fake_process(0, 0))
        self.assertTrue(result["vtable_matches"])
        self.assertIn("match_tail", result["windows"])
        self.assertIn("home_team", result["windows"])
        self.assertEqual(_unpack(result["windows"]["home_team"])[0x100:0x104], b"\0"*4)
        self.assertEqual(_unpack(result["windows"]["match_tail"])[0x5380:0x5388],
                         HOME.to_bytes(8, "little"))

    def test_missing_vtable_prevents_all_followup_reads(self):
        calls = []

        def read(addr, size):
            calls.append((addr, size))
            return b"\0" * size

        result = capture_one_match(MATCH, VTABLE, read)
        self.assertFalse(result["vtable_matches"])
        self.assertEqual(calls, [(MATCH, 8)])
        self.assertEqual(result["windows"], {})

    def test_exact_visible_home_goal_transition_has_multiple_hypotheses(self):
        before = score_capture(0, 0, tick=1000)
        after = score_capture(1, 0, tick=1100)
        report = analyze_score_change(before, after)
        self.assertEqual(report["match_objects_compared"], 1)
        options = report["candidates"]
        self.assertTrue(any(
            c["window"] == "home_team"
            and c["relative_offset"] == "0x100"
            and c["width_bytes"] == 4
            for c in options
        ))
        self.assertTrue(any(
            c["window"] == "match_head" and c["relative_offset"] == "0x400"
            for c in options
        ))
        self.assertGreater(report["candidate_integer_locations"], 1)
        self.assertIn("UNVERIFIED", report["caveat"])

    def test_no_goal_is_not_a_score_transition(self):
        with self.assertRaisesRegex(ValueError, "did not change"):
            analyze_score_change(score_capture(0, 0), score_capture(0, 0, tick=2000))

    def test_changed_process_or_team_pointer_rejected(self):
        before = score_capture(0, 0)
        after = score_capture(1, 0)
        after["pid"] = 7005
        with self.assertRaisesRegex(ValueError, "pid"):
            analyze_score_change(before, after)
        after["pid"] = 7004
        after["matches"][0]["fields"]["home_team_ptr_candidate"] = "0x12345678"
        report = analyze_score_change(before, after)
        self.assertEqual(report["match_objects_compared"], 0)
        self.assertTrue(report["skipped_objects"])

    def test_integer_candidates_enforce_alignment(self):
        before = bytearray(16)
        after = bytearray(16)
        before[0:4] = (0).to_bytes(4, "little")
        after[0:4] = (1).to_bytes(4, "little")
        changes = _score_transitions(before, after, 0, 1)
        self.assertTrue(any(c["width_bytes"] == 4 and c["offset"] == "0x0"
                            for c in changes))
        with self.assertRaisesRegex(ValueError, "length"):
            _score_transitions(b"\0", b"", 0, 1)

    def test_cli_options_and_offline_report(self):
        args = build_parser().parse_args([
            "capture-score-data", "--from-scan", "captures/scan.json",
            "--dll", "C:/game_plugin.dll", "--home", "0", "--away", "0",
            "--tag", "kickoff", "--out", "captures/0-0.json",
        ])
        self.assertEqual(args.home, 0)
        self.assertEqual(args.tag, "kickoff")
        with mock.patch("builtins.print"):
            with mock.patch("fm_match_sim.cli.json.loads", wraps=json.loads):
                pass
        with mock.patch("builtins.print"):
            import tempfile
            with tempfile.TemporaryDirectory() as folder:
                a, b = Path(folder) / "a.json", Path(folder) / "b.json"
                output = Path(folder) / "result.json"
                a.write_text(json.dumps(score_capture(0, 0)), encoding="utf-8")
                b.write_text(json.dumps(score_capture(1, 0)), encoding="utf-8")
                self.assertEqual(main([
                    "analyze-score-change", "--before", str(a),
                    "--after", str(b), "--out", str(output)
                ]), 0)
                self.assertGreater(json.loads(output.read_text())["candidate_integer_locations"], 0)

    @mock.patch("fm_match_sim.score_probe.sys.platform", "linux")
    def test_live_capture_requires_windows(self):
        with self.assertRaisesRegex(OSError, "Windows"):
            capture_live_score_data(Path("unused.dll"), Path("scan.json"),
                                    home_goals=0, away_goals=0, tag="initial")


if __name__ == "__main__":
    unittest.main()
