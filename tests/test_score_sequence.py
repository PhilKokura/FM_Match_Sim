import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fm_match_sim.cli import main
from fm_match_sim.score_probe import _pack
from fm_match_sim.score_sequence import analyze_score_sequence


ADDRESS = "0x1ACC4E06650"


def capture(tag, home, away, *, event_counter=0, address=ADDRESS):
    match_head = bytearray(0x2000)
    match_tail = bytearray(0x5600)
    home_team = bytearray(0x2000)
    away_team = bytearray(0x2000)
    match_tail[0x2BA0:0x2BA4] = home.to_bytes(4, "little")  # 0x12BA0
    match_tail[0x2BA4:0x2BA8] = away.to_bytes(4, "little")
    match_tail[0x2BA8:0x2BAC] = event_counter.to_bytes(4, "little")
    home_team[0x6EC:0x6F0] = home.to_bytes(4, "little")
    away_team[0xE2C:0xE30] = away.to_bytes(4, "little")
    return {
        "schema_version": 1,
        "pid": 7004,
        "module_base": "0x7FFF7E230000",
        "dll_sha256": "testsha",
        "match_vtable_runtime_address": "0x7FFF82EBC878",
        "tag": tag,
        "visible_score": {"home": home, "away": away},
        "read_only": True,
        "matches": [{
            "address": address,
            "vtable_matches": True,
            "fields": {
                "home_team_ptr_candidate": "0x1AC92960F00",
                "away_team_ptr_candidate": "0x1AC92961640",
            },
            "windows": {
                "match_head": _pack(bytes(match_head)),
                "match_tail": _pack(bytes(match_tail)),
                "home_team": _pack(bytes(home_team)),
                "away_team": _pack(bytes(away_team)),
            },
        }],
    }


def fixture():
    return [
        capture("kickoff", 0, 0, event_counter=0),
        capture("first_goal", 0, 1, event_counter=1),
        capture("provisional", 1, 1, event_counter=2),
        capture("reversal", 0, 1, event_counter=3),
        capture("final", 0, 1, event_counter=4),
    ]


class ScoreSequenceTests(unittest.TestCase):
    def test_two_sides_and_rollback_mapped(self):
        report = analyze_score_sequence(fixture())
        self.assertEqual(report["matched_objects_all_captures"], 1)
        self.assertEqual(report["score_changes_observed"], {"home": 2, "away": 1})
        self.assertEqual(report["decoded_windows"], 4)
        self.assertEqual(report["research_offset_0x12BA0"][0]["values"],
                         [0, 0, 1, 0, 0])
        self.assertIn({
            "match_address": ADDRESS,
            "window": "match_tail",
            "relative_offset": "0x12BA0",
            "width_bytes": 4,
            "values": [0, 0, 1, 0, 0],
        }, report["candidates"]["home"])
        self.assertTrue(any(
            candidate["window"] == "away_team"
            and candidate["relative_offset"] == "0xE2C"
            for candidate in report["candidates"]["away"]
        ))
        self.assertFalse(any(
            candidate["relative_offset"] == "0x12BA8"
            for group in report["candidates"].values() for candidate in group
        ))

    def test_rejects_mismatched_provenance(self):
        captures = fixture()
        captures[-1]["pid"] = 1234
        with self.assertRaisesRegex(ValueError, "pid"):
            analyze_score_sequence(captures)

    def test_skips_pointer_changed_match(self):
        captures = fixture()
        captures[-1]["matches"][0]["fields"]["away_team_ptr_candidate"] = "0x12345678"
        report = analyze_score_sequence(captures)
        self.assertEqual(report["decoded_windows"], 0)
        self.assertTrue(report["skipped_objects"])
        self.assertEqual(report["candidate_counts"]["away"], 0)

    def test_rejects_identical_scores(self):
        with self.assertRaisesRegex(ValueError, "identical"):
            analyze_score_sequence([capture("a", 0, 0),
                                    capture("b", 0, 0),
                                    capture("c", 0, 0)])

    def test_rejects_invalid_capture_counts(self):
        with self.assertRaisesRegex(ValueError, "3-12"):
            analyze_score_sequence(fixture()[:2])

    def test_missing_object_in_stage_not_mistaken_for_same_match(self):
        captures = fixture()
        captures[2]["matches"][0]["address"] = "0x12345000"
        report = analyze_score_sequence(captures)
        self.assertEqual(report["matched_objects_all_captures"], 0)
        self.assertEqual(report["candidate_counts"]["home"], 0)

    def test_offline_cli(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = []
            for index, item in enumerate(fixture()):
                path = Path(folder) / f"capture-{index}.json"
                path.write_text(json.dumps(item), encoding="utf-8")
                paths.append(path)
            output = Path(folder) / "sequence-report.json"
            with patch("builtins.print"):
                result = main([
                    "analyze-score-sequence",
                    "--captures", *(str(path) for path in paths),
                    "--out", str(output),
                ])
            self.assertEqual(result, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["candidate_counts"]["home"], 1)


if __name__ == "__main__":
    unittest.main()
