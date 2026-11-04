import csv
import tempfile
from pathlib import Path
import unittest

from fm_match_sim.benchmark import MatchResult, compare, read_results, verify_repeat


class BenchmarkTests(unittest.TestCase):
    def test_paired_comparison_and_confidence_interval(self):
        a = {i: MatchResult(i, 1, 1, 0.9, 0.8) for i in range(1, 31)}
        b = {i: MatchResult(i, 2, 1, 1.2, 0.8) for i in range(1, 31)}
        report = compare(a, b)
        self.assertEqual(report["paired_seeds"], 30)
        self.assertEqual(report["metrics"]["goal_difference"]["mean_delta"], 1.0)
        self.assertEqual(report["metrics"]["points"]["mean_delta"], 2.0)
        self.assertAlmostEqual(report["metrics"]["xg_difference"]["mean_delta"], 0.3)
        self.assertEqual(report["metrics"]["goal_difference"]["ci95_low"], 1.0)

    def test_small_sample_no_false_precision(self):
        a = {1: MatchResult(1, 1, 1)}
        b = {1: MatchResult(1, 2, 1)}
        report = compare(a, b)
        self.assertIsNone(report["metrics"]["goal_difference"]["ci95_low"])
        self.assertIn("Fewer than 30", report["warnings"][0])

    def test_disjoint_seeds_rejected(self):
        with self.assertRaisesRegex(ValueError, "no common"):
            compare({1: MatchResult(1, 1, 0)}, {2: MatchResult(2, 1, 0)})

    def test_repeat_detects_difference(self):
        a = {1: MatchResult(1, 1, 1), 2: MatchResult(2, 2, 0)}
        b = {1: MatchResult(1, 1, 1), 2: MatchResult(2, 1, 0)}
        report = verify_repeat(a, b)
        self.assertEqual(report["different"], 1)
        self.assertEqual(report["differing_seeds"], [2])

    def test_csv_validates_duplicates_and_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "results.csv"
            with p.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["seed", "home_goals", "away_goals", "finished"])
                writer.writerow([7, 2, 1, 1])
                writer.writerow([7, 2, 1, 1])
            with self.assertRaisesRegex(ValueError, "duplicate seed"):
                read_results(p)
            p.write_text("seed,home_goals,away_goals,finished\n7,2,1,0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unfinished"):
                read_results(p)

    def test_csv_optional_xg_and_bom(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "results.csv"
            p.write_text("seed,home_goals,away_goals,home_xg,away_xg\n5,2,1,1.2,0.6\n",
                         encoding="utf-8-sig")
            row = read_results(p)[5]
            self.assertAlmostEqual(row.xg_difference, 0.6)


if __name__ == "__main__":
    unittest.main()
