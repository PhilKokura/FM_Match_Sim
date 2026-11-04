import csv
import tempfile
from pathlib import Path
import unittest

from fm_match_sim.seeds import parse_seeds, write_plan


class SeedTests(unittest.TestCase):
    def test_ranges_sorted_and_deduplicated(self):
        self.assertEqual(parse_seeds("5,1-3,2,5"), [1, 2, 3, 5])

    def test_rejects_bad_inputs(self):
        for expression in ("", "1-", "4-3", "1,,2", "-3", "1-100001", "4294967296"):
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    parse_seeds(expression)

    def test_plan_writes_two_variants_per_seed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            a, b, out = root / "a.fmf", root / "b.fmf", root / "plan.csv"
            a.write_bytes(b"a")
            b.write_bytes(b"b")
            self.assertEqual(write_plan(out, "fixture", a, b, [1, 3]), 4)
            with out.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([(row["seed"], row["variant"]) for row in rows],
                             [("1", "A"), ("1", "B"), ("3", "A"), ("3", "B")])
            self.assertNotEqual(rows[0]["tactic_sha256"], rows[1]["tactic_sha256"])

    def test_plan_rejects_identical_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            a, b, out = root / "a.fmf", root / "b.fmf", root / "plan.csv"
            a.write_bytes(b"same")
            b.write_bytes(b"same")
            with self.assertRaisesRegex(ValueError, "identical"):
                write_plan(out, "fixture", a, b, [1])


if __name__ == "__main__":
    unittest.main()
