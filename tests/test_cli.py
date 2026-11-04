import contextlib
import csv
import io
import json
import tempfile
from pathlib import Path
import unittest

from fm_match_sim.cli import main


class CliTests(unittest.TestCase):
    def test_plan_and_compare_smoke(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            a, b = root / "a.fmf", root / "b.fmf"
            a.write_bytes(b"a")
            b.write_bytes(b"b")
            plan = root / "plan.csv"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "plan", "--fixture-id", "fixture-one",
                    "--tactic-a", str(a), "--tactic-b", str(b),
                    "--seeds", "1-3", "--out", str(plan),
                ])
            self.assertEqual(status, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["planned_runs"], 6)
            self.assertIn("do not prove", payload["warning"])
            with plan.open(newline="", encoding="utf-8") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 6)

            original = root / "original.csv"
            variant = root / "variant.csv"
            original.write_text("seed,home_goals,away_goals\n1,1,1\n2,0,0\n", encoding="utf-8")
            variant.write_text("seed,home_goals,away_goals\n1,2,1\n2,1,0\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["compare", "--original", str(original),
                               "--variant", str(variant)])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["paired_seeds"], 2)

    def test_invalid_file_returns_error(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = main(["inspect", "--dll", "/a/non-existent/file.dll"])
        self.assertEqual(status, 2)
        self.assertIn("error:", error.getvalue())


if __name__ == "__main__":
    unittest.main()
