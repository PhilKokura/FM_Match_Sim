"""Paired comparisons of results *produced elsewhere* by a match runner."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import math
from pathlib import Path
import statistics


@dataclass(frozen=True)
class MatchResult:
    seed: int
    home_goals: int
    away_goals: int
    home_xg: float | None = None
    away_xg: float | None = None
    finished: bool = True

    @property
    def goal_difference(self) -> int:
        return self.home_goals - self.away_goals

    @property
    def points(self) -> int:
        return 3 if self.goal_difference > 0 else (1 if self.goal_difference == 0 else 0)

    @property
    def xg_difference(self) -> float | None:
        if self.home_xg is None or self.away_xg is None:
            return None
        return self.home_xg - self.away_xg


def _nonnegative_int(value: str, field: str) -> int:
    try:
        parsed = int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid {field}: {value!r}") from exc
    if parsed < 0:
        raise ValueError(f"{field} must be non-negative")
    return parsed


def _optional_float(value: str | None, field: str) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field}: {value!r}") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return parsed


def _finished(value: str | None) -> bool:
    if value is None or not value.strip():
        return True
    code = value.strip().lower()
    if code in ("1", "true", "yes"):
        return True
    if code in ("0", "false", "no"):
        return False
    raise ValueError(f"invalid finished value: {value!r}")


def read_results(path: Path) -> dict[int, MatchResult]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        required = {"seed", "home_goals", "away_goals"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"{path}: required columns: seed,home_goals,away_goals")
        results: dict[int, MatchResult] = {}
        for line_number, row in enumerate(reader, start=2):
            try:
                seed = _nonnegative_int(row["seed"], "seed")
                if seed > 2**32 - 1:
                    raise ValueError("seed exceeds uint32")
                if seed in results:
                    raise ValueError(f"duplicate seed {seed}")
                result = MatchResult(
                    seed=seed,
                    home_goals=_nonnegative_int(row["home_goals"], "home_goals"),
                    away_goals=_nonnegative_int(row["away_goals"], "away_goals"),
                    home_xg=_optional_float(row.get("home_xg"), "home_xg"),
                    away_xg=_optional_float(row.get("away_xg"), "away_xg"),
                    finished=_finished(row.get("finished")),
                )
                if not result.finished:
                    raise ValueError(f"seed {seed} has unfinished match")
                if (result.home_xg is None) != (result.away_xg is None):
                    raise ValueError("home_xg and away_xg must both be present or absent")
                results[seed] = result
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    if not results:
        raise ValueError(f"{path}: no match results")
    return results


def _paired_stats(differences: list[float]) -> dict[str, float | int | None]:
    """Exploratory normal-approximation interval; not a formal small-sample test."""
    count = len(differences)
    mean = statistics.mean(differences)
    if count < 2:
        return {"n": count, "mean_delta": mean, "standard_error": None, "ci95_low": None, "ci95_high": None}
    se = statistics.stdev(differences) / math.sqrt(count)
    if count < 30:
        return {"n": count, "mean_delta": mean, "standard_error": se, "ci95_low": None, "ci95_high": None}
    return {"n": count, "mean_delta": mean, "standard_error": se, "ci95_low": mean - 1.96 * se, "ci95_high": mean + 1.96 * se}


def compare(original: dict[int, MatchResult], variant: dict[int, MatchResult]) -> dict:
    """Variant B minus original A from the same home-team perspective."""
    common = sorted(original.keys() & variant.keys())
    if not common:
        raise ValueError("no common seeds")
    measures = {
        "goal_difference": lambda r: float(r.goal_difference),
        "home_goals": lambda r: float(r.home_goals),
        "away_goals": lambda r: float(r.away_goals),
        "points": lambda r: float(r.points),
    }
    result = {
        "perspective": "home team; delta = variant B minus original A",
        "paired_seeds": len(common),
        "unmatched_original": len(original) - len(common),
        "unmatched_variant": len(variant) - len(common),
        "metrics": {},
    }
    for name, measure in measures.items():
        result["metrics"][name] = _paired_stats([measure(variant[s]) - measure(original[s]) for s in common])
    xg_seeds = [
        seed for seed in common
        if original[seed].xg_difference is not None and variant[seed].xg_difference is not None
    ]
    if xg_seeds:
        result["metrics"]["xg_difference"] = _paired_stats([
            float(variant[s].xg_difference - original[s].xg_difference) for s in xg_seeds
        ])
    result["warnings"] = []
    if len(common) < 30:
        result["warnings"].append("Fewer than 30 paired seeds: no 95% interval is reported.")
    if len(common) != len(original) or len(common) != len(variant):
        result["warnings"].append("Seed sets differ; comparison uses only their intersection.")
    if xg_seeds and len(xg_seeds) < len(common):
        result["warnings"].append("xG available for only a subset of paired seeds.")
    result["warnings"].append(
        "Same seeds do not guarantee equivalent random events across different tactics; "
        "interpret intervals as exploratory and validate on independent fixtures."
    )
    return result


def verify_repeat(first: dict[int, MatchResult], second: dict[int, MatchResult]) -> dict:
    """Check result-level reproducibility for an unchanged tactic and fixture."""
    common = sorted(first.keys() & second.keys())
    if not common:
        raise ValueError("no common seeds")
    different = [seed for seed in common if first[seed] != second[seed]]
    return {
        "paired_seeds": len(common),
        "identical": len(common) - len(different),
        "different": len(different),
        "differing_seeds": different[:100],
        "unmatched_first": len(first) - len(common),
        "unmatched_second": len(second) - len(common),
        "caveat": "Matching final statistics do not prove the underlying match paths or RNG states were identical.",
    }
