"""Deterministic benchmark planning; this module does not run FM27."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path


MAX_SEEDS = 100_000
MAX_SEED_VALUE = 2**32 - 1


def parse_seeds(expression: str) -> list[int]:
    """Parse comma-separated numbers/ranges such as '1-100,200'."""
    if not expression or not expression.strip():
        raise ValueError("seed expression is empty")
    values: set[int] = set()
    for part in expression.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty seed item")
        if "-" in part:
            items = part.split("-")
            if len(items) != 2 or not all(v.isdecimal() for v in items):
                raise ValueError(f"invalid seed range: {part!r}")
            start, end = map(int, items)
            if start > end:
                raise ValueError(f"reversed seed range: {part!r}")
            if end - start + 1 > MAX_SEEDS:
                raise ValueError("seed range exceeds the 100,000-seed safety limit")
            values.update(range(start, end + 1))
        else:
            if not part.isdecimal():
                raise ValueError(f"invalid seed: {part!r}")
            values.add(int(part))
        if len(values) > MAX_SEEDS:
            raise ValueError("too many seeds (maximum 100,000)")
    if min(values) < 0 or max(values) > MAX_SEED_VALUE:
        raise ValueError("seeds must be unsigned 32-bit integers")
    return sorted(values)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_plan(
    destination: Path,
    fixture_id: str,
    tactic_a: Path,
    tactic_b: Path,
    seeds: list[int],
) -> int:
    if not fixture_id.strip():
        raise ValueError("fixture id must not be empty")
    if not seeds:
        raise ValueError("at least one seed is required")
    if not tactic_a.is_file() or not tactic_b.is_file():
        raise ValueError("both tactic files must exist")
    hashes = {"A": sha256_file(tactic_a), "B": sha256_file(tactic_b)}
    if hashes["A"] == hashes["B"]:
        raise ValueError("tactic files have identical SHA-256 hashes")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["fixture_id", "seed", "variant", "tactic_sha256", "tactic_file"])
        for seed in seeds:
            for variant, tactic in (("A", tactic_a), ("B", tactic_b)):
                writer.writerow([fixture_id, seed, variant, hashes[variant], str(tactic)])
    return len(seeds) * 2
