"""Command-line interface for the *offline* FM27 research foundation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .benchmark import compare, read_results, verify_repeat
from .pe import inspect
from .seeds import parse_seeds, write_plan


def _emit(data: dict, out: str | None = None) -> None:
    encoded = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    if out:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fm-match-sim",
        description="FM27 research tools (no live match engine connection yet)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("inspect", help="read-only inspection of an installed game_plugin.dll")
    pe.add_argument("--dll", required=True, help="path to an installed game_plugin.dll")
    pe.add_argument("--no-hash", action="store_true", help="skip SHA-256 of the large binary")
    pe.add_argument("--out", help="optional JSON output path")

    plan = sub.add_parser("plan", help="create A/B paired-seed execution plan; does not simulate")
    plan.add_argument("--fixture-id", required=True, help="stable identifier for one controlled fixture")
    plan.add_argument("--tactic-a", required=True, help="original FMF file")
    plan.add_argument("--tactic-b", required=True, help="variant FMF file")
    plan.add_argument("--seeds", default="1-100", help="e.g. 1-1000,2000")
    plan.add_argument("--out", required=True, help="destination CSV")

    comp = sub.add_parser("compare", help="compare CSV results from two external simulations")
    comp.add_argument("--original", required=True, help="CSV results of tactic A")
    comp.add_argument("--variant", required=True, help="CSV results of tactic B")
    comp.add_argument("--out", help="optional JSON output path")

    repeat = sub.add_parser("verify-repeat", help="compare two identical-input runs")
    repeat.add_argument("--first", required=True, help="first CSV")
    repeat.add_argument("--second", required=True, help="second CSV")
    repeat.add_argument("--out", help="optional JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            _emit(inspect(Path(args.dll), hash_file=not args.no_hash), args.out)
        elif args.command == "plan":
            seeds = parse_seeds(args.seeds)
            runs = write_plan(
                Path(args.out), args.fixture_id, Path(args.tactic_a), Path(args.tactic_b), seeds
            )
            _emit({"plan": args.out, "paired_seeds": len(seeds), "planned_runs": runs,
                   "status": "not executed; requires a separately validated FM27 engine adapter"})
        elif args.command == "compare":
            _emit(compare(read_results(Path(args.original)), read_results(Path(args.variant))), args.out)
        elif args.command == "verify-repeat":
            report = verify_repeat(read_results(Path(args.first)), read_results(Path(args.second)))
            _emit(report, args.out)
            return 1 if report["different"] or report["unmatched_first"] or report["unmatched_second"] else 0
    except (OSError, ValueError, OverflowError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
