"""Command-line interface for the *offline* FM27 research foundation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .benchmark import compare, read_results, verify_repeat
from .live import probe_live
from .match_objects import scan_live_matches
from .memory_map import map_live_memory
from .pe import inspect
from .seeds import parse_seeds, write_plan
from .score_probe import analyze_score_change, capture_live_score_data
from .snapshots import diff_snapshots, snapshot_live


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

    live = sub.add_parser("probe-live", help="read-only runtime signature check (Windows)")
    live.add_argument("--pid", type=int, required=True, help="PID of the running fm.exe")
    live.add_argument("--base", type=lambda raw: int(raw, 0), required=True,
                      help="loaded game_plugin.dll module base, e.g. 0x7FFF7E230000")
    live.add_argument("--dll", required=True, help="path to the installed DLL")
    live.add_argument("--out", help="optional JSON output path")

    memory_map = sub.add_parser("map-live",
        help="read-only inventory of process memory regions (no memory-content scanning)")
    memory_map.add_argument("--pid", type=int, required=True)
    memory_map.add_argument("--base", type=lambda raw: int(raw, 0), required=True)
    memory_map.add_argument("--dll", required=True)
    memory_map.add_argument("--top", type=int, default=12,
                            help="number of largest readable private regions, 1-30")
    memory_map.add_argument("--out", help="optional JSON output path")

    scan = sub.add_parser("scan-live-matches",
                          help="bounded read-only scan for candidate GAME_MATCH objects (Windows)")
    scan.add_argument("--pid", type=int, required=True)
    scan.add_argument("--base", type=lambda raw: int(raw, 0), required=True)
    scan.add_argument("--dll", required=True)
    scan.add_argument("--scan-mib", type=int, default=512,
                      help="maximum private memory attempted, 1-8192 MiB (default: 512)")
    scan.add_argument("--skip-mib", type=int, default=0,
                      help="eligible private memory to skip before scanning, 0-8192 MiB")
    scan.add_argument("--max-seconds", type=int, default=25)
    scan.add_argument("--out", help="optional JSON output path")

    snap = sub.add_parser("snapshot-matches",
                          help="read only selected match-object candidates from scan JSON")
    snap.add_argument("--from-scan", required=True, help="JSON from scan-live-matches")
    snap.add_argument("--dll", required=True, help="installed game_plugin.dll")
    snap.add_argument("--out", required=True, help="JSON snapshot output path")

    diff = sub.add_parser("diff-match-snapshots",
                          help="compare two offline candidate snapshots")
    diff.add_argument("--first", required=True, help="JSON snapshot before")
    diff.add_argument("--second", required=True, help="JSON snapshot after")
    diff.add_argument("--out", help="optional diff JSON path")

    score = sub.add_parser("capture-score-data",
        help="bounded read-only capture of candidate match/team memory windows")
    score.add_argument("--from-scan", required=True, help="JSON from scan-live-matches")
    score.add_argument("--dll", required=True, help="path to installed game_plugin.dll")
    score.add_argument("--home", type=int, required=True, help="visible home goals")
    score.add_argument("--away", type=int, required=True, help="visible away goals")
    score.add_argument("--tag", required=True, help="label e.g. baseline or first_goal")
    score.add_argument("--include-idle", action="store_true",
                       help="include clock=0 match candidates")
    score.add_argument("--out", required=True,
                       help="private capture JSON; keep within ignored captures/ folder")

    score_analysis = sub.add_parser("analyze-score-change",
        help="offline possible integer score fields from two manual-score captures")
    score_analysis.add_argument("--before", required=True)
    score_analysis.add_argument("--after", required=True)
    score_analysis.add_argument("--out", help="optional small JSON report")

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
        elif args.command == "probe-live":
            report = probe_live(Path(args.dll), pid=args.pid, module_base=args.base)
            _emit(report, args.out)
            return 0 if report["all_signatures_match"] else 1
        elif args.command == "map-live":
            _emit(map_live_memory(Path(args.dll), pid=args.pid,
                                  module_base=args.base, top=args.top), args.out)
        elif args.command == "scan-live-matches":
            _emit(scan_live_matches(Path(args.dll), pid=args.pid,
                                    module_base=args.base,
                                    max_scan_mib=args.scan_mib,
                                    max_seconds=args.max_seconds,
                                    skip_mib=args.skip_mib), args.out)
        elif args.command == "snapshot-matches":
            _emit(snapshot_live(Path(args.dll), Path(args.from_scan)), args.out)
        elif args.command == "diff-match-snapshots":
            before = json.loads(Path(args.first).read_text(encoding="utf-8-sig"))
            after = json.loads(Path(args.second).read_text(encoding="utf-8-sig"))
            _emit(diff_snapshots(before, after), args.out)
        elif args.command == "capture-score-data":
            data = capture_live_score_data(Path(args.dll), Path(args.from_scan),
                                           home_goals=args.home, away_goals=args.away,
                                           tag=args.tag, include_idle=args.include_idle)
            path = Path(args.out)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            _emit({"written": str(path), "tag": args.tag,
                   "visible_score": data["visible_score"],
                   "captured_objects": len(data["matches"]),
                   "captured_windows": sum(
                       sum("data" in window for window in item["windows"].values())
                       for item in data["matches"]),
                   "read_only": True,
                   "warning": "This file includes raw game process memory. Keep it private."})
        elif args.command == "analyze-score-change":
            before = json.loads(Path(args.before).read_text(encoding="utf-8-sig"))
            after = json.loads(Path(args.after).read_text(encoding="utf-8-sig"))
            _emit(analyze_score_change(before, after), args.out)
        elif args.command == "plan":
            seeds = parse_seeds(args.seeds)
            runs = write_plan(
                Path(args.out), args.fixture_id, Path(args.tactic_a), Path(args.tactic_b), seeds
            )
            _emit({"plan": args.out, "paired_seeds": len(seeds), "planned_runs": runs,
                   "status": "not executed; requires a separately validated FM27 engine adapter",
                   "warning": "different FMF file hashes do not prove different tactic settings"})
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
