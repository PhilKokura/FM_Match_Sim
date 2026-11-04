"""Offline scoring hypotheses across an ordered sequence of score captures.

All inputs stay local: this module emits only candidate offsets and value
traces, never the underlying process-memory bytes. It cannot prove that an
integer is a real score field, nor identify a native callable game API.
"""

from __future__ import annotations

from collections import Counter

from .score_probe import MAX_SCORE, _unpack

WINDOW_OFFSETS = {
    "match_head": 0,
    "match_tail": 0x10000,
    "home_team": 0,
    "away_team": 0,
}
MAX_CAPTURES = 12
MAX_CANDIDATES_PER_SIDE = 30
KNOWN_RESEARCH_OFFSET = 0x12BA0


def _validate_captures(captures: list[dict]) -> list[dict]:
    if not isinstance(captures, list) or not (3 <= len(captures) <= MAX_CAPTURES):
        raise ValueError("expected 3-12 ordered score captures")
    reference = captures[0]
    required = ("schema_version", "pid", "module_base", "dll_sha256",
                "match_vtable_runtime_address")
    if reference.get("schema_version") != 1:
        raise ValueError("unsupported score capture schema")
    score_series = []
    for index, capture in enumerate(captures):
        for name in required:
            if capture.get(name) != reference.get(name):
                raise ValueError(f"capture {index} differs in {name}")
        if capture.get("read_only") is not True:
            raise ValueError(f"capture {index} is not marked read-only")
        score = capture.get("visible_score")
        if not isinstance(score, dict):
            raise ValueError(f"capture {index} is missing visible_score")
        for side in ("home", "away"):
            value = score.get(side)
            if type(value) is not int or not 0 <= value <= MAX_SCORE:
                raise ValueError(f"capture {index} has invalid {side} goals")
        if not isinstance(capture.get("matches"), list):
            raise ValueError(f"capture {index} is missing matches")
        score_series.append(score)
    if not any(score_series[i] != score_series[0]
               for i in range(1, len(score_series))):
        raise ValueError("all visible scores are identical; no goal transition to analyze")
    return score_series


def _common_match_objects(captures: list[dict]) -> tuple[list[tuple[str, list[dict]]], list[dict]]:
    lookups = []
    for capture in captures:
        records = {}
        for item in capture["matches"]:
            address = item.get("address")
            if not isinstance(address, str) or address in records:
                raise ValueError("invalid or duplicate match object address in capture")
            records[address] = item
        lookups.append(records)
    common = set(lookups[0]).intersection(*(set(x) for x in lookups[1:]))
    included = []
    excluded = []
    for address in sorted(common, key=lambda raw: int(raw, 16)):
        records = [lookup[address] for lookup in lookups]
        if not all(record.get("vtable_matches") is True for record in records):
            excluded.append({"match_address": address, "reason": "vtable mismatch"})
            continue
        pointers = (
            "home_team_ptr_candidate",
            "away_team_ptr_candidate",
        )
        if any(len({record.get("fields", {}).get(ptr) for record in records}) != 1
               or not records[0].get("fields", {}).get(ptr)
               for ptr in pointers):
            excluded.append({"match_address": address, "reason": "team pointers changed"})
            continue
        included.append((address, records))
    return included, excluded


def _decode_windows(records: list[dict], name: str) -> list[bytes] | None:
    windows = [record.get("windows", {}).get(name) for record in records]
    if any(not isinstance(window, dict) or "data" not in window for window in windows):
        return None
    chunks = [_unpack(window) for window in windows]
    if len({len(chunk) for chunk in chunks}) != 1:
        return None
    return chunks


def analyze_score_sequence(captures: list[dict]) -> dict:
    """Find u32 locations that mirror all supplied displayed scores.

    Only *common* match object addresses with unchanged team pointers are
    considered. An exact match is a hypothesis, not validation: counters,
    UI-state fields and correlated events can match the same score series.
    """
    visible = _validate_captures(captures)
    common, excluded = _common_match_objects(captures)
    transitions = {
        side: sum(a[side] != b[side] for a, b in zip(visible, visible[1:]))
        for side in ("home", "away")
    }
    results = {"home": [], "away": []}
    trace = []
    decoded = 0
    for address, records in common:
        for name, origin in WINDOW_OFFSETS.items():
            chunks = _decode_windows(records, name)
            if chunks is None:
                continue
            decoded += 1
            # Keep 32-bit aligned values: the initial first-goal analysis
            # produced hundreds of unrelated 1/2/4-byte false positives.
            for offset in range(0, len(chunks[0]) - 3, 4):
                values = [int.from_bytes(chunk[offset:offset + 4], "little")
                          for chunk in chunks]
                if name == "match_tail" and origin + offset == KNOWN_RESEARCH_OFFSET:
                    trace.append({
                        "match_address": address,
                        "window": name,
                        "relative_offset": f"0x{origin + offset:X}",
                        "values": values,
                        "displayed_home": [score["home"] for score in visible],
                        "displayed_away": [score["away"] for score in visible],
                    })
                for side in ("home", "away"):
                    if not transitions[side]:
                        continue
                    if values == [score[side] for score in visible]:
                        results[side].append({
                            "match_address": address,
                            "window": name,
                            "relative_offset": f"0x{origin + offset:X}",
                            "width_bytes": 4,
                            "values": values,
                        })
    # A side-associated team window is useful as a sorting hint, not proof.
    def priority(side: str, item: dict) -> tuple:
        preferred = item["window"] == f"{side}_team"
        return (not preferred, item["window"] != "match_tail",
                item["match_address"], int(item["relative_offset"], 16))

    for side in results:
        results[side].sort(key=lambda item: priority(side, item))

    return {
        "pid": captures[0]["pid"],
        "captures": [
            {"tag": capture.get("tag"), "visible_score": score}
            for capture, score in zip(captures, visible)
        ],
        "matched_objects_all_captures": len(common),
        "decoded_windows": decoded,
        "skipped_objects": excluded,
        "score_changes_observed": transitions,
        "candidate_counts": {side: len(items) for side, items in results.items()},
        "candidates": {
            side: items[:MAX_CANDIDATES_PER_SIDE]
            for side, items in results.items()
        },
        "truncated": {
            side: len(items) > MAX_CANDIDATES_PER_SIDE
            for side, items in results.items()
        },
        "research_offset_0x12BA0": trace,
        "caveat": (
            "Exact u32 score-series matches are UNVERIFIED hypotheses. "
            "Team-pointer naming, home/away mapping and native field semantics "
            "are not validated. Confirm against independent fixtures, "
            "non-goal controls and native function dataflow before usage."
        ),
    }
