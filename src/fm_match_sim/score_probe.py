"""Bounded, read-only binary captures for locating native FM27 score fields.

This module gathers small snapshots of *candidate* match and team structures,
then performs an offline before/after comparison against manually observed
score changes. It does not identify authoritative score fields on its own.
Never executes game code or writes to the game process.
"""

from __future__ import annotations

import base64
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zlib

from .live import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
    _read_process_memory,
    probe_live,
)
from .match_objects import MATCH_VTABLE_RVA
from .snapshots import MAX_USER_ADDRESS, parse_scan, snapshot_candidate

MAX_MATCHES = 16
MAX_SCORE = 30
READ_CHUNK = 4096
# Intentionally bounded research windows, NOT claimed native struct sizes.
MATCH_WINDOWS = (
    ("match_head", 0, 0x2000),
    ("match_tail", 0x10000, 0x5600),
)
TEAM_WINDOW_SIZE = 0x2000
MAX_DECOMPRESSED_WINDOW = 0x8000
MAX_REPORT_ITEMS = 60


def _valid_pointer(value: object) -> int | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        address = int(value, 16)
    except ValueError:
        return None
    if address < 0x10000 or address > MAX_USER_ADDRESS - TEAM_WINDOW_SIZE or address % 8:
        return None
    return address


def _pack(data: bytes) -> dict:
    return {
        "encoding": "zlib+base64",
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": base64.b64encode(zlib.compress(data, 6)).decode("ascii"),
    }


def _unpack(window: dict) -> bytes:
    """Limit decompression of untrusted files and verify length + checksum."""
    if not isinstance(window, dict) or window.get("encoding") != "zlib+base64":
        raise ValueError("unsupported memory window encoding")
    size = window.get("byte_length")
    if type(size) is not int or not (1 <= size <= MAX_DECOMPRESSED_WINDOW):
        raise ValueError("invalid memory window size")
    raw = base64.b64decode(window["data"], validate=True)
    inflater = zlib.decompressobj()
    content = inflater.decompress(raw, MAX_DECOMPRESSED_WINDOW + 1)
    if (not inflater.eof or inflater.unconsumed_tail or inflater.unused_data
            or len(content) != size or len(content) > MAX_DECOMPRESSED_WINDOW):
        raise ValueError("invalid or oversized compressed memory window")
    if hashlib.sha256(content).hexdigest() != window.get("sha256"):
        raise ValueError("memory window checksum mismatch")
    return content


def _window_capture(read, address: int, size: int) -> dict:
    """Avoid reading large remote ranges atomically; fail closed on partial data."""
    if size <= 0 or size > MAX_DECOMPRESSED_WINDOW:
        raise ValueError("memory window size out of bounds")
    if address < 0x10000 or address > MAX_USER_ADDRESS - size:
        raise ValueError("memory window address out of bounds")
    chunks = []
    try:
        for index in range(0, size, READ_CHUNK):
            length = min(READ_CHUNK, size - index)
            data = read(address + index, length)
            if len(data) != length:
                raise OSError("short process-memory read")
            chunks.append(data)
    except OSError as exc:
        return {"error": str(exc)}
    return _pack(b"".join(chunks))


def capture_one_match(address: int, expected_vtable: int, read) -> dict:
    """Capture fixed-size windows only while the vtable remains unchanged."""
    snapshot = snapshot_candidate(address, expected_vtable, read)
    result = {
        "address": f"0x{address:X}",
        "vtable_matches": snapshot["vtable_matches"],
        "fields": snapshot.get("fields", {}),
        "windows": {},
    }
    if not snapshot["vtable_matches"]:
        result["status"] = "skipped: vtable no longer matches"
        return result

    home = _valid_pointer(result["fields"].get("home_team_ptr_candidate"))
    away = _valid_pointer(result["fields"].get("away_team_ptr_candidate"))
    if home is None or away is None or home == away:
        result["status"] = "skipped: invalid or overlapping team pointers"
        return result

    for name, offset, size in MATCH_WINDOWS:
        result["windows"][name] = _window_capture(read, address + offset, size)
    result["windows"]["home_team"] = _window_capture(read, home, TEAM_WINDOW_SIZE)
    result["windows"]["away_team"] = _window_capture(read, away, TEAM_WINDOW_SIZE)

    # A current vtable match does not establish object lifetime through capture.
    try:
        after_vtable = int.from_bytes(read(address, 8), "little")
    except OSError:
        after_vtable = 0
    if after_vtable != expected_vtable:
        result["windows"] = {}
        result["status"] = "discarded: vtable changed during capture"
    else:
        result["status"] = "captured unverified match/team data"
    return result


def capture_live_score_data(
    dll: Path, scan_json: Path, *, home_goals: int, away_goals: int,
    tag: str, include_idle: bool = False,
) -> dict:
    """Save locally; do not publish the output because it contains raw game memory."""
    if sys.platform != "win32":
        raise OSError("capture-score-data runs only on Windows")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("capture-score-data requires 64-bit Python")
    if not (0 <= home_goals <= MAX_SCORE and 0 <= away_goals <= MAX_SCORE):
        raise ValueError("visible goals must be between 0 and 30")
    if not tag or len(tag) > 64 or not all(c.isalnum() or c in "-_" for c in tag):
        raise ValueError("tag must be 1-64 letters, digits, hyphens or underscores")

    scan = json.loads(scan_json.read_text(encoding="utf-8-sig"))
    pid, base, addresses = parse_scan(scan)
    if len(addresses) > MAX_MATCHES:
        raise ValueError("too many candidates for bounded score capture (maximum 16)")
    provenance = probe_live(dll, pid=pid, module_base=base)
    if not provenance["all_signatures_match"]:
        raise ValueError("live DLL signatures differ from researched build")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid
    )
    if not handle:
        raise OSError(
            f"OpenProcess failed for PID {pid}, Windows error {ctypes.get_last_error()}"
        )
    matches = []
    skipped_idle = 0
    try:
        def read(address: int, size: int) -> bytes:
            return _read_process_memory(handle, address, size, kernel32)

        for address in addresses:
            fields = snapshot_candidate(address, base + MATCH_VTABLE_RVA, read)
            if not fields["vtable_matches"]:
                continue
            if not include_idle and not fields["fields"].get("clock_u32_candidate"):
                skipped_idle += 1
                continue
            matches.append(capture_one_match(address, base + MATCH_VTABLE_RVA, read))
    finally:
        kernel32.CloseHandle(handle)
    return {
        "schema_version": 1,
        "capture_utc": datetime.now(timezone.utc).isoformat(),
        "pid": pid,
        "module_base": f"0x{base:X}",
        "dll_sha256": provenance["dll_sha256"],
        "match_vtable_runtime_address": f"0x{base + MATCH_VTABLE_RVA:X}",
        "tag": tag,
        "visible_score": {"home": home_goals, "away": away_goals},
        "read_only": True,
        "skipped_idle_candidates": skipped_idle,
        "matches": matches,
        "caveat": (
            "Raw compressed memory data, possibly containing unrelated game/session "
            "information. Keep this file local. Native struct lengths, team mapping "
            "and score offsets are NOT validated."
        ),
    }


def _score_transitions(before: bytes, after: bytes, old: int, new: int) -> list[dict]:
    """Look for aligned integer locations consistent with a visible score change."""
    if len(before) != len(after):
        raise ValueError("memory windows differ in length")
    if old == new:
        return []
    result = []
    for width in (4, 2, 1):
        # An overlapping u8 match adds little information if there is already a
        # corresponding u32 match, but keep types distinct for static validation.
        for offset in range(0, len(before) - width + 1, width):
            a = int.from_bytes(before[offset:offset + width], "little")
            b = int.from_bytes(after[offset:offset + width], "little")
            if a == old and b == new:
                result.append({"offset": f"0x{offset:X}", "width_bytes": width,
                               "before": a, "after": b})
    return result


def analyze_score_change(before: dict, after: dict) -> dict:
    """Return hypotheses only; a later independent score event must validate."""
    for field in ("schema_version", "pid", "module_base", "dll_sha256",
                  "match_vtable_runtime_address"):
        if before.get(field) != after.get(field):
            raise ValueError(f"capture mismatch: {field}")
    if before.get("schema_version") != 1 or before.get("read_only") is not True \
            or after.get("read_only") is not True:
        raise ValueError("inputs must be read-only score captures with schema_version=1")
    first = before.get("visible_score", {})
    second = after.get("visible_score", {})
    for item in (first, second):
        if (type(item.get("home")) is not int or type(item.get("away")) is not int
                or not (0 <= item["home"] <= MAX_SCORE)
                or not (0 <= item["away"] <= MAX_SCORE)):
            raise ValueError("invalid visible score metadata")
    if first == second:
        raise ValueError("visible score did not change; a goal event is required")

    left = {item["address"]: item for item in before.get("matches", [])}
    right = {item["address"]: item for item in after.get("matches", [])}
    if not left or not right:
        raise ValueError("no captured match structures to compare")

    candidates: list[dict] = []
    inspected = 0
    skipped = []
    for address in sorted(set(left) & set(right), key=lambda value: int(value, 16)):
        a, b = left[address], right[address]
        if not a.get("vtable_matches") or not b.get("vtable_matches"):
            skipped.append({"address": address, "reason": "vtable mismatch"})
            continue
        for ptr in ("home_team_ptr_candidate", "away_team_ptr_candidate"):
            if a["fields"].get(ptr) != b["fields"].get(ptr):
                skipped.append({"address": address, "reason": "team pointers changed"})
                break
        else:
            inspected += 1
            for name in ("match_head", "match_tail", "home_team", "away_team"):
                x, y = a.get("windows", {}).get(name), b.get("windows", {}).get(name)
                if not x or not y or "error" in x or "error" in y:
                    continue
                first_bytes, second_bytes = _unpack(x), _unpack(y)
                origin = 0x10000 if name == "match_tail" else 0
                for side in ("home", "away"):
                    if first[side] == second[side]:
                        continue
                    transitions = _score_transitions(
                        first_bytes, second_bytes, first[side], second[side]
                    )
                    for change in transitions:
                        if len(candidates) >= 50_000:
                            raise ValueError("too many matches to analyze safely")
                        candidates.append({
                            "match_address": address,
                            "window": name,
                            "side_hypothesis": side,
                            "relative_offset": f"0x{origin + int(change['offset'], 16):X}",
                            "width_bytes": change["width_bytes"],
                        })
    # Prioritize aligned 32-bit fields, then the structure associated with
    # the named side; neither heuristic proves native field semantics.
    def rank(row: dict) -> tuple:
        preferred = row["window"] == row["side_hypothesis"] + "_team"
        return (-row["width_bytes"], -int(preferred),
                row["match_address"], row["window"],
                int(row["relative_offset"], 16))
    candidates.sort(key=rank)
    return {
        "pid": before["pid"],
        "before": {"tag": before.get("tag"), "score": first},
        "after": {"tag": after.get("tag"), "score": second},
        "match_objects_compared": inspected,
        "candidate_integer_locations": len(candidates),
        "candidates": candidates[:MAX_REPORT_ITEMS],
        "truncated": len(candidates) > MAX_REPORT_ITEMS,
        "skipped_objects": skipped,
        "caveat": (
            "These are UNVERIFIED integer transitions, not identified score fields. "
            "Confirm candidate offsets via native score-update xrefs and further "
            "independent goals/non-goal control captures before using them."
        ),
    }
