"""Read-only snapshots of selected FM27 match-object candidates.

The offsets are unverified research leads for one exact FM27 DLL build.
A matching vtable pointer is NOT proof of a valid, live match object.
This module never invokes game functions, writes process memory, or injects code.
"""

from __future__ import annotations

import ctypes
import json
from pathlib import Path
import struct
import sys

from .live import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
    _read_process_memory,
    probe_live,
)
from .match_objects import MATCH_VTABLE_RVA

MAX_CANDIDATES = 64
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF

# The exact object layout has not been validated dynamically. All field
# labels deliberately include "candidate" in exported data.
FIELD_LAYOUT = {
    "seed_u32_candidate": (0x20, 4),
    "home_team_ptr_candidate": (0x15380, 8),
    "away_team_ptr_candidate": (0x15388, 8),
    "clock_u32_candidate": (0x154EC, 4),
    "flags_u32_candidate": (0x15500, 4),
}


def parse_scan(scan: dict) -> tuple[int, int, list[int]]:
    """Trust only bounded addresses from the scan's exact reported process."""
    if not isinstance(scan, dict) or scan.get("read_only") is not True:
        raise ValueError("scan must be a read-only scan-live-matches result")
    pid = scan.get("pid")
    if type(pid) is not int or not (1 <= pid <= 0xFFFFFFFF):
        raise ValueError("invalid scan PID")
    base_str = scan.get("module_base")
    if not isinstance(base_str, str) or not base_str.startswith("0x"):
        raise ValueError("invalid scan module base")
    try:
        base = int(base_str, 16)
    except ValueError as exc:
        raise ValueError("invalid scan module base") from exc
    if base <= 0 or base > MAX_USER_ADDRESS:
        raise ValueError("scan module base out of bounds")

    expected = base + MATCH_VTABLE_RVA
    if scan.get("match_vtable_rva") != f"0x{MATCH_VTABLE_RVA:X}":
        raise ValueError("scan vtable RVA differs from researched build")
    if scan.get("match_vtable_runtime_address") != f"0x{expected:X}":
        raise ValueError("scan vtable runtime address differs from expected base")
    raw_addresses = scan.get("candidate_object_addresses")
    if (not isinstance(raw_addresses, list)
            or not 1 <= len(raw_addresses) <= MAX_CANDIDATES
            or scan.get("candidate_count") != len(raw_addresses)):
        raise ValueError("scan must contain 1-64 candidate addresses")
    addresses: list[int] = []
    for raw in raw_addresses:
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise ValueError("invalid candidate address")
        try:
            address = int(raw, 16)
        except ValueError as exc:
            raise ValueError("invalid candidate address") from exc
        if address <= 0 or address > MAX_USER_ADDRESS - max(
            offset + size for offset, size in FIELD_LAYOUT.values()
        ) or address % 8:
            raise ValueError("candidate address out of bounds or not aligned")
        addresses.append(address)
    if len(addresses) != len(set(addresses)):
        raise ValueError("duplicate candidate addresses")
    return pid, base, addresses


def snapshot_candidate(address: int, expected_vtable: int, read) -> dict:
    """Read only explicit small fields, and only after the vtable still matches.

    read(address, size) -> bytes; isolated to permit deterministic unit tests.
    """
    result: dict = {
        "address": f"0x{address:X}",
        "vtable_matches": False,
        "fields": {},
    }
    try:
        vtable = read(address, 8)
        if len(vtable) != 8:
            raise OSError("short vtable pointer read")
        actual = struct.unpack("<Q", vtable)[0]
        result["vtable_at_snapshot"] = f"0x{actual:X}"
        result["vtable_matches"] = actual == expected_vtable
    except OSError as exc:
        result["vtable_read_error"] = str(exc)
        return result
    if not result["vtable_matches"]:
        result["status"] = "vtable changed or candidate no longer allocated"
        return result

    for name, (offset, size) in FIELD_LAYOUT.items():
        try:
            data = read(address + offset, size)
            if len(data) != size:
                raise OSError("short field read")
            value = int.from_bytes(data, "little")
            result["fields"][name] = (
                f"0x{value:X}" if name.endswith("_ptr_candidate") else value
            )
        except OSError as exc:
            result["fields"][name] = None
            result.setdefault("read_errors", {})[name] = str(exc)
    flags = result["fields"].get("flags_u32_candidate")
    result["fields"]["finished_bit2_candidate"] = (
        bool(flags & 0x4) if flags is not None else None
    )
    result["status"] = "matching vtable; object validity and field semantics unproven"
    return result


def snapshot_live(dll: Path, scan_json: Path) -> dict:
    if sys.platform != "win32":
        raise OSError("snapshot-matches runs only on Windows")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("snapshot-matches requires 64-bit Python")
    scan = json.loads(scan_json.read_text(encoding="utf-8-sig"))
    pid, base, addresses = parse_scan(scan)
    provenance = probe_live(dll, pid=pid, module_base=base)
    if not provenance["all_signatures_match"]:
        raise ValueError("live DLL signatures differ from the researched build")

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
            f"OpenProcess failed for PID {pid} (Windows error {ctypes.get_last_error()})"
        )
    try:
        def read(address: int, length: int) -> bytes:
            return _read_process_memory(handle, address, length, kernel32)

        snapshots = [
            snapshot_candidate(address, base + MATCH_VTABLE_RVA, read)
            for address in addresses
        ]
    finally:
        kernel32.CloseHandle(handle)
    return {
        "pid": pid,
        "module_base": f"0x{base:X}",
        "dll_sha256": provenance["dll_sha256"],
        "match_vtable_runtime_address": f"0x{base + MATCH_VTABLE_RVA:X}",
        "candidate_count": len(addresses),
        "matching_vtables": sum(1 for x in snapshots if x["vtable_matches"]),
        "candidates": snapshots,
        "read_only": True,
        "caveat": (
            "Field offsets and semantics are unverified research hypotheses. "
            "They may be unrelated to a live match, or reflect inactive objects. "
            "Snapshot changes can support further investigation but do not prove "
            "safe callable engine functions or a valid match object."
        ),
    }


def diff_snapshots(before: dict, after: dict) -> dict:
    """Offline diff; never touches the FM27 process."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("both snapshots must be JSON objects")
    for field in ("pid", "module_base", "dll_sha256", "match_vtable_runtime_address"):
        if before.get(field) != after.get(field):
            raise ValueError(f"snapshots differ in {field}; cannot compare")
    if before.get("read_only") is not True or after.get("read_only") is not True:
        raise ValueError("both files must be read-only snapshots")
    a = {item["address"]: item for item in before.get("candidates", [])}
    b = {item["address"]: item for item in after.get("candidates", [])}
    if not a or set(a) != set(b):
        raise ValueError("snapshots must contain the same candidate addresses")

    changes = []
    for address in sorted(a, key=lambda value: int(value, 16)):
        first, second = a[address], b[address]
        changed_fields = {}
        for name in ("vtable_matches", *FIELD_LAYOUT, "finished_bit2_candidate"):
            old = first.get(name) if name == "vtable_matches" else first.get("fields", {}).get(name)
            new = second.get(name) if name == "vtable_matches" else second.get("fields", {}).get(name)
            if old != new:
                changed_fields[name] = {"before": old, "after": new}
        changes.append({
            "address": address,
            "vtable_matches_in_both": (
                first.get("vtable_matches") is True
                and second.get("vtable_matches") is True
            ),
            "changed_fields": changed_fields,
        })
    return {
        "pid": before.get("pid"),
        "candidate_count": len(changes),
        "candidates_with_changes": sum(bool(row["changed_fields"]) for row in changes),
        "changes": changes,
        "caveat": (
            "Observed value changes do not validate tentative field semantics; "
            "no object was dereferenced and no game function was executed."
        ),
    }
