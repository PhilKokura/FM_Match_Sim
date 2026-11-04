"""Non-invasive Windows process memory-region inventory for FM27.

Only VirtualQueryEx metadata is read. Does not inspect the bytes within a region,
modify the target process, or enumerate user data.
"""

from __future__ import annotations

import ctypes
from pathlib import Path
import sys

from .live import probe_live
from .match_objects import (
    MAX_ADDRESS,
    MEM_COMMIT,
    MEM_PRIVATE,
    PROCESS_QUERY_INFORMATION,
    MemoryBasicInformation,
    _eligible,
    _regions,
)

MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
GIB = 1 << 30
MIB = 1 << 20
MAX_REGIONS = 500_000


def summarize_regions(regions: list[tuple[int, int, int, int, int]], *, top: int = 12) -> dict:
    """Summarize allocation classes and the portions excluded by the scanner."""
    if not 1 <= top <= 30:
        raise ValueError("top must be between 1 and 30")

    by_type: dict[str, dict[str, int]] = {}
    eligible: list[tuple[int, int]] = []
    all_committed = 0
    for start, size, state, protect, region_type in regions:
        if state != MEM_COMMIT or size <= 0:
            continue
        all_committed += size
        name = {
            MEM_PRIVATE: "private",
            MEM_IMAGE: "image",
            MEM_MAPPED: "mapped",
        }.get(region_type, f"other_0x{region_type:X}")
        group = by_type.setdefault(name, {"committed_bytes": 0, "regions": 0})
        group["committed_bytes"] += size
        group["regions"] += 1
        if _eligible(state, protect, region_type):
            eligible.append((start, size))

    eligible.sort()
    total_eligible = sum(size for _, size in eligible)
    first_two_gib = 2 * GIB
    consumed = 0
    before_budget = 0
    for _, size in eligible:
        take = min(size, max(0, first_two_gib - consumed))
        if take == 0:
            break
        consumed += take
        before_budget += 1

    # Group by 1-TiB virtual-address bands to show where eligible pages are mapped.
    bands: dict[int, dict[str, int]] = {}
    for start, size in eligible:
        key = start // (1 << 40)
        bucket = bands.setdefault(key, {"regions": 0, "bytes": 0})
        bucket["regions"] += 1
        bucket["bytes"] += size

    return {
        "regions_enumerated": len(regions),
        "committed_mib": round(all_committed / MIB, 2),
        "committed_by_type": {
            k: {"regions": v["regions"], "mib": round(v["committed_bytes"] / MIB, 2)}
            for k, v in sorted(by_type.items())
        },
        "readable_committed_private_mib": round(total_eligible / MIB, 2),
        "readable_committed_private_region_count": len(eligible),
        "eligible_mib_beyond_first_2gib": round(max(0, total_eligible - first_two_gib) / MIB, 2),
        "eligible_regions_encountered_at_2gib_cap": before_budget,
        "largest_readable_private_regions": [
            {"start": f"0x{start:X}", "mib": round(size / MIB, 2)}
            for start, size in sorted(eligible, key=lambda r: r[1], reverse=True)[:top]
        ],
        "address_bands_1tib": [
            {"start": f"0x{key << 40:X}", "end_exclusive": f"0x{(key+1) << 40:X}",
             "regions": value["regions"], "mib": round(value["bytes"] / MIB, 2)}
            for key, value in sorted(bands.items())
        ],
        "limits": {
            "current_scanner_only_private": True,
            "current_scanner_scans_lowest_addresses_first": True,
            "current_scanner_budget_mib": 2048,
            "vtable_in_mapped_or_image_memory_not_scanned": True,
        },
        "caveat": (
            "Region metadata alone does not establish where a match object exists. "
            "This inventory is not a full heap scan or a proof of an active match object."
        ),
    }


def map_live_memory(dll: Path, *, pid: int, module_base: int, top: int = 12) -> dict:
    """Map Win64 regions after validating the exact game build and loaded functions."""
    if sys.platform != "win32":
        raise OSError("map-live runs only on Windows")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("map-live requires 64-bit Python")
    if pid <= 0 or module_base <= 0:
        raise ValueError("PID and module base must be positive")
    if not 1 <= top <= 30:
        raise ValueError("top must be between 1 and 30")

    provenance = probe_live(dll, pid=pid, module_base=module_base)
    if not provenance["all_signatures_match"]:
        raise ValueError("live signature check failed; refusing memory map")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.VirtualQueryEx.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
    if not handle:
        raise OSError(
            f"OpenProcess failed for PID {pid} (Windows error {ctypes.get_last_error()})"
        )
    try:
        regions = []
        for region in _regions(kernel32, handle):
            regions.append(region)
            if len(regions) > MAX_REGIONS:
                raise ValueError("memory map exceeded region safety limit")
    finally:
        kernel32.CloseHandle(handle)

    summary = summarize_regions(regions, top=top)
    return {
        "pid": pid,
        "module_base": f"0x{module_base:X}",
        "dll_sha256": provenance["dll_sha256"],
        "read_only": True,
        **summary,
    }
