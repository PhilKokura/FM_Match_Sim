"""Bounded, read-only scan for candidate FM27 GAME_MATCH objects.

Never writes target memory, changes threads, injects code or executes engine calls.
The vtable RVA is a research finding for ONE exact game_plugin.dll build.
A matching vtable pointer is not evidence that an object is live or valid.
"""

from __future__ import annotations

import ctypes
from pathlib import Path
import sys
import time

from .live import probe_live


# Match-lifecycle investigation, 2026-11-04, specific researched FM27 build.
MATCH_VTABLE_RVA = 0x4C8C878

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
CHUNK_SIZE = 1024 * 1024
MAX_ADDRESS = 0x00007FFFFFFFFFFF


class MemoryBasicInformation(ctypes.Structure):
    """64-bit Windows MEMORY_BASIC_INFORMATION layout."""

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("PartitionId", ctypes.c_uint16),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


def _regions(kernel32: object, handle: int):
    address = 0x10000
    while address < MAX_ADDRESS:
        info = MemoryBasicInformation()
        count = kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
        )
        if count != ctypes.sizeof(info):
            break
        start = int(info.BaseAddress or 0)
        size = int(info.RegionSize)
        if size <= 0:
            break
        yield start, size, info.State, info.Protect, info.Type
        nxt = start + size
        if nxt <= address or nxt > MAX_ADDRESS:
            break
        address = nxt


def _eligible(state: int, protect: int, memory_type: int) -> bool:
    return (
        state == MEM_COMMIT and memory_type == MEM_PRIVATE
        and not (protect & (PAGE_NOACCESS | PAGE_GUARD))
        and (protect & 0xFF) in READABLE
    )


def scan_bytes(data: bytes, needle: bytes, base: int) -> list[int]:
    """Return addresses of exact aligned pointer occurrences."""
    if len(needle) != 8:
        raise ValueError("needle must contain an 8-byte pointer")
    hits = []
    pos = 0
    while (pos := data.find(needle, pos)) >= 0:
        address = base + pos
        if address % 8 == 0:
            hits.append(address)
        pos += 1
    return hits


def _region_window(region_size: int, skip_left: int, budget_left: int) -> tuple[int, int]:
    """How many eligible bytes to skip and then inspect within one region."""
    if min(region_size, skip_left, budget_left) < 0:
        raise ValueError("region size, skip and budget must not be negative")
    skip = min(skip_left, region_size)
    take = min(region_size - skip, budget_left)
    return skip, take


def scan_live_matches(
    dll: Path, *, pid: int, module_base: int,
    max_scan_mib: int = 512, max_hits: int = 12, max_seconds: int = 25,
    skip_mib: int = 0,
) -> dict:
    """Only inspect committed private memory; stop on strict data/time/hit limits."""
    if sys.platform != "win32":
        raise OSError("scan-live-matches runs only on Windows")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("scan-live-matches requires 64-bit Python")
    if not (1 <= max_scan_mib <= 8192):
        raise ValueError("scan budget must be between 1 and 8192 MiB")
    if not (0 <= skip_mib <= 8192):
        raise ValueError("skip budget must be between 0 and 8192 MiB")
    if not (1 <= max_hits <= 64):
        raise ValueError("max_hits must be between 1 and 64")
    if not (1 <= max_seconds <= 180):
        raise ValueError("max_seconds must be between 1 and 180")

    # Confirm the exact build and live entrypoint signatures before reading heap memory.
    provenance = probe_live(dll, pid=pid, module_base=module_base)
    if not provenance["all_signatures_match"]:
        raise ValueError("live signature check failed; refusing match-object scan")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.VirtualQueryEx.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    kernel32.ReadProcessMemory.restype = ctypes.c_int

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid)
    if not handle:
        raise OSError(
            f"OpenProcess failed for PID {pid} (Windows error {ctypes.get_last_error()})"
        )

    needle_address = module_base + MATCH_VTABLE_RVA
    needle = needle_address.to_bytes(8, "little")
    hits: list[str] = []
    errors = 0
    regions_considered = 0
    regions_read = 0
    scanned = 0
    skipped = 0
    skip_left = skip_mib * 1024 * 1024
    maximum = max_scan_mib * 1024 * 1024
    deadline = time.monotonic() + max_seconds
    reason = "address space fully enumerated"

    try:
        for start, region_size, state, protect, memory_type in _regions(kernel32, handle):
            if time.monotonic() >= deadline:
                reason = "time budget reached"
                break
            if not _eligible(state, protect, memory_type):
                continue
            regions_considered += 1
            # Skip only readable committed private bytes, exactly as the previous
            # scan counted them. This avoids repeating its first 2 GiB.
            region_skip, region_read = _region_window(
                region_size, skip_left, maximum - scanned
            )
            skip_left -= region_skip
            skipped += region_skip
            if region_skip == region_size:
                continue
            if region_read <= 0:
                reason = "byte budget reached"
                break
            limit = region_skip + region_read
            position = region_skip
            regions_read += 1
            previous = b""
            while position < limit:
                if time.monotonic() >= deadline:
                    reason = "time budget reached"
                    break
                amount = min(CHUNK_SIZE, limit - position)
                buffer = ctypes.create_string_buffer(amount)
                count = ctypes.c_size_t()
                address = start + position
                ok = kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(address), buffer,
                    amount, ctypes.byref(count)
                )
                scanned += amount
                if ok and count.value == amount:
                    data = previous + buffer.raw
                    hits.extend(
                        f"0x{p:X}"
                        for p in scan_bytes(data, needle, address - len(previous))
                    )
                    previous = data[-7:]
                    if len(hits) >= max_hits:
                        hits = hits[:max_hits]
                        reason = "hit limit reached"
                        break
                else:
                    previous = b""
                    errors += 1
                position += amount
            if reason != "address space fully enumerated":
                break
    finally:
        kernel32.CloseHandle(handle)

    if skip_left and reason == "address space fully enumerated":
        reason = "skip exceeds eligible private memory"

    return {
        "pid": pid,
        "module_base": f"0x{module_base:X}",
        "match_vtable_rva": f"0x{MATCH_VTABLE_RVA:X}",
        "match_vtable_runtime_address": f"0x{needle_address:X}",
        "candidate_object_addresses": hits,
        "candidate_count": len(hits),
        "bytes_attempted": scanned,
        "bytes_skipped": skipped,
        "requested_skip_mib": skip_mib,
        "requested_scan_mib": max_scan_mib,
        "private_regions_considered": regions_considered,
        "private_regions_read": regions_read,
        "read_failures": errors,
        "stop_reason": reason,
        "read_only": True,
        "caveat": (
            "Candidates are raw vtable-pointer matches only; they could be stale objects, "
            "unrelated memory, or inactive allocations. A negative result is limited to "
            "the scanned memory and time window, and does not prove the object is absent. "
            "No object is dereferenced here."
        ),
    }
