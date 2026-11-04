"""Read-only signature checks against an already running FM27 process.

This module never writes memory, allocates remote memory, executes remote
threads, loads DLLs, hooks functions or changes the running game.
"""

from __future__ import annotations

import ctypes
from pathlib import Path
import struct
import sys

from .pe import CANDIDATES, KNOWN_SHA256, inspect


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SIGNATURE_LENGTH = 12


def _read_process_memory(handle: int, address: int, length: int, kernel32: object) -> bytes:
    buffer = ctypes.create_string_buffer(length)
    count = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buffer, length, ctypes.byref(count)
    )
    if not ok or count.value != length:
        code = ctypes.get_last_error()
        raise OSError(
            f"ReadProcessMemory failed at 0x{address:X} "
            f"(requested {length}, got {count.value}, Windows error {code})"
        )
    return buffer.raw


def compare_prefix(expected: bytes, actual: bytes) -> bool:
    """Strict check of matching entrypoint bytes, not a functional ABI test."""
    return len(expected) == SIGNATURE_LENGTH and expected == actual


def probe_live(dll: Path, *, pid: int, module_base: int) -> dict:
    if sys.platform != "win32":
        raise OSError("probe-live runs only on Windows")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("probe-live requires 64-bit Python")
    if pid <= 0 or module_base <= 0:
        raise ValueError("PID and module base must be positive")
    if module_base > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("module base exceeds 64-bit address range")

    # Check *before* opening a live process: offsets cannot be trusted in other builds.
    local = inspect(dll, hash_file=True)
    if local["sha256"] != KNOWN_SHA256:
        raise ValueError("DLL hash differs from the researched build; refusing live probe")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid
    )
    if not handle:
        raise OSError(f"OpenProcess failed for PID {pid}, Windows error {ctypes.get_last_error()}")

    try:
        # A valid PE signature is the minimum guard against using a wrong ASLR base.
        if _read_process_memory(handle, module_base, 2, kernel32) != b"MZ":
            raise ValueError(f"0x{module_base:X} does not point to an MZ module header")
        offset = struct.unpack(
            "<I", _read_process_memory(handle, module_base + 0x3C, 4, kernel32)
        )[0]
        if offset > 0x10000:
            raise ValueError("invalid loaded PE header offset")
        if _read_process_memory(handle, module_base + offset, 4, kernel32) != b"PE\x00\x00":
            raise ValueError("invalid loaded PE signature")

        candidates = {}
        with dll.open("rb") as source:
            for name, rva in CANDIDATES.items():
                disk = local["entrypoint_candidates"][name]
                offset = disk["raw_file_offset"]
                if offset is None:
                    raise ValueError(f"no disk-backed bytes for {name}")
                source.seek(offset)
                expected = source.read(SIGNATURE_LENGTH)
                address = module_base + rva
                actual = _read_process_memory(handle, address, SIGNATURE_LENGTH, kernel32)
                candidates[name] = {
                    "rva": disk["rva"],
                    "runtime_address": f"0x{address:X}",
                    "disk_bytes": expected.hex(),
                    "memory_bytes": actual.hex(),
                    "matches_disk": compare_prefix(expected, actual),
                }
    finally:
        kernel32.CloseHandle(handle)

    all_match = all(item["matches_disk"] for item in candidates.values())
    return {
        "pid": pid,
        "module_base": f"0x{module_base:X}",
        "dll_sha256": local["sha256"],
        "candidates": candidates,
        "all_signatures_match": all_match,
        "status": (
            "read-only signature check passed"
            if all_match else "one or more signatures differ; stop and investigate"
        ),
        "caveat": (
            "Matching bytes do not establish valid calling conventions, initialized engine "
            "state, safe memory ownership, fixture access, or match simulation."
        ),
        "read_only": True,
    }
