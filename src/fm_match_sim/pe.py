"""Read-only FM27 PE inspection. File RVAs are not executable runtime bindings."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct


# Identity and candidate entry points from the read-only 2026-11-04 feasibility report.
KNOWN_SIZE = 404_308_480
KNOWN_SHA256 = "252ff8fb5b7a4a5a5464db6ba632e309eef9b6e65ffa992ae20575a189e66c6a"
CANDIDATES = {
    "fixture_factory": 0xC33370,
    "match_writer_thunk": 0x49EF150,
    "match_reader": 0x4973930,
    "prepare_candidate": 0x16B8DBD0,
    "play_to_end": 0x4520BD0,
}


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class PEImage:
    file_size: int
    machine: int
    image_base: int
    image_size: int
    sections: tuple[Section, ...]

    def rva_file_offset(self, rva: int) -> int | None:
        """Return physical file offset, if the RVA is backed by raw section bytes."""
        for section in self.sections:
            start = section.virtual_address
            end = start + max(section.virtual_size, section.raw_size)
            delta = rva - start
            if start <= rva < end and 0 <= delta < section.raw_size:
                offset = section.raw_offset + delta
                if offset < self.file_size:
                    return offset
        return None


def parse_pe(path: Path) -> PEImage:
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(min(size, 1024 * 1024))
    if len(head) < 0x40 or head[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
    if pe_offset > len(head) - 24 or head[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid or inaccessible PE header")
    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", head, coff)
    optional_size = struct.unpack_from("<H", head, coff + 16)[0]
    opt = coff + 20
    if machine != 0x8664 or opt + optional_size > len(head) or optional_size < 64:
        raise ValueError("not a valid PE32+ x64 executable")
    if struct.unpack_from("<H", head, opt)[0] != 0x20B:
        raise ValueError("not PE32+")
    image_base = struct.unpack_from("<Q", head, opt + 24)[0]
    image_size = struct.unpack_from("<I", head, opt + 56)[0]
    section_start = opt + optional_size
    if section_count > 96 or section_start + section_count * 40 > len(head):
        raise ValueError("invalid or inaccessible PE section table")
    sections: list[Section] = []
    for index in range(section_count):
        start = section_start + index * 40
        name = head[start:start + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", head, start + 8)
        if raw_size and (raw_offset > size or raw_size > size - raw_offset):
            raise ValueError(f"section {name!r} lies outside the file")
        sections.append(Section(name, virtual_address, virtual_size, raw_offset, raw_size))
    return PEImage(size, machine, image_base, image_size, tuple(sections))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect(path: Path, *, hash_file: bool = True) -> dict:
    pe = parse_pe(path)
    digest = sha256_file(path) if hash_file else None
    known = digest == KNOWN_SHA256 if digest is not None else False
    entries: dict[str, dict] = {}
    with path.open("rb") as stream:
        for name, rva in CANDIDATES.items():
            offset = pe.rva_file_offset(rva)
            preview = None
            if offset is not None:
                stream.seek(offset)
                preview = stream.read(12).hex()
            entries[name] = {
                "rva": f"0x{rva:X}",
                "raw_file_offset": offset,
                "raw_bytes_12": preview,
            }
    warnings = [
        "RVA file mapping does not establish a callable function, a valid runtime ABI or a safe engine host.",
        "Protected/wrapped sections may not expose their runtime instructions in raw file bytes.",
    ]
    if not known:
        warnings.append(
            "Exact known DLL hash not confirmed; all documented RVAs must be independently revalidated."
        )
    return {
        "path": str(path),
        "file_size": pe.file_size,
        "image_base": f"0x{pe.image_base:X}",
        "image_size": pe.image_size,
        "sha256": digest,
        "matches_research_hash": known,
        "matches_research_size": pe.file_size == KNOWN_SIZE,
        "sections": [s.name for s in pe.sections],
        "entrypoint_candidates": entries,
        "warnings": warnings,
    }
