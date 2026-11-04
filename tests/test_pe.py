import struct
import tempfile
from pathlib import Path
import unittest

from fm_match_sim.pe import parse_pe, inspect


class PeTests(unittest.TestCase):
    def _make_pe(self, file: Path):
        data = bytearray(1024)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", data, 0x84, 0x8664, 1)
        struct.pack_into("<H", data, 0x84 + 16, 0xF0)
        opt = 0x84 + 20
        struct.pack_into("<H", data, opt, 0x20B)
        struct.pack_into("<Q", data, opt + 24, 0x180000000)
        struct.pack_into("<I", data, opt + 56, 0x4000)
        section = opt + 0xF0
        data[section:section + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x100, 0x200)
        data[0x210:0x214] = b"\x90\x90\xC3\xCC"
        file.write_bytes(data)

    def test_pe_parser_and_rva_mapping(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "game_plugin.dll"
            self._make_pe(p)
            image = parse_pe(p)
            self.assertEqual(image.image_base, 0x180000000)
            self.assertEqual(image.rva_file_offset(0x1010), 0x210)
            self.assertIsNone(image.rva_file_offset(0x2000))
            report = inspect(p, hash_file=True)
            self.assertFalse(report["matches_research_hash"])
            self.assertEqual(report["file_size"], 1024)

    def test_non_pe_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "invalid.dll"
            p.write_bytes(b"hello")
            with self.assertRaisesRegex(ValueError, "MZ"):
                parse_pe(p)


if __name__ == "__main__":
    unittest.main()
