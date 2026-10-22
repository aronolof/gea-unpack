import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gea_unpack.embedded import EmbeddedReader
from test_gea import entry


class EmbeddedTests(unittest.TestCase):
    def fixture(self, root, moved=0):
        prefix = b"MZ" + b"P" * 94
        logical = b"\x80" + struct.pack("<I", 4) + b"DATA"
        desc = entry(b"file", size=4, compressed=len(logical))
        pattern = b"p%i.pak\0"
        hsize = 73 + len(pattern) + len(desc)
        end = len(prefix) + hsize + len(logical)
        header = bytearray(73)
        header[:4] = b"GEA\0"
        header[10] = 1
        struct.pack_into("<H", header, 24, 1)
        struct.pack_into("<I", header, 26, hsize)
        struct.pack_into("<Q", header, 30, len(logical))
        struct.pack_into("<I", header, 38, len(desc))
        struct.pack_into("<Q", header, 42, end)
        struct.pack_into("<Q", header, 58, end)
        struct.pack_into("<I", header, 66, moved)
        header[70] = 8
        header[71] = 1
        body = (logical[-moved:] + logical[:-moved]) if moved else logical
        path = root / "update.exe"
        path.write_bytes(prefix + header + pattern + desc + body + b"TRAILER")
        pe = SimpleNamespace(
            sections=[],
            OPTIONAL_HEADER=SimpleNamespace(
                DATA_DIRECTORY=[None] * 4 + [SimpleNamespace(VirtualAddress=0, Size=0)]
            ),
            get_overlay_data_start_offset=lambda: len(prefix),
            close=lambda: None,
        )
        return path, pe, len(prefix), hsize, end

    def test_absolute_bounds_trailer_and_moved_source_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            for moved in [0, 3]:
                path, pe, offset, hsize, end = self.fixture(Path(tmp), moved)
                with patch("pefile.PE", return_value=pe):
                    with EmbeddedReader(path) as reader:
                        self.assertEqual(
                            reader.read(0, 9), b"\x80" + struct.pack("<I", 4) + b"DATA"
                        )
                        self.assertEqual(reader.trailer["source_offset"], end)
                        self.assertEqual(
                            reader.trailer["sha256"], hashlib.sha256(b"TRAILER").hexdigest()
                        )
                        block = next(reader.blocks(reader.members[0]))
                        self.assertEqual(block["codec"], 0)
                        span = reader.locators(6, 3)[0]
                        self.assertEqual(
                            span["source_offset"], offset + hsize if moved else offset + hsize + 6
                        )
                        with self.assertRaises(ValueError):
                            reader.read(9, 1)

    def test_invalid_absolute_extent_and_false_overlay_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, pe, offset, hsize, end = self.fixture(Path(tmp))
            raw = bytearray(path.read_bytes())
            struct.pack_into("<Q", raw, offset + 42, len(raw) + 1)
            path.write_bytes(raw)
            with patch("pefile.PE", return_value=pe):
                with self.assertRaisesRegex(ValueError, "absolute extent"):
                    EmbeddedReader(path)
            path, pe, offset, hsize, end = self.fixture(Path(tmp))
            raw = bytearray(path.read_bytes())
            raw[offset : offset + 4] = b"NOPE"
            path.write_bytes(raw)
            with patch("pefile.PE", return_value=pe):
                with self.assertRaisesRegex(ValueError, "overlay does not begin"):
                    EmbeddedReader(path)


class EmbeddedReportTests(unittest.TestCase):
    fixture = EmbeddedTests.fixture

    def test_report_keeps_overlay_sections_and_certificate_range(self):
        from gea_unpack.unpack import inspect_archive

        with tempfile.TemporaryDirectory() as tmp:
            path, pe, offset, _, end = self.fixture(Path(tmp))
            pe.sections = [SimpleNamespace(Name=b".text", PointerToRawData=64, SizeOfRawData=32)]
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] = SimpleNamespace(VirtualAddress=end, Size=7)
            with patch("pefile.PE", return_value=pe):
                report = inspect_archive(path)
            self.assertEqual(report.header["overlay_offset"], offset)
            self.assertEqual(report.header["pe_sections"][0]["source_offset"], 64)
            self.assertEqual(
                report.header["security_directory"], {"source_offset": end, "bytes": 7}
            )
            self.assertFalse(report.verified)

    def test_malformed_pe_has_a_useful_cli_error(self):
        import io
        from contextlib import redirect_stderr

        from gea_unpack.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.exe"
            path.write_bytes(b"MZbroken")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(main([str(path), "--list"]), 1)
            self.assertIn("Invalid PE container", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()


def test_pe_without_certificate_directory_is_inspectable(tmp_path):
    from gea_unpack.unpack import inspect_archive

    path, pe, _, _, _ = EmbeddedTests().fixture(tmp_path)
    pe.OPTIONAL_HEADER.DATA_DIRECTORY = []
    with patch("pefile.PE", return_value=pe):
        report = inspect_archive(path)
    assert report.header["security_directory"] == {"source_offset": 0, "bytes": 0}
