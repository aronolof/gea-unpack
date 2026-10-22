import struct
import tempfile
import unittest
from pathlib import Path

from gea_unpack.lzge import decode
from gea_unpack.reader import Reader, descriptions


def entry(name, flags=0, extra=b"", size=1, compressed=6):
    return struct.pack("<HQIII", flags, 0, size, compressed, 0) + extra + name + b"\0"


def volumes(root, logical):
    info = entry(b"a") + entry(b"b")
    pattern = b"p%i.pak\0"
    hsize = 73 + len(pattern) + len(info)
    moved = 3
    first = 4
    unique = 12345
    header = bytearray(73)
    header[:4] = b"GEA\0"
    struct.pack_into("<I", header, 6, unique)
    header[10] = 1
    struct.pack_into("<H", header, 24, 2)
    struct.pack_into("<I", header, 26, hsize)
    struct.pack_into("<Q", header, 30, len(logical))
    struct.pack_into("<I", header, 38, len(info))
    struct.pack_into("<Q", header, 42, hsize + moved + first)
    struct.pack_into("<Q", header, 50, 65535)
    second = logical[first:-moved]
    struct.pack_into("<Q", header, 58, 10 + len(second))
    struct.pack_into("<I", header, 66, moved)
    header[70] = 8
    header[71] = 1
    paths = [root / "p1.pak", root / "p2.pak"]
    paths[0].write_bytes(header + pattern + info + logical[-moved:] + logical[:first])
    paths[1].write_bytes(b"GEA\0" + struct.pack("<HI", 1, unique) + second)
    return paths


class GEATests(unittest.TestCase):
    def test_description_inheritance_and_path_validation(self):
        raw = entry(b"a", 0x51, struct.pack("<II", 32, 4)) + b"data\0" + entry(b"b")
        rows = descriptions(raw)
        self.assertEqual([r["member_name"] for r in rows], ["data/a", "data/b"])
        self.assertEqual([r["attribute"] for r in rows], [32, 32])
        self.assertEqual([r["group"] for r in rows], [4, 4])
        self.assertEqual([r["logical_offset"] for r in rows], [0, 6])
        with self.assertRaises(ValueError):
            descriptions(entry(b"../escape"))
        with self.assertRaises(ValueError):
            descriptions(raw[:-1])

    def test_seams_and_moved_data_have_exact_physical_locators(self):
        logical = b"\x80" + struct.pack("<I", 1) + b"A" + b"\x80" + struct.pack("<I", 1) + b"B"
        with tempfile.TemporaryDirectory() as tmp:
            paths = volumes(Path(tmp), logical)
            with Reader(paths) as reader:
                self.assertEqual(reader.read(0, len(logical)), logical)
                self.assertEqual(len(reader.locators(0, 5)), 2)
                self.assertEqual(list(reader.blocks(reader.members[0]))[0]["codec"], 0)
                self.assertEqual(reader.read(11, 1), b"B")
                self.assertEqual(reader.locators(11, 1)[0]["source_index"], 0)

    def test_wrong_missing_and_truncated_volumes_cannot_pass(self):
        logical = b"\x80" + struct.pack("<I", 1) + b"A" + b"\x80" + struct.pack("<I", 1) + b"B"
        with tempfile.TemporaryDirectory() as tmp:
            paths = volumes(Path(tmp), logical)
            with self.assertRaises(ValueError):
                Reader(paths[:1])
            raw = bytearray(paths[1].read_bytes())
            raw[4] = 2
            paths[1].write_bytes(raw)
            with self.assertRaises(ValueError):
                Reader(paths)
            paths = volumes(Path(tmp), logical)
            paths[1].write_bytes(paths[1].read_bytes()[:-1])
            with self.assertRaises(ValueError):
                Reader(paths)

    def test_block_extent_does_not_skip_corruption(self):
        logical = b"\x80" + struct.pack("<I", 2) + b"A" + b"\x80" + struct.pack("<I", 1) + b"B"
        with tempfile.TemporaryDirectory() as tmp:
            with Reader(volumes(Path(tmp), logical)) as reader:
                with self.assertRaises(ValueError):
                    list(reader.blocks(reader.members[0]))


def literal_fixture(value, size=4):
    # Independent bit writer for a fixed two-symbol pretree and unary main tree.
    bits = []

    def number(n, width):
        bits.extend((n >> i) & 1 for i in range(width))

    maxoff = (1 << size.bit_length()) - 1
    end = 2
    slots = 3
    from gea_unpack.lzge import RANGE_BITS

    for width in RANGE_BITS[3:]:
        end += 1 << width
        slots += 1
        if end - 1 >= maxoff:
            break
    count = 256 + 18 * slots + 1
    number(0, 3)
    number(1, 1)
    number(0, 1)
    number(0, 2)
    number(1, 1)
    number(0, 1)
    bits.extend([1, 1] + [0] * 18)
    bits.extend(1 if i == value else 0 for i in range(count))
    bits.extend([0] * size)
    return bytes(
        sum(bits[j + i] << (7 - i) for i in range(min(8, len(bits) - j)))
        for j in range(0, len(bits), 8)
    )


class LZGETests(unittest.TestCase):
    def test_literal_stream_and_truncation(self):
        raw = literal_fixture(65)
        self.assertEqual(decode(raw, 4)[0], b"AAAA")
        with self.assertRaises(ValueError):
            decode(raw[:3], 4)

    def test_match_without_history_and_output_limit_rejected(self):
        with self.assertRaises(ValueError):
            decode(literal_fixture(256), 4)
        with self.assertRaises(ValueError):
            decode(b"", 9 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()


def test_lzge_match_uses_prior_solid_history():
    # Symbol 256 is a length-two match at the initial recent distance of three.
    # The alphabet is built for total history+output size five.
    assert decode(literal_fixture(256, size=5), 2, history=b"ABC")[0] == b"AB"
