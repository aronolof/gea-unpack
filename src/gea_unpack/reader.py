"""Directory-backed Gentee GEA 1.0 volumes with exact physical source mapping.

Format evidence: Gentee's geacommon.g, gead.g and geadfile.g (2009).
This reader does not execute captured installers or application bytecode.
"""

import bisect
import struct
from pathlib import Path, PurePosixPath

from .lzge import decode


def descriptions(raw):
    pos = 0
    folder = ""
    attribute = group = password = 0
    rows = []
    names = set()
    logical = 0

    def word(n):
        nonlocal pos
        if pos + n > len(raw):
            raise ValueError("Truncated GEA description field")
        data = raw[pos : pos + n]
        pos += n
        return data

    def string():
        nonlocal pos
        end = raw.find(b"\0", pos)
        if end < 0 or end - pos > 4096:
            raise ValueError("GEA description string exceeds bound")
        data = raw[pos:end]
        pos = end + 1
        return data.decode("cp1252")

    while pos < len(raw):
        start = pos
        flags, time, size, compressed, crc = struct.unpack("<HQIII", word(22))
        if flags & ~0x1F1:
            raise ValueError("Unknown GEA file-description flags")
        if flags & 1:
            attribute = struct.unpack("<I", word(4))[0]
        version = struct.unpack("<II", word(8)) if flags & 32 else None
        if flags & 64:
            group = struct.unpack("<I", word(4))[0]
        if flags & 128:
            password = struct.unpack("<I", word(4))[0]
        filename = string()
        if flags & 16:
            folder = string()
        path = str(PurePosixPath(folder.replace("\\", "/")) / filename)
        if (
            not filename
            or "/" in filename
            or "\\" in filename
            or "\0" in path
            or ":" in path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
        ):
            raise ValueError("Unsafe GEA member name")
        if path.casefold() in names:
            raise ValueError("GEA member name collision")
        names.add(path.casefold())
        if password:
            raise ValueError("Password-protected member is not supported")
        rows.append(
            {
                "ordinal": len(rows) + 1,
                "member_name": path,
                "flags": flags,
                "filetime_raw": time,
                "bytes": size,
                "compressed_bytes": compressed,
                "crc_raw": crc,
                "attribute": attribute,
                "version_raw": version,
                "group": group,
                "password_id": password,
                "logical_offset": logical,
                "description_offset": start,
                "description_bytes": pos - start,
                "raw_description_hex": raw[start:pos].hex(),
            }
        )
        logical += compressed
        if len(rows) > 100000:
            raise ValueError("GEA directory exceeds member bound")
    return rows


def main_header(raw):
    if len(raw) != 73 or raw[:4] != b"GEA\0" or struct.unpack_from("<H", raw, 4)[0]:
        raise ValueError("Not a GEA main volume")
    unique = struct.unpack_from("<I", raw, 6)[0]
    header = {
        "major": raw[10],
        "minor": raw[11],
        "filetime_raw": struct.unpack_from("<Q", raw, 12)[0],
        "flags": struct.unpack_from("<I", raw, 20)[0],
        "volumes": struct.unpack_from("<H", raw, 24)[0],
        "header_bytes": struct.unpack_from("<I", raw, 26)[0],
        "summary_bytes": struct.unpack_from("<Q", raw, 30)[0],
        "description_bytes": struct.unpack_from("<I", raw, 38)[0],
        "main_bytes": struct.unpack_from("<Q", raw, 42)[0],
        "volume_bytes": struct.unpack_from("<Q", raw, 50)[0],
        "last_bytes": struct.unpack_from("<Q", raw, 58)[0],
        "moved_bytes": struct.unpack_from("<I", raw, 66)[0],
        "memory_mb": raw[70],
        "block_bytes": raw[71] * 0x40000,
        "solid_bytes": raw[72] * 0x40000,
        "raw_hex": raw.hex(),
    }
    return unique, header


class Reader:
    def __init__(self, paths):
        self.paths = [Path(p) for p in paths]
        paths = self.paths
        if not paths:
            raise ValueError("Missing GEA main volume")
        self.files = []
        try:
            for p in self.paths:
                self.files.append(p.open("rb"))
            f = self.files[0]
            raw = f.read(73)
            if len(raw) != 73 or raw[:4] != b"GEA\0" or struct.unpack_from("<H", raw, 4)[0] != 0:
                raise ValueError("Not a GEA main volume")
            self.unique, self.header = main_header(raw)
            h = self.header
            if (h["major"], h["minor"]) != (1, 0) or h["flags"] & ~2:
                raise ValueError("Unsupported GEA version or password/header flags")
            if h["volumes"] != len(paths) or not 1 <= h["volumes"] <= 65535:
                raise ValueError("Missing or extra GEA volumes")
            if (
                h["main_bytes"] != paths[0].stat().st_size
                or not 73 < h["header_bytes"] <= 16 * 1024 * 1024
            ):
                raise ValueError("GEA main extent/header differs")
            if (
                not 0 < h["description_bytes"] <= 16 * 1024 * 1024
                or not 0 < h["block_bytes"] <= 8 * 1024 * 1024
                or h["solid_bytes"] > 8 * 1024 * 1024
            ):
                raise ValueError("GEA directory/block/solid bounds exceeded")
            self._read_directory(f)
            self.segments = []
            cursor = 0
            for i, p in enumerate(paths):
                size = p.stat().st_size
                if i:
                    prefix = self.files[i].read(10)
                    if (
                        len(prefix) != 10
                        or prefix[:4] != b"GEA\0"
                        or struct.unpack_from("<HI", prefix, 4) != (i, self.unique)
                    ):
                        raise ValueError("GEA volume identity/order differs")
                    expected = h["last_bytes"] if i == len(paths) - 1 else h["volume_bytes"]
                    if size != expected:
                        raise ValueError("GEA continuation volume size differs")
                start = h["header_bytes"] + h["moved_bytes"] if i == 0 else 10
                if start > size:
                    raise ValueError("GEA moved-data extent exceeds main volume")
                self.segments.append(
                    {
                        "logical_start": cursor,
                        "logical_end": cursor + size - start,
                        "source_index": i,
                        "source_offset": start,
                        "bytes": size - start,
                    }
                )
                cursor += size - start
            if h["moved_bytes"]:
                self.segments.append(
                    {
                        "logical_start": cursor,
                        "logical_end": cursor + h["moved_bytes"],
                        "source_index": 0,
                        "source_offset": h["header_bytes"],
                        "bytes": h["moved_bytes"],
                    }
                )
                cursor += h["moved_bytes"]
            if cursor != h["summary_bytes"]:
                raise ValueError("GEA volumes/moved bytes do not cover logical data")
            self.starts = [s["logical_start"] for s in self.segments]
        except Exception:
            self.close()
            raise

    def _read_directory(self, f, offset=0):
        h = self.header
        f.seek(offset)
        head = f.read(h["header_bytes"])
        stop = head.find(b"\0", 73)
        if stop < 0 or stop - 73 > 4096:
            raise ValueError("GEA volume pattern missing")
        self.pattern = head[73:stop].decode("ascii")
        self.description_offset = offset + stop + 1
        self.compressed_descriptions = head[stop + 1 :]
        if h["flags"] & 2:
            self.raw_descriptions, self.description_decode = decode(
                self.compressed_descriptions, h["description_bytes"], maximum=16 * 1024 * 1024
            )
        else:
            self.raw_descriptions = self.compressed_descriptions
            self.description_decode = None
            if len(self.raw_descriptions) != h["description_bytes"]:
                raise ValueError("GEA raw description extent differs")
        self.members = descriptions(self.raw_descriptions)
        if sum(m["compressed_bytes"] for m in self.members) != h["summary_bytes"]:
            raise ValueError("GEA member compressed sizes do not cover logical data")

    def close(self):
        for f in self.files:
            f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def locators(self, offset, size):
        if offset < 0 or size < 0 or offset + size > self.header["summary_bytes"]:
            raise ValueError("GEA logical range outside archive")
        result = []
        while size:
            i = bisect.bisect_right(self.starts, offset) - 1
            s = self.segments[i]
            n = min(size, s["logical_end"] - offset)
            if n <= 0:
                raise ValueError("GEA logical coverage gap")
            result.append(
                {
                    "source_index": s["source_index"],
                    "source_offset": s["source_offset"] + offset - s["logical_start"],
                    "bytes": n,
                    "logical_offset": offset,
                }
            )
            offset += n
            size -= n
        return result

    def read(self, offset, size):
        if size > 16 * 1024 * 1024:
            raise ValueError("GEA read exceeds bounded chunk")
        raw = bytearray()
        for span in self.locators(offset, size):
            f = self.files[span["source_index"]]
            f.seek(span["source_offset"])
            data = f.read(span["bytes"])
            if len(data) != span["bytes"]:
                raise ValueError("GEA physical span truncated")
            raw.extend(data)
        return bytes(raw)

    def blocks(self, member):
        cursor = member["logical_offset"]
        end = cursor + member["compressed_bytes"]
        index = 0
        while cursor < end:
            if cursor + 5 > end:
                raise ValueError("Truncated GEA block header")
            raw = self.read(cursor, 5)
            mode, size = struct.unpack("<BI", raw)
            if not size or cursor + 5 + size > end:
                raise ValueError("GEA block extent outside member")
            if bool(mode & 128) != (index == 0):
                raise ValueError("GEA file-start marker differs")
            codec = (mode & 127) >> 4
            order = (mode & 15) + 1
            if codec not in (0, 1, 2):
                raise ValueError("Unknown GEA compression type")
            if codec and size > self.header["block_bytes"]:
                raise ValueError("Compressed GEA block exceeds declared buffer")
            yield {
                "index": index,
                "logical_offset": cursor,
                "payload_offset": cursor + 5,
                "compressed_bytes": size,
                "mode_raw": mode,
                "codec": codec,
                "order": order,
                "source_spans": self.locators(cursor, 5 + size),
                "raw_header_hex": raw.hex(),
            }
            cursor += 5 + size
            index += 1
