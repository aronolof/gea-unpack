"""GEA at a PE's structural overlay boundary, retaining original absolute offsets.

The original gead.init and gead.read source uses geaoff and an absolute
head.geasize, and allows appended signature/trailer bytes. No magic scanning,
modified archive header, or installer execution is needed.
"""

import hashlib
import struct

from .reader import Reader, main_header


class EmbeddedReader(Reader):
    def __init__(self, path):
        self.paths = [path]
        self.files = []
        try:
            try:
                import pefile
            except ImportError as exc:
                raise ValueError("Embedded PE archives require gea-unpack[pe]") from exc
            try:
                pe = pefile.PE(str(path), fast_load=True)
            except pefile.PEFormatError as exc:
                raise ValueError(f"Invalid PE container: {exc}") from exc
            try:
                offset = pe.get_overlay_data_start_offset()
                self.pe_sections = [
                    {
                        "name_hex": s.Name.hex(),
                        "source_offset": s.PointerToRawData,
                        "bytes": s.SizeOfRawData,
                    }
                    for s in pe.sections
                ]
                directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                self.security_directory = (
                    {"source_offset": directories[4].VirtualAddress, "bytes": directories[4].Size}
                    if len(directories) > 4
                    else {"source_offset": 0, "bytes": 0}
                )
            finally:
                pe.close()
            if offset is None:
                raise ValueError("PE has no structural overlay")
            self.files = [path.open("rb")]
            f = self.files[0]
            f.seek(offset)
            raw = f.read(73)
            if len(raw) != 73 or raw[:4] != b"GEA\0" or struct.unpack_from("<H", raw, 4)[0] != 0:
                raise ValueError("PE overlay does not begin with a GEA main header")
            self.overlay_offset = offset
            self.unique, self.header = main_header(raw)
            h = self.header
            size = path.stat().st_size
            if (h["major"], h["minor"]) != (1, 0) or h["flags"] & ~2 or h["volumes"] != 1:
                raise ValueError("Unsupported embedded GEA version/flags/volume count")
            if (
                not 73 < h["header_bytes"] <= 16 * 1024 * 1024
                or not offset + h["header_bytes"] <= h["main_bytes"] <= size
            ):
                raise ValueError("Embedded GEA absolute extent/header differs")
            if (
                not 0 < h["description_bytes"] <= 16 * 1024 * 1024
                or not 0 < h["block_bytes"] <= 8 * 1024 * 1024
                or h["solid_bytes"] > 8 * 1024 * 1024
            ):
                raise ValueError("Embedded GEA directory/block/solid bounds exceeded")
            self._read_directory(f, offset)
            start = offset + h["header_bytes"] + h["moved_bytes"]
            end = h["main_bytes"]
            if start > end:
                raise ValueError("Embedded moved-data extent exceeds main file")
            self.segments = []
            cursor = 0
            if end > start:
                self.segments.append(
                    {
                        "logical_start": 0,
                        "logical_end": end - start,
                        "source_index": 0,
                        "source_offset": start,
                        "bytes": end - start,
                    }
                )
                cursor = end - start
            if h["moved_bytes"]:
                self.segments.append(
                    {
                        "logical_start": cursor,
                        "logical_end": cursor + h["moved_bytes"],
                        "source_index": 0,
                        "source_offset": offset + h["header_bytes"],
                        "bytes": h["moved_bytes"],
                    }
                )
                cursor += h["moved_bytes"]
            if cursor != h["summary_bytes"]:
                raise ValueError("Embedded data/moved extents do not cover logical size")
            self.starts = [s["logical_start"] for s in self.segments]
            f.seek(end)
            digest = hashlib.sha256()
            while chunk := f.read(1024 * 1024):
                digest.update(chunk)
            self.trailer = {
                "source_offset": end,
                "bytes": size - end,
                "sha256": digest.hexdigest(),
                "classification": "retained; meaning unresolved",
            }
        except Exception:
            self.close()
            raise
