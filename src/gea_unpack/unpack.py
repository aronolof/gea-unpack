"""Bounded GEA extraction. Each file is published only after size/CRC validation."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zlib
from pathlib import Path

from .errors import ParseError
from .gea import open_archive
from .lzge import decode
from .model import ArchiveReport

DEFAULT_MAX_OUTPUT = 1024 * 1024 * 1024


def _report(reader, operation):
    return ArchiveReport(
        sources=[{"path": str(p), "bytes": p.stat().st_size} for p in reader.paths],
        header={
            **reader.header,
            "archive_id": reader.unique,
            "volume_pattern": reader.pattern,
            "logical_source_segments": reader.segments,
            "description_source_offset": reader.description_offset,
            "compressed_description_hex": reader.compressed_descriptions.hex(),
            "decoded_description_hex": reader.raw_descriptions.hex(),
            **(
                {
                    "overlay_offset": reader.overlay_offset,
                    "pe_sections": reader.pe_sections,
                    "security_directory": reader.security_directory,
                }
                if hasattr(reader, "overlay_offset")
                else {}
            ),
        },
        members=[{**m, "blocks": list(reader.blocks(m))} for m in reader.members],
        operation=operation,
        trailer=getattr(reader, "trailer", None),
    )


def inspect_archive(input_path: Path) -> ArchiveReport:
    with open_archive(input_path) as reader:
        return _report(reader, "list")


def _target(directory, name, inputs):
    root = directory.resolve()
    target = directory / name
    if not target.resolve().is_relative_to(root):
        raise ParseError(f"Member destination escapes output directory: {name}")
    for source in inputs:
        if target.resolve() == source.resolve() or (
            target.exists() and os.path.samefile(target, source)
        ):
            raise ParseError(f"Member would replace an input volume: {name}")
    if target.is_symlink():
        raise ParseError(f"Member destination is a symbolic link: {name}")
    return target


def extract_archive(
    input_path: Path,
    output_dir: Path | None = None,
    *,
    member: str | None = None,
    test: bool = False,
    force: bool = False,
    max_output: int | None = DEFAULT_MAX_OUTPUT,
    progress=None,
) -> ArchiveReport:
    if max_output is not None and max_output < 0:
        raise ValueError("max_output must be non-negative or None")
    directory = Path(output_dir) if output_dir else Path(input_path).with_suffix(".extracted")
    with open_archive(input_path) as reader:
        report = _report(reader, "test" if test else "extract")
        selected = [m for m in report.members if member is None or m["member_name"] == member]
        if not selected:
            raise ParseError(f"Member not found: {member}")
        last = selected[-1]["ordinal"]
        processed = report.members[:last]
        if max_output is not None and sum(m["bytes"] for m in processed) > max_output:
            raise ParseError(
                "Declared decoded output exceeds limit (including solid prerequisites)"
            )
        destinations = {}
        for m in selected:
            if not test:
                target = _target(directory, m["member_name"], reader.paths)
                if target.exists() and not force:
                    raise FileExistsError(f"Output exists: {target}")
                destinations[m["ordinal"]] = target
        history = b""
        selected_ids = {m["ordinal"] for m in selected}
        for m in processed:
            target = destinations.get(m["ordinal"])
            temporary = None
            out = None
            try:
                if target is not None:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    out = tempfile.NamedTemporaryFile(
                        dir=target.parent, prefix=".gea-", delete=False
                    )
                    temporary = Path(out.name)
                crc = size = 0
                digest = hashlib.sha256()
                for block in m["blocks"]:
                    codec = block["codec"]
                    if codec == 2:
                        raise ParseError(
                            f"Member {m['member_name']} block {block['index']}: PPMd is unsupported"
                        )
                    if codec == 0:
                        history = b""
                        remaining = block["compressed_bytes"]
                        offset = block["payload_offset"]
                        if size + remaining > m["bytes"]:
                            raise ParseError("Stored block exceeds member size")
                        chunks = _stored(reader, offset, remaining)
                    else:
                        expected = min(reader.header["block_bytes"], m["bytes"] - size)
                        if expected <= 0:
                            raise ParseError("Compressed data after declared member end")
                        if block["order"] != 1:
                            history = b""
                        elif (
                            len(history) + expected
                            > reader.header["block_bytes"] + reader.header["solid_bytes"]
                        ):
                            bound = reader.header["solid_bytes"]
                            history = history[-bound:] if bound else b""
                        data, consumption = decode(
                            reader.read(block["payload_offset"], block["compressed_bytes"]),
                            expected,
                            history=history,
                        )
                        block["consumption"] = consumption
                        history += data
                        chunks = (data,)
                    before = size
                    for data in chunks:
                        size += len(data)
                        crc = zlib.crc32(data, crc)
                        digest.update(data)
                        if out is not None:
                            out.write(data)
                    block["decoded_bytes"] = size - before
                if size != m["bytes"] or (crc ^ 0xFFFFFFFF) != m["crc_raw"]:
                    raise ParseError(f"Member {m['member_name']}: declared size or CRC differs")
                m.update(verified=True, sha256=digest.hexdigest(), decoded_bytes=size)
                if progress is not None:
                    progress(m)
                if out is not None:
                    out.close()
                    _target(directory, m["member_name"], reader.paths)
                    if force:
                        os.replace(temporary, target)
                    else:
                        # A late arrival cannot be overwritten between preflight and publication.
                        os.link(temporary, target)
                        temporary.unlink()
                    temporary = None
                if m["ordinal"] in selected_ids:
                    report.outputs.append(
                        {
                            "member_name": m["member_name"],
                            "bytes": size,
                            "sha256": digest.hexdigest(),
                            "output": str(target) if target else None,
                        }
                    )
            finally:
                if out is not None:
                    out.close()
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        report.verified = True
        return report


def _stored(reader, offset, remaining):
    while remaining:
        n = min(1024 * 1024, remaining)
        yield reader.read(offset, n)
        remaining -= n
        offset += n


def unpack_archive(input_path: Path, output_path: Path | None = None, trim_spis=False):
    """Migration alias: output_path now names a directory; trimming is rejected."""
    if trim_spis:
        raise ParseError("--trim-spis cannot establish archive framing; extract named members")
    return extract_archive(input_path, output_path)


def report_to_json(report: ArchiveReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
