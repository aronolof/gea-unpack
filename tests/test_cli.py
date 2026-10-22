import json
import struct
import zlib
from pathlib import Path

import pytest

from gea_unpack.cli import main
from gea_unpack.errors import ParseError
from gea_unpack.gea import discover_parts
from gea_unpack.unpack import extract_archive
from test_gea import volumes


def archive(root: Path):
    logical = b"\x80" + struct.pack("<I", 1) + b"A" + b"\x80" + struct.pack("<I", 1) + b"B"
    paths = volumes(root, logical)
    raw = bytearray(paths[0].read_bytes())
    # Two independent original member CRCs; the fixture directory has two 24-byte entries.
    for offset, data in [(73 + 8 + 18, b"A"), (73 + 8 + 24 + 18, b"B")]:
        struct.pack_into("<I", raw, offset, zlib.crc32(data) ^ 0xFFFFFFFF)
    paths[0].write_bytes(raw)
    return paths


def test_list_json_never_writes(tmp_path, capsys):
    paths = archive(tmp_path)
    assert main([str(paths[0]), "--list", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "2.0.0"
    assert not report["verified"]
    assert len(report["members"]) == 2
    assert not paths[0].with_suffix(".extracted").exists()


def test_extract_members_and_test_without_output(tmp_path):
    paths = archive(tmp_path)
    report = extract_archive(paths[0], test=True)
    assert report.verified
    assert not paths[0].with_suffix(".extracted").exists()
    out = tmp_path / "out"
    report = extract_archive(paths[0], out)
    assert (out / "a").read_bytes() == b"A"
    assert (out / "b").read_bytes() == b"B"
    assert all(m["verified"] for m in report.members)
    with pytest.raises(FileExistsError):
        extract_archive(paths[0], out)
    extract_archive(paths[0], out, force=True)


def test_selection_and_output_budget(tmp_path):
    paths = archive(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(ParseError, match="limit"):
        extract_archive(paths[0], out, max_output=1)
    assert not out.exists()
    extract_archive(paths[0], out, member="b")
    assert not (out / "a").exists()
    assert (out / "b").read_bytes() == b"B"


def test_bad_crc_preserves_destination_and_cleans_temporary(tmp_path):
    paths = archive(tmp_path)
    data = bytearray(paths[0].read_bytes())
    data[73 + 8 + 18] ^= 1
    paths[0].write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    (out / "a").write_bytes(b"original")
    with pytest.raises(ParseError, match="CRC"):
        extract_archive(paths[0], out, force=True)
    assert (out / "a").read_bytes() == b"original"
    assert not list(out.glob(".gea-*"))


def test_source_hardlink_and_symlink_are_protected(tmp_path):
    paths = archive(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / "a").hardlink_to(paths[1])
    with pytest.raises(ParseError, match="input volume"):
        extract_archive(paths[0], out, force=True)
    (out / "a").unlink()
    (out / "a").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ParseError):
        extract_archive(paths[0], out, force=True)


def test_cli_rejects_inspection_output_options(tmp_path):
    with pytest.raises(SystemExit):
        main([str(tmp_path), "--list", "-d", str(tmp_path / "out")])


def test_discovery_uses_declared_pattern_and_rejects_ambiguity(tmp_path):
    paths = archive(tmp_path)
    assert discover_parts(paths[0]) == paths
    assert discover_parts(tmp_path) == paths
    (tmp_path / "unrelated.pak").write_bytes(paths[0].read_bytes())
    with pytest.raises(ParseError, match="exactly one"):
        discover_parts(tmp_path)


def test_directory_discovery_accepts_uppercase_extension(tmp_path):
    paths = archive(tmp_path)
    renamed = paths[0].with_suffix(".PAK")
    paths[0].rename(renamed)
    assert discover_parts(tmp_path) == [renamed, paths[1]]


def test_ppmd_is_explicitly_unsupported_and_never_published(tmp_path):
    paths = archive(tmp_path)
    raw = bytearray(paths[0].read_bytes())
    hsize = struct.unpack_from("<I", raw, 26)[0]
    moved = struct.unpack_from("<I", raw, 66)[0]
    raw[hsize + moved] = 0xA0  # First block, PPMd codec, order one.
    paths[0].write_bytes(raw)
    out = tmp_path / "out"
    with pytest.raises(ParseError, match="PPMd is unsupported"):
        extract_archive(paths[0], out)
    assert not (out / "a").exists()
    assert not list(out.glob(".gea-*"))
