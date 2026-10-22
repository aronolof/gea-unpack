# gea-unpack

Extract and verify members of Gentee GEA 1.0 archives. Supports multipart PAK
sets and GEA archives embedded at a Windows PE executable's structural overlay.
Requires Python 3.11 or newer.

## Install

```sh
uv tool install .
# Optional PE container support:
uv tool install '.[pe]'
```

## Use

```sh
gea-unpack /path/to/archive_1.pak --list --json
gea-unpack /path/to/archive_1.pak --test
gea-unpack /path/to/archive_1.pak -d /path/to/members
gea-unpack /path/to/archive_1.pak --member data/payload.bin -d /path/to/selected
```

Select the main volume (index zero) or a directory containing exactly one main
volume. Continuation filenames come from the declared pattern; archive identity,
volume order, counts and sizes must agree. Missing, mixed and truncated volumes
raise errors. Embedded archives are parsed without executing the PE file.

`--list` reads directory metadata and block boundaries without decoding member
payloads or writing output. `--test` decodes and verifies original member sizes
and CRCs without publishing files. Extraction always performs those checks.
The default total decoded-output limit is 1 GiB; `--max-output 0` disables it.
Selecting a member currently decodes all preceding members to preserve possible
solid-history dependencies; those decoded bytes also count toward the limit.

Stored data, LZGE payloads and compressed directories are supported. PPMd is
recognized but not decoded. Password-protected and unsupported-version archives
raise explicit errors. Compatibility with arbitrary format variants is not
established by the synthetic test suite.

## Metadata and output handling

The reader preserves member names, folders, inherited attributes and groups,
version fields, raw timestamps and directory-entry bytes. Logical ranges map
through continuation headers and moved-tail data to exact physical source spans.
Source timestamps are retained without interpreting their meaning.

Each output is staged beside its destination and published after size/CRC
validation. Existing files require `--force`. Input files, destination symlinks
and paths escaping the output directory are protected. Publication is atomic per
file; a later failure can leave earlier verified members published. Standalone
extraction does not currently provide resumable checkpoints.

Reads and codec buffers are bounded. Metadata storage scales with the number of
members and blocks. Embedded archive reports retain overlay, section, certificate
range and trailing-byte metadata. This does not verify cryptographic signatures
or establish trust in an executable.

## Python API

```python
from pathlib import Path
from gea_unpack import open_archive, extract_archive

with open_archive(Path('archive_1.pak')) as reader:
    member = reader.members[0]
    blocks = list(reader.blocks(member))
    spans = reader.locators(blocks[0]['payload_offset'], 16)
    data = reader.read(blocks[0]['payload_offset'], 16)

report = extract_archive(Path('archive_1.pak'), Path('members'), max_output=None)
```

`Reader([Path(...), ...])` accepts an explicit ordered volume set. Reports use
JSON schema 2.0.0 and contain source paths/sizes, raw header and directory
metadata, physical source segments, member blocks, verification state, decoded
SHA-256 hashes and output paths. Inspection leaves `verified=false`. Input hashes
may be supplied by the caller's acquisition layer. Checksums and hashes identify
integrity/byte equality, not the meaning or safety of extracted content.

## Migration from 0.1

The previous fixed-prefix concatenation did not reconstruct GEA volume boundaries
or moved-tail data correctly. Named-member extraction replaces the old `.bin`
default and `-o` behavior; use `-d` for a destination directory. The default
extraction directory has the input suffix replaced with `.extracted`.

`--trim-spis` is removed because a signature match cannot establish an archive
member boundary. `unpack_archive(input, output_path)` remains a migration alias,
but its output path now names a directory; requesting trimming raises an error.
JSON consumers must adopt schema 2.0.0.

## Development

```sh
uv sync --extra dev --extra pe --locked
uv run --extra dev --extra pe pytest
uv run --extra dev ruff check src tests
uv build
```

Current focus: portable format support, declared boundaries, useful errors and
byte-level verification. Application-specific schemas belong in consuming tools.
The public suite uses synthetic fixtures covering volume seams, moved data,
metadata inheritance, malformed extents, compression history, CRC failures,
output protection, resource limits and embedded absolute offsets. Additional
compatibility checks must use lawfully shareable fixtures or externally supplied
inputs; no external corpus is required to run this repository's tests.

The LZGE implementation is adapted from Gentee's MIT-licensed source. Its
original notice is retained in `src/gea_unpack/third_party/GENTEE-LICENSE`.
Format references include Gentee's `geacommon.g`, `gead.g` and `geadfile.g`.
