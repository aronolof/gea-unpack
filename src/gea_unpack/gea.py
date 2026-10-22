"""GEA volume discovery; directory and logical-range parsing live in reader."""

from pathlib import Path

from .embedded import EmbeddedReader
from .errors import ParseError
from .reader import Reader


def discover_parts(input_path: Path) -> list[Path]:
    path = Path(input_path)
    candidates = (
        sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() == ".pak")
        if path.is_dir()
        else [path]
    )
    if not candidates:
        raise ParseError(f"No .pak files found in {path}")
    mains = []
    for candidate in candidates:
        with candidate.open("rb") as source:
            prefix = source.read(10)
        if prefix[:4] == b"GEA\0" and len(prefix) == 10 and prefix[4:6] == b"\0\0":
            mains.append(candidate)
    if len(mains) != 1:
        raise ParseError("Select exactly one GEA main volume (part index zero)")
    main = mains[0]
    # Volume names are supplied by the main header; never collect unrelated siblings.
    with main.open("rb") as source:
        header = source.read(73)
        if len(header) != 73:
            raise ParseError("Truncated GEA main header")
        count = int.from_bytes(header[24:26], "little")
        hsize = int.from_bytes(header[26:30], "little")
        if not 73 < hsize <= 16 * 1024 * 1024 or not count:
            raise ParseError("Invalid GEA header size or volume count")
        pattern = source.read(min(hsize - 73, 4097)).split(b"\0", 1)[0]
    try:
        pattern = pattern.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ParseError("Invalid volume pattern") from exc
    result = [main]
    for index in range(2, count + 1):
        # Gentee uses %i, not arbitrary printf operations.
        if pattern.count("%i") != 1 or "%" in pattern.replace("%i", ""):
            raise ParseError("Unsupported GEA volume pattern")
        name = pattern.replace("%i", str(index))
        if "/" in name or "\\" in name or ":" in name or name in (".", ".."):
            raise ParseError("Unsafe GEA volume pattern")
        candidate = main.parent / name
        if not candidate.is_file():
            raise ParseError(f"Missing GEA volume: {name}")
        result.append(candidate)
    return result


def open_archive(input_path: Path):
    path = Path(input_path)
    if path.is_file():
        with path.open("rb") as source:
            prefix = source.read(2)
        if prefix == b"MZ":
            return EmbeddedReader(path)
    return Reader(discover_parts(path))


def unwrap(*_args, **_kwargs):
    raise ParseError("Fixed-prefix unwrapping was incorrect; use extract_archive for named members")
