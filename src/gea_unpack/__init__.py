"""Directory-based Gentee GEA extraction."""

from .gea import open_archive
from .reader import Reader
from .unpack import extract_archive, inspect_archive

__version__ = "0.2.0"
__all__ = ["Reader", "open_archive", "extract_archive", "inspect_archive"]
