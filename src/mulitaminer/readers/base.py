"""Input-format abstraction.

A reader turns an input file (whatever its format) into a ``RawDocument`` the
extraction pipeline can consume. Formats register themselves by file
extension; the orchestrator just calls :func:`get_reader` and never has to know
whether the input was a PDF, CSV, XML, etc. — Open/Closed: adding a format is a
new ``readers/<fmt>.py`` + ``@register``, with no pipeline change.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawDocument:
    """Unstructured input ready for the chunk → LLM pipeline.

    ``text`` is the body fed into block creation; ``visual_layout_path`` points
    at a written layout dump some scanner strategies use for context (``None``
    when the format has no such notion).
    """
    text: str
    visual_layout_path: Optional[str] = None
    output_ext: str = "txt"
    source_format: str = "unknown"


class InputReader(ABC):
    """Base class for input-format readers."""

    extensions: tuple[str, ...] = ()

    @abstractmethod
    def read(self, path: str, scanner: Optional[str] = None,
             output_dir: Optional[str] = None, **opts) -> Optional[RawDocument]:
        """Read ``path`` into a :class:`RawDocument` (or ``None`` on failure)."""
        ...


_READERS: dict[str, type[InputReader]] = {}


def register(reader_cls: type[InputReader]) -> type[InputReader]:
    """Class decorator: register a reader for each of its ``extensions``."""
    for ext in reader_cls.extensions:
        _READERS[ext.lower()] = reader_cls
    return reader_cls


def get_reader(path: str) -> InputReader:
    """Return a reader instance for ``path`` based on its file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in _READERS:
        raise ValueError(
            f"No reader for '{ext}' files; available: {sorted(_READERS)}"
        )
    return _READERS[ext]()
