"""Input readers: format-agnostic entry to the extraction pipeline.

Importing this package registers the built-in readers (currently PDF) so
``get_reader`` can dispatch by file extension.
"""
from mulitaminer.readers.base import InputReader, RawDocument, get_reader, register

# Import side-effect: each module registers its reader via @register.
from mulitaminer.readers import pdf  # noqa: F401,E402

__all__ = ["InputReader", "RawDocument", "get_reader", "register"]
