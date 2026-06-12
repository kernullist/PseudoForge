from __future__ import annotations


class KernelCorpusError(RuntimeError):
    """Base class for Kernel Corpus tool errors."""


class InvalidCorpusError(KernelCorpusError):
    """Raised when a PseudoForge corpus root is missing or malformed."""


class StalePackError(KernelCorpusError):
    """Raised when a generated pack no longer matches its source corpus."""


class QueryError(KernelCorpusError):
    """Raised when a corpus query cannot be completed."""
