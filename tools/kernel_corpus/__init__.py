"""Read-only helpers for PseudoForge kernel corpus packs."""

from __future__ import annotations

from tools.kernel_corpus.ea import normalize_ea, normalize_ea_list
from tools.kernel_corpus.errors import InvalidCorpusError, KernelCorpusError, QueryError, StalePackError
from tools.kernel_corpus.paths import CorpusPaths, resolve_corpus_paths, validate_corpus_root
from tools.kernel_corpus.schema import (
    EVIDENCE_PACK_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    PACK_SCHEMA_VERSION,
    PSEUDOFORGE_INDEX_SCHEMA,
)

__all__ = [
    "CorpusPaths",
    "EVIDENCE_PACK_SCHEMA_VERSION",
    "InvalidCorpusError",
    "KernelCorpusError",
    "MANIFEST_SCHEMA_VERSION",
    "PACK_SCHEMA_VERSION",
    "PSEUDOFORGE_INDEX_SCHEMA",
    "QueryError",
    "StalePackError",
    "normalize_ea",
    "normalize_ea_list",
    "resolve_corpus_paths",
    "validate_corpus_root",
]
