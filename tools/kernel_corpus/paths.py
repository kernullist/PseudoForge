from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.kernel_corpus.errors import InvalidCorpusError
from tools.kernel_corpus.schema import (
    FUNCTIONS_DIRNAME,
    INDEX_FILENAME,
    METADATA_FILENAME,
    OVERVIEW_FILENAME,
    PSEUDOFORGE_INDEX_SCHEMA,
    RUN_MANIFEST_FILENAME,
    STANDARD_CORPUS_FILENAMES,
)


@dataclass(frozen=True)
class CorpusPaths:
    root: Path
    index_path: Path
    overview_path: Path
    metadata_path: Path
    run_manifest_path: Path
    functions_dir: Path
    forge_paths: tuple[Path, ...]

    def standard_artifact_paths(self) -> dict[str, Path]:
        return {
            "index": self.index_path,
            "overview": self.overview_path,
            "metadata": self.metadata_path,
            "run_manifest": self.run_manifest_path,
            "functions_dir": self.functions_dir,
        }


def resolve_corpus_paths(corpus_root: str | Path) -> CorpusPaths:
    root = Path(corpus_root)
    return CorpusPaths(
        root=root,
        index_path=root / INDEX_FILENAME,
        overview_path=root / OVERVIEW_FILENAME,
        metadata_path=root / METADATA_FILENAME,
        run_manifest_path=root / RUN_MANIFEST_FILENAME,
        functions_dir=root / FUNCTIONS_DIRNAME,
        forge_paths=tuple(sorted(root.glob("*.forge"))) if root.exists() else (),
    )


def validate_corpus_root(corpus_root: str | Path) -> CorpusPaths:
    paths = resolve_corpus_paths(corpus_root)
    if not paths.root.exists():
        raise InvalidCorpusError("Corpus root does not exist: %s" % paths.root)
    if not paths.root.is_dir():
        raise InvalidCorpusError("Corpus root is not a directory: %s" % paths.root)
    if not paths.index_path.is_file():
        raise InvalidCorpusError("Corpus index is missing: %s" % paths.index_path)
    if not paths.functions_dir.is_dir():
        raise InvalidCorpusError("Functions directory is missing: %s" % paths.functions_dir)
    index = _read_json_object(paths.index_path)
    schema = str(index.get("schema", ""))
    if schema != PSEUDOFORGE_INDEX_SCHEMA:
        raise InvalidCorpusError("Unsupported corpus index schema: %s" % (schema or "<missing>"))
    return paths


def standard_corpus_paths(corpus_root: str | Path) -> dict[str, Path]:
    paths = resolve_corpus_paths(corpus_root)
    return {name: paths.root / filename for name, filename in _STANDARD_PATH_NAMES.items()}


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidCorpusError("Corpus index could not be read: %s" % exc) from exc
    if not isinstance(data, dict):
        raise InvalidCorpusError("Corpus index is not a JSON object: %s" % path)
    return data


_STANDARD_PATH_NAMES = {
    "index": INDEX_FILENAME,
    "overview": OVERVIEW_FILENAME,
    "metadata": METADATA_FILENAME,
    "run_manifest": RUN_MANIFEST_FILENAME,
    "functions_dir": FUNCTIONS_DIRNAME,
}

assert set(STANDARD_CORPUS_FILENAMES) == {
    INDEX_FILENAME,
    OVERVIEW_FILENAME,
    METADATA_FILENAME,
    RUN_MANIFEST_FILENAME,
}
