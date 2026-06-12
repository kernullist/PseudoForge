from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus.ea import normalize_ea, normalize_ea_list
from tools.kernel_corpus.errors import InvalidCorpusError, KernelCorpusError, QueryError, StalePackError
from tools.kernel_corpus.paths import resolve_corpus_paths, standard_corpus_paths, validate_corpus_root
from tools.kernel_corpus.schema import PSEUDOFORGE_INDEX_SCHEMA


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusBootstrapTests(unittest.TestCase):
    def test_normalize_ea_accepts_supported_forms(self) -> None:
        self.assertEqual("0x14093A130", normalize_ea(0x14093A130))
        self.assertEqual("0x14093A130", normalize_ea("0x14093a130"))
        self.assertEqual("0x14093A130", normalize_ea("0X14093A130"))
        self.assertEqual("0x1000", normalize_ea("4096"))

    def test_normalize_ea_rejects_invalid_values(self) -> None:
        for value in ("", "not_an_ea", -1, True):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    normalize_ea(value)

    def test_normalize_ea_list_deduplicates_in_order(self) -> None:
        self.assertEqual(
            ["0x140001000", "0x140002000"],
            normalize_ea_list(["0x140001000", "0X140001000", 0x140002000]),
        )

    def test_error_types_share_base_class(self) -> None:
        for error_type in (InvalidCorpusError, StalePackError, QueryError):
            self.assertTrue(issubclass(error_type, KernelCorpusError))

    def test_resolve_corpus_paths_does_not_require_existing_root(self) -> None:
        paths = resolve_corpus_paths(Path("missing-corpus"))

        self.assertEqual(Path("missing-corpus"), paths.root)
        self.assertEqual(Path("missing-corpus") / "pseudoforge-corpus-index.json", paths.index_path)
        self.assertEqual(Path("missing-corpus") / "functions", paths.functions_dir)
        self.assertEqual((), paths.forge_paths)

    def test_standard_corpus_paths_resolves_expected_artifacts(self) -> None:
        paths = standard_corpus_paths(FIXTURE_ROOT)

        self.assertEqual(FIXTURE_ROOT / "pseudoforge-corpus-index.json", paths["index"])
        self.assertEqual(FIXTURE_ROOT / "pseudoforge-corpus-overview.md", paths["overview"])
        self.assertEqual(FIXTURE_ROOT / "pseudoforge-corpus-metadata.json", paths["metadata"])
        self.assertEqual(FIXTURE_ROOT / "pseudoforge-ida-run.json", paths["run_manifest"])
        self.assertEqual(FIXTURE_ROOT / "functions", paths["functions_dir"])

    def test_validate_corpus_root_accepts_minimal_fixture(self) -> None:
        paths = validate_corpus_root(FIXTURE_ROOT)

        self.assertEqual(FIXTURE_ROOT, paths.root)
        self.assertTrue(paths.index_path.is_file())
        self.assertTrue(paths.functions_dir.is_dir())
        self.assertEqual(1, len(paths.forge_paths))
        self.assertEqual("minimal.forge", paths.forge_paths[0].name)
        self.assertEqual(paths.index_path, paths.standard_artifact_paths()["index"])

    def test_validate_corpus_root_rejects_missing_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "functions").mkdir()

            with self.assertRaisesRegex(InvalidCorpusError, "index"):
                validate_corpus_root(root)

    def test_validate_corpus_root_rejects_missing_functions_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_index(root / "pseudoforge-corpus-index.json", PSEUDOFORGE_INDEX_SCHEMA)

            with self.assertRaisesRegex(InvalidCorpusError, "Functions directory"):
                validate_corpus_root(root)

    def test_validate_corpus_root_rejects_wrong_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "functions").mkdir()
            _write_index(root / "pseudoforge-corpus-index.json", "wrong_schema")

            with self.assertRaisesRegex(InvalidCorpusError, "Unsupported"):
                validate_corpus_root(root)


def _write_index(path: Path, schema: str) -> None:
    path.write_text(json.dumps({"schema": schema, "functions": []}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
