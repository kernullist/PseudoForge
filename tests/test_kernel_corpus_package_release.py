from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.atlas import generate_atlas
from tools.kernel_corpus.errors import KernelCorpusError
from tools.kernel_corpus.lifecycle import trace_lifecycle
from tools.kernel_corpus.package_release import (
    CHECKSUMS_NAME,
    DEFAULT_GITHUB_REPO,
    MANIFEST_NAME,
    README_NAME,
    SCHEMA,
    SplitVolumeWriter,
    package_release,
    parse_size,
)
from tools.kernel_corpus.validate_pack import validate_pack


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusPackageReleaseTests(unittest.TestCase):
    def test_package_release_writes_extractable_split_archive_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            pack_root = temp_root / "pack"
            builder.build_pack(FIXTURE_ROOT, pack_root)
            trace_lifecycle(
                pack_root,
                "process_object",
                max_seeds=8,
                depth=1,
                output_path=pack_root / "evidence-packs" / "process_object.json",
            )
            generate_atlas(pack_root, pack_root / "reports" / "atlas", limit=8)
            output_dir = temp_root / "release"
            install_root = (temp_root / "install-root").resolve(strict=False)
            install_pack_root = install_root / "ntoskrnl-test-r1" / "kernel-pack"

            result = package_release(
                pack_root=pack_root,
                artifact_id="ntoskrnl-test-r1",
                output_dir=output_dir,
                source_corpus_root=FIXTURE_ROOT,
                install_root=install_root,
                volume_size="1m",
                pseudoforge_commit="test-commit",
            )

            release_dir = output_dir / "ntoskrnl-test-r1"
            manifest_path = release_dir / MANIFEST_NAME
            readme_path = release_dir / README_NAME
            checksums_path = release_dir / CHECKSUMS_NAME
            archive_parts = sorted(release_dir.glob("ntoskrnl-test-r1.tar.gz.*"))

            self.assertFalse(result["dry_run"])
            self.assertEqual(SCHEMA, result["schema"])
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(readme_path.is_file())
            self.assertTrue(checksums_path.is_file())
            self.assertGreaterEqual(len(archive_parts), 1)
            self.assertIn("gh release create ntoskrnl-test-r1", result["release_command"])
            self.assertIn("--repo %s" % DEFAULT_GITHUB_REPO, result["release_command"])
            self.assertIn("README-install.md", result["release_command"])
            self.assertIn("New-Item -ItemType Directory -Force $InstallRoot | Out-Null", result["install_commands"])
            self.assertIn('cmd /c copy /b "ntoskrnl-test-r1.tar.gz.*" "ntoskrnl-test-r1.tar.gz"', result["install_commands"])
            self.assertTrue(result["relocation"]["enabled"])
            self.assertGreater(result["relocation"]["text_files_rewritten"], 0)
            self.assertGreater(result["relocation"]["sqlite_rows_rewritten"], 0)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(SCHEMA, manifest["schema"])
            self.assertEqual("ntoskrnl-test-r1", manifest["artifact_id"])
            self.assertEqual(DEFAULT_GITHUB_REPO, manifest["github_repo"])
            self.assertEqual("test-commit", manifest["source"]["pseudoforge_commit"])
            self.assertEqual(str(install_pack_root), manifest["install"]["pack_root_after_extract"])
            self.assertEqual(str(install_pack_root), manifest["relocation"]["pack_root_after_extract"])
            self.assertEqual(["kernel-pack", "raw-corpus"], [item["name"] for item in manifest["components"]])

            checksum_text = checksums_path.read_text(encoding="utf-8")
            self.assertIn(MANIFEST_NAME, checksum_text)
            self.assertIn(README_NAME, checksum_text)
            self.assertIn("ntoskrnl-test-r1.tar.gz.001", checksum_text)
            readme_text = readme_path.read_text(encoding="utf-8")
            self.assertIn('New-Item -ItemType Directory -Force $InstallRoot | Out-Null', readme_text)
            self.assertIn('tar -xzf "ntoskrnl-test-r1.tar.gz" -C $InstallRoot', readme_text)

            archive_blob = b"".join(path.read_bytes() for path in archive_parts)
            with tarfile.open(fileobj=io.BytesIO(archive_blob), mode="r:gz") as archive:
                names = set(archive.getnames())
                archive.extractall(install_root)
            self.assertIn("ntoskrnl-test-r1/%s" % MANIFEST_NAME, names)
            self.assertIn("ntoskrnl-test-r1/%s" % README_NAME, names)
            self.assertIn("ntoskrnl-test-r1/kernel-pack/manifest.json", names)
            self.assertIn("ntoskrnl-test-r1/kernel-pack/corpus.sqlite", names)
            self.assertIn("ntoskrnl-test-r1/raw-corpus/pseudoforge-corpus-index.json", names)

            extracted_manifest = json.loads((install_pack_root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(str(install_pack_root / "corpus.sqlite"), extracted_manifest["sqlite_path"])
            validation = validate_pack(install_pack_root, include_derived=True)
            self.assertTrue(validation["ok"], validation["issues"])

    def test_package_release_dry_run_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            pack_root = temp_root / "pack"
            builder.build_pack(FIXTURE_ROOT, pack_root)
            output_dir = temp_root / "release"

            result = package_release(
                pack_root=pack_root,
                artifact_id="dry-run-r1",
                output_dir=output_dir,
                volume_size="1m",
                dry_run=True,
            )

            self.assertTrue(result["dry_run"])
            self.assertFalse((output_dir / "dry-run-r1").exists())
            self.assertEqual(["kernel-pack"], [item["name"] for item in result["components"]])
            self.assertIn('cmd /c copy /b "dry-run-r1.tar.gz.*" "dry-run-r1.tar.gz"', result["install_commands"])

    def test_package_release_rejects_missing_pack_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            pack_root = Path(temp_dir) / "pack"
            pack_root.mkdir()
            (pack_root / "manifest.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(KernelCorpusError, "SQLite database is missing"):
                package_release(pack_root=pack_root, artifact_id="bad-r1", output_dir=Path(temp_dir) / "out")

    def test_parse_size_accepts_units(self) -> None:
        self.assertEqual(1024, parse_size("1k"))
        self.assertEqual(1024 * 1024, parse_size("1m"))
        self.assertEqual(2 * 1024 * 1024 * 1024, parse_size("2g"))
        self.assertEqual(1536, parse_size("1.5k"))

    def test_split_volume_writer_splits_on_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "payload.bin"
            with SplitVolumeWriter(base_path, 10) as writer:
                writer.write(b"0123456789ABCDEF012345")

            parts = sorted(Path(temp_dir).glob("payload.bin.*"))
            self.assertEqual(["payload.bin.001", "payload.bin.002", "payload.bin.003"], [item.name for item in parts])
            self.assertEqual(b"0123456789", parts[0].read_bytes())
            self.assertEqual(b"ABCDEF0123", parts[1].read_bytes())
            self.assertEqual(b"45", parts[2].read_bytes())


if __name__ == "__main__":
    unittest.main()
