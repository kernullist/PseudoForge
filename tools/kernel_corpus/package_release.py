from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError  # noqa: E402


SCHEMA = "kernel_corpus_release_package_v1"
DEFAULT_GITHUB_REPO = "kernullist/kernel-corpus"
DEFAULT_VOLUME_SIZE = "1900m"
DEFAULT_OUTPUT_DIR = "release/kernel-corpus"
README_NAME = "README-install.md"
MANIFEST_NAME = "artifact-manifest.json"
CHECKSUMS_NAME = "checksums.sha256"


@dataclass(frozen=True)
class Component:
    name: str
    path: Path
    required: bool = True


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = package_release(
            pack_root=args.pack_root,
            artifact_id=args.artifact_id,
            output_dir=args.output_dir,
            source_corpus_root=args.source_corpus_root,
            run_log_root=args.run_log_root,
            extra_paths=args.extra_path,
            volume_size=args.volume_size,
            compression_level=args.compression_level,
            github_repo=args.github_repo,
            pseudoforge_commit=args.pseudoforge_commit,
            dry_run=args.dry_run,
        )
    except (OSError, KernelCorpusError, ValueError) as exc:
        print("Kernel corpus release packaging failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def package_release(
    *,
    pack_root: str | Path,
    artifact_id: str,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    source_corpus_root: str | Path = "",
    run_log_root: str | Path = "",
    extra_paths: list[str] | tuple[str, ...] | None = None,
    volume_size: str = DEFAULT_VOLUME_SIZE,
    compression_level: int = 6,
    github_repo: str = DEFAULT_GITHUB_REPO,
    pseudoforge_commit: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    artifact = _validate_artifact_id(artifact_id)
    pack = Path(pack_root).resolve()
    out_dir = _resolve_output_dir(output_dir).resolve() / artifact
    volume_bytes = parse_size(volume_size)
    if volume_bytes < 1024 * 1024:
        raise KernelCorpusError("Volume size must be at least 1 MiB: %s" % volume_size)
    if compression_level < 0 or compression_level > 9:
        raise KernelCorpusError("Compression level must be between 0 and 9.")

    components = _components(pack, source_corpus_root, run_log_root, extra_paths or [])
    _validate_components(components)
    pack_manifest = _read_pack_manifest(pack)
    commit = pseudoforge_commit or _git_commit(ROOT)
    component_summaries = [_component_summary(component) for component in components]
    archive_base = out_dir / ("%s.tar.gz" % artifact)
    manifest = _artifact_manifest(
        artifact,
        pack,
        out_dir,
        pack_manifest,
        component_summaries,
        volume_size,
        volume_bytes,
        compression_level,
        commit,
        github_repo,
    )
    readme = _install_readme(artifact, github_repo)

    if dry_run:
        return {
            "schema": SCHEMA,
            "dry_run": True,
            "artifact_id": artifact,
            "output_dir": str(out_dir),
            "archive_base": str(archive_base),
            "component_count": len(components),
            "components": component_summaries,
            "volume_size_bytes": volume_bytes,
            "files": [],
            "release_command": _release_command(artifact, github_repo, out_dir),
            "install_commands": _install_commands(artifact),
            "install_command": " ; ".join(_install_commands(artifact)),
        }

    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / MANIFEST_NAME
    readme_path = out_dir / README_NAME
    checksums_path = out_dir / CHECKSUMS_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    readme_path.write_text(readme, encoding="utf-8")

    archive_parts = _write_split_tar_gz(
        archive_base,
        artifact,
        components,
        manifest_path,
        readme_path,
        volume_bytes,
        compression_level,
    )
    checksum_entries = _write_checksums(checksums_path, [manifest_path, readme_path] + archive_parts)
    files = [_file_payload(path) for path in [manifest_path, readme_path, checksums_path] + archive_parts]
    return {
        "schema": SCHEMA,
        "dry_run": False,
        "artifact_id": artifact,
        "output_dir": str(out_dir),
        "archive_base": str(archive_base),
        "component_count": len(components),
        "components": component_summaries,
        "volume_size_bytes": volume_bytes,
        "files": files,
        "checksums": checksum_entries,
        "release_command": _release_command(artifact, github_repo, out_dir),
        "install_commands": _install_commands(artifact),
        "install_command": " ; ".join(_install_commands(artifact)),
    }


def parse_size(text: str) -> int:
    value = (text or "").strip().lower()
    if not value:
        raise KernelCorpusError("Volume size is empty.")
    suffix = value[-1]
    multiplier = 1
    number = value
    if suffix in {"k", "m", "g"}:
        number = value[:-1]
        multiplier = {"k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}[suffix]
    try:
        parsed = float(number)
    except ValueError as exc:
        raise KernelCorpusError("Invalid volume size: %s" % text) from exc
    if parsed <= 0:
        raise KernelCorpusError("Volume size must be positive: %s" % text)
    return int(parsed * multiplier)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Package a Kernel Corpus pack as split release assets for GitHub Releases."
    )
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root containing manifest.json and corpus.sqlite.")
    parser.add_argument(
        "--artifact-id",
        required=True,
        help="Release artifact id, for example ntoskrnl-26200.8457-amd64-r1.",
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory where release assets are written.")
    parser.add_argument("--source-corpus-root", default="", help="Optional raw PseudoForge corpus root to include.")
    parser.add_argument("--run-log-root", default="", help="Optional run-log directory to include.")
    parser.add_argument("--extra-path", action="append", default=[], help="Optional extra file or directory to include. May repeat.")
    parser.add_argument("--volume-size", default=DEFAULT_VOLUME_SIZE, help="Split volume size, such as 1900m.")
    parser.add_argument("--compression-level", type=int, default=6, help="gzip compression level 0..9.")
    parser.add_argument(
        "--github-repo",
        default=DEFAULT_GITHUB_REPO,
        help="Owner/repo used in generated gh release commands. Default: %s." % DEFAULT_GITHUB_REPO,
    )
    parser.add_argument("--pseudoforge-commit", default="", help="Override the recorded PseudoForge commit.")
    parser.add_argument("--dry-run", action="store_true", help="Print package plan without writing files.")
    return parser


def _components(
    pack_root: Path,
    source_corpus_root: str | Path,
    run_log_root: str | Path,
    extra_paths: list[str] | tuple[str, ...],
) -> list[Component]:
    components = [Component("kernel-pack", pack_root)]
    if str(source_corpus_root or ""):
        components.append(Component("raw-corpus", Path(source_corpus_root).resolve()))
    if str(run_log_root or ""):
        components.append(Component("run-logs", Path(run_log_root).resolve()))
    for index, item in enumerate(extra_paths, start=1):
        components.append(Component("extra-%02d-%s" % (index, _safe_component_name(Path(item).name)), Path(item).resolve()))
    return components


def _validate_components(components: list[Component]) -> None:
    seen: set[Path] = set()
    for component in components:
        if not component.path.exists():
            raise KernelCorpusError("Release component is missing: %s" % component.path)
        if component.path in seen:
            raise KernelCorpusError("Duplicate release component path: %s" % component.path)
        seen.add(component.path)
        if component.name == "kernel-pack":
            if not (component.path / "manifest.json").is_file():
                raise KernelCorpusError("Kernel pack manifest is missing: %s" % (component.path / "manifest.json"))
            if not (component.path / "corpus.sqlite").is_file():
                raise KernelCorpusError("Kernel pack SQLite database is missing: %s" % (component.path / "corpus.sqlite"))


def _read_pack_manifest(pack_root: Path) -> dict[str, Any]:
    path = pack_root / "manifest.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KernelCorpusError("Could not read pack manifest: %s" % exc) from exc
    if not isinstance(payload, dict):
        raise KernelCorpusError("Pack manifest is not a JSON object: %s" % path)
    return payload


def _artifact_manifest(
    artifact_id: str,
    pack_root: Path,
    output_dir: Path,
    pack_manifest: dict[str, Any],
    components: list[dict[str, Any]],
    volume_size_text: str,
    volume_size_bytes: int,
    compression_level: int,
    pseudoforge_commit: str,
    github_repo: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "artifact_id": artifact_id,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "distribution": "github_release_assets",
        "github_repo": github_repo,
        "archive": {
            "format": "split tar.gz",
            "base_name": "%s.tar.gz" % artifact_id,
            "volume_size": volume_size_text,
            "volume_size_bytes": volume_size_bytes,
            "compression": "gzip",
            "compression_level": compression_level,
        },
        "source": {
            "pack_root": str(pack_root),
            "pseudoforge_commit": pseudoforge_commit,
            "pack_schema": str(pack_manifest.get("schema", "")),
            "target_path": str(pack_manifest.get("target_path", "")),
            "source_corpus_root": str(pack_manifest.get("source_corpus_root", "")),
            "source_index_sha256": str(pack_manifest.get("source_index_sha256", "")),
            "function_count": _int_value(pack_manifest.get("function_count"), 0),
            "skipped_count": _int_value(pack_manifest.get("skipped_count"), 0),
            "pack_generated_at": str(pack_manifest.get("generated_at", "")),
        },
        "output_dir": str(output_dir),
        "components": components,
        "install": {
            "extract_root_example": "F:\\pseudoforge-corpora",
            "pack_root_after_extract": "F:\\pseudoforge-corpora\\%s\\kernel-pack" % artifact_id,
            "mcp_config_command": (
                'python -B .\\tools\\kernel_corpus\\install_wiring.py mcp-config '
                '--pack-root "F:\\pseudoforge-corpora\\%s\\kernel-pack"'
            )
            % artifact_id,
        },
    }


def _component_summary(component: Component) -> dict[str, Any]:
    file_count = 0
    total_bytes = 0
    if component.path.is_file():
        file_count = 1
        total_bytes = component.path.stat().st_size
    else:
        for path in component.path.rglob("*"):
            if path.is_file():
                file_count += 1
                total_bytes += path.stat().st_size
    return {
        "name": component.name,
        "source_path": str(component.path),
        "kind": "file" if component.path.is_file() else "directory",
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def _install_readme(artifact_id: str, github_repo: str) -> str:
    repo_arg = " --repo %s" % github_repo if github_repo else ""
    return "\n".join(
        [
            "# Kernel Corpus Release %s" % artifact_id,
            "",
            "This release contains a split Kernel Corpus runtime data package.",
            "It is required runtime data for the PseudoForge Kernel Corpus MCP server.",
            "",
            "## Download",
            "",
            "```powershell",
            "gh release download %s%s --dir .\\%s" % (artifact_id, repo_arg, artifact_id),
            "```",
            "",
            "## Verify",
            "",
            "```powershell",
            "Get-FileHash .\\%s\\* -Algorithm SHA256" % artifact_id,
            "Get-Content .\\%s\\checksums.sha256" % artifact_id,
            "```",
            "",
            "Compare the computed hashes with `checksums.sha256`.",
            "",
            "## Reassemble And Extract",
            "",
            "```powershell",
            "Set-Location .\\%s" % artifact_id,
            *_install_commands(artifact_id),
            "```",
            "",
            "Expected pack root after extraction:",
            "",
            "```text",
            "F:\\pseudoforge-corpora\\%s\\kernel-pack" % artifact_id,
            "```",
            "",
            "## Configure MCP",
            "",
            "```powershell",
            'python -B .\\tools\\kernel_corpus\\install_wiring.py mcp-config --pack-root "F:\\pseudoforge-corpora\\%s\\kernel-pack"'
            % artifact_id,
            "```",
            "",
        ]
    )


def _install_commands(artifact_id: str) -> list[str]:
    return [
        '$InstallRoot = "F:\\pseudoforge-corpora"',
        "New-Item -ItemType Directory -Force $InstallRoot | Out-Null",
        'cmd /c copy /b "%s.tar.gz.*" "%s.tar.gz"' % (artifact_id, artifact_id),
        'tar -xzf "%s.tar.gz" -C $InstallRoot' % artifact_id,
    ]


def _write_split_tar_gz(
    archive_base: Path,
    artifact_id: str,
    components: list[Component],
    manifest_path: Path,
    readme_path: Path,
    volume_bytes: int,
    compression_level: int,
) -> list[Path]:
    for old_part in archive_base.parent.glob(archive_base.name + ".*"):
        if old_part.is_file():
            old_part.unlink()
    with SplitVolumeWriter(archive_base, volume_bytes) as split_writer:
        with gzip.GzipFile(filename=archive_base.name, mode="wb", compresslevel=compression_level, fileobj=split_writer) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w|") as archive:
                _add_file(archive, manifest_path, "%s/%s" % (artifact_id, MANIFEST_NAME))
                _add_file(archive, readme_path, "%s/%s" % (artifact_id, README_NAME))
                for component in components:
                    _add_path(archive, component.path, "%s/%s" % (artifact_id, component.name))
    return split_writer.parts


def _add_path(archive: tarfile.TarFile, path: Path, arcname: str) -> None:
    if path.is_file():
        _add_file(archive, path, arcname)
        return
    root = path
    for child in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if child.is_dir():
            continue
        _add_file(archive, child, "%s/%s" % (arcname, child.relative_to(root).as_posix()))


def _add_file(archive: tarfile.TarFile, path: Path, arcname: str) -> None:
    archive.add(path, arcname=arcname, recursive=False)


def _write_checksums(path: Path, files: list[Path]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    lines: list[str] = []
    for file_path in files:
        digest = _file_sha256(file_path)
        size = file_path.stat().st_size
        entries.append({"name": file_path.name, "sha256": digest, "size": size})
        lines.append("%s  %s" % (digest, file_path.name))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return entries


def _file_payload(path: Path) -> dict[str, Any]:
    return {
        "name": path.name,
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": _file_sha256(path),
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _release_command(artifact_id: str, github_repo: str, output_dir: Path) -> str:
    repo_arg = " --repo %s" % github_repo if github_repo else ""
    return (
        'gh release create %s%s --title "Kernel Corpus %s" '
        '--notes-file "%s" "%s" "%s" "%s"'
    ) % (
        artifact_id,
        repo_arg,
        artifact_id,
        output_dir / README_NAME,
        output_dir / (artifact_id + ".tar.gz.*"),
        output_dir / MANIFEST_NAME,
        output_dir / CHECKSUMS_NAME,
    )


def _resolve_output_dir(path: str | Path) -> Path:
    item = Path(path)
    if item.is_absolute():
        return item
    return ROOT / item


def _validate_artifact_id(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise KernelCorpusError("Artifact id is required.")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(char not in allowed for char in text):
        raise KernelCorpusError("Artifact id contains unsupported characters: %s" % value)
    if text.startswith(".") or text.endswith("."):
        raise KernelCorpusError("Artifact id must not start or end with a dot: %s" % value)
    return text


def _safe_component_name(value: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    cleaned = "".join(char if char in allowed else "_" for char in value).strip("._")
    return cleaned or "path"


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _git_commit(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return completed.stdout.strip()


class SplitVolumeWriter:
    def __init__(self, base_path: Path, volume_bytes: int) -> None:
        self.base_path = base_path
        self.volume_bytes = volume_bytes
        self.parts: list[Path] = []
        self._handle: BinaryIO | None = None
        self._part_index = 0
        self._part_size = 0
        self._total_size = 0

    def __enter__(self) -> "SplitVolumeWriter":
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        self._open_next_part()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._total_size

    def write(self, data: bytes | bytearray | memoryview) -> int:
        view = memoryview(data)
        total = len(view)
        offset = 0
        while offset < total:
            if self._handle is None:
                self._open_next_part()
            remaining = self.volume_bytes - self._part_size
            if remaining <= 0:
                self._open_next_part()
                remaining = self.volume_bytes
            chunk_size = min(remaining, total - offset)
            chunk = view[offset : offset + chunk_size]
            assert self._handle is not None
            self._handle.write(chunk)
            self._part_size += chunk_size
            self._total_size += chunk_size
            offset += chunk_size
        return total

    def flush(self) -> None:
        if self._handle is not None:
            self._handle.flush()

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _open_next_part(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._part_index += 1
        self._part_size = 0
        part_path = self.base_path.with_name("%s.%03d" % (self.base_path.name, self._part_index))
        self.parts.append(part_path)
        self._handle = part_path.open("wb")


if __name__ == "__main__":
    raise SystemExit(main())
