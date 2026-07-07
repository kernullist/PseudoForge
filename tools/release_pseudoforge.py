from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path


SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
VERSION_ASSIGNMENT_RE = re.compile(r'(?m)^VERSION\s*=\s*"(?P<version>\d+\.\d+\.\d+)"\s*$')
DOC_VERSION_RE = re.compile(r"Current plugin version: `(?P<version>\d+\.\d+\.\d+)`\.")
PACKAGE_ENTRIES = (
    Path("pseudoforge.py"),
    Path("ida-plugin.json"),
    Path("ida_pseudoforge"),
    Path("tools/kernel_corpus"),
    Path("README.md"),
)
SKIPPED_DIR_NAMES = {"__pycache__", ".pytest_cache"}
SKIPPED_SUFFIXES = {".pyc", ".pyo"}


@dataclass(frozen=True)
class ReleaseResult:
    old_version: str
    new_version: str
    archive_path: Path
    sha256: str
    file_count: int


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    try:
        result = prepare_release(
            repo_root=repo_root,
            bump=args.bump,
            explicit_version=args.version,
            output_dir=Path(args.output_dir),
            no_version_bump=args.no_version_bump,
            dry_run=args.dry_run,
        )
    except ReleaseError as exc:
        print("PseudoForge release failed: %s" % exc, file=sys.stderr)
        return 1

    if args.dry_run:
        print("PseudoForge release dry run")
    else:
        print("PseudoForge release complete")
    print("Old version: %s" % result.old_version)
    print("New version: %s" % result.new_version)
    print("Archive: %s" % result.archive_path)
    print("SHA256: %s" % result.sha256)
    print("Files: %d" % result.file_count)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bump the PseudoForge plugin version and package installable release files."
    )
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--output-dir", default="release")
    parser.add_argument("--bump", choices=("patch", "minor", "major"), default="patch")
    parser.add_argument("--version", default="", help="Set an explicit x.y.z version instead of using --bump.")
    parser.add_argument(
        "--no-version-bump",
        action="store_true",
        help="Package the current version without modifying version files.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the planned release without writing files.")
    return parser


def prepare_release(
    repo_root: Path,
    bump: str = "patch",
    explicit_version: str = "",
    output_dir: Path | str = "release",
    no_version_bump: bool = False,
    dry_run: bool = False,
) -> ReleaseResult:
    version_file = repo_root / "ida_pseudoforge" / "version.py"
    manifest_file = repo_root / "ida-plugin.json"
    readme_file = repo_root / "README.md"
    status_file = repo_root / "pseudoforge_implementation_status.md"

    old_version = read_runtime_version(version_file)
    manifest_version = read_manifest_version(manifest_file)
    if old_version != manifest_version:
        raise ReleaseError(
            "Runtime version %s does not match ida-plugin.json version %s" % (old_version, manifest_version)
        )

    if no_version_bump and explicit_version:
        raise ReleaseError("--version cannot be used with --no-version-bump")
    new_version = old_version if no_version_bump else resolve_new_version(old_version, bump, explicit_version)

    archive_dir = _resolve_output_dir(repo_root, output_dir)
    archive_path = archive_dir / ("PseudoForge-%s.zip" % new_version)
    package_files = package_file_list(repo_root)

    if dry_run:
        return ReleaseResult(
            old_version=old_version,
            new_version=new_version,
            archive_path=archive_path,
            sha256="",
            file_count=len(package_files),
        )

    if not no_version_bump:
        write_runtime_version(version_file, new_version)
        write_manifest_version(manifest_file, new_version)
        write_doc_version(readme_file, new_version)
        write_doc_version(status_file, new_version)

    archive_dir.mkdir(parents=True, exist_ok=True)
    file_count = write_release_zip(repo_root, archive_path, package_files)
    return ReleaseResult(
        old_version=old_version,
        new_version=new_version,
        archive_path=archive_path,
        sha256=file_sha256(archive_path),
        file_count=file_count,
    )


def read_runtime_version(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseError("Could not read %s: %s" % (path, exc)) from exc
    match = VERSION_ASSIGNMENT_RE.search(text)
    if match is None:
        raise ReleaseError("Could not find VERSION assignment in %s" % path)
    return validate_version(match.group("version"))


def write_runtime_version(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = VERSION_ASSIGNMENT_RE.subn('VERSION = "%s"' % validate_version(version), text, count=1)
    if count != 1:
        raise ReleaseError("Could not update VERSION assignment in %s" % path)
    path.write_text(updated, encoding="utf-8")


def read_manifest_version(path: Path) -> str:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError("Could not read %s: %s" % (path, exc)) from exc
    try:
        return validate_version(str(manifest["plugin"]["version"]))
    except KeyError as exc:
        raise ReleaseError("%s has no plugin.version field" % path) from exc


def write_manifest_version(path: Path, version: str) -> None:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError("Could not read %s: %s" % (path, exc)) from exc
    manifest.setdefault("plugin", {})["version"] = validate_version(version)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_doc_version(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = DOC_VERSION_RE.subn("Current plugin version: `%s`." % validate_version(version), text, count=1)
    if count != 1:
        raise ReleaseError("Could not update current plugin version in %s" % path)
    path.write_text(updated, encoding="utf-8")


def resolve_new_version(old_version: str, bump: str, explicit_version: str = "") -> str:
    if explicit_version:
        new_version = validate_version(explicit_version)
        if _version_tuple(new_version) <= _version_tuple(old_version):
            raise ReleaseError("Explicit version %s must be greater than current version %s" % (new_version, old_version))
        return new_version
    return bump_version(old_version, bump)


def bump_version(version: str, bump: str) -> str:
    major, minor, patch = _version_tuple(validate_version(version))
    if bump == "patch":
        patch += 1
    elif bump == "minor":
        minor += 1
        patch = 0
    elif bump == "major":
        major += 1
        minor = 0
        patch = 0
    else:
        raise ReleaseError("Unsupported version bump: %s" % bump)
    return "%d.%d.%d" % (major, minor, patch)


def validate_version(version: str) -> str:
    if SEMVER_RE.match(version or "") is None:
        raise ReleaseError("Version must use x.y.z numeric form: %s" % version)
    return version


def package_file_list(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for entry in PACKAGE_ENTRIES:
        path = repo_root / entry
        if not path.exists():
            raise ReleaseError("Release package entry is missing: %s" % entry)
        if path.is_file():
            files.append(path)
            continue
        for child in sorted(path.rglob("*")):
            if child.is_dir():
                continue
            if should_skip_package_file(child):
                continue
            files.append(child)
    return sorted(files, key=lambda item: item.relative_to(repo_root).as_posix())


def should_skip_package_file(path: Path) -> bool:
    if any(part in SKIPPED_DIR_NAMES for part in path.parts):
        return True
    return path.suffix.lower() in SKIPPED_SUFFIXES


def write_release_zip(repo_root: Path, archive_path: Path, files: list[Path]) -> int:
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(repo_root).as_posix())
    return len(files)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _resolve_output_dir(repo_root: Path, output_dir: Path | str) -> Path:
    path = Path(output_dir)
    if not path.is_absolute():
        path = repo_root / path
    return path


def _version_tuple(version: str) -> tuple[int, int, int]:
    match = SEMVER_RE.match(version)
    if match is None:
        raise ReleaseError("Version must use x.y.z numeric form: %s" % version)
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


class ReleaseError(RuntimeError):
    pass


if __name__ == "__main__":
    raise SystemExit(main())
