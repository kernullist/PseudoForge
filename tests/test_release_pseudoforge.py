import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path

import ida_pseudoforge
from ida_pseudoforge.version import PLUGIN_NAME, VERSION, plugin_title
from tools import release_pseudoforge


class ReleasePseudoForgeTests(unittest.TestCase):
    def test_plugin_version_matches_manifest(self):
        manifest_path = Path(__file__).resolve().parents[1] / "ida-plugin.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(VERSION, manifest["plugin"]["version"])
        self.assertEqual(VERSION, ida_pseudoforge.__version__)
        self.assertEqual("PseudoForge", PLUGIN_NAME)
        self.assertEqual("PseudoForge %s" % VERSION, plugin_title())

    def test_bump_version(self):
        self.assertEqual("1.2.4", release_pseudoforge.bump_version("1.2.3", "patch"))
        self.assertEqual("1.3.0", release_pseudoforge.bump_version("1.2.3", "minor"))
        self.assertEqual("2.0.0", release_pseudoforge.bump_version("1.2.3", "major"))

    def test_prepare_release_bumps_versions_and_writes_zip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")

            result = release_pseudoforge.prepare_release(repo_root, output_dir="release")

            self.assertEqual(result.old_version, "0.1.0")
            self.assertEqual(result.new_version, "0.1.1")
            self.assertEqual(result.archive_path.name, "PseudoForge-0.1.1.zip")
            self.assertTrue(result.archive_path.exists())
            self.assertEqual(64, len(result.sha256))
            self.assertIn('VERSION = "0.1.1"', (repo_root / "ida_pseudoforge" / "version.py").read_text())
            manifest = json.loads((repo_root / "ida-plugin.json").read_text(encoding="utf-8"))
            self.assertEqual("0.1.1", manifest["plugin"]["version"])
            self.assertIn("Current plugin version: `0.1.1`.", (repo_root / "README.md").read_text())
            self.assertIn(
                "Current plugin version: `0.1.1`.",
                (repo_root / "pseudoforge_implementation_status.md").read_text(),
            )
            with zipfile.ZipFile(result.archive_path) as archive:
                names = set(archive.namelist())
            self.assertIn("pseudoforge.py", names)
            self.assertIn("ida-plugin.json", names)
            self.assertIn("ida_pseudoforge/version.py", names)
            self.assertIn("tools/kernel_corpus/mcp_server.py", names)
            self.assertIn("README.md", names)
            self.assertNotIn("ida_pseudoforge/__pycache__/ignored.pyc", names)
            self.assertNotIn("tests/not_packaged.py", names)
            self.assertNotIn("tools/not_packaged.py", names)

    def test_current_release_package_contains_runtime_domain_profiles_and_mcp_tools(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            result = release_pseudoforge.prepare_release(
                repo_root,
                output_dir=temp_path,
                no_version_bump=True,
            )
            extract_dir = temp_path / "installed"
            with zipfile.ZipFile(result.archive_path) as archive:
                names = set(archive.namelist())
                archive.extractall(extract_dir)
            expected_profile_root = str((extract_dir / "ida_pseudoforge" / "profiles").resolve())

            domain_profiles = sorted(
                name
                for name in names
                if name.startswith("ida_pseudoforge/profiles/domain_identity/")
                and name.endswith(".json")
            )

            self.assertIn("pseudoforge.py", names)
            self.assertIn("ida-plugin.json", names)
            self.assertIn("ida_pseudoforge/core/contract_packs.py", names)
            self.assertIn("ida_pseudoforge/core/domain_identity.py", names)
            self.assertIn("ida_pseudoforge/profiles/domain_packs_manifest.json", names)
            self.assertIn("ida_pseudoforge/profiles/profiles_manifest.json", names)
            self.assertIn("ida_pseudoforge/profiles/subsystem_identity_index.json", names)
            self.assertIn("ida_pseudoforge/profiles/contracts/win_user_api_contracts.json", names)
            self.assertIn("ida_pseudoforge/profiles/contracts/linux_user_api_contracts.json", names)
            self.assertIn("ida_pseudoforge/profiles/contracts/cxx_runtime_contracts.json", names)
            self.assertIn("ida_pseudoforge/profiles/contracts/uefi_api_contracts.json", names)
            self.assertIn("ida_pseudoforge/profiles/contracts/macos_macho_api_contracts.json", names)
            self.assertIn("tools/kernel_corpus/mcp_server.py", names)
            self.assertIn("tools/kernel_corpus/query.py", names)
            self.assertIn("tools/kernel_corpus/store.py", names)
            self.assertIn("tools/kernel_corpus/schema.py", names)
            self.assertIn("tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md", names)
            self.assertGreater(len(domain_profiles), 0)
            self.assertFalse(any(name.startswith("tools/") and not name.startswith("tools/kernel_corpus/") for name in names))
            self.assertFalse(any(name.startswith("tests/") for name in names))
            self.assertFalse(
                any(name.startswith("tests/fixtures/general_binaries/") for name in names)
            )
            self.assertFalse(
                any(name.startswith("tests/fixtures/general_corpus/") for name in names)
            )

            smoke = _run_packaged_runtime_smoke(extract_dir)

        self.assertTrue(smoke["domain_profiles_available"])
        self.assertEqual(expected_profile_root, smoke["profile_root"])
        self.assertGreater(smoke["domain_profile_count"], 0)
        self.assertEqual(
            [
                "cxx_runtime",
                "firmware_uefi",
                "generic_core",
                "linux_elf_user",
                "macos_macho_user",
                "win_user_pe",
                "windows_kernel",
            ],
            smoke["active_domain_pack_ids"],
        )
        self.assertGreaterEqual(smoke["contract_profile_count"], 5)
        self.assertEqual(0, smoke["user_contract_comment_count"])
        self.assertGreater(smoke["domain_pack_manifest_count"], 0)
        self.assertEqual("I/O Manager", smoke["io_manager_subsystem"])
        self.assertEqual(1, smoke["type_correction_count"])
        self.assertEqual("windows.io_manager.delete_device", smoke["type_correction_profile"])
        self.assertTrue(smoke["type_corrected_signature"])
        self.assertTrue(smoke["type_corrected_body_cast_removed"])
        self.assertFalse(smoke["type_correction_apply_to_idb"])
        self.assertIn("tools.kernel_corpus.schema", smoke["tools_modules"])
        self.assertEqual("kernel_corpus_pack_v2", smoke["kernel_corpus_pack_schema"])

    def test_prepare_release_no_version_bump_packages_current_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")

            result = release_pseudoforge.prepare_release(repo_root, no_version_bump=True)

            self.assertEqual(result.old_version, "0.1.0")
            self.assertEqual(result.new_version, "0.1.0")
            self.assertEqual(result.archive_path.name, "PseudoForge-0.1.0.zip")
            self.assertIn('VERSION = "0.1.0"', (repo_root / "ida_pseudoforge" / "version.py").read_text())

    def test_prepare_release_rejects_manifest_runtime_version_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")
            manifest_path = repo_root / "ida-plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["plugin"]["version"] = "0.2.0"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(release_pseudoforge.ReleaseError, "does not match"):
                release_pseudoforge.prepare_release(repo_root)

    def test_prepare_release_dry_run_does_not_write_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = _write_minimal_repo(Path(temp_dir), "0.1.0")

            result = release_pseudoforge.prepare_release(repo_root, dry_run=True)

            self.assertEqual(result.new_version, "0.1.1")
            self.assertFalse(result.archive_path.exists())
            self.assertEqual("", result.sha256)
            self.assertIn('VERSION = "0.1.0"', (repo_root / "ida_pseudoforge" / "version.py").read_text())


def _run_packaged_runtime_smoke(package_root: Path) -> dict[str, object]:
    script = textwrap.dedent(
        """
        import json
        import sys

        import pseudoforge
        import ida_pseudoforge.ida.plugin
        import ida_pseudoforge.ida.actions
        from ida_pseudoforge.core.capture import capture_from_pseudocode
        from ida_pseudoforge.core.domain_identity import domain_identity_profiles_available
        from ida_pseudoforge.core.lvar_analysis import build_clean_plan
        from ida_pseudoforge.core.render import render_cleaned_pseudocode
        from ida_pseudoforge.profiles import loader as profile_loader
        from tools.kernel_corpus.schema import PACK_SCHEMA_VERSION

        domain_profiles_available = domain_identity_profiles_available()
        io_manager_metadata = profile_loader.subsystem_identity_metadata("windows.io_manager.delete_device")
        pseudocode = (
            "void __stdcall IoDeleteDevice(__int64 a1)\\n"
            "{\\n"
            "  IopCompleteUnloadOrDelete((ULONG_PTR)a1);\\n"
            "}\\n"
        )
        capture = capture_from_pseudocode(
            pseudocode,
            source_path=r"D:\\bin\\os\\26200.8457\\ntoskrnl.exe.i64",
        )
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)
        type_correction = plan.type_corrections[0] if plan.type_corrections else None
        active_profiles = profile_loader.active_profile_names()
        active_domain_pack_ids = profile_loader.active_domain_pack_ids()
        domain_pack_manifests = profile_loader.active_domain_pack_manifests()
        domain_pack_manifest_count = len(domain_pack_manifests)
        domain_profile_names = [
            name
            for name in active_profiles
            if name.startswith("domain_identity/")
        ]
        contract_profile_names = [
            name
            for manifest in domain_pack_manifests
            for name in manifest.get("profile_names", [])
            if str(name).startswith("contracts/")
        ]
        contract_comment_count = sum(
            1
            for item in plan.comments
            if isinstance(item, dict) and item.get("kind") == "contract_pack_api"
        )
        tools_modules = sorted(
            name
            for name in sys.modules
            if name == "tools" or name.startswith("tools.")
        )
        print(
            json.dumps(
                {
                    "domain_profiles_available": domain_profiles_available,
                    "active_domain_pack_ids": active_domain_pack_ids,
                    "domain_pack_manifest_count": domain_pack_manifest_count,
                    "domain_profile_count": len(domain_profile_names),
                    "contract_profile_count": len(contract_profile_names),
                    "user_contract_comment_count": contract_comment_count,
                    "io_manager_subsystem": io_manager_metadata.get("subsystem", ""),
                    "profile_root": profile_loader.active_profile_root(),
                    "type_corrected_signature": "void __stdcall IoDeleteDevice(PDEVICE_OBJECT deviceObject)" in rendered,
                    "type_corrected_body_cast_removed": (
                        "IopCompleteUnloadOrDelete(deviceObject);" in rendered
                        and "(ULONG_PTR)deviceObject" not in rendered
                        and "(ULONG_PTR)a1" not in rendered
                    ),
                    "type_correction_apply_to_idb": bool(type_correction.apply_to_idb) if type_correction else True,
                    "type_correction_count": len(plan.type_corrections),
                    "type_correction_profile": type_correction.profile_id if type_correction else "",
                    "tools_modules": tools_modules,
                    "kernel_corpus_pack_schema": PACK_SCHEMA_VERSION,
                },
                sort_keys=True,
            )
        )
        """
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PSEUDOFORGE_PROFILE_DIR", None)
    env["PYTHONNOUSERSITE"] = "1"
    result = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=str(package_root),
        env=env,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            "Packaged runtime smoke failed with exit code %d\nstdout:\n%s\nstderr:\n%s"
            % (result.returncode, result.stdout, result.stderr)
        )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise AssertionError("Packaged runtime smoke did not emit JSON output")
    return json.loads(lines[-1])


def _write_minimal_repo(root: Path, version: str) -> Path:
    package_root = root / "ida_pseudoforge"
    package_root.mkdir(parents=True)
    (package_root / "version.py").write_text(
        'from __future__ import annotations\n\nPLUGIN_NAME = "PseudoForge"\nVERSION = "%s"\n__version__ = VERSION\n'
        % version,
        encoding="utf-8",
    )
    (package_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    pycache = package_root / "__pycache__"
    pycache.mkdir()
    (pycache / "ignored.pyc").write_bytes(b"ignored")
    (root / "pseudoforge.py").write_text("def PLUGIN_ENTRY():\n    return None\n", encoding="utf-8")
    (root / "ida-plugin.json").write_text(
        json.dumps({"plugin": {"version": version}}, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("Current plugin version: `%s`.\n" % version, encoding="utf-8")
    (root / "pseudoforge_implementation_status.md").write_text(
        "Current plugin version: `%s`.\n" % version,
        encoding="utf-8",
    )
    tests_dir = root / "tests"
    tools_dir = root / "tools"
    tests_dir.mkdir()
    tools_dir.mkdir()
    kernel_corpus_dir = tools_dir / "kernel_corpus"
    kernel_corpus_dir.mkdir()
    (tests_dir / "not_packaged.py").write_text("", encoding="utf-8")
    (tools_dir / "not_packaged.py").write_text("", encoding="utf-8")
    (kernel_corpus_dir / "__init__.py").write_text("", encoding="utf-8")
    (kernel_corpus_dir / "mcp_server.py").write_text("", encoding="utf-8")
    (kernel_corpus_dir / "schema.py").write_text('PACK_SCHEMA_VERSION = "kernel_corpus_pack_v2"\n', encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
