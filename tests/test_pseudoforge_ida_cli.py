from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools import pseudoforge_ida_cli


class _FakeProcess:
    pid = 1234

    def __init__(self) -> None:
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


class PseudoForgeIdaCliTests(unittest.TestCase):
    def test_ida_cli_builds_batch_args_with_plugin_llm_and_export_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida64.exe"
            idb_path = temp_path / "driver.sys.i64"
            output_dir = temp_path / "out"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [
                    str(ida_path),
                    str(idb_path),
                    str(output_dir),
                    "--name-regex",
                    "^DriverEntry$",
                    "--max-functions",
                    "1",
                    "--no-pdb",
                ]
            )

            run = pseudoforge_ida_cli._prepare_run(args)

            self.assertIn("--export-dir", run.batch_args)
            self.assertIn(str(output_dir / "functions"), run.batch_args)
            self.assertIn("--corpus-metadata", run.batch_args)
            self.assertIn(str(output_dir / "pseudoforge-corpus-metadata.json"), run.batch_args)
            self.assertIn("--llm-renames-auto", run.batch_args)
            self.assertIn("--require-configured-llm", run.batch_args)
            self.assertIn("--overwrite-forge", run.batch_args)
            self.assertIn("-Opdb:off", run.ida_args)
            self.assertTrue(any(item.startswith("-S") for item in run.ida_args))
            self.assertEqual(output_dir / "pseudoforge-ida-cancel.txt", run.cancel_file)
            self.assertIn("--cancel-file", run.batch_args)
            self.assertIn(str(output_dir / "pseudoforge-ida-cancel.txt"), run.batch_args)

    def test_ida_cli_allow_no_llm_omits_required_llm_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida.exe"
            idb_path = temp_path / "sample.idb"
            output_dir = temp_path / "out"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [str(ida_path), str(idb_path), str(output_dir), "--allow-no-llm"]
            )

            run = pseudoforge_ida_cli._prepare_run(args)

            self.assertIn("--llm-renames-auto", run.batch_args)
            self.assertNotIn("--require-configured-llm", run.batch_args)

    def test_ida_cli_upsert_forge_does_not_overwrite_existing_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida.exe"
            idb_path = temp_path / "sample.idb"
            output_dir = temp_path / "out"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [str(ida_path), str(idb_path), str(output_dir), "--upsert-forge"]
            )

            run = pseudoforge_ida_cli._prepare_run(args)

            self.assertIn("--upsert-forge", run.batch_args)
            self.assertNotIn("--overwrite-forge", run.batch_args)

    def test_ida_cli_rejects_resume_with_upsert_forge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida.exe"
            idb_path = temp_path / "sample.idb"
            output_dir = temp_path / "out"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [str(ida_path), str(idb_path), str(output_dir), "--resume", "--upsert-forge"]
            )

            with self.assertRaisesRegex(RuntimeError, "--resume"):
                pseudoforge_ida_cli._prepare_run(args)

    def test_ida_cli_forwards_exact_ea_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida64.exe"
            idb_path = temp_path / "driver.sys.i64"
            output_dir = temp_path / "out"
            ea_file = temp_path / "failed-eas.txt"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            ea_file.write_text("0x140200008\n", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [
                    str(ida_path),
                    str(idb_path),
                    str(output_dir),
                    "--ea",
                    "0x140291E88",
                    "--ea-file",
                    str(ea_file),
                    "--no-pdb",
                ]
            )

            run = pseudoforge_ida_cli._prepare_run(args)

            self.assertIn("--ea", run.batch_args)
            self.assertIn("0x140291E88", run.batch_args)
            self.assertIn("--ea-file", run.batch_args)
            self.assertIn(str(ea_file), run.batch_args)

    def test_ida_cli_uses_explicit_cancel_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida64.exe"
            idb_path = temp_path / "driver.sys.i64"
            output_dir = temp_path / "out"
            cancel_file = temp_path / "stop-now.txt"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [
                    str(ida_path),
                    str(idb_path),
                    str(output_dir),
                    "--cancel-file",
                    str(cancel_file),
                ]
            )

            run = pseudoforge_ida_cli._prepare_run(args)

            self.assertEqual(cancel_file, run.cancel_file)
            self.assertFalse(run.cancel_file_is_default)
            self.assertIn("--cancel-file", run.batch_args)
            self.assertIn(str(cancel_file), run.batch_args)

    def test_ida_cli_pdb_path_sets_child_symbol_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida64.exe"
            idb_path = temp_path / "driver.sys.i64"
            output_dir = temp_path / "out"
            pdb_dir = temp_path / "symbols"
            pdb_file = temp_path / "build" / "driver.pdb"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            pdb_dir.mkdir()
            pdb_file.parent.mkdir()
            pdb_file.write_text("", encoding="utf-8")
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [
                    str(ida_path),
                    str(idb_path),
                    str(output_dir),
                    "--pdb-path",
                    str(pdb_dir),
                    "--pdb-path",
                    str(pdb_file),
                    "--symbol-path",
                    r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
                ]
            )

            run = pseudoforge_ida_cli._prepare_run(args)

            self.assertIsNotNone(run.ida_env)
            self.assertIn(str(pdb_dir), run.pdb_symbol_path)
            self.assertIn(str(pdb_file.parent), run.pdb_symbol_path)
            self.assertIn(r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols", run.pdb_symbol_path)
            self.assertEqual(run.pdb_symbol_path, run.ida_env["_NT_SYMBOL_PATH"])
            self.assertEqual(run.pdb_alt_symbol_path, run.ida_env["_NT_ALT_SYMBOL_PATH"])

    def test_ida_cli_rejects_pdb_paths_when_pdb_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida64.exe"
            idb_path = temp_path / "driver.sys.i64"
            output_dir = temp_path / "out"
            pdb_dir = temp_path / "symbols"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            pdb_dir.mkdir()
            args = pseudoforge_ida_cli._build_parser().parse_args(
                [
                    str(ida_path),
                    str(idb_path),
                    str(output_dir),
                    "--no-pdb",
                    "--pdb-path",
                    str(pdb_dir),
                ]
            )

            with self.assertRaisesRegex(RuntimeError, "--no-pdb"):
                pseudoforge_ida_cli._prepare_run(args)

    def test_ida_cli_dry_run_writes_manifest_without_starting_ida(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            ida_path = temp_path / "ida64.exe"
            idb_path = temp_path / "target.i64"
            output_dir = temp_path / "out"
            ida_path.write_text("", encoding="utf-8")
            idb_path.write_text("", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = pseudoforge_ida_cli.main(
                    [str(ida_path), str(idb_path), str(output_dir), "--dry-run"]
                )

            manifest_path = output_dir / "pseudoforge-ida-run.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

            self.assertEqual(exit_code, 0)
            self.assertEqual("", stderr.getvalue())
            self.assertEqual("dry_run", manifest["status"])
            self.assertEqual("plugin_config", manifest["llm"]["mode"])
            self.assertTrue(manifest["llm"]["required"])
            self.assertTrue(manifest["pdb"]["enabled"])
            self.assertFalse(manifest["pdb"]["disabled"])
            self.assertEqual(
                str(output_dir / "pseudoforge-corpus-index.json"),
                manifest["corpus_index_path"],
            )
            self.assertEqual(
                str(output_dir / "pseudoforge-corpus-overview.md"),
                manifest["corpus_overview_path"],
            )
            self.assertEqual(
                str(output_dir / "pseudoforge-ida-cancel.txt"),
                manifest["cancel_file"],
            )
            self.assertIn("Dry run", stdout.getvalue())

    def test_ida_cli_progress_monitor_prints_current_function(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "run.jsonl"
            monitor = pseudoforge_ida_cli._ReportProgressMonitor(report_path)
            report_path.write_text(
                json.dumps(
                    {
                        "event": "progress",
                        "phase": "function_start",
                        "index": 3,
                        "selected_functions": 51,
                        "ea": "0x140001000",
                        "name": "DriverEntry",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                monitor.poll()

            self.assertIn("Analyzing 3/51: DriverEntry (0x140001000)", stdout.getvalue())

    def test_ida_cli_interrupt_request_writes_cancel_file_and_kills_hung_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cancel_file = Path(temp_dir) / "nested" / "cancel.txt"
            report_path = Path(temp_dir) / "missing.jsonl"
            monitor = pseudoforge_ida_cli._ReportProgressMonitor(report_path)
            process = _FakeProcess()
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                exit_code = pseudoforge_ida_cli._request_process_stop(
                    process,
                    cancel_file,
                    monitor,
                    cancel_timeout_seconds=0.0,
                    terminate_timeout_seconds=0.0,
                )

            self.assertIsNone(exit_code)
            self.assertTrue(cancel_file.exists())
            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)
            self.assertIn("Cancel file:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
