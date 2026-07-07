from __future__ import annotations

import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from tools.pseudoforge_corpus_index import build_corpus_index
from tools import pseudoforge_corpus_qa
from tools.pseudoforge_corpus_qa import build_context_pack, retrieve_evidence


DRIVER_ENTRY_CLEANED = """
NTSTATUS __fastcall DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
  driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;
  PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
  return STATUS_SUCCESS;
}
"""


DEVICE_CONTROL_CLEANED = """
NTSTATUS __fastcall DeviceControlDispatch(PDEVICE_OBJECT deviceObject, PIRP irp)
{
  IO_STACK_LOCATION *stackLocation;
  ULONG ioControlCode;

  stackLocation = IoGetCurrentIrpStackLocation(irp);
  ioControlCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;
  switch ( ioControlCode )
  {
    case 0x91234000:
      return HandleReadRequest(irp);
    default:
      return STATUS_INVALID_DEVICE_REQUEST;
  }
}
"""


class CorpusIndexQaTests(unittest.TestCase):
    def test_corpus_index_builds_clusters_from_artifacts_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_sample_corpus(root)

            index = build_corpus_index(root)

            tags_by_name = {item["name"]: set(item["tags"]) for item in index["functions"]}
            cluster_tags = {item["tag"] for item in index["clusters"]}
            self.assertEqual(2, index["overview"]["functions"])
            self.assertIn("entrypoint", tags_by_name["DriverEntry"])
            self.assertIn("callback", tags_by_name["DriverEntry"])
            self.assertIn("ioctl", tags_by_name["DeviceControlDispatch"])
            self.assertIn("dispatch", tags_by_name["DeviceControlDispatch"])
            self.assertIn("ioctl", cluster_tags)
            device = next(item for item in index["functions"] if item["name"] == "DeviceControlDispatch")
            self.assertEqual("\\Device\\PseudoForge", device["data_refs"][0]["value"])
            self.assertIn("disassembly", device["artifacts"])
            self.assertTrue((root / "pseudoforge-corpus-index.json").exists())
            self.assertTrue((root / "pseudoforge-corpus-overview.md").exists())

    def test_corpus_index_handles_empty_output_without_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            index = build_corpus_index(root)

            self.assertEqual(0, index["overview"]["functions"])
            self.assertEqual({}, index["report_summary"])
            self.assertTrue((root / "pseudoforge-corpus-index.json").exists())
            self.assertTrue((root / "pseudoforge-corpus-overview.md").exists())

    def test_corpus_index_tolerates_malformed_optional_artifact_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_sample_corpus(root)
            bundle_dir = root / "functions" / "0000000140002000_DeviceControlDispatch"
            (bundle_dir / "DeviceControlDispatch.rename-map.json").write_text("[]", encoding="utf-8")
            (bundle_dir / "DeviceControlDispatch.rule-report.json").write_text("[]", encoding="utf-8")

            index = build_corpus_index(root)

            by_name = {item["name"]: item for item in index["functions"]}
            self.assertEqual(0, by_name["DeviceControlDispatch"]["counts"]["active_renames"])
            self.assertIn("ioctl", by_name["DeviceControlDispatch"]["tags"])

    def test_corpus_qa_retrieves_korean_query_and_builds_context_pack(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_sample_corpus(root)
            index = build_corpus_index(root)

            retrieved = retrieve_evidence(index, "IOCTL 디스패치 구조 알려줘", top=1)
            context = build_context_pack(index, "IOCTL 디스패치 구조 알려줘", retrieved)

            self.assertEqual("DeviceControlDispatch", retrieved[0]["name"])
            self.assertIn("tag:ioctl", retrieved[0]["reasons"])
            self.assertIn("0x140002000", context)
            self.assertIn("DeviceControlDispatch.cleaned.cpp", context)
            self.assertIn("Use only the evidence below", context)

    def test_corpus_qa_missing_index_fails_before_llm_provider_setup(self) -> None:
        old_builder = pseudoforge_corpus_qa._build_text_provider
        provider_calls = []
        pseudoforge_corpus_qa._build_text_provider = lambda args: provider_calls.append(args) or object()
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                exit_code = pseudoforge_corpus_qa.main(["missing-index.json", "question", "--llm"])
        finally:
            pseudoforge_corpus_qa._build_text_provider = old_builder

        self.assertEqual(1, exit_code)
        self.assertEqual([], provider_calls)
        self.assertIn("not found", stderr.getvalue())

    def test_corpus_qa_llm_provider_error_returns_clean_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_sample_corpus(root)
            index = build_corpus_index(root)
            index_path = Path(index["index_path"])
            old_builder = pseudoforge_corpus_qa._build_text_provider
            pseudoforge_corpus_qa._build_text_provider = lambda args: (_ for _ in ()).throw(
                RuntimeError("provider unavailable")
            )
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    exit_code = pseudoforge_corpus_qa.main([str(index_path), "IOCTL?", "--llm"])
            finally:
                pseudoforge_corpus_qa._build_text_provider = old_builder

            self.assertEqual(1, exit_code)
            self.assertIn("provider unavailable", stderr.getvalue())


def _write_sample_corpus(root: Path) -> None:
    functions_dir = root / "functions"
    entry_dir = functions_dir / "0000000140001000_DriverEntry"
    ioctl_dir = functions_dir / "0000000140002000_DeviceControlDispatch"
    entry_dir.mkdir(parents=True)
    ioctl_dir.mkdir(parents=True)
    _write_function_bundle(
        entry_dir,
        "DriverEntry",
        "0x140001000",
        DRIVER_ENTRY_CLEANED,
        warnings=[],
        buffer_contracts=[],
    )
    _write_function_bundle(
        ioctl_dir,
        "DeviceControlDispatch",
        "0x140002000",
        DEVICE_CONTROL_CLEANED,
        warnings=["review IOCTL access"],
        buffer_contracts=[{"command_value": 0x91234000, "command_name": "IOCTL_SAMPLE"}],
    )
    (root / "pseudoforge-corpus-metadata.json").write_text(
        json.dumps(
            {
                "schema": "pseudoforge_corpus_metadata_v1",
                "idb_path": "sample.i64",
                "target_path": "sample.sys",
                "image_base": "0x140000000",
                "processor": "metapc",
                "segments": [{"name": ".text", "start_ea": "0x140001000", "end_ea": "0x140010000"}],
                "imports": [
                    {"ea": "0x180001000", "module": "ntoskrnl.exe", "name": "IoGetCurrentIrpStackLocation"},
                    {"ea": "0x180002000", "module": "ntoskrnl.exe", "name": "PsSetCreateProcessNotifyRoutine"},
                ],
                "exports": [{"ea": "0x140001000", "name": "DriverEntry", "ordinal": 1}],
                "strings": [{"ea": "0x140020000", "value": "\\Device\\PseudoForge"}],
                "functions": [
                    {
                        "ea": "0x140001000",
                        "name": "DriverEntry",
                        "callee_eas": ["0x140002000"],
                        "callee_names": ["DeviceControlDispatch"],
                        "caller_eas": [],
                        "caller_names": [],
                        "imports_called": [
                            {"ea": "0x180002000", "module": "ntoskrnl.exe", "name": "PsSetCreateProcessNotifyRoutine"}
                        ],
                        "strings_referenced": [],
                    },
                    {
                        "ea": "0x140002000",
                        "name": "DeviceControlDispatch",
                        "callee_eas": [],
                        "callee_names": [],
                        "caller_eas": ["0x140001000"],
                        "caller_names": ["DriverEntry"],
                        "imports_called": [
                            {"ea": "0x180001000", "module": "ntoskrnl.exe", "name": "IoGetCurrentIrpStackLocation"}
                        ],
                        "strings_referenced": [{"ea": "0x140020000", "value": "\\Device\\PseudoForge"}],
                        "data_refs": [
                            {
                                "source_ea": "0x140002010",
                                "target_ea": "0x140020000",
                                "target_name": "aDevicePseudoForge",
                                "segment": ".rdata",
                                "ref_kind": "string",
                                "value": "\\Device\\PseudoForge",
                                "source_text": "lea rcx, aDevicePseudoForge",
                            }
                        ],
                        "data_ref_count": 1,
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / "sample_20260606.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"event": "function", "status": "ok", "ea": "0x140001000", "name": "DriverEntry"}),
                json.dumps({"event": "function", "status": "ok", "ea": "0x140002000", "name": "DeviceControlDispatch"}),
                json.dumps({"event": "summary", "processed": 2, "succeeded": 2, "skipped": 0, "failed": 0}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_function_bundle(
    directory: Path,
    name: str,
    ea: str,
    cleaned: str,
    warnings: list[str],
    buffer_contracts: list[dict[str, object]],
) -> None:
    cleaned_path = directory / ("%s.cleaned.cpp" % name)
    disasm_path = directory / ("%s.disasm.asm" % name)
    raw_path = directory / ("%s.raw.cpp" % name)
    rename_map_path = directory / ("%s.rename-map.json" % name)
    warnings_path = directory / ("%s.warnings.json" % name)
    buffer_contracts_path = directory / ("%s.buffer-contracts.json" % name)
    rule_report_path = directory / ("%s.rule-report.json" % name)
    summary_path = directory / ("%s.ida-batch-summary.json" % name)
    cleaned_path.write_text(cleaned, encoding="utf-8")
    disasm_path.write_text("; disassembly for %s\n" % name, encoding="utf-8")
    raw_path.write_text(cleaned, encoding="utf-8")
    rename_map_path.write_text(json.dumps({"renames": []}), encoding="utf-8")
    warnings_path.write_text(json.dumps(warnings), encoding="utf-8")
    buffer_contracts_path.write_text(json.dumps(buffer_contracts), encoding="utf-8")
    rule_report_path.write_text(json.dumps({"matched_rules": []}), encoding="utf-8")
    summary_path.write_text(
        json.dumps(
            {
                "mode": "ida_batch_export",
                "function": name,
                "function_ea": ea,
                "source_path": "sample.sys",
                "rename_candidates": 0,
                "renames": 0,
                "flow_rewrites": 0,
                "buffer_contracts": len(buffer_contracts),
                "warnings": len(warnings),
                "rule_diagnostics": {"matched_rules": 0},
                "llm_status": "ok",
                "artifacts": {
                    "cleaned_pseudocode": str(cleaned_path),
                    "disassembly": str(disasm_path),
                    "raw_pseudocode": str(raw_path),
                    "rename_map": str(rename_map_path),
                    "warnings": str(warnings_path),
                    "buffer_contracts": str(buffer_contracts_path),
                    "rule_report": str(rule_report_path),
                    "summary": str(summary_path),
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
