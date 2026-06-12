from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.kernel_corpus import builder
from tools.kernel_corpus.atlas import SUBSYSTEMS, generate_atlas, main
from tools.kernel_corpus.lifecycle import trace_lifecycle


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"
EXPECTED_PAGES = {
    "process.md",
    "thread.md",
    "object-manager.md",
    "memory.md",
    "io-manager.md",
    "registry.md",
    "security.md",
    "etw-wmi.md",
    "driver-load-unload.md",
}


class KernelCorpusAtlasTests(unittest.TestCase):
    def test_generate_atlas_writes_expected_pages(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"

            result = generate_atlas(pack_root, output_dir, limit=8)

            self.assertTrue(result["ok"])
            self.assertEqual(len(SUBSYSTEMS), result["page_count"])
            self.assertEqual(EXPECTED_PAGES, {item["filename"] for item in result["pages"]})
            for filename in EXPECTED_PAGES:
                self.assertTrue((output_dir / filename).is_file(), filename)

    def test_each_page_contains_corpus_identity(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            for filename in EXPECTED_PAGES:
                text = (output_dir / filename).read_text(encoding="utf-8")
                self.assertIn("## Corpus Identity", text)
                self.assertIn("Pack root:", text)
                self.assertIn("Schema: `kernel_corpus_pack_v1`", text)
                self.assertIn("Target: `minimal.i64`", text)
                self.assertIn("Functions: `3`", text)
                self.assertIn("Manifest:", text)
                self.assertIn("SQLite:", text)

    def test_function_evidence_contains_ea_and_artifact_path(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "process.md").read_text(encoding="utf-8")
            self.assertIn("`0x140001000` `NtCreateUserProcess`", text)
            self.assertIn("function.ida-batch-summary.json", text)
            self.assertIn("function.cleaned.cpp", text)
            self.assertIn(str((FIXTURE_ROOT / "functions").resolve()), text)

    def test_missing_subsystem_data_has_clear_gap_section(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "registry.md").read_text(encoding="utf-8")
            self.assertIn("## Gaps And Uncertainty", text)
            self.assertIn("No high-signal functions matched", text)
            self.assertIn("- No matching functions selected.", text)

    def test_lifecycle_pack_is_referenced_when_available(self) -> None:
        with _built_pack() as pack_root:
            trace_lifecycle(
                pack_root,
                "process_object",
                max_seeds=8,
                depth=1,
                output_path=pack_root / "evidence-packs" / "process_object.json",
            )
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "process.md").read_text(encoding="utf-8")
            self.assertIn("## Lifecycle Evidence Packs", text)
            self.assertIn("`process_object`: available", text)
            self.assertIn("evidence-packs", text)

    def test_major_hubs_suppress_generic_and_unrelated_neighbors(self) -> None:
        functions = [
            _function(
                "0x140001000",
                "NtCreateUserProcess",
                ["process_thread"],
                ["create process"],
                ["0x140002000", "0x140004000", "0x140005000", "0x140006000", "0x140007000"],
            ),
            _function(
                "0x140002000",
                "PspInsertProcess",
                ["process_thread", "object_manager"],
                ["insert process"],
                ["0x140004000", "0x140005000", "0x140006000", "0x140007000"],
            ),
            _function(
                "0x140003000",
                "PsLookupProcessByProcessId",
                ["process_thread"],
                ["lookup process"],
                ["0x140005000"],
            ),
            _function("0x140004000", "memset_0", ["memory"], ["memory fill"], []),
            _function("0x140005000", "CmpDumpOneKeyBody", ["process_thread", "registry"], ["registry dump"], []),
            _function("0x140006000", "DifPsSetCreateProcessNotifyRoutineWrapper", ["process_thread"], ["process wrapper"], []),
            _function(
                "0x140007000",
                "Feature_Servicing_ZwTerminateMinimalProcess_Terminate_Fix__private_IsEnabledDeviceUsageNoInline",
                ["process_thread"],
                ["process feature flag"],
                [],
            ),
        ]
        with _built_custom_pack(functions) as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            generate_atlas(pack_root, output_dir, limit=8)

            text = (output_dir / "process.md").read_text(encoding="utf-8")
            hubs = _section(text, "## Major Caller/Callee Hubs", "## Lifecycle Evidence Packs")
            hub_names = _hub_names(hubs)
            self.assertIn("PspInsertProcess", hub_names)
            self.assertNotIn("memset_0", hub_names)
            self.assertNotIn("CmpDumpOneKeyBody", hub_names)
            self.assertNotIn("DifPsSetCreateProcessNotifyRoutineWrapper", hub_names)
            self.assertNotIn(
                "Feature_Servicing_ZwTerminateMinimalProcess_Terminate_Fix__private_IsEnabledDeviceUsageNoInline",
                hub_names,
            )

    def test_cli_outputs_json_manifest(self) -> None:
        with _built_pack() as pack_root:
            output_dir = pack_root / "reports" / "atlas"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--pack-root",
                        str(pack_root),
                        "--output-dir",
                        str(output_dir),
                        "--limit",
                        "8",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertTrue(payload["ok"])
            self.assertEqual(len(SUBSYSTEMS), payload["page_count"])
            self.assertTrue((output_dir / "process.md").is_file())


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


@contextlib.contextmanager
def _built_custom_pack(functions: list[dict[str, Any]]):
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        corpus_root = root / "corpus"
        pack_root = root / "pack"
        _write_corpus(corpus_root, functions)
        builder.build_pack(corpus_root, pack_root)
        yield pack_root


def _write_corpus(corpus_root: Path, functions: list[dict[str, Any]]) -> None:
    (corpus_root / "functions").mkdir(parents=True)
    index = {
        "schema": "pseudoforge_corpus_index_v1",
        "pseudoforge_version": "test",
        "generated_at": "2026-06-12T00:00:00+00:00",
        "functions": [],
        "overview": {
            "functions": len(functions),
            "report_status_counts": {
                "ok": len(functions),
            },
        },
        "metadata": {
            "target_path": "synthetic.i64",
        },
        "report_summary": {
            "status_counts": {
                "ok": len(functions),
            },
        },
    }
    for function in functions:
        item = dict(function)
        stem = "%016x_%s" % (int(str(item["ea"]), 0), item["name"])
        function_dir = corpus_root / "functions" / stem
        function_dir.mkdir(parents=True)
        cleaned = function_dir / "function.cleaned.cpp"
        raw = function_dir / "function.raw.cpp"
        summary = function_dir / "function.ida-batch-summary.json"
        cleaned.write_text(str(item["cleaned_excerpt"]), encoding="utf-8")
        raw.write_text(str(item["cleaned_excerpt"]), encoding="utf-8")
        summary.write_text(json.dumps({"ea": item["ea"], "name": item["name"]}, ensure_ascii=True), encoding="utf-8")
        item["directory"] = str(Path("functions") / stem)
        item["summary_path"] = str(Path("functions") / stem / "function.ida-batch-summary.json")
        item["artifacts"] = {
            "cleaned_pseudocode": str(Path("functions") / stem / "function.cleaned.cpp"),
            "raw_pseudocode": str(Path("functions") / stem / "function.raw.cpp"),
            "summary": str(Path("functions") / stem / "function.ida-batch-summary.json"),
        }
        index["functions"].append(item)
    (corpus_root / "pseudoforge-corpus-index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )


def _function(ea: str, name: str, tags: list[str], terms: list[str], callees: list[str]) -> dict[str, Any]:
    return {
        "ea": ea,
        "name": name,
        "tags": tags,
        "terms": terms,
        "mode": "synthetic",
        "counts": {
            "warnings": 0,
            "buffer_contracts": 0,
        },
        "llm_status": "ok",
        "callee_eas": callees,
        "caller_eas": [],
        "imports_called": [],
        "strings_referenced": [],
        "interesting_lines": terms,
        "cleaned_excerpt": "%s synthetic evidence: %s" % (name, " ".join(terms)),
    }


def _section(text: str, start: str, end: str) -> str:
    start_index = text.index(start) + len(start)
    end_index = text.index(end, start_index)
    return text[start_index:end_index]


def _hub_names(section: str) -> list[str]:
    names = []
    for line in section.splitlines():
        if not line.startswith("- `"):
            continue
        parts = line.split("`")
        if len(parts) >= 4:
            names.append(parts[3])
    return names


if __name__ == "__main__":
    unittest.main()
