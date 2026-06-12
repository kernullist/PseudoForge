from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.kernel_corpus import builder
from tools.kernel_corpus.lifecycle import ONTOLOGY_SCHEMA_VERSION, load_ontology, main, trace_lifecycle
from tools.kernel_corpus.schema import EVIDENCE_PACK_SCHEMA_VERSION

ONTOLOGY_DIR = Path(__file__).resolve().parents[1] / "tools" / "kernel_corpus" / "ontology"
EXPECTED_TOPICS = {
    "process_object",
    "thread_object",
    "file_object",
    "driver_object",
    "device_object",
    "registry_key",
    "section_object",
    "module_image",
}


class KernelCorpusLifecycleTests(unittest.TestCase):
    def test_all_lifecycle_ontologies_have_reviewable_schema(self) -> None:
        paths = sorted(ONTOLOGY_DIR.glob("*.json"))
        topics = {path.stem for path in paths}
        self.assertTrue(EXPECTED_TOPICS.issubset(topics))

        for path in paths:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(ONTOLOGY_SCHEMA_VERSION, data.get("schema"), path.name)
            self.assertEqual(path.stem, data.get("topic"), path.name)
            self.assertTrue(_non_empty_string_list(data.get("labels")), path.name)
            self.assertTrue(_non_empty_string_list(data.get("seed_names")), path.name)
            self.assertTrue(_non_empty_string_list(data.get("seed_terms")), path.name)
            self.assertTrue(_non_empty_string_list(data.get("tags")), path.name)
            phases = data.get("phases")
            self.assertIsInstance(phases, dict, path.name)
            self.assertGreaterEqual(len(phases), 4, path.name)
            for phase_id, phase in phases.items():
                self.assertIsInstance(phase, dict, "%s:%s" % (path.name, phase_id))
                self.assertIsInstance(phase.get("title"), str, "%s:%s" % (path.name, phase_id))
                self.assertTrue(phase.get("title"), "%s:%s" % (path.name, phase_id))
                has_hints = any(
                    _non_empty_string_list(phase.get(key))
                    for key in ("seed_names", "name_terms", "terms", "tags")
                )
                self.assertTrue(has_hints, "%s:%s" % (path.name, phase_id))

    def test_lifecycle_tracer_loads_each_supported_ontology(self) -> None:
        for topic in sorted(EXPECTED_TOPICS):
            ontology, path = load_ontology(topic)
            self.assertEqual(topic, ontology["topic"])
            self.assertEqual("%s.json" % topic, path.name)

    def test_process_graph_maps_seed_functions_to_expected_phases(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], ["0x140002000"]),
            _function("0x140002000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], ["0x140003000"]),
            _function("0x140003000", "PspInitializeProcess", ["process_thread"], ["initialize", "process"], ["0x140004000"]),
            _function("0x140004000", "PspInsertProcess", ["process_thread", "object_manager"], ["insert", "process"], ["0x140005000", "0x140006000"]),
            _function("0x140005000", "ObInsertObject", ["object_manager"], ["insert", "object"], []),
            _function("0x140006000", "PspCallProcessNotifyRoutines", ["process_thread", "callback"], ["notify", "process"], []),
            _function("0x140007000", "PspExitProcess", ["process_thread"], ["exit", "process"], ["0x140008000"]),
            _function("0x140008000", "PspRundownSingleProcess", ["process_thread"], ["rundown", "process"], ["0x140009000"]),
            _function("0x140009000", "PspProcessDelete", ["process_thread", "object_manager"], ["delete", "process"], ["0x14000a000"]),
            _function("0x14000a000", "ObDereferenceObject", ["object_manager"], ["dereference", "object"], []),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=20, depth=2)

            phases = _phase_by_name(pack)
            self.assertEqual(EVIDENCE_PACK_SCHEMA_VERSION, pack["schema"])
            self.assertEqual("entry", phases["NtCreateUserProcess"])
            self.assertEqual("allocate", phases["PspAllocateProcess"])
            self.assertEqual("initialize", phases["PspInitializeProcess"])
            self.assertEqual("publish", phases["PspInsertProcess"])
            self.assertEqual("publish", phases["ObInsertObject"])
            self.assertEqual("notify", phases["PspCallProcessNotifyRoutines"])
            self.assertEqual("exit", phases["PspExitProcess"])
            self.assertEqual("rundown", phases["PspRundownSingleProcess"])
            self.assertEqual("delete", phases["PspProcessDelete"])
            self.assertIn(("0x140001000", "0x140002000"), _edge_pairs(pack))
            self.assertIn(("0x140004000", "0x140006000"), _edge_pairs(pack))

    def test_file_object_graph_maps_seed_functions_to_expected_phases(self) -> None:
        functions = [
            _function("0x140101000", "NtCreateFile", ["file", "io_manager"], ["create file", "file object"], ["0x140102000"]),
            _function("0x140102000", "IopAllocateFileObject", ["file", "io_manager", "memory"], ["allocate file", "file object"], ["0x140103000"]),
            _function("0x140103000", "IopInitializeFileObject", ["file", "io_manager"], ["initialize file", "object attributes"], ["0x140104000"]),
            _function("0x140104000", "ObInsertObject", ["file", "object_manager"], ["insert file object", "handle"], ["0x140105000"]),
            _function("0x140105000", "IopCallDriver", ["file", "io_manager", "callback"], ["file system notify", "callback"], []),
            _function("0x140106000", "ObReferenceObjectByHandle", ["file", "object_manager"], ["reference", "file handle"], []),
            _function("0x140107000", "NtClose", ["file", "object_manager"], ["close file"], ["0x140108000"]),
            _function("0x140108000", "IopCleanupFileObject", ["file", "io_manager"], ["cleanup file", "rundown"], ["0x140109000"]),
            _function("0x140109000", "IopDeleteFile", ["file", "io_manager", "object_manager"], ["delete file", "final reference"], ["0x14010a000"]),
            _function("0x14010a000", "ObDereferenceObject", ["object_manager"], ["dereference", "object delete"], []),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "file_object", max_seeds=20, depth=2)

            phases = _phase_by_name(pack)
            self.assertEqual(EVIDENCE_PACK_SCHEMA_VERSION, pack["schema"])
            self.assertEqual("file_object", pack["topic"])
            self.assertEqual("entry", phases["NtCreateFile"])
            self.assertEqual("allocate", phases["IopAllocateFileObject"])
            self.assertEqual("initialize", phases["IopInitializeFileObject"])
            self.assertEqual("publish", phases["ObInsertObject"])
            self.assertEqual("notify", phases["IopCallDriver"])
            self.assertEqual("steady_state", phases["ObReferenceObjectByHandle"])
            self.assertEqual("exit", phases["NtClose"])
            self.assertEqual("rundown", phases["IopCleanupFileObject"])
            self.assertEqual("delete", phases["IopDeleteFile"])
            self.assertIn(("0x140101000", "0x140102000"), _edge_pairs(pack))
            self.assertIn(("0x140108000", "0x140109000"), _edge_pairs(pack))

    def test_ambiguous_functions_receive_lower_confidence(self) -> None:
        functions = [
            _function("0x140001000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], []),
            _function("0x140002000", "PspProcessWorker", ["process_thread"], ["process"], []),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1)

            candidates = {item["name"]: item for item in pack["candidates"]}
            self.assertLess(candidates["PspProcessWorker"]["confidence"], candidates["PspAllocateProcess"]["confidence"])
            self.assertEqual("steady_state", candidates["PspProcessWorker"]["phase"])
            self.assertIn("allocate", candidates["PspAllocateProcess"]["phase"])

    def test_missing_exact_seed_still_allows_term_based_candidates(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], []),
            _function(
                "0x140002000",
                "PspTerminateProcessWorker",
                ["process_thread"],
                ["exit", "terminate", "process"],
                [],
                excerpt="void PspTerminateProcessWorker(...) { /* process exit terminate */ }",
            ),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1)

            candidates = {item["name"]: item for item in pack["candidates"]}
            self.assertEqual("exit", candidates["PspTerminateProcessWorker"]["phase"])
            self.assertTrue(
                any("seed term match: exit" in item for item in candidates["PspTerminateProcessWorker"]["why_selected"])
            )
            self.assertIn("Exact seed not found: PspExitProcess", pack["gaps"])

    def test_process_lifecycle_penalizes_thread_only_neighbors(self) -> None:
        functions = [
            _function(
                "0x140001000",
                "NtTerminateProcess",
                ["process_thread"],
                ["terminate process"],
                ["0x140002000", "0x140003000"],
            ),
            _function(
                "0x140002000",
                "PspTerminateThreadByPointer",
                ["process_thread"],
                ["terminate thread"],
                [],
            ),
            _function(
                "0x140003000",
                "PspTerminateProcess",
                ["process_thread"],
                ["terminate process"],
                [],
            ),
            _function(
                "0x140004000",
                "PspTerminateAllThreads",
                ["process_thread"],
                ["terminate thread"],
                [],
            ),
        ]
        with _built_pack(functions) as pack_root:
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1)

            candidates = {item["name"]: item for item in pack["candidates"]}
            self.assertLess(
                candidates["PspTerminateThreadByPointer"]["confidence"],
                candidates["PspTerminateProcess"]["confidence"],
            )
            self.assertTrue(
                any(
                    "topic relevance penalty" in item
                    for item in candidates["PspTerminateThreadByPointer"]["why_selected"]
                )
            )
            self.assertLess(
                candidates["PspTerminateAllThreads"]["confidence"],
                candidates["PspTerminateProcess"]["confidence"],
            )
            self.assertTrue(
                any(
                    "topic relevance penalty" in item
                    for item in candidates["PspTerminateAllThreads"]["why_selected"]
                )
            )

    def test_evidence_pack_contains_paths_phase_labels_and_writes_output(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], ["0x140002000"]),
            _function("0x140002000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], []),
        ]
        with _built_pack(functions) as pack_root:
            output_path = pack_root / "evidence-packs" / "process_object.json"
            pack = trace_lifecycle(pack_root, "process_object", max_seeds=10, depth=1, output_path=output_path)
            written = json.loads(output_path.read_text(encoding="utf-8"))

            self.assertEqual(str(output_path.resolve()), pack["output_path"])
            self.assertEqual(pack["output_path"], written["output_path"])
            function = _function_by_name(pack, "NtCreateUserProcess")
            self.assertEqual("entry", function["phase"])
            self.assertGreaterEqual(function["confidence"], 0.5)
            self.assertTrue(Path(function["artifacts"]["summary"]).is_absolute())
            self.assertTrue(Path(function["evidence"][0]["path"]).is_absolute())
            self.assertIn("phase entry", " ".join(function["why_selected"]))

    def test_cli_writes_lifecycle_json_output(self) -> None:
        functions = [
            _function("0x140001000", "NtCreateUserProcess", ["process_thread"], ["create", "process"], ["0x140002000"]),
            _function("0x140002000", "PspAllocateProcess", ["process_thread", "memory"], ["allocate", "process"], []),
        ]
        with _built_pack(functions) as pack_root:
            output_path = pack_root / "evidence-packs" / "process_object.json"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--pack-root",
                        str(pack_root),
                        "--topic",
                        "process_object",
                        "--depth",
                        "1",
                        "--output",
                        str(output_path),
                    ]
                )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("process_object", payload["topic"])
            self.assertEqual(str(output_path.resolve()), payload["output_path"])
            self.assertTrue(output_path.is_file())


@contextlib.contextmanager
def _built_pack(functions: list[dict[str, Any]]):
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


def _function(
    ea: str,
    name: str,
    tags: list[str],
    terms: list[str],
    callees: list[str],
    *,
    excerpt: str | None = None,
) -> dict[str, Any]:
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
        "cleaned_excerpt": excerpt or ("%s synthetic evidence: %s" % (name, " ".join(terms))),
    }


def _phase_by_name(pack: dict[str, Any]) -> dict[str, str]:
    return {
        function["name"]: phase["id"]
        for phase in pack["phases"]
        for function in phase["functions"]
    }


def _function_by_name(pack: dict[str, Any], name: str) -> dict[str, Any]:
    for phase in pack["phases"]:
        for function in phase["functions"]:
            if function["name"] == name:
                return function
    raise AssertionError("function not found: %s" % name)


def _edge_pairs(pack: dict[str, Any]) -> list[tuple[str, str]]:
    return [(edge["src_ea"], edge["dst_ea"]) for edge in pack["edges"]]


def _non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(item, str) and item for item in value)


if __name__ == "__main__":
    unittest.main()
