from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder, query
from tools.kernel_corpus.answer_harness import build_prompt, main, validate_answer


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusAnswerHarnessTests(unittest.TestCase):
    def test_prompt_generation_from_fixture_evidence_pack(self) -> None:
        with _built_pack() as pack_root:
            evidence_path, _pack = _write_fixture_evidence_pack(pack_root)

            prompt = build_prompt(
                pack_root,
                evidence_path,
                "Explain the process object path using corpus evidence.",
            )

            text = prompt["prompt"]
            self.assertIn("## Corpus Identity", text)
            self.assertIn("## Selected Functions", text)
            self.assertIn("## Edges", text)
            self.assertIn("## Answer Contract", text)
            self.assertIn("Explain the process object path", text)
            self.assertIn("`0x140001000` `NtCreateUserProcess`", text)
            self.assertIn("`0x140001000` `NtCreateUserProcess` -> `0x140002000` `PspAllocateProcess`", text)
            self.assertIn("function.ida-batch-summary.json", text)
            self.assertFalse(prompt["truncated"])

    def test_validation_passes_for_well_cited_answer(self) -> None:
        with _built_pack() as pack_root:
            _evidence_path, pack = _write_fixture_evidence_pack(pack_root, include_gap=True)
            first, second = pack["functions"]
            answer = "\n".join(
                [
                    "Overall flow:",
                    "The corpus evidence shows a small process creation chain.",
                    "",
                    "Major functions:",
                    "- `%s` `%s`: entry claim. Artifact: `%s`. Inference: confirmed corpus evidence."
                    % (first["ea"], first["name"], first["artifacts"]["summary"]),
                    "- `%s` `%s`: allocation claim. Artifact: `%s`. Inference: confirmed corpus evidence."
                    % (second["ea"], second["name"], second["artifacts"]["summary"]),
                    "",
                    "Gaps:",
                    "- The evidence pack reports a missing requested EA.",
                ]
            )

            report = validate_answer(pack, answer)

            self.assertTrue(report["passed"])
            self.assertEqual(0, report["warning_count"])
            self.assertEqual(2, report["checked_major_function_bullets"])
            self.assertTrue(report["gap_section_present"])

    def test_validation_warns_on_uncited_major_claims(self) -> None:
        with _built_pack() as pack_root:
            _evidence_path, pack = _write_fixture_evidence_pack(pack_root, include_gap=True)
            answer = "\n".join(
                [
                    "Major functions:",
                    "- NtCreateUserProcess creates the process object.",
                ]
            )

            report = validate_answer(pack, answer)
            warning_codes = {warning["code"] for warning in report["warnings"]}

            self.assertFalse(report["passed"])
            self.assertIn("missing_ea", warning_codes)
            self.assertIn("missing_nearby_artifact_path", warning_codes)
            self.assertIn("missing_gaps_section", warning_codes)

    def test_validation_prefers_ea_matches_over_name_substrings(self) -> None:
        pack = {
            "schema": "kernel_corpus_evidence_pack_v1",
            "topic": "security_access_check",
            "functions": [
                {
                    "ea": "0x140001000",
                    "name": "SeAccessCheck",
                    "artifacts": {
                        "summary": r"C:\corpus\SeAccessCheck.json",
                    },
                },
                {
                    "ea": "0x140002000",
                    "name": "SeAccessCheckWithHint",
                    "artifacts": {
                        "summary": r"C:\corpus\SeAccessCheckWithHint.json",
                    },
                },
            ],
            "gaps": [],
        }
        answer = "\n".join(
            [
                "Major functions:",
                r"- `0x140002000` `SeAccessCheckWithHint`: hinted check. Artifact: `C:\corpus\SeAccessCheckWithHint.json`. Inference: confirmed corpus evidence.",
            ]
        )

        report = validate_answer(pack, answer)

        self.assertTrue(report["passed"])
        self.assertEqual(0, report["warning_count"])
        self.assertEqual(1, report["checked_major_function_bullets"])
        self.assertEqual(1, report["cited_function_count"])

    def test_cli_writes_prompt_and_report(self) -> None:
        with _built_pack() as pack_root:
            evidence_path, pack = _write_fixture_evidence_pack(pack_root)
            answer_path = pack_root / "answer.md"
            prompt_path = pack_root / "prompt.md"
            report_path = pack_root / "answer-report.json"
            first, second = pack["functions"]
            answer_path.write_text(
                "\n".join(
                    [
                        "Major functions:",
                        "- `%s` `%s`: entry claim. Artifact: `%s`. Inference: confirmed corpus evidence."
                        % (first["ea"], first["name"], first["artifacts"]["summary"]),
                        "- `%s` `%s`: allocation claim. Artifact: `%s`. Inference: confirmed corpus evidence."
                        % (second["ea"], second["name"], second["artifacts"]["summary"]),
                    ]
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--pack-root",
                        str(pack_root),
                        "--evidence-pack",
                        str(evidence_path),
                        "--question",
                        "Explain the process creation chain.",
                        "--prompt-out",
                        str(prompt_path),
                        "--answer-in",
                        str(answer_path),
                        "--report-out",
                        str(report_path),
                    ]
                )

            payload = json.loads(stdout.getvalue())
            written_report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(0, exit_code)
            self.assertTrue(prompt_path.is_file())
            self.assertTrue(report_path.is_file())
            self.assertEqual(str(prompt_path.resolve()), payload["prompt_path"])
            self.assertEqual(str(report_path.resolve()), payload["report_path"])
            self.assertTrue(payload["validation"]["passed"])
            self.assertTrue(written_report["validation"]["passed"])
            self.assertNotIn("prompt", payload)


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


def _write_fixture_evidence_pack(pack_root: Path, *, include_gap: bool = False) -> tuple[Path, dict[str, object]]:
    output_path = pack_root / "evidence-packs" / "process_object.json"
    eas = ["0x140001000", "0x140002000"]
    if include_gap:
        eas.append("0xDEADBEEF")
    pack = query.build_evidence_pack(
        pack_root,
        eas,
        "process_object",
        output_path=output_path,
    )
    return output_path, pack


if __name__ == "__main__":
    unittest.main()
