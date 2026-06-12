from __future__ import annotations

import contextlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.kernel_corpus import builder
from tools.kernel_corpus.canonical_answers import (
    ARTIFACT_SCHEMA_VERSION,
    RUN_SCHEMA_VERSION,
    build_canonical_answers,
    load_manifest,
    select_topics,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "kernel_corpus" / "minimal"


class KernelCorpusCanonicalAnswerTests(unittest.TestCase):
    def test_default_manifest_covers_p0_and_p1_topics(self) -> None:
        manifest = load_manifest()
        topics = select_topics(manifest)

        p0 = [topic.topic_id for topic in topics if topic.priority == "P0"]
        p1 = [topic.topic_id for topic in topics if topic.priority == "P1"]

        self.assertEqual(24, len(p0))
        self.assertEqual(15, len(p1))
        self.assertIn("process_object_lifecycle", p0)
        self.assertIn("callback_registration_inventory", p1)
        self.assertEqual(len(topics), len({topic.topic_id for topic in topics}))

    def test_builds_lifecycle_and_focused_artifacts_from_fixture_pack(self) -> None:
        with _built_pack() as pack_root:
            manifest_path = _write_fixture_manifest(pack_root)
            output_root = pack_root / "canonical-answers"

            result = build_canonical_answers(
                pack_root,
                output_root=output_root,
                manifest_path=manifest_path,
                topic_ids=["process_object_lifecycle", "focused_process_entrypoints"],
            )

            self.assertEqual(RUN_SCHEMA_VERSION, result["schema"])
            self.assertTrue(result["ok"])
            self.assertEqual(2, result["topic_count"])
            self.assertEqual(2, result["passed_count"])

            for topic in result["topics"]:
                topic_dir = Path(topic["directory"])
                self.assertTrue((topic_dir / "answer.md").is_file())
                self.assertTrue((topic_dir / "evidence-pack.json").is_file())
                self.assertTrue((topic_dir / "trace.json").is_file())
                self.assertTrue((topic_dir / "prompt.md").is_file())
                self.assertTrue((topic_dir / "candidate-review.md").is_file())
                self.assertTrue((topic_dir / "source-map.md").is_file())
                self.assertTrue((topic_dir / "gaps.md").is_file())
                validation = json.loads((topic_dir / "validation.json").read_text(encoding="utf-8"))
                artifact_manifest = json.loads((topic_dir / "manifest.json").read_text(encoding="utf-8"))
                self.assertTrue(validation["passed"], topic["id"])
                self.assertEqual(0, validation["warning_count"], topic["id"])
                self.assertEqual(ARTIFACT_SCHEMA_VERSION, artifact_manifest["schema"])
                self.assertIn("Artifact:", (topic_dir / "answer.md").read_text(encoding="utf-8"))


@contextlib.contextmanager
def _built_pack():
    with tempfile.TemporaryDirectory() as temp_dir:
        pack_root = Path(temp_dir) / "pack"
        builder.build_pack(FIXTURE_ROOT, pack_root)
        yield pack_root


def _write_fixture_manifest(pack_root: Path) -> Path:
    manifest = {
        "schema": "kernel_corpus_canonical_topics_v1",
        "description": "Fixture canonical topics.",
        "priorities": {
            "P0": "fixture",
            "P1": "fixture",
        },
        "references": {
            "kernel_objects": {
                "title": "Managing Kernel Objects",
                "url": "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-kernel-objects",
                "scope": "Fixture reference.",
            }
        },
        "topics": [
            {
                "id": "process_object_lifecycle",
                "priority": "P0",
                "title": "Process Object Lifecycle",
                "question": "Explain the process object lifecycle from fixture evidence.",
                "mode": "lifecycle",
                "lifecycle_topic": "process_object",
                "max_seeds": 12,
                "depth": 1,
                "source_refs": ["kernel_objects"],
            },
            {
                "id": "focused_process_entrypoints",
                "priority": "P1",
                "title": "Focused Process Entrypoints",
                "question": "Explain selected process entrypoints from fixture evidence.",
                "mode": "focused",
                "max_functions": 3,
                "seed_names": ["NtCreateUserProcess", "PspAllocateProcess"],
                "queries": ["process"],
                "tags": ["process_thread"],
                "source_refs": ["kernel_objects"],
            },
        ],
    }
    path = pack_root / "fixture-canonical-topics.json"
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True), encoding="utf-8")
    return path


if __name__ == "__main__":
    unittest.main()
