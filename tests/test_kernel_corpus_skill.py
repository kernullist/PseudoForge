from __future__ import annotations

import unittest
from pathlib import Path


SKILL_PATH = Path(__file__).resolve().parents[1] / "tools" / "kernel_corpus" / "skills" / "kernel-corpus-analysis" / "SKILL.md"


class KernelCorpusSkillTests(unittest.TestCase):
    def test_skill_metadata_declares_kernel_corpus_analysis(self) -> None:
        text = SKILL_PATH.read_text(encoding="utf-8")
        metadata = _frontmatter(text)

        self.assertEqual("kernel-corpus-analysis", metadata["name"])
        self.assertIn("PseudoForge kernel corpus packs", metadata["description"])
        self.assertIn("MCP", metadata["description"])

    def test_skill_points_agents_to_mcp_first_and_evidence_packs(self) -> None:
        text = SKILL_PATH.read_text(encoding="utf-8")

        self.assertIn("Use MCP first", text)
        self.assertIn("corpus_status", text)
        self.assertIn("trace_lifecycle", text)
        self.assertIn("get_function", text)
        self.assertIn("get_neighbors", text)
        self.assertIn("build_evidence_pack", text)
        self.assertIn("Claim -> EA -> function name -> artifact path -> inference level", text)

    def test_skill_contains_required_answer_contracts_and_korean_mapping(self) -> None:
        text = SKILL_PATH.read_text(encoding="utf-8")

        self.assertIn("## Lifecycle Answer Contract", text)
        self.assertIn("## Function Answer Contract", text)
        self.assertIn("## Subsystem Atlas Contract", text)
        self.assertIn("프로세스 생성/종료/삭제", text)
        self.assertIn("스레드 생성/종료/삭제", text)
        self.assertIn("IOCTL/디스패치", text)
        self.assertIn("콜백/노티파이", text)

    def test_skill_does_not_embed_private_corpus_data(self) -> None:
        text = SKILL_PATH.read_text(encoding="utf-8")

        self.assertNotIn("F:\\", text)
        self.assertNotIn("26200.8457", text)
        self.assertNotIn("29964", text)
        self.assertNotIn("analysis-ouput", text)


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise AssertionError("missing frontmatter start")
    end = text.find("\n---\n", 4)
    if end == -1:
        raise AssertionError("missing frontmatter end")
    result: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


if __name__ == "__main__":
    unittest.main()
