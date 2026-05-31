from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from ida_pseudoforge.config import (
    LlmConfig,
    ProviderCredential,
    PseudoForgeConfig,
    get_provider_api_key,
    load_config,
    save_config,
)
from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.llm_assist import parse_llm_rename_response, suggest_renames_with_provider
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.models.cli_provider import CliRenameProvider
from ida_pseudoforge.models.provider_factory import build_rename_provider
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
    PROVIDER_CLAUDE_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CODEX_CLI,
    PROVIDER_DEEPSEEK,
    PROVIDER_OPENROUTER,
    is_known_provider,
    normalize_provider,
    provider_defaults,
    provider_model_options,
)


LLM_PLAN_SAMPLE = r"""
__int64 __fastcall LlmPlanSample(int a1)
{
  int v115;

  v115 = a1 + 1;
  return v115;
}
"""


LARGE_DISPATCHER_SAMPLE = (
    r"""
__int64 __fastcall LargeDispatcherSample(int a1)
{
  int v5;
  int v115;
  int ActiveProcessorCount;
  int v126;

  v5 = a1;
  v115 = v5 - 235;
  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  v126 = 0;
"""
    + "\n".join(f"  if ( v5 == {index} )\n    return v5 + {index};" for index in range(50))
    + r"""
  return v115 + ActiveProcessorCount + v126;
}
"""
)


class LlmConfigTests(unittest.TestCase):
    def test_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config = PseudoForgeConfig(
                    llm=LlmConfig(
                        enabled=True,
                        provider=PROVIDER_OPENROUTER,
                        base_url="https://openrouter.example.invalid/v1",
                        model="openrouter-test-model",
                        timeout_seconds=42,
                        command_template="test command",
                        extra_headers={"X-Test": "1"},
                    ),
                    credentials={
                        PROVIDER_OPENROUTER: ProviderCredential(api_key="sk-test"),
                    },
                )
                path = save_config(config)
                raw = json.loads(path.read_text(encoding="utf-8"))
                loaded = load_config()

                self.assertTrue(path.exists())
                self.assertNotIn("api_key", raw["llm"])
                self.assertEqual(raw["credentials"][PROVIDER_OPENROUTER]["api_key"], "sk-test")
                self.assertTrue(loaded.llm.enabled)
                self.assertEqual(loaded.llm.provider, PROVIDER_OPENROUTER)
                self.assertEqual(get_provider_api_key(loaded, PROVIDER_OPENROUTER), "sk-test")
                self.assertEqual(loaded.llm.base_url, "https://openrouter.example.invalid/v1")
                self.assertEqual(loaded.llm.model, "openrouter-test-model")
                self.assertEqual(loaded.llm.timeout_seconds, 42)
                self.assertEqual(loaded.llm.command_template, "test command")
                self.assertEqual(loaded.llm.extra_headers["X-Test"], "1")
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_parse_llm_rename_response(self) -> None:
        suggestions, warnings = parse_llm_rename_response(
            """
            {
              "renames": [
                {
                  "old": "v3",
                  "new": "inputByteLength",
                  "confidence": 0.86,
                  "reason": "local stores a byte length"
                },
                {
                  "old": "v4",
                  "new": "bad-name",
                  "confidence": 0.65,
                  "reason": "too weak"
                }
              ],
              "warnings": ["review manually"]
            }
            """
        )

        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].old, "v3")
        self.assertIn("low confidence", warnings[0])
        self.assertIn("review manually", warnings)

    def test_parse_fenced_llm_rename_response(self) -> None:
        suggestions, warnings = parse_llm_rename_response(
            """
            Here is the JSON:
            ```json
            {"renames":[{"old":"v3","new":"byteLength","confidence":0.9,"reason":"length"}]}
            ```
            """
        )

        self.assertFalse(warnings)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].new, "byteLength")

    def test_large_dispatcher_llm_raises_confidence_floor_and_hides_low_confidence_warnings(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v115",
                                "new": "classMinus235",
                                "confidence": 0.82,
                                "reason": "dispatcher delta",
                            },
                            {
                                "old": "ActiveProcessorCount",
                                "new": "activeProcessorCount",
                                "confidence": 0.98,
                                "reason": "processor count result",
                            },
                        ]
                    }
                )

        capture = capture_from_pseudocode(LARGE_DISPATCHER_SAMPLE)
        suggestions, warnings = suggest_renames_with_provider(capture, FakeProvider())
        rename_map = {item.old: item.new for item in suggestions if item.apply}

        self.assertNotIn("v115", rename_map)
        self.assertEqual(rename_map["ActiveProcessorCount"], "activeProcessorCount")
        self.assertFalse(any("low confidence" in warning.lower() for warning in warnings))

    def test_parse_dict_warning_message(self) -> None:
        suggestions, warnings = parse_llm_rename_response(
            """
            {
              "renames": [],
              "warnings": [
                {"message": "review import recovery"},
                {"old": "BadReferenceName", "reason": "paired release routine differs"}
              ]
            }
            """
        )

        self.assertFalse(suggestions)
        self.assertEqual(
            warnings,
            [
                "review import recovery",
                "Potential bad call target BadReferenceName: paired release routine differs",
            ],
        )

    def test_rendered_comment_text_is_ascii_safe(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [],
                        "warnings": [
                            {"message": "한글 warning"}
                        ],
                    },
                    ensure_ascii=False,
                )

        capture = capture_from_pseudocode(LLM_PLAN_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("한글", rendered)
        self.assertIn("\\ud55c\\uae00 warning", rendered)

    def test_build_plan_with_llm_provider(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return '{"renames":[{"old":"v115","new":"bootPagesDelta","confidence":0.86,"reason":"case arithmetic"}]}'

        capture = capture_from_pseudocode(LLM_PLAN_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}

        self.assertEqual(rename_map["v115"], "bootPagesDelta")

    def test_cli_provider_reads_stdout(self) -> None:
        command = subprocess.list2cmdline(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdin.read(); print('{\"renames\": []}')",
            ]
        )
        capture = capture_from_pseudocode(LLM_PLAN_SAMPLE)
        provider = CliRenameProvider(command_template=command, timeout_seconds=10)

        self.assertEqual(provider.suggest_renames(capture).strip(), '{"renames": []}')

    def test_provider_factory_openrouter(self) -> None:
        provider = build_rename_provider(
            LlmConfig(
                enabled=True,
                provider=PROVIDER_OPENROUTER,
                model="test-model",
            ),
            api_key="sk-test",
        )

        self.assertEqual(provider.base_url, "https://openrouter.ai/api/v1")
        self.assertEqual(provider.model, "test-model")
        self.assertEqual(provider.extra_headers["X-Title"], "PseudoForge")

    def test_chatgpt_oauth_old_alias_is_not_accepted(self) -> None:
        self.assertFalse(is_known_provider("chatgpt_oauth"))
        self.assertEqual(
            normalize_provider("chatgpt_oauth_via_codex_cli"),
            PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
        )

    def test_claude_login_aliases_are_accepted(self) -> None:
        self.assertEqual(
            normalize_provider("claude_login_via_claude_cli"),
            PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
        )
        self.assertEqual(
            normalize_provider("claude cli login"),
            PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
        )
        self.assertTrue(is_known_provider("claude-code-login"))

    def test_provider_model_options(self) -> None:
        openrouter_models = provider_model_options(PROVIDER_OPENROUTER)
        self.assertIn("openrouter/auto", openrouter_models)
        self.assertIn("anthropic/claude-opus-4.8", openrouter_models)
        self.assertNotIn("anthropic/claude-opus-4.6", openrouter_models)
        self.assertIn("deepseek-v4-flash", provider_model_options(PROVIDER_DEEPSEEK))
        self.assertIn(
            "gpt-5.5",
            provider_model_options(PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI),
        )
        claude_models = provider_model_options(PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI)
        self.assertEqual(claude_models[0], "claude-opus-4-8")
        self.assertIn("claude-sonnet-4-6", claude_models)
        self.assertIn("claude-haiku-4-5", claude_models)
        self.assertIn("sonnet", claude_models)
        self.assertNotIn("claude-opus-4.6", claude_models)

    def test_cli_provider_defaults_pass_selected_model(self) -> None:
        for provider in (
            PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
            PROVIDER_CODEX_CLI,
            PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
            PROVIDER_CLAUDE_CLI,
        ):
            command_template = provider_defaults(provider).command_template
            self.assertIn("{model}", command_template)
            self.assertNotIn("--ask-for-approval", command_template)

    def test_claude_cli_defaults_disable_tools_and_session_persistence(self) -> None:
        for provider in (PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI, PROVIDER_CLAUDE_CLI):
            command_template = provider_defaults(provider).command_template

            self.assertIn("--no-session-persistence", command_template)
            self.assertIn('--tools ""', command_template)

    def test_old_codex_command_template_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CHATGPT_OAUTH_VIA_CODEX_CLI,
                                "model": "gpt-5.5",
                                "command_template": (
                                    "codex exec --skip-git-repo-check --sandbox read-only "
                                    "--ask-for-approval never --output-last-message {output_file} -"
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertIn("{model}", loaded.llm.command_template)
                self.assertNotIn("--ask-for-approval", loaded.llm.command_template)
                self.assertEqual(loaded.llm.model, "gpt-5.5")
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_invalid_codex_command_template_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CODEX_CLI,
                                "model": "gpt-5.5",
                                "command_template": (
                                    "codex exec -m {model} --skip-git-repo-check "
                                    "--sandbox read-only --ask-for-approval never "
                                    "--output-last-message {output_file} -"
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertIn("{model}", loaded.llm.command_template)
                self.assertNotIn("--ask-for-approval", loaded.llm.command_template)
                self.assertEqual(loaded.llm.provider, PROVIDER_CODEX_CLI)
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir

    def test_old_claude_command_template_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            old_config_dir = os.environ.get("PSEUDOFORGE_CONFIG_DIR")
            os.environ["PSEUDOFORGE_CONFIG_DIR"] = temp_dir
            try:
                config_path = os.path.join(temp_dir, "pseudoforge_config.json")
                with open(config_path, "w", encoding="utf-8") as file:
                    json.dump(
                        {
                            "llm": {
                                "enabled": True,
                                "provider": PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
                                "model": "sonnet",
                                "command_template": (
                                    "claude -p --model {model} --permission-mode dontAsk "
                                    "--output-format text"
                                ),
                            },
                            "credentials": {},
                        },
                        file,
                    )

                loaded = load_config()

                self.assertEqual(loaded.llm.provider, PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI)
                self.assertIn("{model}", loaded.llm.command_template)
                self.assertIn("--no-session-persistence", loaded.llm.command_template)
                self.assertIn('--tools ""', loaded.llm.command_template)
            finally:
                if old_config_dir is None:
                    os.environ.pop("PSEUDOFORGE_CONFIG_DIR", None)
                else:
                    os.environ["PSEUDOFORGE_CONFIG_DIR"] = old_config_dir


if __name__ == "__main__":
    unittest.main()
