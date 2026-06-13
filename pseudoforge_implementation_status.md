# PseudoForge Implementation Status

Current plugin version: `0.1.2`.

## Current MVP

Implemented in this folder:

1. IDA plugin entrypoint
   - `pseudoforge.py`
   - `ida-plugin.json`
   - `ida_pseudoforge/version.py` as the runtime version source of truth

2. IDA integration layer
   - `ida_pseudoforge/ida/action_registry.py`
   - `ida_pseudoforge/ida/analysis_state.py`
   - `ida_pseudoforge/ida/plugin.py`
   - `ida_pseudoforge/ida/actions.py`
   - `ida_pseudoforge/ida/async_runner.py`
   - `ida_pseudoforge/ida/decompiler.py`
   - `ida_pseudoforge/ida/apply_changes.py`
   - `ida_pseudoforge/ida/llm_config_dialog.py`
   - `ida_pseudoforge/ida/ui_preview.py`
   - `ida_pseudoforge/ida/thread_helpers.py`
   - `ida_pseudoforge/logging.py`
   - IDA menu actions for preview, LLM configuration, and version/settings display

3. Core analysis engine
   - function capture from pseudocode text
   - local declaration extraction
   - function prototype parsing
   - `ida_pseudoforge/core/kernel_semantics.py`
   - high-confidence parameter/local rename plan generation
   - rename validation
   - dispatcher/case value recovery from comparison and subtraction chains
   - `SYSTEM_INFORMATION_CLASS` delta-chain normalization through the profile reverse lookup
   - chained dispatcher temporaries are rewritten when the source delta remains structurally adjacent
   - stale dispatcher temporary comparisons after large branch bodies are left unchanged
   - single-return safe body extraction for recovered switch outlines
   - cleanup label classification
   - kernel driver semantics pass
   - NTSTATUS literal normalization in returns and status assignments
   - WDK-generated NTSTATUS profile coverage includes 5391 unsigned/signed lookup entries for WDK 10.0.26100.0
   - driver-dispatch NTSTATUS coverage includes `STATUS_INVALID_USER_BUFFER`, `STATUS_DELETE_PENDING`, `STATUS_DEVICE_BUSY`, `STATUS_BUFFER_TOO_SMALL`, `STATUS_INVALID_DEVICE_REQUEST`, and newer facilities such as `STATUS_IORING_VERSION_NOT_SUPPORTED`
   - low success/wait status values are intentionally excluded from the generated profile except `STATUS_SUCCESS` and `STATUS_PENDING`
   - deterministic LIST_ENTRY record/link/tail rename hints that outrank generic LLM suggestions
   - LIST_ENTRY unlink/insert-tail insights
   - inferred provider record layout hints for common allocation/list patterns
   - ERESOURCE, critical region, pool allocation, object reference, and failfast insights
   - pool tag decoding for common Hex-Rays integer literals
   - profile-backed NTSTATUS, `SYSTEM_INFORMATION_CLASS`, and `PROCESSINFOCLASS` names
   - DriverEntry-style setup recognition with deterministic `driverObject`, `registryPath`, `status`, `extension`, `deviceObject`, `deviceName`, and `majorIndex` names
   - DriverEntry preview signature normalization, IRP major-function constants, `NT_SUCCESS` tests, `DO_*` device flags, and `FILE_DEVICE_SECURE_OPEN` rendering
   - IOCTL dispatcher case constant annotation with exact `CTL_CODE(DeviceType, Function, Method, Access)` bitfield decoding
   - IOCTL-gated `IO_STACK_LOCATION.Parameters.DeviceIoControl` field rendering and deterministic device-control local naming from `_DWORD *` stack-location indexing
   - command buffer contract recovery under `ida_pseudoforge/core/buffer_contracts.py`
     for IOCTL, `NtSetInformationProcess`, `NtSetInformationThread`,
     `NtSetSystemInformation`, and strongly evidenced generic switch
     dispatchers, producing report-only per-case observed size/field guard
     predicates, derived valid predicates for common rejection branches,
     inferred field accesses, synthetic structure names, helper edges,
     confidence, and evidence
   - focused disassembly-assisted buffer contract evidence under
     `ida_pseudoforge/core/disasm_contracts.py`, using an injectable offline
     `DisasmCaseSlice` model to recover selected-case size guards, fixed-offset
     field reads/writes, field predicates, x64 register/stack call arguments,
     and direct or indirect helper edges before merging into the existing
     `CommandBufferContract` schema
   - IDA focused buffer-contract analysis can capture a bounded disassembly CFG
     slice through `ida_pseudoforge/ida/disasm_capture.py` without modifying the
     IDB. Cursor mode starts from the current EA; explicit value mode also tries
     a generic immediate-compare/conditional-branch case-entry fallback when no
     cursor entry EA is available.
   - disassembly evidence is used only for focused case analysis and injected
     focused CLI/test paths; full all-case recovery remains pseudocode-first
     unless a selected-case disassembly slice is explicitly supplied
   - selected-case buffer contract recovery for focused CLI and IDA cursor-case
     deep analysis, including generated C++ struct previews
   - cursor-case analysis resolves the active Hex-Rays pseudocode line through
     `ida_hexrays.get_widget_vdui(...).cpos.lnnum` first; only the explicit
     case-value action prompts for a command value
   - preview-only inferred driver device-extension field rendering for common DriverEntry initialization and cleanup offsets
   - 25H2-range `SYSTEM_INFORMATION_CLASS` profile coverage
   - 25H2-range `PROCESSINFOCLASS` profile coverage through `ProcessAvailableCpus`
   - `NtSetSystemInformation` canonical prototype and body alias normalization
   - `NtSetInformationProcess` canonical prototype normalization
   - WDK-backed `kernel_api.json` profile generated from WDK `km` and `shared` headers
   - kernel API profile currently includes 3501 function prototypes, 1760 enums, 8354 structures, 19865 aliases, 58251 macros, and 93592 symbol index entries for WDK 10.0.26100.0
   - built-in split kernel API profile artifacts now ship for functions, enums, structures, aliases, macros, symbols, and indices, each with manifest metadata
   - profile lookup covers function, structure, alias, macro, enum, and enum member names through the `symbols` index
   - API argument rewrite uses profile metadata for `POOL_FLAGS`, `BOOLEAN`, and pool tag parameters
   - kernel API override profile maps private wrapper prefixes such as `Obp -> Ob`, `Psp -> Ps`, `Iop -> Io`, `Mmp -> Mm`, and `Sep -> Se` when a public WDK prototype exists
   - `WithTag`/pool API `Tag` arguments are inferred as pool tags, including private wrapper calls such as `ObpReferenceObjectByHandleWithTag`
   - scalar `BOOLEAN` parameters are inferred as boolean argument rewrite targets
   - low-byte boolean call argument cleanup for known kernel helper calls
   - cleaned preview shows normalized original pseudocode first and appends recovered switch-case view as an auxiliary outline
   - recovered switch-case view omits complex case bodies instead of emitting style-breaking partial fragments
   - recovered switch cases include body-state metadata, source line anchors, and shared-tail labels in switch outlines and flow reports
   - native switch bodies already present in normalized original pseudocode are not duplicated in the auxiliary outline
   - generated pseudocode style pass enforces next-line braces, mandatory braces, standalone `else`, and guard flattening
   - generated pseudocode style pass treats a C label plus its following statement as one control-body unit when adding braces, preventing unbraced `if`/label fragments without matching specific label names
   - duplicate semantic cleanup labels are given stable suffixes such as `InvalidParameter_17` to avoid duplicate labels and accidental self-goto rewrites
   - `do { } while (false)` single-exit conversion is not forced
   - LLM warning dictionaries are normalized to readable warning messages
   - routine skipped rename warnings are display-filtered for large dispatchers
   - `.forge` metadata warning count uses the same displayed warning count as the rendered header
   - large-dispatcher LLM rename validation rejects speculative dispatcher temporaries
   - cleaned pseudocode export
   - cleaned pseudocode preview in an IDA custom viewer
   - aggregate `.forge` file beside the analyzed binary, with one replaceable section per function EA
   - runtime version is shown in `Show settings`, CLI `--version`, preview/export headers, switch outlines, `.forge` sections, and IDA Free JSON reports
   - `tools/release_pseudoforge.py` bumps the plugin version and writes `release/PseudoForge-<version>.zip`
   - aggregate `.forge` storage finalizes path-like string literals before writing
   - path-like C/C++ string literal finalization lives in
     `ida_pseudoforge/core/render_literals.py` while preserving the public
     `ida_pseudoforge.core.render._finalize_rendered_c_like_text` import path
   - generic runtime helper alias inference lives in
     `ida_pseudoforge/core/helper_aliases.py` and classifies strongly evidenced
     no-PDB memory-fill or memory-move helpers from signature roles plus helper
     body behavior before rewriting caller sites as `memset` or `memmove`
   - critical-region entry rewrite and LIST_ENTRY/provider-link hint annotation
     live in `ida_pseudoforge/core/render_kernel_hints.py`
   - low-byte parameter call-argument cleanup lives in
     `ida_pseudoforge/core/render_call_args.py`
   - known function/callback signature and body routing lives in
     `ida_pseudoforge/core/render_signatures.py`
   - generated header formatting and kernel semantic rewrite counting live in
     `ida_pseudoforge/core/render_header.py`
   - `Show current analysis result` displays only the cached current function `.forge` section and does not trigger decompile, LLM, or `.forge` refresh work
   - top-level `Analyzed functions...` action opens a chooser from cached `.forge` section markers instead of opening the full aggregate file
   - switch outline export
   - flow report export
   - IDA Output progress logging
   - IDA Output is limited to user-action start, completion, and failure messages
   - asynchronous log queue drained by an IDA main-thread timer callback
   - `PSEUDOFORGE_DISABLE_OUTPUT_LOG=1` fallback that keeps file trace while disabling Output writes
   - Analyze completion shows the summary popup and opens the cached preview after the popup closes
   - Analyze completion opens the current function section preview when the aggregate `.forge` has multiple sections
   - preview UI before/after checkpoints mirrored to `%TEMP%\pseudoforge_preview_trace.log`
   - worker-thread execution for analyze/export so Output logs can update while LLM work is running
   - plugin analysis state records target path, function EA/name, fingerprint, capture, plan, and `.forge` text/path as a session
   - analyze/export/apply share a conservative background coordination group to avoid racing plugin state
   - apply-selected-renames refuses stale sessions when the current function no longer matches the analyzed function
   - apply-selected-renames performs final preflight before `ida_hexrays.rename_lvar()`, including selected-source, apply flag, arg/lvar kind, identifier, missing-local, collision, and duplicate-target checks
   - analysis session path identity normalizes Windows case and separator differences to avoid false stale-session refusals
   - plugin action lifecycle is centralized through `ActionRegistry`
   - preview popup actions can be cleaned up during plugin termination
   - native IDA `simplecustviewer_t` preview, avoiding PyQt/PluginForm embedding for the `.forge` viewer
   - preview popup actions for Copy all, Save as, and Analyzed functions
   - Copy all writes `.forge` text directly through Windows Clipboard API `CF_UNICODETEXT`
   - Copy all writes `%TEMP%\pseudoforge_clipboard\copy_all.log` with clipboard API status
   - deterministic rules matching engine v1 under `ida_pseudoforge/core/deterministic`
   - data-only JSON rule pack schema, loader, validator, matcher, emitter, and rule report data
   - builtin rule packs under `ida_pseudoforge/rules/builtin`
   - project-local `.\pseudoforge_rules\*.json` and user-global `%APPDATA%\PseudoForge\rules\*.json` loading
   - v1 active phases: `rename` and `semantic_comment`
   - v1 supported match operators: `regex`, `assignment_regex`, `text_contains`, and `text_contains_all`
   - v2 supported match gates add `call_arg_count` and `call_arg_literal` for exact call-site argument count and literal argument value checks
   - v2 typed fact operators add `lvar`, `assignment`, `call_site`, and
      `profile_function` selectors for scope and match gates over existing
      `RuleContext` facts
   - typed fact matches expose deterministic bindings such as `$lvar`,
      `$assignment_target`, `$call_arg0`, and `$profile_param_name` to reduce
      fragile regex-only rule authoring
   - validator rejects ambiguous typed-match plus legacy `call_arg_*`/`flow_*`
      gate combinations, and accepts `scope.call_site` as an explicit call gate
      for preview-only call argument rewrite rules
   - builtin rules mirror low-risk local rename, assignment rename, and call-presence semantic comment rules while keeping existing hard-coded deterministic passes in place
   - rule-based rename suggestions still pass through `validate_renames()`
   - `RuleEngine.run(..., explain_misses=True)` records opt-in
      `missed_rules` diagnostics for authoring/debug workflows without changing
      normal IDA or CLI analysis reports
   - `tools/pseudoforge_rule_author.py` provides `validate`, `facts`, `run`,
      and `scaffold` commands for project-local rule authoring
   - export bundles include `<function>.rule-report.json`
   - export bundles include `<function>.buffer-contracts.md` and
     `<function>.buffer-contracts.json`
   - export bundles include `<function>.buffer-structs.hpp` packed C++ ABI
     sketches generated from recovered command buffer contracts, including
     observed/valid predicate comments, size constants, inline size validators,
     and directional byte windows for size-only contracts when rejection guards
     are recognized
   - focused IDA buffer-contract preview also reports selected-case context
     for non-buffer cases: shared-tail labels, cleanup classification, and
     generic cast-offset context accesses are shown separately from command
     input/output buffer ABI sketches
   - focused IDA helper capture now scans selected-case call-sites for recovered
     buffer or length arguments before the deep pass, so helper-only cases do
     not depend on a pre-existing local buffer contract
   - focused IDA preview and trace output include helper candidate counts before
     helper capture, making candidate discovery failures distinct from capture
     or decompilation failures
   - focused IDA preview reports captured helpers that are not linked back to
     the selected buffer path, making unrelated helper captures distinct from
     missing propagation
   - selected-case context preview includes case body line counts and a short
     excerpt, with a recovered source-line anchor fallback when dispatcher-name
     body slicing is unavailable
   - helper candidate and helper-edge matching now tolerate narrow casts on
     buffer arguments without relying on sample variable names: helper-only
     calls use length-adjacent pointer arguments as provisional buffer evidence,
     then promote them only when helper bodies expose matching size guards or
     field accesses. Helper evidence is merged back into the caller-side buffer
     contract role, length variables, source evidence, and derived valid
     predicates, so METHOD_BUFFERED helper-only cases can render as `INOUT` when
     input and output lengths guard the same system buffer. Direct IRP ABI
     assignments such as `AssociatedIrp.MasterIrp` or `AssociatedIrp.SystemBuffer`
     are treated as ABI evidence rather than variable-name shortcuts.
   - size-only buffer contracts no longer collapse generated C++ sketches to a
     single anonymous reserved array. When no fixed-offset fields are recovered,
     the sketch emits input/output size constants, an inline size validator, and
     directional byte windows such as shared inout bytes plus input/output
     extension ranges without inventing field names.
   - exact zero-length contracts now render as empty reviewed C++ structs plus
     `length == 0` validators instead of misleading one-byte reserved arrays.
   - NtSet-style shared-tail cases that assign a literal expected length in the
     selected case and validate that length after the switch can recover the
     selected case's size contract without importing unrelated field branches
     from other shared-tail selector paths.
   - NtSet buffer-contract recovery now handles enum `case` labels, repeated
     native switches for the same dispatcher, raw flow-recovered case bodies
     merged with the active rename map, simple buffer aliases such as
     `infoBuffer128 = systemInformation`, dispatcher/class parameters that
     decompile as pointer-looking types, truthy zero-length guards, and C++
     `void **` field reads without emitting invalid `void` members.
   - dispatcher equality branches that jump into a shared tail can recover the
     selected branch and joined tail when the selected body has no direct local
     contract evidence, and typed vector array reads such as
     `infoBuffer128[2].m128i_i64[0]` are converted into fixed byte offsets.
   - export bundles are documented as durable review, audit, sharing, and regression artifacts rather than an IDB write path

4. Offline CLI
   - `tools/pseudoforge_cli.py`
   - `tools/pseudoforge_free_cli.py`
   - `ida_pseudoforge/free/service.py`
   - `tools/pseudoforge_corpus_index.py`
   - `tools/pseudoforge_corpus_qa.py`
   - `tools/pseudoforge_ida_batch.py`
   - `tools/pseudoforge_ida_cli.py`
   - `tools/run_pseudoforge_ida_batch.ps1`
   - `tools/summarize_pseudoforge_ida_batch.py`
   - `tools/empty_llm_rename_provider.py`
   - `tools/pseudoforge_free_console.py`
   - `tools/validate_pseudoforge_rules.py`
   - optional `--llm-renames` path for configured rename assist provider
   - `--llm-provider` supports OpenAI-compatible, Ollama, LM Studio, vLLM, llama.cpp, OpenRouter, DeepSeek API, Codex CLI, Claude CLI, `chatgpt_oauth_via_codex_cli`, and `claude_login_via_claude_cli`
   - optional `--rules-dir` for additional deterministic rule directories
   - optional `--rule-report` for writing a rule report JSON file or directory
   - IDA Free-compatible offline CLI path for copied or saved cloud-decompiled pseudocode text
   - shared IDA Free analysis service for CLI and standalone GUI callers
   - IDA Free CLI path uses `ida_pseudoforge/core/offline_input.py` for conservative single-function extraction
   - IDA Free CLI path rejects no-function and multiple-function inputs with actionable diagnostics
   - IDA Free CLI path emits cleaned pseudocode, raw pseudocode, raw-vs-cleaned diff, rename map, warnings, rule report, and summary artifacts
   - IDA Free CLI path supports `--project-root`, `--rules`, `--llm`, `--no-llm`, `--no-progress`, and `--format text|json`
   - IDA Free CLI text mode prints incremental progress by default and reports `complete`, `partial`, or `failed` final status summaries
   - IDA Free CLI JSON mode keeps stdout machine-readable and writes progress to stderr unless `--no-progress` is used
   - IDA Free CLI path does not import IDA-only modules, does not use IDAPython or local Hex-Rays APIs, and does not modify an IDB
   - headless IDA batch mode can iterate `.i64`/`.idb` functions, call Hex-Rays decompile, analyze through PseudoForge, append `.forge` sections, and write JSONL progress reports
   - external IDA CLI path accepts `ida_path`, `idb_path`, and `output_dir`, launches IDA batch mode, auto-uses saved plugin LLM settings inside IDA, and writes full per-function export bundles under `functions\<ea>_<function>`
   - batch mode supports `--llm-renames-auto` for saved plugin config reuse and `--require-configured-llm` for fail-closed LLM-included runs
   - batch mode supports `--export-dir` for full per-function cleaned, raw, diff, rename-map, rule-report, buffer-contract, warning, and summary artifacts
   - external IDA CLI supports `--pdb-path` and `--symbol-path` to set child-process `_NT_SYMBOL_PATH` / `_NT_ALT_SYMBOL_PATH` for PDB-backed batch analysis, while rejecting those options when `--no-pdb` is used
   - external IDA CLI tails batch JSONL progress in wait mode and prints `Analyzing <index>/<total>: <function> (<ea>)` for the currently running function
   - external IDA CLI supports Ctrl+C cancellation by writing the configured/default cancel sentinel, waiting for cooperative batch stop, and terminating the IDA process if it remains busy
   - batch mode supports `--corpus-metadata` to export IDA-level segments, imports, exports, strings, names, per-function call edges, import calls, string references, caller/callee names, and function flags for downstream corpus understanding
   - external IDA CLI now writes `pseudoforge-corpus-metadata.json`, builds `pseudoforge-corpus-index.json`, and writes `pseudoforge-corpus-overview.md` by default after a completed run
   - corpus index builder merges function bundles, metadata, report summaries, warnings, deterministic rule diagnostics, buffer contracts, tags, imports, strings, and call relationships into a searchable JSON artifact
   - corpus Q&A CLI retrieves relevant functions from the index, emits an evidence context pack without requiring LLM calls, and can use saved/overridden LLM provider settings for evidence-cited answers
   - corpus artifacts are agent-agnostic handoff files: external agents can read the corpus index, metadata, overview, per-function bundles, or focused `qa-context.md` files without IDA or PseudoForge runtime access
   - `docs/pseudoforge-corpus-agent-skill.md` provides a copy-ready Markdown skill that tells other AI agents how to use the full batch corpus for grounded binary Q&A
   - the corpus-agent skill documents the recommended split between `%USERPROFILE%\.codex\skills\pseudoforge-corpus-qa\SKILL.md` for the skill and `F:\pseudoforge-corpora\<target-name>\` or repo-local `pseudoforge_out\<target-name>\` for generated artifacts
   - `tools/kernel_corpus/` provides the consumer-side Kernel Corpus pack layer: SQLite builder, scale profiler, freshness validator, read-only query CLI, stdio MCP server, lifecycle tracer, subsystem atlas generator, answer harness, deterministic question router/answer planner, cross-build canonical drift comparator, canonical P0/P1/P2 answer artifact generator, canonical quality audit with reviewable golden expectations, read-only canonical answer discovery/retrieval via `canonical_store.py` and MCP tools, canonical production review queue generation with optional read-only operator decision ledgers, canonical-first agent workflow rules with pass/degraded/fail/stale decision boundaries, first-pass audit tuning to zero failing P0/P1 topics on the local ntoskrnl pack, 36-topic P2 operational curation tier with zero failing local ntoskrnl audit topics, expanded lifecycle ontologies, lifecycle cross-topic candidate penalties, relevance-filtered atlas hubs, dry-run-first install wiring, opt-in experimental vector recall, and the `kernel-corpus-analysis` skill
   - `docs/kernel-corpus-runbook.md` documents the Kernel Corpus build, freshness validation, status, query, lifecycle, atlas, answer-prompt harness, deterministic answer planning, cross-build canonical drift comparison, canonical P0/P1/P2 answer artifact generation, P2-only build and audit smoke commands, canonical audit reports, canonical MCP discovery/retrieval workflow, canonical answer decision matrix, canonical review queue and generated decision-ledger workflow, audit expectation tuning rules, scale profiling, recommended bounds, experimental vector recall risks, MCP config, skill install/update/uninstall, and generated-output workflow while keeping generated packs under ignored or external output roots
   - optional `--compare-dir` / `-CompareDir` emits per-function raw Hex-Rays text, PseudoForge cleaned output, full `.forge` section, and raw-vs-cleaned unified diff artifacts
   - batch compare JSONL records include shared-style artifact keys while preserving legacy path fields
   - optional `--llm-renames` / `-LlmRenames` routes batch analysis through the same rename provider/fallback path as interactive IDA Analyze
   - IDA batch rendering applies direct helper alias postprocessing before
     writing compare artifacts, forge sections, and diffs so caller cleanup does
     not depend on a prior all-functions interactive analysis pass
   - `tools/score_pseudoforge_quality.py` scores raw-vs-cleaned compare
     directories using `ida_pseudoforge/core/quality_score.py` and emits JSON
     or Markdown summaries of remaining artifacts and recovery signals
   - Hex-Rays decompile-unavailable functions are recorded as `skipped` instead of PseudoForge failures

5. IDA Free Studio standalone GUI
   - `tools/pseudoforge_free_gui.py`
   - `ida_pseudoforge/gui/free_app.py`
   - PySide6 desktop entrypoint for IDA Free users
   - side-by-side raw and cleaned pseudocode panes
   - C-like syntax highlighting for raw and cleaned pseudocode editors
   - toolbar actions for Paste, Open, Analyze, Stop, Copy Cleaned, Save Bundle, and Settings
   - bottom tabs for warnings, accepted/skipped renames, raw-vs-cleaned diff, rule report, and artifact paths
   - background worker thread for deterministic analysis and optional provider calls
   - cooperative cancellation at safe analysis service boundaries; active provider calls are not force-killed
   - Settings dialog reuses the existing provider registry/factory/config model for OpenAI-compatible, Ollama, LM Studio, vLLM, llama.cpp, OpenRouter, DeepSeek, Codex CLI, Claude CLI, `chatgpt_oauth_via_codex_cli`, and `claude_login_via_claude_cli`
   - default review bundles are written under `%LOCALAPPDATA%\PseudoForge\sessions\<timestamp>_<input>` when available
   - Save Bundle rewrites the current result to a user-selected directory without rerunning analysis
   - PySide6 is an optional GUI dependency; the CLI and deterministic core remain usable without it
   - Free Studio does not import IDA-only modules, does not use IDAPython/local Hex-Rays APIs, and does not modify an IDB

6. Optional LLM assist
   - `ida_pseudoforge/models/openai_compatible.py`
   - `ida_pseudoforge/models/cli_provider.py`
   - `ida_pseudoforge/models/provider_factory.py`
   - `ida_pseudoforge/models/provider_registry.py`
   - `ida_pseudoforge/models/prompting.py`
   - `ida_pseudoforge/core/llm_assist.py`
   - `ida_pseudoforge/config.py`
   - IDA-side `pseudoforge_config.json` storage
   - read-only provider combo box in `Configure LLM rename assist`
   - read-only provider-specific model combo box in `Configure LLM rename assist`
   - dynamic model discovery through `codex debug models` / Codex cache for ChatGPT and Codex CLI providers
   - warning-free static Claude model list for Claude CLI providers, headed by current IDs and aliases: `claude-opus-4-8`, `claude-sonnet-4-6`, and `claude-haiku-4-5`
   - dynamic model discovery through `/models` for HTTP providers, with static fallback
   - Free Studio settings refresh HTTP provider model lists from `/models` when the provider, base URL, or API key changes
   - named local OpenAI-compatible providers for Ollama, LM Studio, vLLM, and llama.cpp use local default base URLs and do not require API keys by default
   - CLI command templates pass the selected model through `{model}`
   - Claude CLI defaults include `--no-session-persistence`, disabled tools, and `--setting-sources project,local` so user/global Claude hooks do not pollute JSON-only rename-assist output
   - migration for old default Codex/Claude command templates that did not pass `{model}`, used unsupported Codex CLI flags, omitted safer Claude print-mode flags, or omitted Claude setting-source isolation
   - Windows CLI provider calls and Codex model discovery request hidden child console windows to avoid Claude/Codex console flashes during normal runs
   - analyze summary displays warning details instead of only warning counts
   - IDA Output now includes a short ASCII-safe reason when LLM rename assist fails before deterministic fallback
   - provider-specific API key storage under `credentials`
   - API key prompt only when an enabled API-backed HTTP provider has no stored key
   - disabled by default
   - IDA LLM configuration dialog logic is isolated in `ida_pseudoforge/ida/llm_config_dialog.py`, and model-discovery exceptions fall back to static model lists without saving corrupt config

7. Tests
   - `tests/test_ida_plugin_safety.py`
   - `tests/test_buffer_contracts.py`
   - `tests/test_free_service.py`
   - `tests/test_free_gui.py`
   - `tests/test_render_callbacks.py`
   - `tests/test_render_call_args.py`
   - `tests/test_render_dispatcher.py`
   - `tests/test_forge_store.py`
   - `tests/test_render_driver_entry.py`
   - `tests/test_render_flow.py`
   - `tests/test_render_header.py`
   - `tests/test_render_ioctl.py`
   - `tests/test_render_kernel_hints.py`
   - `tests/test_render_labels.py`
   - `tests/test_render_literals.py`
   - `tests/test_render_memory.py`
   - `tests/test_render_ntset.py`
   - `tests/test_rename_heuristics.py`
   - `tests/test_render_snapshots.py`
   - `tests/test_render_signatures.py`
   - `tests/test_render_status.py`
   - `tests/test_render_style.py`
   - `tests/test_render_warnings.py`
   - `tests/test_render_zw.py`
   - `tests/test_rule_engine.py`
   - `tests/test_rule_integration.py`
   - `tests/test_rule_pack_validator.py`
   - `tests/test_rule_context.py`
   - `tests/test_ui_preview.py`
   - `tests/test_plan_builder.py`
   - `tests/test_helper_aliases.py`
   - `tests/test_ida_batch.py`
   - `tests/test_ida_identity_apply_smoke.py`
   - `tests/test_kernel_api_profile_builder.py`
   - `tests/test_llm_cli_provider.py`
   - `tests/test_llm_config.py`
   - `tests/test_llm_rename_filters.py`
   - `tests/test_profile_loader.py`
   - `tests/test_profile_load_smoke.py`
   - `tests/test_export_bundle.py`
   - `tests/test_logging.py`
   - `tests/test_pseudoforge_free_cli.py`
   - `tests/test_quality_score.py`
   - `tests/test_release_pseudoforge.py`
   - `tests/test_render_cleanup.py`
   - `tests/test_rule_diagnostics.py`
   - renderer golden snapshots under `tests/snapshots`
   - current suite covers 463 unit tests

## Latest Implementation Notes

Focused disassembly-assisted buffer contract recovery:

- Added `ida_pseudoforge/core/disasm_contracts.py` with an offline
  `DisasmCaseSlice` / `DisasmInstruction` model so tests and CLI-adjacent
  workflows can inject disassembly evidence without importing IDA modules.
- The disassembly analyzer tracks simple aliases from moves/loads, maps x64
  Windows call arguments from `RCX`, `RDX`, `R8`, `R9`, and available
  `[rsp+20h...]` stack arguments, and resolves `mov rax, Helper; call rax`
  style indirect helper targets without naming any specific kernel helper.
- Selected-case disassembly evidence recovers `cmp`/`test` plus conditional
  branch size guards, fixed-offset buffer memory reads/writes, field predicates,
  bitmask predicates, and helper call edges. Rejection branches derive valid
  predicates such as `length >= min` or `field == expected`.
- `recover_buffer_contracts()` now accepts focused disassembly slices and merges
  them into the existing `BufferSizeConstraint`, `FieldAccess`,
  `FieldConstraint`, and `HelperContractEdge` data model. Matching pseudocode
  and disassembly evidence raises confidence slightly; conflicting size or
  field predicate evidence is retained and reported as a warning instead of
  silently overwriting either source.
- Disassembly helper edges are resolved through the existing helper pseudocode
  capture path when available, or through an injected helper disassembly slice
  when pseudocode is not available. Both paths preserve the configured helper
  depth limit and keep unresolved helper escapes explicit.
- IDA focused analysis captures bounded basic-block CFG slices from the selected
  case entry when possible. Cursor mode uses the active screen EA; explicit
  value mode can fall back to a generic immediate-compare/conditional-branch
  target search. If no reliable native entry is found, analysis remains
  pseudocode-first and unchanged.
- C++ struct sketches now benefit directly from disassembly-derived field
  offsets and predicates because the merged evidence feeds the existing struct
  renderer. Size-only cases still render size constants and byte windows rather
  than invented field names.
- Current limitations: the IDA value-mode native-entry fallback is intentionally
  conservative and does not fully decode every compiler jump-table layout yet;
  helper field writes are represented as caller-visible fields only when the
  merged selected-case evidence or propagated helper predicates expose a fixed
  offset; unsupported/no-evidence cases still prefer an explicit no-contract
  report over fabricated structure fields.

P1 renderer snapshot protection update:

- Added a renderer snapshot harness for `render_cleaned_pseudocode()` output.
- Initial normalized golden snapshots cover native API dispatcher,
  DriverEntry/device-extension cleanup, IOCTL dispatch, OB pre-operation
  callback, and generic non-kernel style output.
- Snapshot comparison normalizes version and input fingerprint metadata while
  preserving the rendered header/body structure for regression review.
- Snapshot updates require explicit `PSEUDOFORGE_UPDATE_SNAPSHOTS=1` and are
  documented in `tests/snapshots/README.md`.
- `render_cleaned_pseudocode()` now builds a `RenderContext` carrying capture,
  plan, active rename map, display-filtered warnings, and native switch
  dispatcher metadata before header/body rendering.
- NTSTATUS literal replacement, 32-bit status assignment/store replacement, and
  status accumulator type upgrades now live in `ida_pseudoforge/core/render_status.py`.
- Generated-code style normalization now lives in
  `ida_pseudoforge/core/render_style.py`, with focused direct module coverage
  plus existing renderer snapshots preserving output behavior.
- Dispatcher/profile literal rendering for `SYSTEM_INFORMATION_CLASS`,
  `PROCESSINFOCLASS`, and character case labels now lives in
  `ida_pseudoforge/core/render_dispatcher.py`.
- IOCTL/IRP rendering for `CTL_CODE(...)` switch annotations,
  `AssociatedIrp.SystemBuffer`, IRP dispatch signatures/body cleanup, and
  `IO_STACK_LOCATION.Parameters.DeviceIoControl` field access now lives in
  `ida_pseudoforge/core/render_ioctl.py`.
- Semantic label rendering for cleanup label renaming, annotations,
  indentation normalization, and stale embedded-tail hoisting now lives in
  `ida_pseudoforge/core/render_labels.py`.
- DriverEntry rendering for canonical signature output, status normalization,
  IRP major constants, device flags, and `IoCreateDevice` secure-open rendering
  now lives in `ida_pseudoforge/core/render_driver_entry.py`.
- Callback rendering for OB pre-operation signatures, callback registration
  toggle body cleanup, and Configuration Manager callback registration status
  checks now lives in `ida_pseudoforge/core/render_callbacks.py`.
- Zw API probe rendering for `OBJECT_ATTRIBUTES` length/flag cleanup,
  `NtCurrentProcess()` / `NtCurrentThread()`, and Zw status success checks now
  lives in `ida_pseudoforge/core/render_zw.py`.
- Zw API probe, reused Zw status-slot, and `MmGetSystemRoutineAddress`
  indirect-call regressions now live in `tests/test_render_zw.py`.
- TraceLogging template switch false-positive regression now lives in
  `tests/test_render_flow.py`.
- Known `PVOID` native signature/body-alias regression now lives in
  `tests/test_render_signatures.py`.
- NtSet m128 alias split and prenormalized alias regressions now live in
  `tests/test_render_ntset.py`.
- Semantic-label stale-layout and duplicate-label regressions now live in
  `tests/test_render_labels.py`, with reusable kernel samples in
  `tests/fixtures/kernel_samples.py`.
- Success-accounting label-tail classification regression now lives in
  `tests/test_render_labels.py`.
- Shared NtSet system-information sample coverage now uses
  `tests/fixtures/ntset_samples.py` instead of importing from the deleted core
  monolith.
- Snapshot-shared DriverEntry, IOCTL dispatch, and single-line style samples
  now use `tests/fixtures/snapshot_samples.py` instead of importing from
  renderer test modules.
- Firmware handler kernel-driver semantics regression now lives in
  `tests/test_render_kernel_hints.py`.
- Multiline-condition brace and single-line if-body style regressions now live
  in `tests/test_render_style.py`.
- Deterministic rename heuristic and cfunc/text lvar merge regressions now live
  in `tests/test_rename_heuristics.py`.
- LLM rename filtering regressions now live in
  `tests/test_llm_rename_filters.py`.
- Repeated JSON rename-provider fixtures for the LLM rename-filter suite now
  live in `tests/helpers.py`.
- Plan-builder semantic recovery and shadowed duplicate-target warning
  regressions now live in `tests/test_plan_builder.py`.
- The final broad render smoke coverage moved into `tests/test_render_ntset.py`
  and `tests/test_render_flow.py`; `tests/test_core_engine.py` has been
  removed.
- `NtSetSystemInformation` m128/body rendering for typed `systemInformation`
  access, mutable alias splitting, and `userProbeEnd` recovery now lives in
  `ida_pseudoforge/core/render_ntset.py`.
- Warning formatting, warning ranking, and display-only suppression filters now
  live in `ida_pseudoforge/core/render_warnings.py` while preserving the public
  `ida_pseudoforge.core.render.display_warning_count` import path.
- Flow report and conservative switch outline rendering now live in
  `ida_pseudoforge/core/render_flow.py` while preserving the public
  `ida_pseudoforge.core.render.render_flow_report`,
  `ida_pseudoforge.core.render.render_switch_outline`, and
  `_is_safe_switch_outline_body` import paths.
- Path-like C/C++ string literal finalization now lives in
  `ida_pseudoforge/core/render_literals.py` while preserving the public
  `ida_pseudoforge.core.render._finalize_rendered_c_like_text` import path
  used by forge storage and IDA preview save/copy paths.
- Kernel hint rendering for critical-region entry normalization and
  LIST_ENTRY/provider-link comments now lives in
  `ida_pseudoforge/core/render_kernel_hints.py` while preserving the public
  private-helper aliases imported through `ida_pseudoforge.core.render`.
- Low-byte parameter call-argument cleanup now lives in
  `ida_pseudoforge/core/render_call_args.py` while preserving the public
  private-helper alias imported through `ida_pseudoforge.core.render`.
- Known function/callback signature replacement and signature-sensitive body
  routing now live in `ida_pseudoforge/core/render_signatures.py` while
  preserving public private-helper aliases imported through
  `ida_pseudoforge.core.render`; empty capture names now fall back to the
  prototype function name for signature replacement.
- Generated header formatting and kernel semantic rewrite counting now live in
  `ida_pseudoforge/core/render_header.py` while preserving the public
  `ida_pseudoforge.core.render._kernel_semantic_rewrite_count` import path.

P1 profile loader diagnostics update:

- Profile loading now records visible warnings for missing files, invalid JSON,
  read failures, and non-object profile roots instead of silently returning an
  empty profile without diagnostics.
- Renderer headers/flow reports, offline CLI, IDA Free CLI artifacts, and IDA
  batch JSONL records include profile load warnings after profile-backed paths
  run.
- `profiles_manifest.json` records built-in profile kind, source version, entry
  counts, and SHA-256 metadata.
- Export summaries report manifest metadata for profiles loaded during the
  current run.
- Kernel API runtime lookups now use split family loader APIs for functions,
  enums, indices, and symbols when those files are present, with monolithic
  `kernel_api.json` fallback for the current built-in profile.
- `tools/build_kernel_api_profile.py` can write split family profile files with
  `--split-output-dir`; `--split-only` skips monolithic output for split-only
  generation workflows.
- `tools/profile_load_smoke.py` measures split-family cold-load and repeated
  cached lookup paths and fails closed on profile warnings, empty loads, or
  unexpected monolithic `kernel_api.json` loads while split files are present.
- Optional target-build profile roots can be selected with
  `PSEUDOFORGE_PROFILE_DIR` or `--profile-dir` on the offline CLI, IDA Free CLI,
  IDA batch script, and profile smoke tool, plus `-ProfileDir` on the
  PowerShell batch wrapper. Changing the loader profile root clears cached
  profile data, and IDA batch start JSONL records the selected profile
  directory.
- Interactive IDA sessions can persist a profile root through
  `Edit/PseudoForge/Configure profile directory`; subsequent interactive
  analysis applies that root before deterministic or optional LLM analysis.
- `tests/test_profile_loader.py` covers invalid JSON warning recording and cache
  reset behavior plus active profile manifest/name reporting, profile directory
  selection, empty-selection environment override behavior, smoke-tool profile
  directory selection, and split-family loader fallback behavior.

P1 export artifact parity update:

- Shared export bundles now include raw pseudocode, warnings JSON,
  raw-vs-cleaned diff, and per-function summary JSON in addition to the existing
  cleaned pseudocode, switch outline, rename map, flow report, and rule report.
- Shared artifact writing now lives in `ida_pseudoforge/core/export_bundle.py`,
  with a compatibility wrapper left at `ida_pseudoforge.core.render.write_export_bundle`.
- IDA interactive export, offline CLI, and IDA Free CLI calls pass entrypoint
  metadata into the shared bundle writer.
- IDA Free CLI keeps the existing `.ida-free-summary.json` summary filename
  without leaving an extra unreported `.summary.json` artifact.
- Shared export summaries and IDA Free result summaries include active profile
  root, loaded profile names, and manifest metadata when profile manifests
  exist.
- `README.md` documents artifact parity across IDA interactive export, offline
  CLI, and IDA Free CLI.
- `tests/test_export_bundle.py` covers parity artifact creation and summary
  metadata.

P1 deterministic rules v2 preview boundary update:

- Rule packs can use `schema_version: 2` for preview-only
  `call_arg_rewrite` emissions.
- `call_arg_rewrite` rules must declare `preview_only: true`, a target function
  name, a non-negative argument index, and a replacement.
- Static target function names must be gated by matching `calls_any`/`calls_all`
  scope so v2 rewrite candidates do not match only on broad text evidence.
- Runtime support emits `RuleEmission(kind="call_arg_rewrite")` but does not
  convert it into rename/comment plan outputs or any IDB write path.
- Rule reports now include `rewrite_emissions` entries for preview-only
  `call_arg_rewrite` candidates with `applied`, `shadowed`, or `rejected`
  status.
- `build_clean_plan()` runs the `call_arg_rewrite` phase for reporting only;
  accepted rewrite candidates remain out of rename, comment, pseudocode, and
  IDB-write paths.
- Rule packs can also use `schema_version: 2` for preview-only `text_rewrite`
  emissions gated by `requires_comment_kind`.
- `text_rewrite` rules require explicit `before_regex`, `replacement`, and
  `preview_only: true` fields.
- Runtime support records `RuleEmission(kind="text_rewrite")` candidates in
  `rewrite_emissions` and resolves overlapping spans as `applied`/`shadowed`
  report entries only.
- `build_clean_plan()` runs the `text_rewrite` phase after semantic comments
  for reporting only; accepted candidates do not change rendered pseudocode or
  any IDB-write path.
- Rule packs can now use `schema_version: 2` for preview-only `flow` emissions
  over already recovered `FlowRewrite` facts.
- `flow` rules require `preview_only: true`, a non-empty `flow_kind`, and
  `flow_case_count_min >= 3`; optional dispatcher regex and body-state gates
  can further narrow the recovered branch evidence.
- Runtime support records `RuleEmission(kind="flow")` candidates in
  `rewrite_emissions` and resolves same-dispatcher/same-flow-kind conflicts as
  `applied`/`shadowed` report entries only.
- `build_clean_plan()` runs the `flow` phase after conservative flow recovery;
  accepted candidates do not change `CleanPlan.flow_rewrites`, rendered
  pseudocode, switch outlines, or any IDB-write path.
- Builtin v2 report-only rules now mirror the low-risk
  `PsSetCreateProcessNotifyRoutine`/`PspSetCreateProcessNotifyRoutine`
  BOOLEAN remove-argument cleanup family for parity comparison with the
  existing kernel API renderer path.
- `deterministic_rules_matching_engine_design.md` documents the v2
  preview/export-only boundary.

P2 RuleContext call-site facts update:

- `RuleContext.call_sites` now records argument lists, absolute argument spans,
  and line indexes.
- Call-site argument parsing reuses shared parenthesis matching and parameter
  splitting helpers, including nested calls and comma-containing strings.
- Malformed call text keeps a partial call-site fact without raising.
- `RuleContext.assignments` now records RHS identifiers, numeric literals, and
  pure RHS call names/arguments for assignment dataflow gates.
- Non-call RHS expressions keep call details empty while preserving identifier
  and literal facts.
- `RuleContext` now exposes local-variable facts from `FunctionCapture.lvars`,
  including type text, argument status, index, location, and identity metadata.
- `lvar_types` and `arg_names` indexes provide direct access to typed locals
  and captured arguments without reparsing pseudocode declarations.
- V2 rule matching now supports `call_arg_count` and `call_arg_literal` gates
  over the same call site, keeping v1 match operators unchanged.
- `RuleContext.profile_functions` now records profile-backed metadata for known
  calls, including headers, return types, parameter names/types/kinds, enum
  tags, and alias information.
- Rule contexts built during `build_clean_plan()` use the kernel API profile
  lookup and skip unknown or failed profile lookups without aborting rules.

P2 switch body reporting update:

- Recovered switch cases now carry explicit body states:
  `single_statement_body`, `complete_branch_slice`, `shared_tail`,
  `fallthrough_or_join`, and `complex_unsliced`.
- Switch outlines and flow reports include source line anchors and shared-tail
  labels when available, while still refusing to expand goto-dependent shared
  tails as unique case bodies.
- Complete local branch slices are expanded only when their simple statements
  end in a local return and contain no labels, gotos, or nested control flow.
- Native switch recovery now handles `switch (...) {` brace placement on the
  switch line and has regression coverage for fallthrough cases plus nested
  switch cases that must not be promoted to the parent dispatcher.
- Flow and switch-outline regressions now live in `tests/test_render_flow.py`.
- No-PDB DriverEntry, DriverEntry wrapper, device-extension, and offset-guard
  regressions now live in `tests/test_render_driver_entry.py`.
- Memory Manager probe regressions now live in `tests/test_render_memory.py`.
- Bounded logging rotation regression now lives in `tests/test_logging.py`.
- Plugin version/manifest parity regression now lives in
  `tests/test_release_pseudoforge.py`.
- Status literal rendering regressions now live in `tests/test_render_status.py`.
- NTSTATUS profile lookup and generator regressions now live in
  `tests/test_render_status.py`.
- Dispatcher/profile literal regressions now live in
  `tests/test_render_dispatcher.py`.
- Generated style and positive-guard inversion regressions now live in
  `tests/test_render_style.py`.
- Forge-store aggregate/upsert, section lookup, save filename, and
  current-section preview regressions now live in `tests/test_forge_store.py`.
- Preview syntax highlighting regressions now live in
  `tests/test_ui_preview.py`.
- RuleContext call-site, assignment, local-variable identity, and
  profile-function fact regressions now live in `tests/test_rule_context.py`.
- Deterministic rule-pack validator regressions now live in
  `tests/test_rule_pack_validator.py`, with shared test rule builders in
  `tests/helpers.py`.
- Legacy `tests/llm_test_helpers.py` and `tests/rule_test_helpers.py` remain as
  compatibility re-export modules only.
- Deterministic RuleEngine emission, gate, conflict, and runtime-error
  regressions now live in `tests/test_rule_engine.py`.
- Deterministic rule integration regressions for build-plan reports, builtin
  call-argument rewrites, project rule loading, source-path discovery,
  duplicate rule-dir dedupe, source spoofing, and semantic-comment dedupe now
  live in `tests/test_rule_integration.py`.
- IDA batch report summary, optional-LLM fallback, compare artifact, and
  Windows-safe file-stem regressions now live in `tests/test_ida_batch.py`.
- LLM config, provider registry, response parsing, CLI stdout, and
  command-template migration regressions now live in `tests/test_llm_config.py`.
- Kernel API profile rewrite, alias lookup, WDK parser, and profile semantics
  regressions now live in `tests/test_kernel_api_profile_builder.py`.
- IOCTL/IRP dispatch, stack-location union-arm gating, buffered SystemBuffer,
  completion-tail, warning suppression, and CTL_CODE literal regressions now
  live in `tests/test_render_ioctl.py`.
- Callback signature, OB pre-operation field rewrite, callback registration
  toggle, packed operation registration, and registry callback regressions now
  live in `tests/test_render_callbacks.py`.

P0 rename identity hardening update:

- Cfunc-derived local captures now carry optional lvar identity metadata.
- Rename plans attach captured lvar identity data where available.
- Apply-selected-renames now rechecks the current lvar identity before calling
  `ida_hexrays.rename_lvar()` and rejects same-name/different-identity drift.
- Identity-backed IDA apply is refused if the current lvar identity cannot be
  re-read before the write.
- Lvar location capture now prefers stable stack offset, register, definition
  EA/block, and locator text anchors while ignoring object-address strings.
- Legacy name-based preflight remains available when identity metadata is not
  present, preserving offline and older-capture behavior.
- Focused safety tests cover identity match, identity drift rejection, and
  legacy fallback plus enriched location anchor extraction.
- `tools/pseudoforge_ida_identity_apply_smoke.py` validated the identity-backed
  apply path in IDA Professional 9.0 against a temporary `notepad.exe` IDB:
  after a Hex-Rays refresh, stable identity preflight passed,
  same-name/different-identity drift was rejected, `ida_hexrays.rename_lvar()`
  applied the selected local rename, and the renamed local was visible after a
  second refresh. The smoke tool refuses non-temp inputs by default because it
  performs a real local-variable rename.

P2 IDA UX diagnostics update:

- The IDA analysis completion summary now includes deterministic rule-report
  counts for matched rules, rewrite emissions by status, rule-pack load errors,
  and validation errors.
- The IDA analysis completion summary includes bounded rule load and validation
  error details so broken rule packs can be identified without opening the full
  JSON report first.
- Export `.summary.json`, IDA Free `.ida-free-summary.json`, and IDA Free JSON
  results include a shared `rule_diagnostics` payload with matched-rule counts,
  rewrite emission status/kind counts, and rule load/validation error details.
- Detailed rule diagnostics remain in the exported `rule-report.json`; the IDA
  popup keeps error details bounded, while export summaries retain full
  machine-readable rule error details for audit workflows.

P2 IDA LLM model discovery UX update:

- IDA LLM configuration now performs a bounded live `/models` lookup for HTTP
  providers after the selected base URL and required API key are known, so the
  model chooser reflects the current endpoint on the same configuration run.
  Review mode fixed the live lookup timeout bound to honor the configured
  timeout up to 60 seconds instead of cutting local HTTP providers off early.
- Codex-backed CLI catalog discovery keeps the non-blocking cache path because
  CLI model enumeration can be slow and does not depend on an editable base URL.
- Duplicate background refreshes for the same provider cache key are suppressed
  while one refresh is already running.
- Existing fail-closed/fallback behavior is preserved: discovery failures use
  provider static models with a warning.

P2 IDA side-by-side preview update:

- Analysis preview can try an experimental dockable raw-vs-cleaned review panel
  through the persisted `Edit/PseudoForge/Configure preview mode` setting.
- The plugin explicitly creates the `Edit/PseudoForge` parent menu and the
  `Advanced` child menu before attaching actions, and `Edit/Plugins/PseudoForge`
  opens the preview mode configuration as a fallback.
- `PSEUDOFORGE_PREVIEW_BACKEND` remains a temporary launch-time override for
  forcing `side_by_side` or `simple` during troubleshooting.
- The dockable panel uses IDA `PluginForm` plus Qt widgets when available.
- Cached current-function preview now reuses the active raw Hex-Rays analysis
  session for side-by-side mode when the session still matches the current
  function, and new `.forge` sections persist encoded raw pseudocode so cached
  side-by-side preview can be reopened without rerunning analysis. Legacy
  sections without stored raw pseudocode warn and open the cleaned cached
  section only.
- The dockable panel now keeps the status, warning/rule summary, and search
  controls in fixed-height rows so the raw and cleaned code panes receive the
  available vertical space.
- Side-by-side search now marks every matched occurrence with a subdued
  highlight and marks the active `Prev`/`Next` match with a stronger highlight.
- The raw and cleaned dockable panes use Qt syntax highlighting when
  `QSyntaxHighlighter` is available, reusing the same token-role classifier as
  the simple preview with an explicit neutral foreground base so IDA theme
  defaults do not turn unchanged pseudocode into comment green, while
  preserving plain-text fallback.
- README now includes a side-by-side dockable preview screenshot at
  `screenshots/example4.png`, showing compact status/search rows, raw and
  cleaned panes, syntax highlighting, and active search-match highlighting.
- README now includes a focused buffer-contract analysis screenshot at
  `screenshots/example_buffer_analysis.png`, showing the cursor-case context
  menu action and generated C++ ABI sketch preview.
- README now links the standalone IDA Free Studio GUI walkthrough video at
  `screenshots/IDA-free-gui-demo.mp4`, showing the paste/open, analysis,
  review-tab, cleaned-output, and bundle-save workflow for copied IDA Free
  cloud-decompiled pseudocode.
- Dockable preview fallback now reports the concrete unavailable backend reason.
  Inside IDA, Qt binding discovery is constrained to Qt5-compatible bindings so
  PySide6/PyQt6 cannot be loaded into IDA 9.0's Qt5 process.
- The existing `simplecustviewer_t` preview remains the default path and the
  fallback path when the feature flag is disabled or the dockable backend cannot
  be created.

P2 long-running operation cancellation/progress update:

- Interactive IDA analyze/export/apply-preparation tasks now have cooperative
  cancellation checkpoints and a `Cancel current operation` menu action.
- Cancellation does not forcefully terminate an active Hex-Rays decompile or LLM
  provider call; it stops at the next safe PseudoForge phase boundary.
- Headless IDA batch reports now emit `progress` records before each function
  starts, so the currently long-running function is visible before completion.
- `tools/pseudoforge_ida_batch.py --cancel-file` and the wrapper
  `-CancelFile` option stop at the next function boundary when the sentinel file
  exists and record a `stop` event with `reason=cancel_file`.
- `tools/pseudoforge_ida_cli.py` now consumes those progress records while it
  waits, prints the current function ordinal/name/EA, and maps Ctrl+C to the
  configured/default cancel sentinel before forcefully cleaning up IDA if needed.

The current implementation state reflects the `NtSetSystemInformation`,
`NtSetInformationProcess`, and `NtSetInformationThread` large-dispatcher
regression pass:

- `NtSetSystemInformation` preview now uses the canonical native API signature and introduces typed `__m128i *` aliases without changing the underlying decompiler body semantics.
- `SYSTEM_INFORMATION_CLASS` literal and delta-chain rewrites are profile-backed, including chained temporaries such as `v86 = v85 - 8` when the rewrite is still structurally tied to the original dispatcher comparison.
- `NtSetInformationProcess` preview now uses the canonical native API signature with `PROCESSINFOCLASS processInformationClass` and rewrites process-info-class case labels/comparisons through the 25H2 profile.
- `NtSetInformationThread` preview now uses the canonical native API signature
  with `THREADINFOCLASS threadInformationClass` and uses WDK-backed
  `THREADINFOCLASS` enum values for switch recovery and buffer-contract names.
- The 26200.8457 kernel IDB regression pass loaded
  `D:\bin\os\26200.8457\ntoskrnl.exe.i64` through IDA batch and then re-ran
  deterministic contract export on the captured raw Hex-Rays pseudocode. The
  current contract coverage is:
  `NtSetInformationProcess` 58 contracts from 70 recovered cases,
  `NtSetInformationThread` 26 contracts from 31 recovered cases, and
  `NtSetSystemInformation` 49 contracts from 56 recovered cases. No
  `*InformationClass` dispatcher parameter is emitted as a buffer source in
  these exports.
- The latest `NtSetSystemInformation` export newly recovers
  `SystemFileCacheInformation` and `SystemWatchdogTimerHandler` contracts from
  shared-tail/typed-array evidence. `SystemFileCacheInformation` now emits a
  `systemInformationLength >= 0x40` size validator and fields at offsets
  `0x18` and `0x20`.
- `NtSetSystemInformation` buffer-contract recovery now follows selected
  `goto LABEL_x` shared-tail joins when the selected case body has no direct
  local buffer evidence but the joined label tail exposes length or field
  evidence. This recovers `SystemLoadGdiDriverInSystemSpace` from the 26200.8457
  IDB without matching that case value or label name: the current replay records
  accepted `systemInformationLength` forms of `48` and `56`, plus returned
  output fields at offsets `0x10`, `0x18`, `0x20`, `0x28`, and `0x30`.
- Buffer roles now merge selected-case field access direction with ABI/source
  role evidence, so an input parameter that is also written by the selected
  case renders as `INOUT` instead of hiding output fields under an input-only
  structure name.
- C++ size validators now preserve multiple exact accepted sizes for the same
  length parameter as alternatives, for example `systemInformationLength == 0x30
  || systemInformationLength == 0x38`, instead of collapsing the validator to
  only one exact branch.
- Review-mode regression coverage now verifies that helper-local aliases such as
  `localInput = inputBufferLength` are propagated back to caller length names,
  and that dispatcher-condition fallback context does not pollute a selected case
  that already has direct size/field evidence.
- Buffer-contract helper discovery now handles casted function-pointer style
  invocations and ignores Hex-Rays byte/word accessor pseudo-calls plus
  C/Hex-Rays type and calling-convention tokens when building helper
  candidates. The 26200.8457 raw `NtSetSystemInformation` replay for
  `SystemRegisterFirmwareTableInformationHandler` now records the
  `systemInformation` buffer escaping to `ExpRegisterFirmwareTableInformationHandler`
  with caller-side `systemInformationLength`/`inputLength` evidence instead of
  reporting `LOBYTE` as the only helper candidate.
- Focused helper-candidate discovery now follows selected `goto LABEL_x`
  shared tails when the tail helper receives the active buffer or length
  arguments, so cursor-case analysis can capture helper-only shared-tail paths
  before the deep pass. The contract pass uses the same helper-tail evidence
  without relaxing the stricter size/field evidence gate for structure layout
  recovery.
- Focused buffer-contract recovery now has a native-switch fallback for explicit
  case filters. If flow recovery misses or omits the selected case body, the
  focused pass scans native `switch` bodies directly and still applies the same
  profile-backed dispatcher kind, helper-edge, shared-tail, and C++ structure
  recovery logic. This prevents `NtSetSystemInformation` case `75` from
  collapsing to zero contracts when the recovered flow is incomplete.
- Fallback buffer-source inference now skips identifiers that are used as call
  targets, preventing helper names such as `ValidateTailSystemBuffer` from being
  promoted to fake buffer variables merely because their names contain
  `Buffer`.
- Remaining no-contract cases are left untyped when the selected body has no
  direct information-buffer/length evidence or only unsupported/no-op return
  behavior. This is intentional: the contract pass prefers an explicit
  selected-case context report over inventing an input/output structure. In the
  26200.8457 `NtSetSystemInformation` replay the remaining untyped recovered
  cases are `SystemMirrorMemoryInformation`,
  `SystemWow64SharedInformationObsolete`, `SystemCoverageInformation`,
  `SystemVirtualAddressInformation`, `SystemRegistryAppendString`,
  `SystemHypervisorDetailInformation`, and
  `SystemTrustedAppsRuntimeInformation`.

Review-mode validation for this buffer-contract pass:

```text
python -B -m unittest tests.test_buffer_contracts -v: 36 tests OK
python -B -m unittest discover -v: 463 tests OK
python -B -m compileall .\ida_pseudoforge: passed
git diff --check -- .: passed with CRLF normalization warning for pseudoforge_implementation_status.md
hardcoding scan over production buffer-contract paths: no sample-specific hits outside profile data
NtSetSystemInformation raw replay: focused case 75 produces 1 contract for case 0x4B and captures ExpRegisterFirmwareTableInformationHandler escape; focused shared-tail case 54 produces 1 INOUT contract and keeps exact 0x30/0x38 size alternatives in the generated C++ validator
```
- Casted native switches such as `switch ((int)a2)` are recognized as native dispatchers, so length/alignment comparisons on `ProcessInformationLength` are not promoted into auxiliary switch recovery.
- Switch outline generation is intentionally conservative: only single-statement
  returns and complete local branch slices are expanded, while complex or shared
  branch bodies point back to the normalized original pseudocode.
- TraceLogging/C++ template wrapper functions are excluded from switch recovery to avoid mapping wrapper size constants onto unrelated `SYSTEM_INFORMATION_CLASS` names.
- The matching TraceLogging switch false-positive regression now lives in `tests/test_render_flow.py`.
- Direct `return 0` becomes `STATUS_SUCCESS` only when the function has strong NTSTATUS return evidence; mixed error-code helpers with decompiler `__int64`/`char` return types keep raw zero returns.
- LLM-only `status` renames no longer enable zero-to-`STATUS_SUCCESS` assignment rewriting; that rewrite requires strong NTSTATUS context or a deterministic kernel-status accumulator.
- `status_codes.json` is generated from WDK `shared\ntstatus.h`; the default generator policy keeps `STATUS_SUCCESS`, `STATUS_PENDING`, and severity-bit informational/warning/error codes, while excluding low wait/success aliases such as `STATUS_WAIT_1` to avoid rewriting ordinary boolean-like status locals.
- LLM-assisted runs no longer apply generic prototype fallback argument names such as `argument0`; explicit API parameter names and strong semantic renames are kept, while generic LLM argument placeholders are rejected.
- LLM argument renames for raw `aN` parameters require stronger confidence than local renames, reducing speculative names for forwarded internal helper arguments.
- LLM `saved*` local renames copied directly from `aN` parameters now require a strong matching semantic rename for that source parameter; uncertain forwarded arguments no longer leak into confident saved-copy names.
- LLM local/argument renames now reject PascalCase names so inferred private structure roles do not look like authoritative type or field names.
- Label role classification distinguishes accounting/state-update success return tails from cleanup dispatch tails, while preserving `__fastfail(3)` corrupt-list labels.
- Rename validation now suppresses weak large-dispatcher names for numeric temporaries and preserves stronger deterministic names such as `infoClass`, `inputLength`, CPU set buffers, saved previous mode, active processor count, and allocated pool buffers.
- Rendered warning counts are synchronized between `.forge` section metadata and the human-readable header after display-only warning filters are applied.
- Preview/save/copy paths finalize escaped path-like string literals consistently, and current-function preview opens the matching `.forge` section instead of always opening the full aggregate file.
- Headless IDA batch analysis now prefers the workspace package over an already installed IDA plugin package, merges text-declared locals with `cfunc.lvars`, and supports append-only `.forge` writing for full-kernel sweeps.
- Batch comparison artifacts can now be enabled for raw Hex-Rays vs PseudoForge review without changing the default full-kernel sweep output size.
- Batch comparison records keep legacy path fields and include shared-style
  artifact keys for raw pseudocode, cleaned pseudocode, forge sections, and
  raw-vs-cleaned diffs.
- Batch LLM mode is explicit: deterministic sweeps stay cheap by default, while `-LlmRenames` uses configured provider settings and records per-function `llm_status`.
- A WDK WDM kernel-pattern driver corpus now lives under `samples/kernel_pattern_driver`; Release/Debug x64 builds and TestSign succeed locally.
- The kernel-pattern driver now includes an opt-in `ObRegisterCallbacks` process object callback path with LIST_ENTRY-backed whitelist/blacklist walks, `CONTAINING_RECORD`, requested-access checks, and whitelist auto-add telemetry concentrated inside `PfkpObjectPreOperation` for single-function decompile testing.
- OB pre-operation callback rendering now reduces noisy Hex-Rays raw offset loads such as `*(_DWORD *)(*(_QWORD *)(preOperationInfo + 32) + 4LL)` to `preOperationInfo->Parameters->...OriginalDesiredAccess` when the callback context is known.
- No-symbol OB pre-operation callback rendering now recognizes suspicious `POB_PRE_OPERATION_CALLBACK` second parameters when field-use evidence matches `POB_PRE_OPERATION_INFORMATION`, preserves a stronger context-parameter name when available, normalizes the second parameter to `preOperationInfo`, rewrites typed-array offset loads such as `*((_QWORD *)preOperationInfo + 4)`, and renders zero callback returns as `OB_PREOP_SUCCESS`.
- No-PDB OB pre-operation callback signature overrides now keep the function body
  parameter tokens consistent with the rendered signature, and typed offset
  field loads for profile-known fields such as `Object`, `ObjectType`, and
  `CallContext` are rewritten only after `OB_PRE_OPERATION_INFORMATION`
  evidence is present. Unprofiled offsets such as the current flag-style DWORD
  remain raw instead of being invented.
- OB pre-operation typed field rendering now derives field offsets from the
  loaded kernel structure and alias profiles rather than encoding byte offsets
  in the rewrite rule.
- OB pre-operation desired-access low-byte zero initialization is normalized to a full scalar zero assignment only after `OriginalDesiredAccess` field evidence identifies the target access-mask local.
- OB pre-operation private LIST_ENTRY process-rule records and event records now receive preview-only inferred record types only when allocation size, list walk shape, and fixed field-write evidence all match; confirmed process-rule loops are rendered with a separate `LIST_ENTRY *` iterator and `CONTAINING_RECORD(...)`.
- Profile-backed `0xC???????` NTSTATUS error literals are now rendered symbolically in 4-byte local assignments and `_DWORD` stores, while wider stores keep the raw literal.
- DriverEntry cleanup now recognizes the kernel-pattern test driver's dispatch-table/device-creation shape and renders a preview-only `INFERRED_DRIVER_DEVICE_EXTENSION`, `NT_SUCCESS(status)`, IRP major constants, `DO_BUFFERED_IO`, `DO_DEVICE_INITIALIZING`, `FILE_DEVICE_SECURE_OPEN`, lookaside pool tags, work-item cleanup, registry-path buffer cleanup, and resource/lookaside field access.
- DriverEntry display warnings now suppress routine LLM sub-function rename guesses and redundant `DeferredContext`/device-extension wording after deterministic DriverEntry evidence is recovered.
- Unknown or vendor `DEVICE_TYPE` values remain literal, such as `0x8337u`, unless a trusted binary/profile source proves a standard `FILE_DEVICE_*` name; original source macro names are not inferred.
- Inferred DriverEntry device-extension structs are preview aids only; they do not rewrite allocation or whole-extension zeroing sizes into reconstructed source `sizeof(...)` expressions.
- IOCTL dispatcher case labels now keep the original numeric case value and Hex-Rays integer suffixes, and add exact `CTL_CODE(...)` comments, for example `METHOD_BUFFERED` and access bits, without inventing driver-specific `IOCTL_*` names.
- IRP dispatch handlers now render preview signatures as `NTSTATUS __fastcall Name(PDEVICE_OBJECT deviceObject, PIRP irp)` when IRP completion or `IoStatus` evidence identifies the handler.
- No-PDB IRP dispatch detection now accepts direct `IofCompleteRequest(...)` evidence for the second parameter, including casted `(IRP *)a2` forms, without forcing a DeviceControl union arm.
- `IO_STACK_LOCATION` `_DWORD *` index rendering is union-arm gated: the DeviceIoControl arm is used only when IRP dispatch evidence is present, `ioControlCode` is loaded from the stack location, and an IOCTL dispatcher is present; non-IOCTL IRP paths remain raw until their major-function-specific union arm is proven.
- IRP dispatch body cleanup now renders `deviceObject->DeviceExtension`, upgrades local `status` to `NTSTATUS`, and emits `return status;` without requiring DeviceControl-specific evidence.
- DeviceControl stack-location rendering no longer requires a DeviceExtension load, and LLM-suggested `ioControlCode`/`ioStackLocation` names alone do not force the DeviceControl union arm outside IRP dispatch paths.
- Driver dispatch DeviceExtension locals are recovered deterministically from `DeviceObject + 64`/`DeviceObject->DeviceExtension`, overriding weaker names such as `deviceContext`.
- METHOD_BUFFERED-only DeviceControl paths can render `AssociatedIrp.MasterIrp` as `AssociatedIrp.SystemBuffer` with a `PVOID` local only when `IoControlCode` is proven to come from the DeviceControl stack location, while METHOD_NEITHER, mixed-method dispatchers, or IOCTL-like switches without stack evidence keep the original union alias.
- Device-control dispatch cleanup now detects stack-location variables by `[6]` `IoControlCode` usage instead of by variable name, and deterministic names correct reversed LLM `inputBufferLength`/`outputBufferLength` suggestions using the x64 `IO_STACK_LOCATION.Parameters.DeviceIoControl` indices.
- IRP completion tail labels that set `IoStatus`, call `IofCompleteRequest`, and return status are now classified as `irp_complete_request_tail` and rendered as `CompleteIrp` instead of `unknown_label_block`.
- Device-control display warnings now suppress stale buffered/SystemBuffer, dispatch-signature, subhandler-renaming, and low-confidence LLM rename noise once deterministic IOCTL/IRP evidence has already resolved those points.
- Headless IDA batch validation can pass `-Opdb:off` through `tools/run_pseudoforge_ida_batch.ps1 -NoPdb`, and the wrapper retries once when a fresh IDA load exits with an empty report file.
- `MmGetSystemRoutineAddress` assignments now allow profile-backed argument cleanup for matching indirect calls. Routine-string evidence receives high confidence, variable-name-only evidence is lower confidence, arity mismatches are skipped, and the rendered call remains indirect with a `resolved indirect call` comment.
- Callback registration toggles that combine process/image/thread notify callbacks with `ObRegisterCallbacks` now recover deterministic local names, suppress stale LLM struct warnings, normalize `NTSTATUS`/`BOOLEAN` signature pieces, and rewrite Hex-Rays `_QWORD[4]` operation registration arrays into `OB_OPERATION_REGISTRATION` field assignments.
- Configuration Manager registry callback probe functions that call `CmGetCallbackVersion`, `CmRegisterCallbackEx`, `CmRegisterCallback`, and `CmUnRegisterCallback` now recover callback context, version, altitude, cookie, and split registration status roles without relying on LLM names, and successful registration checks render as `NT_SUCCESS(...)`.
- Memory Manager probe functions that combine `MmGetSystemRoutineAddress`, `MmCopyMemory`, MDL setup, noncached memory, and contiguous memory allocation now recover routine-name, buffer, MDL, byte-count, and physical-address locals. Reused probe sinks get neutral names instead of a single stale API role, and preview cleanup can suppress write-only scratch captures while preserving probed calls as `(void)Call(...)`. Generic cleanup also normalizes scalar out-parameter arrays, single-assignment pointer aliases, unrolled wide-array copies, and same-named struct-field locals by usage pattern, while `MmCopyMemory` flag literals now render as `MM_COPY_MEMORY_PHYSICAL` or `MM_COPY_MEMORY_VIRTUAL`.
- Zw API corpus/probe functions that combine object, registry, token, and file Zw calls now recover deterministic handle, token, status, object-attribute, timeout, IO-status, value-name, and shared info-buffer roles. The preview normalizes `OBJECT_ATTRIBUTES` size, `OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE`, `NtCurrentProcess()`, `NtCurrentThread()`, and `NT_SUCCESS(...)` checks without inventing direct import-style replacements.
- README and deterministic rules design docs now include project-local JSON authoring examples, validation commands, CLI application commands, and rule report inspection steps.
- README preview documentation now includes the animated interactive IDA demo at `screenshots/PseudoForge-demo.gif`.
- Repository documentation is now maintained in English-only form, including README, design documents, status notes, and sample documentation.
- The `NtSetSystemInformation_switch_renamed.cpp` offline CLI smoke input has been moved from the repository root to `samples/pseudocode/`, and documentation commands now reference the sample path.

Deterministic rules matching engine v1 is implemented:

- `deterministic_rules_matching_engine_design.md` remains the phased design document for later `flow` migration and hard-coded rewrite parity work.
- Current v1 keeps kernel API, kernel rewrites, cleanup rewrite, and flow recovery behavior unchanged except for additive rule reporting.
- Rule packs are loaded from builtin, project-local, and user-global directories, with project-local resolution based on the analyzed source/binary path instead of process CWD only.
- Rule pack loading is cached by directory signature for session reuse while still picking up file additions, removals, size changes, and timestamp changes.
- Rule directory resolution deduplicates equivalent builtin, project-local, user-global, and explicit extra paths before loading.
- Invalid rule packs are rejected fail-closed and surfaced through redacted rule report/warnings without crashing analysis.
- Rule validation rejects invalid scope regexes, invalid match regexes, ambiguous primary regex matchers, empty match definitions, empty text gates, duplicate rule IDs, boolean numeric fields, invalid confidence, and missing emit fields.
- Runtime rule exceptions are caught per rule and recorded as rejected rule emissions instead of aborting analysis.
- Rule JSON cannot spoof internal trusted rename sources; emitted rename suggestions always use source `rule`.
- Rename rule conflicts for the same target are resolved with `override_of`, priority, confidence, load order, and rule ID before the existing rename validator runs.

## Implemented IDA Actions

Menu path:

```text
Edit/PseudoForge/
  Analyze current function
  Show current analysis result
  Analyzed functions...
  Export cleaned pseudocode
  Analyze buffer contract for cursor case
  Analyze buffer contract by case value...
  Cancel current operation
  Configure LLM rename assist
  Configure profile directory
  Configure preview mode
  Show settings
  Advanced/
    Apply selected renames to IDB
```

Pseudocode right-click menu:

```text
PseudoForge/
  Analyze current function
  Show current analysis result
  Analyzed functions...
  Export cleaned pseudocode
  Analyze buffer contract for cursor case
  Analyze buffer contract by case value...
  Cancel current operation
  Configure LLM rename assist
  Configure profile directory
  Configure preview mode
  Show settings
  Advanced/
    Apply selected renames to IDB
```

Hotkeys:

```text
Ctrl+Alt+F        Analyze current function
Ctrl+Alt+P        Show current analysis result
Ctrl+Alt+Shift+P  Analyzed functions...
Ctrl+Alt+Shift+F  Export cleaned pseudocode
Ctrl+Alt+B        Analyze buffer contract for cursor case
Ctrl+Alt+Shift+V  Configure preview mode
```

## Exported Files

The export action writes a bundle under `pseudoforge_out` next to the IDB when possible.
Its main purpose is to preserve a reviewable PseudoForge result outside the IDA UI. The bundle is intended for code review, Git diffs, regression samples, audit trails, and tool-to-tool handoff. It is not an apply-renames path and does not modify the IDB.

Analyze/preview also updates an aggregate preview file beside the analyzed input binary:

```text
<input_binary_stem>.forge
```

The `.forge` file is sectioned by function EA. Re-analyzing one function replaces only that function section and preserves sections for other functions.

```text
<function>.cleaned.cpp
<function>.switch-outline.cpp
<function>.rename-map.json
<function>.flow-report.md
<function>.buffer-contracts.md
<function>.buffer-contracts.json
<function>.buffer-structs.hpp
<function>.rule-report.json
```

`switch-outline.cpp` now includes only single-statement returns and complete
local branch slices. Complex dispatcher paths remain in the normalized original
pseudocode.

## Current Validation Run

Commands that passed:

```powershell
python -B -m unittest tests.test_render_ioctl tests.test_render_ntset tests.test_render_flow -v
python -B -m unittest tests.test_buffer_contracts -v
python -B -m unittest discover -s tests -v
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
python -B -m json.tool .\ida-plugin.json
python -B -m json.tool .\ida_pseudoforge\profiles\kernel_api.json
python -B -m json.tool .\ida_pseudoforge\profiles\kernel_api_overrides.json
python -B -m json.tool .\ida_pseudoforge\profiles\status_codes.json
python -B -m json.tool .\ida_pseudoforge\profiles\process_information_class.json
python -B -m json.tool .\ida_pseudoforge\profiles\system_information_class.json
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
python -B .\tools\build_status_codes_profile.py --version 10.0.26100.0 --dry-run --summary
python -B .\tools\pseudoforge_cli.py --version
python -B .\tools\release_pseudoforge.py --dry-run
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_claude_hidden_existing_cli_smoke
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_buffer_contract_smoke
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_buffer_struct_smoke
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_buffer_case_0x18_smoke --buffer-contract-case 0x18
python -B .\tools\pseudoforge_free_cli.py --version
python -B .\tools\pseudoforge_free_cli.py --help
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_claude_hidden_free_cli_smoke
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_buffer_contract_free_smoke --format json --no-progress
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_buffer_struct_free_smoke --format json --no-progress
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_buffer_case_0x18_free_smoke --buffer-contract-case 0x18 --format json --no-progress
git diff --check -- .
```

Latest unit test count: 448 tests.

Latest no-PDB kernel pattern driver quality loop:

```text
Date: 2026-06-01
IDA: C:\Program Files\IDA Professional 9.0\ida.exe
Driver: samples\kernel_pattern_driver\x64\Release\PfKernelPattern.sys
No-PDB method: copied .sys to a fresh input_no_pdb directory and ran -NoPdb
Processed: 46 functions
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
Report: pseudoforge_ida_e2e_quality_report.md
Final artifacts: pseudoforge_out\ida_e2e_quality\cycle4_20260601_200922
```

Latest no-PDB generic quality-lift loop:

```text
Date: 2026-06-01
Implemented:
- Added ida_pseudoforge.core.quality_score plus tools/score_pseudoforge_quality.py for corpus-agnostic raw-vs-cleaned quality reports.
- Added generic dataflow rename recovery for repeated constant-offset structure bases, LIST_ENTRY heads, single lookaside allocation results, optimized memmove/memset-style helpers, and output-buffer contracts.
- Lowered generic prototype argument names below stronger dataflow-backed sources so no-PDB roles can replace argumentN without overriding callback/profile/LLM evidence.
- Extended text local capture to parse multi-pointer declarations such as _QWORD **v11.
- Relaxed single-assignment pointer-alias cleanup so indexed alias uses fold to the canonical pointer while address-taken aliases remain protected.
- Review-mode hardcoding audit removed a direct qword_140... decompiler-global literal from production rewrite logic and replaced it with a generic qword_[0-9A-Fa-f]+ pattern.

Validation:
- python -B -m unittest discover -s tests -v: 363 tests OK
- python -m pytest -q: 363 passed, 5 subtests passed
- python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
- git diff --check -- .: passed
- IDA Professional 9.0 no-PDB cycle12: processed=46, succeeded=46, skipped=0, failed=0, LLM disabled=46

Quality score cycle4 -> cycle12:
- average score: 61.98 -> 65.83
- average opportunity: 43.87 -> 40.80
- generic_argument_name: 252 -> 60
- compiler_local_name: 931 -> 872
- artifact_reduction: 377 -> 518

Final artifacts:
- pseudoforge_out\ida_e2e_quality\cycle12_20260601_211425
- pseudoforge_out\ida_e2e_quality\cycle12_20260601_211425\quality_score.md
- pseudoforge_out\ida_e2e_quality\cycle12_20260601_211425\quality_score.json
```

Latest headless IDA batch validation, retained as prior full-corpus evidence:

```text
IDA: IDA Professional 9.0 headless batch
IDB: local ntoskrnl.exe.i64 test database
Processed: 30043 functions
Succeeded: 29982
Skipped: 61 Hex-Rays decompile-unavailable functions
PseudoForge failures: 0
Output: %TEMP%\pseudoforge_ida_batch_full.forge
Report: %TEMP%\pseudoforge_ida_batch_full.jsonl
```

GPT-5.5 LLM batch validation history:

```text
Date: 2026-05-28
IDA: IDA Professional 9.0
IDB: D:\bin\os\26200.8457\ntoskrnl.exe.i64
LLM provider/model: codex_cli / gpt-5.5
```

Primary 72-function runs:

| Run | Range | First function | Last function | Processed | Succeeded | Skipped | Failed | LLM final status | Review verdicts | Artifacts |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| 1 | initial 72 | `0x140018BE8 nullsub_3` | `0x140208120 MiReleaseProcessorFlushList` | 72 | 72 | 0 | 0 | ok=72, fallback=0 | pre-fix review: FAIL=6, REVIEW=20, OK-WARN=29, OK=17 | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_full_20260528_180457`; review: `review_72_raw_vs_cleaned.md` |
| 2 | next 72 | `0x140208168 MiGetMultiplexedVm` | `0x14020F7D0 MiWalkPageTables` | 72 | 72 | 0 | 0 | ok=72 after retry, fallback=0 final | FAIL=0, REVIEW=17, OK-WARN=48, OK=7 | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_next72_20260528_200939`; review: `review_next72_raw_vs_cleaned.md`; retry: `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_milogwsaging_retry_20260528_210446` |
| 3 | third 72 | `0x14020FAE8 MiWalkPageTablesRecursivelyNoSynch` | `0x14021A324 RtlSparseArrayElementAllocate` | 72 | 72 | 0 | 0 | ok=72, fallback=0 | FAIL=0, REVIEW=20, OK-WARN=41, OK=11 | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_next72b_20260528_211637`; review: `review_next72b_raw_vs_cleaned.md` |

Cumulative primary LLM coverage:

```text
Primary 72-function batches: 3
Primary functions analyzed: 216
Final LLM ok after retry: 216
Final LLM fallback: 0
Primary failed analyses: 0
```

Non-LLM all-function CompareDir baseline:

```text
Output: %TEMP%\pseudoforge_ida_batch\ntoskrnl_compare_full_20260528_174222
Processed: 30043
Succeeded: 29982
Skipped: 61 Hex-Rays decompile-unavailable functions
Failed: 0
First function: 0x140018BE8 nullsub_3
Last function: 0x141008010 KiServiceTablesLocked
```

Targeted GPT-5.5 validation and rechecks:

| Purpose | Functions | Result | Artifacts |
| --- | --- | --- | --- |
| Smoke test | `NtSetSystemInformation` | processed=1, succeeded=1, LLM ok=1 | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_smoke_20260528_180337` |
| Initial 72 issue recheck | TraceLogging wrapper and status-rewrite/style candidates from the first 72-function review | 9 single-function runs, all succeeded, LLM ok | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_fixed_20260528_191940` |
| Style/status follow-up | `MiReservePageFileSpace`, `MiDeleteCachedSubsection`, `MiEntireSubsectionIsPurged` | 3 single-function runs, all succeeded, LLM ok | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_style_20260528_194645` |
| Status/style final spot check | `MiDeleteCachedSubsection` | processed=1, succeeded=1, LLM ok=1 | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_status_style_20260528_195648` |
| Second 72 timeout retry | `MiLogWsAging` | processed=1, succeeded=1, LLM ok=1 with longer timeout | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_milogwsaging_retry_20260528_210446` |
| Generic argument fix recheck | `MiCountSharedPages`, `MiSetProtectionOnSection`, `MiProtectPrivateMemory`, `MiCreateSlabEntry` | processed=4, succeeded=4, LLM ok=4, generic argument placeholders in cleaned bodies: none | `%TEMP%\pseudoforge_ida_batch\ntoskrnl_llm_gpt55_genericfix_recheck_20260528_222221` |
| Halp allocator rename/tail recheck | `HalpAllocPhysicalMemoryInternal` at `0x140C66648` from `D:\bin\os\26200.8457\ntoskrnl.exe.i64` | processed=1, succeeded=1, LLM ok=1; `LABEL_36` classified as `success_accounting_return_tail`; weak `a1`/`a4` argument renames and `v29` saved-copy rename were skipped | `%TEMP%\pseudoforge_ida_batch\halp_alloc_idb_copy_20260528_231151\run` |

The first 72-function review report is retained as pre-fix evidence. Its six FAIL findings were the issues that drove the later switch-recovery, status-literal, style, and generic-argument fixes. Use the targeted recheck artifacts and the current unit suite as the post-fix validation record.

Historical regression checks that passed after the LLM argument and label-tail fixes:

```powershell
pytest -q
python -m compileall ida_pseudoforge
rg -n "<internal-token-pattern>" ida_pseudoforge/core/validation.py ida_pseudoforge/core/cleanup_rewriter.py tests/test_core_engine.py pseudoforge_implementation_status.md
```

Historical results from that regression pass:

```text
pytest: 99 passed
compileall: passed
sensitive internal token scan: clean
HalpAllocPhysicalMemoryInternal IDB-copy recheck: processed=1, succeeded=1, failed=0, LLM ok=1
kernel-pattern ASCII scan: clean
git diff --check: passed with CRLF normalization warnings only
```

Kernel-pattern driver corpus validation:

```text
sample: samples/kernel_pattern_driver
build: .\samples\kernel_pattern_driver\tools\build.ps1 -Configuration Release
build: .\samples\kernel_pattern_driver\tools\build.ps1 -Configuration Debug
result: PfKernelPattern.sys and PfKernelPatternTool.exe built successfully for Release|x64 and Debug|x64
signing: WDK TestSign reported "Successfully signed" for both PfKernelPattern.sys outputs
live load: not run
```

Callback renderer extraction validation:

```text
python -B -m unittest tests.test_render_callbacks tests.test_render_snapshots -v: 9 tests OK
python -B -m unittest discover -s tests -v: 228 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_callback_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_callback_extract_smoke --format json --no-progress: succeeded
```

IRP dispatch renderer extraction validation:

```text
python -B -m unittest tests.test_render_ioctl tests.test_render_snapshots -v: 21 tests OK
python -B -m unittest discover -s tests -v: 231 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_irp_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_irp_extract_smoke --format json --no-progress: succeeded
```

Zw API renderer extraction validation:

```text
python -B -m unittest tests.test_render_zw tests.test_render_snapshots -v: 9 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_zw_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_zw_extract_smoke --format json --no-progress: succeeded
```

NtSet renderer extraction validation:

```text
python -B -m unittest tests.test_render_ntset tests.test_render_snapshots tests.test_render_signatures.RenderSignatureTests.test_known_pvoid_signature_keeps_typed_body_alias tests.test_rename_heuristics.RenameHeuristicTests.test_cpu_set_mask_stack_buffer_pattern_beats_vague_llm_name -v: 8 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_ntset_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_ntset_extract_smoke --format json --no-progress: succeeded
```

NtSet m128 alias test-suite split validation:

```text
python -B -m unittest tests.test_render_ntset tests.test_core_engine -v: 31 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Label fixture test-suite split validation:

```text
python -B -m unittest tests.test_render_labels tests.test_core_engine -v: 28 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Style test-suite split validation:

```text
python -B -m unittest tests.test_render_style tests.test_render_snapshots tests.test_core_engine -v: 28 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Rename heuristic test-suite split validation:

```text
python -B -m unittest tests.test_rename_heuristics tests.test_core_engine -v: 21 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

LLM rename-filter test-suite split validation:

```text
python -B -m unittest tests.test_llm_rename_filters tests.test_core_engine -v: 16 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Label-tail test-suite split validation:

```text
python -B -m unittest tests.test_render_labels tests.test_core_engine -v: 9 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

NtSet fixture split validation:

```text
python -B -m unittest tests.test_core_engine tests.test_render_snapshots -v: 5 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Snapshot fixture split validation:

```text
python -B -m unittest tests.test_render_driver_entry tests.test_render_ioctl tests.test_render_style tests.test_render_snapshots -v: 33 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Warning renderer extraction validation:

```text
python -B -m unittest tests.test_render_warnings tests.test_render_snapshots tests.test_export_bundle tests.test_render_ioctl.RenderIoctlTests.test_irp_completion_label_and_resolved_ioctl_warnings_are_display_clean tests.test_llm_config.LlmConfigTests.test_large_dispatcher_llm_raises_confidence_floor_and_hides_low_confidence_warnings -v: 9 tests OK
python -B -m unittest discover -s tests -v: 240 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_warnings_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_warnings_extract_smoke --format json --no-progress: succeeded
```

Flow renderer extraction validation:

```text
python -B -m unittest tests.test_render_flow tests.test_export_bundle -v: 11 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_flow_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_flow_extract_smoke --format json --no-progress: succeeded
```

TraceLogging flow test-suite split validation:

```text
python -B -m unittest tests.test_render_flow tests.test_core_engine -v: 37 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Path literal renderer extraction validation:

```text
python -B -m unittest tests.test_render_literals tests.test_render_signatures.RenderSignatureTests.test_known_pvoid_signature_keeps_typed_body_alias tests.test_forge_store.ForgeStoreTests.test_forge_store_finalizes_c_like_literals tests.test_forge_store.ForgeStoreTests.test_forge_store_finalizes_existing_aggregate_on_upsert -v: 6 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_literals_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_literals_extract_smoke --format json --no-progress: succeeded
```

Kernel hint renderer extraction validation:

```text
python -B -m unittest tests.test_render_kernel_hints tests.test_render_driver_entry.RenderDriverEntryTests.test_driver_entry_wrapper_comment_does_not_claim_device_creation_sequence tests.test_render_snapshots -v: 6 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_kernel_hints_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_kernel_hints_extract_smoke --format json --no-progress: succeeded
```

Kernel semantics test-suite split validation:

```text
python -B -m unittest tests.test_render_kernel_hints tests.test_core_engine -v: 27 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Call-argument renderer extraction validation:

```text
python -B -m unittest tests.test_render_call_args tests.test_render_signatures.RenderSignatureTests.test_known_pvoid_signature_keeps_typed_body_alias tests.test_rule_integration.RuleIntegrationTests.test_builtin_call_arg_rewrite_report_mirrors_boolean_kernel_api_cleanup tests.test_kernel_api_profile_builder.KernelApiProfileBuilderTests.test_kernel_api_profile_rewrites_pool_flags_and_tags -v: 6 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_call_args_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_call_args_extract_smoke --format json --no-progress: succeeded
```

Signature renderer extraction validation:

```text
python -B -m unittest tests.test_render_signatures tests.test_render_callbacks tests.test_render_driver_entry tests.test_render_ioctl tests.test_render_ntset tests.test_render_zw -v: 48 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_signatures_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_signatures_extract_smoke --format json --no-progress: succeeded
```

Known PVOID signature test-suite split validation:

```text
python -B -m unittest tests.test_render_signatures tests.test_core_engine -v: 31 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Header renderer extraction validation:

```text
python -B -m unittest tests.test_render_header tests.test_render_snapshots tests.test_llm_config.LlmConfigTests.test_rendered_comment_text_is_ascii_safe tests.test_render_kernel_hints.RenderKernelHintTests.test_kernel_driver_semantics -v: 5 tests OK
python -B -m unittest discover -s tests -v: 256 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_header_extract_smoke: succeeded
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_header_extract_smoke --format json --no-progress: succeeded
```

IOCTL/IRP test-suite split validation:

```text
python -B -m unittest tests.test_render_ioctl tests.test_render_snapshots tests.test_core_engine -v: 66 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Callback test-suite split validation:

```text
python -B -m unittest tests.test_render_callbacks tests.test_core_engine -v: 48 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Zw/API test-suite split validation:

```text
python -B -m unittest tests.test_render_zw tests.test_core_engine -v: 43 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

DriverEntry test-suite split validation:

```text
python -B -m unittest tests.test_render_driver_entry tests.test_core_engine -v: 39 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Memory Manager test-suite split validation:

```text
python -B -m unittest tests.test_render_memory tests.test_core_engine -v: 33 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Logging test-suite split validation:

```text
python -B -m unittest tests.test_logging tests.test_core_engine -v: 32 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

Release/version test-suite split validation:

```text
python -B -m unittest tests.test_release_pseudoforge tests.test_core_engine -v: 36 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
git diff --check -- .: passed
```

DriverEntry cleanup regression validation:

```text
python -B -m unittest tests.test_render_callbacks.RenderCallbacksTests.test_callback_registration_toggle_rewrites_ob_operation_registration tests.test_render_callbacks.RenderCallbacksTests.test_registry_callback_registration_probe_gets_cm_semantics tests.test_render_memory.RenderMemoryTests.test_memory_manager_probe_gets_mm_semantics tests.test_render_zw.RenderZwTests.test_zw_api_probe_gets_deterministic_names_and_status_checks tests.test_render_driver_entry.RenderDriverEntryTests.test_driver_entry_device_extension_semantics tests.test_render_ioctl.RenderIoctlTests.test_ioctl_switch_case_labels_decode_ctl_code_bitfields tests.test_kernel_api_profile_builder.KernelApiProfileBuilderTests.test_kernel_api_profile_rewrites_pool_flags_and_tags -v: 7 tests OK
python -B -m unittest tests.test_render_driver_entry.RenderDriverEntryTests.test_driver_entry_device_extension_semantics tests.test_render_driver_entry.RenderDriverEntryTests.test_driver_entry_extension_rewrite_requires_dword_scaled_offsets -v: 2 tests OK
python -B -m unittest tests.test_render_ioctl.RenderIoctlTests.test_ioctl_switch_case_labels_decode_ctl_code_bitfields tests.test_render_ioctl.RenderIoctlTests.test_ioctl_stack_location_rewrite_does_not_require_device_extension_use tests.test_render_ioctl.RenderIoctlTests.test_irp_stack_location_union_arm_is_not_forced_without_ioctl_evidence tests.test_render_ioctl.RenderIoctlTests.test_irp_stack_location_roles_require_driver_dispatch_evidence tests.test_render_ioctl.RenderIoctlTests.test_llm_ioctl_like_names_do_not_force_irp_union_arm_without_dispatch_evidence tests.test_render_ioctl.RenderIoctlTests.test_master_irp_alias_rewrite_requires_all_buffered_ioctl_cases tests.test_render_ioctl.RenderIoctlTests.test_master_irp_alias_rewrite_requires_device_control_stack_evidence tests.test_render_ioctl.RenderIoctlTests.test_ioctl_ctl_code_decode_handles_methods_and_access_bits tests.test_render_ioctl.RenderIoctlTests.test_ioctl_case_labels_decode_hexrays_integer_suffixes -v: 9 tests OK
python -B -m unittest discover -s tests -v: 265 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
python -m json.tool .\ida_pseudoforge\profiles\kernel_api_overrides.json > $null: passed
git diff --check -- .: passed with CRLF normalization warnings only
.\samples\kernel_pattern_driver\tools\build.ps1 -Configuration Release: passed, PfKernelPattern.sys signed
MSBuild .\samples\kernel_pattern_driver\PfKernelPattern.sln /m:1 /p:Configuration=Debug /p:Platform=x64: passed after retrying a transient WDK ApiValidator temp-file lock
```

Claude CLI login bridge validation:

```text
python -B -m unittest discover -s tests -v: 103 tests OK
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin: 2 rule files OK
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --llm-renames --llm-provider claude_login_via_claude_cli --llm-command "python .\tools\empty_llm_rename_provider.py" --out %TEMP%\pseudoforge_claude_login_provider_smoke: succeeded
claude auth --help: confirms auth login command is available
document language scan: clean
git diff --check -- .: passed with CRLF normalization warnings only
```

Maintainability hardening update:

```text
implemented:
- WDK kernel API profile parsing now strips comments and preprocessor lines from the function-declaration scan path.
- Bogus prose-derived function metadata such as Iprtrmib.h "Manager" is rejected and removed from functions and symbol indices.
- Integer macro expression evaluation uses a small AST evaluator instead of eval().
- CLI LLM providers execute command templates as argv with shell=False by default.
- Raw shell execution is available only with an explicit shell: or raw-shell: command-template prefix.
- Codex model discovery now invokes ["codex", "debug", "models"] with shell=False.
- Pattern-based local rename rules were extracted from lvar_analysis.py into core/pattern_renames.py.
- New focused tests were added for kernel API profile building and LLM CLI provider execution.

deferred:
- The historical test_core_engine.py monolith has been removed; broad coverage
  now lives in focused domain suites.
- render.py is now a pipeline coordinator plus compatibility import surface;
  ida/actions.py and ida/ui_preview.py remain candidates for later scoped
  extraction.
```

IDA Free offline CLI update:

```text
implemented:
- IDA Free remains unsupported for the interactive plugin path because that path requires IDAPython and local Hex-Rays pseudocode APIs.
- tools/pseudoforge_free_cli.py provides a Python-only offline workflow for pseudocode copied or saved from IDA Free cloud decompiler output.
- The IDA Free CLI extracts exactly one complete function per input file and fails closed for missing or ambiguous multiple functions.
- The IDA Free CLI writes cleaned pseudocode, raw pseudocode, raw-vs-cleaned diff, rename map, flow report, warnings JSON, rule report, per-function summary JSON, and a run manifest.
- Project-local rules are supported through --project-root, and additional rule directories are supported through --rules.
- Optional LLM rename assist is available through --llm and uses the existing offline provider system with deterministic fallback on provider failure.
- tools/pseudoforge_free_console.py owns progress and final-summary rendering so the CLI adapter stays focused on parsing and IO orchestration.
- --help is served before analysis dependencies are loaded, while real analysis still fails closed if IDA-only modules are present.
- Text console output prints incremental progress by default, while --no-progress suppresses incremental progress and keeps the final summary.
- Text summaries distinguish complete, partial, and failed runs.
- JSON console output keeps stdout machine-readable and sends progress to stderr by default.
- The path does not import IDA-only modules, does not use IDAPython or local Hex-Rays APIs, and never modifies an IDB.
- README IDA Free CLI usage screenshot was refreshed to show the current progress and final-summary output.

unsupported:
- No IDA Free menu integration.
- No apply-renames action.
- No direct cloud decompiler API integration.
- No multi-function splitting in a single pasted file in this first slice.
```

IDA Free Studio GUI update:

```text
implemented:
- Added ida_pseudoforge/free/service.py as the shared IDA Free analysis service for the CLI and standalone GUI.
- tools/pseudoforge_free_cli.py now delegates analysis orchestration to the shared service while preserving its flags, JSON/text output, artifact names, and fail-closed IDA-only module checks.
- Added tools/pseudoforge_free_gui.py and ida_pseudoforge/gui/free_app.py as the PseudoForge Free Studio desktop entrypoint.
- The GUI provides left raw pseudocode and right cleaned pseudocode panes, Paste/Open/Analyze/Stop/Copy Cleaned/Save Bundle/Settings actions, and warnings/renames/diff/rule-report/artifacts tabs.
- The GUI uses a background worker thread and cooperative cancellation checks between safe service phases.
- LLM settings reuse the existing provider registry/factory/config storage, with static provider model choices and no API-key logging.
- Save Bundle reuses the current CleanPlan and capture to write the same IDA Free artifact bundle into a user-selected directory without rerunning analysis.
- PySide6 is required only for the GUI; tools/pseudoforge_free_gui.py exits with an actionable install message when PySide6 is unavailable.
- Added focused tests in tests/test_free_service.py and tests/test_free_gui.py.
- Review mode fixed direct service callers so FreeAnalysisOptions.profile_dir is applied inside the shared service with call-scoped profile restoration instead of relying on CLI/GUI preconfiguration.
- Review mode fixed stale GUI result state so Paste/Open/new Analyze clears cleaned output, tabs, and Save Bundle state before a new analysis succeeds.
- Review mode fixed Save Bundle summary metadata so re-saving an existing result preserves the original profile root, active profiles, and profile manifests without rerunning analysis.
- Review mode hardened PySide6 enum compatibility helpers and delayed optional service-summary imports away from the GUI import path.
- Free Studio settings now disable provider-irrelevant LLM fields: HTTP providers enable Base URL, API-backed HTTP providers enable API key, local HTTP providers leave API key disabled, and local CLI providers enable CLI command only.
- Added tools/run_pseudoforge_free_gui.ps1 so Free Studio can install and run PySide6 from a repo-local .venv-free-gui instead of exposing PySide6 to IDA's global Python environment.
- Hardened the IDA plugin preview path so IDA 9.0 never imports PySide6/PyQt6 for dockable preview; those Qt6 bindings are reserved for the standalone Free Studio process.
- Documented the recorded Free Studio usage walkthrough at screenshots/IDA-free-gui-demo.mp4 so IDA Free users can see the expected paste/open, Analyze, review-tabs, cleaned-output, and Save Bundle flow before running the app.
- Review mode fixed model-catalog refresh timeouts so Free Studio and the IDA LLM configuration path honor the configured timeout up to a 60-second bound instead of failing early on slower local HTTP runtimes.

validated:
- python -B -m unittest tests.test_free_gui tests.test_ida_plugin_safety tests.test_llm_cli_provider tests.test_llm_config -v: 105 tests OK, 7 PySide6-dependent GUI tests skipped when PySide6 is not installed.
- python -B -m unittest tests.test_free_service tests.test_pseudoforge_free_cli tests.test_ida_batch -v: 45 tests OK.
- python -B -m unittest discover -s tests -v: 507 tests OK, 7 PySide6-dependent GUI tests skipped when PySide6 is not installed.
- python -B -m compileall .\ida_pseudoforge .\tools .\tests: passed.
- git diff --check -- .: passed with CRLF normalization warnings only.
- python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_review_free_cli_smoke --format json --no-progress: succeeded.
- python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_review_cli_smoke: succeeded.
- python -B .\tools\pseudoforge_free_gui.py on a machine without PySide6: exits with the expected install guidance.
```

Local LLM provider update:

```text
implemented:
- Added named local OpenAI-compatible providers: ollama, lm_studio, vllm, and llama_cpp.
- Added default local endpoints: http://localhost:11434/v1, http://localhost:1234/v1, http://localhost:8000/v1, and http://localhost:8080/v1.
- Local providers reuse the existing OpenAI-compatible chat-completions provider but set api_key_required=False, so requests omit Authorization unless an optional key is supplied through CLI options or environment variables.
- Model discovery now treats all HTTP providers consistently through /models, with static fallback for offline or unavailable local runtimes.
- IDA plugin LLM configuration prompts for API keys only for API-backed HTTP providers; local HTTP providers ask for base URL and model without forcing a key.
- Free Studio settings keep Base URL enabled for local HTTP providers, disable API key and CLI command fields, reload available models after base URL changes, honor the configured timeout up to 60 seconds, and show visible model-catalog loaded/fallback status with a manual Refresh retry.
- Local HTTP provider chat-completions requests use text response format for LM Studio/Ollama/vLLM/llama.cpp compatibility while keeping rename JSON extraction and validation gates.
- The generic openai_compatible provider keeps JSON object mode by default, but retries once with text response format when a local-compatible server rejects JSON object mode.
- Free CLI and offline CLI provider choices expand automatically from the shared provider registry.

limitations:
- Local model quality and JSON-mode compatibility depend on the selected runtime and loaded model.
- If a local endpoint is protected by an authenticated proxy and GUI credential entry is needed, use openai_compatible with the local base URL or provide provider-specific key environment variables.
```

Interactive plugin safety update:

```text
implemented:
- Added a plugin analysis session model for the interactive IDA path.
- Replaced direct LAST_* state use with a session store that carries target path, function EA/name, fingerprint, capture, plan, and .forge output.
- Analyze, export, and apply now share a conservative background coordination group so overlapping actions cannot race shared plugin state.
- Apply-selected-renames refuses stale sessions when the current IDA function no longer matches the analyzed function.
- Apply-selected-renames revalidates selected candidates immediately before IDB write and only lets explicit arg/lvar rename candidates reach ida_hexrays.rename_lvar().
- Apply preflight rejects unselected, missing, non-apply-safe, non-arg/lvar, invalid identifier, colliding, and duplicate-target candidates.
- Session path identity now normalizes Windows path case and separators to avoid false stale-session refusals.
- Plugin action registration and menu attachment are routed through ActionRegistry.
- Preview popup actions now have a cleanup hook that plugin term() calls during unload/reload.
- LLM config dialog code is isolated from actions.py, and model-discovery exceptions use static fallback choices without saving corrupt config.
- Export purpose is documented as a durable review/regression artifact path, separate from IDB rename application.
- Removed the top-level full aggregate `.forge` preview action and the direct full `.forge` open popup action; `Show current analysis result` is now the primary preview action and `Analyzed functions...` is available from the top-level menu and pseudocode context menu.
- Removed per-function dynamic popup entries in favor of the `Analyzed functions...` chooser to avoid huge context menus on large `.forge` files.
- Interactive plugin loading plus capture, export, and action behavior were validated in the Hex-Rays pseudocode view.
- Added focused plugin safety tests for session identity, stale apply refusal, apply preflight, IDB write gating, task coordination, action lifecycle, preview cleanup, Windows path identity normalization, and LLM config failure handling.

deferred:
- LLM model discovery now uses a non-blocking cache-backed refresh; richer live
  refresh UI is still deferred.
- True object-level ctree rename application is still incomplete; apply continues to call ida_hexrays.rename_lvar(function_ea, old, new) after the new session and identity preflight gates pass.
- Interactive export now shares raw pseudocode, warnings JSON, raw-vs-cleaned diff, and summary JSON artifacts with the CLI paths; only IDA Free CLI-specific run manifest output remains separate.
```

Follow-up no-PDB quality lift:

```text
implemented:
- Added generic WDK API metadata-backed local rename recovery for address-taken out parameters, API return locals, and API argument role locals.
- Added exact constant pointer-expression alias reuse for already established stable pointer aliases.
- Review mode fixed API profile pointer typedef handling so runtime-memory heuristics keep their narrower pointer checks.
- Review mode fixed generic API argument rename collisions against existing case-variant locals.

validated:
- python -B -m unittest discover -s tests -v: 376 OK
- python -m pytest -q: 376 passed, 5 subtests passed
- python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
- git diff --check -- .: passed
- IDA Professional 9.0 no-PDB batch: 46 processed, 46 succeeded, 0 skipped, 0 failed, LLM disabled=46

artifacts:
- pseudoforge_out\ida_e2e_quality\qualitylift_20260601_220431
- pseudoforge_out\ida_e2e_quality\qualitylift_20260601_220431\quality_score.md

quality:
- average score: 65.83 -> 66.63
- compiler_local_name: 872 -> 818
- raw_pointer_offset: 73 -> 70
- artifact_reduction: 518 -> 554
```

Runtime helper alias quality lift:

```text
implemented:
- Added generic runtime helper alias inference for no-PDB `sub_*` memory-fill
  and memory-move helpers based on recovered signature roles and helper body
  evidence.
- Added batch postprocessing so inferred helper aliases render caller sites as
  standard `memset` or `memmove` calls in cleaned compare artifacts,
  per-function forge sections, aggregate forge output, and refreshed diffs.
- Helper function definitions keep their original `sub_*` names; only call
  sites are rewritten.
- Added interactive direct-callee probing so normal IDA use does not require
  analyzing all functions before helper aliases can appear in the current
  preview.
- Review mode fixed result-alias comparison handling so `result == ...` is not
  treated as a mutation.

validated:
- python -B -m unittest discover -s tests -v: 385 OK
- python -m pytest -q: 385 passed, 5 subtests passed
- python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
- git diff --check -- .: passed
- hardcoding scan over touched runtime-helper files: no sample-specific hits
- IDA Professional 9.0 no-PDB batch: 46 processed, 46 succeeded, 0 skipped, 0 failed, LLM disabled=46

artifacts:
- pseudoforge_out\ida_e2e_quality\helperalias_memset_20260601_223437
- pseudoforge_out\ida_e2e_quality\helperalias_memset_20260601_223437\quality_score.md

quality:
- average score: 66.63 -> 67.37
- average opportunity: 40.02 -> 39.33
- average reward: 7.39 -> 7.52
- unresolved_helper_call: 90 -> 74
- artifact_reduction: 554 -> 586
```

Inferred record field-access quality lift:

```text
implemented:
- Added generic pointer-sized cast/index cleanup for already inferred OB
  process-rule records. This converts forms such as casted `entry[2]` field
  reads into `entry->ProcessId` only after independent record evidence has
  identified the local as an `INFERRED_OB_PROCESS_RULE_RECORD`.
- Extended the same evidence gate from equality-only list checks to equality and
  inequality comparisons, covering while-list scans as well as for-loop scans.
- Added regression coverage for both casted index reads and inequality-based
  record walks.

review:
- Confirmed the rule is not tied to function address, binary name, pool tag, or
  sample-specific symbol text.
- Tightened the cast type pattern so `void *` is accepted but plain `void` is
  not.

validated:
- python -B -m unittest discover -s tests -v: 385 OK
- python -m pytest -q: 385 passed, 5 subtests passed
- python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
- git diff --check -- .: passed
- hardcoding scan over touched inferred-record files: no sample-specific hits
- IDA Professional 9.0 no-PDB batch with -SkipLibThunk: 46 processed, 46
  succeeded, 0 skipped, 0 failed, LLM disabled=46
- IDA Professional 9.0 no-PDB all-discovered-function batch: 51 processed, 51
  succeeded, 0 skipped, 0 failed, LLM disabled=51

artifacts:
- pseudoforge_out\ida_e2e_quality\record_compare_skiplib_20260601_225228
- pseudoforge_out\ida_e2e_quality\record_compare_skiplib_20260601_225228\quality_summary.md
- pseudoforge_out\ida_e2e_quality\record_compare_20260601_224936
- pseudoforge_out\ida_e2e_quality\record_compare_20260601_224936\quality_summary.md

quality:
- 46-function average score remains 67.37 after this narrow field-access lift.
- profile_field_access rewards: 45 -> 50
- typed_index_offset count: 58 -> 57
- unresolved_width_type count: 412 -> 406
- raw_pointer_offset count remains 70
```

No-PDB IDA batch postprocess and Opus 4.8 validation:

```text
implemented:
- Extended direct-helper alias postprocessing into IDA batch rendering so
  compare cleaned files, forge sections, and diffs all see the same helper
  cleanup as the interactive preview path.
- Exact-size local array zero-fill calls now render as
  memset(localArray, 0, sizeof(localArray)) after a helper is generically
  classified as memset; pointer targets keep explicit byte counts.
- Generated-code style now wraps control bodies that begin with a plain C label
  and include a following terminal statement, avoiding malformed unbraced
  if/label output.
- The LLM rename prompt is framed as defensive static-code readability and
  rename-only JSON output, keeping code rewrite and operational guidance out of
  the provider task.

validated:
- python -B -m unittest discover -s tests -v: 400 tests OK
- python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools: passed
- git diff --check -- .: passed
- IDA Professional 9.0 no-PDB all-discovered-function batch with
  claude_login_via_claude_cli / claude-opus-4-8: 51 processed, 51 succeeded,
  0 skipped, 0 failed, LLM ok=48, deterministic fallback=3 provider policy
  blocks

artifacts:
- pseudoforge_out\ida_batch_eval\ida_postprocess_llm_opus48_full_20260602_004100
- pseudoforge_out\ida_batch_eval\ida_postprocess_llm_opus48_full_20260602_004100\quality.md
- pseudoforge_out\ida_batch_eval\ida_postprocess_llm_opus48_full_20260602_004100\quality.json

quality:
- average score: 75.88
- average opportunity: 30.78
- average reward: 8.16
- cleaned-output sanity scan: dangling else=0, broken pointer-member comparison=0,
  unresolved helper-call memset candidate=0, unbraced if-label body=0
```

Claude CLI rename-assist stabilization:

```text
implemented:
- Claude CLI provider defaults now include --setting-sources project,local in
  addition to print mode, no session persistence, and disabled tools.
- Saved older default Claude command templates without setting-source isolation
  are migrated on config load.
- Interactive IDA LLM fallback logging now includes a short ASCII-safe reason in
  Output while still preserving deterministic fallback behavior.
- Existing IDA user configs using the older default Claude template can be
  migrated to the isolated command template while preserving the selected model,
  including claude-opus-4-8.

validated:
- python -B -m unittest discover -s tests -v: 402 tests OK
- python -B -m compileall .\ida_pseudoforge .\tests: passed
- git diff --check -- .: passed
- Claude CLI smoke reached the provider with the isolated command; the live
  failure observed in this run was an external session-limit message, not hook
  output contamination.
```

Next continuation point:

```text
Next batch should continue after 0x14021A324 RtlSparseArrayElementAllocate.
Suggested StartEa: 0x14021A325
For the historical ntoskrnl GPT batches, keep LLM path enabled with
-LlmProvider codex_cli -LlmModel gpt-5.5. For current Claude-login validation,
use -LlmProvider claude_login_via_claude_cli -LlmModel claude-opus-4-8 and a
command template containing --setting-sources project,local.
```

NtSet focused buffer-contract recheck against 26200.8457 ntoskrnl:

```text
implemented:
- Added tools/pseudoforge_ida_case_contract_batch.py for headless IDA focused
  buffer-contract case analysis using FunctionName:caseValue targets.
- Helper contract edges now preserve propagated field accesses, not only size
  and field predicates.
- Helper typed pointer parameters can use profile structure layouts to map
  param->Field accesses back to caller buffer offsets.
- Profile layout sizing uses x64 alignment and guards against alias cycles such
  as ULONG <-> DWORD.
- C++ struct rendering now keeps byte-sized profile fields such as BOOLEAN from
  being widened to the default 32-bit placeholder field size.
- Helper length propagation now prefers helper parameter names, so mode/flag
  arguments passed in variables with length-like caller names are not treated as
  buffer lengths.
- C character case labels such as case 'K': are parsed through the shared C
  literal parser, and NtSet* parameter-position fallback registers raw
  a1/a2/a3-style system/process/thread information buffers without relying on
  recovered parameter names.
- Helper analysis now treats caller temporaries as length operands when the
  helper parameter name/type identifies a size argument, while integer-cast
  arguments such as (unsigned int)v3 are not promoted to provisional buffers.

validated:
- IDA Professional 9.0 opened D:\bin\os\26200.8457\ntoskrnl.exe.i64 with
  -Opdb:off and processed NtSetInformationProcess, NtSetInformationThread, and
  NtSetSystemInformation by NameRegex: processed=3, succeeded=3.
- Full-function CLI replay on the fresh raw Hex-Rays output kept the expected
  contract counts: Process=58, Thread=26, System=49.
- Focused IDA case batch processed representative cases:
  NtSetSystemInformation 0x4B/0x36/0x50, NtSetInformationProcess 0x8/0x9/0x4D,
  NtSetInformationThread 0x3/0x4/0x1E: processed=9, succeeded=9.
- NtSetSystemInformation case 0x4B now captures
  ExpRegisterFirmwareTableInformationHandler and emits a
  PF_SYSTEM_SystemRegisterFirmwareTableInformationHandler_INPUT sketch with
  SYSTEM_FIRMWARE_TABLE_HANDLER fields ProviderSignature@0, Register@4,
  FirmwareTableHandler@8, and DriverObject@0x10 instead of a size-only reserved
  byte blob.
- The raw-argument form `case 'K': return
  ExpRegisterFirmwareTableInformationHandler(a2, (unsigned int)v3, a3, 1LL);`
  is covered by regression tests and recovers the same helper-backed structure.
- IDA focused case batch rechecked NtSetSystemInformation:0x4B after the
  char-literal fix: contracts=1, helpers=1, buffers=1.
- python -B -m unittest tests.test_buffer_contracts -v: 38 tests OK.
- python -B -m unittest discover -v: 465 tests OK.

review follow-up:
- Tightened helper length propagation so integer parameters such as ULONG flags
  are not treated as buffer lengths merely because of their type; helper
  length mapping now requires length/size/bytes-style parameter names.
- NtSet* parameter-position fallback now uses the prototype/signature function
  name when FunctionCapture.name is empty, preserving raw/offline captures that
  still contain an NtSet* signature.
- Added regressions for Helper(buffer, flags, inputLength) and empty-name
  NtSetSystemInformation captures.
- Production code hardcoding scan found no embedded 26200.8457 paths, ntoskrnl
  EAs, case 0x4B literals, or firmware-specific helper/structure names outside
  generated profiles/tests.
- python -B -m unittest tests.test_buffer_contracts -v: 40 tests OK.
- python -B -m unittest discover -v: 467 tests OK.
```

## Known Limits

1. Switch body reconstruction is conservative.
   - It can recover top-level dispatcher case values and single-return case bodies.
   - Deep nested or heavily shared branch bodies still require manual review.

2. LLM-assisted rename is optional and disabled by default.
   - Current default plan remains deterministic and validator-gated.
   - HTTP providers use OpenAI-compatible chat completions endpoints.
   - Local HTTP providers for Ollama, LM Studio, vLLM, and llama.cpp use named defaults and do not require API keys by default.
   - CLI providers run a configured local command with prompt on stdin.
   - CLI provider custom command templates must include `{model}` if the selected model should be passed to the command.
   - `chatgpt_oauth_via_codex_cli` is implemented as a Codex CLI auth bridge and requires `codex login` outside IDA once.
   - `claude_login_via_claude_cli` is implemented as a Claude CLI auth bridge and requires `claude auth login` outside IDA once.
   - Claude CLI defaults include `--setting-sources project,local`; older saved
     default templates are migrated, but explicitly custom templates remain the
     user's responsibility.
   - Provider-side session limits or policy blocks still produce deterministic
     fallback; the Output log now includes a short reason when available.
   - PseudoForge does not run browser login inside IDA; old `chatgpt_oauth` is not accepted as a provider ID.
   - IDA uses `Edit/PseudoForge/Configure LLM rename assist` and stores settings under the IDA user directory.

3. IDA-side preview defaults to a simple text preview window.
   - A persisted setting can enable the dockable raw-vs-cleaned side-by-side
     panel.
   - `PSEUDOFORGE_PREVIEW_BACKEND` remains available as a temporary override.
   - The dockable panel includes synchronized line search and a warning/rule
     analysis summary pane.

4. True object-level ctree rename application is not complete.
   - IDA apply currently uses `ida_hexrays.rename_lvar(function_ea, old, new)`
     after identity-aware preflight passes.
   - Identity-backed preflight and refresh behavior has been validated in a
     temporary IDA smoke run.

## Next Steps

1. Improve switch body reconstruction for shared/fallthrough branch paths.
2. Investigate true object-level ctree rename application beyond the validated
   identity preflight gates.
3. Compare report-only deterministic rule candidates against more hard-coded
   renderer paths before any replacement work.
4. Expand semantic overlays for more WDK APIs beyond the currently known pool/list/resource cases.
