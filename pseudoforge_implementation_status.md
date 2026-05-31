# PseudoForge Implementation Status

Current plugin version: `0.1.0`.

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
   - builtin rules mirror low-risk local rename, assignment rename, and call-presence semantic comment rules while keeping existing hard-coded deterministic passes in place
   - rule-based rename suggestions still pass through `validate_renames()`
   - export bundles include `<function>.rule-report.json`
   - export bundles are documented as durable review, audit, sharing, and regression artifacts rather than an IDB write path

4. Offline CLI
   - `tools/pseudoforge_cli.py`
   - `tools/pseudoforge_free_cli.py`
   - `tools/pseudoforge_ida_batch.py`
   - `tools/run_pseudoforge_ida_batch.ps1`
   - `tools/summarize_pseudoforge_ida_batch.py`
   - `tools/empty_llm_rename_provider.py`
   - `tools/pseudoforge_free_console.py`
   - `tools/validate_pseudoforge_rules.py`
   - optional `--llm-renames` path for configured rename assist provider
   - `--llm-provider` supports OpenAI-compatible, OpenRouter, DeepSeek API, Codex CLI, Claude CLI, `chatgpt_oauth_via_codex_cli`, and `claude_login_via_claude_cli`
   - optional `--rules-dir` for additional deterministic rule directories
   - optional `--rule-report` for writing a rule report JSON file or directory
   - IDA Free-compatible offline CLI path for copied or saved cloud-decompiled pseudocode text
   - IDA Free CLI path uses `ida_pseudoforge/core/offline_input.py` for conservative single-function extraction
   - IDA Free CLI path rejects no-function and multiple-function inputs with actionable diagnostics
   - IDA Free CLI path emits cleaned pseudocode, raw pseudocode, raw-vs-cleaned diff, rename map, warnings, rule report, and summary artifacts
   - IDA Free CLI path supports `--project-root`, `--rules`, `--llm`, `--no-llm`, `--no-progress`, and `--format text|json`
   - IDA Free CLI text mode prints incremental progress by default and reports `complete`, `partial`, or `failed` final status summaries
   - IDA Free CLI JSON mode keeps stdout machine-readable and writes progress to stderr unless `--no-progress` is used
   - IDA Free CLI path does not import IDA-only modules, does not use IDAPython or local Hex-Rays APIs, and does not modify an IDB
   - headless IDA batch mode can iterate `.i64`/`.idb` functions, call Hex-Rays decompile, analyze through PseudoForge, append `.forge` sections, and write JSONL progress reports
   - optional `--compare-dir` / `-CompareDir` emits per-function raw Hex-Rays text, PseudoForge cleaned output, full `.forge` section, and raw-vs-cleaned unified diff artifacts
   - batch compare JSONL records include shared-style artifact keys while preserving legacy path fields
   - optional `--llm-renames` / `-LlmRenames` routes batch analysis through the same rename provider/fallback path as interactive IDA Analyze
   - Hex-Rays decompile-unavailable functions are recorded as `skipped` instead of PseudoForge failures

5. Optional LLM assist
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
   - CLI command templates pass the selected model through `{model}`
   - migration for old default Codex/Claude command templates that did not pass `{model}`, used unsupported Codex CLI flags, or omitted the safer Claude print-mode flags
   - Windows CLI provider calls and Codex model discovery request hidden child console windows to avoid Claude/Codex console flashes during normal runs
   - analyze summary displays warning details instead of only warning counts
   - provider-specific API key storage under `credentials`
   - API key prompt only when an enabled HTTP provider has no stored key
   - disabled by default
   - IDA LLM configuration dialog logic is isolated in `ida_pseudoforge/ida/llm_config_dialog.py`, and model-discovery exceptions fall back to static model lists without saving corrupt config

6. Tests
   - `tests/test_ida_plugin_safety.py`
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
   - `tests/test_render_style.py`
   - `tests/test_render_warnings.py`
   - `tests/test_render_zw.py`
   - `tests/test_rule_engine.py`
   - `tests/test_rule_integration.py`
   - `tests/test_rule_pack_validator.py`
   - `tests/test_rule_context.py`
   - `tests/test_ui_preview.py`
   - `tests/test_plan_builder.py`
   - `tests/test_profile_loader.py`
   - `tests/test_export_bundle.py`
   - `tests/test_ida_batch.py`
   - `tests/test_llm_config.py`
   - `tests/test_llm_rename_filters.py`
   - `tests/test_logging.py`
   - `tests/test_pseudoforge_free_cli.py`
   - `tests/test_release_pseudoforge.py`
   - renderer golden snapshots under `tests/snapshots`
   - current suite covers 268 unit tests

## Latest Implementation Notes

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

P2 IDA UX diagnostics update:

- The IDA analysis completion summary now includes deterministic rule-report
  counts for matched rules, rewrite emissions by status, rule-pack load errors,
  and validation errors.
- Detailed rule diagnostics remain in the exported `rule-report.json`; the
  summary only exposes concise counts.

The current implementation state reflects the `NtSetSystemInformation` and `NtSetInformationProcess` large-dispatcher regression pass:

- `NtSetSystemInformation` preview now uses the canonical native API signature and introduces typed `__m128i *` aliases without changing the underlying decompiler body semantics.
- `SYSTEM_INFORMATION_CLASS` literal and delta-chain rewrites are profile-backed, including chained temporaries such as `v86 = v85 - 8` when the rewrite is still structurally tied to the original dispatcher comparison.
- `NtSetInformationProcess` preview now uses the canonical native API signature with `PROCESSINFOCLASS processInformationClass` and rewrites process-info-class case labels/comparisons through the 25H2 profile.
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
- Memory Manager probe functions that combine `MmGetSystemRoutineAddress`, `MmCopyMemory`, MDL setup, noncached memory, and contiguous memory allocation now recover routine-name, buffer, MDL, byte-count, and physical-address locals. `MmCopyMemory` flag literals now render as `MM_COPY_MEMORY_PHYSICAL` or `MM_COPY_MEMORY_VIRTUAL`.
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
  Configure LLM rename assist
  Configure profile directory
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
  Configure LLM rename assist
  Configure profile directory
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
<function>.rule-report.json
```

`switch-outline.cpp` now includes only single-statement returns and complete
local branch slices. Complex dispatcher paths remain in the normalized original
pseudocode.

## Current Validation Run

Commands that passed:

```powershell
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
python -B .\tools\pseudoforge_free_cli.py --version
python -B .\tools\pseudoforge_free_cli.py --help
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_claude_hidden_free_cli_smoke
git diff --check -- .
```

Latest unit test count: 189 tests.

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
- render.py, ida/actions.py, and ida/ui_preview.py remain candidates for later scoped extraction; they were not broadly rewritten in this pass to avoid behavior drift.
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
- Full non-blocking LLM model discovery UI refresh is still deferred; current behavior keeps the existing dialog flow with safer fallback handling.
- True object-level ctree rename application is still incomplete; apply continues to call ida_hexrays.rename_lvar(function_ea, old, new) after the new session and identity preflight gates pass.
- Manual IDA validation of identity-backed apply after local type/name refresh is still pending.
- Interactive export now shares raw pseudocode, warnings JSON, raw-vs-cleaned diff, and summary JSON artifacts with the CLI paths; only IDA Free CLI-specific run manifest output remains separate.
```

Next continuation point:

```text
Next batch should continue after 0x14021A324 RtlSparseArrayElementAllocate.
Suggested StartEa: 0x14021A325
Keep LLM path enabled with -LlmProvider codex_cli -LlmModel gpt-5.5.
```

## Known Limits

1. Switch body reconstruction is conservative.
   - It can recover top-level dispatcher case values and single-return case bodies.
   - Deep nested or heavily shared branch bodies still require manual review.

2. LLM-assisted rename is optional and disabled by default.
   - Current default plan remains deterministic and validator-gated.
   - HTTP providers use OpenAI-compatible chat completions endpoints.
   - CLI providers run a configured local command with prompt on stdin.
   - CLI provider custom command templates must include `{model}` if the selected model should be passed to the command.
   - `chatgpt_oauth_via_codex_cli` is implemented as a Codex CLI auth bridge and requires `codex login` outside IDA once.
   - `claude_login_via_claude_cli` is implemented as a Claude CLI auth bridge and requires `claude auth login` outside IDA once.
   - PseudoForge does not run browser login inside IDA; old `chatgpt_oauth` is not accepted as a provider ID.
   - IDA uses `Edit/PseudoForge/Configure LLM rename assist` and stores settings under the IDA user directory.

3. IDA-side preview uses a simple text preview window.
   - A richer dockable side-by-side panel is still pending.

4. True object-level ctree rename application is not complete.
   - IDA apply currently uses `ida_hexrays.rename_lvar(function_ea, old, new)`
     after identity-aware preflight passes.
   - Manual IDA validation of enriched lvar anchors is still pending.

## Next Steps

1. Extend deterministic rules matching engine beyond v2 preview reports with a safe `flow` phase when branch evidence is strong enough.
2. Improve switch body reconstruction for shared/fallthrough branch paths.
3. Add a richer dockable side-by-side preview panel.
4. Manually validate identity-backed local variable rename application inside
   IDA after local type/name refresh.
5. Expand semantic overlays for more WDK APIs beyond the currently known pool/list/resource cases.
