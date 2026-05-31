# PseudoForge Improvement Plan

Date: 2026-05-31

This plan records improvement work found by reading the current documentation,
core analysis code, IDA integration code, CLI tooling, and tests. It is scoped to
work that improves correctness, safety, maintainability, validation coverage, and
operational usability without weakening PseudoForge's deterministic-first design.

## Review Scope

Reviewed documentation:

- `README.md`
- `pseudoforge_implementation_status.md`
- `ida_pseudocode_refactor_plugin_design.md`
- `deterministic_rules_matching_engine_design.md`
- `samples/kernel_pattern_driver/README.md`

Reviewed code areas:

- Core plan construction, validation, flow recovery, rendering, kernel semantics,
  kernel API rewrites, deterministic rules, profile loading, and forge storage.
- IDA action, preview, async, apply, decompiler, and config-dialog integration.
- Offline CLI, IDA Free CLI, IDA batch, release, profile-builder, and rule
  validation tools.
- Unit tests and current coverage layout.

Generated profile payloads such as `ida_pseudoforge/profiles/kernel_api.json`
were treated as generated data. The review focused on their loader, builder, size,
metadata, and runtime impact rather than hand-reviewing every generated entry.

## Priority Summary

1. P0: Preserve the current safety boundary while improving rename identity.
2. P1: Split the monolithic renderer and add snapshot-based output protection.
3. P1: Reduce kernel profile load cost and add versioned profile selection.
4. P1: Align interactive export artifacts with the IDA Free CLI artifact set.
5. P1: Continue deterministic rules v2 with span-safe rewrite phases.
6. P2: Improve switch body reconstruction without synthesizing unsafe bodies.
7. P2: Split the test monolith into domain-focused suites.
8. P2: Improve IDA UX for large previews, model discovery, and rule diagnostics.
9. P3: Expand real-target validation and release/documentation hygiene.

## P0: Safer Rename Identity Tracking

Status: In progress.

Completed:

- [x] Added optional IDA lvar identity metadata for cfunc-derived locals.
- [x] Attached captured lvar identity data to IDA-originated rename plans when
  available.
- [x] Added identity-aware apply preflight that rejects same-name/different-
  identity drift before IDB modification.
- [x] Refused identity-backed IDA apply when current lvar identity cannot be
  re-read before the write.
- [x] Preserved legacy name-based fallback when identity metadata is unavailable.
- [x] Added focused tests for identity match, identity drift, and legacy fallback.

Remaining:

- [ ] Add richer ctree location anchors if a stable Hex-Rays API surface is
  mapped and tested.
- [ ] Validate the identity-backed apply path manually inside IDA after a local
  type/name refresh.

### Current Evidence

- `pseudoforge_implementation_status.md` lists ctree identity tracking as a known
  incomplete area.
- `ida_pseudoforge/core/lvar_analysis.py:35` builds a `CleanPlan` from text
  captures and rename suggestions.
- `ida_pseudoforge/core/validation.py:148` validates rename candidates by known
  names, collisions, identifier shape, and LLM-specific heuristics.
- `ida_pseudoforge/ida/apply_changes.py` performs final apply preflight, but the
  final IDA write still depends on the old local name string reaching
  `ida_hexrays.rename_lvar()`.

### Problem

The current string-name path is conservative and validator-gated, but it is still
weaker than an identity-backed apply path. Decompiled locals can be renamed,
merged, split, or shadowed between analysis and apply. The session fingerprint
and stale-function checks reduce this risk, but they do not prove the selected
old-name string maps to the same Hex-Rays local identity that was analyzed.

### Plan

1. Extend `FunctionCapture` local entries with stable IDA-side identity metadata
   when running inside IDA:
   - lvar index
   - declaration type string
   - storage/location text when available
   - ctree location anchors where practical
   - original name and normalized source fingerprint
2. Add `RenameSuggestion.identity` or equivalent metadata for IDA-originated
   arg/lvar candidates.
3. Update apply preflight to compare the current cfunc lvar list against the
   captured identity before calling `rename_lvar()`.
4. Keep the current old-name fallback only for offline exports and for IDA
   versions where identity metadata cannot be retrieved.
5. Add focused tests with fake cfunc/lvar identity drift:
   - same name, different identity: reject
   - same identity, same function, same fingerprint: allow
   - missing identity on legacy capture: require current conservative checks
6. Add one manual IDA validation checklist item for rename apply after a local
   type/name refresh.

### Acceptance Criteria

- Apply rejects same-name/different-identity drift before IDB modification.
- Existing offline CLI behavior is unchanged.
- Existing `apply_selected_renames()` tests continue to pass.
- New tests cover identity mismatch, missing identity fallback, and successful
  identity-backed apply.

### Validation

```powershell
python -B -m unittest tests.test_ida_plugin_safety -v
python -B -m unittest discover -s tests -v
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
git diff --check -- .
```

## P1: Renderer Decomposition And Snapshot Protection

Status: In progress.

Completed:

- [x] Added renderer snapshot test harness with normalized version and
  fingerprint metadata.
- [x] Added initial golden snapshots for native API dispatcher,
  DriverEntry/device-extension cleanup, IOCTL dispatch, OB pre-operation
  callback, and generic non-kernel style output.
- [x] Added an explicit snapshot update workflow under `tests/snapshots`.
- [x] Introduced `RenderContext` for capture, plan, rename map, displayed
  warnings, and native switch dispatcher metadata.
- [x] Moved NTSTATUS literal and status-type rewrite helpers into a scoped
  `render_status` module while keeping `ida_pseudoforge.core.render` imports
  compatible.
- [x] Moved generated-code style normalization into a scoped `render_style`
  module with behavior-preserving direct tests and snapshot coverage.
- [x] Moved dispatcher/profile literal rendering for `SYSTEM_INFORMATION_CLASS`,
  `PROCESSINFOCLASS`, and character case labels into a scoped
  `render_dispatcher` module.
- [x] Moved IOCTL/IRP rendering for `CTL_CODE(...)` switch annotations,
  `AssociatedIrp.SystemBuffer`, and `IO_STACK_LOCATION.Parameters.DeviceIoControl`
  field access into a scoped `render_ioctl` module.
- [x] Moved IRP dispatch signature and body cleanup for canonical dispatch
  parameters, status/length local types, DeviceExtension access, IRP alias
  removal, completion casts, and status returns into `render_ioctl`.
- [x] Moved semantic label rendering for cleanup label renaming, annotations,
  indentation normalization, and stale embedded-tail hoisting into a scoped
  `render_labels` module.
- [x] Moved DriverEntry rendering for canonical signature output, status
  normalization, IRP major constants, device flags, and `IoCreateDevice`
  secure-open rendering into a scoped `render_driver_entry` module.
- [x] Moved callback rendering for OB pre-operation signatures, callback
  registration toggle body cleanup, and registry callback status checks into a
  scoped `render_callbacks` module.
- [x] Moved Zw API probe rendering for `OBJECT_ATTRIBUTES` length/flag cleanup,
  `NtCurrentProcess()` / `NtCurrentThread()`, and Zw status success checks into
  a scoped `render_zw` module.
- [x] Moved `NtSetSystemInformation` m128/body rendering for typed
  `systemInformation` access, mutable alias splitting, and `userProbeEnd`
  recovery into a scoped `render_ntset` module.
- [x] Moved warning formatting, ranking, and display-only suppression filters
  into a scoped `render_warnings` module while preserving public render imports.
- [x] Moved flow report and conservative switch outline rendering into a scoped
  `render_flow` module while preserving public render imports.
- [x] Moved path-like C/C++ string literal finalization into a scoped
  `render_literals` module while preserving public render imports.
- [x] Moved critical-region entry rewrite and LIST_ENTRY/provider-link hint
  annotation into a scoped `render_kernel_hints` module while preserving public
  render imports.
- [x] Moved low-byte parameter call-argument cleanup into a scoped
  `render_call_args` module while preserving public render imports.
- [x] Moved known function/callback signature replacement and
  signature-sensitive body routing into a scoped `render_signatures` module
  while preserving public render imports.
- [x] Moved generated header formatting and kernel semantic rewrite counting
  into a scoped `render_header` module while preserving public render imports.

Remaining:

- [ ] Move the remaining renderer passes into scoped modules one rewrite family
  at a time.
- [ ] Preserve public render imports during extraction.
- [ ] Keep extraction commits behavior-preserving unless documented otherwise.

### Current Evidence

- `ida_pseudoforge/core/render.py` is the largest production module at roughly
  182 lines after the status, style, dispatcher, IOCTL/IRP, semantic-label,
  DriverEntry, callback, IRP dispatch, Zw API, NtSet, warning-display,
  flow/switch-outline, path-literal, kernel-hint, call-argument, signature
  routing, and header extraction slices.
- `render_cleaned_pseudocode()` still coordinates many ordered text passes in
  `ida_pseudoforge/core/render.py`.
- `ida_pseudoforge/core/render.py` preserves the public `write_export_bundle`
  import path as a compatibility wrapper around
  `ida_pseudoforge/core/export_bundle.py`.
- Style normalization now lives in `ida_pseudoforge/core/render_style.py`.
- Dispatcher/profile literal rendering now lives in
  `ida_pseudoforge/core/render_dispatcher.py`.
- IOCTL/IRP rendering now lives in `ida_pseudoforge/core/render_ioctl.py`,
  including IRP dispatch signature/body cleanup, and semantic label rendering
  now lives in `ida_pseudoforge/core/render_labels.py`.
- DriverEntry rendering now lives in
  `ida_pseudoforge/core/render_driver_entry.py`.
- Callback rendering now lives in
  `ida_pseudoforge/core/render_callbacks.py`.
- Zw API probe rendering now lives in `ida_pseudoforge/core/render_zw.py`,
  and `NtSetSystemInformation` body rendering now lives in
  `ida_pseudoforge/core/render_ntset.py`; warning formatting/ranking/filtering
  now lives in `ida_pseudoforge/core/render_warnings.py`.
- Flow report and conservative switch outline rendering now live in
  `ida_pseudoforge/core/render_flow.py`.
- Path-like C/C++ string literal finalization now lives in
  `ida_pseudoforge/core/render_literals.py`.
- Critical-region entry rewrite and LIST_ENTRY/provider-link hint annotation
  now live in `ida_pseudoforge/core/render_kernel_hints.py`.
- Low-byte parameter call-argument cleanup now lives in
  `ida_pseudoforge/core/render_call_args.py`.
- Known function/callback signature replacement and signature-sensitive body
  routing now live in `ida_pseudoforge/core/render_signatures.py`.
- Generated header formatting and kernel semantic rewrite counting now live in
  `ida_pseudoforge/core/render_header.py`.

### Problem

The render pipeline is behavior-rich and already valuable, but the current file
shape makes regression risk high. A local change to one rewrite family can
silently affect unrelated output because ordering is implicit in one long
function and many helper names live in the same namespace. Unit tests cover many
cases, but they are mostly assertion-based rather than full rendered-output
snapshots.

### Plan

1. Introduce a small `RenderContext` object containing `capture`, `plan`,
   `rename_map`, `warnings`, and native switch metadata.
2. Split render passes into scoped modules:
   - `render/status.py`
   - `render/dispatcher.py`
   - `render/ioctl.py`
   - `render/kernel_api.py`
   - `render/driver_entry.py`
   - `render/callbacks.py`
   - `render/labels.py`
   - `render/style.py`
   - `render/export_bundle.py`
3. Keep the public import path stable:
   - `render_cleaned_pseudocode`
   - `render_switch_outline`
   - `render_flow_report`
   - `write_export_bundle`
4. Add golden snapshot fixtures for representative cases:
   - native API dispatcher
   - DriverEntry/device-extension cleanup
   - IOCTL dispatch
   - OB pre-operation callback
   - generic non-kernel function
5. Add a snapshot update workflow that is explicit and reviewable.
6. Only move one rewrite family per commit to keep diff review sane.

### Acceptance Criteria

- Public render API remains compatible.
- Snapshot failures show clean raw-vs-cleaned diffs.
- No behavior changes occur during pure extraction commits unless explicitly
  documented.
- `render.py` becomes a thin compatibility layer or is removed after imports are
  migrated.

### Validation

```powershell
python -B -m unittest discover -s tests -v
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_smoke
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_smoke
git diff --check -- .
```

## P1: Profile Loading, Size, And Version Management

Status: In progress.

Completed:

- [x] Added profile loader diagnostics for missing files, invalid JSON, read
  failures, and non-object profile roots.
- [x] Exposed profile load warnings in renderer warning output, flow reports,
  offline CLI warnings, IDA Free CLI warnings, and IDA batch JSONL records.
- [x] Added focused loader coverage for invalid JSON profile diagnostics.
- [x] Added profile manifest metadata and active profile reporting in export
  summaries.

Remaining:

- [ ] Split generated kernel API profile output into smaller artifacts.
- [ ] Add lookup-family loader APIs that avoid loading the full kernel profile.
- [ ] Add optional target-build profile selection.
- [ ] Add cold-load and repeated-lookup performance smoke checks.

### Current Evidence

- `ida_pseudoforge/profiles/kernel_api.json` is about 44 MB.
- `ida_pseudoforge/profiles/loader.py:13` loads JSON profiles through an
  unbounded `lru_cache`.
- `ida_pseudoforge/core/kernel_api.py:127` loads the full kernel API profile for
  symbol and function metadata lookup.
- The implementation status records a single WDK 10.0.26100.0-generated profile
  as the current broad profile.

### Problem

The full generated profile is convenient, but loading the entire 44 MB JSON
payload is expensive in IDA startup and first-analysis contexts. It also bakes
one WDK version into runtime behavior, while target binaries can come from
different Windows builds. Silent JSON load failure currently returns `{}`, which
keeps analysis alive but can hide profile corruption.

### Plan

1. Split generated profile output into smaller artifacts:
   - `kernel_functions.json`
   - `kernel_enums.json`
   - `kernel_structures.json`
   - `kernel_aliases.json`
   - `kernel_macros.json`
   - `kernel_symbol_index.json`
   - `profile_manifest.json`
2. Add loader APIs for specific lookup families instead of loading the whole
   profile for every path.
3. Add profile manifest metadata:
   - WDK version
   - generated timestamp
   - header set
   - entry counts
   - generator version
   - SHA-256 per split file
4. Add optional target-build profile selection:
   - default profile remains current behavior
   - CLI and IDA settings can select a profile version
   - batch mode records selected profile metadata in JSONL
5. Turn profile JSON decode errors into warnings in export/batch reports while
   keeping deterministic fallback behavior.
6. Add performance smoke checks for cold profile load and repeated lookups.

### Acceptance Criteria

- First lookup only loads the minimum needed profile file.
- Current generated metadata counts are preserved or intentionally documented.
- Corrupt profile files produce visible warnings instead of silent empty
  semantics.
- Batch JSONL records the active profile manifest.

### Validation

```powershell
python -B .\tools\build_kernel_api_profile.py --version 10.0.26100.0 --dry-run --summary --function ExAllocatePool2 --function MmCopyMemory
python -B .\tools\build_status_codes_profile.py --version 10.0.26100.0 --dry-run --summary
python -B -m unittest tests.test_kernel_api_profile_builder -v
python -B -m unittest discover -s tests -v
```

## P1: Interactive Export Parity With IDA Free CLI

Status: In progress.

Completed:

- [x] Added raw pseudocode, warnings JSON, raw-vs-cleaned diff, and summary JSON
  to the shared export bundle while preserving existing artifact keys.
- [x] Added entrypoint metadata for interactive export, offline CLI, and IDA Free
  CLI calls that use the shared bundle writer.
- [x] Added README artifact parity table across IDA interactive export, offline
  CLI, and IDA Free CLI.
- [x] Added focused export bundle coverage for parity artifacts and summary
  metadata.
- [x] Moved shared artifact writing into `ida_pseudoforge/core/export_bundle.py`
  while preserving the legacy `ida_pseudoforge.core.render.write_export_bundle`
  import path.
- [x] Added shared-style artifact keys to IDA batch compare records while
  preserving legacy `raw_path`/`cleaned_path`/`diff_path` fields.
- [x] Added profile manifest metadata to shared export and IDA Free summary
  payloads once manifests exist.

Remaining:

- [ ] Extend profile manifest metadata into future split-profile and
  target-build selection reports.

### Current Evidence

- `ida_pseudoforge/core/export_bundle.py` writes cleaned pseudocode, switch
  outline, rename map, flow report, rule report, raw pseudocode, warnings JSON,
  raw-vs-cleaned diff, and per-function summary JSON.
- `tools/pseudoforge_free_cli.py` now uses the shared bundle writer for those
  artifacts, keeps its `.ida-free-summary.json` compatibility filename, and
  adds the run manifest.
- `pseudoforge_implementation_status.md` records the shared export parity update
  and the completed profile manifest reporting follow-up.
- IDA batch compare records preserve legacy path fields and now include an
  `artifacts` map with shared export key names.

### Current Gap

Interactive IDA export, offline CLI, IDA Free CLI, and IDA batch compare records
now expose the shared raw/cleaned/diff artifact shape where practical. The
remaining export metadata work is future split-profile and target-build
selection reporting.

### Plan

1. Move shared artifact writing into a reusable export module.
2. Add optional raw pseudocode, warnings JSON, raw-vs-cleaned diff, and summary
   JSON to interactive export.
3. Keep existing artifact names stable.
4. Record entrypoint metadata:
   - `ida_interactive`
   - `ida_batch`
   - `ida_free_offline`
5. Include version, function EA, target path identity, profile manifest, LLM
   status, rule report status, and warning counts in the summary JSON.
6. Add a README table comparing artifact parity across entrypoints.

### Acceptance Criteria

- Interactive export includes raw-vs-cleaned diff by default.
- Existing scripts that consume current artifact names keep working.
- IDA Free and IDA interactive summaries share a common schema where practical.

### Validation

```powershell
python -B -m unittest tests.test_pseudoforge_free_cli -v
python -B -m unittest tests.test_ida_plugin_safety -v
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_export_parity
```

## P1: Deterministic Rules V2 Rewrite Phases

Status: In progress.

Completed:

- [x] Added `schema_version: 2` validation support for preview-only
  `call_arg_rewrite` rules.
- [x] Required v2 `call_arg_rewrite` emissions to declare `preview_only: true`,
  a target function name, a non-negative argument index, and a replacement.
- [x] Required static v2 `call_arg_rewrite` function names to be gated by
  matching `calls_any`/`calls_all` scope.
- [x] Added runtime `RuleEmission(kind="call_arg_rewrite")` support without
  converting those emissions into rename/comment plan outputs or IDB writes.
- [x] Added rule-report `rewrite_emissions` entries for preview-only
  `call_arg_rewrite` candidates with `applied`, `shadowed`, or `rejected`
  status.
- [x] Mirrored the low-risk
  `PsSetCreateProcessNotifyRoutine`/`PspSetCreateProcessNotifyRoutine`
  BOOLEAN remove-argument cleanup family as builtin report-only
  `call_arg_rewrite` rules for parity comparison.
- [x] Documented the v2 preview-only boundary in
  `deterministic_rules_matching_engine_design.md`.

Remaining:

- [ ] Add `text_rewrite` only after span conflict detection exists.
- [ ] Add `flow` only after stronger branch evidence exists.

### Current Evidence

- `deterministic_rules_matching_engine_design.md` documents v2
  `call_arg_rewrite` as preview/export-only and still reserves `text_rewrite`
  and `flow`.
- `ida_pseudoforge/core/deterministic/validators.py` accepts v1 rename/comment
  phases and v2 preview-only `call_arg_rewrite`, with emit kind matching phase.
- `ida_pseudoforge/core/deterministic/schema.py` exposes
  `RuleReport.rewrite_emissions` for preview-only rewrite status reporting.
- `ida_pseudoforge/rules/builtin/call_arg_rewrites.json` mirrors one BOOLEAN
  call-argument cleanup family without replacing hard-coded rendering.
- `ida_pseudoforge/core/deterministic/context.py:55` builds regex-oriented
  facts: assignments, calls, labels, and literals.
- Existing hard-coded rewrites remain in `kernel_rewrites.py`, `kernel_api.py`,
  and `render.py`.

### Problem

The rule engine is already useful for rename and semantic-comment rules, but the
more valuable kernel cleanup behavior is still hard-coded. Moving everything at
once would be risky. The next step should add rule phases that can report and
shadow hard-coded behavior before they are allowed to replace it.

### Plan

1. Add a rule v2 schema version while keeping v1 compatibility.
2. Add `call_arg_rewrite` as the first v2 phase:
   - only preview/export output
   - no IDB writes
   - typed argument index and function-name gates required
   - report applied/rejected rewrites
3. Add `text_rewrite` after span conflict detection exists:
   - explicit `before_regex`
   - explicit `replacement`
   - `requires_comment_kind` or equivalent semantic gate
   - export-only by default
4. Add `flow` only after match facts include enough branch evidence to avoid
   overclaiming control-flow recovery.
5. Mirror one low-risk hard-coded rewrite family first, then compare outputs.
6. Keep hard-coded behavior active until parity snapshots pass.

### Acceptance Criteria

- Invalid v2 rules fail closed with useful validation errors.
- Reports show matched, applied, shadowed, and rejected rewrite emissions.
- Rule rewrites cannot touch IDB state.
- At least one low-risk call-argument rewrite has parity coverage against the
  existing hard-coded path.

### Validation

```powershell
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
python -B -m unittest discover -s tests -v
```

## P2: Richer RuleContext And Dataflow Facts

Status: Completed.

Completed:

- [x] Added call-site argument lists, absolute argument spans, and line indexes
  to `RuleContext.call_sites`.
- [x] Reused shared parenthesis matching and parameter splitting helpers for
  nested calls and comma-containing strings.
- [x] Added coverage for nested call arguments, string commas, absolute spans,
  and malformed call text fallback.
- [x] Added typed assignment facts for RHS identifiers, numeric literals, and
  pure RHS call expressions.
- [x] Added lvar type, argument, location, index, and identity facts from
  `FunctionCapture.lvars`.
- [x] Added v2 rule match gates for call argument count and literal argument
  values without regex.
- [x] Added profile-backed function facts for known calls, including parameter
  names, types, kinds, enum tags, headers, return types, and alias metadata.

### Current Evidence

- `RuleContext` now indexes regex facts plus call-site, assignment dataflow, and
  local-variable/profile metadata facts.
- V2 rules can gate matches on exact call-site argument count and exact literal
  argument values.
- Rule contexts built by `build_clean_plan()` include kernel profile metadata
  for known function calls while ignoring missing or failed profile lookups.
- Existing render and kernel rewrite code already contains argument splitting,
  call-argument parsing, literal parsing, and helper-specific heuristics.

### Problem

V2 rules need stronger facts than text spans. Without typed call-site,
assignment, local-variable, and profile facts, JSON rules either become too weak
to be useful or too broad to be safe. Reusing parser helpers also reduces
duplicate parsing bugs.

### Plan

1. Add typed call-site facts:
   - call name
   - full argument list
   - argument spans
   - line index
2. Add typed assignment facts:
   - lhs
   - rhs
   - rhs identifiers
   - literal values
   - call expression if rhs is a call
3. Add lvar type facts from `FunctionCapture.lvars`.
4. Add profile facts for known functions and enums.
5. Reuse existing `_split_arguments()` logic through a shared utility module.
6. Add tests for nested calls, casts, strings, comma-containing expressions, and
   malformed decompiler text.

### Acceptance Criteria

- Rule matching can gate on function call argument count and literal argument
  values without ad hoc regex.
- Existing v1 rule packs behave exactly as before.
- Malformed pseudocode produces partial facts, not runtime crashes.

## P2: Conservative Switch Body Reconstruction

Status: In progress.

Completed:

- [x] Added explicit recovered case body states:
  `single_statement_body`, `shared_tail`, `fallthrough_or_join`, and
  `complex_unsliced`.
- [x] Added source line anchors and shared-tail labels to switch outlines and
  flow reports.
- [x] Added regression coverage for shared cleanup tails without expanding them
  as unique case bodies.

Remaining:

- [ ] Add branch-slice helper that only extracts bodies when all exits and joins
  are represented.
- [ ] Add regression samples for fallthrough and nested native switches.

### Current Evidence

- README and status docs both list full switch body reconstruction for shared
  and fallthrough branches as pending.
- `render_switch_outline()` intentionally expands only safe bodies and points
  complex cases back to normalized original pseudocode.
- `render_flow_report()` now maps cases to body state, source line anchor, and
  shared-tail label when available.

### Problem

The current conservative output is safer than an overconfident fake switch, but
large dispatcher review still requires too much manual correlation when many
cases share labels, cleanup tails, or fallthrough-like paths.

### Plan

1. Represent recovered cases with explicit body states:
   - `single_statement_body`
   - `shared_tail`
   - `fallthrough_or_join`
   - `complex_unsliced`
2. Add labels and source line anchors to the outline for non-expanded cases.
3. Add a sidecar `flow-report.md` section mapping each case to labels and
   branch anchors.
4. Add a branch-slice helper that only extracts bodies when all exits and joins
   are represented.
5. Add regression samples for shared cleanup, goto-dependent paths, fallthrough,
   and nested native switches.

### Acceptance Criteria

- Complex cases are easier to audit without pretending to be full switch bodies.
- No output path loses the normalized original pseudocode.
- Cases with shared tails are labeled as shared rather than expanded as unique
  bodies.

## P2: Test Suite Restructure

### Current Evidence

- `tests/test_core_engine.py` is about 5140 lines.
- The status document already lists the historical monolith as deferred debt.
- Test coverage is broad but organized mostly by accumulation rather than by
  subsystem.

### Problem

The current test monolith makes focused review harder. It also increases merge
conflict risk and makes it harder to identify which subsystem owns a regression.

### Plan

1. Split `test_core_engine.py` into domain suites:
   - `test_plan_builder.py`
   - `test_render_status.py`
   - `test_render_dispatcher.py`
   - `test_render_driver_entry.py`
   - `test_render_ioctl.py`
   - `test_render_labels.py`
   - `test_render_callbacks.py`
   - `test_validation.py`
   - `test_deterministic_rules.py`
   - `test_forge_store.py`
2. Move shared fixtures into `tests/fixtures/` or `tests/helpers.py`.
3. Add snapshot fixtures for rendered output.
4. Keep `python -B -m unittest discover -s tests -v` as the canonical local
   command.
5. Make each split commit behavior-preserving.

### Acceptance Criteria

- Test count is preserved during split.
- Domain-specific test files can be run independently.
- Fixture duplication goes down.

## P2: IDA UX And Long-Running Operation Improvements

### Current Evidence

- The simple custom viewer has preview size/highlight limits in
  `ida_pseudoforge/ida/ui_preview.py`.
- The status document defers full non-blocking LLM model discovery.
- The README lists a richer dockable side-by-side preview panel as pending.

### Problem

PseudoForge targets large kernel functions. The current simple viewer is stable
and intentionally low-risk, but large output review still needs better
navigation, diffing, rule diagnostics, and long-running progress behavior.

### Plan

1. Keep `simplecustviewer_t` as the fallback path.
2. Add a dockable side-by-side review panel behind a feature flag:
   - raw pseudocode
   - cleaned pseudocode
   - synchronized line search
   - warning/rule summary pane
3. Add non-blocking model discovery:
   - show cached/static models immediately
   - refresh in background
   - save only after successful user confirmation
4. Add cancellation/progress hooks for long LLM and batch work where IDA APIs
   allow it.
5. Add rule load/validation warnings as concise Output messages with full
   details in the rule report.

### Acceptance Criteria

- Existing viewer remains available and tested.
- Dockable panel can be disabled by environment/config.
- Model discovery failure never corrupts saved config.
- Large previews still fall back to plain text safely.

## P3: Real-Target Validation Continuation

### Current Evidence

- The status document records large-scale non-LLM and LLM ntoskrnl validation.
- The next continuation point is after `0x14021A324 RtlSparseArrayElementAllocate`.

### Problem

The current validation history is strong, but it is manually curated and stored
mostly as status text. Continuing real-target validation should produce
machine-readable review artifacts and issue buckets so regressions become easier
to compare across runs.

### Plan

1. Continue the next 72-function LLM batch from `StartEa: 0x14021A325`.
2. Store review verdicts in a structured JSON/Markdown pair:
   - `OK`
   - `OK-WARN`
   - `REVIEW`
   - `FAIL`
3. Add summarizer support for recurring warning classes and rendered-output
   quality buckets.
4. Convert accepted findings into focused regression tests before broad fixes.
5. Track profile version, IDA version, model/provider, and command line in every
   report.

### Acceptance Criteria

- Each broad validation run has a reproducible command and structured summary.
- Every `FAIL` has either a linked regression test or a documented false alarm.
- Batch summaries can compare status counts between two runs.

## P3: Documentation And Release Hygiene

### Current Evidence

- README is comprehensive but very large.
- The status document contains implementation notes, validation history, known
  limits, deferred work, and next steps in one file.
- Release packaging is tested and current release output is ignored by Git.

### Problem

Large docs are useful while moving quickly, but users and maintainers need
separate surfaces: install/usage, developer architecture, validation history,
rules authoring, and release process. Mixing all of these into README/status
increases drift.

### Plan

1. Keep README as the user-facing entrypoint.
2. Split detailed docs into `docs/`:
   - `docs/architecture.md`
   - `docs/rules.md`
   - `docs/validation.md`
   - `docs/release.md`
   - `docs/ida-free.md`
   - `docs/batch.md`
3. Keep `pseudoforge_implementation_status.md` as a current status ledger, but
   move historical validation tables into `docs/validation-history/`.
4. Add a release checklist:
   - version parity
   - unit tests
   - compileall
   - JSON validation
   - rules validation
   - CLI smoke
   - IDA Free smoke
   - `git diff --check`
5. Link this improvement plan from README after it stabilizes.

### Acceptance Criteria

- README stays shorter and easier to scan.
- Historical validation evidence remains available.
- Release commands are not duplicated inconsistently across docs.

## Suggested Execution Order

1. Add rename identity metadata and preflight hardening.
2. Add snapshot testing infrastructure before renderer extraction.
3. Extract renderer modules one family at a time.
4. Add export parity shared writer.
5. Split generated kernel profile and add manifest-aware loader.
6. Add deterministic rules v2 `call_arg_rewrite`.
7. Expand `RuleContext` facts and then add guarded `text_rewrite`.
8. Improve switch reports before attempting deeper body reconstruction.
9. Split `test_core_engine.py` after behavior is stabilized.
10. Add dockable preview and non-blocking model discovery.

## Current Validation Baseline To Preserve

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
python -B .\tools\build_kernel_api_profile.py --version 10.0.26100.0 --dry-run --summary --function ExAllocatePool2 --function ExAcquireResourceExclusiveLite
python -B .\tools\build_status_codes_profile.py --version 10.0.26100.0 --dry-run --summary
python -B .\tools\pseudoforge_cli.py --version
python -B .\tools\release_pseudoforge.py --dry-run
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_smoke
python -B .\tools\pseudoforge_free_cli.py --version
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_smoke
git diff --check -- .
```
