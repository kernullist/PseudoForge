# PseudoForge

PseudoForge is an IDA Pro / Hex-Rays plugin that turns noisy pseudocode into reviewable, kernel-aware cleanup artifacts.

The core direction is deterministic-first. PseudoForge does not let an LLM rewrite arbitrary code. It builds a validated `CleanPlan` from deterministic analysis, optional data-only rules, and optional LLM rename suggestions, then writes preview/export artifacts that can be compared against the original pseudocode. IDB writes remain limited to user-selected, validator-gated local and argument renames.

All repository documentation is written in English. Generated comments, logs, rule text, and examples should also stay ASCII-only unless a file has an explicit reason to use another character set.

## Preview

The left side is raw Hex-Rays pseudocode. The right side is the PseudoForge preview.

Animated demo of the interactive IDA preview workflow:

![PseudoForge interactive IDA preview demo](screenshots/PseudoForge-demo.gif)

Static preview examples:

![PseudoForge preview comparing raw Hex-Rays pseudocode with kernel-aware cleaned output](screenshots/example.png)

The second preview shows no-symbol OB callback cleanup with inferred `LIST_ENTRY` record types and `CONTAINING_RECORD`-based traversal.

![PseudoForge preview of no-symbol OB callback cleanup with inferred LIST_ENTRY records](screenshots/example2.png)

The third preview shows the `PfKernelPattern` IOCTL handler cleanup, including IRP dispatch naming, `IO_STACK_LOCATION.Parameters.DeviceIoControl` field rendering, `SystemBuffer` union alias cleanup, NTSTATUS names, and decoded `CTL_CODE(...)` case comments.

![PseudoForge preview of PfKernelPattern IOCTL handler cleanup with decoded CTL_CODE comments](screenshots/example3.png)

## Decompiler Output Dependency

PseudoForge works on Hex-Rays pseudocode output. Its cleanup quality depends heavily on the quality of the initial decompilation.

Better Hex-Rays output usually produces better PseudoForge output. Type information, function prototypes, structure recovery, imported kernel symbols, PDB/type library availability, and correct calling conventions all improve deterministic matching and reduce noisy casts.

PseudoForge does not recover semantics that are completely absent from the decompiler output, and it does not treat LLM suggestions as authoritative rewrites. LLM assist remains optional and must pass deterministic validation. Preview/export artifacts are the primary output; IDB writes remain limited to explicitly selected, validator-gated rename operations.

For best results:

- Let IDA finish analysis before previewing or exporting PseudoForge output.
- Load relevant PDBs, type libraries, WDK headers, and kernel type information when available.
- Fix obviously wrong function prototypes and calling conventions before cleanup.
- Prefer symbol and type recovery over text-only cleanup.
- Review inferred structure rewrites, especially when fixed offsets are converted into semantic fields.

## Quick Start

1. Use IDA Pro 9.x or newer with Hex-Rays for the interactive plugin path.
2. Copy `pseudoforge.py`, `ida-plugin.json`, and `ida_pseudoforge/` into the IDA user plugin directory.
3. Open a pseudocode view and run `Edit/PseudoForge/Analyze current function`.
4. Review the generated `<input>.forge` section or export bundle before applying any IDB rename.
5. For offline smoke testing, run:

```powershell
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_smoke
```

Key documentation:

- [pseudoforge_implementation_status.md](pseudoforge_implementation_status.md): current implemented scope and validation history.
- [pseudoforge_improvement_plan.md](pseudoforge_improvement_plan.md): prioritized improvement backlog from the current code and documentation review.
- [ida_pseudocode_refactor_plugin_design.md](ida_pseudocode_refactor_plugin_design.md): overall product and architecture design.
- [deterministic_rules_matching_engine_design.md](deterministic_rules_matching_engine_design.md): deterministic JSON rule engine design.
- [samples/kernel_pattern_driver/README.md](samples/kernel_pattern_driver/README.md): WDK sample corpus for kernel-pattern analysis.

## Versioning

Current plugin version: `0.1.0`.

The runtime version source is `ida_pseudoforge/version.py`. The `ida-plugin.json` manifest version must match it; the unit suite enforces this parity so plugin packaging and runtime reporting do not drift.

Ways to check the installed/current version:

```powershell
python -B .\tools\pseudoforge_cli.py --version
python -B .\tools\pseudoforge_free_cli.py --version
```

Inside IDA, run `Edit/PseudoForge/Show settings`. Preview/export headers, switch outlines, aggregate `.forge` sections, and IDA Free CLI JSON reports also include the version.

Release packaging bumps the patch version by default, updates `ida_pseudoforge/version.py`, `ida-plugin.json`, and the current-version lines in the docs, then writes an installable zip named with the new version:

```powershell
python -B .\tools\release_pseudoforge.py
```

The default archive path is:

```text
release\PseudoForge-<new-version>.zip
```

Useful release options:

```powershell
python -B .\tools\release_pseudoforge.py --dry-run
python -B .\tools\release_pseudoforge.py --bump minor
python -B .\tools\release_pseudoforge.py --version 0.2.0
python -B .\tools\release_pseudoforge.py --no-version-bump
```

## Current Implementation Status

The current implementation is an MVP+ slice. The core engine, offline CLI, deterministic rules engine, headless IDA batch path, and interactive IDA plugin load/capture/export/action workflow have been validated.

Implemented:

1. Current-function Hex-Rays pseudocode capture.
2. Parameter and local rename plan generation from prototypes and usage patterns.
3. Rename validation for collisions, reserved words, invalid identifiers, and weak speculative names.
4. Dispatcher case recovery from `vX = dispatcher - constant` chains.
   - Chained delta temporaries can be rendered as profile-backed enum comparisons.
   - Stale delta temporaries reused after large branch bodies are kept unchanged.
5. Native top-level `switch(dispatcher)` case and single-return body extraction.
6. Nested switch depth tracking so inner cases are not mixed into the top-level dispatcher.
7. Cleanup label classification.
8. Kernel driver semantics pass.
   - NTSTATUS literal normalization in returns and status assignments.
   - Profile-backed `0xC???????` NTSTATUS error literals in 4-byte local assignments and `_DWORD` stores.
   - Deterministic LIST_ENTRY record/link/tail naming that outranks generic LLM suggestions.
   - LIST_ENTRY unlink/insert-tail pattern hints.
   - ERESOURCE, critical region, pool allocation, object reference, and failfast insights.
   - Pool tag decoding such as `0x54465241` to `ARFT`.
9. Profile-backed NTSTATUS, `SYSTEM_INFORMATION_CLASS`, and `PROCESSINFOCLASS` names.
   - 25H2-range `SYSTEM_INFORMATION_CLASS` and `PROCESSINFOCLASS` profile coverage.
   - Preview-only canonical prototypes for `NtSetSystemInformation` and `NtSetInformationProcess`.
10. Recovered dispatcher output as an auxiliary switch-case outline appended after normalized original pseudocode.
11. Generated pseudocode style normalization.
   - Opening braces on the next line.
   - Mandatory braces for `if`, `else`, `for`, and `while`.
   - Standalone `else`.
   - Guard flattening after terminating branches.
   - No forced `do { } while (false)` conversion.
12. Cleaned pseudocode preview in an IDA native custom viewer.
13. Aggregate `<input>.forge` analysis file beside the analyzed binary.
14. Export bundle for cleaned pseudocode, switch outline, rename map, flow report, and rule report.
15. Action for applying selected local and argument renames to the IDB.
16. IDA Output progress logging with file-backed trace logs.
17. Offline CLI smoke path that does not require IDA.
18. Multi-provider optional LLM rename assist inside IDA.
19. Optional offline CLI LLM rename assist.
20. Synchronized warning counts between `.forge` metadata and preview headers.
21. Stable `.forge` path/string escaping and current-function section preview.
22. Headless IDA batch analysis over `.i64` / `.idb` functions.
23. WDK-based kernel driver test corpus under `samples/kernel_pattern_driver`.
24. Deterministic rules matching engine v1.
   - Data-only JSON rule pack loader.
   - Builtin, project-local, and user-global rule directories.
   - Regex and assignment-based rename rules.
   - Semantic comment rules.
   - Fail-closed validator CLI.
   - Per-function rule report export.
25. Deterministic rules matching engine v2 preview/report phases.
   - Preview-only `call_arg_rewrite` reports.
   - Preview-only `text_rewrite` reports with semantic comment gates and span
     conflict detection.
26. IDA analysis completion summaries include deterministic rule diagnostic
    counts.
27. Export summaries and IDA Free result summaries include deterministic rule
    diagnostic counts plus rule load and validation error details.
28. IDA LLM model discovery uses a non-blocking background refresh cache so
    configuration dialogs can open with static or cached model lists.

Still pending:

1. Full switch body reconstruction for shared and fallthrough branches.
2. Manual IDA validation and true object-level ctree rename application beyond the current identity preflight gates.
3. Richer dockable side-by-side preview panel.
4. Deterministic rule phase expansion for `flow` and broader parity migration.
5. Wider profile coverage from real target builds.

Detailed implementation tracking lives in [pseudoforge_implementation_status.md](pseudoforge_implementation_status.md).

## Requirements

Core plugin:

- Windows
- IDA Pro 9.x or newer
- Hex-Rays decompiler
- IDA-bundled Python 3
- No external Python packages for core operation

IDA Pro 7.6 or newer may be able to run PseudoForge, but that compatibility path has not been verified yet. Treat IDA 9.x as the supported requirement until older versions are tested directly.

Offline CLI:

- Validated with Python 3.11
- Standard library only

IDA Free:

- Not supported as an interactive PseudoForge plugin target.
- IDA Free does not provide the IDAPython and local Hex-Rays APIs required by the plugin actions.
- Supported only through the offline CLI workflow where copied or saved cloud-decompiled pseudocode text is processed outside IDA.
- The IDA Free CLI path does not modify an IDB and does not apply renames back into IDA.

Optional LLM rename assist:

- OpenAI-compatible `/chat/completions` endpoint
- OpenRouter `/chat/completions` endpoint
- DeepSeek OpenAI-compatible endpoint
- ChatGPT OAuth via Codex CLI, Codex CLI, Claude login via Claude CLI, or Claude CLI command bridge
- IDA configuration through `Configure LLM rename assist`
- Environment variables or command-line options for offline CLI
- Not required for deterministic analysis

## File Layout

```text
pseudoforge.py
ida-plugin.json
ida_pseudoforge/
  version.py
  config.py
  core/
    capture.py
    deterministic/
      context.py
      emitters.py
      engine.py
      loader.py
      schema.py
      validators.py
      matchers/
        regex.py
    forge_store.py
    kernel_api.py
    kernel_rewrites.py
    normalize.py
    kernel_semantics.py
    lvar_analysis.py
    flow_recovery.py
    cleanup_rewriter.py
    offline_input.py
    pattern_renames.py
    llm_assist.py
    rule_diagnostics.py
    validation.py
    render.py
    render_callbacks.py
    render_call_args.py
    render_dispatcher.py
    render_driver_entry.py
    render_flow.py
    render_header.py
    render_ioctl.py
    render_kernel_hints.py
    render_labels.py
    render_literals.py
    render_ntset.py
    render_signatures.py
    render_status.py
    render_style.py
    render_warnings.py
    render_zw.py
    plan_schema.py
    api_semantics.py
  profiles/
    loader.py
    profiles_manifest.json
    kernel_api.json
    kernel_api_overrides.json
    status_codes.json
    process_information_class.json
    system_information_class.json
  rules/
    builtin/
      kernel_comments.json
      local_renames.json
  models/
    base.py
    cli_provider.py
    model_discovery.py
    openai_compatible.py
    prompting.py
    provider_factory.py
    provider_registry.py
    subprocess_utils.py
  logging.py
  ida/
    action_registry.py
    analysis_state.py
    async_runner.py
    plugin.py
    actions.py
    decompiler.py
    llm_config_dialog.py
    apply_changes.py
    ui_preview.py
    thread_helpers.py
tools/
  build_kernel_api_profile.py
  build_status_codes_profile.py
  empty_llm_rename_provider.py
  pseudoforge_cli.py
  pseudoforge_free_console.py
  pseudoforge_free_cli.py
  pseudoforge_ida_batch.py
  release_pseudoforge.py
  run_pseudoforge_ida_batch.ps1
  summarize_pseudoforge_ida_batch.py
  validate_pseudoforge_rules.py
samples/
  pseudocode/
    NtSetSystemInformation_switch_renamed.cpp
  kernel_pattern_driver/
tests/
  test_export_bundle.py
  test_ida_plugin_safety.py
  test_kernel_api_profile_builder.py
  test_llm_cli_provider.py
  test_plan_builder.py
  test_profile_loader.py
  test_pseudoforge_free_cli.py
  test_render_callbacks.py
  test_render_call_args.py
  test_render_dispatcher.py
  test_render_driver_entry.py
  test_render_flow.py
  test_render_header.py
  test_render_ioctl.py
  test_render_kernel_hints.py
  test_render_labels.py
  test_render_literals.py
  test_render_ntset.py
  test_render_snapshots.py
  test_render_signatures.py
  test_render_style.py
  test_render_warnings.py
  test_render_zw.py
  test_release_pseudoforge.py
```

## Installation

Copy the plugin entrypoint, plugin manifest, and package directory into the IDA user plugin directory:

```text
pseudoforge.py
ida-plugin.json
ida_pseudoforge/
```

The common Windows user plugin directory is:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins
```

PowerShell copy example:

```powershell
$pluginDir = Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"
New-Item -ItemType Directory -Force $pluginDir | Out-Null

Copy-Item .\pseudoforge.py -Destination $pluginDir -Force
Copy-Item .\ida-plugin.json -Destination $pluginDir -Force
Copy-Item .\ida_pseudoforge -Destination $pluginDir -Recurse -Force
```

To confirm the IDA user directory, run this in the IDA Python console:

```python
import ida_diskio
print(ida_diskio.get_user_idadir())
```

During development, a symlink or junction install is usually faster:

```powershell
$pluginDir = Join-Path $env:APPDATA "Hex-Rays\IDA Pro\plugins"
New-Item -ItemType Directory -Force $pluginDir | Out-Null

New-Item -ItemType SymbolicLink -Path (Join-Path $pluginDir "pseudoforge.py") -Target (Resolve-Path .\pseudoforge.py) -Force
New-Item -ItemType SymbolicLink -Path (Join-Path $pluginDir "ida-plugin.json") -Target (Resolve-Path .\ida-plugin.json) -Force
New-Item -ItemType Junction -Path (Join-Path $pluginDir "ida_pseudoforge") -Target (Resolve-Path .\ida_pseudoforge) -Force
```

If symlink creation is blocked by Windows policy, use the copy method.

## IDA Usage

1. Restart IDA.
2. Open the target binary.
3. Open the Hex-Rays pseudocode view.
4. Confirm that `Edit/PseudoForge` is visible.
5. Run an action on the target function.

Menu:

```text
Edit/PseudoForge/
  Analyze current function
  Show current analysis result
  Analyzed functions...
  Export cleaned pseudocode
  Configure LLM rename assist
  Show settings
  Advanced/
    Apply selected renames to IDB
```

Pseudocode view context menu:

```text
PseudoForge/
  Analyze current function
  Show current analysis result
  Analyzed functions...
  Export cleaned pseudocode
  Configure LLM rename assist
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

### Actions

`Analyze current function` decompiles the current function, builds the rename plan, flow outline, cleanup classification, deterministic rule report, and warnings, then updates the function section in `<input>.forge`. It does not modify the IDB.

`Show current analysis result` opens only the cached `.forge` section whose function start EA matches the current pseudocode cursor. It does not decompile, invoke an LLM, run analysis, or refresh the `.forge` file. If the current function has not been analyzed yet, it asks the user to run `Analyze current function` first. `Copy all` and `Save as...` operate on that selected section.

`Analyzed functions...` opens a chooser built from cached `.forge` function-section markers. It avoids opening the full aggregate `.forge` as the primary UI, which keeps navigation usable after many functions have been analyzed.

`Export cleaned pseudocode` analyzes the current function and writes a review/audit bundle. Its main purpose is to freeze a PseudoForge result outside the IDA UI so the cleaned pseudocode, rename plan, flow report, and rule report can be shared, diffed, regression-tested, and inspected later. It writes to `pseudoforge_out` beside the IDB when possible and does not modify the IDB.

`Advanced/Apply selected renames to IDB` analyzes the function if needed, shows a rename chooser, refuses stale sessions when the current function changed, and applies only user-selected local or argument renames that pass final preflight through `ida_hexrays.rename_lvar()`. This path is intentionally separate from preview/export.

`Configure LLM rename assist` stores optional LLM settings in `<IDA user directory>\pseudoforge_config.json`. HTTP provider API keys are stored per provider under `credentials` and are prompted only when an enabled provider needs a missing key.

`Show settings` displays the current plugin version, config path, and LLM status. API keys are masked.

### Preview Behavior

- The preview first shows normalized original pseudocode.
- Functions with recovered dispatcher information append an auxiliary switch-case outline.
- The auxiliary outline summarizes nested if/else dispatcher chains as switch cases.
- Only single-statement returns and complete local branch slices are expanded in the outline.
- Complex shared or fallthrough bodies point back to the normalized original pseudocode instead of emitting misleading fragments.
- Native switches already present in the normalized original pseudocode are not duplicated in the auxiliary outline.
- Viewer lines use IDA color tag syntax highlighting where practical; large previews automatically fall back to plain text.
- `.forge`, `Copy all`, and `Save as...` output remain plain text without color tags.
- Set `PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT=1` before launching IDA to isolate syntax-highlight issues.
- Right-click in the preview for `PseudoForge/Copy all`, `PseudoForge/Save as...`, and `PseudoForge/Analyzed functions...`.
- `PseudoForge/Analyzed functions...` and the top-level `Analyzed functions...` action parse `.forge` markers and open a chooser of all analyzed sections.
- Function-section `Save as...` defaults to `PseudoForge__<target>__<function>_0x<EA>.cpp`.
- `Copy all` uses the Windows Clipboard API with `CF_UNICODETEXT`; it does not shell out or rely on a Qt clipboard.
- Clipboard status is written to `%TEMP%\pseudoforge_clipboard\copy_all.log`.

### Kernel Driver Cleanup

- Casted NTSTATUS returns such as `return (unsigned int)-1073741727;` can render as `STATUS_PRIVILEGE_NOT_HELD`.
- Status accumulator assignments such as `status = 0x40000000;` can render as `STATUS_OBJECT_NAME_EXISTS`.
- Profile-backed `0xC???????` NTSTATUS error literals in 4-byte local assignments and `_DWORD` stores render symbolically, for example `v16 = STATUS_INSUFFICIENT_RESOURCES;`.
- Wider stores keep the raw literal unless there is stronger type evidence.
- `status_codes.json` is generated from WDK `ntstatus.h`; low wait/success aliases are excluded by default except `STATUS_SUCCESS` and `STATUS_PENDING`.
- Direct `return 0` becomes `STATUS_SUCCESS` only under strong NTSTATUS return evidence such as an explicit `NTSTATUS` prototype, a known signature override, or an `Nt*` / `Zw*` native API name.
- LLM-only `status` renames do not make `status = 0` become `STATUS_SUCCESS`; success assignments require strong NTSTATUS context or a deterministic kernel-status accumulator.
- LIST_ENTRY walks, unlink, and insert-tail patterns can produce role-centered names such as `providerRecord`, `providerLink`, `nextLink`, `previousLink`, and `tailLink`.
- Deterministic kernel names outrank generic LLM suggestions.
- LLM local and argument renames prefer lowerCamel names. PascalCase LLM names are skipped because they can look like authoritative types or fields.
- DriverEntry-style setup can recover lowerCamel `driverObject`, `registryPath`, `status`, `extension`, `deviceObject`, `deviceName`, and `majorIndex` names without relying on LLM suggestions.
- Strong DriverEntry evidence can render the preview signature as `NTSTATUS __fastcall DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)` while keeping IDB writes preview-only.
- Driver dispatch table initialization can render `IRP_MJ_MAXIMUM_FUNCTION`, `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, and `IRP_MJ_DEVICE_CONTROL`.
- Driver device flags can render `DO_BUFFERED_IO` and `DO_DEVICE_INITIALIZING`, and `IoCreateDevice` device characteristics can render `FILE_DEVICE_SECURE_OPEN`.
- Unknown or vendor `DEVICE_TYPE` values, for example `0x8337u`, stay as literals unless a trusted binary/profile source proves a standard `FILE_DEVICE_*` name. PseudoForge does not infer original source macro names.
- IOCTL dispatcher case constants can be annotated with exact `CTL_CODE(DeviceType, Function, Method, Access)` bitfield decoding, including `METHOD_BUFFERED`, while preserving Hex-Rays integer suffixes and without inventing original `IOCTL_*` macro names.
- IRP dispatch handlers can render preview signatures as `NTSTATUS __fastcall Name(PDEVICE_OBJECT deviceObject, PIRP irp)` once IRP completion or `IoStatus` evidence identifies the handler.
- No-PDB dispatch handlers can still recover `deviceObject` and `irp` when the second parameter is completed through `IofCompleteRequest(...)`, including casted forms such as `(IRP *)a2`.
- `IO_STACK_LOCATION` index rewrites are union-arm gated. `Parameters.DeviceIoControl.*` is emitted only when IRP dispatch evidence and DeviceControl `IoControlCode` stack-index evidence are present; other IRP major-function paths keep raw indexing until their own union arm is identified.
- IRP dispatch body cleanup can render `deviceObject->DeviceExtension`, `NTSTATUS status`, and `return status;` without requiring DeviceControl-specific evidence.
- METHOD_BUFFERED-only DeviceControl dispatchers can render the `AssociatedIrp.MasterIrp` union alias as `AssociatedIrp.SystemBuffer` with a `PVOID` local type, but only when `IoControlCode` is proven to come from the DeviceControl stack location. Mixed methods, METHOD_NEITHER cases, or IOCTL-like switches without stack evidence keep the original union alias.
- LLM-proposed names such as `ioControlCode` or `ioStackLocation` do not force a DeviceControl union arm when the function is not an IRP dispatch path.
- Device-control dispatchers can recover `deviceObject`, `irp`, `ioStackLocation`, `ioControlCode`, `outputBufferLength`, and `inputBufferLength` from usage. The stack-location variable does not need to already be named `ioStackLocation`.
- IRP completion tails that set `IoStatus`, call `IofCompleteRequest`, and return status can be labeled as `CompleteIrp` instead of staying as unknown labels.
- Device-control display warnings suppress resolved buffered/SystemBuffer and dispatch-signature cautions once deterministic IOCTL and IRP evidence has already proved the rewrite.
- DriverEntry device-extension offset usage can produce a preview-only `INFERRED_DRIVER_DEVICE_EXTENSION` and field access for common initialization, cleanup, work-item, registry-path, lookaside, timer, DPC, rundown, and resource fields.
- Inferred device-extension structs do not authorize reconstructing original `sizeof(...)` source expressions. Allocation and whole-extension zeroing sizes remain as Hex-Rays literals unless there is direct evidence.
- DriverEntry display warnings suppress routine LLM sub-function rename guesses and redundant `DeviceExtension` wording once deterministic DriverEntry/device-extension evidence has been recovered.
- Function pointers resolved through `MmGetSystemRoutineAddress` can use WDK profile metadata when the routine string or function-pointer variable name matches a profiled API and the call arity matches. The preview keeps the indirect call form and adds a `resolved indirect call` comment instead of rewriting it into a direct import-style call.
- Callback registration toggles that combine process, image, thread, and object callbacks can recover `deviceExtension`, `enable`, callback status locals, `OB_FLT_REGISTRATION_VERSION`, and `OB_OPERATION_REGISTRATION` field assignments from Hex-Rays `_QWORD[4]` stack arrays.
- Configuration Manager registry callback probes can recover `callbackContext`, `majorVersion`, `minorVersion`, `callbackCookie`, `altitudeString`, `registerExStatus`, and `registerStatus`, while rendering successful `CmRegisterCallback(Ex)` checks with `NT_SUCCESS(...)`.
- Memory Manager probe functions that combine `MmGetSystemRoutineAddress`, `MmCopyMemory`, MDL setup, noncached memory, and contiguous memory allocation can recover routine-name, buffer, MDL, byte-count, and physical-address locals. `MmCopyMemory` flags render as `MM_COPY_MEMORY_PHYSICAL` or `MM_COPY_MEMORY_VIRTUAL`.
- Zw API corpus/probe functions that exercise object, registry, token, and file calls can recover handle, status, object-attribute, timeout, IO-status, value-name, and shared info-buffer roles. Preview rendering keeps the calls intact while normalizing `OBJECT_ATTRIBUTES` size, `OBJ_*` flags, `NtCurrentProcess()`, `NtCurrentThread()`, and successful status checks.
- Confident record layout evidence can simplify offset arithmetic into preview-only `CONTAINING_RECORD(...)` forms.
- Known OB pre-operation callbacks simplify raw offset loads such as `*(_DWORD *)(*(_QWORD *)(preOperationInfo + 32) + 4LL)` and typed-array offset loads such as `*(_DWORD *)(*((_QWORD *)preOperationInfo + 4) + 4LL)` into typed `preOperationInfo->Parameters->...OriginalDesiredAccess` access.
- No-symbol OB pre-operation callbacks with a suspicious `POB_PRE_OPERATION_CALLBACK` second parameter can be normalized to `POB_PRE_OPERATION_INFORMATION preOperationInfo` when field-use evidence matches the callback information layout.
- OB pre-operation private LIST_ENTRY records and event records can receive preview-only inferred record types when allocation size, list walk shape, and field-write evidence all match. Confirmed record loops are rendered with a separate `LIST_ENTRY *` iterator and `CONTAINING_RECORD(...)`.
- Identified LIST_ENTRY heads can become aliases such as `providerListHead = (LIST_ENTRY *)&ExpFirmwareTableProviderListHead`.
- Verified neighboring-link checks can render as `RemoveEntryList(providerLink)` and `InsertTailList(providerListHead, newProviderLink)`.
- Self-linked LIST_ENTRY initialization can render as `InitializeListHead(newProviderLink)`.
- Suspicious call targets are preserved with warning comments; uncertain targets are not replaced with different API names.
- Semantic labels such as `CorruptListEntry`, `InvalidParameter`, and `Cleanup` are column-zero labels.
- Duplicate semantic labels receive stable suffixes such as `InvalidParameter_17`.
- Safe tail-label hoisting separates error/failfast paths from normal cleanup returns.
- `Flow rewrites` counts dispatcher/switch recovery only. Kernel semantic substitutions are counted under `Kernel semantic rewrites`.
- Recovered switch outlines and flow reports include per-case body states,
  source line anchors, and shared-tail labels. Complete local branch slices can
  be expanded when they end in a local return; shared, partial, or complex
  bodies stay in the normalized original pseudocode.
- TraceLogging and C++ template wrapper functions are not promoted to recovered switch outlines.
- Kernel rewrite patterns belong in `core/kernel_rewrites.py`, either in `KernelRewriteRule` entries or narrow helper passes. Avoid adding individual kernel patterns directly to `render.py`.
- Kernel rewrite rules should be gated by `Kernel insights` comment kind and confidence where applicable.
- WDK-backed API parameter metadata can render calls like `ExAllocatePool2(0x100uLL, 0x28uLL, 0x54465241u)` as `ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, POOL_TAG('A', 'R', 'F', 'T'))`.
- Scalar `BOOLEAN` arguments can render as `TRUE` or `FALSE`.

## Kernel Pattern Driver Sample

`samples/kernel_pattern_driver` contains a WDM driver corpus for PseudoForge analysis regression testing. It follows the shape of the Microsoft `Windows-driver-samples` WDM IOCTL sample while concentrating common kernel driver call combinations into one binary.

Included patterns:

- `DriverEntry`, `DriverUnload`, `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, and `IRP_MJ_DEVICE_CONTROL`
- `IoCreateDevice`, `IoCreateSymbolicLink`, and `METHOD_BUFFERED` IOCTL validation
- `ExAllocatePool2`, `ExFreePoolWithTag`, and `NPAGED_LOOKASIDE_LIST`
- `LIST_ENTRY` event retention and variable output with `FIELD_OFFSET`
- `FAST_MUTEX`, `ERESOURCE`, and critical-region pairing
- `PsLookupProcessByProcessId` and `ObDereferenceObject`
- `KTIMER`, `KDPC`, and `IoQueueWorkItem`
- Optional process, image, and thread callback registration
- Optional `ObRegisterCallbacks` process object callback registration
- LIST_ENTRY-backed process whitelist/blacklist traversal with `CONTAINING_RECORD`
- A single-function object pre-operation callback path in `PfkpObjectPreOperation`, including requested-access checks and requester whitelist auto-add behavior

Build:

```powershell
.\samples\kernel_pattern_driver\tools\build.ps1 -Configuration Release
```

Output:

```text
samples\kernel_pattern_driver\x64\Release\PfKernelPattern.sys
samples\kernel_pattern_driver\x64\Release\PfKernelPatternTool.exe
```

## WDK Kernel API Profile

PseudoForge reads `ida_pseudoforge/profiles/kernel_api.json` by default for WDK API prototypes and selected argument semantics. Runtime lookup paths can also use split family files when they are present, such as `kernel_functions.json`, `kernel_enums.json`, `kernel_indices.json`, and `kernel_symbol_index.json`, before falling back to the monolithic profile. `kernel_api_overrides.json` adds private wrapper aliases and deterministic argument semantics that do not exist directly in WDK headers.

Regenerate the profile from WDK headers:

```powershell
python -B .\tools\build_kernel_api_profile.py --list-versions
python -B .\tools\build_kernel_api_profile.py --version 10.0.26100.0
python -B .\tools\build_kernel_api_profile.py --version 10.0.26100.0 --split-output-dir .\ida_pseudoforge\profiles
```

Inspect selected functions without writing a profile:

```powershell
python -B .\tools\build_kernel_api_profile.py --version 10.0.26100.0 --header wdm.h --dry-run --function ExAllocatePool2 --function ExFreePoolWithTag
```

Options:

- `--wdk-include-root`: defaults to `C:\Program Files (x86)\Windows Kits\10\Include`.
- `--version`: WDK include version; omitted means the newest installed `km` include directory.
- `--header`: header name to parse; may be repeated.
- `--directory`: WDK include subdirectory; defaults to `km` and `shared`.
- `--all-km-headers`: parse only `km\*.h` for the selected WDK version.
- `--out`: output profile path; defaults to `ida_pseudoforge/profiles/kernel_api.json`.
- `--split-output-dir`: also write split family profiles such as `kernel_functions.json`, `kernel_enums.json`, `kernel_indices.json`, and `kernel_symbol_index.json`.
- `--split-only`: with `--split-output-dir`, skip writing the monolithic `--out` profile.
- `--function`: function name to extract; may be repeated.
- `--known-only`: generate only functions with PseudoForge semantic overlays.
- `--summary`: print function/enum count summary.
- `--verbose-summary`: include function names in the summary.
- `--dry-run`: print JSON to stdout instead of writing a file.

`profiles_manifest.json` records source version, profile kind, entry counts,
and SHA-256 metadata for the built-in profile files. Export summaries include
the active profile root, loaded profile names, and manifest entries for profiles
touched during a run.

Smoke-check the split-profile load path without forcing a brittle timing gate:

```powershell
python -B .\tools\profile_load_smoke.py --family functions --repeat 100 --json
```

The smoke command measures cold-load and repeated cached lookup time. It fails
if profile warnings are emitted, no entries load, or a split family file exists
but `kernel_api.json` is loaded instead. Optional `--max-cold-ms` and
`--max-repeated-ms` thresholds can be used for local performance tracking.

Alternate target-build profile sets can be selected with
`PSEUDOFORGE_PROFILE_DIR`, the `--profile-dir` option on Python tools, or
`-ProfileDir` on `tools/run_pseudoforge_ida_batch.ps1`. Inside IDA, use
`Edit/PseudoForge/Configure profile directory` to persist an interactive
profile root selection. The default remains the built-in profile directory.

The built-in profile is currently generated from WDK `10.0.26100.0` and includes:

- 470 headers
- 3501 function prototypes
- 1760 enums
- 8354 structures
- 19865 typedef aliases
- 58251 macros
- 93592 symbol index entries
- Semantic overlays for `POOL_FLAGS`, `BOOLEAN`, pool tag parameters, and selected resource/list/pool APIs
- Override aliases such as `Obp -> Ob`, `Psp -> Ps`, `Iop -> Io`, `Mmp -> Mm`, and `Sep -> Se`
- Derived argument semantics for exact `Tag` arguments in pool and `WithTag` APIs

The profile includes a `symbols` index for name-based lookup. Names such as `NdisRegisterProtocolDriver`, `FltRegisterFilter`, `PDEVICE_OBJECT`, and `POOL_FLAG_PAGED` can be found as functions, aliases, macros, or enum members. Private wrapper aliases are exposed as `function_alias` entries, so a call such as `ObpReferenceObjectByHandleWithTag` can use the public `ObReferenceObjectByHandleWithTag` prototype metadata while preserving the original call spelling.

## `.forge` Analysis Files

PseudoForge stores analyzed cleaned pseudocode beside the target binary.

Example:

```text
C:\work\a.exe
C:\work\a.forge
```

Rules:

- The filename keeps the input stem and changes only the extension to `.forge`.
- If IDA cannot provide the input file path, the IDB path is used as a fallback.
- One `.forge` file can contain multiple functions.
- Each function section is wrapped with `// PSEUDOFORGE FUNCTION BEGIN ea=...` and `END` markers.
- Re-analyzing the same EA replaces only that function section.
- Other function sections are preserved.
- `Show current analysis result` shows only the matching function section.
- `Analyzed functions...` lists all cached `.forge` sections without opening the full aggregate file first.
- The preview context-menu action `PseudoForge/Analyzed functions...` provides the same chooser from inside a preview window.
- Run `Analyze current function` to refresh the current function section.

## LLM Configuration Inside IDA

LLM rename assist can be configured without a separate CLI.

1. Run `Edit/PseudoForge/Configure LLM rename assist`.
2. Choose `Yes` for `Enable PseudoForge LLM rename assist?`.
3. Select a provider in the read-only provider combo box.
4. Enter the base URL for HTTP providers.
5. Enter an API key only if the selected HTTP provider has no stored key.
6. Select a model in the provider-specific read-only model combo box.
7. Enter a command template for CLI providers.
8. Set the timeout in seconds.
9. Subsequent `Analyze current function`, `Export cleaned pseudocode`, and `Apply selected renames` actions use LLM rename assist when it is enabled.

API key policy:

- `openai_compatible`, `openrouter`, and `deepseek_api` require API keys.
- API keys are stored under provider-specific `credentials`, not under `llm`.
- Existing provider keys are reused when changing models.
- To replace a key, edit or delete the provider credential in `pseudoforge_config.json`, then run the configuration action again.

Supported provider IDs:

```text
openai_compatible
openrouter
chatgpt_oauth_via_codex_cli
codex_cli
claude_login_via_claude_cli
claude_cli
deepseek_api
```

Default provider settings:

| Provider | Default model | Default endpoint or command |
| --- | --- | --- |
| `openai_compatible` | `gpt-5-mini` | `https://api.openai.com/v1` |
| `openrouter` | `openrouter/auto` | `https://openrouter.ai/api/v1` |
| `chatgpt_oauth_via_codex_cli` | `gpt-5-mini` | `codex exec -m {model} --skip-git-repo-check --sandbox read-only --output-last-message {output_file} -` |
| `codex_cli` | `gpt-5-mini` | `codex exec -m {model} --skip-git-repo-check --sandbox read-only --output-last-message {output_file} -` |
| `claude_login_via_claude_cli` | `claude-sonnet-4-6` | `claude -p --model {model} --permission-mode dontAsk --output-format text --no-session-persistence --tools ""` |
| `claude_cli` | `claude-sonnet-4-6` | `claude -p --model {model} --permission-mode dontAsk --output-format text --no-session-persistence --tools ""` |
| `deepseek_api` | `deepseek-v4-flash` | `https://api.deepseek.com` |

The default timeout is 60 seconds.

Model discovery:

- IDA configuration uses a non-blocking model discovery cache. If no live model
  catalog is cached yet, the dialog opens with provider static models while a
  background refresh updates the cache for the next configuration run.
- `chatgpt_oauth_via_codex_cli` and `codex_cli` read the Codex model catalog through `codex debug models` using argv-based subprocess execution, not a shell command string.
- If `codex debug models` fails, `%USERPROFILE%\.codex\models_cache.json` is used.
- Claude CLI providers use provider-specific static model lists. This is the expected path because Claude CLI does not expose a model catalog command. The static list starts with the current Claude API/Claude Code model IDs and aliases: `claude-opus-4-8`, `claude-sonnet-4-6`, and `claude-haiku-4-5`.
- HTTP providers query the selected base URL's `/models` endpoint.
- If an enabled HTTP provider has no stored key, the key prompt appears before model discovery.
- Discovery failures fall back to provider-specific static model lists.
- A custom model stored in `pseudoforge_config.json` is temporarily added to the combo box on the next configuration run so the current setting is not lost.

`chatgpt_oauth_via_codex_cli` lets IDA call Codex CLI with the ChatGPT OAuth session saved by `codex login`. `claude_login_via_claude_cli` lets IDA call Claude CLI with the Anthropic account session saved by `claude auth login`. PseudoForge does not implement in-IDA browser login. `codex_cli` and `claude_cli` remain generic local CLI bridges with editable command templates.

CLI command template placeholders:

```text
{prompt_file}   temporary file containing the prompt
{output_file}   temporary file expected to contain the provider response
{model}         selected model name
```

PseudoForge also sends the prompt to CLI providers over stdin. If `{output_file}` is present, the file is preferred; otherwise stdout is used. CLI command templates are parsed into argv and executed with `shell=False` by default. On Windows, CLI provider calls and Codex model discovery request hidden child console windows so local CLI bridges such as Claude CLI do not flash a separate console during normal runs. Prefix a template with `shell:` or `raw-shell:` only when an explicitly reviewed advanced shell pipeline is required. The default Codex, ChatGPT, and Claude templates include `{model}`. Old default templates that omitted `{model}`, used unsupported Codex CLI flags, or used the older Claude CLI template without the selected model are migrated on load; user-created custom templates are preserved.

Config path:

```text
<IDA user directory>\pseudoforge_config.json
```

Example:

```json
{
  "llm": {
    "enabled": true,
    "provider": "openai_compatible",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-5-mini",
    "timeout_seconds": 60,
    "command_template": "",
    "extra_headers": {}
  },
  "credentials": {
    "openai_compatible": {
      "api_key": "sk-..."
    }
  }
}
```

OpenRouter example:

```json
{
  "llm": {
    "enabled": true,
    "provider": "openrouter",
    "base_url": "https://openrouter.ai/api/v1",
    "model": "openrouter/auto",
    "timeout_seconds": 60,
    "command_template": "",
    "extra_headers": {
      "X-Title": "PseudoForge"
    }
  },
  "credentials": {
    "openrouter": {
      "api_key": "sk-or-..."
    }
  }
}
```

DeepSeek API example:

```json
{
  "llm": {
    "enabled": true,
    "provider": "deepseek_api",
    "base_url": "https://api.deepseek.com",
    "model": "deepseek-v4-flash",
    "timeout_seconds": 60,
    "command_template": "",
    "extra_headers": {}
  },
  "credentials": {
    "deepseek_api": {
      "api_key": "<deepseek-api-key>"
    }
  }
}
```

Codex CLI / ChatGPT OAuth via Codex CLI example:

```json
{
  "llm": {
    "enabled": true,
    "provider": "chatgpt_oauth_via_codex_cli",
    "base_url": "",
    "model": "gpt-5-mini",
    "timeout_seconds": 120,
    "command_template": "codex exec -m {model} --skip-git-repo-check --sandbox read-only --output-last-message {output_file} -",
    "extra_headers": {}
  },
  "credentials": {}
}
```

Claude CLI login example:

```json
{
  "llm": {
    "enabled": true,
    "provider": "claude_login_via_claude_cli",
    "base_url": "",
    "model": "claude-sonnet-4-6",
    "timeout_seconds": 120,
    "command_template": "claude -p --model {model} --permission-mode dontAsk --output-format text --no-session-persistence --tools \"\"",
    "extra_headers": {}
  },
  "credentials": {}
}
```

If an LLM call fails, PseudoForge falls back to the deterministic plan and records the failure in warnings. The IDB write boundary is unchanged: only user-selected, validator-gated renames can be applied.

## Export Output

Export is the durable artifact path for PseudoForge analysis. It is not an apply path and is not meant to rewrite the IDB. The export bundle lets reviewers compare the cleaned output against the original decompiler text, inspect why a rename or semantic cleanup appeared, archive analysis results, and build regression samples from real functions.

`Export cleaned pseudocode` writes:

```text
<function>.cleaned.cpp
<function>.switch-outline.cpp
<function>.rename-map.json
<function>.flow-report.md
<function>.rule-report.json
<function>.raw.cpp
<function>.warnings.json
<function>.raw-vs-cleaned.diff
<function>.summary.json
```

The IDA Free CLI keeps its compatibility summary filename as
`<function>.ida-free-summary.json`.

File purposes:

- `.cleaned.cpp`: readable pseudocode with validated renames and NTSTATUS literal cleanup.
- `.switch-outline.cpp`: recovered dispatcher case values and conservative body excerpts.
- `.rename-map.json`: full `CleanPlan` JSON.
- `.flow-report.md`: dispatcher, recovered cases, cleanup labels, and warning report.
- `.rule-report.json`: deterministic rule matches, rejected emissions, load errors, and validation errors.
- `.raw.cpp`: original captured decompiler text used as analysis input.
- `.warnings.json`: plan and profile-load warnings as reviewable JSON.
- `.raw-vs-cleaned.diff`: unified diff from raw pseudocode to cleaned output.
- `.summary.json` / `.ida-free-summary.json`: per-function export metadata, counts, deterministic rule diagnostics, rule load/validation error details, active profile root, loaded profile names, active profile manifests, profile warnings, and artifact paths.

Artifact parity:

| Artifact | IDA interactive export | Offline CLI | IDA Free CLI |
| --- | --- | --- | --- |
| Cleaned pseudocode | yes | yes | yes |
| Switch outline | yes | yes | yes |
| Rename map / CleanPlan | yes | yes | yes |
| Flow report | yes | yes | yes |
| Rule report | yes | yes | yes |
| Raw pseudocode | yes | yes | yes |
| Warnings JSON | yes | yes | yes |
| Raw-vs-cleaned diff | yes | yes | yes |
| Per-function summary | yes | yes | yes |
| Run manifest | no | no | yes |

Caveats:

- `switch-outline.cpp` does not synthesize deep shared branches or fallthrough bodies.
- Control-flow rewrites are preview/export-only artifacts and never modify the IDB.
- The IDB receives only user-selected local or argument renames.
- Export artifacts are intended to be reviewed against the original pseudocode.

## Offline CLI

Run the core engine outside IDA:

```powershell
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_smoke
```

Expected output:

```text
PseudoForge export complete
Function: NtSetSystemInformation
Renames: <count>
Flow rewrites: <count>
cleaned_pseudocode: ...
switch_outline: ...
rename_map: ...
flow_report: ...
rule_report: ...
raw_pseudocode: ...
warnings: ...
raw_vs_cleaned_diff: ...
summary: ...
```

Use LLM rename assist with provider-specific environment variables or options:

```powershell
$env:PSEUDOFORGE_OPENAI_API_KEY = "<api-key>"
$env:PSEUDOFORGE_OPENAI_MODEL = "gpt-5-mini"
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --llm-renames --out $env:TEMP\pseudoforge_cli_smoke
```

OpenRouter:

```powershell
$env:PSEUDOFORGE_OPENROUTER_API_KEY = "<openrouter-api-key>"
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --llm-renames --llm-provider openrouter --out $env:TEMP\pseudoforge_cli_smoke
```

DeepSeek:

```powershell
$env:PSEUDOFORGE_DEEPSEEK_API_KEY = "<deepseek-api-key>"
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --llm-renames --llm-provider deepseek_api --out $env:TEMP\pseudoforge_cli_smoke
```

Codex CLI:

```powershell
codex login
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --llm-renames --llm-provider codex_cli --llm-timeout 120 --out $env:TEMP\pseudoforge_cli_smoke
```

Claude CLI login:

```powershell
claude auth login
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --llm-renames --llm-provider claude_login_via_claude_cli --llm-timeout 120 --out $env:TEMP\pseudoforge_cli_smoke
```

Optional environment variables:

```text
PSEUDOFORGE_OPENAI_API_KEY
PSEUDOFORGE_OPENAI_BASE_URL
PSEUDOFORGE_OPENAI_MODEL
PSEUDOFORGE_OPENROUTER_API_KEY
PSEUDOFORGE_OPENROUTER_BASE_URL
PSEUDOFORGE_OPENROUTER_MODEL
PSEUDOFORGE_DEEPSEEK_API_KEY
PSEUDOFORGE_DEEPSEEK_BASE_URL
PSEUDOFORGE_DEEPSEEK_MODEL
```

Default values:

```text
PSEUDOFORGE_OPENAI_BASE_URL=https://api.openai.com/v1
PSEUDOFORGE_OPENAI_MODEL=gpt-5-mini
PSEUDOFORGE_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
PSEUDOFORGE_OPENROUTER_MODEL=openrouter/auto
PSEUDOFORGE_DEEPSEEK_BASE_URL=https://api.deepseek.com
PSEUDOFORGE_DEEPSEEK_MODEL=deepseek-v4-flash
```

LLM rename assist only adds candidate names to the deterministic rename plan. LLM output must still pass JSON parsing, confidence thresholding, and rename validation.

## IDA Free Offline CLI

IDA Free is not a supported interactive plugin target for PseudoForge. The interactive actions require IDAPython and local Hex-Rays pseudocode APIs, which are not available in IDA Free. Users can still copy or save a single cloud-decompiled pseudocode function and process that text outside IDA:

```powershell
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_smoke
```

The IDA Free CLI accepts one or more text files. Each file should contain one complete function. Leading or trailing copied text is tolerated when the function boundary is unambiguous. Multiple functions in one file fail closed with an actionable error.

Project-local deterministic rules:

```powershell
python -B .\tools\pseudoforge_free_cli.py .\copied_from_ida_free.cpp --project-root . --rules .\extra_rules --out $env:TEMP\pseudoforge_free_cli_smoke
```

Optional offline LLM rename assist:

```powershell
python -B .\tools\pseudoforge_free_cli.py .\copied_from_ida_free.cpp --llm --llm-provider claude_login_via_claude_cli --llm-timeout 120 --out $env:TEMP\pseudoforge_free_cli_llm
```

Project-local rules and LLM rename assist together:

```powershell
New-Item -ItemType Directory -Force .\pseudoforge_rules | Out-Null
claude auth login
python -B .\tools\pseudoforge_free_cli.py .\copied_from_ida_free.cpp `
  --project-root . `
  --rules .\extra_rules `
  --llm `
  --llm-provider claude_login_via_claude_cli `
  --llm-timeout 120 `
  --out $env:TEMP\pseudoforge_free_rules_llm
```

In this mode, builtin rules, `.\pseudoforge_rules\*.json`, user-global rules, and `--rules` directories are loaded first. LLM rename suggestions are then added as optional candidates and still pass deterministic validation before they can appear in the output plan. Invalid rule packs are reported in the rule report and do not crash analysis. LLM provider failures fall back to the deterministic plan.

The default text console output prints incremental progress before long phases such as LLM-assisted plan building and artifact writing. Use `--no-progress` when only the final text summary is needed.

Example IDA Free CLI run with project-local rules and Claude CLI login:

![PseudoForge IDA Free CLI command and output artifacts](screenshots/ida_free_usage.png)

The screenshot shows the current text console flow with incremental progress and a structured final status summary.

Example IDA Free result comparison. The left side is IDA Free cloud-decompiled pseudocode, and the right side is the cleaned PseudoForge offline output:

![IDA Free raw pseudocode beside PseudoForge cleaned output](screenshots/ida_free_result.png)

Structured console output:

```powershell
python -B .\tools\pseudoforge_free_cli.py .\copied_from_ida_free.cpp --format json --out $env:TEMP\pseudoforge_free_cli_json
```

With `--format json`, stdout remains machine-readable JSON. Progress messages are written to stderr so scripts can continue parsing stdout safely.

IDA Free CLI artifacts include:

- `<function>.cleaned.cpp`
- `<function>.switch-outline.cpp`
- `<function>.rename-map.json`
- `<function>.flow-report.md`
- `<function>.rule-report.json`
- `<function>.raw.cpp`
- `<function>.warnings.json`
- `<function>.raw-vs-cleaned.diff`
- `<function>.ida-free-summary.json`
- `pseudoforge-free-report.json`

IDA Free CLI limitations:

- No interactive PseudoForge menu, preview action, or apply-renames action.
- No IDB writes.
- No direct IDAPython, IDA SDK, or local Hex-Rays API access.
- Output quality depends on the copied decompiler text quality.
- Inferred structure rewrites and semantic comments still require review against the original pseudocode.

## Headless IDA Batch

`tools/pseudoforge_ida_batch.py` runs inside IDA batch mode. It opens a `.i64` or `.idb`, calls `ida_hexrays.decompile()` per function, analyzes through PseudoForge, appends `.forge` sections, and writes JSONL progress reports. The normal entrypoint is the PowerShell wrapper `tools/run_pseudoforge_ida_batch.ps1`.

Example:

```powershell
.\tools\run_pseudoforge_ida_batch.ps1 `
  -IdaPath "C:\Path\To\IDA\ida.exe" `
  -IdbPath "D:\Path\To\ntoskrnl.exe.i64" `
  -TargetPath "D:\Path\To\ntoskrnl.exe" `
  -OutputDir "$env:TEMP\pseudoforge_ida_batch\ntoskrnl" `
  -OverwriteForge
```

Single-function smoke:

```powershell
.\tools\run_pseudoforge_ida_batch.ps1 `
  -IdaPath "C:\Path\To\IDA\ida.exe" `
  -IdbPath "D:\Path\To\ntoskrnl.exe.i64" `
  -TargetPath "D:\Path\To\ntoskrnl.exe" `
  -NameRegex "^NtSetSystemInformation$" `
  -MaxFunctions 1
```

Wrapper options:

- `-MaxFunctions N`: analyze only the first N matching functions.
- `-NameRegex REGEX`: filter functions by name.
- `-Resume`: skip EAs already present in the existing `.forge`.
- `-OverwriteForge`: create a fresh `.forge` before append-only batch export.
- `-UpsertForge`: slower path that verifies aggregate section replacement.
- `-LlmRenames`: use saved or explicit LLM rename assist settings.
- `-NoPdb`: pass `-Opdb:off` to IDA so validation runs do not load PDB/debug symbols.
- `-NoWait`: start the IDA process and return immediately.

Summarize an existing report:

```powershell
python -B .\tools\summarize_pseudoforge_ida_batch.py "$env:TEMP\pseudoforge_ida_batch\ntoskrnl\ntoskrnl.exe_<timestamp>.jsonl"
```

Compare raw Hex-Rays output against PseudoForge output:

```powershell
.\tools\run_pseudoforge_ida_batch.ps1 `
  -IdaPath "C:\Path\To\IDA\ida.exe" `
  -IdbPath "D:\Path\To\ntoskrnl.exe.i64" `
  -TargetPath "D:\Path\To\ntoskrnl.exe" `
  -NameRegex "^NtSetSystemInformation$" `
  -MaxFunctions 1 `
  -CompareDir "$env:TEMP\pseudoforge_ida_batch\ntoskrnl_compare"
```

`-CompareDir` writes:

- `raw\*.cpp`: raw IDA Hex-Rays `cfunc.get_pseudocode()` text.
- `cleaned\*.cpp`: PseudoForge normalized/export pseudocode.
- `forge\*.forge`: full `.forge` section for the function.
- `diff\*.diff`: raw vs cleaned unified diff.

Each JSONL function record includes legacy comparison paths, a shared-style
`artifacts` map, SHA-256 hashes, line counts, and diff line counts.

To include the same LLM assist path used by interactive IDA Analyze, add `-LlmRenames`. Full-kernel LLM batch runs can issue many provider calls, so check cost and runtime first.

LLM wrapper overrides:

- `-LlmProvider openrouter|chatgpt_oauth_via_codex_cli|codex_cli|claude_login_via_claude_cli|claude_cli|deepseek_api|openai_compatible`
- `-LlmModel MODEL`
- `-LlmTimeout SECONDS`
- `-LlmBaseUrl URL`
- `-LlmCommand COMMAND_TEMPLATE`
- `-LlmApiKey KEY`

No-op CLI provider smoke:

```powershell
$noopProvider = "python " + (Resolve-Path .\tools\empty_llm_rename_provider.py).Path
.\tools\run_pseudoforge_ida_batch.ps1 `
  -IdaPath "C:\Path\To\IDA\ida.exe" `
  -IdbPath "D:\Path\To\ntoskrnl.exe.i64" `
  -NameRegex "^NtSetSystemInformation$" `
  -MaxFunctions 1 `
  -LlmRenames `
  -LlmProvider codex_cli `
  -LlmCommand $noopProvider
```

Functions that Hex-Rays cannot decompile are recorded as `skipped`, not as PseudoForge failures.

For unknown third-party binary validation, use `-NoPdb` and review the IDA log for unexpected symbol loading. The wrapper also retries once when a fresh IDA load exits with an empty report file before the batch script has produced records.

## Deterministic Rules

PseudoForge includes a v1 deterministic rules matching engine. The supported production scope is data-only JSON rules for `rename` and `semantic_comment`.

Rule load paths:

```text
ida_pseudoforge/rules/builtin/*.json
.\pseudoforge_rules\*.json
%APPDATA%\PseudoForge\rules\*.json
```

Interactive IDA analysis resolves `.\pseudoforge_rules` relative to the analyzed input binary directory. Offline CLI resolves it relative to the source pseudocode file and also accepts explicit `--rules-dir`.

Builtin rules currently mirror low-risk deterministic hard-coded passes for report/parity visibility. They do not replace existing hard-coded rename validation, cleanup classification, flow recovery, or kernel API rewrite behavior.

Authoring workflow:

1. Create `pseudoforge_rules` beside the analyzed `.idb`, binary, or pseudocode input.
2. Add a rule pack JSON file, for example `project_kernel_rules.json`.
3. Validate the pack before use.
4. In IDA, run PseudoForge analysis normally. In the CLI, place rules beside the source input or pass `--rules-dir .\pseudoforge_rules`.
5. Use `--rule-report` to inspect matched rules, rejected emissions, load errors, and validation errors.

Validation:

```powershell
New-Item -ItemType Directory -Force .\pseudoforge_rules
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
python -B .\tools\validate_pseudoforge_rules.py .\pseudoforge_rules
```

Project-local rule pack example:

```json
{
  "schema_version": 1,
  "id": "project.kernel_object_rules",
  "description": "Project-local PseudoForge deterministic rules for kernel object callback analysis.",
  "rules": [
    {
      "id": "project.rename.exact_previous_mode",
      "phase": "rename",
      "priority": 100,
      "confidence": 0.99,
      "scope": {
        "lvars_any": ["PreviousMode"]
      },
      "match": {
        "text_contains": "PreviousMode"
      },
      "emit": {
        "kind": "rename",
        "rename_kind": "lvar",
        "target": "PreviousMode",
        "new_name": "previousMode",
        "evidence": "Hex-Rays kept kernel PreviousMode casing"
      }
    },
    {
      "id": "project.rename.requester_process",
      "phase": "rename",
      "priority": 100,
      "confidence": 0.94,
      "scope": {
        "calls_any": ["PsGetCurrentProcessId"]
      },
      "match": {
        "assignment_regex": "\\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*PsGetCurrentProcessId\\(\\)\\b"
      },
      "emit": {
        "kind": "rename",
        "rename_kind": "lvar",
        "target": "$dst",
        "new_name": "requesterProcessId",
        "evidence": "Local receives current process id in object callback path"
      }
    },
    {
      "id": "project.comment.object_pre_operation_callback",
      "phase": "semantic_comment",
      "priority": 80,
      "confidence": 0.90,
      "scope": {
        "function_name_regex": ".*ObjectPreOperation$",
        "prototype_contains": "PRE_OPERATION"
      },
      "match": {
        "text_contains_all": ["OB_OPERATION_HANDLE_CREATE", "OriginalDesiredAccess"]
      },
      "emit": {
        "kind": "semantic_comment",
        "comment_kind": "object_pre_operation",
        "text": "Object pre-operation callback checks requested process access",
        "evidence": "OB create operation and OriginalDesiredAccess are present"
      }
    },
    {
      "id": "project.override.updated_status_name",
      "phase": "rename",
      "priority": 120,
      "confidence": 0.96,
      "enabled": true,
      "override_of": "builtin.local.updated_status",
      "scope": {
        "lvars_any": ["updated"],
        "text_contains": "STATUS_"
      },
      "match": {
        "text_contains": "updated"
      },
      "emit": {
        "kind": "rename",
        "rename_kind": "lvar",
        "target": "updated",
        "new_name": "status",
        "evidence": "Project policy treats updated as the NTSTATUS accumulator"
      }
    }
  ]
}
```

Authoring patterns:

1. Exact local rename
   - Use `scope.lvars_any` to require the local first.
   - Use `match.text_contains` to confirm the text appears in the function.
   - Use the real Hex-Rays local name directly in `emit.target`.
2. Assignment-based rename
   - Add a named capture group in `match.assignment_regex`, for example `(?P<dst>...)`.
   - Refer to the binding as `$dst` in `emit.target`.
   - Add a scope gate such as `calls_any` or `text_contains` to reduce false positives.
3. Semantic comment
   - Both `phase` and `emit.kind` must be `semantic_comment`.
   - Keep `comment_kind` short and stable because later reports and rewrites can use it as a key.
   - Keep `text` and `evidence` ASCII.
4. Override rule
   - Rename conflicts for the same target are resolved by `override_of`, `priority`, and `confidence`.
   - To override a builtin policy, set `override_of` to the builtin rule ID and use a higher priority.
   - The final rename still has to pass the existing validator.

Operational rules:

1. Do not use `regex` and `assignment_regex` in the same rule.
2. `scope` is optional, but production rules should usually include a scope gate.
3. `confidence` must be a number from `0.0` to `1.0`; booleans are rejected.
4. Use `enabled: false` for temporary disablement.
5. JSON rule files cannot contain execution or network fields such as `python`, `shell`, `command`, `subprocess`, `url`, or `network`.
6. Rules affect preview/export plans and reports only. IDB renames still use the explicit user-selected validator-gated rename path.

Supported scope operators:

```text
calls_any
calls_all
lvars_any
function_name_regex
prototype_contains
text_contains
text_contains_all
```

Supported match operators:

```text
regex
assignment_regex
text_contains
text_contains_all
```

Schema version 2 also supports preview/export-oriented call argument gates:

```text
call_arg_count
call_arg_literal
```

Supported v1 emissions:

```text
rename
semantic_comment
```

Schema version 2 also supports preview-only `call_arg_rewrite` and
`text_rewrite` emissions.
The builtin v2 report-only rules currently mirror the low-risk
`PsSetCreateProcessNotifyRoutine`/`PspSetCreateProcessNotifyRoutine` BOOLEAN
remove-argument cleanup so reports can compare rule candidates against the
existing hard-coded kernel API renderer path. `text_rewrite` candidates require
`before_regex`, `replacement`, `preview_only: true`, and a
`requires_comment_kind` semantic gate.

Rule conflict policy:

1. Higher `priority` and `confidence` sort rules earlier for matching.
2. Rename emissions for the same target are resolved before normal rename validation.
3. Preview-only `call_arg_rewrite` emissions for the same function argument are resolved before report export.
4. Preview-only `text_rewrite` emissions with overlapping spans are resolved before report export.
5. `override_of` is the strongest conflict signal; otherwise `priority` wins before `confidence`.
6. Rule-based renames always use source `rule`; JSON cannot spoof trusted internal sources such as `kernel-status` or `semantic-rule`.
7. Rule report paths are redacted to labels such as `builtin/local_renames.json`, `project/foo.json`, or `user/foo.json`.

Run with additional rules and write a report:

```powershell
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --rules-dir .\pseudoforge_rules --rule-report $env:TEMP\pseudoforge_rules --out $env:TEMP\pseudoforge_cli_smoke
```

Inspect a rule report:

```powershell
Get-ChildItem $env:TEMP\pseudoforge_rules
Get-Content (Get-ChildItem $env:TEMP\pseudoforge_rules -Filter *.rule-report.json | Select-Object -First 1).FullName
```

Report fields:

```text
matched_rules: rules that passed scope/match and emitted data
rewrite_emissions: preview/export-only rewrite emissions with applied, shadowed, or rejected status
rejected_emissions: emissions rejected by conflict, validation, or runtime guards
load_errors: JSON read or parse failures
validation_errors: schema, regex, or forbidden-key failures
```

Safety boundaries:

1. Rule files are JSON data only.
2. User Python execution is not supported.
3. The rule system rejects network, subprocess, and command execution fields.
4. Invalid rule packs fail closed and analysis continues.
5. Invalid regexes, invalid scope regexes, ambiguous primary regex matchers, empty matches, empty text gates, boolean numeric fields, and missing emit fields are rejected at load time.
6. Runtime exceptions reject only the offending rule and analysis continues.
7. Rule-based rename suggestions still pass through `validate_renames()`.
8. `call_arg_rewrite` and `text_rewrite` output is report-only today; it is not converted into rename/comment plan output and cannot modify IDB state.
9. Control-flow rewrite rules are out of v2 preview scope and do not modify IDB state.

## Validation

Unit tests:

```powershell
python -B -m unittest discover -s tests -v
```

Compile check:

```powershell
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
```

Profile JSON checks:

```powershell
python -B -m json.tool .\ida_pseudoforge\profiles\kernel_api.json
python -B -m json.tool .\ida_pseudoforge\profiles\kernel_api_overrides.json
python -B -m json.tool .\ida_pseudoforge\profiles\profiles_manifest.json
python -B -m json.tool .\ida_pseudoforge\profiles\status_codes.json
python -B -m json.tool .\ida_pseudoforge\profiles\process_information_class.json
python -B -m json.tool .\ida_pseudoforge\profiles\system_information_class.json
```

WDK profile generation checks:

```powershell
python -B .\tools\build_kernel_api_profile.py --list-versions
python -B .\tools\build_kernel_api_profile.py --version 10.0.26100.0 --dry-run --summary --function ExAllocatePool2 --function ExAcquireResourceExclusiveLite
python -B .\tools\profile_load_smoke.py --family functions --repeat 100 --json
python -B .\tools\build_status_codes_profile.py --version 10.0.26100.0 --dry-run --summary
```

Rule validation:

```powershell
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
```

Offline export smoke:

```powershell
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_smoke
python -B .\tools\pseudoforge_free_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_free_cli_smoke
```

Patch hygiene:

```powershell
git diff --check -- .
```

Current validation set used during development:

```powershell
python -B -m unittest discover -s tests -v
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
python -B -m json.tool .\ida_pseudoforge\profiles\kernel_api.json
python -B -m json.tool .\ida_pseudoforge\profiles\kernel_api_overrides.json
python -B -m json.tool .\ida_pseudoforge\profiles\profiles_manifest.json
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

## Troubleshooting

`Edit/PseudoForge` is not visible:

1. Confirm that `pseudoforge.py`, `ida-plugin.json`, and `ida_pseudoforge/` are in the same plugin directory.
2. Confirm that `ida_pseudoforge` was not copied as a nested directory.
   - Correct: `plugins\ida_pseudoforge\core\...`
   - Incorrect: `plugins\ida_pseudoforge\ida_pseudoforge\core\...`
3. Check the IDA Output window for Python import errors.
4. Confirm that the Hex-Rays decompiler is active.

IDA hangs immediately after preview:

1. Fully restart the IDA process after updating plugin files.
   - A running IDA process with an old logger thread can keep failing even after new files are copied.
2. Check the last checkpoint in `%TEMP%\pseudoforge_preview_trace.log`.
3. Check `%TEMP%\pseudoforge_trace.log` for `output.timer.started` or `output.timer.disabled`.
4. If Output logging is suspected, set `PSEUDOFORGE_DISABLE_OUTPUT_LOG=1` before launching IDA and retry.

Paste is empty after `Copy all`:

1. Check `%TEMP%\pseudoforge_clipboard\copy_all.log`.
2. A log beginning with `failed ...` indicates a Windows Clipboard API or file path issue.
3. No log means the preview context-menu action `PseudoForge/Copy all` was not invoked.

`Export cleaned pseudocode` fails:

1. Confirm that the cursor is inside a function.
2. Confirm that the target function can be decompiled in the pseudocode view.
3. Confirm write access beside the IDB.
4. Reproduce with the offline CLI using the same pseudocode text.

Rename application fails:

1. Confirm that the target is a local variable or argument.
2. Check for an existing name collision.
3. Confirm the cursor is still inside the same function that was analyzed. PseudoForge refuses apply when the current function no longer matches the analyzed session.
4. Hex-Rays can reject some lvar renames; inspect the export artifact first.

## Design Principles

1. IDB writes happen only after preview and explicit user selection.
2. LLM output is never applied directly; only validated plan items are used.
3. Control-flow rewrites are preview/export-only artifacts.
4. Renames must pass collision, reserved keyword, and identifier validation.
5. Apply-selected-renames rechecks the current analyzed function and performs a final preflight before calling Hex-Rays rename APIs.
6. Every cleanup should leave artifacts that can be compared with the original pseudocode.
7. Kernel-scale functions can legitimately produce partial recovery plus warnings.

## Related Documents

- [ida_pseudocode_refactor_plugin_design.md](ida_pseudocode_refactor_plugin_design.md)
- [deterministic_rules_matching_engine_design.md](deterministic_rules_matching_engine_design.md)
- [pseudoforge_implementation_status.md](pseudoforge_implementation_status.md)
- [pseudoforge_improvement_plan.md](pseudoforge_improvement_plan.md)

## Next Work

1. Continue deterministic rules v2 with a safe `flow` phase after stronger branch evidence exists.
2. Improve shared and fallthrough branch body reconstruction.
3. Manually validate identity-backed rename tracking and investigate true object-level ctree rename application.
4. Implement a dockable side-by-side preview panel.
5. Expand profile coverage against real target builds.
