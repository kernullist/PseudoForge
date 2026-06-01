# PseudoForge IDA No-PDB End-to-End Quality Report

Date: 2026-06-01

This report records the no-PDB IDA end-to-end quality loop for the PseudoForge
kernel pattern driver. The goal was to inspect every decompiled function,
identify practical pseudocode quality gaps, implement only generic fixes, and
review the changes after each development cycle.

## Environment

- IDA executable: `C:\Program Files\IDA Professional 9.0\ida.exe`
- Source test driver: `samples\kernel_pattern_driver\x64\Release\PfKernelPattern.sys`
- No-PDB method: copied only the `.sys` into a fresh `input_no_pdb` directory and
  ran the batch wrapper with `-NoPdb`, which passes `-Opdb:off` to IDA.
- Batch wrapper: `tools\run_pseudoforge_ida_batch.ps1`
- LLM rename assist: disabled

## Baseline

Output directory:

```text
pseudoforge_out\ida_e2e_quality\baseline_20260601_190332
```

Baseline result:

```text
Functions selected: 46
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

Quality findings from the baseline review:

1. The no-PDB OB pre-operation callback had an inconsistent parameter rewrite.
   The signature was upgraded to `PVOID registrationContext`, but the function
   body still referenced `a1`, producing inconsistent pseudocode.
2. The same callback still showed raw offset field loads for
   `OB_PRE_OPERATION_INFORMATION`, including `preOperationInfo + 8`. The
   nearby `preOperationInfo + 4` flag-style check was noted separately because
   the current structure profile does not expose a trusted `Flags` field.
3. Compiler runtime helper functions such as optimized copy/set routines remain
   verbose. They were treated as a known limitation because collapsing them into
   `memmove` or `memset` needs stronger whole-function runtime recognition than
   was available in this cycle.

## Cycle 1

Implemented:

- Synchronized OB pre-operation callback body tokens when a known callback
  signature override changes generic no-PDB parameter names.
- Added a no-PDB regression test that checks the signature/body consistency
  without relying on a sample address or symbol name.

Output directory:

```text
pseudoforge_out\ida_e2e_quality\cycle1_20260601_190821
```

Cycle 1 result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
```

Review finding after Cycle 1:

- The body/signature mismatch was fixed, but the callback still contained raw
  typed offset expressions for known `OB_PRE_OPERATION_INFORMATION` fields.

## Cycle 2

Implemented:

- Rewrote typed no-PDB pointer field loads for profile-known
  `OB_PRE_OPERATION_INFORMATION` fields:
  - `Object`
  - `ObjectType`
  - `CallContext`
- Extended the no-PDB regression test to cover profile-known typed field loads.

Review finding after Cycle 2:

- The first implementation still encoded structure byte offsets directly and
  rewrote `+4` as `Flags` even though the split WDK structure profile does not
  expose that field. That was too speculative.

Output directory:

```text
pseudoforge_out\ida_e2e_quality\cycle2_20260601_191032
```

Cycle 2 result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

## Cycle 3 Review Correction

Implemented:

- Added profile metadata lookup helpers for kernel structures and aliases.
- Replaced OB pre-operation typed field rewrites with a profile-backed layout
  pass. Field offsets are now computed from `kernel_structures.json` plus alias
  type layout instead of being encoded in the rewrite rule.
- Derived the `Parameters->...OriginalDesiredAccess` load shape from the
  profile-known `Parameters` field and the profile-known
  `OriginalDesiredAccess` member offset in the create/duplicate handle
  structures.
- Removed the speculative `Flags` rewrite. `preOperationInfo + 4` remains raw
  until the profile exposes a trusted field for it.
- Added a negative regression so a generic `preInfo` name plus operation-like
  DWORD check does not trigger OB field rewrites without additional structural
  evidence.

Output directory:

```text
pseudoforge_out\ida_e2e_quality\cycle3_20260601_200530
```

Cycle 3 result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

## Cycle 4 Final Validation

Implemented:

- Added an idempotency guard so already-rendered
  `preOperationInfo->Parameters` sources still flow through the same
  profile-backed desired-access rewrite path.

Output directory:

```text
pseudoforge_out\ida_e2e_quality\cycle4_20260601_200922
```

Cycle 4 result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

Representative before/after:

```cpp
// Baseline
OB_PREOP_CALLBACK_STATUS __fastcall sub_140001A70(
        PVOID registrationContext,
        POB_PRE_OPERATION_INFORMATION preOperationInfo)
{
  ProcessId = PsGetProcessId(*(PEPROCESS *)(preOperationInfo + 8));
  ExAcquireFastMutex((PFAST_MUTEX)(a1 + 72));
  if ( v6 || (*(_DWORD *)(preOperationInfo + 4) & 1) != 0 || !v8 )
  {
    ...
  }
}
```

```cpp
// Cycle 4
OB_PREOP_CALLBACK_STATUS __fastcall sub_140001A70(
        PVOID registrationContext,
        POB_PRE_OPERATION_INFORMATION preOperationInfo)
{
  ProcessId = PsGetProcessId((PEPROCESS)preOperationInfo->Object);
  ExAcquireFastMutex((PFAST_MUTEX)(registrationContext + 72));
  if ( v6 || (*(_DWORD *)(preOperationInfo + 4) & 1) != 0 || !v8 )
  {
    ...
  }
}
```

## Hardcoding Audit

- No function EA, sample pool tag, binary filename, or test-driver-specific
  variable name was used as a rule gate.
- The callback parameter synchronization is gated by known OB pre-operation
  callback structural evidence and the existing callback signature override.
- The field rewrites are gated by `OB_PRE_OPERATION_INFORMATION` structural
  evidence, then apply only to fields present in the loaded kernel structure
  profile. Byte offsets are derived from profile field order and alias type
  layout.
- Fields that are not present in the trusted profile, such as the current
  `Flags`-style offset, are intentionally left raw instead of being invented.
- Regression tests use no-PDB style generic `sub_*`, `a1`, and `a2` inputs.

## Validation

Commands run successfully:

```powershell
python -m unittest tests.test_render_callbacks.RenderCallbacksTests.test_no_pdb_ob_pre_operation_signature_keeps_body_parameter_consistent
python -m unittest tests.test_render_callbacks tests.test_render_snapshots tests.test_render_memory
python -m pytest -q
python -B -m unittest discover -s tests -v
python -m compileall ida_pseudoforge tests
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
git diff --check -- .
.\tools\run_pseudoforge_ida_batch.ps1 -IdaPath 'C:\Program Files\IDA Professional 9.0\ida.exe' -IdbPath <cycle4>\input_no_pdb\PfKernelPattern.sys -TargetPath <cycle4>\input_no_pdb\PfKernelPattern.sys -OutputDir <cycle4> -ForgePath <cycle4>\PfKernelPattern.forge -CompareDir <cycle4>\compare -ReportPath <cycle4>\ida_batch.jsonl -IdaLogPath <cycle4>\ida.log -NoPdb -SkipLibThunk
```

Observed results:

```text
pytest: 345 passed, 5 subtests passed
unittest discover: 345 tests OK
compileall: passed
git diff --check: passed
IDA no-PDB cycle4 batch: processed=46, succeeded=46, skipped=0, failed=0
```

## Generic No-Hardcoding Quality Lift

Implemented after cycle4:

- Added `ida_pseudoforge.core.quality_score` and
  `tools/score_pseudoforge_quality.py` to score raw-vs-cleaned compare
  artifacts with corpus-agnostic Hex-Rays artifact penalties and conservative
  semantic recovery rewards.
- Added generic dataflow-backed rename recovery for:
  - repeated constant-offset structure-base parameters -> `context`
  - self-referential LIST_ENTRY heads -> `listHead`
  - single lookaside allocation results -> `lookasideEntry`
  - optimized memory-copy/fill helpers -> `destination`, `source`,
    `fillByte`, `byteCount`
  - structured output-buffer contracts -> `outputBuffer`,
    `outputBufferLength`, `returnLength`
- Improved text local capture for multi-pointer declarations such as
  `_QWORD **v11`.
- Folded indexed uses of single-assignment pointer aliases back to the canonical
  pointer while preserving address-taken aliases.
- Review-mode hardcoding audit removed a direct `qword_140...` production
  rewrite literal and replaced it with a generic `qword_[0-9A-Fa-f]+` pattern.

Final output directory:

```text
pseudoforge_out\ida_e2e_quality\cycle12_20260601_211425
```

Cycle 12 result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

Quality score movement:

| Metric | Cycle 4 | Cycle 12 |
| --- | ---: | ---: |
| Average score | 61.98 | 65.83 |
| Average opportunity | 43.87 | 40.80 |
| Average reward | 6.41 | 7.20 |
| `generic_argument_name` count | 252 | 60 |
| `compiler_local_name` count | 931 | 872 |
| `artifact_reduction` count | 377 | 518 |

Representative improvements:

```cpp
// Runtime memory helper, cycle12
__m128 *__fastcall sub_140004300(char *destination, char *source, unsigned __int64 byteCount)
{
  result = (__m128 *)destination;
  ...
}
```

```cpp
// Structured output-buffer contract, cycle12
__int64 __fastcall sub_1400017CC(__int64 context, _DWORD *outputBuffer, unsigned int outputBufferLength, _QWORD *returnLength)
{
  if ( outputBufferLength < 0x18 )
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  ...
  *returnLength = 40LL * v10 + 24;
  return result;
}
```

Validation commands:

```powershell
python -B -m unittest discover -s tests -v
python -m pytest -q
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
git diff --check -- .
.\tools\run_pseudoforge_ida_batch.ps1 -IdaPath 'C:\Program Files\IDA Professional 9.0\ida.exe' -IdbPath <cycle12>\input_no_pdb\PfKernelPattern.sys -TargetPath <cycle12>\input_no_pdb\PfKernelPattern.sys -OutputDir <cycle12> -ForgePath <cycle12>\PfKernelPattern.forge -CompareDir <cycle12>\compare -ReportPath <cycle12>\ida_batch.jsonl -IdaLogPath <cycle12>\ida.log -NoPdb -SkipLibThunk
python -B .\tools\score_pseudoforge_quality.py --compare-dir <cycle12>\compare --report <cycle12>\ida_batch.jsonl --json-output <cycle12>\quality_score.json --markdown-output <cycle12>\quality_score.md --top 15
```

## Remaining Limitations

- Optimized compiler runtime helpers are still verbose. They should be handled
  further by generic whole-function runtime-helper classification, not by
  address or sample-specific matching. The current cycle recovers helper
  parameter roles but intentionally does not rename helper functions yet.
- No-PDB cross-function role propagation is still conservative. Functions called
  from `DriverEntry` or dispatch tables can be inferred locally when evidence is
  present, but the batch pipeline does not yet propagate role names across the
  whole IDB.
- Complex cleanup labels in large callback paths are still preserved when the
  control-flow evidence is not strong enough to restructure safely.

## Follow-up Generic API Metadata Lift

Implemented after the postcommit review pass:

- Added generic WDK API metadata-backed rename recovery for:
  - address-taken local out parameters, such as profile parameter
    `CurrentTime` -> `currentTime`
  - API return locals, such as `KeAcquireSpinLockRaiseToDpc` -> `oldIrql`
    and `PsGetCurrentThreadId` -> `currentThreadId`
  - API argument role locals, such as `ExFreeToNPagedLookasideList` parameter
    `Lookaside` -> `lookasideList`
- Added exact constant pointer-expression alias reuse. When a local is assigned
  a stable `(base + offset)` pointer expression, later equivalent uses of that
  expression can be rendered through the local alias instead of repeating the
  raw offset.
- Review mode found and fixed two generic-rule risks before final validation:
  - pointer-typedef detection was moved into an API-profile-only helper so
    runtime-memory size/type checks do not treat unrelated `P...` scalar names
    as pointers
  - generic API argument renames now yield when the desired target would shadow
    an existing local that differs only by case

Latest output directory:

```text
pseudoforge_out\ida_e2e_quality\qualitylift_20260601_220431
```

Latest result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

Quality score movement from the postcommit baseline:

| Metric | Postcommit | Latest |
| --- | ---: | ---: |
| Average score | 65.83 | 66.63 |
| Average opportunity | 40.80 | 40.02 |
| Average reward | 7.20 | 7.39 |
| `compiler_local_name` count | 872 | 818 |
| `raw_pointer_offset` count | 73 | 70 |
| `artifact_reduction` count | 518 | 554 |

Representative cleaned output:

```cpp
lookasideList = (struct _NPAGED_LOOKASIDE_LIST *)(context + 192);
lookasideEntry = ExAllocateFromNPagedLookasideList((PNPAGED_LOOKASIDE_LIST)lookasideList);
oldIrql = KeAcquireSpinLockRaiseToDpc((PKSPIN_LOCK)(context + 128));
KeQuerySystemTimePrecise(&currentTime);
ExFreeToNPagedLookasideList(lookasideList, entry);
KeReleaseSpinLock((PKSPIN_LOCK)(context + 128), oldIrql);
```

## Runtime Helper Alias Follow-up

The previous quality-lift pass still left many caller sites with unresolved
runtime helper calls even when the helper implementation itself had already
been recognized as an optimized memory primitive.

Implemented generic rule:

- Infer runtime memory-fill and memory-move helpers only from no-PDB evidence:
  decompiler-style `sub_*` name, three-argument signature after deterministic
  parameter recovery, first-parameter return behavior, byte-count control, and
  memory write/read body patterns.
- Render caller sites through standard `memset` or `memmove` calls in batch
  compare artifacts and aggregate `.forge` output after all selected functions
  are processed, while preserving the helper function definition name.
- In interactive IDA use, do not require full-function preanalysis. PseudoForge
  probes only direct `sub_*` callees from the current function, runs the same
  deterministic helper evidence, and leaves calls unchanged when evidence is
  missing.
- Review mode fixed a false-negative risk where a result-alias comparison such
  as `result == 0` could be mistaken for alias mutation.

Latest output directory:

```text
pseudoforge_out\ida_e2e_quality\helperalias_memset_20260601_223437
```

Latest result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
Runtime helper aliases: sub_1400045C0 -> memset
Rewritten files: 21
```

Quality score movement from the previous quality-lift run:

| Metric | Previous | Latest |
| --- | ---: | ---: |
| Average score | 66.63 | 67.37 |
| Average opportunity | 40.02 | 39.33 |
| Average reward | 7.39 | 7.52 |
| `unresolved_helper_call` count | 90 | 74 |
| `artifact_reduction` count | 554 | 586 |

Representative cleaned output:

```cpp
memset(sourceBuffer, 0LL, 64LL);
memset(copyBuffer, 0LL, 64LL);
```

Remaining quality blockers are now dominated by structure/layout recovery and
compiler-local dataflow recovery rather than simple helper-call opacity.

## Inferred Record Field-Access Follow-up

The helper-alias run still left some OB callback list-walk records with raw
field expressions after the record type was already inferred. The remaining
forms were not tied to one function or address; they were alternate Hex-Rays
spellings for the same record fields.

Implemented generic rule:

- For locals already proven to be `INFERRED_OB_PROCESS_RULE_RECORD`, rewrite
  pointer-sized cast/index field reads such as casted `entry[2]` into
  `entry->ProcessId`.
- Extend the record inference gate from equality-only comparisons to equality
  and inequality comparisons so while-list scans get the same field cleanup as
  for-loop scans.
- Keep the rule gated by independent record evidence: process-id field compare,
  hit-count update, and last-seen-time update. No function address, binary name,
  pool tag, or sample-specific symbol text is used.
- Review mode tightened the cast pattern so `void *` is accepted but plain
  `void` is not.

Comparable output directory:

```text
pseudoforge_out\ida_e2e_quality\record_compare_skiplib_20260601_225228
```

Comparable result:

```text
Processed: 46
Succeeded: 46
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=46
Compare artifacts: 46
```

All-discovered-function output directory:

```text
pseudoforge_out\ida_e2e_quality\record_compare_20260601_224936
```

All-discovered-function result:

```text
Processed: 51
Succeeded: 51
Skipped: 0
Failed: 0
Warnings: 0
LLM status: disabled=51
Compare artifacts: 51
```

Quality movement from the helper-alias run:

| Metric | Helper alias | Inferred record |
| --- | ---: | ---: |
| Average score | 67.37 | 67.37 |
| Average opportunity | 39.33 | 39.33 |
| Average reward | 7.52 | 7.52 |
| `profile_field_access` count | 45 | 50 |
| `typed_index_offset` count | 58 | 57 |
| `unresolved_width_type` count | 412 | 406 |

Representative cleaned output:

```cpp
INFERRED_OB_PROCESS_RULE_RECORD *v11; // rcx
...
while ( v11->ProcessId != processId )
{
  v11 = (INFERRED_OB_PROCESS_RULE_RECORD *)v11->Link.Flink;
  ...
}
++v11->HitCount;
KeQuerySystemTimePrecise(&v11->LastSeenTime);
```

## Final Judgment

For the current no-PDB kernel pattern driver, PseudoForge now reaches practical
review quality across the comparable 46-function `-SkipLibThunk` set and also
processes all 51 IDA-discovered functions successfully when library thunks are
included. No known incorrect rewrite remained from the reviewed output, the
concrete no-PDB callback mismatch found in the baseline was fixed with generic
regression-tested rules, and the follow-up quality-lift cycles reduced generic
argument artifacts from 252 to 60 without adding sample-specific hardcoding.
