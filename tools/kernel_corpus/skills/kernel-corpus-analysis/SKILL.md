---
name: kernel-corpus-analysis
description: Use when answering questions about PseudoForge kernel corpus packs through MCP or local evidence packs, including kernel lifecycle, subsystem, function, callgraph, import/string, and evidence-grounded reverse-engineering analysis.
---

# Kernel Corpus Analysis

Use this skill for PseudoForge Kernel Corpus analysis. The corpus data stays outside this skill; this file only defines the operating procedure and answer contracts.

Hard rule for every major claim:

```text
Claim -> EA -> function name -> artifact path -> inference level
```

## First Moves

1. Locate the pack root from the user, thread context, MCP config, or a local path such as `<workspace>/pseudoforge_out/kernel_corpus/<target>`.
2. Call `corpus_status` before analysis. Check schema, function count, skipped count, manifest path, SQLite path, and warnings.
3. Use MCP first when available. If MCP is unavailable, use the local CLIs under `tools/kernel_corpus/`.
4. Prefer focused evidence packs over loading broad raw corpus output.
5. Do not answer from generic Windows internals alone.

Local lifecycle fallback:

```powershell
python -B .\tools\kernel_corpus\lifecycle.py --pack-root "<pack-root>" --topic process_object --depth 2 --output "<pack-root>\evidence-packs\process_object.json"
```

Supported lifecycle topics:

- `process_object`
- `thread_object`
- `file_object`
- `driver_object`
- `device_object`
- `registry_key`
- `section_object`
- `module_image`

Local subsystem atlas fallback:

```powershell
python -B .\tools\kernel_corpus\atlas.py --pack-root "<pack-root>" --output-dir "<pack-root>\reports\atlas"
```

Local answer harness fallback:

```powershell
python -B .\tools\kernel_corpus\answer_harness.py --pack-root "<pack-root>" --evidence-pack "<pack-root>\evidence-packs\process_object.json" --question "<question>" --atlas-page process.md --prompt-out "<pack-root>\answer-prompts\process_object.md" --answer-in "<pack-root>\answers\process_object.md" --report-out "<pack-root>\answer-reports\process_object.json"
```

## Tool Workflow

- Lifecycle questions: call `trace_lifecycle` first with `topic` such as `process_object`, `thread_object`, `file_object`, `driver_object`, `device_object`, `registry_key`, `section_object`, or `module_image`, then inspect high-impact functions with `get_function`, and use `get_neighbors` for ambiguous transitions.
- Function questions: use `search_functions` or exact EA lookup with `get_function`; then cite cleaned/raw/summary artifact paths.
- Subsystem questions: generate or inspect atlas pages first when available; then search by names, tags, imports, and strings; expand nearby callers/callees; build an evidence pack for broad answers.
- Import/string questions: use `search_by_import` or `search_by_string`, then verify with `get_function`.
- Broad answers: call `build_evidence_pack` or `trace_lifecycle` and treat the pack as the answer boundary.
- Durable handoff or review: call the local answer harness to generate the bounded prompt and validate the drafted Markdown answer.

## Evidence Discipline

- Cite EA, function name, and artifact path for important claims.
- Separate confirmed corpus evidence from inference.
- Treat lifecycle phase labels and LLM rename suggestions as hypotheses until supported by function evidence or edges.
- State gaps from skipped functions, missing exact seeds, missing edges, stale packs, or low-confidence phase assignments.
- Do not claim a transition is proven unless the evidence pack contains a supporting edge or function relationship.
- Treat answer harness warnings as citation lint that must be reviewed before reusing an answer.
- Do not mutate the source corpus or IDB. Writing a derived evidence pack is acceptable only when the workflow or user asks for a durable artifact.

## Korean Query Mapping

Map Korean questions into corpus search terms and lifecycle topics before retrieval:

| Korean intent | Use topic/query terms |
| --- | --- |
| 프로세스 생성/종료/삭제 | `process_object`, `process`, `create process`, `exit process`, `delete process`, `Psp*Process` |
| 스레드 생성/종료/삭제 | `thread_object`, `thread`, `create thread`, `exit thread`, `delete thread`, `Psp*Thread` |
| 파일 오브젝트 생성/닫기/삭제 | `file_object`, `file object`, `create file`, `close file`, `delete file`, `NtCreateFile`, `Iop*File` |
| 드라이버 오브젝트 로드/언로드 | `driver_object`, `driver object`, `load driver`, `unload driver`, `DriverEntry`, `Iop*Driver` |
| 디바이스 오브젝트 생성/삭제 | `device_object`, `device object`, `create device`, `delete device`, `attach device`, `IoCreateDevice`, `IoDeleteDevice` |
| 섹션/맵드 뷰 생성/해제 | `section_object`, `section object`, `create section`, `map view`, `unmap view`, `NtCreateSection`, `NtMapViewOfSection` |
| 모듈/이미지 로드/언로드 | `module_image`, `image load`, `system image`, `load image notify`, `MmLoadSystemImage`, `PspCallImageNotifyRoutines` |
| 오브젝트/참조/삭제 | `object`, `ObInsertObject`, `ObReferenceObject`, `ObDereferenceObject`, `delete` |
| 핸들/핸들 테이블 | `handle`, `object table`, `handle table`, `ObReferenceObjectByHandle` |
| IOCTL/디스패치 | `ioctl`, `device control`, `IRP_MJ_DEVICE_CONTROL`, `dispatch` |
| 메모리/풀/매핑 | `memory`, `pool`, `allocate`, `map`, `section`, `Mm` |
| 레지스트리 | `registry_key`, `registry`, `Cm`, `NtCreateKey`, `ZwQueryValueKey`, `ZwSetValueKey` |
| 보안/토큰/권한 | `security`, `token`, `privilege`, `Se`, `access check` |
| 콜백/노티파이 | `callback`, `notify`, `PsSet*NotifyRoutine`, `PspCall*Notify*` |
| 로드/언로드 | `load`, `unload`, `DriverEntry`, `Unload`, `PsSetLoadImageNotifyRoutine` |

## Lifecycle Answer Contract

Use this shape for lifecycle questions:

```markdown
Overall flow:
1. Entry
2. Allocation and initialization
3. Object insertion and visibility
4. Notification side paths
5. Exit and rundown
6. Final dereference and delete

Major functions:
- `0x...` `FunctionName`: role, phase confidence, artifact path.

Confirmed from this corpus:
- Evidence-backed observations with EA/function/path citations.

Inference:
- Clearly marked reasoning that connects evidence.

Gaps:
- Missing edges, skipped functions, ambiguous phase assignments, or missing seeds.
```

## Function Answer Contract

For a single function:

```markdown
Identity:
- EA, name, tags, mode, artifact paths.

What this function appears to do:
- Evidence-backed summary from cleaned/raw/summary artifacts.

Callgraph/import/string evidence:
- Direct callers/callees, imports, strings, and why they matter.

Confidence:
- Confirmed evidence vs inference, including warnings or missing artifacts.
```

## Subsystem Atlas Contract

For a subsystem or broad flow:

```markdown
Scope:
- Corpus status and retrieval query terms.

Core clusters:
- Function groups by role, with EA/name/path citations.

Edges and entry points:
- Caller/callee relationships that are present in the evidence pack.

Operational interpretation:
- What the evidence suggests, separated from assumptions.

Gaps and next retrieval:
- Missing tags, skipped functions, deeper neighbors, or extra evidence packs to build.
```

## Guardrails

- Do not copy generated ntoskrnl data into this skill.
- Do not rely on memory or generic Windows behavior when corpus evidence is available.
- Do not treat cleaned pseudocode as perfect; inspect raw/summary artifacts when precision matters.
- Do not hide uncertainty. A useful kernel answer can say "unknown from this corpus" and propose the next retrieval.
