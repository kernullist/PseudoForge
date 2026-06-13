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
2. Run the local freshness validator when the pack may be old or when derived evidence packs/atlas pages already exist.
3. Call `corpus_status` before analysis. Check schema, function count, skipped count, manifest path, SQLite path, and warnings.
4. Use MCP first when available. If MCP is unavailable, use the local CLIs under `tools/kernel_corpus/`.
5. For cross-build or pack-revision drift questions, call `compare_canonical_answers` first when available. Compare by canonical topic id and normalized function name; treat EAs as build-local evidence.
6. For broad lifecycle, subsystem, or security-engineering questions, call `plan_kernel_answer` first when available. If the planner is unavailable, call `find_canonical_answers` or `list_canonical_answers` before live retrieval when canonical tools are available.
7. Prefer focused evidence packs over loading broad raw corpus output.
8. Do not answer from generic Windows internals alone.

Local freshness fallback:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py --pack-root "<pack-root>" --include-derived --format text
```

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

Local canonical answer fallback:

```powershell
python -B .\tools\kernel_corpus\canonical_store.py find --pack-root "<pack-root>" --query "<question>" --max-topics 5
python -B .\tools\kernel_corpus\canonical_store.py get --pack-root "<pack-root>" --topic process_object_lifecycle --quality --gaps --max-chars 12000
```

Local answer planner fallback:

```powershell
python -B .\tools\kernel_corpus\answer_planner.py --pack-root "<pack-root>" --question "<question>" --format markdown --plan-out "<pack-root>\answer-plans\planned-answer.md"
```

Local canonical drift fallback:

```powershell
python -B .\tools\kernel_corpus\canonical_compare.py --pack-root-a "<old-pack-root>" --pack-root-b "<new-pack-root>" --topic process_object_lifecycle --format markdown --report-out "<workspace>\pseudoforge_out\kernel_corpus\drift\process_object_lifecycle.md"
```

## Tool Workflow

- Cross-build drift questions: call `compare_canonical_answers` for compact JSON, or `get_canonical_drift_report` for bounded Markdown. Inspect missing topics, quality/status changes, same-name different-EA entries, selected-function additions/removals, phase changes, edge changes, and stale quality warnings before drafting.
- Canonical answer questions: call `find_canonical_answers` for the user's wording, then `get_canonical_answer` for the best passing topic. Inspect `quality.md` and `gaps.md`; use degraded topics only with caveats, and use failed topics only as retrieval hints. Cite the canonical topic id alongside EA, function name, and artifact path.
- Broad natural-language questions: call `plan_kernel_answer` and follow its selected canonical candidates, live retrieval steps, citation contract, and stop conditions before drafting. The planner does not generate final prose.
- Lifecycle questions: call `trace_lifecycle` first with `topic` such as `process_object`, `thread_object`, `file_object`, `driver_object`, `device_object`, `registry_key`, `section_object`, or `module_image`, then inspect high-impact functions with `get_function`, and use `get_neighbors` for ambiguous transitions.
- Function questions: use `search_functions` or exact EA lookup with `get_function`; then cite cleaned/raw/summary artifact paths.
- Subsystem questions: generate or inspect atlas pages first when available; then search by names, tags, imports, and strings; expand nearby callers/callees; build an evidence pack for broad answers.
- Import/string questions: use `search_by_import` or `search_by_string`, then verify with `get_function`.
- Broad answers: prefer a passing canonical answer when available, then call `build_evidence_pack` or `trace_lifecycle` for verification, gap filling, or unsupported topic boundaries.
- Freshness checks: use `validate_pack.py` before reusing older pack roots, lifecycle evidence packs, or atlas pages. Treat validator errors as stop-and-rebuild signals.
- Durable handoff or review: call the local answer harness to generate the bounded prompt and validate the drafted Markdown answer.

## Canonical Answer Workflow

Use canonical answers as the first evidence layer only after freshness and quality checks:

1. Validate pack freshness before trusting canonical artifacts.
2. Call `find_canonical_answers` for natural-language questions, or `list_canonical_answers` when filtering by priority, mode, or quality status.
3. Prefer canonical answers with `quality.status == pass` and zero validation warnings.
4. Inspect `quality.md` and `gaps.md` before making polished claims.
5. Use live retrieval with `search_functions`, `get_function`, `get_neighbors`, or `trace_lifecycle` to verify high-impact claims and fill gaps.
6. Cite canonical topic id, EA, function name, and artifact path for important claims.

Decision matrix:

| State | Action |
| --- | --- |
| canonical pass + fresh pack | Use as first evidence layer, then verify high-impact claims. |
| canonical degraded + fresh pack | Use only with explicit caveats and live verification of gaps. |
| canonical fail + fresh pack | Do not use as final-answer evidence; use only as a tuning or retrieval hint. |
| canonical missing + fresh pack | Run live retrieval or generate the missing topic bundle. |
| canonical present + stale pack | Rebuild or warn before use; stale canonical artifacts do not override fresh corpus evidence. |

If a review queue exists, prefer topics with `review_state == approved` and
`quality.status == pass`. Treat pass without approval as generated but
unreviewed, not as human-reviewed truth. Treat stale approvals as review debt.

Canonical answers never override fresher function artifacts. If live retrieval contradicts a canonical draft, cite the fresh evidence and call out the canonical artifact as stale, degraded, or needing regeneration.

## Evidence Discipline

- Cite EA, function name, and artifact path for important claims.
- Separate confirmed corpus evidence from inference.
- Treat lifecycle phase labels and LLM rename suggestions as hypotheses until supported by function evidence or edges.
- Expect broad graph-neighbor lifecycle candidates from another object topic to be lower-quality unless the evidence pack records exact seed or target-topic evidence.
- State gaps from skipped functions, missing exact seeds, missing edges, stale packs, or low-confidence phase assignments.
- Do not claim a transition is proven unless the evidence pack contains a supporting edge or function relationship.
- Do not hide validator errors. Rebuild stale packs or derived artifacts before answering, unless the user explicitly wants a stale-pack comparison.
- Treat answer harness warnings as citation lint that must be reviewed before reusing an answer.
- Treat canonical quality status as retrieval quality metadata: `pass` can be used as the first evidence layer, `degraded` requires explicit caveats and live verification, and `fail` is not final-answer evidence.
- For drift answers, cite both pack labels or roots, canonical topic id, function name, both EAs when relevant, and artifact paths from both sides. Do not describe different EAs as semantic drift unless function evidence or selected role/edge/phase changes support that inference.
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

Atlas hub lists are filtered retrieval hints. Generic helpers and subsystem-unrelated neighbors may be intentionally absent; use `get_neighbors` for exhaustive graph expansion.

## Guardrails

- Do not copy generated ntoskrnl data into this skill.
- Do not rely on memory or generic Windows behavior when corpus evidence is available.
- Do not treat cleaned pseudocode as perfect; inspect raw/summary artifacts when precision matters.
- Do not hide uncertainty. A useful kernel answer can say "unknown from this corpus" and propose the next retrieval.
