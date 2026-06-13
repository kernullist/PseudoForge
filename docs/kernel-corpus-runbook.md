# Kernel Corpus Runbook

This runbook explains how to use the PseudoForge Kernel Corpus tooling after a
large IDA batch run has produced corpus artifacts. The tooling is a
consumer-side analysis layer under `tools/kernel_corpus/`; it does not modify
the IDB and does not belong under `ida_pseudoforge/`.

For a user-facing install and daily usage walkthrough, start with
[`docs/kernel-corpus-install-usage.md`](kernel-corpus-install-usage.md), then
return to this runbook for detailed operator commands and edge-case handling.

## Purpose

Use this workflow when an agent or analyst needs target-specific answers such
as:

```text
Explain the process object lifecycle in this ntoskrnl build using major
functions as evidence.
```

The answer must be grounded in the current corpus, not generic Windows
internals memory. Important claims should follow this rule:

```text
Claim -> EA -> function name -> artifact path -> inference level
```

## Paths

Source corpus root:

```text
F:\kernullist\analysis-ouput\ntoskrnl
```

Repo-local smoke pack root:

```text
F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl
```

Long-term research pack root:

```text
F:\pseudoforge-corpora\<target>
```

`pseudoforge_out/` is ignored by Git. Use it for local smoke runs, generated
evidence packs, atlas pages, and local prompt handoff documents. Do not commit
large generated corpora, SQLite packs, ntoskrnl reports, or goal prompt
documents.

## Build A Pack

Build or refresh the SQLite pack from an existing PseudoForge corpus:

```powershell
python -B .\tools\kernel_corpus\builder.py `
  --corpus-root "F:\kernullist\analysis-ouput\ntoskrnl" `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --overwrite `
  --json
```

Expected output files:

```text
<pack-root>\manifest.json
<pack-root>\corpus.sqlite
```

The manifest records the source corpus path, source index hash, target path,
function count, skipped count, PseudoForge version, pack schema, and generated
time.

## Check Status

Before trusting an existing pack, run the freshness validator:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --include-derived `
  --format text
```

For machine-readable automation:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --include-derived `
  --format json
```

The validator fails on clear pack inconsistencies: missing `manifest.json`,
missing `corpus.sqlite`, unsupported schemas, SQLite `corpus_manifest` rows
that differ from `manifest.json`, source-index hash mismatch when the source
index is accessible, and function/count mismatches. It warns when an external
source path cannot be verified.

Derived artifact checks are optional. Use `--include-derived` to scan the
default evidence-pack and atlas directories, or pass focused paths:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --evidence-pack "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\evidence-packs\process_object.json" `
  --atlas-page "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\reports\atlas\process.md" `
  --format text
```

Regenerate packs, lifecycle evidence packs, atlas pages, and answer prompts
when the validator reports stale source hashes or derived artifacts older than
the pack manifest.

Check pack health before answering broad questions:

```powershell
python -B .\tools\kernel_corpus\query.py status `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl"
```

Review:

- `manifest.function_count`
- `manifest.unique_ea_count`
- `manifest.skipped_count`
- `counts.functions`
- `counts.call_edges`
- `counts.function_fts`
- `warnings`

A warning about mismatched source index hashes means the manifest and SQLite
metadata disagree. Rebuild the pack before relying on it.

## Query Functions

Search by term, tag, and optional name regex:

```powershell
python -B .\tools\kernel_corpus\query.py search `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --query "create process" `
  --tag process_thread `
  --limit 20
```

Fetch one function by EA:

```powershell
python -B .\tools\kernel_corpus\query.py get-function `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --ea 0x140001000
```

Traverse callers and callees:

```powershell
python -B .\tools\kernel_corpus\query.py neighbors `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --ea 0x140001000 `
  --direction both `
  --depth 2 `
  --limit 100
```

Search import and string references:

```powershell
python -B .\tools\kernel_corpus\query.py search-import `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --query PsSetCreateProcessNotifyRoutine

python -B .\tools\kernel_corpus\query.py search-string `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --query Process
```

## Build Focused Evidence Packs

For hand-picked functions:

```powershell
python -B .\tools\kernel_corpus\query.py build-evidence-pack `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --topic process_object_manual `
  --ea 0x140001000 `
  --ea 0x140002000 `
  --output "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\evidence-packs\process_object_manual.json"
```

The evidence pack is the answer boundary for focused analysis. Agents should
cite the pack and the underlying function artifacts.

## Build And Validate Answer Prompts

Use the answer harness when handing an evidence pack to an AI model or checking
that a drafted answer preserved the evidence chain:

```powershell
python -B .\tools\kernel_corpus\answer_harness.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --evidence-pack "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\evidence-packs\process_object.json" `
  --question "Explain how process objects are created, published, notified, exited, and deleted in this ntoskrnl build." `
  --atlas-page process.md `
  --prompt-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answer-prompts\process_object.md" `
  --answer-in "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answers\process_object.md" `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answer-reports\process_object.json"
```

`--answer-in` is optional. Without it, the harness only writes or returns the
bounded prompt. With it, the harness emits warning-only validation JSON for:

- major-function bullets that mention a known function without its EA
- bullets that omit the function name
- claims that lack a nearby artifact path from the evidence pack
- answers that omit gaps or uncertainty when the evidence pack has gaps

Generated prompts, answers, and validation reports are derived research
artifacts. Keep them under `pseudoforge_out/` or an external corpus folder; do
not commit them.

## Build Canonical Answer Artifacts

Use the canonical answer generator when you want a durable batch of
evidence-grounded baseline answers rather than a one-off prompt. The topic
catalog lives in:

```text
tools\kernel_corpus\canonical_topics.json
```

The quality expectation manifest lives in:

```text
tools\kernel_corpus\canonical_expectations.json
```

List the catalog:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py list `
  --priority P0

python -B .\tools\kernel_corpus\canonical_answers.py list `
  --priority P1

python -B .\tools\kernel_corpus\canonical_answers.py list `
  --priority P2
```

Build the core P0/P1 bundles for a pack:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --priority P0 `
  --priority P1 `
  --force
```

Build the broader P2 curation tier separately when you want operational
coverage beyond the minimum core answer set:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --priority P2 `
  --force
```

Default output:

```text
<pack-root>\canonical-answers
```

Each topic directory contains:

```text
answer.md
candidate-review.md
evidence-pack.json
gaps.md
manifest.json
prompt.md
source-map.md
trace.json
validation.json
```

`answer.md` is a validated baseline, not a final human-reviewed conclusion.
Validation is citation lint: it proves that major claims keep the EA, function
name, artifact path, and gap/uncertainty discipline. It does not prove that the
selected candidates are the best semantic candidates.

Run the canonical audit before promoting a generated bundle:

```powershell
python -B .\tools\kernel_corpus\canonical_audit.py `
  --canonical-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers" `
  --format text `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers\quality-report.json"
```

Audit only the P2 curation tier:

```powershell
python -B .\tools\kernel_corpus\canonical_audit.py `
  --canonical-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers" `
  --priority P2 `
  --format text `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers\quality-report-p2.json"
```

The audit is candidate-quality lint. It checks generated topic bundles against
reviewable expectations: required and suspicious function-name regexes,
preferred and suspicious tags, selected-function count, edge coverage,
lifecycle phase coverage, validation warnings, source-reference coverage, and
source identity. It emits:

```text
<canonical-root>\quality-report.json
<canonical-root>\quality-report.md
<topic-dir>\quality.json
<topic-dir>\quality.md
```

Generated quality reports are derived research artifacts. Keep them under the
ignored pack root or another external corpus workspace. Neither answer
validation nor canonical audit replaces expert review; inspect
`candidate-review.md`, `gaps.md`, and `quality.md` before treating the answer
as a polished analysis result.

Expectation tuning rules:

- Put only concrete function-name patterns in `required_name_regexes`.
- Treat constants, status codes, macros, inline aliases, structure names, and
  absent private routine names as bonus context, source-map context, or explicit
  gaps instead of required function matches.
- Prefer current corpus tag names when setting `preferred_tags`; public
  subsystem names are useful for topic search, but they may not be actual pack
  tags.
- Keep suspicious regexes active for noisy wrapper families. Passing audit
  topics can still contain review actions when the candidate list deserves
  manual inspection.

Local ntoskrnl smoke after the P0/P1 catalog was added:

```text
topics=39
P0=24
P1=15
passed=39
failed=0
validation warnings=0
generated files=353
```

Local ntoskrnl smoke after the first canonical audit tuning pass:

```text
topics=39
P0=24
P1=15
audit pass=39
audit degraded=0
audit fail=0
answer validation warnings=0
```

Local ntoskrnl smoke after P2 topic expansion:

```text
total catalog topics=75
P0=24
P1=15
P2=36
P2 build passed=36
P2 build failed=0
P2 audit pass=36
P2 audit degraded=0
P2 audit fail=0
P2 answer validation warnings=0
```

## Answer From Canonical Artifacts

When canonical answer artifacts exist, agents should inspect them before
running broad live retrieval. The MCP server exposes these read-only tools:

```text
list_canonical_answers(pack_root?, priority?, status?, mode?, max_topics?)
get_canonical_answer(pack_root?, topic_id, include_answer?, include_quality?, include_gaps?, max_chars?)
get_canonical_quality_report(pack_root?, priority?, status?, max_topics?, max_chars?)
find_canonical_answers(pack_root?, query, priority?, status?, max_topics?)
```

Recommended agent workflow:

1. Validate pack freshness.
2. Call `list_canonical_answers` or `find_canonical_answers` for the user's
   topic.
3. If a passing canonical answer exists, call `get_canonical_answer` and
   inspect `quality.md` and `gaps.md` before drafting.
4. Use `search_functions`, `get_function`, `get_neighbors`, or
   `trace_lifecycle` only to verify high-impact claims, fill gaps, or answer
   questions outside the canonical topic boundary.
5. Cite the canonical topic id plus EA, function name, and artifact path for
   important claims.

Passing canonical answers are preferred over degraded answers. Degraded topics
can still be inspected when the question explicitly needs that area, but the
answer should state the quality caveat and verify gaps with live retrieval.
Failed topics should be treated as diagnostic retrieval hints, not final
answer material.

For local debugging without MCP, use the canonical store helper:

```powershell
python -B .\tools\kernel_corpus\canonical_store.py list `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --status pass `
  --max-topics 20

python -B .\tools\kernel_corpus\canonical_store.py find `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --query "remote process access" `
  --max-topics 5

python -B .\tools\kernel_corpus\canonical_store.py get `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --topic process_object_lifecycle `
  --quality `
  --gaps `
  --max-chars 12000

python -B .\tools\kernel_corpus\canonical_store.py report `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --status pass `
  --max-topics 20
```

The helper and MCP tools only read files under `<pack-root>\canonical-answers`.
Topic ids are identifiers, not paths, and returned Markdown is bounded by
`max_chars`.

Operator decision matrix:

| State | Operator action |
| --- | --- |
| canonical pass + fresh pack | Use the answer as the first evidence layer, inspect `quality.md` and `gaps.md`, then verify high-impact claims against live function artifacts. |
| canonical degraded + fresh pack | Use only with explicit caveats; inspect gaps and rerun live search, `get_function`, `get_neighbors`, or `trace_lifecycle` before finalizing. |
| canonical fail + fresh pack | Do not use as final answer material; treat it as a tuning hint for expectations, seeds, tags, or retrieval ranking. |
| canonical missing + fresh pack | Run live retrieval immediately, or generate the missing topic bundle with `canonical_answers.py build`. |
| canonical present + stale pack | Rebuild the pack or regenerate canonical bundles before use; stale canonical artifacts never override fresh corpus evidence. |

Rerun live lifecycle/search when:

- `quality.status` is `degraded` or `fail`
- `validation_warning_count` is nonzero
- `gaps.md` lists missing seeds, weak edges, skipped functions, or ambiguous
  phase assignments
- the user asks outside the canonical topic boundary
- the freshness validator reports stale pack or derived-artifact state
- `get_function` or `get_neighbors` shows fresher evidence that contradicts
  the canonical draft

Regenerate stale bundles after rebuilding a pack:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --priority P0 `
  --priority P1 `
  --priority P2 `
  --force

python -B .\tools\kernel_corpus\canonical_audit.py `
  --canonical-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers" `
  --format text `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers\quality-report.json"
```

When preparing a model prompt manually, pass canonical answer excerpts only as
explicit canonical context, not as unquestioned truth. Preserve the answer
contract: claim -> EA -> function name -> artifact path -> inference level.

## Review Canonical Answer Production Queue

Use the review queue when the canonical catalog is too large to inspect topic
directories one by one. The queue is deterministic and read-only by default:

```powershell
python -B .\tools\kernel_corpus\canonical_review_queue.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --format markdown `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\canonical-answers\review-queue.md"

python -B .\tools\kernel_corpus\canonical_review_queue.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --status degraded `
  --format json
```

Default generated report paths:

```text
<canonical-root>\review-queue.json
<canonical-root>\review-queue.md
```

The queue separates:

- failing topics
- degraded topics
- missing-quality topics
- passing but unreviewed topics
- approved topics
- stale review decisions

Within those groups, the queue keeps review debt near the top by sorting on
priority, quality status, higher validation warning count, lower quality score,
and topic id.

`quality.status == pass` is not human approval. Human promotion is tracked by
an optional generated decision ledger:

```text
<canonical-root>\review-decisions.json
```

Decision ledger schema:

```json
{
  "schema": "kernel_corpus_canonical_review_decisions_v1",
  "decisions": [
    {
      "topic_id": "process_object_lifecycle",
      "decision": "approved",
      "reviewer": "analyst",
      "reviewed_at": "2026-06-13T00:00:00Z",
      "source_index_sha256": "<pack-source-index-hash>",
      "pack_generated_at": "<pack-generated-at>",
      "notes": "Reviewed candidate list, gaps, and quality report."
    }
  ]
}
```

Supported decisions are `approved`, `needs_review`, `rejected`, and
`superseded`. A stale `approved` decision is not treated as approved when the
topic source hash or pack generation time changes. The queue reports it as a
stale decision with `re_review_source_changed`.

The review queue does not write or mutate `review-decisions.json`. Operators
edit or generate that ledger separately, keep it under the ignored canonical
root, and rerun the queue. Reports and decision ledgers are generated state;
do not commit them.

## Plan A Kernel Answer

Use the answer planner before drafting broad natural-language answers. The
planner is deterministic and read-only: it does not call an LLM, does not write
canonical artifacts, and does not generate final prose.

```powershell
python -B .\tools\kernel_corpus\answer_planner.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --question "이 커널에서 프로세스 오브젝트가 생성되고 사라질 때까지 주요 함수 기준으로 설명해줘" `
  --format markdown `
  --plan-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answer-plans\process_object_lifecycle.md"
```

The plan output schema is:

```text
kernel_corpus_answer_plan_v1
```

The planner routes against:

- generated canonical topic id, title, question, quality, and major functions
- committed canonical topic definitions
- Korean query mappings from the skill
- lifecycle ontology labels
- atlas page names and subsystem tags
- high-confidence function names such as `NtOpenProcess` or
  `MmCopyVirtualMemory`

Quality policy:

- canonical `pass`: use as the first evidence layer, then verify important
  claims with live retrieval
- canonical `degraded`: excluded by default; include only with
  `--allow-degraded`, inspect gaps, and verify live
- canonical `fail` or `missing`: retrieval hint only, not final-answer evidence
- canonical missing: use live lifecycle/search/atlas workflow

Planner output includes selected canonical candidates, excluded canonical hints,
ordered MCP calls, CLI fallbacks, required citations, expected uncertainty
checks, final-answer outline, and stop conditions. Generated plan files belong
under the ignored pack output tree; do not commit them.

MCP equivalent:

```json
{
  "name": "plan_kernel_answer",
  "arguments": {
    "question": "process object lifecycle",
    "max_topics": 3,
    "allow_degraded": false
  }
}
```

Treat the plan as a retrieval contract. Draft the answer only after executing
or inspecting the recommended canonical, lifecycle, function, neighbor, atlas,
or evidence-pack steps.

## Evaluate Answer Workflows

Use the answer eval runner when you want a deterministic regression check for
common kernel-answer workflows. The runner checks routing, canonical topic
selection, fallback tools, required functions, optional drafted answers, gap
discipline, and degraded/stale canonical handling. It does not call a model in
the default path.

```powershell
python -B .\tools\kernel_corpus\answer_eval.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --format markdown `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answer-eval\answer-eval-report.md"
```

The case manifest lives in:

```text
tools\kernel_corpus\answer_eval_cases.json
```

Its schema is:

```text
kernel_corpus_answer_eval_cases_v1
```

The report schema is:

```text
kernel_corpus_answer_eval_report_v1
```

Use `--plans-dir` when another session has already produced planner JSON files
named `<case-id>.json`. Use `--answers-dir` when another session has drafted
Markdown answers named `<case-id>.md` or `<case-id>.markdown`:

```powershell
python -B .\tools\kernel_corpus\answer_eval.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --plans-dir "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answer-plans" `
  --answers-dir "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answers" `
  --format json `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\answer-eval\answer-eval-report.json"
```

Status interpretation:

- `pass`: routing and supplied answer checks met the case contract.
- `degraded`: routing checks were usable, but optional final-answer evidence
  was missing or incomplete. A default run without `--answers-dir` normally
  lands here.
- `fail`: the workflow violated the case contract, such as missing an expected
  canonical topic, using an unsupported fallback, omitting required functions,
  missing required citations, hiding gaps, or using degraded/stale canonical
  material without a caveat.

Generated eval reports are derived research artifacts. Keep them under the
ignored pack root or another external corpus workspace; do not commit them.

## Export A Knowledge Graph

Use the knowledge graph exporter when an agent needs to navigate relationships
across canonical topics, lifecycle packs, atlas pages, functions, phases, tags,
imports, strings, and generated artifact paths. The graph is compact and
bounded by default. It is not a full-kernel graph dump.

```powershell
python -B .\tools\kernel_corpus\knowledge_graph.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --priority P0 `
  --include-atlas `
  --include-lifecycle `
  --format markdown `
  --output "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\reports\knowledge-graph.md"
```

The graph schema is:

```text
kernel_corpus_knowledge_graph_v1
```

Default export contents:

- canonical selected functions
- optional lifecycle selected functions from existing evidence packs
- optional atlas page mentions from existing atlas pages
- call edges among selected functions
- top tags, imports, strings, and artifact paths for selected functions

Useful local query helpers:

```powershell
python -B .\tools\kernel_corpus\knowledge_graph.py list-topics `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl"

python -B .\tools\kernel_corpus\knowledge_graph.py topic-functions `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --topic process_object_lifecycle

python -B .\tools\kernel_corpus\knowledge_graph.py function-topics `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --function PspAllocateProcess

python -B .\tools\kernel_corpus\knowledge_graph.py shared-functions `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl"

python -B .\tools\kernel_corpus\knowledge_graph.py topic-path `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --source-topic process_object_lifecycle `
  --target-topic remote_process_access_flow
```

MCP equivalents:

```json
{
  "name": "get_topic_graph",
  "arguments": {
    "topic_id": "process_object_lifecycle",
    "max_nodes": 120,
    "max_edges": 240,
    "include_atlas": true,
    "include_lifecycle": true
  }
}
```

```json
{
  "name": "find_topic_paths",
  "arguments": {
    "source_topic": "process_object_lifecycle",
    "target_topic": "remote_process_access_flow",
    "max_paths": 5
  }
}
```

```json
{
  "name": "get_function_roles",
  "arguments": {
    "ea_or_name": "PspAllocateProcess",
    "max_topics": 10
  }
}
```

Generated graph reports should live under `pseudoforge_out/` or an external
research pack root. Treat graph centrality, shared-function counts, and bridge
functions as navigation signals only. Important claims still require EA,
function name, and artifact path evidence from canonical answers, evidence
packs, or `get_function`.

## Compare Canonical Drift

Use the canonical drift comparator when you need to explain what changed
between two Windows kernel builds or two revisions of the same Kernel Corpus
pack. The comparator is deterministic and read-only for both pack roots. It
compares topic catalogs, canonical quality metadata, selected evidence
functions, phase assignments, and call edges by normalized function name.

Do not compare EAs as stable cross-build identity. EAs are reported only as
build-local evidence attached to the same function name.

```powershell
python -B .\tools\kernel_corpus\canonical_compare.py `
  --pack-root-a "F:\pseudoforge-corpora\ntoskrnl-old" `
  --pack-root-b "F:\pseudoforge-corpora\ntoskrnl-new" `
  --label-a old `
  --label-b new `
  --topic process_object_lifecycle `
  --format markdown `
  --report-out "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\drift\process_object_lifecycle.md"
```

The report schema is:

```text
kernel_corpus_canonical_drift_v1
```

The comparator reports:

- topics present in both packs, missing in A, and missing in B
- priority, mode, title, quality status, score, validation-warning, selected
  function count, edge count, and gap-count changes
- same normalized function name with different build-local EA
- selected functions added or removed
- lifecycle/focused phase assignment changes
- call-edge additions and removals by function-name pair
- artifact path pairs for same-name selected functions
- source identity for each pack: target path, source corpus root, source index
  path/hash, function count, skipped count, generated time, and schema

The comparator warns when canonical quality reports are missing or when a
canonical topic's source hash or pack generation time does not match its pack
manifest.

MCP equivalents:

```json
{
  "name": "compare_canonical_answers",
  "arguments": {
    "pack_root_a": "F:\\pseudoforge-corpora\\ntoskrnl-old",
    "pack_root_b": "F:\\pseudoforge-corpora\\ntoskrnl-new",
    "topic_id": "process_object_lifecycle",
    "max_topics": 5
  }
}
```

```json
{
  "name": "get_canonical_drift_report",
  "arguments": {
    "pack_root_a": "F:\\pseudoforge-corpora\\ntoskrnl-old",
    "pack_root_b": "F:\\pseudoforge-corpora\\ntoskrnl-new",
    "topic_id": "process_object_lifecycle",
    "max_chars": 12000
  }
}
```

Generated drift reports should live under `pseudoforge_out/` or an external
research folder. The comparator rejects report paths inside either compared
pack root so it does not mutate the packs being compared. Do not commit drift
reports.

## Trace Lifecycles

Trace a process object lifecycle:

```powershell
python -B .\tools\kernel_corpus\lifecycle.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --topic process_object `
  --depth 2 `
  --output "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\evidence-packs\process_object.json"
```

Trace a thread object lifecycle:

```powershell
python -B .\tools\kernel_corpus\lifecycle.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --topic thread_object `
  --depth 2 `
  --output "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\evidence-packs\thread_object.json"
```

Supported lifecycle topics:

```text
process_object
thread_object
file_object
driver_object
device_object
registry_key
section_object
module_image
```

Use the same command shape for the other topics:

```powershell
python -B .\tools\kernel_corpus\lifecycle.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --topic file_object `
  --depth 2 `
  --output "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\evidence-packs\file_object.json"
```

Treat phase labels as corpus-backed hypotheses. If the evidence pack reports
missing exact seeds, weak edges, skipped functions, or low-confidence phases,
state those gaps in the final answer.

Lifecycle selection favors exact seed and target-topic evidence. Broad-term or
graph-neighbor candidates whose names clearly belong to another lifecycle topic
are demoted rather than treated as equal lifecycle evidence.

## Generate The Atlas

Generate deterministic subsystem maps:

```powershell
python -B .\tools\kernel_corpus\atlas.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --output-dir "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\reports\atlas"
```

Expected pages:

```text
driver-load-unload.md
etw-wmi.md
io-manager.md
memory.md
object-manager.md
process.md
registry.md
security.md
thread.md
```

Use atlas pages for discovery and orientation. Do not treat them as final
proof; inspect referenced functions and evidence packs for important claims.
Atlas hub lists are relevance-filtered. Generic helpers, validation wrappers,
feature-flag probes, and subsystem-irrelevant neighbors are intentionally
suppressed so the hub section stays useful for review.

## Profile Scale Behavior

Use the performance profiler after query, lifecycle, atlas, or schema/index
changes:

```powershell
python -B .\tools\kernel_corpus\perf_profile.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --lifecycle-max-seeds 32 `
  --lifecycle-depth 2 `
  --atlas-output-dir "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl\reports\atlas-perf" `
  --atlas-limit 24
```

Profile pack build separately when a source corpus is available:

```powershell
python -B .\tools\kernel_corpus\perf_profile.py `
  --build-corpus-root "F:\kernullist\analysis-ouput\ntoskrnl" `
  --build-pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl-perf-indexed" `
  --overwrite-build `
  --lifecycle-max-seeds 32 `
  --lifecycle-depth 2 `
  --atlas-output-dir "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl-perf-indexed\reports\atlas-perf" `
  --atlas-limit 24
```

The profiler emits `kernel_corpus_performance_profile_v1` JSON with timings for:

- `pack_build`
- `status`
- `text_search`
- `tag_search`
- `neighbor_traversal`
- `lifecycle_tracing`
- `atlas_generation`

Observed local smoke on the 29,964-function ntoskrnl pack:

| Operation | Before tuning | After indexed rebuild and query tuning |
| --- | ---: | ---: |
| Status | ~3.7 s | ~12 ms |
| Text search | ~270 ms | ~33 ms |
| Tag search | ~136 ms | ~25 ms |
| Neighbor traversal, depth 2, limit 120 | ~1.2 s | ~21 ms |
| Lifecycle, `process_object`, max seeds 32, depth 2 | ~90 s | ~15 s |
| Atlas, 9 pages, limit 24 | ~45 s | ~16 s |
| Pack build, 29,964 functions and 123,081 edges | not measured before | ~13 s |

Recommended interactive bounds:

- Keep normal search limits at 20 to 50. Raise toward 200 only for review
  sessions where result breadth matters more than latency.
- Use lifecycle `--max-seeds 32 --depth 2` for first-pass answers. Raise depth
  only after inspecting gaps or ambiguous edges.
- Use atlas `--limit 24` for the default subsystem map. Raise toward 80 only
  for offline report refreshes.
- Rebuild older packs with the current builder before judging neighbor or
  lifecycle performance; the builder creates indexes for tag lookup and reverse
  call-edge traversal.
- Do not replace structured SQLite retrieval with fuzzy model search. Use FTS,
  exact name lookup, bounded graph traversal, and evidence packs as the primary
  path.

## Experimental Vector Recall

Vector recall is optional and experimental. It is a secondary discovery booster
only; SQLite, exact EA lookup, and artifact citations remain authoritative.
Do not enable it in normal MCP operation unless the user explicitly asks for
the experiment.

Build an experimental index from bounded function metadata:

```powershell
python -B .\tools\kernel_corpus\experimental\vector_recall.py build-index `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl"
```

By default the index is written under:

```text
<pack-root>\experimental\vector_recall\vector-index.json
```

That path is generated state. Do not commit vector indexes or embedding
databases. The repo `.gitignore` also ignores `vector-index.json` files under
`experimental\vector_recall`.

The index stores vectors plus metadata only. It does not store full source
text. Indexed text is bounded to:

- function name
- tags
- terms
- interesting lines
- cleaned excerpt

Run vector-only candidate recall:

```powershell
python -B .\tools\kernel_corpus\experimental\vector_recall.py query `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --query "process object rundown delete" `
  --limit 20 `
  --min-score 0.65
```

Run the merge/rerank experiment:

```powershell
python -B .\tools\kernel_corpus\experimental\vector_recall.py merge `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl" `
  --query "process object rundown delete" `
  --tag process_thread `
  --limit 20 `
  --vector-limit 40 `
  --vector-min-score 0.65
```

Merged recall combines:

- exact name hits
- tag hits
- FTS hits
- vector hits

Every vector result must resolve back to:

```text
EA -> function name -> SQLite function payload -> artifact paths
```

Do not answer directly from embedding text or vector scores. Treat vector hits
as candidates to inspect with `get_function`, `get_neighbors`, lifecycle
evidence packs, or the answer harness.

Known risks:

- Semantic false positives, especially when one function mentions another in
  interesting lines.
- Stale embeddings after pack rebuilds. Rebuild the vector index when the pack
  manifest source hash changes.
- Model or backend version drift. Query output warns when backend name/version
  differs from index metadata.
- Cost and local storage if a real embedding backend replaces the deterministic
  token-hash experiment backend.
- Recall bias from bounded excerpts. Missing text in the vector index is not
  evidence that a function is irrelevant.

Local bounded smoke with the deterministic token-hash backend showed the
plumbing works, but it did not prove semantic lift for broad lifecycle queries:
with `--max-functions 5000`, `process object rundown delete` produced no
high-confidence vector-only hits at the default `--min-score 0.65`, while the
merged result fell back to FTS and tag candidates. Lowering the threshold is
useful for diagnostics but quickly exposes false positives, so a real embedding
backend must be evaluated before treating vector recall as a meaningful
semantic booster.

## Run The MCP Server

Start the read-only stdio MCP server:

```powershell
python -B .\tools\kernel_corpus\mcp_server.py `
  --pack-root "F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\ntoskrnl"
```

Generate a copy-ready MCP config snippet for a client config file:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py mcp-config `
  --pack-root "F:\pseudoforge-corpora\ntoskrnl-26200.8457"
```

The output keeps a generic `mcpServers` block and adds
`clientSnippets.claudeCode` plus `clientSnippets.codex` so the operator can copy
the exact client-specific command or TOML block.

Generic MCP JSON shape:

```json
{
  "mcpServers": {
    "pseudoforge-kernel-corpus": {
      "command": "python",
      "args": [
        "-B",
        "F:\\kernullist\\PseudoForge\\tools\\kernel_corpus\\mcp_server.py",
        "--pack-root",
        "F:\\pseudoforge-corpora\\ntoskrnl-26200.8457"
      ]
    }
  }
}
```

Claude Code CLI registration:

```powershell
claude mcp add --transport stdio --scope local pseudoforge-kernel-corpus -- `
  python -B "F:\kernullist\PseudoForge\tools\kernel_corpus\mcp_server.py" `
  --pack-root "F:\pseudoforge-corpora\ntoskrnl-26200.8457"

claude mcp list
```

Use `--scope user` when the same machine-local corpus should be available to
Claude Code outside this project. Avoid project scope unless you intentionally
want to share a project MCP config.

Codex CLI registration:

```powershell
codex mcp add pseudoforge-kernel-corpus -- `
  python -B "F:\kernullist\PseudoForge\tools\kernel_corpus\mcp_server.py" `
  --pack-root "F:\pseudoforge-corpora\ntoskrnl-26200.8457"

codex mcp list
```

Codex can also read the server from `%USERPROFILE%\.codex\config.toml`:

```toml
[mcp_servers.pseudoforge-kernel-corpus]
command = "python"
args = ["-B", "F:\\kernullist\\PseudoForge\\tools\\kernel_corpus\\mcp_server.py", "--pack-root", "F:\\pseudoforge-corpora\\ntoskrnl-26200.8457"]
cwd = "F:\\kernullist\\PseudoForge"
startup_timeout_sec = 10
tool_timeout_sec = 60
```

Use an explicit pack root per target. Do not bake one permanent ntoskrnl path
into the skill or MCP server. Start a new Claude Code or Codex session after
changing MCP configuration.

Implemented tools:

- `corpus_status`
- `search_functions`
- `get_function`
- `get_neighbors`
- `search_by_import`
- `search_by_string`
- `build_evidence_pack`
- `trace_lifecycle`
- `generate_atlas`
- `list_atlas_pages`
- `get_atlas_page`
- `list_canonical_answers`
- `get_canonical_answer`
- `get_canonical_quality_report`
- `find_canonical_answers`
- `plan_kernel_answer`
- `compare_canonical_answers`
- `get_canonical_drift_report`
- `get_topic_graph`
- `find_topic_paths`
- `get_function_roles`

The server returns compact JSON with EAs, function names, artifact paths,
selection reasons, warnings, and bounded excerpts. It should not return large
cleaned pseudocode blobs by default.

Atlas MCP tool arguments:

```json
{
  "name": "generate_atlas",
  "arguments": {
    "pack_root": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl",
    "output_dir": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl\\reports\\atlas",
    "limit": 24
  }
}
```

```json
{
  "name": "list_atlas_pages",
  "arguments": {
    "pack_root": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl"
  }
}
```

```json
{
  "name": "get_atlas_page",
  "arguments": {
    "pack_root": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl",
    "page": "process.md",
    "max_chars": 12000
  }
}
```

`pack_root` is optional for these tools when the MCP server was already started
with the target pack root. `generate_atlas` still requires an explicit
`output_dir`; relative output paths are resolved under `pack_root`, and absolute
output paths must stay under `pack_root`. Generated atlas files remain derived
artifacts under the pack output tree. `get_atlas_page` accepts a page filename,
not an arbitrary path, and returns bounded Markdown plus a `truncated` flag.

Knowledge graph MCP tool arguments:

```json
{
  "name": "get_topic_graph",
  "arguments": {
    "pack_root": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl",
    "topic_id": "process_object_lifecycle",
    "max_nodes": 120,
    "max_edges": 240,
    "include_atlas": true,
    "include_lifecycle": true
  }
}
```

```json
{
  "name": "find_topic_paths",
  "arguments": {
    "pack_root": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl",
    "source_topic": "process_object_lifecycle",
    "target_topic": "remote_process_access_flow",
    "max_paths": 5
  }
}
```

```json
{
  "name": "get_function_roles",
  "arguments": {
    "pack_root": "F:\\kernullist\\PseudoForge\\pseudoforge_out\\kernel_corpus\\ntoskrnl",
    "ea_or_name": "PspAllocateProcess",
    "max_topics": 10
  }
}
```

These graph tools rebuild a compact in-memory graph from existing pack,
canonical, lifecycle, and atlas artifacts. They do not generate canonical
answers, lifecycle packs, or atlas pages.

## Use The Skill

The source skill instructions live here:

```text
tools\kernel_corpus\skills\kernel-corpus-analysis\SKILL.md
```

Use the skill when asking an agent to answer lifecycle, subsystem, function,
callgraph, import/string, or evidence-pack questions from a kernel corpus. The
skill contains retrieval procedure and answer contracts only; it does not
contain corpus data.

Run `tools\kernel_corpus\validate_pack.py` before relying on an older pack,
then use the skill for retrieval and answer discipline.

For durable answer handoff, combine the skill with
`tools\kernel_corpus\answer_harness.py` so the final prompt and validation
report are reproducible.

Plan the copy target without writing anything:

```powershell
$SkillRoot = "$env:USERPROFILE\.claude\skills"   # Claude Code
# $SkillRoot = "$env:USERPROFILE\.codex\skills" # Codex

python -B .\tools\kernel_corpus\install_wiring.py skill-plan `
  --target-root $SkillRoot
```

Install the skill into an explicit skill root:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py install-skill `
  --target-root $SkillRoot `
  --apply
```

Update the installed copy from the repo source:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py install-skill `
  --target-root $SkillRoot `
  --replace `
  --apply
```

Uninstall the copied skill:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py uninstall-skill `
  --target-root $SkillRoot `
  --apply
```

The helper is dry-run by default. It only writes or removes files when
`--apply` is present, and it only operates on the direct
`kernel-corpus-analysis` child under the selected target root. Tests should use
a temporary `--target-root`; do not write into a user's global skill directory
during validation.

The Kernel Corpus skill and MCP server are operational add-ons, not IDA plugin
runtime dependencies. Keep them under `tools/kernel_corpus/`, keep generated
packs under ignored or external output roots, and keep normal PseudoForge IDA
plugin packaging independent of MCP availability.

## Package Release Assets

For large corpus distribution, publish split archives as GitHub Release assets
in the dedicated `kernullist/kernel-corpus` artifact repository instead of
committing the corpus or archive parts into Git history. PseudoForge code
releases should not carry corpus packages. The local packaging helper writes:

```text
artifact-manifest.json
checksums.sha256
README-install.md
<artifact-id>.tar.gz.001
<artifact-id>.tar.gz.002
...
```

Package a corpus release:

```powershell
python -B .\tools\kernel_corpus\package_release.py `
  --pack-root "F:\pseudoforge-corpora\ntoskrnl-26200.8457" `
  --source-corpus-root "F:\kernullist\analysis-ouput\ntoskrnl" `
  --artifact-id ntoskrnl-26200.8457-amd64-r1 `
  --output-dir "F:\kernel-corpus-release-staging" `
  --github-repo kernullist/kernel-corpus `
  --install-root "F:\pseudoforge-corpora" `
  --volume-size 1900m
```

The helper is relocation-safe by default. It archives a temporary staged copy
of `kernel-pack` whose JSON, Markdown, manifest `sqlite_path`, and SQLite
`corpus_manifest` pack-root references are rewritten for:

```text
<install-root>\<artifact-id>\kernel-pack
```

Keep this default for public releases. Use `--no-relocate-pack` only for local
debug packages that must preserve the source pack's absolute paths.

Upload the generated assets:

```powershell
gh release create ntoskrnl-26200.8457-amd64-r1 `
  --repo kernullist/kernel-corpus `
  --title "Kernel Corpus ntoskrnl-26200.8457-amd64-r1" `
  --notes-file "F:\kernel-corpus-release-staging\ntoskrnl-26200.8457-amd64-r1\README-install.md" `
  "F:\kernel-corpus-release-staging\ntoskrnl-26200.8457-amd64-r1\ntoskrnl-26200.8457-amd64-r1.tar.gz.*" `
  "F:\kernel-corpus-release-staging\ntoskrnl-26200.8457-amd64-r1\artifact-manifest.json" `
  "F:\kernel-corpus-release-staging\ntoskrnl-26200.8457-amd64-r1\checksums.sha256" `
  "F:\kernel-corpus-release-staging\ntoskrnl-26200.8457-amd64-r1\README-install.md"
```

Install a release package by downloading all assets, comparing hashes with
`checksums.sha256`, creating the install root if needed, reassembling the split
archive with `copy /b`, extracting with `tar -xzf`, and pointing MCP at
`<install-root>\<artifact-id>\kernel-pack`.

## Freshness Rules

Rebuild the pack when any of these changes:

- `pseudoforge-corpus-index.json`
- source corpus root
- per-function artifact set
- PseudoForge version used for the source run
- builder schema or import behavior

Regenerate lifecycle evidence packs and atlas pages after rebuilding the pack.
Generated reports contain timestamps and should be considered derived from the
pack that existed at generation time.

## Validation

Run the focused Kernel Corpus test suite:

```powershell
python -B -m pytest `
  tests/test_kernel_corpus_bootstrap.py `
  tests/test_kernel_corpus_builder.py `
  tests/test_kernel_corpus_query.py `
  tests/test_kernel_corpus_mcp_contract.py `
  tests/test_kernel_corpus_lifecycle.py `
  tests/test_kernel_corpus_skill.py `
  tests/test_kernel_corpus_atlas.py `
  tests/test_kernel_corpus_answer_harness.py `
  tests/test_kernel_corpus_validate_pack.py `
  tests/test_kernel_corpus_install_wiring.py `
  tests/test_kernel_corpus_perf_profile.py `
  tests/test_kernel_corpus_vector_recall.py `
  tests/test_kernel_corpus_canonical_answers.py `
  tests/test_kernel_corpus_canonical_audit.py `
  tests/test_kernel_corpus_canonical_compare.py `
  tests/test_kernel_corpus_canonical_review_queue.py `
  tests/test_kernel_corpus_answer_planner.py `
  tests/test_kernel_corpus_knowledge_graph.py `
  tests/test_kernel_corpus_answer_eval.py `
  tests/test_kernel_corpus_package_release.py
```

For documentation-only edits, also run:

```powershell
git diff --check -- .
```

## Troubleshooting

- Missing `manifest.json` or `corpus.sqlite`: rebuild the pack.
- Validator `source_index_hash_mismatch`: rebuild the pack from the current
  source corpus before trusting query, lifecycle, atlas, or answer outputs.
- Validator derived-artifact stale errors: regenerate lifecycle evidence packs,
  atlas pages, and answer prompts from the current pack.
- Empty FTS results: check `counts.function_fts`; SQLite FTS5 may be disabled
  in the local Python build.
- Missing exact lifecycle seeds: inspect the ontology seed names and search by
  broader terms or tags.
- Weak lifecycle edges: increase `--depth` within the bounded limit and inspect
  `neighbors` around high-confidence functions.
- Stale atlas page: regenerate the atlas after pack rebuild.
- Answer harness citation warnings: add EA, function name, and artifact path to
  each major-function bullet; add a gaps section when the evidence pack has
  gaps or uncertainty notes.
- Canonical audit failures: inspect `quality.md` for missing required
  functions, forbidden or suspicious candidates, missing lifecycle phases, weak
  edge coverage, validation warnings, stale source identity, and tuning actions.
- Planner selected no canonical topic: follow the live retrieval steps and
  state that canonical coverage was unavailable or not quality-eligible.
- Answer eval `degraded` with `answer_not_provided`: provide `--answers-dir`
  when final drafted Markdown should be checked; routing-only eval without
  answers is intentionally degraded rather than failed.
- Answer eval missing required functions: inspect the selected canonical topic,
  live retrieval plan, and case regexes. Update retrieval or expectations only
  when the pack evidence supports the change.
- Answer eval stale/degraded warnings: regenerate or audit canonical artifacts,
  or add an explicit caveat and live verification before using that material.
- Answer eval report path rejected: keep `--report-out` under `<pack-root>` or
  write to the default `<pack-root>\answer-eval` location.
- Canonical drift report shows same-name different-EA changes: treat the EA as
  build-local evidence, not a cross-build identity mismatch by itself.
- Canonical drift warnings mention missing or stale quality files: regenerate
  or audit canonical answers for that pack before using the topic as approved
  evidence.
- Knowledge graph has no topics: generate or copy canonical answers into
  `<pack-root>\canonical-answers`, or intentionally use live retrieval without
  graph context.
- Knowledge graph optional-input warnings: `--include-atlas` and
  `--include-lifecycle` only read existing atlas pages and evidence packs; they
  do not generate them.
- Knowledge graph bridge or centrality output looks important: treat it as a
  retrieval hint, then verify with `get_function`, canonical answers, or an
  evidence pack before making a claim.
- Release package extraction leaves no `kernel-pack`: confirm the split parts
  were reassembled in order and extracted under the intended install root.
- Very broad answers: build or inspect an evidence pack first, then answer from
  the pack instead of scanning the full corpus ad hoc.
