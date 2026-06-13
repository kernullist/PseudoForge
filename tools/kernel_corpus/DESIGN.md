# Kernel Corpus MCP Design

## Purpose

Build a separate, evidence-grounded kernel corpus toolchain on top of
PseudoForge IDA batch artifacts. The tool lets an AI agent answer questions
such as:

```text
Explain how process objects are created, published, notified, exited, and
deleted in this ntoskrnl build, using the major functions as evidence.
```

The tool must not teach the model to answer from generic Windows internals
memory alone. It should retrieve target-specific evidence from the generated
PseudoForge corpus, assemble a compact evidence pack, and let the AI produce a
grounded explanation with EA, function name, and artifact citations.

## Placement

Keep this project separate from the installed IDA plugin code.

```text
tools/
  kernel_corpus/
    DESIGN.md
    answer_planner.py
    answer_harness.py
    atlas.py
    builder.py
    canonical_answers.py
    canonical_audit.py
    canonical_compare.py
    canonical_review_queue.py
    canonical_store.py
    canonical_expectations.json
    canonical_topics.json
    ea.py
    errors.py
    install_wiring.py
    lifecycle.py
    mcp_server.py
    paths.py
    perf_profile.py
    query.py
    schema.py
    store.py
    validate_pack.py
    experimental/
      __init__.py
      vector_recall.py
    ontology/
      process_object.json
      thread_object.json
      file_object.json
      driver_object.json
      device_object.json
      registry_key.json
      section_object.json
      module_image.json
    skills/
      kernel-corpus-analysis/
        SKILL.md
```

Do not put MCP code under `ida_pseudoforge/`. The IDA plugin should remain the
producer of deterministic artifacts. `tools/kernel_corpus/` should be the
consumer-side analysis and retrieval layer.

Large generated packs must not be committed. Recommended output locations:

```text
F:\pseudoforge-corpora\<target>\
F:\kernullist\analysis-ouput\<target>\
F:\kernullist\PseudoForge\pseudoforge_out\kernel_corpus\<target>\
```

`pseudoforge_out/` is already ignored and is suitable for smoke output. Long
term research corpora should live outside the repo.

## Inputs

The first implementation should work without IDA. It consumes an existing
PseudoForge corpus directory:

```text
<corpus-root>/
  pseudoforge-corpus-index.json
  pseudoforge-corpus-overview.md
  pseudoforge-corpus-metadata.json
  pseudoforge-ida-run.json
  pseudoforge-ida-summary*.json
  <target>.forge
  functions/
    <EA>_<safe-name>/
      *.ida-batch-summary.json
      *.cleaned.cpp
      *.raw.cpp
      *.raw-vs-cleaned.diff
      *.rename-map.json
      *.rule-report.json
      *.warnings.json
      *.buffer-contracts.json
```

The source of truth for retrieval is:

1. `pseudoforge-corpus-index.json`
2. Per-function summary and artifact files
3. Aggregate `.forge` sections when direct artifacts are missing
4. Corpus metadata only when it matches the current corpus state

The recent ntoskrnl run showed why the index and per-function artifacts should
be treated as authoritative after merges: metadata can become stale after a
partial retry or aborted run.

## Outputs

The builder creates a compact knowledge pack:

```text
<pack-root>/
  manifest.json
  corpus.sqlite
  evidence-packs/
    <topic>.json
  answer-prompts/
    <topic>.md
  answer-reports/
    <topic>.json
  reports/
    corpus-status.md
    atlas/
      process.md
      thread.md
      object-manager.md
      ...
```

`corpus.sqlite` is the main MCP backing store. JSON files remain available for
debugging, portability, and handoff to other agents.

## Architecture

### Current v1 status

The implementation is complete through Phase 23:

1. Pack builder imports PseudoForge corpus indexes into SQLite.
2. Query CLI exposes status, search, function lookup, neighbor traversal,
   import/string search, and focused evidence-pack generation.
3. MCP stdio server wraps the read-only query, lifecycle, and atlas tools.
4. Lifecycle tracer supports reviewable process, thread, file, driver, device,
   registry key, section, and module/image ontologies.
5. `kernel-corpus-analysis` skill documents the evidence-grounded agent
   workflow.
6. Subsystem atlas generation emits deterministic Markdown pages for major
   kernel subsystems.
7. The runbook documents build, query, MCP, lifecycle, atlas, freshness, and
   generated-output boundaries.
8. MCP atlas tools generate, list, and return bounded atlas Markdown pages.
9. Expanded lifecycle ontologies cover additional object and subsystem flows.
10. The answer harness turns evidence packs into bounded AI prompts and checks
    answer Markdown for missing EA, function-name, artifact-path, and gap
    discipline warnings.
11. The pack freshness validator checks manifest, SQLite, source-index hash,
    function counts, lifecycle evidence packs, and atlas metadata before an
    operator or agent trusts derived artifacts.
12. Real ntoskrnl review tuned lifecycle and atlas ranking: cross-topic
    lifecycle candidates are penalized unless exact evidence keeps them in
    scope, and atlas hubs suppress generic helpers or subsystem-irrelevant
    neighbors.
13. Install wiring emits copy-ready MCP config snippets and dry-run-first skill
    install, update, and uninstall plans without mixing the tooling into the
    IDA plugin package.
14. Performance profiling and targeted scale tuning cover pack build, status,
    search, tag lookup, neighbors, lifecycle tracing, and atlas generation on
    full-kernel packs.
15. Experimental vector recall lives under an explicit opt-in experimental
    package, resolves every vector hit back to SQLite function payloads, and
    keeps generated vector indexes outside committed repo state by default.
16. Canonical answer generation catalogs P0/P1/P2 kernel-analysis topics and
    emits reviewable answer bundles with evidence packs, traces, prompts,
    answer drafts, source maps, candidate reviews, gaps, and validation
    reports under the ignored pack output tree.
17. Canonical answer quality audit checks generated P0/P1/P2 answer bundles
    against reviewable golden expectations, writes ignored quality reports,
    and feeds deterministic candidate-quality metadata back into generated
    artifacts.
18. The P2 curation tier adds broad operational topics across process
    protection, handle duplication, jobs, ALPC, tokens, ACLs, code integrity,
    registry hives, file names, VADs, PFNs, system threads, APC/context
    surfaces, debug ports, ETW/WMI, object types, push locks, lookaside lists,
    pool tracking, IRP cancellation, unload hazards, device interfaces, PnP,
    power, boot-start drivers, hypervisor/VSL, enclaves, hotpatching, cache
    manager sections, and Timer2 paths.
19. Canonical answer artifacts are exposed through read-only MCP tools and a
    local `canonical_store.py` helper, so agents can list, find, inspect, and
    quality-check generated canonical answers before falling back to live
    retrieval.
20. The agent workflow now treats canonical answers as a first evidence layer
    only after freshness and quality checks, with an explicit pass/degraded/fail
    and stale-artifact decision matrix in the skill and runbook.
21. Canonical answer production review queues summarize generated topics by
    audit quality and human review decision state without mutating source code
    or generated decision ledgers.
22. A deterministic answer planner maps natural-language kernel questions to
    canonical candidates, live retrieval steps, citation requirements, and
    stop conditions before an agent drafts prose.
23. A cross-pack canonical drift comparator explains how canonical topics,
    selected evidence functions, phase labels, call edges, quality status, and
    source identity differ between two Kernel Corpus packs without treating EAs
    as stable cross-build identities.

Generated packs and reports remain intentionally outside Git.

### 1. Pack Builder

Build command:

```powershell
python -B .\tools\kernel_corpus\builder.py `
  --corpus-root "F:\kernullist\analysis-ouput\ntoskrnl" `
  --pack-root "F:\pseudoforge-corpora\ntoskrnl-26200.8457"
```

Responsibilities:

1. Validate corpus completeness.
2. Hash the corpus index and key artifact files.
3. Import functions, tags, terms, call edges, imports, strings, warnings, and
   buffer-contract counts into SQLite.
4. Build FTS5 tables for function name, tags, terms, interesting lines, and
   cleaned excerpts.
5. Build call graph tables from `caller_eas` and `callee_eas`.
6. Store artifact paths without copying large source files by default.
7. Emit `manifest.json` with source corpus path, target path, PseudoForge
   version, counts, input hashes, and generated time.

### 2. SQLite Store

Minimum tables:

```sql
CREATE TABLE corpus_manifest (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE functions (
    ea TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    directory TEXT NOT NULL,
    summary_path TEXT NOT NULL,
    cleaned_path TEXT,
    raw_path TEXT,
    diff_path TEXT,
    mode TEXT,
    llm_status TEXT,
    warning_count INTEGER NOT NULL DEFAULT 0,
    buffer_contract_count INTEGER NOT NULL DEFAULT 0,
    cleaned_excerpt TEXT
);

CREATE TABLE function_tags (
    ea TEXT NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (ea, tag)
);

CREATE TABLE call_edges (
    src_ea TEXT NOT NULL,
    dst_ea TEXT NOT NULL,
    edge_kind TEXT NOT NULL,
    PRIMARY KEY (src_ea, dst_ea, edge_kind)
);

CREATE TABLE function_imports (
    ea TEXT NOT NULL,
    import_name TEXT NOT NULL
);

CREATE TABLE function_strings (
    ea TEXT NOT NULL,
    string_value TEXT NOT NULL
);

CREATE VIRTUAL TABLE function_fts USING fts5(
    ea UNINDEXED,
    name,
    tags,
    terms,
    imports,
    strings,
    interesting_lines,
    cleaned_excerpt
);
```

Keep schema additions additive. MCP clients should tolerate missing optional
columns and use `manifest.json` for feature checks.

### 3. Domain Ontology

The ontology is a small, reviewable seed layer. It should not hardcode answers.
It only tells the retriever where to start.

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

Example `ontology/process_object.json` shape:

```json
{
  "schema": "kernel_corpus_lifecycle_ontology_v1",
  "topic": "process_object",
  "labels": ["process", "eprocess", "process object"],
  "tags": ["process", "process_thread", "object_manager"],
  "seed_names": [
    "NtCreateUserProcess",
    "NtCreateProcessEx",
    "PspAllocateProcess",
    "PspInsertProcess",
    "PspExitProcess",
    "PspProcessDelete"
  ],
  "seed_terms": [
    "EPROCESS",
    "Process",
    "CreateProcess",
    "ExitProcess",
    "ProcessDelete",
    "PsSetCreateProcessNotifyRoutine"
  ],
  "phases": {
    "entry": {
      "seed_names": ["NtCreateUserProcess"],
      "name_terms": ["NtCreate", "ZwCreate"],
      "terms": ["create process"],
      "tags": ["process_thread"]
    }
  }
}
```

The ontology should be generic across Windows builds. The MCP must still
retrieve and cite target-specific functions before answering.

### 4. MCP Server

The MCP server is a read-only interface over the pack.

Implemented v1 tools:

```text
corpus_status(pack_root)
search_functions(pack_root, query, tags, name_regex, limit)
get_function(pack_root, ea, include_excerpt, include_artifacts)
get_neighbors(pack_root, ea, direction, depth, limit)
search_by_import(pack_root, import_query, limit)
search_by_string(pack_root, string_query, limit)
build_evidence_pack(pack_root, eas, topic, output_path)
trace_lifecycle(pack_root, topic, max_seeds, depth, output_path)
generate_atlas(pack_root, output_dir, limit)
list_atlas_pages(pack_root)
get_atlas_page(pack_root, page, max_chars)
list_canonical_answers(pack_root, priority, status, mode, max_topics)
get_canonical_answer(pack_root, topic_id, include_answer, include_quality, include_gaps, max_chars)
get_canonical_quality_report(pack_root, priority, status, max_topics, max_chars)
find_canonical_answers(pack_root, query, priority, status, max_topics)
plan_kernel_answer(pack_root, question, max_topics, allow_degraded)
compare_canonical_answers(pack_root_a, pack_root_b, topic_id, priority, max_topics)
get_canonical_drift_report(pack_root_a, pack_root_b, topic_id, max_chars)
```

Optional later tools:

```text
explain_cluster(pack_root, tag)
find_bridge_functions(pack_root, source_tag, target_tag)
```

Every MCP result should return compact structured data:

```json
{
  "ea": "0x14093A130",
  "name": "NtSetInformationProcess",
  "tags": ["dispatch", "memory", "process_thread"],
  "summary_path": "...",
  "cleaned_path": "...",
  "why_selected": ["name match", "process_thread tag", "caller edge"],
  "confidence": 0.82
}
```

Avoid returning large cleaned pseudocode by default. Return excerpts and paths,
then let the agent call `get_function` for details.

## Lifecycle Tracing

`trace_lifecycle` is the key high-value feature.

Input:

```json
{
  "topic": "process_object",
  "max_seeds": 32,
  "depth": 2
}
```

Algorithm:

1. Load ontology seeds for the topic.
2. Search exact names first.
3. Search FTS for seed terms and Korean/English synonyms.
4. Rank candidates by:
   - exact name match
   - exported or well-known `Nt*`, `Zw*`, `Ps*`, `Psp*`, `Ob*`, `Mm*`, `Se*`
     role
   - matching tags
   - caller/callee proximity to already selected seeds
   - warning and buffer evidence as secondary signals
5. Expand call graph one or two hops.
6. Assign phase labels using ontology phase hints and local evidence:
   - `entry`
   - `allocate`
   - `initialize`
   - `publish`
   - `notify`
   - `steady_state`
   - `exit`
   - `rundown`
   - `delete`
7. Build an evidence pack with selected functions, phase labels, edges,
   excerpts, artifacts, and uncertainty notes.
8. Return the evidence pack path plus a compact summary for the agent.

The first version can be heuristic. It does not need perfect whole-kernel
understanding. It needs to be evidence-preserving, explainable, and easy to
correct.

Selection should preserve exact seed hits, but broad-term and graph-neighbor
candidates are penalized when their name clearly belongs to another lifecycle
topic, such as thread-only helpers inside a process-object trace. This keeps
generic object-manager seeds available while reducing cross-object leakage.

## Evidence Pack Schema

Evidence packs are small, durable JSON files that the AI can load for a single
question.

```json
{
  "schema": "kernel_corpus_evidence_pack_v1",
  "topic": "process_object",
  "pack_root": "F:\\pseudoforge-corpora\\ntoskrnl-26200.8457",
  "created_at": "2026-06-12T00:00:00Z",
  "status": {
    "corpus_complete": true,
    "function_count": 29964,
    "skipped_count": 77
  },
  "phases": [
    {
      "id": "entry",
      "title": "User/API entry",
      "functions": [
        {
          "ea": "0x...",
          "name": "NtCreateUserProcess",
          "role": "Primary user-mode process creation syscall",
          "confidence": 0.9,
          "evidence": [
            {
              "kind": "cleaned_excerpt",
              "path": "...cleaned.cpp",
              "text": "..."
            }
          ],
          "inference_notes": []
        }
      ]
    }
  ],
  "edges": [
    {
      "src_ea": "0x...",
      "dst_ea": "0x...",
      "edge_kind": "callee"
    }
  ],
  "gaps": [
    "Some object-manager final dereference transitions may require deeper graph expansion."
  ]
}
```

The evidence pack is the answer boundary. The AI should cite it and the
underlying artifact paths.

## Answer Harness

`tools/kernel_corpus/answer_harness.py` is the local bridge between a retrieved
evidence pack and an AI answer. It does not call a model. It builds a bounded
prompt that contains corpus identity, evidence-pack summary, selected
functions, selected edges, gaps, optional atlas context, and the answer
contract. It deliberately avoids copying full raw corpus contents into the
prompt.

Validation mode reads a Markdown answer and emits warning-only JSON. It checks
that major-function bullets include the EA and function name, that an artifact
path from the evidence pack appears near the claim, and that answers include a
gaps or uncertainty section when the evidence pack records gaps.

Example:

```powershell
python -B .\tools\kernel_corpus\answer_harness.py `
  --pack-root "<pack-root>" `
  --evidence-pack "<pack-root>\evidence-packs\process_object.json" `
  --question "Explain this kernel's process object lifecycle." `
  --atlas-page process.md `
  --prompt-out "<pack-root>\answer-prompts\process_object.md" `
  --answer-in "<pack-root>\answers\process_object.md" `
  --report-out "<pack-root>\answer-reports\process_object.json"
```

Prompt and report files are derived artifacts. Store them under the ignored
pack output tree or another external research folder, not in Git.

## Canonical Answer Artifacts

`tools/kernel_corpus/canonical_topics.json` is the durable catalog of
canonical kernel-analysis topics. P0 covers core ntoskrnl object, I/O, memory,
security, callback, dispatch, and synchronization flows. P1 covers security
and anti-cheat oriented overlays such as remote process access, identity
sources, token impersonation, callback inventories, telemetry, verifier
classes, low-resource paths, and deadlock risks. P2 is the broader curation
tier for operational analyst questions that are useful but not required for
the minimum core answer set.

`tools/kernel_corpus/canonical_answers.py` turns the catalog into generated
artifact bundles. Each topic directory contains:

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

Lifecycle topics reuse ontology-driven `trace_lifecycle`. Focused topics use a
bounded mix of exact-name lookup, text search, tag search, and candidate
scoring before building a normal evidence pack. Every generated `answer.md`
passes the same evidence-chain validator used by `answer_harness.py`; passing
validation means the draft preserves EA, function name, artifact path, and gap
discipline. It does not mean every candidate is semantically final.

Example:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root "<pack-root>" `
  --priority P0 `
  --priority P1 `
  --force
```

For the broad curation tier:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root "<pack-root>" `
  --priority P2 `
  --force
```

Default output:

```text
<pack-root>\canonical-answers
```

Generated canonical answer bundles are research artifacts. Keep them under the
ignored pack root or another external corpus workspace.

`tools/kernel_corpus/canonical_expectations.json` is the reviewable golden
expectation layer for the current P0/P1/P2 catalog. It defines required, bonus,
forbidden, and suspicious function-name regexes; preferred and suspicious tags;
minimum selected-function counts; minimum edge counts; required lifecycle
phases; validation-warning ceilings; and source-reference coverage.
Required function regexes must match concrete function names that can appear in
an evidence pack. Status codes, macros, inline aliases, structure names, and
private routine names absent from the corpus belong in bonus context,
source-map context, or explicit gaps rather than required-name checks.

`tools/kernel_corpus/canonical_audit.py` is deterministic candidate-quality
lint for generated canonical answer bundles. It reads each topic's
`manifest.json`, `evidence-pack.json`, `trace.json`, `validation.json`,
`candidate-review.md`, `source-map.md`, and `gaps.md`, then emits status,
score, missing required functions, suspicious candidates, forbidden candidates,
missing phases, weak edge coverage, validation warnings, gap counts, source
identity warnings, and recommended tuning actions.

Example:

```powershell
python -B .\tools\kernel_corpus\canonical_audit.py `
  --canonical-root "<pack-root>\canonical-answers" `
  --format text `
  --report-out "<pack-root>\canonical-answers\quality-report.json"
```

P2-only audit is supported for curation runs:

```powershell
python -B .\tools\kernel_corpus\canonical_audit.py `
  --canonical-root "<pack-root>\canonical-answers" `
  --priority P2 `
  --format text `
  --report-out "<pack-root>\canonical-answers\quality-report-p2.json"
```

Generated quality reports live under the ignored canonical answer root:

```text
<canonical-root>\quality-report.json
<canonical-root>\quality-report.md
<topic-dir>\quality.json
<topic-dir>\quality.md
```

Answer validation is citation lint. Canonical audit is candidate-quality lint.
Neither replaces expert review of `candidate-review.md`, `gaps.md`, and the
underlying corpus artifacts.

`tools/kernel_corpus/canonical_store.py` is the read-only access layer for
generated canonical answer artifacts. It locates `<pack-root>\canonical-answers`,
reads root `index.json` and `quality-report.json` when present, scans topic
manifests, and returns compact metadata plus bounded Markdown sections. It
also provides local debugging commands:

```powershell
python -B .\tools\kernel_corpus\canonical_store.py list --pack-root "<pack-root>"
python -B .\tools\kernel_corpus\canonical_store.py find --pack-root "<pack-root>" --query "remote process access"
python -B .\tools\kernel_corpus\canonical_store.py get --pack-root "<pack-root>" --topic process_object_lifecycle
python -B .\tools\kernel_corpus\canonical_store.py report --pack-root "<pack-root>"
```

The MCP server wraps the same helper through `list_canonical_answers`,
`get_canonical_answer`, `get_canonical_quality_report`, and
`find_canonical_answers`. These tools are read-only. Topic ids are validated as
identifiers, index-provided directories must remain under the canonical root,
and returned text is bounded by `max_chars`. Agents should prefer canonical
topics with `quality.status == pass` and zero validation warnings, inspect
degraded topics only with caveats, and use live search/function/neighborhood or
lifecycle tools for verification and gap filling.

Canonical answer workflow decision matrix:

| State | Action |
| --- | --- |
| canonical pass + fresh pack | Use as first evidence layer, inspect quality and gaps, then verify high-impact claims. |
| canonical degraded + fresh pack | Use only with explicit caveats and live verification of gaps. |
| canonical fail + fresh pack | Do not use as final-answer evidence; use only as tuning or retrieval hints. |
| canonical missing + fresh pack | Run live retrieval or generate the missing topic bundle. |
| canonical present + stale pack | Rebuild or warn before use; stale artifacts do not override fresh corpus evidence. |

The workflow is intentionally conservative. Canonical artifacts guide the
answer, but fresh corpus evidence from `get_function`, `get_neighbors`,
`search_functions`, or `trace_lifecycle` wins when it contradicts a generated
draft.

`tools/kernel_corpus/canonical_review_queue.py` turns a generated canonical
answer tree into an operator queue. It reads topic manifests, quality reports,
validation reports, evidence packs, and an optional
`<canonical-root>\review-decisions.json` ledger. It emits
`kernel_corpus_canonical_review_queue_v1` payloads with pack identity, source
identity, quality status, validation warning count, gap count, selected major
functions, important artifact paths, review decision state, stale-decision
flags, and suggested review actions.

Queue ordering is deterministic and review-debt oriented: priority first,
then quality status, higher validation warning count, lower quality score, and
topic id.

The review queue is read-only by default. `--report-out` writes bounded
generated reports under the canonical root:

```text
<canonical-root>\review-queue.json
<canonical-root>\review-queue.md
```

The optional decision ledger has schema
`kernel_corpus_canonical_review_decisions_v1` and supports `approved`,
`needs_review`, `rejected`, and `superseded`. A generated pass is never treated
as human approval. Approved decisions become stale when their recorded source
hash or pack generation time no longer matches the topic artifact.

### Answer Planner

`tools/kernel_corpus/answer_planner.py` is the read-only routing layer between
natural-language questions and Kernel Corpus evidence workflows. It emits
`kernel_corpus_answer_plan_v1` payloads and never calls a model or drafts the
final answer.

Planner inputs:

```text
--pack-root
--question
--max-topics
--allow-degraded
--format json|text|markdown
--plan-out
```

The planner matches the question against generated canonical topic metadata,
the committed canonical topic manifest, Korean query mappings from the skill,
lifecycle ontology labels, atlas subsystem pages, subsystem tags, and
high-confidence kernel function names. It prefers canonical topics only when
quality status allows it: `pass` topics are selected by default, `degraded`
topics are selected only with `--allow-degraded`, and failed or missing topics
remain retrieval hints.

The plan includes:

- pack freshness recommendation and validator command
- routing hints such as lifecycle topic, atlas page, tags, and function names
- selected canonical candidates and excluded canonical hints
- ordered MCP calls and local CLI fallbacks
- citation contract
- final-answer outline
- stop conditions and warnings

The MCP server exposes the same read-only planner as:

```text
plan_kernel_answer(pack_root?, question, max_topics?, allow_degraded?)
```

The MCP tool returns compact JSON only and does not generate prose answers.

### Canonical Drift Compare

`tools/kernel_corpus/canonical_compare.py` compares canonical answer artifacts
and live pack metadata across two pack roots. It emits
`kernel_corpus_canonical_drift_v1` payloads and treats each pack as read-only.

Inputs:

```text
--pack-root-a
--pack-root-b
--label-a
--label-b
--topic
--priority
--status
--max-topics
--format json|text|markdown
--report-out
```

The comparator uses stable cross-build anchors:

- canonical topic id, title, mode, priority, and quality status
- normalized selected function name
- selected function role, tag, phase, and artifact path
- call edges represented as function-name pairs
- source corpus root, source index path/hash, target path, function count,
  skipped count, generated time, and schema

EAs are included as build-local evidence only. A same-name/different-EA result
does not imply a semantic rename by itself; it means the same normalized
function name resolved to a different address in each pack.

The report surfaces:

- topics present in both packs, missing in A, and missing in B
- priority, mode, title, quality status, score, validation warning, selected
  function count, edge count, and gap-count changes
- selected functions added or removed by normalized name
- phase assignment changes
- call-edge additions and removals by function-name pair
- artifact path pairs for same-name selected functions
- missing or stale canonical quality files

`--report-out` may write JSON, text, or Markdown outside the compared pack
roots. It rejects parent traversal and rejects outputs inside either pack root
so the comparison does not mutate the packs being compared. Generated drift
reports belong under `pseudoforge_out/` or an external research folder.

The MCP server exposes compact read-only drift helpers:

```text
compare_canonical_answers(pack_root_a, pack_root_b, topic_id?, priority?, max_topics?)
get_canonical_drift_report(pack_root_a, pack_root_b, topic_id?, max_chars?)
```

## Pack Freshness Validator

`tools/kernel_corpus/validate_pack.py` is the preflight gate for pack reuse. It
returns JSON by default and has a human-readable text mode for operator checks.
The validator does not mutate the source corpus, the pack, or derived
artifacts.

It fails on clear inconsistencies:

- missing pack root, `manifest.json`, or `corpus.sqlite`
- unsupported manifest schema or pack schema
- `corpus_manifest` rows that differ from `manifest.json`
- accessible source index hash that differs from
  `manifest.source_index_sha256`
- manifest function/count metadata that differs from SQLite tables
- derived evidence or atlas metadata that clearly points to a different pack
  or an older pack generation

It warns when freshness cannot be proven, such as an inaccessible external
source index path or missing optional generated-time metadata.

Example:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root "<pack-root>" `
  --include-derived `
  --format text
```

For focused checks, pass `--evidence-pack` and `--atlas-page` explicitly
instead of scanning the default derived-artifact directories.

## Skill Layer

The skill should be small. It should not contain the ntoskrnl corpus. It should
teach the agent how to use the MCP.

Skill location:

```text
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
```

Core skill rules:

1. Use MCP before answering kernel lifecycle, subsystem, or flow questions.
2. Prefer target-specific evidence over generic Windows internals knowledge.
3. Cite EA, function name, and artifact path for important claims.
4. Separate confirmed evidence from inference.
5. Build an evidence pack for broad questions.
6. For lifecycle questions, call `trace_lifecycle` first.
7. Run `validate_pack.py` before trusting an old pack or derived artifacts.
8. For supported broad topics, call canonical answer tools before running live
   retrieval; use live retrieval to verify, fill gaps, or handle unsupported
   topic boundaries.
8. For durable handoff or review, run `answer_harness.py` to produce the
   prompt and warning report.
9. If the corpus is partial or stale, state the limitation.

## Answer Contract

For a lifecycle question, the agent should answer in this shape:

```markdown
Overall flow:
1. Entry
2. Allocation and initialization
3. Object insertion and visibility
4. Notification side paths
5. Exit and rundown
6. Final dereference and delete

Major functions:
- `0x...` `FunctionName`: role and evidence path.

Confirmed from this corpus:
- Target-specific observations.

Inference:
- Clearly marked reasoning that connects evidence.

Gaps:
- Missing edges, skipped functions, or ambiguous transitions.
```

No answer should claim that a transition is proven unless the evidence pack
contains the supporting function or edge.

The answer harness enforces this contract as lint-style warnings. A warning is
not proof the answer is wrong, but it marks claims that need citation,
uncertainty, or manual review before reuse.

## Example Flow

User asks:

```text
In this kernel, explain the process object lifecycle from creation to deletion.
```

Agent workflow:

1. `validate_pack.py --pack-root <pack-root> --include-derived`
2. `corpus_status(pack_root)`
3. `trace_lifecycle(pack_root, "process_object", depth=2)`
4. `get_function` for the highest-impact functions in each phase
5. Optionally `get_neighbors` around ambiguous edges
6. Build a bounded prompt with `answer_harness.py`
7. Produce an evidence-grounded narrative with citations
8. Validate the answer with `answer_harness.py --answer-in`

The final answer should read like a kernel reverse-engineering report, not a
generic OS textbook explanation.

## Install Wiring

`tools/kernel_corpus/install_wiring.py` keeps installation repeatable while
preserving the separation between the IDA plugin producer and the Kernel Corpus
consumer tooling.

Implemented commands:

```text
skill-plan
install-skill
uninstall-skill
mcp-config
```

Rules:

1. Skill installation is dry-run by default and requires `--apply` before it
   writes or removes files.
2. Update requires explicit `--replace --apply` so an existing installed skill
   is not overwritten accidentally.
3. Tests must pass a temporary `--target-root` and must not write into the
   user's global `%USERPROFILE%\.codex\skills` tree.
4. MCP config generation requires an explicit pack root or leaves a visible
   `<PACK_ROOT>` placeholder.
5. Normal IDA plugin packaging must not depend on MCP, installed skills, or
   generated kernel corpus packs.

## Performance And Scale

`tools/kernel_corpus/perf_profile.py` measures the major interactive and
offline paths:

```text
pack_build
status
text_search
tag_search
neighbor_traversal
lifecycle_tracing
atlas_generation
```

Targeted optimizations are evidence-preserving:

1. Builder-created indexes cover function names, tag lookup by tag, reverse
   call-edge traversal, and value joins.
2. Status uses the manifest FTS row count when available instead of scanning
   the FTS virtual table on every status call.
3. Search uses FTS for excerpt/term search when available and keeps `LIKE`
   fallback for names and non-FTS packs.
4. Bulk search and neighbor traversal return artifact paths without checking
   the filesystem for every candidate; direct `get_function` and evidence-pack
   generation still report missing artifact warnings.
5. Lifecycle seed-term discovery can request excerpts in the first search
   result, avoiding repeated function fetches during candidate validation.
6. Atlas generation reuses repeated search and neighbor results within one
   generation pass while preserving deterministic output ordering.

Observed local ntoskrnl smoke scale:

```text
functions: 29964
call edges: 123081
status: ~12 ms
text/tag search: ~25-35 ms
neighbor traversal depth 2 limit 120: ~21 ms
process_object lifecycle max seeds 32 depth 2: ~15 s
atlas 9 pages limit 24: ~16 s
pack build with indexes: ~13 s
```

Recommended first-pass bounds are lifecycle `max_seeds=32`, lifecycle
`depth=2`, atlas `limit=24`, and search limits between 20 and 50. Higher
limits remain available for offline review, but agents should first inspect
gaps and evidence quality before widening graph expansion.

## Experimental Vector Recall

Vector recall is a secondary booster, not a replacement for structured
retrieval. The experiment lives under:

```text
tools/kernel_corpus/experimental/vector_recall.py
```

Default generated state lives under the selected pack root:

```text
<pack-root>/experimental/vector_recall/vector-index.json
```

The index contains bounded sparse vector metadata and text hashes, not full
source text. Text sources are limited to function name, tags, terms,
interesting lines, and cleaned excerpt. Query results return candidate EAs,
vector score, source text kind, and a resolved SQLite function payload with
artifact paths.

Merge/rerank combines exact name hits, tag hits, FTS hits, and vector hits. The
rerank score is only a discovery signal; claims still require the normal
evidence contract:

```text
Claim -> EA -> function name -> artifact path -> inference level
```

Risks and controls:

1. Semantic false positives are expected. Vector hits must be inspected, not
   used as answer text.
2. Stale embeddings are detected by comparing the vector index source hash to
   the current pack manifest.
3. Backend/model drift is surfaced as a warning when backend name or version
   differs from index metadata.
4. Cost and storage stay opt-in. The default backend is a deterministic local
   token-hash backend for plumbing experiments, not a production semantic
   embedding model.
5. Token-hash smoke results should be treated as qualitative plumbing checks.
   Broad semantic lift needs a real embedding backend and threshold tuning.
6. Normal MCP and query workflows do not import or require this module.

## Implementation Phases

### Phase 0: Skeleton and design

Deliver:

```text
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Clear separation from `ida_pseudoforge/`.
- No generated corpus checked into the repo.

### Phase 1: SQLite builder

Deliver:

```text
tools/kernel_corpus/builder.py
tools/kernel_corpus/schema.py
tests/test_kernel_corpus_builder.py
```

Acceptance:

- Build `corpus.sqlite` from a PseudoForge corpus index.
- Import function count, tags, artifacts, call edges, imports, strings, and
  FTS rows.
- Validate against the merged ntoskrnl corpus:
  - 29964 indexed functions
  - 29964 unique EAs
  - skipped count preserved as corpus status

### Phase 2: Read-only query CLI

Deliver:

```text
tools/kernel_corpus/query.py
tests/test_kernel_corpus_query.py
```

Acceptance:

- Search by name, term, tag, import, and string.
- Fetch function details by EA.
- Fetch caller/callee neighbors.
- Return compact JSON suitable for MCP wrapping.

### Phase 3: MCP server

Deliver:

```text
tools/kernel_corpus/mcp_server.py
tests/test_kernel_corpus_mcp_contract.py
```

Acceptance:

- Expose the initial MCP tools.
- Keep tools read-only.
- Return bounded result sizes by default.
- Include enough artifact paths for follow-up inspection.

### Phase 4: Lifecycle tracer

Deliver:

```text
tools/kernel_corpus/lifecycle.py
tools/kernel_corpus/ontology/process_object.json
tools/kernel_corpus/ontology/thread_object.json
tests/test_kernel_corpus_lifecycle.py
```

Acceptance:

- Build a process-object evidence pack from the ntoskrnl corpus.
- Assign phase labels with confidence scores.
- Preserve uncertainty rather than inventing missing edges.

### Phase 5: Skill packaging

Deliver:

```text
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
```

Acceptance:

- The skill tells agents to use MCP first.
- It defines the lifecycle answer contract.
- It keeps corpus data out of the skill folder.

### Phase 6: Subsystem atlas

Deliver:

```text
tools/kernel_corpus/atlas.py
```

Acceptance:

- Generate Markdown atlas pages for process, thread, object manager, memory,
  I/O, registry, security, ETW/WMI, and driver load/unload flows.
- Every page cites evidence packs and artifact paths.

### Phase 7: Docs, status, and runbook

Deliver:

```text
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
README.md
```

Acceptance:

- Design file reflects implemented files instead of stale future markers.
- Runbook documents build, status, query, lifecycle, atlas, MCP, skill, and
  generated-output boundaries.
- Follow-up goals are captured as local-only prompt documents under
  `pseudoforge_out/`.

### Phase 8: MCP atlas tools

Deliver:

```text
tools/kernel_corpus/mcp_server.py
tests/test_kernel_corpus_mcp_contract.py
docs/kernel-corpus-runbook.md
```

Acceptance:

- MCP exposes `generate_atlas`, `list_atlas_pages`, and `get_atlas_page`.
- `generate_atlas` writes only to an explicit output directory.
- MCP atlas output directories stay under the selected pack root.
- `list_atlas_pages` returns filename, absolute path, size, last write time,
  and atlas-page detection.
- `get_atlas_page` returns page metadata, bounded Markdown text, and a
  truncation flag.
- Fixture tests cover the atlas MCP contract without requiring a real
  ntoskrnl pack.

### Phase 9: Lifecycle ontology expansion

Deliver:

```text
tools/kernel_corpus/ontology/file_object.json
tools/kernel_corpus/ontology/driver_object.json
tools/kernel_corpus/ontology/device_object.json
tools/kernel_corpus/ontology/registry_key.json
tools/kernel_corpus/ontology/section_object.json
tools/kernel_corpus/ontology/module_image.json
tests/test_kernel_corpus_lifecycle.py
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
docs/kernel-corpus-runbook.md
```

Acceptance:

- New ontologies include schema, topic, labels, seed names, seed terms, tag
  hints, and phase hints.
- Ontologies stay generic across Windows builds and do not hardcode answers.
- Tests validate schema compatibility, topic/file-name match, non-empty
  labels, seeds, tags, and phase hints.
- `trace_lifecycle` can load every supported ontology.
- A synthetic `file_object` graph maps major seed functions to lifecycle
  phases.

### Phase 10: Answer harness

Deliver:

```text
tools/kernel_corpus/answer_harness.py
tests/test_kernel_corpus_answer_harness.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
```

Acceptance:

- Generate a bounded prompt from a fixture evidence pack without embedding raw
  full corpus contents.
- Include corpus identity, evidence summary, selected functions, edges, gaps,
  optional atlas context, and the answer contract.
- Validate Markdown answers with warnings for missing EA, function name,
  nearby artifact path, or required gaps/uncertainty section.
- Keep generated prompts and reports under ignored or external output roots.

### Phase 11: Pack freshness validator

Deliver:

```text
tools/kernel_corpus/validate_pack.py
tests/test_kernel_corpus_validate_pack.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
```

Acceptance:

- Validate pack root, manifest, SQLite, supported schema, SQLite manifest
  rows, source-index hash, and function/count consistency.
- Optionally validate lifecycle evidence-pack schema, pack root, topic,
  generated time, and atlas Markdown metadata.
- Emit machine-readable JSON and human-readable text output.
- Warn on unverifiable external paths and fail only on clear inconsistencies.
- Tests cover fresh, stale, missing, and partial states without requiring the
  real ntoskrnl corpus.

### Phase 12: Lifecycle and atlas quality tuning

Deliver:

```text
tools/kernel_corpus/lifecycle.py
tools/kernel_corpus/atlas.py
tests/test_kernel_corpus_lifecycle.py
tests/test_kernel_corpus_atlas.py
```

Acceptance:

- Regenerate process and thread lifecycle evidence packs on the real ntoskrnl
  smoke pack.
- Regenerate subsystem atlas pages on the real ntoskrnl smoke pack.
- Penalize cross-topic lifecycle graph neighbors without hardcoding ntoskrnl
  names.
- Suppress generic/noisy atlas hubs such as intrinsic memory helpers,
  validation wrappers, feature-flag probes, and subsystem-irrelevant
  neighbors.
- Add fixture regression tests for every heuristic change.

### Phase 13: Skill and MCP install packaging

Deliver:

```text
tools/kernel_corpus/install_wiring.py
tests/test_kernel_corpus_install_wiring.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Document the source skill path, target skill path, install, update, and
  uninstall procedures.
- Emit a copy-ready MCP config snippet with command, args, server path, and
  explicit pack root.
- Keep plugin packaging separate from Kernel Corpus skill, MCP, and generated
  pack outputs.
- Avoid writing into the user's global skill directory during tests.
- Test deterministic helper behavior with temporary target roots.

### Phase 14: Performance and scale pass

Deliver:

```text
tools/kernel_corpus/perf_profile.py
tools/kernel_corpus/query.py
tools/kernel_corpus/store.py
tools/kernel_corpus/lifecycle.py
tools/kernel_corpus/atlas.py
tests/test_kernel_corpus_perf_profile.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Add lightweight timings for pack build, status, text search, tag search,
  neighbor traversal, lifecycle tracing, and atlas generation.
- Profile the local ntoskrnl smoke pack when available.
- Optimize only measured bottlenecks while preserving deterministic ordering
  and evidence quality.
- Add fixture tests for profiler output and changed query behavior.
- Document observed full-kernel scale limits and recommended bounds.

### Phase 15: Secondary vector recall experiment

Deliver:

```text
tools/kernel_corpus/experimental/__init__.py
tools/kernel_corpus/experimental/vector_recall.py
tests/test_kernel_corpus_vector_recall.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
.gitignore
```

Acceptance:

- Keep vector recall disabled unless explicitly invoked.
- Index only bounded text sources: function name, tags, terms, interesting
  lines, and cleaned excerpt.
- Store generated vector metadata under the pack root by default and keep
  vector index JSON ignored by Git.
- Return vector candidates as EAs with vector score, source text kind, and
  resolved SQLite function payloads with artifact paths.
- Add a merge/rerank experiment that combines exact name, tag, FTS, and vector
  sources.
- Document semantic false positives, stale embeddings, backend/model drift,
  cost, local storage, and citation-contract risks.
- Test metadata plumbing with a tiny fake embedding backend.

### Phase 16: Canonical answer artifact generator

Deliver:

```text
tools/kernel_corpus/canonical_topics.json
tools/kernel_corpus/canonical_answers.py
tests/test_kernel_corpus_canonical_answers.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Catalog all P0/P1 canonical kernel-analysis topics in a reviewable manifest.
- Generate per-topic answer bundles under `<pack-root>\canonical-answers`.
- Keep generated bundles out of Git by default.
- Support lifecycle and focused retrieval modes.
- Emit `answer.md`, `evidence-pack.json`, `trace.json`, `prompt.md`,
  `validation.json`, `candidate-review.md`, `source-map.md`, `gaps.md`, and a
  per-topic `manifest.json`.
- Validate generated answer drafts with zero evidence-chain warnings.

### Phase 17: Canonical answer quality audit

Deliver:

```text
tools/kernel_corpus/canonical_expectations.json
tools/kernel_corpus/canonical_audit.py
tools/kernel_corpus/canonical_answers.py
tests/test_kernel_corpus_canonical_audit.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Cover every current P0/P1 canonical answer topic with reviewable quality
  expectations.
- Audit generated answer bundles without model calls or external web access.
- Report pass, degraded, or fail status with stable scores and stable topic
  ordering.
- Detect missing required functions, forbidden or suspicious candidates,
  missing lifecycle phases, weak edge coverage, validation warnings, source
  reference gaps, source identity drift, and generated-artifact gaps.
- Write ignored root-level and per-topic quality reports under
  `<pack-root>\canonical-answers`.
- Keep tuning evidence-based: update expectations for invalid non-function
  requirements, update ontology seeds for real missing lifecycle candidates,
  and update retrieval scoring only when deterministic candidate evidence
  exposes obvious noise.
- Keep normal tests fixture-based and independent of the full ntoskrnl pack.

### Phase 18: Canonical answer topic expansion and curation

Deliver:

```text
tools/kernel_corpus/canonical_topics.json
tools/kernel_corpus/canonical_expectations.json
tools/kernel_corpus/canonical_answers.py
tools/kernel_corpus/canonical_audit.py
tests/test_kernel_corpus_canonical_answers.py
tests/test_kernel_corpus_canonical_audit.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Support P2 priority end to end in manifest loading, listing, generation,
  audit filtering, and audit ordering.
- Add 30 to 60 concrete P2 topics with explicit retrieval seeds, queries,
  tags, and public source-reference anchors.
- Keep every canonical topic covered by exactly one expectation entry.
- Keep required regexes concrete function-name patterns, not constants,
  status codes, macros, structures, or absent aliases.
- Keep normal tests fixture-based while allowing optional local ntoskrnl smoke
  for P2 generation and audit.
- Keep generated P2 answer bundles and quality reports under ignored output
  roots.

### Phase 19: Canonical answer MCP tools

Deliver:

```text
tools/kernel_corpus/canonical_store.py
tools/kernel_corpus/mcp_server.py
tests/test_kernel_corpus_mcp_contract.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
```

Acceptance:

- Expose read-only `list_canonical_answers`, `get_canonical_answer`,
  `get_canonical_quality_report`, and `find_canonical_answers` MCP tools.
- Return absolute artifact paths and bounded Markdown/text payloads.
- Reject topic-id traversal and index-provided directories outside the
  canonical root.
- Preserve default MCP pack-root behavior.
- Keep missing canonical roots inspectable through warnings.
- Cover fixture canonical trees, filtering, ordering, truncation, and path
  safety with tests.

### Phase 20: Agent workflow canonical answer integration

Deliver:

```text
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
pseudoforge_implementation_status.md
tests/test_kernel_corpus_skill.py
```

Acceptance:

- Skill instructions require freshness validation before trusting canonical
  artifacts.
- Agents find/list canonical answers for broad lifecycle, subsystem, and
  security-engineering questions before live retrieval.
- Passing canonical answers are first evidence layer only, not final truth.
- Degraded answers require caveats and live verification.
- Failed answers are diagnostic hints, not final-answer evidence.
- Missing canonical answers trigger live retrieval or explicit bundle
  generation.
- Stale canonical artifacts require rebuild or warning before use.
- Tests lock the workflow phrases and decision matrix without requiring a full
  ntoskrnl pack.

### Phase 21: Canonical production review queue

Deliver:

```text
tools/kernel_corpus/canonical_review_queue.py
tests/test_kernel_corpus_canonical_review_queue.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
pseudoforge_implementation_status.md
```

Acceptance:

- Generate stable JSON, text, and Markdown review queues from
  `<pack-root>\canonical-answers`.
- Support `--pack-root`, optional `--canonical-root`, `--priority`,
  `--status`, `--max-topics`, `--format`, `--report-out`, and
  `--decision-file`.
- Include pack identity, canonical root, source target identity, topic
  metadata, quality status, score, validation warning count, gap count,
  selected major functions, artifact paths, review decision state, and
  suggested review action.
- Keep queue output bounded and deterministic.
- Keep decision ledgers generated and read-only from the queue tool.
- Support `approved`, `needs_review`, `rejected`, and `superseded` decisions.
- Never treat generated audit pass status as human approval.
- Keep stale or mismatched source identity visible, including stale approved
  decisions.
- Reject canonical roots, decision files, and report outputs outside the
  canonical output tree.
- Test pass/degraded/fail/missing topics, missing quality files, decision
  merge ordering, stale approval visibility, Markdown grouping, report writes,
  and path escape rejection.

### Phase 22: Question router and answer planner

Deliver:

```text
tools/kernel_corpus/answer_planner.py
tests/test_kernel_corpus_answer_planner.py
tests/test_kernel_corpus_mcp_contract.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
pseudoforge_implementation_status.md
```

Acceptance:

- Route broad natural-language questions to canonical candidates first when
  quality permits.
- Map Korean process lifecycle wording to `process_object_lifecycle` and live
  `trace_lifecycle` verification.
- Exclude degraded canonical topics by default and include them only with
  explicit degraded-topic allowance.
- Keep failed or missing canonical topics as retrieval hints only.
- Add live retrieval steps for exact or canonical-derived high-confidence
  function names when those functions exist in the pack.
- Return a live retrieval plan for unknown topics instead of an empty answer.
- Emit stable JSON, text, and Markdown without model calls or corpus mutation.
- Add the read-only `plan_kernel_answer` MCP tool.
- Test routing, degraded gating, unknown-topic fallback, stable truncation,
  generated plan path safety, and MCP contract behavior.

### Phase 23: Cross-build canonical drift

Deliver:

```text
tools/kernel_corpus/canonical_compare.py
tests/test_kernel_corpus_canonical_compare.py
tests/test_kernel_corpus_mcp_contract.py
docs/kernel-corpus-runbook.md
tools/kernel_corpus/DESIGN.md
tools/kernel_corpus/skills/kernel-corpus-analysis/SKILL.md
pseudoforge_implementation_status.md
```

Acceptance:

- Compare one canonical topic across two pack roots without mutating either
  pack.
- Compare all topics by priority/topic id with bounded output.
- Report topics missing on either side.
- Report priority, mode, title, quality status, score, validation warning,
  selected-function count, edge count, and gap-count changes.
- Match selected evidence primarily by normalized function name and explain
  same-name/different-EA changes as build-local EA drift.
- Report selected functions added or removed, phase assignment changes, call
  edge additions/removals by function-name pair, and artifact path pairs.
- Include both pack source identities and warn on missing or stale canonical
  quality files.
- Add compact read-only MCP drift tools.
- Keep generated drift reports out of Git and reject report outputs inside
  either compared pack root.
- Test fixture A/B packs for EA drift, quality drift, missing topics, edge
  drift, stable truncation, path safety, and MCP contract behavior.

## Testing Strategy

Use small fixture corpora for unit tests. Do not require the full ntoskrnl
corpus in normal test runs.

Test layers:

1. Schema migration tests.
2. Builder tests with tiny fixture index JSON.
3. Query tests for FTS and graph traversal.
4. MCP contract tests with fixed JSON snapshots.
5. Lifecycle phase assignment tests with synthetic function graphs.
6. Answer harness tests for prompt generation and citation warnings.
7. Pack freshness validator tests for fresh, stale, missing, partial, and
   derived-artifact states.
8. Lifecycle/atlas quality tests for cross-topic penalties and hub filtering.
9. Install wiring tests for dry-run skill plans, explicit temporary target
   roots, update/delete behavior, and MCP config JSON shape.
10. Performance profiler tests for fixture build and retrieval coverage.
11. Vector recall experiment tests with a fake embedding backend.
12. Canonical answer manifest, P2 priority, and fixture-generation tests.
13. Canonical audit expectation, P2 filtering/order, report, and
    scoring-regression tests.
14. Skill and runbook workflow text tests for canonical-answer decision rules.
15. Canonical production review queue tests for quality grouping, decision
    ledger merge, stale approval visibility, report rendering, and path safety.
16. Answer planner tests for Korean routing, canonical quality gates, live
    function search steps, unknown-topic fallback, stable truncation, generated
    plan path safety, and MCP contract behavior.
17. Canonical drift tests for cross-pack catalog, source identity, selected
    function, phase, edge, report truncation, path safety, and MCP contract
    behavior.
18. Optional integration smoke against the real ntoskrnl pack when present.

Integration tests should skip cleanly when the large corpus path is absent.

## Operational Notes

- Keep all generated paths absolute in MCP responses.
- Normalize EAs to uppercase hex like `0x14093A130`.
- Treat missing artifacts as degraded evidence, not fatal errors.
- Never mutate the source PseudoForge corpus from MCP tools.
- Never update the IDB from this tool.
- Keep lifecycle heuristics reviewable as JSON ontology plus Python scoring.
- Run pack freshness validation before reusing old packs, evidence packs, or
  atlas pages.
- Keep skill and MCP install helpers dry-run-first, and require explicit target
  roots in tests.
- Rebuild older packs before judging reverse-neighbor performance; existing
  SQLite files do not gain new builder indexes until rebuilt.
- Keep bulk retrieval bounded and deterministic. Do not suppress low-confidence
  evidence solely to improve timing.
- Keep vector recall opt-in and secondary. Never answer from embedding text or
  vector score alone.
- Call the answer planner before broad natural-language answers when available;
  use the plan as a retrieval contract, not as final prose.
- Treat atlas hubs as relevance-filtered retrieval hints; generic helpers are
  intentionally suppressed from hub lists.
- Treat answer harness validation as citation lint, not final factual proof.
- Treat canonical answer drafts as validated baselines, not polished final
  reverse-engineering conclusions; review candidate lists before reuse.
- Treat canonical quality audit as candidate-quality lint, not expert review.
  Use `quality.md` to decide which retrieval expectations, seeds, tags, or
  ontology phases need tuning.
- Treat passing canonical answers as first evidence layer only. Degraded,
  failed, missing, or stale canonical states must drive caveats, live
  retrieval, regeneration, or tuning before final answers.
- Treat canonical review decisions as generated operator state. Do not commit
  review queues or decision ledgers, and do not let stale approvals hide source
  identity drift.
- Use canonical drift compare for build-to-build questions before drafting
  conclusions. Match functions by normalized name first, and treat EAs as
  build-local evidence.
- Do not write drift reports into either compared pack root. Store them under
  ignored output roots or external corpus workspaces.
- Avoid model-generated persistent facts unless they are tied to evidence pack
  IDs and source corpus hashes.

## Recommendation

Start with SQLite plus MCP, not vector-only RAG. The target questions need exact
EA, symbol, call edge, tag, import, and artifact retrieval. Vector search can
be added later as a secondary recall booster, but it should not replace the
structured corpus store.

The first production-worthy milestone is:

```text
PseudoForge corpus -> corpus.sqlite -> MCP search/get/neighbor tools ->
validate_pack -> trace_lifecycle(process_object) -> evidence pack ->
answer harness -> grounded AI answer
```
