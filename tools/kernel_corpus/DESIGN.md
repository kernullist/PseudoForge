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
    answer_harness.py
    atlas.py
    builder.py
    ea.py
    errors.py
    lifecycle.py
    mcp_server.py
    paths.py
    query.py
    schema.py
    store.py
    validate_pack.py
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

The initial implementation is complete through Phase 12:

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
```

Optional later tools:

```text
compare_lifecycle(pack_root_a, pack_root_b, topic)
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
9. Optional integration smoke against the real ntoskrnl pack when present.

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
- Treat atlas hubs as relevance-filtered retrieval hints; generic helpers are
  intentionally suppressed from hub lists.
- Treat answer harness validation as citation lint, not final factual proof.
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
