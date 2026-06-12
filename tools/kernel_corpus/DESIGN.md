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
    builder.py                  # future
    mcp_server.py               # future
    schema.py                   # future
    lifecycle.py                # future
    ontology/
      process_object.json       # future
      thread_object.json        # future
      file_object.json          # future
    skills/
      kernel-corpus-analysis/
        SKILL.md                # future
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
    <timestamp>-<topic>.json
  reports/
    corpus-status.md
    lifecycle-process-object.md
```

`corpus.sqlite` is the main MCP backing store. JSON files remain available for
debugging, portability, and handoff to other agents.

## Architecture

### 1. Pack Builder

Future command:

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

Example `ontology/process_object.json`:

```json
{
  "id": "process_object",
  "labels": ["process", "eprocess", "process object"],
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
  "phase_hints": {
    "entry": ["NtCreate", "ZwCreate"],
    "allocate": ["Allocate", "Initialize"],
    "publish": ["Insert", "ObInsert", "CidTable"],
    "notify": ["Notify", "Callback", "Etw", "Audit"],
    "exit": ["Exit", "Terminate", "Rundown"],
    "delete": ["Delete", "Dereference", "Cleanup"]
  }
}
```

The ontology should be generic across Windows builds. The MCP must still
retrieve and cite target-specific functions before answering.

### 4. MCP Server

The MCP server is a read-only interface over the pack.

Initial tools:

```text
corpus_status(pack_root)
search_functions(pack_root, query, tags, name_regex, limit)
get_function(pack_root, ea, include_excerpt, include_artifacts)
get_neighbors(pack_root, ea, direction, depth, limit)
search_by_import(pack_root, import_query, limit)
search_by_string(pack_root, string_query, limit)
build_evidence_pack(pack_root, eas, topic, output_path)
trace_lifecycle(pack_root, topic, max_seeds, depth, output_path)
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

## Skill Layer

The skill should be small. It should not contain the ntoskrnl corpus. It should
teach the agent how to use the MCP.

Future skill location:

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
7. If the corpus is partial or stale, state the limitation.

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

## Example Flow

User asks:

```text
In this kernel, explain the process object lifecycle from creation to deletion.
```

Agent workflow:

1. `corpus_status(pack_root)`
2. `trace_lifecycle(pack_root, "process_object", depth=2)`
3. `get_function` for the highest-impact functions in each phase
4. Optionally `get_neighbors` around ambiguous edges
5. Produce an evidence-grounded narrative with citations

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

## Testing Strategy

Use small fixture corpora for unit tests. Do not require the full ntoskrnl
corpus in normal test runs.

Test layers:

1. Schema migration tests.
2. Builder tests with tiny fixture index JSON.
3. Query tests for FTS and graph traversal.
4. MCP contract tests with fixed JSON snapshots.
5. Lifecycle phase assignment tests with synthetic function graphs.
6. Optional integration smoke against the real ntoskrnl pack when present.

Integration tests should skip cleanly when the large corpus path is absent.

## Operational Notes

- Keep all generated paths absolute in MCP responses.
- Normalize EAs to uppercase hex like `0x14093A130`.
- Treat missing artifacts as degraded evidence, not fatal errors.
- Never mutate the source PseudoForge corpus from MCP tools.
- Never update the IDB from this tool.
- Keep lifecycle heuristics reviewable as JSON ontology plus Python scoring.
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
trace_lifecycle(process_object) -> evidence pack -> grounded AI answer
```
