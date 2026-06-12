# Kernel Corpus Runbook

This runbook explains how to use the PseudoForge Kernel Corpus tooling after a
large IDA batch run has produced corpus artifacts. The tooling is a
consumer-side analysis layer under `tools/kernel_corpus/`; it does not modify
the IDB and does not belong under `ida_pseudoforge/`.

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

The emitted JSON has this shape:

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

Use an explicit pack root per target. Do not bake one permanent ntoskrnl path
into the skill or MCP server.

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
python -B .\tools\kernel_corpus\install_wiring.py skill-plan `
  --target-root "$env:USERPROFILE\.codex\skills"
```

Install the skill into an explicit Codex skill root:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py install-skill `
  --target-root "$env:USERPROFILE\.codex\skills" `
  --apply
```

Update the installed copy from the repo source:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py install-skill `
  --target-root "$env:USERPROFILE\.codex\skills" `
  --replace `
  --apply
```

Uninstall the copied skill:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py uninstall-skill `
  --target-root "$env:USERPROFILE\.codex\skills" `
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
  tests/test_kernel_corpus_perf_profile.py
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
- Very broad answers: build or inspect an evidence pack first, then answer from
  the pack instead of scanning the full corpus ad hoc.
