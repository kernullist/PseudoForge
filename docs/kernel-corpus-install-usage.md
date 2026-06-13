# Kernel Corpus Installation And Usage Guide

This guide explains how to install and use the PseudoForge Kernel Corpus
tooling from a user's point of view. It assumes a PseudoForge IDA batch run has
already produced a corpus directory with `pseudoforge-corpus-index.json` and
per-function artifacts.

Use this guide when you want an AI agent or analyst to answer questions such
as:

```text
Explain the process object lifecycle in this kernel using the major functions.
```

The desired answer path is:

```text
user question -> answer planner -> canonical answers or live retrieval ->
evidence packs -> cited final answer -> answer eval
```

The Kernel Corpus tooling is a consumer-side analysis layer. It does not modify
the IDB, does not require IDA at query time, and does not belong inside the
installed IDA plugin package.

## Components

| Component | Purpose |
| --- | --- |
| Source corpus | PseudoForge batch output from IDA, including index JSON and per-function files. |
| Kernel Corpus pack | SQLite-backed searchable pack built from the source corpus. |
| Local CLIs | Deterministic query, lifecycle, atlas, canonical, planner, and eval commands. |
| MCP server | Read-only tool server that lets an AI client query the pack. |
| Skill | Agent instructions for evidence discipline and answer shape. |
| Canonical answers | Generated baseline answer bundles for recurring kernel topics. |
| Answer eval | Deterministic regression checks for answer workflows and drafted Markdown. |

## Prerequisites

1. Windows PowerShell.
2. Python available as `python`.
3. This repository checked out locally.
4. A completed PseudoForge source corpus directory.
5. Optional: an MCP-capable AI client.
6. Optional: a Claude Code skill root such as `%USERPROFILE%\.claude\skills`
   or a Codex skill root such as `%USERPROFILE%\.codex\skills`.

The normal Kernel Corpus tools use Python standard-library modules and the
repo code. They do not require IDA, Hex-Rays, PySide6, or an LLM provider for
the deterministic build/query/eval paths.

## Recommended Paths

Use a repo-local ignored pack for smoke and iteration:

```powershell
$Repo = "F:\kernullist\PseudoForge"
$CorpusRoot = "F:\kernullist\analysis-ouput\ntoskrnl"
$PackRoot = "$Repo\pseudoforge_out\kernel_corpus\ntoskrnl"
Set-Location $Repo
```

Use an external pack root for long-term corpora:

```powershell
$Repo = "F:\kernullist\PseudoForge"
$CorpusRoot = "F:\kernullist\analysis-ouput\ntoskrnl"
$PackRoot = "F:\pseudoforge-corpora\ntoskrnl-26200.8457"
Set-Location $Repo
```

`pseudoforge_out/` is ignored by Git. Large generated packs, canonical answer
bundles, eval reports, drafted answers, vector indexes, and review decision
ledgers should stay under ignored or external output roots.

## Install From A Release Package

If a Kernel Corpus release package already exists, install that package instead
of rebuilding the corpus. This is the preferred path for a full ntoskrnl corpus
because generation can take multiple days.

Download the release assets:

```powershell
$Repo = "F:\kernullist\PseudoForge"
$ArtifactRepo = "kernullist/kernel-corpus"
$ArtifactId = "ntoskrnl-26200.8457-amd64-r1"
$DownloadDir = "F:\downloads\$ArtifactId"
$InstallRoot = "F:\pseudoforge-corpora"

gh release download $ArtifactId `
  --repo $ArtifactRepo `
  --dir $DownloadDir
```

Verify the downloaded files:

```powershell
Get-FileHash "$DownloadDir\*" -Algorithm SHA256
Get-Content "$DownloadDir\checksums.sha256"
```

Reassemble and extract the split archive:

```powershell
Set-Location $DownloadDir
New-Item -ItemType Directory -Force $InstallRoot | Out-Null
cmd /c copy /b "$ArtifactId.tar.gz.*" "$ArtifactId.tar.gz"
tar -xzf "$ArtifactId.tar.gz" -C $InstallRoot
```

Set the pack root from the extracted package:

```powershell
$PackRoot = "$InstallRoot\$ArtifactId\kernel-pack"
Set-Location $Repo

python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root $PackRoot `
  --include-derived `
  --format text
```

Then generate the MCP config:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py mcp-config `
  --pack-root $PackRoot
```

Release packages should contain:

```text
artifact-manifest.json
checksums.sha256
README-install.md
<artifact-id>.tar.gz.001
<artifact-id>.tar.gz.002
...
```

The archive extracts to:

```text
F:\pseudoforge-corpora\<artifact-id>\
  kernel-pack\
  raw-corpus\        # optional, included when the release carries full source artifacts
  run-logs\          # optional
```

If you install from a release package, skip the source-corpus build steps below
unless you intentionally need to regenerate the pack from raw PseudoForge
output.

## Package A Corpus Release

When publishing a corpus through GitHub Releases, use the dedicated
`kernullist/kernel-corpus` artifact repository. Do not attach corpus packages
to PseudoForge code releases, and do not commit the archive parts into Git
history. Generate release assets and upload them to the corpus repository
release.

Create a split release package:

```powershell
$Repo = "F:\kernullist\PseudoForge"
$ArtifactRepo = "kernullist/kernel-corpus"
$ArtifactId = "ntoskrnl-26200.8457-amd64-r1"
$CorpusRoot = "F:\kernullist\analysis-ouput\ntoskrnl"
$PackRoot = "F:\pseudoforge-corpora\ntoskrnl-26200.8457"
$InstallRoot = "F:\pseudoforge-corpora"
$ReleaseOut = "F:\kernel-corpus-release-staging"
Set-Location $Repo

python -B .\tools\kernel_corpus\package_release.py `
  --pack-root $PackRoot `
  --source-corpus-root $CorpusRoot `
  --artifact-id $ArtifactId `
  --output-dir $ReleaseOut `
  --github-repo $ArtifactRepo `
  --install-root $InstallRoot `
  --volume-size 1900m
```

By default the package helper stages a temporary copy of `kernel-pack` and
rewrites pack-root metadata for
`$InstallRoot\$ArtifactId\kernel-pack` before archiving. This keeps derived
evidence packs, atlas pages, answer plans, manifest `sqlite_path`, and SQLite
`corpus_manifest` rows consistent after a user extracts the release package.
Use `--no-relocate-pack` only when intentionally archiving the pack with its
current absolute paths.

Preview without writing files:

```powershell
python -B .\tools\kernel_corpus\package_release.py `
  --pack-root $PackRoot `
  --artifact-id $ArtifactId `
  --output-dir $ReleaseOut `
  --github-repo $ArtifactRepo `
  --install-root $InstallRoot `
  --dry-run
```

Upload the generated assets:

```powershell
gh release create $ArtifactId `
  --repo $ArtifactRepo `
  --title "Kernel Corpus $ArtifactId" `
  --notes-file "$ReleaseOut\$ArtifactId\README-install.md" `
  "$ReleaseOut\$ArtifactId\$ArtifactId.tar.gz.*" `
  "$ReleaseOut\$ArtifactId\artifact-manifest.json" `
  "$ReleaseOut\$ArtifactId\checksums.sha256" `
  "$ReleaseOut\$ArtifactId\README-install.md"
```

GitHub Release assets in `kernullist/kernel-corpus` are the distribution
channel. PseudoForge Git commits should keep only code, schemas, tests, and
small documentation or registry files.

## Step 1: Verify The Source Corpus

Confirm the source corpus has the expected files:

```powershell
Test-Path "$CorpusRoot\pseudoforge-corpus-index.json"
Test-Path "$CorpusRoot\functions"
Get-ChildItem -Path "$CorpusRoot\functions" -Directory | Measure-Object
```

The index and function directories are the main inputs. If the index is stale
after a partial retry or merge, rebuild or merge the PseudoForge corpus first.

## Step 2: Build The Kernel Corpus Pack

Build or refresh the SQLite pack:

```powershell
python -B .\tools\kernel_corpus\builder.py `
  --corpus-root $CorpusRoot `
  --pack-root $PackRoot `
  --overwrite `
  --json
```

Expected output:

```text
<pack-root>\manifest.json
<pack-root>\corpus.sqlite
```

The manifest records source corpus identity, target path, source index hash,
function counts, skipped counts, PseudoForge version, schema version, and pack
generation time.

## Step 3: Validate Pack Freshness

Run validation before using an existing pack:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root $PackRoot `
  --include-derived `
  --format text
```

Use JSON for automation:

```powershell
python -B .\tools\kernel_corpus\validate_pack.py `
  --pack-root $PackRoot `
  --include-derived `
  --format json
```

Stop and rebuild when validation reports:

- missing `manifest.json`
- missing `corpus.sqlite`
- unsupported pack schema
- mismatched SQLite manifest rows
- source-index hash mismatch
- function-count mismatch

Warnings about unverifiable external source paths are not always fatal, but
they should be resolved before high-trust analysis.

## Step 4: Check Pack Status

Inspect the pack summary:

```powershell
python -B .\tools\kernel_corpus\query.py status `
  --pack-root $PackRoot
```

Review:

- `manifest.function_count`
- `manifest.unique_ea_count`
- `manifest.skipped_count`
- `counts.functions`
- `counts.call_edges`
- `counts.function_fts`
- `warnings`

If `counts.function_fts` is zero, text search quality will be limited.

## Step 5: Install The Skill

The skill tells an agent how to use Kernel Corpus evidence. It does not contain
corpus data. Keep generated packs outside the skill folder.

For Claude Code, use:

```powershell
$SkillRoot = "$env:USERPROFILE\.claude\skills"
```

For Codex, use:

```powershell
$SkillRoot = "$env:USERPROFILE\.codex\skills"
```

Preview the install target without writing anything:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py skill-plan `
  --target-root $SkillRoot
```

Install:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py install-skill `
  --target-root $SkillRoot `
  --apply
```

Update an existing installed skill from the repo source:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py install-skill `
  --target-root $SkillRoot `
  --replace `
  --apply
```

Uninstall:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py uninstall-skill `
  --target-root $SkillRoot `
  --apply
```

The helper is dry-run by default. It writes or removes files only when
`--apply` is present, and it only operates on the direct
`kernel-corpus-analysis` child under the selected target root.

## Step 6: Configure MCP

Generate a copy-ready MCP config snippet:

```powershell
python -B .\tools\kernel_corpus\install_wiring.py mcp-config `
  --pack-root $PackRoot
```

The emitted JSON keeps the generic `mcpServers` block and also includes
`clientSnippets.claudeCode` and `clientSnippets.codex` entries for copy-ready
client setup.

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

Use one explicit pack root per target. Do not hardcode a single permanent
ntoskrnl path into the skill itself.

### Claude Code CLI

Register the stdio server with Claude Code:

```powershell
claude mcp add --transport stdio --scope local pseudoforge-kernel-corpus -- `
  python -B "$Repo\tools\kernel_corpus\mcp_server.py" `
  --pack-root $PackRoot
```

Verify the registration:

```powershell
claude mcp list
```

Use `--scope user` instead of `--scope local` when this corpus should be
available outside the current project. Avoid `--scope project` unless you
intentionally want to create a shareable project MCP config; release-package
paths are usually machine-local.

### Codex CLI And App

Codex can be configured through the CLI:

```powershell
codex mcp add pseudoforge-kernel-corpus -- `
  python -B "$Repo\tools\kernel_corpus\mcp_server.py" `
  --pack-root $PackRoot

codex mcp list
```

Or edit `%USERPROFILE%\.codex\config.toml` directly. Use a project-scoped
`.codex\config.toml` only for trusted projects and only when the pack path is
intentionally project-local.

```toml
[mcp_servers.pseudoforge-kernel-corpus]
command = "python"
args = ["-B", "F:\\kernullist\\PseudoForge\\tools\\kernel_corpus\\mcp_server.py", "--pack-root", "F:\\pseudoforge-corpora\\ntoskrnl-26200.8457"]
cwd = "F:\\kernullist\\PseudoForge"
startup_timeout_sec = 10
tool_timeout_sec = 60
```

Start a new Claude Code or Codex session after changing MCP configuration.

For manual debugging, start the server directly:

```powershell
python -B .\tools\kernel_corpus\mcp_server.py `
  --pack-root $PackRoot
```

The server is stdio-based. It is normally launched by the MCP client rather
than used interactively in a terminal.

## Step 7: Ask Questions Through The Agent

When MCP and the skill are available, ask the agent to use the Kernel Corpus
pack before answering. Good prompts are concrete and mention the target flow:

```text
Use the kernel-corpus-analysis skill and the configured Kernel Corpus MCP.
Explain the process object lifecycle in this kernel using major functions.
Include EA, function name, artifact path, and uncertainty for each major claim.
```

```text
Use the Kernel Corpus pack. Explain how remote process access flows through
NtOpenProcess and memory-copy paths. Prefer canonical answers first, then live
retrieval for gaps.
```

The agent should:

1. Check pack status or freshness.
2. Call `plan_kernel_answer` for broad questions.
3. Inspect passing canonical answers first.
4. Use live retrieval for gaps or unsupported topics.
5. Cite EA, function name, and artifact path for important claims.
6. State gaps and uncertainty instead of filling them from generic memory.

## Local CLI Usage

Use local CLIs when MCP is unavailable or when you want reproducible artifacts.

### Search Functions

```powershell
python -B .\tools\kernel_corpus\query.py search `
  --pack-root $PackRoot `
  --query "process create" `
  --limit 20
```

Search by tag and name regex:

```powershell
python -B .\tools\kernel_corpus\query.py search `
  --pack-root $PackRoot `
  --tag process `
  --name-regex "^(Nt|Zw|Psp).*Process" `
  --limit 50
```

### Inspect One Function

```powershell
python -B .\tools\kernel_corpus\query.py get-function `
  --pack-root $PackRoot `
  --ea 0x140001000
```

Use `--no-excerpt` or `--no-artifacts` when you only need compact metadata.

### Traverse Call Neighbors

```powershell
python -B .\tools\kernel_corpus\query.py neighbors `
  --pack-root $PackRoot `
  --ea 0x140001000 `
  --direction both `
  --depth 2 `
  --limit 80
```

### Search Imports And Strings

```powershell
python -B .\tools\kernel_corpus\query.py search-import `
  --pack-root $PackRoot `
  --query "PsSetCreateProcessNotifyRoutine" `
  --limit 20
```

```powershell
python -B .\tools\kernel_corpus\query.py search-string `
  --pack-root $PackRoot `
  --query "Process" `
  --limit 20
```

### Build A Focused Evidence Pack

```powershell
python -B .\tools\kernel_corpus\query.py build-evidence-pack `
  --pack-root $PackRoot `
  --topic process_object_manual_review `
  --ea 0x140001000 `
  --ea 0x140002000 `
  --output "$PackRoot\evidence-packs\process_object_manual_review.json"
```

The evidence pack is the preferred handoff boundary for a focused answer.

## Lifecycle And Atlas Usage

Generate lifecycle evidence for a known topic:

```powershell
python -B .\tools\kernel_corpus\lifecycle.py `
  --pack-root $PackRoot `
  --topic process_object `
  --max-seeds 32 `
  --depth 2 `
  --output "$PackRoot\evidence-packs\process_object.json"
```

Common lifecycle topics include:

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

Generate subsystem atlas pages:

```powershell
python -B .\tools\kernel_corpus\atlas.py `
  --pack-root $PackRoot `
  --output-dir "$PackRoot\reports\atlas" `
  --limit 24
```

Atlas pages are navigation aids. They are not proof by themselves. Verify
important claims with `get-function`, lifecycle evidence, or canonical answers.

## Canonical Answer Usage

Canonical answers are durable baseline artifacts for recurring topics. They
are generated from the pack and validated for citation discipline, but they are
not a replacement for expert review.

List available topic definitions:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py list `
  --priority P0
```

Build P0 and P1 canonical answers:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root $PackRoot `
  --priority P0 `
  --priority P1 `
  --force
```

Build P2 operational topics separately:

```powershell
python -B .\tools\kernel_corpus\canonical_answers.py build `
  --pack-root $PackRoot `
  --priority P2 `
  --force
```

Inspect generated canonical answers:

```powershell
python -B .\tools\kernel_corpus\canonical_store.py list `
  --pack-root $PackRoot `
  --priority P0 `
  --status pass
```

```powershell
python -B .\tools\kernel_corpus\canonical_store.py find `
  --pack-root $PackRoot `
  --query "remote process access" `
  --max-topics 5
```

```powershell
python -B .\tools\kernel_corpus\canonical_store.py get `
  --pack-root $PackRoot `
  --topic process_object_lifecycle `
  --quality `
  --gaps `
  --max-chars 12000
```

Audit generated canonical answers:

```powershell
python -B .\tools\kernel_corpus\canonical_audit.py `
  --canonical-root "$PackRoot\canonical-answers" `
  --format text `
  --report-out "$PackRoot\canonical-answers\quality-report.json"
```

Decision rules:

- `pass`: use as the first evidence layer, then verify high-impact claims.
- `degraded`: use only with explicit caveats and live verification.
- `fail`: treat as a retrieval or tuning hint, not final answer evidence.
- stale source identity: rebuild or regenerate before trusting the artifact.

## Plan And Validate Answers

For broad natural-language questions, generate a deterministic plan before
drafting prose:

```powershell
python -B .\tools\kernel_corpus\answer_planner.py `
  --pack-root $PackRoot `
  --question "Explain the process object lifecycle in this kernel using major functions." `
  --format markdown `
  --plan-out "$PackRoot\answer-plans\process_object_lifecycle.md"
```

The plan tells the agent which canonical topics, live retrieval tools,
function names, citation fields, and stop conditions to use.

Generate an evidence-grounded prompt from an evidence pack:

```powershell
python -B .\tools\kernel_corpus\answer_harness.py `
  --pack-root $PackRoot `
  --evidence-pack "$PackRoot\evidence-packs\process_object.json" `
  --question "Explain the process object lifecycle in this kernel using major functions." `
  --atlas-page process.md `
  --prompt-out "$PackRoot\answer-prompts\process_object.md"
```

Validate a drafted answer:

```powershell
python -B .\tools\kernel_corpus\answer_harness.py `
  --pack-root $PackRoot `
  --evidence-pack "$PackRoot\evidence-packs\process_object.json" `
  --question "Explain the process object lifecycle in this kernel using major functions." `
  --answer-in "$PackRoot\answers\process_object.md" `
  --report-out "$PackRoot\answer-reports\process_object.json"
```

The harness checks citation discipline. It warns about missing EA, missing
function names, missing nearby artifact paths, and missing gaps or uncertainty
sections when the evidence pack has gaps.

## Answer Eval Regression

Run deterministic workflow eval without model calls:

```powershell
python -B .\tools\kernel_corpus\answer_eval.py `
  --pack-root $PackRoot `
  --format markdown `
  --report-out "$PackRoot\answer-eval\answer-eval-report.md"
```

A default run without `--answers-dir` usually reports `degraded` cases because
final answer Markdown was not supplied. That is useful for routing smoke.

Run eval against drafted answers:

```powershell
python -B .\tools\kernel_corpus\answer_eval.py `
  --pack-root $PackRoot `
  --answers-dir "$PackRoot\answers" `
  --format markdown `
  --report-out "$PackRoot\answer-eval\answer-eval-report.md"
```

Run only one case:

```powershell
python -B .\tools\kernel_corpus\answer_eval.py `
  --pack-root $PackRoot `
  --case process_object_lifecycle `
  --format text
```

Status meaning:

- `pass`: routing and supplied answer checks met the case contract.
- `degraded`: routing is usable, but final answer evidence is absent or
  incomplete.
- `fail`: expected canonical topic, fallback tool, required function,
  citation, gap, stale/degraded, or forbidden-pattern checks failed.

Use eval reports as regression signals, not as expert review.

## Knowledge Graph Usage

Build a bounded graph from existing canonical, lifecycle, and atlas artifacts:

```powershell
python -B .\tools\kernel_corpus\knowledge_graph.py `
  --pack-root $PackRoot `
  --priority P0 `
  --include-atlas `
  --include-lifecycle `
  --format markdown `
  --output "$PackRoot\reports\knowledge-graph.md"
```

Find functions shared across topics:

```powershell
python -B .\tools\kernel_corpus\knowledge_graph.py shared-functions `
  --pack-root $PackRoot `
  --include-atlas `
  --include-lifecycle
```

Find topic paths:

```powershell
python -B .\tools\kernel_corpus\knowledge_graph.py topic-path `
  --pack-root $PackRoot `
  --source-topic process_object_lifecycle `
  --target-topic remote_process_access_flow `
  --include-lifecycle `
  --max-paths 5
```

Find all topic roles for a function:

```powershell
python -B .\tools\kernel_corpus\knowledge_graph.py function-topics `
  --pack-root $PackRoot `
  --function PspAllocateProcess `
  --max-topics 10
```

Graph output is a navigation signal. Use function artifacts or evidence packs
before making claims.

## Cross-Build Drift Usage

Compare canonical answer evidence between two pack roots:

```powershell
$OldPackRoot = "F:\pseudoforge-corpora\ntoskrnl-old"
$NewPackRoot = "F:\pseudoforge-corpora\ntoskrnl-new"

python -B .\tools\kernel_corpus\canonical_compare.py `
  --pack-root-a $OldPackRoot `
  --pack-root-b $NewPackRoot `
  --label-a old `
  --label-b new `
  --topic process_object_lifecycle `
  --format markdown `
  --report-out "$Repo\pseudoforge_out\kernel_corpus\drift\process_object_lifecycle.md"
```

Treat EAs as build-local evidence. Prefer normalized function names, selected
roles, phase labels, and call-edge changes when explaining drift.

## Recommended Daily Workflow

1. Set `$Repo`, `$CorpusRoot`, and `$PackRoot`.
2. Install from a release package, or build/refresh the pack if no release
   package exists.
3. Validate freshness.
4. Generate or refresh canonical answers for the needed priorities.
5. Audit canonical answers.
6. Configure MCP and install/update the skill.
7. Ask broad questions through the agent using the skill.
8. Use local CLIs for focused evidence packs and reproducible reports.
9. Validate drafted answers with the answer harness.
10. Run answer eval before treating answer workflows as stable.
11. Package updated corpus artifacts as `kernullist/kernel-corpus` GitHub
    Release assets when the corpus must be shared.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `manifest.json` missing | Pack was not built or wrong path was used. | Rebuild with `builder.py` and check `$PackRoot`. |
| `corpus.sqlite` missing | Build failed or output path is stale. | Rebuild and inspect builder JSON output. |
| Source hash mismatch | Source corpus changed after pack build. | Rebuild the pack from the current source corpus. |
| Empty text search | FTS table missing or unavailable. | Check `counts.function_fts`; rebuild if needed. |
| MCP tool cannot find pack | MCP config points to the wrong pack root. | Regenerate config with `install_wiring.py mcp-config`. |
| Skill works but answers are generic | Agent did not use MCP or local CLIs. | Explicitly ask it to use `kernel-corpus-analysis` and the configured MCP. |
| Canonical topic is degraded | Required evidence is weak or missing. | Inspect `quality.md`, `gaps.md`, and run live retrieval. |
| Answer harness warnings | Draft lacks EA, function name, artifact path, or gaps section. | Add citations and uncertainty notes to major claims. |
| Answer eval degraded only | No answer Markdown was supplied. | Add `--answers-dir` or accept routing-only degraded smoke. |
| Answer eval fails required functions | Routing, canonical topic, or case expectation is off. | Inspect selected topics and update retrieval or expectations only with evidence. |
| Report output rejected | Output path escaped the allowed root. | Write under `<pack-root>` or the documented external report path. |
| Release asset is over the upload limit | Split volume size is too large. | Repackage with `--volume-size 1900m` or smaller. |
| Extracted MCP pack is missing | Archive was extracted to a different root or artifact id. | Check `artifact-manifest.json` and set `$PackRoot` to `<install-root>\<artifact-id>\kernel-pack`. |

## Safety Boundaries

- Do not copy generated ntoskrnl packs into the repo history.
- Do publish large corpus bundles as `kernullist/kernel-corpus` GitHub Release
  assets, not ordinary Git blobs or PseudoForge release payloads.
- Do not put corpus data inside the skill folder.
- Do not treat canonical answers as human-reviewed truth.
- Do not answer directly from graph centrality, vector scores, or generic
  Windows memory.
- Do not ignore pack freshness warnings for final analysis.
- Do not weaken answer harness or eval checks to make a poor answer pass.
