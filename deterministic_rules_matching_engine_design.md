# Deterministic Rules Matching Engine Design

## Purpose

This document defines the deterministic rules matching engine for PseudoForge.

The goal is to let users add rename, semantic insight, API argument rewrite, label classification, warning, and future text rewrite behavior without editing core Python code.

Core principles:

1. Rules do not directly modify pseudocode.
2. Rules only produce match evidence and emissions.
3. Emissions are converted into the existing `CleanPlan` model.
4. Text and control-flow rewrites remain preview/export-only by default.
5. IDB-writeable work remains limited to safe operations such as validator-gated renames selected by the user.

## Current Integration Points

Existing deterministic logic is split across several modules:

```text
ida_pseudoforge/core/lvar_analysis.py
ida_pseudoforge/core/kernel_semantics.py
ida_pseudoforge/core/kernel_api.py
ida_pseudoforge/core/kernel_rewrites.py
ida_pseudoforge/core/cleanup_rewriter.py
ida_pseudoforge/core/flow_recovery.py
ida_pseudoforge/core/render.py
```

The rules engine does not remove these paths immediately. It first adds a common rule runtime, then migrates low-risk rules only after parity tests prove equivalent output.

The initial integration point is `build_clean_plan()`:

```text
capture function
  -> deterministic core analysis
  -> deterministic rules engine
  -> optional LLM assist
  -> rename validation
  -> render/export
```

Long-term order:

```text
FunctionCapture
  -> RuleContext
  -> RulePack loader
  -> RuleMatcher
  -> RuleEmission
  -> CleanPlan adapters
  -> validators
  -> preview/export/report
```

## Recommended Directory Structure

```text
ida_pseudoforge/
  core/
    deterministic/
      __init__.py
      schema.py
      context.py
      loader.py
      engine.py
      validators.py
      emitters.py
      matchers/
        __init__.py
        regex.py
  rules/
    builtin/
      local_renames.json
      kernel_comments.json
tools/
  validate_pseudoforge_rules.py
```

User-added rules are loaded from outside the package:

```text
.\pseudoforge_rules\*.json
%APPDATA%\PseudoForge\rules\*.json
```

Recommended load order:

1. Builtin package rules.
2. Project-local rules beside the analyzed input.
3. User-global rules.
4. Explicit CLI `--rules-dir` paths.

Conflicts are not simple last-wins merges. They are resolved through `override_of`, `priority`, `confidence`, source order, and `rule_id`.

## Core Types

`schema.py` contains data-only types. The current v1 implementation keeps these objects simple and serializable; matcher/runtime state lives outside the schema objects.

```python
@dataclass(slots=True)
class RulePack:
    schema_version: int
    id: str
    description: str
    rules: list[Rule]
    source_path: str = ""
    source_label: str = ""

@dataclass(slots=True)
class Rule:
    id: str
    phase: str
    priority: int
    confidence: float
    scope: dict[str, Any]
    match: dict[str, Any]
    emit: dict[str, Any]
    enabled: bool = True
    override_of: str = ""
    source_path: str = ""
    source_label: str = ""
    source_order: int = 0
    pack_id: str = ""

@dataclass(slots=True)
class RuleMatch:
    rule_id: str
    phase: str
    confidence: float
    bindings: dict[str, str]
    span: tuple[int, int] | None = None
    evidence: str = ""
    emission_kind: str = ""

@dataclass(slots=True)
class RuleEmission:
    kind: str
    rule_id: str
    confidence: float
    payload: dict[str, Any]
    evidence: str = ""
    priority: int = 0
    source_path: str = ""
    source_label: str = ""
    source_order: int = 0
    override_of: str = ""
```

`RuleEmission.kind` must be convertible to existing plan model values.

Allowed v1 emission kinds:

```text
rename
semantic_comment
```

Allowed v2 preview/export-only emission kinds:

```text
call_arg_rewrite
```

Future reserved kinds:

```text
warning
cleanup_label
text_rewrite
symbol_alias
flow
```

## RuleContext

`context.py` converts `FunctionCapture` into indexes that are easy for matchers to use.

Required indexes:

- Normalized pseudocode text.
- Raw lines.
- Function name.
- Prototype text.
- Local names.
- Parameter names.
- Call names.
- Comments and kernel insights.
- Optional profile facts.

Current v1 shape:

```python
@dataclass(slots=True)
class RuleContext:
    capture: FunctionCapture
    text: str
    lines: list[str]
    lvar_names: set[str]
    calls: set[str]
    assignments: list[AssignmentFact]
    call_sites: list[CallSiteFact]
    labels: list[LabelFact]
    literals: list[LiteralFact]
```

The first implementation can use regex-based fact extraction. Ctree-identity based facts can be added later.

## Rule Phases

Phases stabilize execution order.

Supported production v1 phases:

```text
rename
semantic_comment
```

Supported preview/export-only v2 phases:

```text
call_arg_rewrite
```

Reserved future phases:

```text
symbol_alias
warning
cleanup_label
flow
text_rewrite
```

Recommended policy:

1. `symbol_alias` enriches alias metadata before profile lookup.
2. `rename` emits `RenameSuggestion` candidates only.
3. `semantic_comment` emits insight comments for `CleanPlan.comments`.
4. `warning` emits reviewer-facing suspicious pattern reports.
5. `cleanup_label` emits label role candidates.
6. `flow` emits dispatcher/switch recovery candidates.
7. `call_arg_rewrite` emits profile-backed argument rewrite candidates.
8. `text_rewrite` requires a semantic comment gate, confidence gate, and export-only behavior.

Except for v2 `call_arg_rewrite`, reserved phases must be rejected by the
validator until they have explicit preview/export-only boundaries.

## JSON Rule Format

Minimum pack schema:

```json
{
  "schema_version": 1,
  "id": "builtin.local_renames",
  "description": "Low-risk local rename mirror rules.",
  "rules": []
}
```

Rename rule example:

```json
{
  "id": "builtin.local.updated_status",
  "phase": "rename",
  "priority": 50,
  "confidence": 0.92,
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
    "evidence": "Local named updated is used as an NTSTATUS accumulator"
  }
}
```

Assignment-based rename example:

```json
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
    "evidence": "Local receives the current process id"
  }
}
```

Semantic comment rule example:

```json
{
  "id": "builtin.comment.object_reference",
  "phase": "semantic_comment",
  "priority": 20,
  "confidence": 0.90,
  "scope": {
    "calls_any": ["ObReferenceObjectByHandle"]
  },
  "match": {
    "text_contains": "ObReferenceObjectByHandle"
  },
  "emit": {
    "kind": "semantic_comment",
    "comment_kind": "object_reference",
    "text": "Function references an object by handle",
    "evidence": "ObReferenceObjectByHandle call is present"
  }
}
```

Preview-only v2 call argument rewrite example:

```json
{
  "schema_version": 2,
  "id": "project.call_arg_rewrites",
  "description": "Preview-only call argument rewrite candidates.",
  "rules": [
    {
      "id": "project.call_arg_rewrite.probe_size",
      "phase": "call_arg_rewrite",
      "priority": 50,
      "confidence": 0.90,
      "scope": {
        "calls_any": ["ProbeForRead"]
      },
      "match": {
        "text_contains": "ProbeForRead"
      },
      "emit": {
        "kind": "call_arg_rewrite",
        "function_name": "ProbeForRead",
        "argument_index": 1,
        "replacement": "sizeof(*inputBuffer)",
        "preview_only": true,
        "evidence": "Size argument can be explained in preview output"
      }
    }
  ]
}
```

The validator requires `preview_only: true` and a `calls_any` or `calls_all`
scope gate. Static `function_name` values must appear in that gate; binding-based
function names are allowed only with an explicit call scope gate for later typed
matchers.

Current v1 application procedure:

1. Build `RuleContext` from the current capture.
2. Load valid builtin, project-local, user-global, and explicit rule packs.
3. Reject invalid packs fail-closed and add load/validation errors to the report.
4. Evaluate scope gates.
5. Evaluate the primary matcher.
6. Resolve emissions into `CleanPlan` items.
7. Run existing rename validation.
8. Export rule report metadata.

## Match Operators

Supported v1 scope operators:

```text
calls_any
calls_all
lvars_any
function_name_regex
prototype_contains
text_contains
text_contains_all
```

Supported v1 match operators:

```text
regex
assignment_regex
text_contains
text_contains_all
```

Operator behavior:

- `calls_any`: passes if any listed call appears in the indexed call set.
- `calls_all`: passes only if all listed calls appear.
- `lvars_any`: passes if any listed local or parameter appears.
- `function_name_regex`: matches the function name.
- `prototype_contains`: checks substring presence in the prototype.
- `text_contains`: checks substring presence in normalized text.
- `text_contains_all`: requires every listed substring.
- `regex`: runs against normalized text and can expose named bindings.
- `assignment_regex`: runs against normalized text and is intended for assignment-style binding extraction.

The initial implementation does not build a nested expression parser. Where call argument parsing already exists, future rule phases should reuse existing helpers such as `_split_arguments()`.

## Conflict Resolution

Multiple emissions can target the same item.

Rename conflict order:

1. `override_of` relationship.
2. `apply=false` items are lower priority.
3. Higher `priority`.
4. Higher `confidence`.
5. Project/user rules over builtin rules when all else is equal.
6. Deterministic lexical rule ID order.
7. Final `validate_renames()` collision, keyword, and identifier checks.

Text rewrite conflict policy for future phases:

1. Only one rewrite may modify the same span.
2. A rewrite without `requires_comment_kind` is rejected by default.
3. Replacements containing control-flow keywords force `export_only=true`.
4. Before/after text must pass style and whitespace hygiene checks.

Warning/comment dedupe:

1. Keep only one comment with the same `comment_kind` and evidence.
2. Low-confidence items can remain in the rule report while preview headers show thresholded counts.

## Rule Report

Users need to understand why a rule did or did not fire.

The CLI and IDA export can write:

```text
<function>.rule-report.json
```

Current v1 structure:

```json
{
  "matched_rules": [
    {
      "rule_id": "builtin.comment.object_reference",
      "phase": "semantic_comment",
      "confidence": 0.9,
      "evidence": ["ObReferenceObjectByHandle call is present"]
    }
  ],
  "rejected_emissions": [
    {
      "rule_id": "project.rename.foo",
      "reason": "rename target not found"
    }
  ],
  "load_errors": [],
  "validation_errors": []
}
```

The exported v1 report contains `matched_rules`, `rejected_emissions`, `load_errors`, and `validation_errors`. A future UI summary can show counts only:

```text
// Deterministic rules: 4 matched, 1 rejected, 0 load errors
```

Detailed data belongs in the rule report.

## Loader and Validation CLI

The loader is fail-closed. A bad rule file must not crash analysis.

Recommended CLI:

```powershell
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
python -B .\tools\validate_pseudoforge_rules.py .\pseudoforge_rules
```

Validation items:

1. JSON parse succeeds.
2. `schema_version` is supported.
3. Pack and rule IDs are unique in the load set.
4. `phase` is supported.
5. `confidence` is a real number in range and not a boolean.
6. Regex fields compile.
7. Emit kind has all required fields.
8. Replacement bindings refer to existing named captures.
9. User rules do not contain forbidden execution or network fields.
10. Match definitions are non-empty and unambiguous.
11. Text gates are non-empty.

## Security and Operational Boundaries

1. JSON rules are data-only.
2. User Python plugin rules are out of v1 scope.
3. Rules have no filesystem, network, subprocess, or command execution capability.
4. Rule loading failure records a warning/report entry and disables only that pack.
5. IDB write paths continue to use the existing rename validator.
6. Control-flow and text rewrites remain preview/export-only.
7. Rule reports must not include API keys, model configs, or secret user paths.
8. Rule source paths should be redacted to stable labels such as `builtin/foo.json`, `project/foo.json`, or `user/foo.json`.
9. Comments and generated/log text must remain ASCII.

## Phased Implementation Plan

### Phase 1: Runtime Skeleton

Implemented scope:

1. Add `ida_pseudoforge/core/deterministic/`.
2. Add `RulePack`, `Rule`, `RuleMatch`, `RuleEmission`, and `RuleContext`.
3. Add builtin, project-local, user-global, and explicit rule loaders.
4. Add fail-closed validation.
5. Add validation CLI.
6. Add rule report data.
7. Integrate into `build_clean_plan()` without changing behavior when no external rules are present.

### Phase 2: Low-Risk Rename/Comment Migration

Target scope:

1. Mirror simple `LOCAL_NAME_RULES` local rename rules.
2. Mirror simple `_pattern_renames()` assignment rules with easy parity tests.
3. Mirror simple call-presence semantic comments from `kernel_comments()`.
4. Keep existing hard-coded paths until snapshot/unit tests prove parity.

### Phase 3: Kernel API and Alias Integration

Target scope:

1. Connect `kernel_api_overrides.json` to rule loader/report semantics.
2. Add `symbol_alias` rule support.
3. Add `call_arg_rewrite` rule support.
4. Preserve existing pool tag, boolean, and flags rewrite coverage.

### Phase 4: Text Rewrite Migration

Target scope:

1. Wrap `KernelRewriteRule` as a `text_rewrite_rule`.
2. Promote `requires_comment_kind` to a schema field.
3. Add span conflict detection.
4. Record applied and rejected rewrites in the rule report.
5. Preserve existing firmware/provider-list tests.

### Phase 5: IDA UX

Target scope:

1. Show builtin, project, and user rule paths in settings.
2. Show rule validation failures as one-line Output messages.
3. Add `rule-report.json` to preview/export bundles.
4. Add matched/rejected rule counts to the analysis summary.

## Out of Scope for v1

1. Executing user Python.
2. Network or subprocess access from rules.
3. IDB writes from text/control-flow rewrite rules.
4. Replacing hard-coded deterministic paths without parity tests.
5. Full expression parser.
6. Ctree-identity based matching.
7. Interactive rule authoring UI.

IDA GUI validation remains a separate manual validation task.

## Recommended First Implementation Target

The first production-safe slice should stay narrow:

1. Data-only schema.
2. Fail-closed JSON loader.
3. Rule validator CLI.
4. Regex and assignment-based rename rules.
5. Semantic comment rules.
6. Rule report data.
7. Builtin examples that mirror existing deterministic behavior.
8. Project-local `.\pseudoforge_rules` support.
9. User-global `%APPDATA%\PseudoForge\rules` support.
10. No behavioral change for existing tests unless intentionally documented.

`text_rewrite_rule`, `call_arg_rewrite`, and `flow` should remain reserved skeleton concepts until the next implementation phase.
