from __future__ import annotations

import re

from ida_pseudoforge.core.plan_schema import CleanPlan
from ida_pseudoforge.core.render_style import leading_ws


def rename_kernel_labels(text: str, plan: CleanPlan) -> str:
    result = text
    for source_label, semantic_name in semantic_label_map(plan).items():
        if semantic_name == source_label:
            continue
        result = re.sub(r"\b%s:" % re.escape(source_label), semantic_name + ":", result)
        result = re.sub(r"\bgoto\s+%s\s*;" % re.escape(source_label), "goto " + semantic_name + ";", result)
    return result


def semantic_label_display(label: str, classification: str, semantic_label_map_: dict[str, str] | None = None) -> str:
    if semantic_label_map_ is None:
        semantic_name = semantic_label_name(classification)
    else:
        semantic_name = semantic_label_map_.get(label, "")
    if not semantic_name or semantic_name == label:
        return label
    return "%s -> %s" % (label, semantic_name)


def semantic_label_name(classification: str) -> str:
    mapping = {
        "failfast_corrupt_list_entry": "CorruptListEntry",
        "set_error_status_and_cleanup": "InvalidParameter",
        "release_resource_and_leave_critical_region": "Cleanup",
        "irp_complete_request_tail": "CompleteIrp",
    }
    return mapping.get(classification, "")


def semantic_label_map(plan: CleanPlan) -> dict[str, str]:
    result: dict[str, str] = {}
    used_names: set[str] = set()
    for label in plan.cleanup_labels:
        base_name = semantic_label_name(label.classification)
        if not base_name:
            continue
        semantic_name = base_name
        if semantic_name in used_names:
            semantic_name = "%s_%s" % (base_name, _semantic_label_suffix(label.label, len(used_names) + 1))
            while semantic_name in used_names:
                semantic_name = "%s_%d" % (semantic_name, len(used_names) + 1)
        used_names.add(semantic_name)
        result[label.label] = semantic_name
    return result


def annotate_kernel_labels(text: str, plan: CleanPlan) -> str:
    if not plan.cleanup_labels:
        return text
    annotations = {}
    semantic_labels = semantic_label_map(plan)
    for label in plan.cleanup_labels:
        if label.confidence < 0.70:
            continue
        annotation = "// PseudoForge: %s confidence=%.2f; %s" % (
            label.classification,
            label.confidence,
            _ascii_comment_text(label.evidence),
        )
        annotations[label.label] = annotation
        semantic_name = semantic_labels.get(label.label, "")
        if semantic_name:
            annotations[semantic_name] = annotation
    if not annotations:
        return text

    source_lines = text.splitlines()
    lines = []
    for index, line in enumerate(source_lines):
        stripped = line.strip()
        lines.append(line)
        if stripped.endswith(":"):
            label = stripped[:-1]
            annotation = annotations.get(label)
            if annotation:
                indent = line[: len(line) - len(line.lstrip())]
                comment_indent = _next_code_line_indent(source_lines, index + 1) or (indent + "  ")
                lines.append(comment_indent + annotation)
    return "\n".join(lines)


def normalize_semantic_label_indentation(text: str, plan: CleanPlan) -> str:
    semantic_labels = set(semantic_label_map(plan).values())
    if not semantic_labels:
        return text

    result = []
    previous_was_semantic_label = False
    for line in text.splitlines():
        stripped = line.strip()
        label = stripped[:-1] if stripped.endswith(":") else ""
        if label in semantic_labels:
            result.append(label + ":")
            previous_was_semantic_label = True
            continue
        if previous_was_semantic_label and stripped.startswith("// PseudoForge:"):
            result.append("  " + stripped)
        else:
            result.append(line)
        previous_was_semantic_label = False
    return "\n".join(result)


def hoist_embedded_semantic_tail_labels(text: str, plan: CleanPlan) -> str:
    cleanup_label = _first_semantic_label_for_class(plan, "release_resource_and_leave_critical_region")
    ordered_labels = [
        _first_semantic_label_for_class(plan, "set_error_status_and_cleanup"),
        _first_semantic_label_for_class(plan, "failfast_corrupt_list_entry"),
    ]
    ordered_labels = [label for label in ordered_labels if label]
    semantic_labels = set(semantic_label_map(plan).values())
    if cleanup_label not in semantic_labels:
        return text

    lines = text.splitlines()
    hoisted_blocks: list[tuple[str, list[str]]] = []
    for label in ordered_labels:
        if label not in semantic_labels:
            continue
        result = _extract_pre_cleanup_semantic_label(lines, label, cleanup_label)
        if result is None:
            continue
        lines, block = result
        hoisted_blocks.append((label, block))

    if not hoisted_blocks:
        return text

    cleanup_index = _find_label_line(lines, cleanup_label)
    if cleanup_index < 0:
        return "\n".join(lines)
    cleanup_end_index = _find_semantic_label_block_end(lines, cleanup_index)
    if cleanup_end_index < cleanup_index:
        return "\n".join(lines)

    insert_lines: list[str] = []
    for label in ordered_labels:
        for hoisted_label, block in hoisted_blocks:
            if hoisted_label == label:
                insert_lines.extend(block)
                break

    lines = lines[: cleanup_end_index + 1] + insert_lines + lines[cleanup_end_index + 1 :]
    return "\n".join(lines)


def _semantic_label_suffix(label: str, fallback: int) -> str:
    match = re.search(r"(\d+)$", label)
    if match is not None:
        return match.group(1)
    return str(fallback)


def _first_semantic_label_for_class(plan: CleanPlan, classification: str) -> str:
    labels = semantic_label_map(plan)
    for label in plan.cleanup_labels:
        if label.classification == classification:
            return labels.get(label.label, "")
    return ""


def _extract_pre_cleanup_semantic_label(
    lines: list[str],
    label: str,
    cleanup_label: str,
) -> tuple[list[str], list[str]] | None:
    cleanup_index = _find_label_line(lines, cleanup_label)
    label_index = _find_label_line(lines, label)
    if label_index < 0 or cleanup_index < 0 or label_index > cleanup_index:
        return None

    cursor = label_index + 1
    block = [label + ":"]
    while cursor < len(lines) and lines[cursor].strip().startswith("// PseudoForge:"):
        block.append("  " + lines[cursor].strip())
        cursor += 1

    if cursor >= len(lines):
        return None

    body_indent = leading_ws(lines[cursor])
    body_end_index = _find_semantic_label_block_end(lines, label_index)
    if body_end_index < cursor:
        return None
    body_lines = ["  " + line.strip() for line in lines[cursor : body_end_index + 1] if line.strip()]

    if not body_lines or not any(_is_terminal_semantic_label_statement(line.strip()) for line in body_lines):
        return None

    block.extend(body_lines)
    if len(body_indent) > 2:
        replacement = body_indent + "goto %s;" % label
        updated_lines = lines[:label_index] + [replacement] + lines[body_end_index + 1 :]
    elif _previous_code_line(lines, label_index) == "goto %s;" % cleanup_label:
        previous_index = _previous_code_line_index(lines, label_index)
        updated_lines = lines[:previous_index] + lines[body_end_index + 1 :]
    else:
        updated_lines = lines[:label_index] + lines[body_end_index + 1 :]
    return updated_lines, block


def _find_semantic_label_block_end(lines: list[str], label_index: int) -> int:
    cursor = label_index + 1
    while cursor < len(lines) and lines[cursor].strip().startswith("// PseudoForge:"):
        cursor += 1
    body_start = cursor
    while cursor < len(lines):
        stripped = lines[cursor].strip()
        if not stripped:
            cursor += 1
            continue
        if cursor != body_start and stripped.endswith(":"):
            break
        if cursor != body_start and stripped == "}":
            break
        cursor += 1
        if _is_terminal_semantic_label_statement(stripped):
            return cursor - 1
    return cursor - 1


def _find_label_line(lines: list[str], label: str) -> int:
    target = label + ":"
    for index, line in enumerate(lines):
        if line.strip() == target:
            return index
    return -1


def _previous_code_line(lines: list[str], start_index: int) -> str:
    index = _previous_code_line_index(lines, start_index)
    if index < 0:
        return ""
    return lines[index].strip()


def _previous_code_line_index(lines: list[str], start_index: int) -> int:
    for index in range(start_index - 1, -1, -1):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("//"):
            continue
        return index
    return -1


def _is_terminal_semantic_label_statement(stripped: str) -> bool:
    return (
        stripped.startswith("goto ")
        or stripped.startswith("return ")
        or stripped.startswith("__fastfail(")
    )


def _next_code_line_indent(lines: list[str], start_index: int) -> str:
    for index in range(start_index, len(lines)):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if stripped.startswith(("//", "/*", "*")):
            continue
        return lines[index][: len(lines[index]) - len(lines[index].lstrip())]
    return ""


def _ascii_comment_text(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")
