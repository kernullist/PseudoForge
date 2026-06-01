from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ida_pseudoforge.core.normalize import extract_parameters_from_signature
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture
from ida_pseudoforge.core.render import _finalize_rendered_c_like_text, display_warning_count
from ida_pseudoforge.version import VERSION


_FILE_HEADER = """// PseudoForge aggregate preview file
// This file is maintained by PseudoForge.
// Function sections are replaced by EA, so multiple analyzed functions can share one file.
"""
_RAW_PSEUDOCODE_BEGIN = "// PSEUDOFORGE RAW PSEUDOCODE BEGIN encoding=base64"
_RAW_PSEUDOCODE_END = "// PSEUDOFORGE RAW PSEUDOCODE END"
_RAW_BLOCK_RE = re.compile(
    r"(?ms)^// PSEUDOFORGE RAW PSEUDOCODE BEGIN encoding=base64\s*\n"
    r"(?P<body>(?:// [A-Za-z0-9+/=]*\s*\n)*)"
    r"^// PSEUDOFORGE RAW PSEUDOCODE END\s*\n?"
)
_RAW_BLOCK_CHUNK_SIZE = 96


@dataclass(frozen=True)
class ForgeFunctionSection:
    ea: int
    name: str
    fingerprint: str
    text: str
    raw_pseudocode: str = ""


def write_forge_function(
    forge_path: str | Path,
    target_path: str | Path,
    capture: FunctionCapture,
    plan: CleanPlan,
    cleaned_pseudocode: str,
) -> str:
    path = Path(forge_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = ""
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="replace")

    section = render_forge_function_section(capture, plan, cleaned_pseudocode)
    updated = upsert_forge_section(existing, str(target_path), capture.ea, section)
    path.write_text(updated, encoding="utf-8")
    return updated


def upsert_forge_section(existing_text: str, target_path: str, function_ea: int, section: str) -> str:
    text = _ensure_header(existing_text, target_path)
    pattern = re.compile(
        r"(?ms)^// PSEUDOFORGE FUNCTION BEGIN ea=0x%X\b.*?"
        r"^// PSEUDOFORGE FUNCTION END ea=0x%X\s*\n?" % (function_ea, function_ea)
    )
    replacement = section.rstrip() + "\n"
    if pattern.search(text):
        updated = pattern.sub(replacement, text).rstrip() + "\n"
    else:
        updated = text.rstrip() + "\n\n" + replacement
    updated = _finalize_rendered_c_like_text(updated)
    return _annotate_call_arity_mismatches(updated)


def parse_forge_function_sections(text: str) -> list[ForgeFunctionSection]:
    pattern = re.compile(
        r"(?ms)^// PSEUDOFORGE FUNCTION BEGIN ea=0x(?P<ea>[0-9A-Fa-f]+)\s+"
        r"name=(?P<name>\S+)(?:\s+fingerprint=(?P<fingerprint>\S+))?.*?"
        r"^// PSEUDOFORGE FUNCTION END ea=0x(?P=ea)\s*$"
    )
    sections: list[ForgeFunctionSection] = []
    for match in pattern.finditer(text or ""):
        try:
            ea = int(match.group("ea"), 16)
        except ValueError:
            continue
        section_text = match.group(0).rstrip() + "\n"
        raw_pseudocode, display_text = _extract_raw_pseudocode(section_text)
        sections.append(
            ForgeFunctionSection(
                ea=ea,
                name=match.group("name") or "function",
                fingerprint=match.group("fingerprint") or "",
                text=display_text,
                raw_pseudocode=raw_pseudocode,
            )
        )
    return sections


def find_forge_function_section(text: str, function_ea: int) -> ForgeFunctionSection | None:
    for section in parse_forge_function_sections(text):
        if section.ea == function_ea:
            return section
    return None


def render_forge_function_section(
    capture: FunctionCapture,
    plan: CleanPlan,
    cleaned_pseudocode: str,
) -> str:
    updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    cleaned_pseudocode = _finalize_rendered_c_like_text(cleaned_pseudocode)
    lines = [
        "// PSEUDOFORGE FUNCTION BEGIN ea=0x%X name=%s fingerprint=%s"
        % (capture.ea, _safe_metadata(capture.name), plan.input_fingerprint),
        "// Updated: %s" % updated_at,
        "// PseudoForge version: %s" % VERSION,
        "// Rename candidates: %d" % len(plan.active_renames()),
        "// Flow rewrites: %d" % len(plan.flow_rewrites),
        "// Warnings: %d" % display_warning_count(plan),
    ]
    raw_block = _render_raw_pseudocode_block(capture.pseudocode)
    if raw_block:
        lines.extend(["", raw_block.rstrip()])
    lines.extend(
        [
            "",
            cleaned_pseudocode.rstrip(),
            "",
            "// PSEUDOFORGE FUNCTION END ea=0x%X" % capture.ea,
        ]
    )
    return "\n".join(lines) + "\n"


def _render_raw_pseudocode_block(raw_pseudocode: str) -> str:
    if not raw_pseudocode:
        return ""
    normalized = raw_pseudocode.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"
    encoded = base64.b64encode(normalized.encode("utf-8", errors="replace")).decode("ascii")
    lines = [_RAW_PSEUDOCODE_BEGIN]
    for index in range(0, len(encoded), _RAW_BLOCK_CHUNK_SIZE):
        lines.append("// " + encoded[index : index + _RAW_BLOCK_CHUNK_SIZE])
    lines.append(_RAW_PSEUDOCODE_END)
    return "\n".join(lines) + "\n"


def _extract_raw_pseudocode(section_text: str) -> tuple[str, str]:
    raw_text = ""

    def replace(match: re.Match[str]) -> str:
        nonlocal raw_text
        if not raw_text:
            encoded = "".join(line[3:].strip() for line in match.group("body").splitlines() if line.startswith("// "))
            try:
                raw_text = base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8", errors="replace")
            except Exception:
                raw_text = ""
        return ""

    display_text = _RAW_BLOCK_RE.sub(replace, section_text).rstrip() + "\n"
    return raw_text, display_text


def _ensure_header(existing_text: str, target_path: str) -> str:
    if existing_text.startswith("// PseudoForge aggregate preview file"):
        return _ensure_aggregate_version(existing_text).rstrip() + "\n"
    header = _FILE_HEADER + "// Version: %s\n// Target: %s\n" % (VERSION, target_path)
    if not existing_text.strip():
        return header.rstrip() + "\n"
    return header.rstrip() + "\n\n" + existing_text.rstrip() + "\n"


def _ensure_aggregate_version(existing_text: str) -> str:
    lines = existing_text.rstrip().splitlines()
    function_index = len(lines)
    for index, line in enumerate(lines):
        if line.startswith("// PSEUDOFORGE FUNCTION BEGIN"):
            function_index = index
            break

    for index, line in enumerate(lines[:function_index]):
        if line.startswith("// Version:"):
            lines[index] = "// Version: %s" % VERSION
            return "\n".join(lines) + "\n"

    insert_at = min(len(_FILE_HEADER.rstrip().splitlines()), len(lines))
    lines.insert(insert_at, "// Version: %s" % VERSION)
    return "\n".join(lines) + "\n"


def _safe_metadata(value: str) -> str:
    result = []
    for char in value or "function":
        if char.isalnum() or char in "_.$@?-":
            result.append(char)
        else:
            result.append("_")
    return "".join(result)


_CALL_ARITY_WARNING_RE = re.compile(r"(?m)^// PseudoForge warning: call arity mismatch .*\n?")


def _annotate_call_arity_mismatches(text: str) -> str:
    clean_text = _CALL_ARITY_WARNING_RE.sub("", text)
    definitions = _function_definition_param_counts(clean_text)
    if not definitions:
        return clean_text

    warnings = []
    seen = set()
    for name, (expected_count, spans) in definitions.items():
        for call_offset, actual_count in _iter_function_calls(clean_text, name):
            if any(start <= call_offset < end for start, end in spans):
                continue
            if actual_count == expected_count:
                continue
            key = (name, expected_count, actual_count)
            if key in seen:
                continue
            seen.add(key)
            warnings.append(
                "// PseudoForge warning: call arity mismatch %s: definition has %d parameter(s), call has %d argument(s)."
                % (name, expected_count, actual_count)
            )

    if not warnings:
        return clean_text
    return _insert_aggregate_warnings(clean_text, warnings)


def _function_definition_param_counts(text: str) -> dict[str, tuple[int, list[tuple[int, int]]]]:
    lines = text.splitlines(keepends=True)
    line_offsets = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line)

    definitions: dict[str, tuple[int, list[tuple[int, int]]]] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if (
            not stripped
            or line[:1].isspace()
            or stripped.startswith(("//", "#", "typedef "))
            or "(" not in line
            or ";" in line
        ):
            index += 1
            continue

        end_index = _find_signature_end(lines, index)
        if end_index < index:
            index += 1
            continue
        brace_index = _next_nonempty_line_index(lines, end_index + 1)
        signature_lines = lines[index : end_index + 1]
        signature_text = "".join(signature_lines).strip()
        signature_has_inline_brace = "{" in signature_text
        if not signature_has_inline_brace and (brace_index < 0 or not lines[brace_index].lstrip().startswith("{")):
            index += 1
            continue

        name = _function_name_from_signature(signature_text)
        if not name:
            index += 1
            continue
        params = extract_parameters_from_signature(signature_text)
        span_end_line = end_index if signature_has_inline_brace else brace_index
        span = (line_offsets[index], line_offsets[span_end_line] + len(lines[span_end_line]))
        expected_count, spans = definitions.get(name, (len(params), []))
        spans.append(span)
        definitions[name] = (expected_count, spans)
        index = span_end_line + 1
    return definitions


def _find_signature_end(lines: list[str], start_index: int) -> int:
    depth = 0
    saw_open = False
    for index in range(start_index, min(len(lines), start_index + 16)):
        for char in lines[index]:
            if char == "(":
                depth += 1
                saw_open = True
            elif char == ")":
                depth -= 1
                if saw_open and depth <= 0:
                    return index
    return -1


def _next_nonempty_line_index(lines: list[str], start_index: int) -> int:
    for index in range(start_index, len(lines)):
        if lines[index].strip():
            return index
    return -1


def _function_name_from_signature(signature: str) -> str:
    prefix = signature.split("(", 1)[0]
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$", prefix)
    if not match:
        return ""
    name = match.group(1)
    if name in {"if", "for", "while", "switch", "return", "sizeof"}:
        return ""
    return name


def _iter_function_calls(text: str, name: str) -> list[tuple[int, int]]:
    calls = []
    pattern = re.compile(r"\b%s\s*\(" % re.escape(name))
    for match in pattern.finditer(text):
        close_index = _find_matching_call_paren(text, match.end() - 1)
        if close_index < 0:
            continue
        args_text = text[match.end() : close_index]
        calls.append((match.start(), _count_top_level_arguments(args_text)))
    return calls


def _find_matching_call_paren(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_index, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _count_top_level_arguments(args_text: str) -> int:
    if not args_text.strip():
        return 0
    depth = 0
    quote = ""
    escaped = False
    count = 1
    for char in args_text:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            count += 1
    return count


def _insert_aggregate_warnings(text: str, warnings: list[str]) -> str:
    warning_text = "\n".join(warnings) + "\n"
    lines = text.splitlines(keepends=True)
    insert_index = 0
    for index, line in enumerate(lines):
        if line.startswith("// Target:"):
            insert_index = index + 1
            break
    if insert_index <= 0:
        return warning_text + text
    return "".join(lines[:insert_index]) + warning_text + "".join(lines[insert_index:])
