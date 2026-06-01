from __future__ import annotations

import re

from ida_pseudoforge.core.normalize import find_matching_paren, split_parameters_with_spans


_CALL_KEYWORDS = {
    "for",
    "if",
    "return",
    "sizeof",
    "switch",
    "while",
}


def apply_generic_render_cleanups(text: str, scratch_sinks: set[str] | None = None) -> str:
    result = rewrite_scalar_out_array_storage(text)
    result = fold_unrolled_wide_array_copies(result)
    result = fold_single_assignment_pointer_aliases(result)
    result = reuse_constant_pointer_expression_aliases(result)
    return suppress_scratch_sink_assignments(result, scratch_sinks or set())


def rewrite_scalar_out_array_storage(text: str) -> str:
    result = text or ""
    for name in _scalar_out_array_candidates(result):
        result = _rewrite_scalar_out_array(result, name)
    return result


def fold_single_assignment_pointer_aliases(text: str) -> str:
    result = text or ""
    changed = True
    while changed:
        changed = False
        for alias, target in _single_assignment_pointer_aliases(result):
            updated = _remove_declaration_and_assignment(result, alias, target)
            updated = re.sub(r"(?<![.>])\b%s\b" % re.escape(alias), target, updated)
            if updated != result:
                result = updated
                changed = True
                break
    return result


def reuse_constant_pointer_expression_aliases(text: str) -> str:
    result = text or ""
    changed = True
    while changed:
        changed = False
        for alias in _constant_pointer_expression_aliases(result):
            updated = _replace_constant_pointer_expression_alias(result, alias)
            if updated != result:
                result = updated
                changed = True
                break
    return result


def fold_unrolled_wide_array_copies(text: str) -> str:
    result = text or ""
    changed = True
    while changed:
        changed = False
        match = _find_unrolled_wide_array_copy(result)
        if not match:
            continue
        replacement = "%sqmemcpy(%s, %s, sizeof(%s));\n" % (
            match["indent"],
            match["dst"],
            match["src"],
            match["src"],
        )
        result = result[: match["start"]] + replacement + result[match["end"] :]
        for temp in match["temps"]:
            result = _remove_unused_wide_temp_declaration(result, temp)
        changed = True
    return result


def suppress_scratch_sink_assignments(text: str, scratch_sinks: set[str]) -> str:
    result = text or ""
    followup_candidates: set[str] = set()
    for name in sorted(scratch_sinks):
        if not _is_write_only_assignment_sink(result, name, min_assignments=1):
            continue
        result, observed = _rewrite_scratch_sink_assignments(result, name)
        followup_candidates.update(observed)
        result = _remove_unused_local_declaration(result, name)
    for name in sorted(followup_candidates):
        if not _is_write_only_assignment_sink(result, name, min_assignments=2):
            continue
        result, _observed = _rewrite_scratch_sink_assignments(result, name)
        result = _remove_unused_local_declaration(result, name)
    return collapse_empty_if_else_blocks(result)


def collapse_empty_if_else_blocks(text: str) -> str:
    lines = (text or "").splitlines()
    changed = True
    while changed:
        changed = False
        index = 0
        updated: list[str] = []
        while index < len(lines):
            replacement = _empty_if_else_replacement(lines, index)
            if not replacement:
                updated.append(lines[index])
                index += 1
                continue
            replacement_lines, next_index = replacement
            updated.extend(replacement_lines)
            index = next_index
            changed = True
        lines = updated
    trailing_newline = "\n" if (text or "").endswith(("\n", "\r\n")) else ""
    return "\n".join(lines) + trailing_newline


def _empty_if_else_replacement(lines: list[str], index: int) -> tuple[list[str], int] | None:
    if index + 6 >= len(lines):
        return None
    if_match = re.fullmatch(r"(?P<indent>[ \t]*)if\s*\(\s*(?P<condition>.+?)\s*\)", lines[index].strip())
    if if_match is None:
        return None
    indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
    if lines[index + 1].strip() != "{" or lines[index + 2].strip() != "}":
        return None
    if lines[index + 3].strip() != "else" or lines[index + 4].strip() != "{":
        return None
    close_index = _matching_brace_line(lines, index + 4)
    if close_index < 0:
        return None
    else_body = lines[index + 5 : close_index]
    if not any(line.strip() for line in else_body):
        return None
    inverted = _invert_condition_text(if_match.group("condition"))
    replacement = [
        "%sif ( %s )" % (indent, inverted),
        "%s{" % indent,
    ]
    replacement.extend(else_body)
    replacement.append("%s}" % indent)
    return replacement, close_index + 1


def _matching_brace_line(lines: list[str], open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(lines)):
        stripped = lines[index].strip()
        if stripped == "{":
            depth += 1
        elif stripped == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _invert_condition_text(condition: str) -> str:
    stripped = (condition or "").strip()
    for operator, inverse in (("!=", "=="), ("==", "!=")):
        match = re.fullmatch(r"(?P<lhs>.+?)\s*%s\s*(?P<rhs>0|NULL|nullptr|FALSE|false|TRUE|true)" % re.escape(operator), stripped)
        if match:
            return "%s %s %s" % (match.group("lhs").strip(), inverse, match.group("rhs").strip())
    if stripped.startswith("!"):
        return stripped[1:].strip()
    return "!( %s )" % stripped


def _scalar_out_array_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    declaration_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<type>ULONG|DWORD|_DWORD|unsigned\s+int)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*2\s*\](?P<suffix>\s*;[^\n]*)$"
    )
    for match in declaration_pattern.finditer(text):
        name = match.group("name")
        if re.search(r"\b%s\s*\[" % re.escape(name), _text_without_match(text, match)):
            continue
        if re.search(r"\*\s*\(\s*_QWORD\s+\*\s*\)\s*%s\b" % re.escape(name), text) is None:
            continue
        candidates.append(name)
    return candidates


def _rewrite_scalar_out_array(text: str, name: str) -> str:
    escaped = re.escape(name)
    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?:ULONG|DWORD|_DWORD|unsigned\s+int)\s+%s\s*\[\s*2\s*\](?P<suffix>\s*;[^\n]*)$"
        % escaped,
        r"\g<indent>SIZE_T %s\g<suffix>" % name,
        text,
        count=1,
    )
    result = re.sub(
        r"\*\s*\(\s*_QWORD\s+\*\s*\)\s*%s\b\s*=\s*(?P<value>[^;]+);" % escaped,
        r"%s = \g<value>;" % name,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"\*\s*\(\s*_QWORD\s+\*\s*\)\s*%s\b\s*;" % escaped,
        r"\g<indent>\g<lhs> = %s;" % name,
        result,
    )
    return _rewrite_standalone_call_arguments(result, name, "&" + name)


def _rewrite_standalone_call_arguments(text: str, old_arg: str, new_arg: str) -> str:
    replacements: list[tuple[int, int, str]] = []
    for match in re.finditer(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        call_name = match.group("name")
        if call_name in _CALL_KEYWORDS:
            continue
        open_index = text.find("(", match.start())
        close_index = find_matching_paren(text, open_index)
        if close_index < 0:
            continue
        parameter_text = text[open_index + 1 : close_index]
        for argument, span in split_parameters_with_spans(parameter_text):
            if argument.strip() != old_arg:
                continue
            replacements.append((open_index + 1 + span[0], open_index + 1 + span[1], new_arg))

    result = text
    for start, end, replacement in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]
    return result


def _single_assignment_pointer_aliases(text: str) -> list[tuple[str, str]]:
    declared = _pointer_local_declarations(text)
    aliases: list[tuple[str, str]] = []
    for alias in declared:
        assignments = list(
            re.finditer(
                r"(?m)^\s*%s\s*=\s*(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
                % re.escape(alias),
                text,
            )
        )
        if len(assignments) != 1:
            continue
        target = assignments[0].group("target")
        if target == alias:
            continue
        if target not in declared:
            continue
        declaration_match = _local_declaration_match(text, alias)
        prefix = text[: assignments[0].start()]
        if declaration_match is not None:
            prefix = prefix[: declaration_match.start()] + prefix[declaration_match.end() :]
        if re.search(r"\b%s\b" % re.escape(alias), prefix):
            continue
        text_without_assignment = text[: assignments[0].start()] + text[assignments[0].end() :]
        if declaration_match is not None:
            text_without_assignment = (
                text_without_assignment[: declaration_match.start()]
                + text_without_assignment[declaration_match.end() :]
            )
        if _has_direct_alias_mutation(text_without_assignment, alias):
            continue
        if len(re.findall(r"(?m)^\s*%s\s*=" % re.escape(alias), text)) != 1:
            continue
        if re.search(r"&\s*%s\b" % re.escape(alias), text):
            continue
        aliases.append((alias, target))
    return aliases


def _constant_pointer_expression_aliases(text: str) -> list[dict[str, object]]:
    declared = _pointer_local_declarations(text)
    aliases: list[dict[str, object]] = []
    assignment_pattern = re.compile(
        r"(?m)^\s*(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:(?P<cast>\([^;\n()]*\*[^;\n()]*\))\s*)?"
        r"\(\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
        r"(?P<offset>0x[0-9A-Fa-f]+|\d+)(?P<suffix>LL|i64|i32|uLL|ULL|u)?\s*\)\s*;\s*$"
    )
    for match in assignment_pattern.finditer(text or ""):
        alias = match.group("alias")
        if alias not in declared:
            continue
        if len(re.findall(r"(?m)^\s*%s\s*=" % re.escape(alias), text or "")) != 1:
            continue
        declaration_match = _local_declaration_match(text, alias)
        prefix = text[: match.start()]
        if declaration_match is not None:
            prefix = prefix[: declaration_match.start()] + prefix[declaration_match.end() :]
        if re.search(r"\b%s\b" % re.escape(alias), prefix):
            continue
        tail = text[match.end() :]
        if _has_direct_alias_mutation(tail, alias):
            continue
        if _has_direct_alias_mutation(tail, match.group("base")):
            continue
        aliases.append(
            {
                "alias": alias,
                "base": match.group("base"),
                "offset": _numeric_offset_value(match.group("offset")),
                "assignment_end": match.end(),
            }
        )
    return aliases


def _replace_constant_pointer_expression_alias(text: str, alias: dict[str, object]) -> str:
    base = str(alias["base"])
    offset = int(alias["offset"])
    name = str(alias["alias"])
    start = int(alias["assignment_end"])
    prefix = text[:start]
    tail = text[start:]
    replaced_tail = _replace_casted_constant_pointer_expression(tail, base, offset, name)
    replaced_tail = _replace_bare_constant_pointer_expression(replaced_tail, base, offset, name)
    return prefix + replaced_tail


def _replace_casted_constant_pointer_expression(text: str, base: str, offset: int, alias: str) -> str:
    expression = _constant_offset_expression_pattern(base, offset)
    pattern = re.compile(
        r"(?P<cast>\((?:[^;\n()]*\*[^;\n()]*|P[A-Z0-9_]+)\))\s*\(\s*%s\s*\)" % expression
    )
    return pattern.sub(lambda match: "%s%s" % (match.group("cast"), alias), text or "")


def _replace_bare_constant_pointer_expression(text: str, base: str, offset: int, alias: str) -> str:
    expression = _constant_offset_expression_pattern(base, offset)
    pattern = re.compile(r"(?<![A-Za-z0-9_])%s(?!\s*[\+\-\[\w])" % expression)
    return pattern.sub(alias, text or "")


def _constant_offset_expression_pattern(base: str, offset: int) -> str:
    literal_patterns = [re.escape(str(offset)), re.escape(hex(offset))]
    if offset >= 10:
        literal_patterns.append(re.escape(hex(offset).upper().replace("X", "x")))
    literal = "(?:%s)(?:LL|i64|i32|uLL|ULL|u)?" % "|".join(dict.fromkeys(literal_patterns))
    return r"%s\s*\+\s*%s" % (re.escape(base), literal)


def _numeric_offset_value(literal: str) -> int:
    return int((literal or "0").lower(), 16 if (literal or "").lower().startswith("0x") else 10)


def _is_write_only_assignment_sink(text: str, name: str, min_assignments: int = 2) -> bool:
    assignments = list(_direct_assignments_to(text, name))
    if len(assignments) < min_assignments:
        return False
    without_assignments = text or ""
    for match in reversed(assignments):
        without_assignments = _text_without_match(without_assignments, match)
    declaration = _local_declaration_match(without_assignments, name)
    if declaration:
        without_assignments = _text_without_match(without_assignments, declaration)
    return re.search(r"\b%s\b" % re.escape(name), without_assignments) is None


def _has_direct_alias_mutation(text: str, alias: str) -> bool:
    escaped = re.escape(alias)
    return bool(
        re.search(r"(?m)^\s*%s\s*(?:[-+*/%%&|^]?=|\+\+|--)" % escaped, text)
        or re.search(r"(?m)^\s*(?:\+\+|--)\s*%s\b" % escaped, text)
    )


def _rewrite_scratch_sink_assignments(text: str, name: str) -> tuple[str, set[str]]:
    result = text or ""
    observed_identifiers: set[str] = set()
    for match in reversed(list(_direct_assignments_to(result, name))):
        indent = match.group("indent")
        rhs = match.group("rhs").strip()
        call_expression = _first_call_expression(rhs)
        if call_expression:
            replacement = "%s(void)%s;\n" % (indent, call_expression)
        else:
            replacement = ""
            observed_identifiers.update(_rhs_identifier_candidates(rhs))
        result = result[: match.start()] + replacement + result[match.end() :]
    return result, observed_identifiers


def _rhs_identifier_candidates(rhs: str) -> set[str]:
    return {
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", rhs or "")
        if token not in {"NULL", "FALSE", "TRUE", "nullptr"}
    }


def _direct_assignments_to(text: str, name: str):
    return re.finditer(
        r"(?m)^(?P<indent>[ \t]*)%s\s*=\s*(?P<rhs>[^;\n]+);[ \t]*(?:\r?\n)?" % re.escape(name),
        text or "",
    )


def _first_call_expression(text: str) -> str:
    for match in re.finditer(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", text or ""):
        call_name = match.group("name")
        if call_name in _CALL_KEYWORDS:
            continue
        open_index = (text or "").find("(", match.start())
        close_index = find_matching_paren(text or "", open_index)
        if close_index < 0:
            continue
        return (text or "")[match.start() : close_index + 1]
    return ""


def _find_unrolled_wide_array_copy(text: str) -> dict[str, object] | None:
    array_counts = _wide_array_declarations(text)
    wide_destinations = _wide_destination_declarations(text)
    lines = _line_spans(text)
    for start_index in range(len(lines)):
        match = _match_unrolled_wide_array_copy_at(text, lines, start_index, array_counts, wide_destinations)
        if match:
            return match
    return None


def _match_unrolled_wide_array_copy_at(
    text: str,
    lines: list[tuple[int, int, str]],
    start_index: int,
    array_counts: dict[str, int],
    wide_destinations: set[str],
) -> dict[str, object] | None:
    loads: dict[str, tuple[str, int]] = {}
    stores: dict[int, str] = {}
    temps: set[str] = set()
    src_name = ""
    dst_name = ""
    block_start = -1
    block_end = -1
    indent = ""

    for line_index in range(start_index, min(len(lines), start_index + 16)):
        line_start, line_end, line = lines[line_index]
        stripped = line.strip()
        if not stripped:
            if block_start >= 0:
                break
            continue
        parsed = _parse_wide_copy_line(stripped)
        if not parsed:
            break
        if block_start < 0:
            block_start = line_start
            indent = line[: len(line) - len(line.lstrip())]
        block_end = line_end

        kind = parsed["kind"]
        if kind == "load":
            current_src = str(parsed["src"])
            index = int(parsed["index"])
            temp = str(parsed["temp"])
            if src_name and current_src != src_name:
                break
            src_name = current_src
            loads[temp] = (current_src, index)
            temps.add(temp)
            continue

        current_dst = str(parsed["dst"])
        current_src = str(parsed.get("src", src_name))
        if dst_name and current_dst != dst_name:
            break
        if src_name and current_src and current_src != src_name:
            break
        dst_name = current_dst
        if current_src:
            src_name = current_src

        store_index = int(parsed["index"])
        if kind == "store_direct":
            if int(parsed["source_index"]) != store_index:
                break
            stores[store_index] = current_src
        elif kind == "store_temp":
            temp = str(parsed["temp"])
            loaded = loads.get(temp)
            if not loaded or loaded[0] != src_name or loaded[1] != store_index:
                break
            stores[store_index] = src_name
            temps.add(temp)

        candidate = _validated_wide_copy_match(
            text,
            block_start,
            block_end,
            indent,
            src_name,
            dst_name,
            stores,
            temps,
            array_counts,
            wide_destinations,
        )
        if candidate:
            return candidate
    return None


def _parse_wide_copy_line(line: str) -> dict[str, object] | None:
    match = re.fullmatch(
        r"(?P<temp>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\[\s*(?P<index>\d+)\s*\]\s*;",
        line,
    )
    if match:
        return {
            "kind": "load",
            "temp": match.group("temp"),
            "src": match.group("src"),
            "index": int(match.group("index")),
        }
    match = re.fullmatch(
        r"\*\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\[\s*0\s*\]\s*;",
        line,
    )
    if match:
        return {
            "kind": "store_direct",
            "dst": match.group("dst"),
            "src": match.group("src"),
            "index": 0,
            "source_index": 0,
        }
    match = re.fullmatch(
        r"(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>\d+)\s*\]\s*=\s*"
        r"(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<source_index>\d+)\s*\]\s*;",
        line,
    )
    if match:
        return {
            "kind": "store_direct",
            "dst": match.group("dst"),
            "src": match.group("src"),
            "index": int(match.group("index")),
            "source_index": int(match.group("source_index")),
        }
    match = re.fullmatch(
        r"(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<index>\d+)\s*\]\s*=\s*"
        r"(?P<temp>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        line,
    )
    if match:
        return {
            "kind": "store_temp",
            "dst": match.group("dst"),
            "index": int(match.group("index")),
            "temp": match.group("temp"),
        }
    return None


def _validated_wide_copy_match(
    text: str,
    start: int,
    end: int,
    indent: str,
    src: str,
    dst: str,
    stores: dict[int, str],
    temps: set[str],
    array_counts: dict[str, int],
    wide_destinations: set[str],
) -> dict[str, object] | None:
    if not src or not dst or src not in array_counts or dst not in wide_destinations:
        return None
    count = array_counts[src]
    if count < 2:
        return None
    expected_indices = set(range(count))
    if set(stores) != expected_indices:
        return None
    if any(stores[index] != src for index in expected_indices):
        return None
    if not temps:
        return None
    block_text = text[start:end]
    for temp in temps:
        if not _wide_temp_declaration_exists(text, temp):
            return None
        outside = text[:start] + text[end:]
        declaration = _wide_temp_declaration_match(outside, temp)
        outside_without_decl = _text_without_match(outside, declaration) if declaration else outside
        if re.search(r"\b%s\b" % re.escape(temp), outside_without_decl):
            return None
        if len(re.findall(r"\b%s\b" % re.escape(temp), block_text)) != 2:
            return None
    return {
        "start": start,
        "end": end,
        "indent": indent,
        "src": src,
        "dst": dst,
        "temps": sorted(temps),
    }


def _wide_array_declarations(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    pattern = re.compile(
        r"(?m)^\s*(?:_OWORD|__int128)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\[\s*(?P<count>\d+)\s*\]\s*;[^\n]*$"
    )
    for match in pattern.finditer(text or ""):
        result[match.group("name")] = int(match.group("count"))
    return result


def _wide_destination_declarations(text: str) -> set[str]:
    result = set(_wide_array_declarations(text))
    pattern = re.compile(r"(?m)^\s*(?:_OWORD|__int128)\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;[^\n]*$")
    for match in pattern.finditer(text or ""):
        result.add(match.group("name"))
    return result


def _wide_temp_declaration_exists(text: str, name: str) -> bool:
    return _wide_temp_declaration_match(text, name) is not None


def _wide_temp_declaration_match(text: str, name: str) -> re.Match[str] | None:
    return re.search(r"(?m)^\s*(?:_OWORD|__int128)\s+%s\s*;[^\n]*\n?" % re.escape(name), text or "")


def _remove_unused_wide_temp_declaration(text: str, name: str) -> str:
    declaration = _wide_temp_declaration_match(text, name)
    if not declaration:
        return text
    without_declaration = _text_without_match(text, declaration)
    if re.search(r"\b%s\b" % re.escape(name), without_declaration):
        return text
    return without_declaration


def _remove_unused_local_declaration(text: str, name: str) -> str:
    declaration = _local_declaration_match(text, name)
    if not declaration:
        return text
    without_declaration = _text_without_match(text, declaration)
    if re.search(r"\b%s\b" % re.escape(name), without_declaration):
        return text
    return without_declaration


def _local_declaration_match(text: str, name: str) -> re.Match[str] | None:
    return re.search(
        r"(?m)^[ \t]*(?:const\s+)?(?:struct\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?\s+"
        r"[\*\&]*\s*%s\s*(?:\[[^\]]+\])?\s*;[^\n]*\n?" % re.escape(name),
        text or "",
    )


def _line_spans(text: str) -> list[tuple[int, int, str]]:
    result = []
    offset = 0
    for line in (text or "").splitlines(keepends=True):
        line_end = offset + len(line)
        result.append((offset, line_end, line.rstrip("\r\n")))
        offset = line_end
    return result


def _pointer_local_declarations(text: str) -> set[str]:
    result: set[str] = set()
    pattern = re.compile(
        r"(?m)^\s*(?P<type>(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*\*)+|P[A-Z0-9_]+)\s*"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;[^\n]*$"
    )
    for match in pattern.finditer(text or ""):
        result.add(match.group("name"))
    return result


def _remove_declaration_and_assignment(text: str, alias: str, target: str) -> str:
    result = re.sub(
        r"(?m)^\s*(?:(?:struct\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*\*)+|P[A-Z0-9_]+)\s*"
        r"%s\s*;[^\n]*\n" % re.escape(alias),
        "",
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^\s*%s\s*=\s*%s\s*;\s*\n" % (re.escape(alias), re.escape(target)),
        "",
        result,
        count=1,
    )
    return result


def _text_without_match(text: str, match: re.Match[str]) -> str:
    return text[: match.start()] + text[match.end() :]
