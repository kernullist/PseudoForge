from __future__ import annotations

import re


def enforce_generated_code_style(text: str, _capture: object | None = None) -> str:
    lines = (text or "").splitlines()
    lines = _normalize_joined_else_lines(lines)
    lines = _split_inline_open_braces(lines)
    lines = _enforce_required_control_braces(lines)
    lines = _expand_else_if_chains(lines)
    lines = _repair_nested_else_after_empty_if(lines)
    lines = _flatten_else_after_terminal_if(lines)
    lines = _invert_positive_guard_with_terminal_else(lines)
    return "\n".join(lines)


def strip_outer_parentheses(text: str) -> str:
    stripped = text.strip()
    while stripped.startswith("(") and stripped.endswith(")") and _outer_parentheses_wrap(stripped):
        stripped = stripped[1:-1].strip()
    return stripped


def leading_ws(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _normalize_joined_else_lines(lines: list[str]) -> list[str]:
    normalized: list[str] = []
    for line in lines:
        stripped = line.strip()
        indent = leading_ws(line)
        if stripped.startswith("} else"):
            normalized.append(indent + "}")
            normalized.append(indent + stripped[2:].strip())
        else:
            normalized.append(line)
    return normalized


def _split_inline_open_braces(lines: list[str]) -> list[str]:
    result: list[str] = []
    for line in lines:
        if _should_split_inline_open_brace(line):
            brace_index = line.rfind("{")
            before = line[:brace_index].rstrip()
            result.append(before)
            result.append(leading_ws(line) + "{")
        else:
            result.append(line)
    return result


def _should_split_inline_open_brace(line: str) -> bool:
    stripped = line.strip()
    if stripped == "{" or not stripped.endswith("{"):
        return False
    if stripped.startswith(("//", "/*", "*")):
        return False
    before = stripped[:-1].rstrip()
    if not before:
        return False
    return (
        before.endswith(")")
        or before in {"else", "do"}
        or before.startswith(("if ", "for ", "while ", "switch ", "else if "))
    )


def _enforce_required_control_braces(lines: list[str]) -> list[str]:
    updated = list(lines)
    index = len(updated) - 1
    while index >= 0:
        stripped = updated[index].strip()
        if _requires_brace_body(stripped):
            header_end = _control_header_end_index(updated, index)
            if header_end < index:
                index -= 1
                continue
            body_index = _next_meaningful_index(updated, header_end + 1)
            if body_index >= 0 and updated[body_index].strip() != "{":
                body_end = _find_statement_end(updated, body_index)
                if body_end >= body_index and _can_wrap_body(updated[body_index].strip()):
                    indent = leading_ws(updated[index])
                    replacement = [indent + "{"]
                    replacement.extend(
                        _reindent_wrapped_lines(updated[body_index : body_end + 1], indent + "  ")
                    )
                    replacement.append(indent + "}")
                    updated = updated[: header_end + 1] + replacement + updated[body_end + 1 :]
        index -= 1
    return updated


def _expand_else_if_chains(lines: list[str]) -> list[str]:
    updated = list(lines)
    index = len(updated) - 1
    while index >= 0:
        stripped = updated[index].strip()
        if _starts_else_if(stripped):
            header_end = _control_header_end_index(updated, index)
            if header_end != index:
                index -= 1
                continue
            end_index = _find_statement_end(updated, index)
            indent = leading_ws(updated[index])
            inner_if = "if" + stripped[len("else if") :]
            replacement = [
                indent + "else",
                indent + "{",
                indent + "  " + inner_if,
            ]
            replacement.extend(_indent_lines(updated[index + 1 : end_index + 1], "  "))
            replacement.append(indent + "}")
            updated = updated[:index] + replacement + updated[end_index + 1 :]
        index -= 1
    return updated


def _requires_brace_body(stripped: str) -> bool:
    if stripped.endswith(";") or stripped.endswith("{"):
        return False
    return (
        _starts_if(stripped)
        or _starts_else_if(stripped)
        or _starts_else(stripped)
        or _starts_for(stripped)
        or _starts_while(stripped)
    )


def _can_wrap_body(stripped: str) -> bool:
    if not stripped:
        return False
    if stripped.endswith(":"):
        return False
    return not stripped.startswith(("case ", "default:"))


def _find_statement_end(lines: list[str], start_index: int) -> int:
    if start_index < 0 or start_index >= len(lines):
        return start_index
    stripped = lines[start_index].strip()
    if stripped == "{":
        return _find_matching_brace(lines, start_index)
    if _starts_if(stripped) or _starts_else_if(stripped):
        if _control_header_end_index(lines, start_index) < start_index:
            return start_index
        body_end = _find_body_end(lines, start_index)
        next_index = _next_meaningful_index(lines, body_end + 1)
        if next_index >= 0 and _starts_else(lines[next_index].strip()):
            return _find_statement_end(lines, next_index)
        return body_end
    if _starts_else(stripped):
        return _find_body_end(lines, start_index)
    if (_starts_for(stripped) or _starts_while(stripped)) and not stripped.endswith(";"):
        if _control_header_end_index(lines, start_index) < start_index:
            return start_index
        return _find_body_end(lines, start_index)
    return start_index


def _find_body_end(lines: list[str], header_index: int) -> int:
    header_end = _control_header_end_index(lines, header_index)
    if header_end < header_index:
        header_end = header_index
    body_index = _next_meaningful_index(lines, header_end + 1)
    if body_index < 0:
        return header_index
    if lines[body_index].strip() == "{":
        return _find_matching_brace(lines, body_index)
    return _find_statement_end(lines, body_index)


def _control_header_end_index(lines: list[str], start_index: int) -> int:
    if start_index < 0 or start_index >= len(lines):
        return -1
    stripped = lines[start_index].strip()
    if not (
        _starts_if(stripped)
        or _starts_else_if(stripped)
        or _starts_for(stripped)
        or _starts_while(stripped)
        or stripped.startswith("switch ")
    ):
        return start_index
    if "(" not in stripped:
        return -1

    depth = 0
    seen_open = False
    for index in range(start_index, len(lines)):
        for char in lines[index]:
            if char == "(":
                depth += 1
                seen_open = True
            elif char == ")":
                depth -= 1
                if seen_open and depth <= 0:
                    return index
        if index > start_index and lines[index].strip().endswith(";") and not seen_open:
            return -1
    return -1


def _find_matching_brace(lines: list[str], open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(lines)):
        depth += lines[index].count("{")
        depth -= lines[index].count("}")
        if depth <= 0:
            return index
    return open_index


def _find_matching_open_brace(lines: list[str], close_index: int) -> int:
    depth = 0
    for index in range(close_index, -1, -1):
        depth += lines[index].count("}")
        depth -= lines[index].count("{")
        if depth <= 0:
            return index
    return close_index


def _next_meaningful_index(lines: list[str], start_index: int) -> int:
    for index in range(start_index, len(lines)):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if _is_comment_line(stripped):
            continue
        return index
    return -1


def _indent_lines(lines: list[str], prefix: str) -> list[str]:
    return [prefix + line if line.strip() else line for line in lines]


def _reindent_wrapped_lines(lines: list[str], target_indent: str) -> list[str]:
    nonblank = [line for line in lines if line.strip()]
    if not nonblank:
        return lines
    minimum_indent = min(len(leading_ws(line)) for line in nonblank)
    return [
        target_indent + line[minimum_indent:] if line.strip() else line
        for line in lines
    ]


def _starts_if(stripped: str) -> bool:
    return stripped.startswith("if ")


def _starts_else_if(stripped: str) -> bool:
    return stripped.startswith("else if ")


def _starts_else(stripped: str) -> bool:
    return stripped == "else" or stripped.startswith("else ")


def _starts_for(stripped: str) -> bool:
    return stripped.startswith("for ")


def _starts_while(stripped: str) -> bool:
    return stripped.startswith("while ")


def _repair_nested_else_after_empty_if(lines: list[str]) -> list[str]:
    updated = list(lines)
    index = len(updated) - 1
    while index >= 0:
        stripped = updated[index].strip()
        if not _starts_if(stripped):
            index -= 1
            continue
        if _control_header_end_index(updated, index) != index:
            index -= 1
            continue
        if_open_index = _next_meaningful_index(updated, index + 1)
        if if_open_index < 0 or updated[if_open_index].strip() != "{":
            index -= 1
            continue
        if_close_index = _find_matching_brace(updated, if_open_index)
        indent = leading_ws(updated[index])
        branch = _nested_else_body_after_empty_if(updated, if_open_index, if_close_index, indent)
        if branch is None:
            index -= 1
            continue
        else_body = branch

        condition = _extract_if_condition(stripped)
        inverted_condition = _invert_condition(condition) or _negate_condition(condition)
        if not inverted_condition:
            index -= 1
            continue

        replacement = [
            "%sif ( %s )" % (indent, inverted_condition),
            indent + "{",
        ]
        replacement.extend(else_body)
        replacement.append(indent + "}")
        updated = updated[:index] + replacement + updated[if_close_index + 1 :]
        index = min(index, len(updated) - 1)
    return updated


def _nested_else_body_after_empty_if(
    lines: list[str],
    if_open_index: int,
    if_close_index: int,
    indent: str,
) -> list[str] | None:
    branch_index = _next_meaningful_index(lines, if_open_index + 1)
    if branch_index < 0:
        return None

    stripped = lines[branch_index].strip()
    if stripped == "else":
        branch_open_index = _next_meaningful_index(lines, branch_index + 1)
        if branch_open_index < 0 or lines[branch_open_index].strip() != "{":
            return None
        branch_close_index = _find_matching_brace(lines, branch_open_index)
        if if_close_index <= branch_close_index:
            return None
        after_branch_index = _next_meaningful_index(lines, branch_close_index + 1)
        if after_branch_index != if_close_index:
            return None

        else_body = _unindent_else_body(lines[branch_open_index + 1 : branch_close_index], indent + "  ")
        return else_body

    if _starts_else_if(stripped):
        branch_end_index = _find_statement_end(lines, branch_index)
        if branch_end_index >= if_close_index:
            return None
        after_branch_index = _next_meaningful_index(lines, branch_end_index + 1)
        if after_branch_index != if_close_index:
            return None
        branch_body = list(lines[branch_index : branch_end_index + 1])
        branch_body[0] = leading_ws(branch_body[0]) + "if" + stripped[len("else if") :]
        return branch_body

    return None


def _flatten_else_after_terminal_if(lines: list[str]) -> list[str]:
    updated = list(lines)
    index = len(updated) - 1
    while index >= 0:
        if updated[index].strip() != "else":
            index -= 1
            continue

        previous_index = _previous_meaningful_index(updated, index - 1)
        next_index = _next_meaningful_index(updated, index + 1)
        if previous_index < 0 or next_index < 0:
            index -= 1
            continue
        if updated[previous_index].strip() != "}" or updated[next_index].strip() != "{":
            index -= 1
            continue

        if_open_index = _find_matching_open_brace(updated, previous_index)
        if_header_index = _previous_meaningful_index(updated, if_open_index - 1)
        if if_header_index < 0 or not _starts_if(updated[if_header_index].strip()):
            index -= 1
            continue
        if not _block_has_terminal_tail(updated[if_open_index + 1 : previous_index]):
            index -= 1
            continue

        else_close_index = _find_matching_brace(updated, next_index)
        indent = leading_ws(updated[index])
        body = _unindent_else_body(updated[next_index + 1 : else_close_index], indent)
        updated = updated[:index] + body + updated[else_close_index + 1 :]
        index = min(index, len(updated) - 1)
    return updated


def _invert_positive_guard_with_terminal_else(lines: list[str]) -> list[str]:
    updated = list(lines)
    index = len(updated) - 1
    while index >= 0:
        stripped = updated[index].strip()
        if not _starts_if(stripped):
            index -= 1
            continue
        if _control_header_end_index(updated, index) != index:
            index -= 1
            continue

        if_open_index = _next_meaningful_index(updated, index + 1)
        if if_open_index < 0 or updated[if_open_index].strip() != "{":
            index -= 1
            continue
        if_close_index = _find_matching_brace(updated, if_open_index)
        else_index = _next_meaningful_index(updated, if_close_index + 1)
        if else_index < 0 or updated[else_index].strip() != "else":
            index -= 1
            continue
        else_open_index = _next_meaningful_index(updated, else_index + 1)
        if else_open_index < 0 or updated[else_open_index].strip() != "{":
            index -= 1
            continue
        else_close_index = _find_matching_brace(updated, else_open_index)
        else_body = updated[else_open_index + 1 : else_close_index]
        if not _block_has_terminal_tail(else_body):
            index -= 1
            continue

        condition = _extract_if_condition(stripped)
        inverted_condition = _invert_condition(condition)
        if not inverted_condition:
            index -= 1
            continue

        indent = leading_ws(updated[index])
        if_body = _unindent_else_body(updated[if_open_index + 1 : if_close_index], indent)
        replacement = [
            "%sif ( %s )" % (indent, inverted_condition),
            indent + "{",
        ]
        replacement.extend(else_body)
        replacement.append(indent + "}")
        replacement.extend(if_body)
        updated = updated[:index] + replacement + updated[else_close_index + 1 :]
        index = min(index, len(updated) - 1)
    return updated


def _extract_if_condition(stripped: str) -> str:
    match = re.match(r"if\s*\(\s*(?P<condition>.+?)\s*\)\s*$", stripped)
    if match is None:
        return ""
    return match.group("condition").strip()


def _invert_condition(condition: str) -> str:
    if not condition:
        return ""
    parts = _split_top_level_operator(condition, "&&")
    if len(parts) > 1:
        inverted_parts = [_invert_condition(part) for part in parts]
        if all(inverted_parts):
            return " || ".join(inverted_parts)
        return ""

    parts = _split_top_level_operator(condition, "||")
    if len(parts) > 1:
        inverted_parts = [_invert_condition(part) for part in parts]
        if all(inverted_parts):
            return " && ".join(inverted_parts)
        return ""

    return _invert_simple_condition(condition)


def _negate_condition(condition: str) -> str:
    stripped = strip_outer_parentheses(condition.strip())
    if not stripped:
        return ""
    return "!(%s)" % stripped


def _split_top_level_operator(condition: str, operator: str) -> list[str]:
    parts = []
    current = []
    depth = 0
    index = 0
    while index < len(condition):
        char = condition[index]
        if char in {"(", "["}:
            depth += 1
        elif char in {")", "]"}:
            depth = max(0, depth - 1)
        if depth == 0 and condition.startswith(operator, index):
            parts.append("".join(current).strip())
            current = []
            index += len(operator)
            continue
        current.append(char)
        index += 1
    item = "".join(current).strip()
    if item:
        parts.append(item)
    return parts


def _invert_simple_condition(condition: str) -> str:
    stripped = strip_outer_parentheses(condition.strip())
    if not stripped:
        return ""
    if stripped.startswith("!"):
        return stripped[1:].strip()
    comparison = _split_top_level_comparison(stripped)
    if comparison is not None:
        left, op, right = comparison
        inverted_ops = {
            ">=": "<",
            "<=": ">",
            ">": "<=",
            "<": ">=",
            "==": "!=",
            "!=": "==",
        }
        return "%s %s %s" % (left, inverted_ops[op], right)
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*|\.[A-Za-z_][A-Za-z0-9_]*)*$", stripped):
        return "!" + stripped
    return ""


def _split_top_level_comparison(condition: str) -> tuple[str, str, str] | None:
    depth = 0
    index = 0
    while index < len(condition):
        char = condition[index]
        if char in {"(", "["}:
            depth += 1
            index += 1
            continue
        if char in {")", "]"}:
            depth = max(0, depth - 1)
            index += 1
            continue
        if depth != 0:
            index += 1
            continue

        for operator in (">=", "<=", "==", "!="):
            if condition.startswith(operator, index) and _is_comparison_boundary(condition, index, operator):
                left = condition[:index].strip()
                right = condition[index + len(operator) :].strip()
                if left and right:
                    return left, operator, right
        if char in {"<", ">"} and _is_comparison_boundary(condition, index, char):
            left = condition[:index].strip()
            right = condition[index + 1 :].strip()
            if left and right:
                return left, char, right
        index += 1
    return None


def _is_comparison_boundary(condition: str, index: int, operator: str) -> bool:
    previous_char = condition[index - 1] if index > 0 else ""
    next_index = index + len(operator)
    next_char = condition[next_index] if next_index < len(condition) else ""
    if operator == ">" and (previous_char in {"-", ">"} or next_char == ">"):
        return False
    if operator == "<" and (previous_char == "<" or next_char == "<"):
        return False
    if operator in {">=", "<="} and previous_char in {operator[0], "-"}:
        return False
    return True


def _outer_parentheses_wrap(text: str) -> bool:
    depth = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
    return depth == 0


def _previous_meaningful_index(lines: list[str], start_index: int) -> int:
    for index in range(start_index, -1, -1):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if _is_comment_line(stripped):
            continue
        return index
    return -1


def _is_comment_line(stripped: str) -> bool:
    return (
        stripped.startswith("//")
        or stripped.startswith("/*")
        or (stripped.startswith("*") and (len(stripped) == 1 or stripped[1].isspace() or stripped[1] == "/"))
    )


def _block_has_terminal_tail(lines: list[str]) -> bool:
    index = _previous_meaningful_index(lines, len(lines) - 1)
    if index < 0:
        return False
    stripped = lines[index].strip()
    return (
        stripped.startswith("return ")
        or stripped.startswith("goto ")
        or stripped in {"break;", "continue;"}
        or stripped.startswith("__fastfail(")
    )


def _unindent_else_body(lines: list[str], target_indent: str) -> list[str]:
    source_indent = target_indent + "  "
    result = []
    for line in lines:
        if line.startswith(source_indent):
            result.append(target_indent + line[len(source_indent) :])
        else:
            result.append(line)
    return result
