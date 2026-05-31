from __future__ import annotations

import re


def finalize_rendered_c_like_text(text: str) -> str:
    return escape_path_like_string_literals(text)


def escape_path_like_string_literals(text: str) -> str:
    string_re = re.compile(
        r"(?P<prefix>(?:\b(?:L|u8|u|U))?\")(?P<body>(?:\\.|[^\"\\])*)(?P<quote>\")"
    )

    def repl(match: re.Match[str]) -> str:
        body = match.group("body")
        if not _looks_like_path_literal(body):
            return match.group(0)
        return match.group("prefix") + _escape_single_backslashes(body) + match.group("quote")

    return string_re.sub(repl, text)


def _looks_like_path_literal(body: str) -> bool:
    if "\\" not in body:
        return False

    normalized = body.replace("\\\\", "\\")
    if re.search(r"\b[A-Za-z]:\\", normalized):
        return True
    if _has_rooted_path_shape(normalized):
        return True
    return _has_backslash_path_segments(normalized) and _has_non_c_escape_backslash(body)


def _has_rooted_path_shape(value: str) -> bool:
    if not value.startswith("\\"):
        return False
    token_match = re.match(r"\\(?P<token>[^\\]+)", value)
    if not token_match:
        return False
    token = token_match.group("token")
    if not token:
        return False
    if len(token) == 1 and token in "abfnrtv?'\"\\":
        return False
    if "\\" in value[1:]:
        return True
    return len(token) > 1 and (token[0].isupper() or token[0] == "?" or "." in token)


def _has_backslash_path_segments(value: str) -> bool:
    return bool(re.search(r"(?:^|[A-Za-z0-9_.?$-])\\[A-Za-z0-9_.?$-]+\\", value))


def _has_non_c_escape_backslash(body: str) -> bool:
    index = 0
    while index < len(body):
        if body[index] != "\\":
            index += 1
            continue
        if index + 1 >= len(body):
            return True
        next_char = body[index + 1]
        if next_char == "\\":
            index += 2
            continue
        if next_char in "abfnrtv?'\"01234567":
            index += 2
            continue
        if next_char in "xXuU":
            index += 2
            continue
        return True
    return False


def _escape_single_backslashes(body: str) -> str:
    result = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue
        if index + 1 < len(body) and body[index + 1] == "\\":
            result.append("\\\\")
            index += 2
            continue
        result.append("\\\\")
        index += 1
    return "".join(result)
