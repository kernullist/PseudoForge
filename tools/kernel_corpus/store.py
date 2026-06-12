from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from tools.kernel_corpus.ea import normalize_ea
from tools.kernel_corpus.errors import InvalidCorpusError
from tools.kernel_corpus.schema import PACK_SCHEMA_VERSION


class KernelCorpusConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


def connect_database(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), factory=KernelCorpusConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_schema(connection: sqlite3.Connection) -> bool:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS corpus_manifest (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS functions (
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

        CREATE TABLE IF NOT EXISTS function_tags (
            ea TEXT NOT NULL,
            tag TEXT NOT NULL,
            PRIMARY KEY (ea, tag)
        );

        CREATE TABLE IF NOT EXISTS call_edges (
            src_ea TEXT NOT NULL,
            dst_ea TEXT NOT NULL,
            edge_kind TEXT NOT NULL,
            PRIMARY KEY (src_ea, dst_ea, edge_kind)
        );

        CREATE TABLE IF NOT EXISTS function_imports (
            ea TEXT NOT NULL,
            import_name TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS function_strings (
            ea TEXT NOT NULL,
            string_value TEXT NOT NULL
        );
        """
    )
    fts5_enabled = sqlite_supports_fts5(connection)
    if fts5_enabled:
        connection.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS function_fts USING fts5(
                ea UNINDEXED,
                name,
                tags,
                terms,
                imports,
                strings,
                interesting_lines,
                cleaned_excerpt
            )
            """
        )
    connection.commit()
    return fts5_enabled


def sqlite_supports_fts5(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("CREATE VIRTUAL TABLE temp.__kernel_corpus_fts_probe USING fts5(value)")
        connection.execute("DROP TABLE temp.__kernel_corpus_fts_probe")
    except sqlite3.Error:
        return False
    return True


def write_manifest_rows(connection: sqlite3.Connection, manifest: dict[str, Any]) -> None:
    rows = [(key, _manifest_value(value)) for key, value in sorted(manifest.items())]
    connection.executemany(
        "INSERT OR REPLACE INTO corpus_manifest(key, value) VALUES (?, ?)",
        rows,
    )
    connection.commit()


def import_index(
    connection: sqlite3.Connection,
    index: dict[str, Any],
    corpus_root: str | Path,
    max_cleaned_chars: int,
    fts5_enabled: bool,
) -> dict[str, int]:
    functions = _coerce_list(index.get("functions"))
    corpus_path = Path(corpus_root)
    max_excerpt = max(0, int(max_cleaned_chars or 0))
    try:
        _clear_import_tables(connection, fts5_enabled)
        for function in sorted(
            (_coerce_dict(item) for item in functions if isinstance(item, dict)),
            key=_function_sort_key,
        ):
            if not function:
                continue
            ea = _function_ea(function)
            artifacts = _coerce_dict(function.get("artifacts"))
            tags = [str(item) for item in _coerce_list(function.get("tags")) if str(item)]
            terms = [str(item) for item in _coerce_list(function.get("terms")) if str(item)]
            imports = _import_names(function)
            strings = _string_values(function)
            interesting_lines = [str(item) for item in _coerce_list(function.get("interesting_lines")) if str(item)]
            counts = _coerce_dict(function.get("counts"))
            cleaned_excerpt = str(function.get("cleaned_excerpt", "") or "")[:max_excerpt]
            directory = _resolve_path_string(corpus_path, str(function.get("directory", "") or ""))
            summary_path = _resolve_path_string(corpus_path, str(function.get("summary_path", "") or ""))
            cleaned_path = _resolve_path_string(corpus_path, str(artifacts.get("cleaned_pseudocode", "") or ""))
            raw_path = _resolve_path_string(corpus_path, str(artifacts.get("raw_pseudocode", "") or ""))
            diff_path = _resolve_path_string(corpus_path, str(artifacts.get("raw_vs_cleaned_diff", "") or ""))

            connection.execute(
                """
                INSERT OR REPLACE INTO functions(
                    ea, name, directory, summary_path, cleaned_path, raw_path,
                    diff_path, mode, llm_status, warning_count,
                    buffer_contract_count, cleaned_excerpt
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ea,
                    str(function.get("name", "") or ""),
                    directory,
                    summary_path,
                    cleaned_path,
                    raw_path,
                    diff_path,
                    str(function.get("mode", "") or ""),
                    str(function.get("llm_status", "") or ""),
                    int(counts.get("warnings", 0) or 0),
                    int(counts.get("buffer_contracts", 0) or 0),
                    cleaned_excerpt,
                ),
            )
            _insert_tags(connection, ea, tags)
            _insert_edges(connection, ea, function)
            _insert_values(connection, "function_imports", "import_name", ea, imports)
            _insert_values(connection, "function_strings", "string_value", ea, strings)
            if fts5_enabled:
                connection.execute(
                    """
                    INSERT INTO function_fts(
                        ea, name, tags, terms, imports, strings,
                        interesting_lines, cleaned_excerpt
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ea,
                        str(function.get("name", "") or ""),
                        " ".join(tags),
                        " ".join(terms),
                        " ".join(imports),
                        " ".join(strings),
                        "\n".join(interesting_lines),
                        cleaned_excerpt,
                    ),
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "function_count": _table_count(connection, "functions"),
        "unique_ea_count": _table_count(connection, "functions"),
        "tag_count": _table_count(connection, "function_tags"),
        "edge_count": _table_count(connection, "call_edges"),
        "import_count": _table_count(connection, "function_imports"),
        "string_count": _table_count(connection, "function_strings"),
        "fts_row_count": _table_count(connection, "function_fts") if fts5_enabled else 0,
    }


def read_manifest_rows(connection: sqlite3.Connection) -> dict[str, str]:
    return {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key, value FROM corpus_manifest")}


def _table_count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])


def _clear_import_tables(connection: sqlite3.Connection, fts5_enabled: bool) -> None:
    for table in (
        "function_strings",
        "function_imports",
        "call_edges",
        "function_tags",
        "functions",
        "corpus_manifest",
    ):
        connection.execute("DELETE FROM %s" % table)
    if fts5_enabled:
        connection.execute("DELETE FROM function_fts")


def _function_ea(function: dict[str, Any]) -> str:
    try:
        return normalize_ea(function.get("ea", ""))
    except (TypeError, ValueError) as exc:
        raise InvalidCorpusError("Function item has invalid EA: %r" % function.get("ea", "")) from exc


def _function_sort_key(function: dict[str, Any]) -> tuple[int, str]:
    try:
        return (int(normalize_ea(function.get("ea", "")), 0), str(function.get("name", "") or ""))
    except (TypeError, ValueError):
        return (2**64 - 1, str(function.get("name", "") or ""))


def _insert_tags(connection: sqlite3.Connection, ea: str, tags: list[str]) -> int:
    rows = [(ea, tag) for tag in dict.fromkeys(tags)]
    connection.executemany("INSERT OR IGNORE INTO function_tags(ea, tag) VALUES (?, ?)", rows)
    return len(rows)


def _insert_edges(connection: sqlite3.Connection, ea: str, function: dict[str, Any]) -> int:
    edges = []
    for callee in _coerce_list(function.get("callee_eas")):
        try:
            edges.append((ea, normalize_ea(callee), "calls"))
        except (TypeError, ValueError):
            continue
    for caller in _coerce_list(function.get("caller_eas")):
        try:
            edges.append((normalize_ea(caller), ea, "calls"))
        except (TypeError, ValueError):
            continue
    rows = list(dict.fromkeys(edges))
    connection.executemany(
        "INSERT OR IGNORE INTO call_edges(src_ea, dst_ea, edge_kind) VALUES (?, ?, ?)",
        rows,
    )
    return len(rows)


def _insert_values(connection: sqlite3.Connection, table: str, column: str, ea: str, values: list[str]) -> int:
    rows = [(ea, value) for value in dict.fromkeys(values)]
    if not rows:
        return 0
    connection.executemany(
        "INSERT INTO %s(ea, %s) VALUES (?, ?)" % (table, column),
        rows,
    )
    return len(rows)


def _import_names(function: dict[str, Any]) -> list[str]:
    result = []
    for item in _coerce_list(function.get("imports_called")):
        if isinstance(item, dict):
            name = str(item.get("name", "") or "")
        else:
            name = str(item or "")
        if name:
            result.append(name)
    return result


def _string_values(function: dict[str, Any]) -> list[str]:
    result = []
    for item in _coerce_list(function.get("strings_referenced")):
        if isinstance(item, dict):
            value = str(item.get("value", "") or "")
        else:
            value = str(item or "")
        if value:
            result.append(value)
    return result


def _resolve_path_string(corpus_root: Path, value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if path.is_absolute():
        return str(path)
    corpus_relative = corpus_root / path
    if corpus_relative.exists():
        return str(corpus_relative.resolve())
    return str(path.resolve())


def _coerce_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _coerce_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _manifest_value(value: Any) -> str:
    if isinstance(value, (dict, list, tuple, bool)) or value is None:
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


assert PACK_SCHEMA_VERSION
