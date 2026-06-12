from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.ea import normalize_ea, normalize_ea_list
from tools.kernel_corpus.errors import QueryError
from tools.kernel_corpus.schema import EVIDENCE_PACK_SCHEMA_VERSION, MANIFEST_FILENAME, SQLITE_FILENAME
from tools.kernel_corpus.store import connect_database, read_manifest_rows

DEFAULT_SEARCH_LIMIT = 20
MAX_SEARCH_LIMIT = 200
DEFAULT_NEIGHBOR_LIMIT = 100
MAX_NEIGHBOR_LIMIT = 1000


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        payload = _run_command(args)
    except (OSError, QueryError, ValueError) as exc:
        print("Kernel corpus query failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def corpus_status(pack_root: str | Path) -> dict[str, Any]:
    paths = _pack_paths(pack_root)
    manifest = _read_manifest(paths["manifest_path"])
    warnings = []
    counts: dict[str, int] = {}
    with connect_database(paths["sqlite_path"]) as connection:
        for table in ("functions", "function_tags", "call_edges", "function_imports", "function_strings"):
            counts[table] = _table_count(connection, table)
        counts["function_fts"] = _manifest_int(manifest, "fts_row_count")
        if counts["function_fts"] < 0:
            counts["function_fts"] = _table_count(connection, "function_fts") if _has_fts(connection) else 0
        db_manifest = read_manifest_rows(connection)
    if str(manifest.get("source_index_sha256", "")) != str(db_manifest.get("source_index_sha256", "")):
        warnings.append("Manifest hash differs between manifest.json and corpus_manifest table.")
    return {
        "ok": True,
        "pack_root": str(paths["pack_root"]),
        "schema_version": str(manifest.get("pack_schema", "")),
        "manifest_path": str(paths["manifest_path"]),
        "sqlite_path": str(paths["sqlite_path"]),
        "manifest": manifest,
        "counts": counts,
        "warnings": warnings,
    }


def search_functions(
    pack_root: str | Path,
    query: str = "",
    tags: list[str] | tuple[str, ...] | None = None,
    name_regex: str = "",
    limit: int = DEFAULT_SEARCH_LIMIT,
    include_excerpt: bool = False,
) -> list[dict[str, Any]]:
    paths = _pack_paths(pack_root)
    bounded_limit = _bounded_limit(limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT)
    tag_values = [str(tag) for tag in (tags or []) if str(tag)]
    query_text = str(query or "").strip()
    regex_text = str(name_regex or "").strip()
    with connect_database(paths["sqlite_path"]) as connection:
        reasons_by_ea: dict[str, set[str]] = {}
        sets: list[set[str]] = []
        if query_text:
            query_eas = _search_query_eas(connection, query_text, bounded_limit * 20, reasons_by_ea)
            sets.append(set(query_eas))
        if tag_values:
            tag_eas = set(_search_tag_eas(connection, tag_values))
            for ea in tag_eas:
                reasons_by_ea.setdefault(ea, set()).update("tag:%s" % tag for tag in tag_values)
            sets.append(tag_eas)
        if regex_text:
            regex = re.compile(regex_text)
            pool = set.intersection(*sets) if sets else set(_all_eas(connection))
            regex_eas = {
                ea
                for ea, name in _names_for_eas(connection, pool).items()
                if regex.search(name)
            }
            for ea in regex_eas:
                reasons_by_ea.setdefault(ea, set()).add("name_regex")
            sets.append(regex_eas)
        if sets:
            candidate_eas = set.intersection(*sets)
        else:
            candidate_eas = set(_all_eas(connection, limit=bounded_limit))
        score_names = _names_for_eas(connection, candidate_eas) if query_text else {}
        ordered_eas = sorted(
            candidate_eas,
            key=lambda ea: (
                -_score_candidate(score_names.get(ea, ""), query_text, reasons_by_ea.get(ea, set())),
                int(ea, 0),
            ),
        )[:bounded_limit]
        return [
            _function_payload(
                connection,
                ea,
                include_excerpt=include_excerpt,
                include_artifacts=True,
                check_artifacts=False,
                reasons=reasons_by_ea.get(ea, set()),
            )
            for ea in ordered_eas
        ]


def get_function(
    pack_root: str | Path,
    ea: str | int,
    include_excerpt: bool = True,
    include_artifacts: bool = True,
) -> dict[str, Any]:
    paths = _pack_paths(pack_root)
    normalized = normalize_ea(ea)
    with connect_database(paths["sqlite_path"]) as connection:
        if not _function_exists(connection, normalized):
            raise QueryError("Function EA was not found in pack: %s" % normalized)
        return _function_payload(
            connection,
            normalized,
            include_excerpt=include_excerpt,
            include_artifacts=include_artifacts,
            check_artifacts=True,
            reasons=set(),
        )


def find_functions_by_name(
    pack_root: str | Path,
    name: str,
    limit: int = DEFAULT_SEARCH_LIMIT,
    include_excerpt: bool = False,
) -> list[dict[str, Any]]:
    paths = _pack_paths(pack_root)
    bounded_limit = _bounded_limit(limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT)
    name_text = str(name or "").strip()
    if not name_text:
        return []
    with connect_database(paths["sqlite_path"]) as connection:
        rows = list(
            connection.execute(
                """
                SELECT ea
                FROM functions
                WHERE name = ? COLLATE NOCASE
                ORDER BY ea
                LIMIT ?
                """,
                (name_text, bounded_limit),
            )
        )
        return [
            _function_payload(
                connection,
                str(row["ea"]),
                include_excerpt=include_excerpt,
                include_artifacts=True,
                check_artifacts=False,
                reasons={"exact_name"},
            )
            for row in rows
        ]


def get_neighbors(
    pack_root: str | Path,
    ea: str | int,
    direction: str = "both",
    depth: int = 1,
    limit: int = DEFAULT_NEIGHBOR_LIMIT,
) -> dict[str, Any]:
    paths = _pack_paths(pack_root)
    root_ea = normalize_ea(ea)
    neighbor_direction = str(direction or "both").lower()
    if neighbor_direction not in {"both", "callers", "callees"}:
        raise QueryError("Unsupported direction: %s" % direction)
    max_depth = max(0, int(depth or 0))
    bounded_limit = _bounded_limit(limit, DEFAULT_NEIGHBOR_LIMIT, MAX_NEIGHBOR_LIMIT)
    with connect_database(paths["sqlite_path"]) as connection:
        if not _function_exists(connection, root_ea):
            raise QueryError("Function EA was not found in pack: %s" % root_ea)
        discovered = {root_ea: 0}
        frontier = [root_ea]
        edges: list[dict[str, str]] = []
        for current_depth in range(1, max_depth + 1):
            next_frontier: list[str] = []
            for current in frontier:
                for edge in _neighbor_edges(connection, current, neighbor_direction):
                    edges.append(edge)
                    other = edge["dst_ea"] if edge["src_ea"] == current else edge["src_ea"]
                    if other in discovered:
                        continue
                    if len(discovered) >= bounded_limit:
                        continue
                    discovered[other] = current_depth
                    next_frontier.append(other)
            frontier = next_frontier
            if not frontier:
                break
        nodes = [
            dict(
                _function_payload(
                    connection,
                    item,
                    include_excerpt=False,
                    include_artifacts=True,
                    check_artifacts=False,
                    reasons={"root"} if item == root_ea else {"neighbor"},
                ),
                depth=discovered[item],
            )
            for item in sorted(discovered, key=lambda value: (discovered[value], int(value, 0)))
        ]
    return {
        "ok": True,
        "root_ea": root_ea,
        "direction": neighbor_direction,
        "depth": max_depth,
        "limit": bounded_limit,
        "nodes": nodes,
        "edges": _dedupe_edges(edges),
        "warnings": [],
    }


def search_by_import(pack_root: str | Path, import_query: str, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict[str, Any]]:
    return _search_by_value(pack_root, "function_imports", "import_name", str(import_query or ""), "import", limit)


def search_by_string(pack_root: str | Path, string_query: str, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict[str, Any]]:
    return _search_by_value(pack_root, "function_strings", "string_value", str(string_query or ""), "string", limit)


def build_evidence_pack(
    pack_root: str | Path,
    eas: list[str | int] | tuple[str | int, ...],
    topic: str,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    paths = _pack_paths(pack_root)
    selected_eas = normalize_ea_list(eas)
    status = corpus_status(paths["pack_root"])
    functions = []
    gaps = []
    with connect_database(paths["sqlite_path"]) as connection:
        existing = {ea for ea in selected_eas if _function_exists(connection, ea)}
        for ea in selected_eas:
            if ea not in existing:
                gaps.append("Function not found in pack: %s" % ea)
                continue
            functions.append(
                _function_payload(
                    connection,
                    ea,
                    include_excerpt=True,
                    include_artifacts=True,
                    check_artifacts=True,
                    reasons={"requested"},
                )
            )
        edges = [
            dict(row)
            for row in connection.execute(
                """
                SELECT src_ea, dst_ea, edge_kind
                FROM call_edges
                WHERE src_ea IN (%s) AND dst_ea IN (%s)
                ORDER BY src_ea, dst_ea, edge_kind
                """
                % (_placeholders(existing), _placeholders(existing)),
                tuple(existing) + tuple(existing),
            )
        ] if existing else []
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    pack = {
        "schema": EVIDENCE_PACK_SCHEMA_VERSION,
        "topic": str(topic or "evidence_pack"),
        "pack_root": str(paths["pack_root"]),
        "created_at": created_at,
        "status": {
            "corpus_complete": True,
            "function_count": int(status["manifest"].get("function_count", 0) or 0),
            "skipped_count": int(status["manifest"].get("skipped_count", 0) or 0),
            "schema_version": status.get("schema_version", ""),
        },
        "functions": functions,
        "edges": edges,
        "gaps": gaps,
        "output_path": "",
    }
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(pack, indent=2, ensure_ascii=True, sort_keys=True), encoding="utf-8")
        pack["output_path"] = str(out.resolve())
    return pack


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query a read-only Kernel Corpus SQLite pack.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="Show pack status and table counts.")
    _add_pack_root(status)

    search = subparsers.add_parser("search", help="Search functions by text, tag, and name regex.")
    _add_pack_root(search)
    search.add_argument("--query", default="", help="Text query for FTS/name/excerpt search.")
    search.add_argument("--tag", action="append", default=[], help="Required tag. Can be repeated.")
    search.add_argument("--name-regex", default="", help="Python regex matched against function names.")
    search.add_argument("--limit", type=int, default=DEFAULT_SEARCH_LIMIT, help="Maximum result count.")

    get_function_parser = subparsers.add_parser("get-function", help="Get one function by EA.")
    _add_pack_root(get_function_parser)
    get_function_parser.add_argument("--ea", required=True, help="Function EA.")
    get_function_parser.add_argument("--no-excerpt", action="store_true", help="Omit cleaned excerpt.")
    get_function_parser.add_argument("--no-artifacts", action="store_true", help="Omit artifact paths.")

    neighbors = subparsers.add_parser("neighbors", help="Traverse caller/callee edges.")
    _add_pack_root(neighbors)
    neighbors.add_argument("--ea", required=True, help="Root function EA.")
    neighbors.add_argument("--direction", choices=("both", "callers", "callees"), default="both")
    neighbors.add_argument("--depth", type=int, default=1)
    neighbors.add_argument("--limit", type=int, default=DEFAULT_NEIGHBOR_LIMIT)

    search_import = subparsers.add_parser("search-import", help="Search functions by referenced import name.")
    _add_pack_root(search_import)
    search_import.add_argument("--query", required=True, help="Import substring.")
    search_import.add_argument("--limit", type=int, default=DEFAULT_SEARCH_LIMIT)

    search_string = subparsers.add_parser("search-string", help="Search functions by referenced string value.")
    _add_pack_root(search_string)
    search_string.add_argument("--query", required=True, help="String substring.")
    search_string.add_argument("--limit", type=int, default=DEFAULT_SEARCH_LIMIT)

    evidence = subparsers.add_parser("build-evidence-pack", help="Build a focused evidence pack from EAs.")
    _add_pack_root(evidence)
    evidence.add_argument("--ea", action="append", default=[], help="Function EA. Can be repeated.")
    evidence.add_argument("--ea-file", default="", help="Text file containing whitespace/comma/semicolon-separated EAs.")
    evidence.add_argument("--topic", required=True, help="Evidence pack topic.")
    evidence.add_argument("--output", default="", help="Optional output JSON path.")
    return parser


def _run_command(args: argparse.Namespace) -> Any:
    if args.command == "status":
        return corpus_status(args.pack_root)
    if args.command == "search":
        return {
            "ok": True,
            "results": search_functions(args.pack_root, query=args.query, tags=args.tag, name_regex=args.name_regex, limit=args.limit),
        }
    if args.command == "get-function":
        return get_function(args.pack_root, args.ea, include_excerpt=not args.no_excerpt, include_artifacts=not args.no_artifacts)
    if args.command == "neighbors":
        return get_neighbors(args.pack_root, args.ea, direction=args.direction, depth=args.depth, limit=args.limit)
    if args.command == "search-import":
        return {"ok": True, "results": search_by_import(args.pack_root, args.query, limit=args.limit)}
    if args.command == "search-string":
        return {"ok": True, "results": search_by_string(args.pack_root, args.query, limit=args.limit)}
    if args.command == "build-evidence-pack":
        return build_evidence_pack(
            args.pack_root,
            _eas_from_args(args.ea, args.ea_file),
            args.topic,
            output_path=args.output or None,
        )
    raise QueryError("Unsupported command: %s" % args.command)


def _add_pack_root(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root containing corpus.sqlite.")


def _pack_paths(pack_root: str | Path) -> dict[str, Path]:
    root = Path(pack_root)
    if not root.exists():
        raise QueryError("Pack root does not exist: %s" % root)
    if not root.is_dir():
        raise QueryError("Pack root is not a directory: %s" % root)
    sqlite_path = root / SQLITE_FILENAME
    manifest_path = root / MANIFEST_FILENAME
    if not sqlite_path.is_file():
        raise QueryError("Pack SQLite database is missing: %s" % sqlite_path)
    if not manifest_path.is_file():
        raise QueryError("Pack manifest is missing: %s" % manifest_path)
    return {
        "pack_root": root.resolve(),
        "sqlite_path": sqlite_path.resolve(),
        "manifest_path": manifest_path.resolve(),
    }


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QueryError("Pack manifest could not be read: %s" % exc) from exc
    if not isinstance(data, dict):
        raise QueryError("Pack manifest is not a JSON object: %s" % path)
    return data


def _search_query_eas(
    connection: sqlite3.Connection,
    query: str,
    limit: int,
    reasons_by_ea: dict[str, set[str]],
) -> list[str]:
    result: list[str] = []
    used_fts = False
    if _has_fts(connection):
        fts_query = _fts_query(query)
        if fts_query:
            try:
                for row in connection.execute(
                    "SELECT ea FROM function_fts WHERE function_fts MATCH ? LIMIT ?",
                    (fts_query, limit),
                ):
                    ea = str(row["ea"])
                    reasons_by_ea.setdefault(ea, set()).add("fts")
                    result.append(ea)
                used_fts = True
            except sqlite3.Error:
                pass
    like = "%%%s%%" % query
    for row in connection.execute(
        """
        SELECT ea
        FROM functions
        WHERE name LIKE ?
        ORDER BY ea
        LIMIT ?
        """,
        (like, limit),
    ):
        ea = str(row["ea"])
        reasons_by_ea.setdefault(ea, set()).add("text")
        result.append(ea)
    if not used_fts:
        for row in connection.execute(
            """
            SELECT ea
            FROM functions
            WHERE cleaned_excerpt LIKE ?
            ORDER BY ea
            LIMIT ?
            """,
            (like, limit),
        ):
            ea = str(row["ea"])
            reasons_by_ea.setdefault(ea, set()).add("text")
            result.append(ea)
    return list(dict.fromkeys(result))


def _search_tag_eas(connection: sqlite3.Connection, tags: list[str]) -> list[str]:
    placeholders = _placeholders(tags)
    return [
        str(row["ea"])
        for row in connection.execute(
            """
            SELECT ea
            FROM function_tags
            WHERE tag IN (%s)
            GROUP BY ea
            HAVING COUNT(DISTINCT tag) = ?
            ORDER BY ea
            """
            % placeholders,
            tuple(tags) + (len(set(tags)),),
        )
    ]


def _search_by_value(
    pack_root: str | Path,
    table: str,
    column: str,
    value_query: str,
    reason_prefix: str,
    limit: int,
) -> list[dict[str, Any]]:
    paths = _pack_paths(pack_root)
    bounded_limit = _bounded_limit(limit, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT)
    like = "%%%s%%" % value_query
    with connect_database(paths["sqlite_path"]) as connection:
        rows = list(
            connection.execute(
                """
                SELECT DISTINCT f.ea, v.%s AS matched_value
                FROM %s v
                JOIN functions f ON f.ea = v.ea
                WHERE v.%s LIKE ?
                ORDER BY f.ea
                LIMIT ?
                """
                % (column, table, column),
                (like, bounded_limit),
            )
        )
        return [
            _function_payload(
                connection,
                str(row["ea"]),
                include_excerpt=False,
                include_artifacts=True,
                check_artifacts=False,
                reasons={("%s:%s" % (reason_prefix, row["matched_value"]))},
            )
            for row in rows
        ]


def _function_payload(
    connection: sqlite3.Connection,
    ea: str,
    *,
    include_excerpt: bool,
    include_artifacts: bool,
    check_artifacts: bool,
    reasons: set[str],
) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM functions WHERE ea = ?", (ea,)).fetchone()
    if row is None:
        raise QueryError("Function EA was not found in pack: %s" % ea)
    payload: dict[str, Any] = {
        "ea": str(row["ea"]),
        "name": str(row["name"]),
        "tags": _tags_for_ea(connection, ea),
        "mode": str(row["mode"] or ""),
        "llm_status": str(row["llm_status"] or ""),
        "warning_count": int(row["warning_count"] or 0),
        "buffer_contract_count": int(row["buffer_contract_count"] or 0),
        "why_selected": sorted(reasons),
        "warnings": [],
    }
    if include_artifacts:
        artifacts = {
            "directory": str(row["directory"] or ""),
            "summary": str(row["summary_path"] or ""),
            "cleaned_pseudocode": str(row["cleaned_path"] or ""),
            "raw_pseudocode": str(row["raw_path"] or ""),
            "raw_vs_cleaned_diff": str(row["diff_path"] or ""),
        }
        payload["artifacts"] = artifacts
        if check_artifacts:
            payload["warnings"].extend(_artifact_warnings(artifacts))
    else:
        payload["summary_path"] = str(row["summary_path"] or "")
        payload["cleaned_path"] = str(row["cleaned_path"] or "")
    if include_excerpt:
        payload["cleaned_excerpt"] = str(row["cleaned_excerpt"] or "")
    return payload


def _neighbor_edges(connection: sqlite3.Connection, ea: str, direction: str) -> list[dict[str, str]]:
    queries: list[tuple[str, tuple[str, ...]]] = []
    if direction in {"both", "callees"}:
        queries.append(("SELECT src_ea, dst_ea, edge_kind FROM call_edges WHERE src_ea = ? ORDER BY dst_ea", (ea,)))
    if direction in {"both", "callers"}:
        queries.append(("SELECT src_ea, dst_ea, edge_kind FROM call_edges WHERE dst_ea = ? ORDER BY src_ea", (ea,)))
    result = []
    for sql, params in queries:
        result.extend(dict(row) for row in connection.execute(sql, params))
    return _dedupe_edges(result)


def _dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    result = []
    for edge in edges:
        key = (edge.get("src_ea", ""), edge.get("dst_ea", ""), edge.get("edge_kind", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(edge)
    return result


def _tags_for_ea(connection: sqlite3.Connection, ea: str) -> list[str]:
    return [
        str(row["tag"])
        for row in connection.execute("SELECT tag FROM function_tags WHERE ea = ? ORDER BY tag", (ea,))
    ]


def _names_for_eas(connection: sqlite3.Connection, eas: set[str]) -> dict[str, str]:
    if not eas:
        return {}
    return {
        str(row["ea"]): str(row["name"])
        for row in connection.execute(
            "SELECT ea, name FROM functions WHERE ea IN (%s)" % _placeholders(eas),
            tuple(eas),
        )
    }


def _all_eas(connection: sqlite3.Connection, limit: int | None = None) -> list[str]:
    sql = "SELECT ea FROM functions ORDER BY ea"
    params: tuple[Any, ...] = ()
    if limit is not None:
        sql += " LIMIT ?"
        params = (limit,)
    return [str(row["ea"]) for row in connection.execute(sql, params)]


def _function_exists(connection: sqlite3.Connection, ea: str) -> bool:
    return connection.execute("SELECT 1 FROM functions WHERE ea = ?", (ea,)).fetchone() is not None


def _score_candidate(name: str, query: str, reasons: set[str]) -> int:
    score = len(reasons)
    if query:
        if name.lower() == query.lower():
            score += 10
        elif query.lower() in name.lower():
            score += 5
    if "fts" in reasons:
        score += 2
    return score


def _has_fts(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'function_fts'"
        ).fetchone()
        is not None
    )


def _table_count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])


def _manifest_int(manifest: dict[str, Any], key: str) -> int:
    try:
        return int(manifest.get(key, -1))
    except (TypeError, ValueError):
        return -1


def _artifact_warnings(artifacts: dict[str, str]) -> list[str]:
    warnings = []
    for key, value in artifacts.items():
        if not value:
            continue
        if key == "directory":
            exists = Path(value).is_dir()
        else:
            exists = Path(value).is_file()
        if not exists:
            warnings.append("Missing artifact %s: %s" % (key, value))
    return warnings


def _bounded_limit(value: int, default: int, maximum: int) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError):
        limit = default
    if limit <= 0:
        return default
    return min(limit, maximum)


def _fts_query(query: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_]+", query)
    safe = []
    for token in tokens:
        item = token.replace('"', "")
        if item:
            safe.append('"%s"' % item)
    return " OR ".join(safe)


def _placeholders(values: Any) -> str:
    count = len(values)
    if count <= 0:
        raise QueryError("At least one value is required")
    return ",".join("?" for _ in range(count))


def _eas_from_args(values: list[str], ea_file: str) -> list[str]:
    result = []
    result.extend(values or [])
    if ea_file:
        text = Path(ea_file).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.split("#", 1)[0]
            result.extend(token for token in re.split(r"[\s,;]+", line.strip()) if token)
    if not result:
        raise QueryError("At least one --ea or --ea-file entry is required")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
