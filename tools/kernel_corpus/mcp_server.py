from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.atlas import (
    DEFAULT_LIMIT as DEFAULT_ATLAS_LIMIT,
    DEFAULT_PAGE_CHARS,
    MAX_LIMIT as MAX_ATLAS_LIMIT,
    MAX_PAGE_CHARS,
    generate_atlas,
    get_atlas_page,
    list_atlas_pages,
)
from tools.kernel_corpus.answer_planner import (
    DEFAULT_MAX_TOPICS as DEFAULT_ANSWER_PLAN_MAX_TOPICS,
    MAX_TOPICS as MAX_ANSWER_PLAN_TOPICS,
    build_answer_plan,
)
from tools.kernel_corpus.canonical_store import (
    DEFAULT_MAX_TOPICS as DEFAULT_CANONICAL_MAX_TOPICS,
    DEFAULT_TEXT_CHARS as DEFAULT_CANONICAL_TEXT_CHARS,
    MAX_TEXT_CHARS as MAX_CANONICAL_TEXT_CHARS,
    MAX_TOPICS as MAX_CANONICAL_TOPICS,
    find_canonical_answers,
    get_canonical_answer,
    get_canonical_quality_report,
    list_canonical_answers,
)
from tools.kernel_corpus.canonical_compare import (
    DEFAULT_MAX_TOPICS as DEFAULT_CANONICAL_DRIFT_MAX_TOPICS,
    DEFAULT_REPORT_CHARS as DEFAULT_CANONICAL_DRIFT_REPORT_CHARS,
    MAX_REPORT_CHARS as MAX_CANONICAL_DRIFT_REPORT_CHARS,
    MAX_TOPICS as MAX_CANONICAL_DRIFT_TOPICS,
    compare_canonical_answers as compare_canonical_answers_drift,
    get_canonical_drift_report,
)
from tools.kernel_corpus.errors import KernelCorpusError, QueryError
from tools.kernel_corpus.lifecycle import (
    DEFAULT_DEPTH as DEFAULT_LIFECYCLE_DEPTH,
    DEFAULT_MAX_SEEDS as DEFAULT_LIFECYCLE_MAX_SEEDS,
    MAX_DEPTH as MAX_LIFECYCLE_DEPTH,
    MAX_MAX_SEEDS as MAX_LIFECYCLE_MAX_SEEDS,
    trace_lifecycle,
)
from tools.kernel_corpus.query import (
    build_evidence_pack,
    corpus_status,
    get_function,
    get_neighbors,
    search_by_import,
    search_by_string,
    search_functions,
)
from tools.kernel_corpus.schema import PACK_SCHEMA_VERSION

DEFAULT_LIMIT = 20
MAX_LIMIT = 200
DEFAULT_NEIGHBOR_DEPTH = 1
MAX_NEIGHBOR_DEPTH = 3


class KernelCorpusMcpServer:
    def __init__(self, pack_root: str | Path) -> None:
        self.pack_root = Path(pack_root)

    def list_tools(self) -> list[dict[str, Any]]:
        return TOOL_DEFINITIONS

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        args = arguments or {}
        try:
            if name == "corpus_status":
                status = corpus_status(self.pack_root)
                return self._ok(
                    {
                        "paths": {
                            "manifest": status.get("manifest_path", ""),
                            "sqlite": status.get("sqlite_path", ""),
                        },
                        "manifest": status.get("manifest", {}),
                        "counts": status.get("counts", {}),
                    },
                    schema_version=str(status.get("schema_version", PACK_SCHEMA_VERSION)),
                    warnings=_coerce_warnings(status),
                )
            if name == "search_functions":
                limit = _bounded_limit(args.get("limit"), DEFAULT_LIMIT, MAX_LIMIT)
                results = search_functions(
                    self.pack_root,
                    query=str(args.get("query", "") or ""),
                    tags=_string_list(args.get("tags", [])),
                    name_regex=str(args.get("name_regex", "") or ""),
                    limit=limit,
                )
                return self._ok({"results": results, "limit": limit})
            if name == "get_function":
                function = get_function(
                    self.pack_root,
                    _required(args, "ea"),
                    include_excerpt=bool(args.get("include_excerpt", True)),
                    include_artifacts=bool(args.get("include_artifacts", True)),
                )
                return self._ok({"function": function}, warnings=_coerce_warnings(function))
            if name == "get_neighbors":
                depth = _bounded_limit(args.get("depth"), DEFAULT_NEIGHBOR_DEPTH, MAX_NEIGHBOR_DEPTH)
                limit = _bounded_limit(args.get("limit"), DEFAULT_LIMIT, MAX_LIMIT)
                neighbors = get_neighbors(
                    self.pack_root,
                    _required(args, "ea"),
                    direction=str(args.get("direction", "both") or "both"),
                    depth=depth,
                    limit=limit,
                )
                return self._ok(
                    {
                        "root_ea": neighbors.get("root_ea", ""),
                        "direction": neighbors.get("direction", "both"),
                        "depth": neighbors.get("depth", depth),
                        "limit": neighbors.get("limit", limit),
                        "nodes": neighbors.get("nodes", []),
                        "edges": neighbors.get("edges", []),
                    },
                    warnings=_coerce_warnings(neighbors),
                )
            if name == "search_by_import":
                limit = _bounded_limit(args.get("limit"), DEFAULT_LIMIT, MAX_LIMIT)
                results = search_by_import(self.pack_root, str(_required(args, "query")), limit=limit)
                return self._ok({"results": results, "limit": limit})
            if name == "search_by_string":
                limit = _bounded_limit(args.get("limit"), DEFAULT_LIMIT, MAX_LIMIT)
                results = search_by_string(self.pack_root, str(_required(args, "query")), limit=limit)
                return self._ok({"results": results, "limit": limit})
            if name == "trace_lifecycle":
                max_seeds = _bounded_limit(
                    args.get("max_seeds"),
                    DEFAULT_LIFECYCLE_MAX_SEEDS,
                    MAX_LIFECYCLE_MAX_SEEDS,
                )
                depth = _bounded_limit(args.get("depth"), DEFAULT_LIFECYCLE_DEPTH, MAX_LIFECYCLE_DEPTH)
                pack = trace_lifecycle(
                    self.pack_root,
                    str(_required(args, "topic")),
                    max_seeds=max_seeds,
                    depth=depth,
                    output_path=None,
                )
                return self._ok(
                    {
                        "evidence_pack": pack,
                        "topic": pack.get("topic", ""),
                        "selected_function_count": pack.get("summary", {}).get("selected_function_count", 0),
                        "edge_count": pack.get("summary", {}).get("edge_count", 0),
                        "max_seeds": max_seeds,
                        "depth": depth,
                    },
                    warnings=_coerce_warnings(pack) + _coerce_gaps(pack) + _coerce_uncertainty_notes(pack),
                )
            if name == "build_evidence_pack":
                pack = build_evidence_pack(
                    self.pack_root,
                    _required_string_list(args, "eas"),
                    str(_required(args, "topic")),
                    output_path=None,
                )
                return self._ok({"evidence_pack": pack}, warnings=_coerce_warnings(pack) + _coerce_gaps(pack))
            if name == "generate_atlas":
                pack_root = _pack_root_arg(args, self.pack_root)
                limit = _bounded_limit(args.get("limit"), DEFAULT_ATLAS_LIMIT, MAX_ATLAS_LIMIT)
                output_dir = _atlas_output_dir_arg(args, pack_root)
                result = generate_atlas(
                    pack_root,
                    output_dir,
                    limit=limit,
                )
                return self._ok(
                    {
                        "output_dir": result.get("output_dir", ""),
                        "generated_at": result.get("generated_at", ""),
                        "page_count": result.get("page_count", 0),
                        "pages": result.get("pages", []),
                        "limit": limit,
                    },
                    pack_root=pack_root,
                )
            if name == "list_atlas_pages":
                pack_root = _pack_root_arg(args, self.pack_root)
                result = list_atlas_pages(pack_root)
                return self._ok(
                    {
                        "atlas_dir": result.get("atlas_dir", ""),
                        "page_count": result.get("page_count", 0),
                        "pages": result.get("pages", []),
                    },
                    pack_root=pack_root,
                    warnings=_coerce_warnings(result),
                )
            if name == "get_atlas_page":
                pack_root = _pack_root_arg(args, self.pack_root)
                max_chars = _bounded_limit(args.get("max_chars"), DEFAULT_PAGE_CHARS, MAX_PAGE_CHARS)
                result = get_atlas_page(
                    pack_root,
                    str(_required(args, "page")),
                    max_chars=max_chars,
                )
                return self._ok(
                    {
                        "page": result.get("metadata", {}),
                        "markdown": result.get("markdown", ""),
                        "max_chars": result.get("max_chars", max_chars),
                        "truncated": bool(result.get("truncated", False)),
                    },
                    pack_root=pack_root,
                )
            if name == "list_canonical_answers":
                pack_root = _pack_root_arg(args, self.pack_root)
                max_topics = _bounded_limit(args.get("max_topics"), DEFAULT_CANONICAL_MAX_TOPICS, MAX_CANONICAL_TOPICS)
                result = list_canonical_answers(
                    pack_root,
                    priority=str(args.get("priority", "") or ""),
                    status=str(args.get("status", "") or ""),
                    mode=str(args.get("mode", "") or ""),
                    max_topics=max_topics,
                )
                return self._ok(
                    {
                        "canonical_root": result.get("canonical_root", ""),
                        "topic_count": result.get("topic_count", 0),
                        "returned_count": result.get("returned_count", 0),
                        "max_topics": result.get("max_topics", max_topics),
                        "topics": result.get("topics", []),
                    },
                    schema_version=str(result.get("schema_version", "")),
                    pack_root=pack_root,
                    warnings=_coerce_warnings(result),
                )
            if name == "get_canonical_answer":
                pack_root = _pack_root_arg(args, self.pack_root)
                max_chars = _bounded_limit(args.get("max_chars"), DEFAULT_CANONICAL_TEXT_CHARS, MAX_CANONICAL_TEXT_CHARS)
                result = get_canonical_answer(
                    pack_root,
                    str(_required(args, "topic_id")),
                    include_answer=bool(args.get("include_answer", True)),
                    include_quality=bool(args.get("include_quality", True)),
                    include_gaps=bool(args.get("include_gaps", True)),
                    max_chars=max_chars,
                )
                return self._ok(
                    {
                        "canonical_root": result.get("canonical_root", ""),
                        "metadata": result.get("metadata", {}),
                        "content": result.get("content", {}),
                        "max_chars": result.get("max_chars", max_chars),
                        "returned_chars": result.get("returned_chars", 0),
                        "truncated": bool(result.get("truncated", False)),
                    },
                    schema_version=str(result.get("schema_version", "")),
                    pack_root=pack_root,
                    warnings=_coerce_warnings(result),
                )
            if name == "get_canonical_quality_report":
                pack_root = _pack_root_arg(args, self.pack_root)
                max_topics = _bounded_limit(args.get("max_topics"), DEFAULT_CANONICAL_MAX_TOPICS, MAX_CANONICAL_TOPICS)
                max_chars = _bounded_limit(args.get("max_chars"), DEFAULT_CANONICAL_TEXT_CHARS, MAX_CANONICAL_TEXT_CHARS)
                result = get_canonical_quality_report(
                    pack_root,
                    priority=str(args.get("priority", "") or ""),
                    status=str(args.get("status", "") or ""),
                    max_topics=max_topics,
                    max_chars=max_chars,
                )
                return self._ok(
                    {
                        "canonical_root": result.get("canonical_root", ""),
                        "report": result.get("report", {}),
                        "topics": result.get("topics", []),
                        "returned_count": result.get("returned_count", 0),
                        "max_topics": result.get("max_topics", max_topics),
                        "markdown": result.get("markdown", ""),
                        "max_chars": result.get("max_chars", max_chars),
                        "truncated": bool(result.get("truncated", False)),
                    },
                    schema_version=str(result.get("schema_version", "")),
                    pack_root=pack_root,
                    warnings=_coerce_warnings(result),
                )
            if name == "find_canonical_answers":
                pack_root = _pack_root_arg(args, self.pack_root)
                max_topics = _bounded_limit(args.get("max_topics"), DEFAULT_CANONICAL_MAX_TOPICS, MAX_CANONICAL_TOPICS)
                result = find_canonical_answers(
                    pack_root,
                    str(_required(args, "query")),
                    priority=str(args.get("priority", "") or ""),
                    status=str(args.get("status", "") or ""),
                    max_topics=max_topics,
                )
                return self._ok(
                    {
                        "canonical_root": result.get("canonical_root", ""),
                        "query": result.get("query", ""),
                        "result_count": result.get("result_count", 0),
                        "returned_count": result.get("returned_count", 0),
                        "max_topics": result.get("max_topics", max_topics),
                        "results": result.get("results", []),
                    },
                    schema_version=str(result.get("schema_version", "")),
                    pack_root=pack_root,
                    warnings=_coerce_warnings(result),
                )
            if name == "plan_kernel_answer":
                pack_root = _pack_root_arg(args, self.pack_root)
                max_topics = _bounded_limit(args.get("max_topics"), DEFAULT_ANSWER_PLAN_MAX_TOPICS, MAX_ANSWER_PLAN_TOPICS)
                result = build_answer_plan(
                    pack_root,
                    str(_required(args, "question")),
                    max_topics=max_topics,
                    allow_degraded=bool(args.get("allow_degraded", False)),
                )
                return self._ok(
                    {
                        "question": result.get("question", ""),
                        "pack_freshness": result.get("pack_freshness", {}),
                        "routing": result.get("routing", {}),
                        "canonical_candidates": result.get("canonical_candidates", []),
                        "excluded_canonical_candidates": result.get("excluded_canonical_candidates", []),
                        "live_retrieval_steps": result.get("live_retrieval_steps", []),
                        "recommended_mcp_calls": result.get("recommended_mcp_calls", []),
                        "citation_contract": result.get("citation_contract", {}),
                        "final_answer_outline": result.get("final_answer_outline", []),
                        "stop_conditions": result.get("stop_conditions", []),
                    },
                    schema_version=str(result.get("schema", "")),
                    pack_root=pack_root,
                    warnings=_coerce_warnings(result),
                )
            if name == "compare_canonical_answers":
                pack_root_a = Path(str(_required(args, "pack_root_a")))
                pack_root_b = Path(str(_required(args, "pack_root_b")))
                max_topics = _bounded_limit(args.get("max_topics"), DEFAULT_CANONICAL_DRIFT_MAX_TOPICS, MAX_CANONICAL_DRIFT_TOPICS)
                result = compare_canonical_answers_drift(
                    pack_root_a,
                    pack_root_b,
                    topic_id=str(args.get("topic_id", "") or ""),
                    priority=str(args.get("priority", "") or ""),
                    max_topics=max_topics,
                )
                return self._ok(
                    {
                        "pack_a": result.get("pack_a", {}),
                        "pack_b": result.get("pack_b", {}),
                        "source_identity": result.get("source_identity", {}),
                        "catalog_summary": result.get("catalog_summary", {}),
                        "topic_count": result.get("topic_count", 0),
                        "returned_count": result.get("returned_count", 0),
                        "topics_truncated": bool(result.get("topics_truncated", False)),
                        "topics": result.get("topics", []),
                    },
                    schema_version=str(result.get("schema", "")),
                    pack_root=pack_root_a,
                    warnings=_coerce_warnings(result),
                )
            if name == "get_canonical_drift_report":
                pack_root_a = Path(str(_required(args, "pack_root_a")))
                pack_root_b = Path(str(_required(args, "pack_root_b")))
                max_chars = _bounded_limit(
                    args.get("max_chars"),
                    DEFAULT_CANONICAL_DRIFT_REPORT_CHARS,
                    MAX_CANONICAL_DRIFT_REPORT_CHARS,
                )
                result = get_canonical_drift_report(
                    pack_root_a,
                    pack_root_b,
                    topic_id=str(args.get("topic_id", "") or ""),
                    max_chars=max_chars,
                )
                return self._ok(
                    {
                        "pack_root_a": result.get("pack_root_a", ""),
                        "pack_root_b": result.get("pack_root_b", ""),
                        "topic_id": result.get("topic_id", ""),
                        "markdown": result.get("markdown", ""),
                        "max_chars": result.get("max_chars", max_chars),
                        "truncated": bool(result.get("truncated", False)),
                    },
                    schema_version=str(result.get("schema", "")),
                    pack_root=pack_root_a,
                    warnings=_coerce_warnings(result),
                )
            return self._error("Unknown tool: %s" % name, error_type="UnknownTool")
        except (OSError, KernelCorpusError, ValueError, KeyError) as exc:
            return self._error(str(exc), error_type=exc.__class__.__name__)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = str(request.get("method", ""))
        if request_id is None and method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                return _jsonrpc_result(
                    request_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": "pseudoforge-kernel-corpus",
                            "version": "0.1.0",
                        },
                        "capabilities": {
                            "tools": {},
                        },
                    },
                )
            if method == "tools/list":
                return _jsonrpc_result(request_id, {"tools": self.list_tools()})
            if method == "tools/call":
                params = request.get("params", {})
                if not isinstance(params, dict):
                    raise QueryError("tools/call params must be an object")
                tool_name = str(params.get("name", ""))
                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise QueryError("tools/call arguments must be an object")
                payload = self.call_tool(tool_name, arguments)
                return _jsonrpc_result(
                    request_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(payload, ensure_ascii=True, sort_keys=True),
                            }
                        ],
                        "isError": not bool(payload.get("ok")),
                    },
                )
            if method == "ping":
                return _jsonrpc_result(request_id, {})
            return _jsonrpc_error(request_id, -32601, "Method not found: %s" % method)
        except (OSError, QueryError, ValueError, KeyError) as exc:
            return _jsonrpc_error(request_id, -32603, str(exc))

    def serve(self, input_stream: TextIO = sys.stdin, output_stream: TextIO = sys.stdout) -> None:
        for line in input_stream:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                response = _jsonrpc_error(None, -32700, "Parse error: %s" % exc)
            else:
                if not isinstance(request, dict):
                    response = _jsonrpc_error(None, -32600, "Invalid request")
                else:
                    response = self.handle_request(request)
            if response is not None:
                output_stream.write(json.dumps(response, ensure_ascii=True, sort_keys=True) + "\n")
                output_stream.flush()

    def _ok(
        self,
        payload: dict[str, Any],
        *,
        schema_version: str = PACK_SCHEMA_VERSION,
        warnings: list[str] | None = None,
        pack_root: str | Path | None = None,
    ) -> dict[str, Any]:
        result_pack_root = Path(pack_root) if pack_root is not None else self.pack_root
        result = {
            "ok": True,
            "pack_root": str(result_pack_root.resolve()) if result_pack_root.exists() else str(result_pack_root),
            "schema_version": schema_version or PACK_SCHEMA_VERSION,
            "warnings": warnings or [],
        }
        result.update(payload)
        return result

    def _error(self, message: str, *, error_type: str) -> dict[str, Any]:
        return {
            "ok": False,
            "pack_root": str(self.pack_root.resolve()) if self.pack_root.exists() else str(self.pack_root),
            "schema_version": PACK_SCHEMA_VERSION,
            "results": [],
            "warnings": [],
            "error": {
                "type": error_type,
                "message": message,
            },
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the read-only Kernel Corpus MCP stdio server.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root containing manifest.json and corpus.sqlite.")
    args = parser.parse_args(argv)
    KernelCorpusMcpServer(args.pack_root).serve()
    return 0


def _required(args: dict[str, Any], name: str) -> Any:
    value = args.get(name)
    if value in (None, ""):
        raise QueryError("Missing required argument: %s" % name)
    return value


def _bounded_limit(value: Any, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    raise QueryError("Expected a string list")


def _required_string_list(args: dict[str, Any], name: str) -> list[str]:
    values = _string_list(_required(args, name))
    if not values:
        raise QueryError("Missing required argument: %s" % name)
    return values


def _pack_root_arg(args: dict[str, Any], default: str | Path) -> Path:
    value = args.get("pack_root")
    if value in (None, ""):
        return Path(default)
    return Path(str(value))


def _atlas_output_dir_arg(args: dict[str, Any], pack_root: Path) -> Path:
    value = _required(args, "output_dir")
    output_dir = Path(str(value))
    resolved_pack_root = pack_root.resolve()
    if not output_dir.is_absolute():
        output_dir = resolved_pack_root / output_dir
    resolved_output_dir = output_dir.resolve()
    try:
        resolved_output_dir.relative_to(resolved_pack_root)
    except ValueError as exc:
        raise QueryError("Atlas output_dir must stay under pack_root: %s" % output_dir) from exc
    return output_dir


def _coerce_warnings(payload: dict[str, Any]) -> list[str]:
    values = payload.get("warnings", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return [str(item) for item in values]


def _coerce_gaps(payload: dict[str, Any]) -> list[str]:
    values = payload.get("gaps", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return ["gap:%s" % item for item in values]


def _coerce_uncertainty_notes(payload: dict[str, Any]) -> list[str]:
    values = payload.get("uncertainty_notes", []) if isinstance(payload, dict) else []
    if not isinstance(values, list):
        return []
    return ["uncertainty:%s" % item for item in values]


def _jsonrpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "corpus_status",
        "description": "Return manifest and table counts for the configured Kernel Corpus pack.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "search_functions",
        "description": "Search functions by text query, tags, and optional name regex.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "default": ""},
                "tags": {"type": "array", "items": {"type": "string"}, "default": []},
                "name_regex": {"type": "string", "default": ""},
                "limit": {"type": "integer", "default": DEFAULT_LIMIT, "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_function",
        "description": "Fetch one function by EA, including artifact paths and an excerpt by default.",
        "inputSchema": {
            "type": "object",
            "required": ["ea"],
            "properties": {
                "ea": {"type": "string"},
                "include_excerpt": {"type": "boolean", "default": True},
                "include_artifacts": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_neighbors",
        "description": "Traverse caller and callee edges around a function.",
        "inputSchema": {
            "type": "object",
            "required": ["ea"],
            "properties": {
                "ea": {"type": "string"},
                "direction": {"type": "string", "enum": ["both", "callers", "callees"], "default": "both"},
                "depth": {"type": "integer", "default": DEFAULT_NEIGHBOR_DEPTH, "minimum": 0, "maximum": MAX_NEIGHBOR_DEPTH},
                "limit": {"type": "integer", "default": DEFAULT_LIMIT, "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "search_by_import",
        "description": "Search functions that reference an import name substring.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": DEFAULT_LIMIT, "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "search_by_string",
        "description": "Search functions that reference a string substring.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": DEFAULT_LIMIT, "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "trace_lifecycle",
        "description": "Build an in-memory lifecycle evidence pack for a topic such as process_object.",
        "inputSchema": {
            "type": "object",
            "required": ["topic"],
            "properties": {
                "topic": {"type": "string"},
                "max_seeds": {
                    "type": "integer",
                    "default": DEFAULT_LIFECYCLE_MAX_SEEDS,
                    "minimum": 1,
                    "maximum": MAX_LIFECYCLE_MAX_SEEDS,
                },
                "depth": {
                    "type": "integer",
                    "default": DEFAULT_LIFECYCLE_DEPTH,
                    "minimum": 1,
                    "maximum": MAX_LIFECYCLE_DEPTH,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "build_evidence_pack",
        "description": "Build an in-memory evidence pack for selected EAs without writing files.",
        "inputSchema": {
            "type": "object",
            "required": ["eas", "topic"],
            "properties": {
                "eas": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "topic": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "generate_atlas",
        "description": "Generate bounded deterministic subsystem atlas pages for a Kernel Corpus pack.",
        "inputSchema": {
            "type": "object",
            "required": ["output_dir"],
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "output_dir": {"type": "string"},
                "limit": {"type": "integer", "default": DEFAULT_ATLAS_LIMIT, "minimum": 1, "maximum": MAX_ATLAS_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_atlas_pages",
        "description": "List generated atlas Markdown pages under the pack's reports/atlas directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pack_root": {"type": "string", "default": ""},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_atlas_page",
        "description": "Return metadata and bounded Markdown text for one generated atlas page.",
        "inputSchema": {
            "type": "object",
            "required": ["page"],
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "page": {"type": "string"},
                "max_chars": {
                    "type": "integer",
                    "default": DEFAULT_PAGE_CHARS,
                    "minimum": 1,
                    "maximum": MAX_PAGE_CHARS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "list_canonical_answers",
        "description": "List generated canonical answer topics and quality metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "priority": {"type": "string", "enum": ["", "P0", "P1", "P2"], "default": ""},
                "status": {"type": "string", "enum": ["", "pass", "degraded", "fail", "missing"], "default": ""},
                "mode": {"type": "string", "enum": ["", "focused", "lifecycle"], "default": ""},
                "max_topics": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_MAX_TOPICS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_TOPICS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_canonical_answer",
        "description": "Return metadata and bounded text for one generated canonical answer.",
        "inputSchema": {
            "type": "object",
            "required": ["topic_id"],
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "topic_id": {"type": "string"},
                "include_answer": {"type": "boolean", "default": True},
                "include_quality": {"type": "boolean", "default": True},
                "include_gaps": {"type": "boolean", "default": True},
                "max_chars": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_TEXT_CHARS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_TEXT_CHARS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_canonical_quality_report",
        "description": "Return canonical quality-report metadata and bounded report Markdown.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "priority": {"type": "string", "enum": ["", "P0", "P1", "P2"], "default": ""},
                "status": {"type": "string", "enum": ["", "pass", "degraded", "fail", "missing"], "default": ""},
                "max_topics": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_MAX_TOPICS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_TOPICS,
                },
                "max_chars": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_TEXT_CHARS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_TEXT_CHARS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "find_canonical_answers",
        "description": "Find canonical answers by topic metadata, quality status, source map, and selected function names.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "query": {"type": "string"},
                "priority": {"type": "string", "enum": ["", "P0", "P1", "P2"], "default": ""},
                "status": {"type": "string", "enum": ["", "pass", "degraded", "fail", "missing"], "default": ""},
                "max_topics": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_MAX_TOPICS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_TOPICS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "plan_kernel_answer",
        "description": "Plan canonical and live Kernel Corpus retrieval steps for a natural-language question without drafting the answer.",
        "inputSchema": {
            "type": "object",
            "required": ["question"],
            "properties": {
                "pack_root": {"type": "string", "default": ""},
                "question": {"type": "string"},
                "max_topics": {
                    "type": "integer",
                    "default": DEFAULT_ANSWER_PLAN_MAX_TOPICS,
                    "minimum": 1,
                    "maximum": MAX_ANSWER_PLAN_TOPICS,
                },
                "allow_degraded": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "compare_canonical_answers",
        "description": "Compare canonical answer catalog and selected evidence drift between two Kernel Corpus pack roots.",
        "inputSchema": {
            "type": "object",
            "required": ["pack_root_a", "pack_root_b"],
            "properties": {
                "pack_root_a": {"type": "string"},
                "pack_root_b": {"type": "string"},
                "topic_id": {"type": "string", "default": ""},
                "priority": {"type": "string", "enum": ["", "P0", "P1", "P2"], "default": ""},
                "max_topics": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_DRIFT_MAX_TOPICS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_DRIFT_TOPICS,
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_canonical_drift_report",
        "description": "Return a bounded Markdown drift report for canonical answers across two Kernel Corpus pack roots.",
        "inputSchema": {
            "type": "object",
            "required": ["pack_root_a", "pack_root_b"],
            "properties": {
                "pack_root_a": {"type": "string"},
                "pack_root_b": {"type": "string"},
                "topic_id": {"type": "string", "default": ""},
                "max_chars": {
                    "type": "integer",
                    "default": DEFAULT_CANONICAL_DRIFT_REPORT_CHARS,
                    "minimum": 1,
                    "maximum": MAX_CANONICAL_DRIFT_REPORT_CHARS,
                },
            },
            "additionalProperties": False,
        },
    },
]


if __name__ == "__main__":
    raise SystemExit(main())
