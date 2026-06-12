from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import QueryError
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
            if name == "build_evidence_pack":
                pack = build_evidence_pack(
                    self.pack_root,
                    _required_string_list(args, "eas"),
                    str(_required(args, "topic")),
                    output_path=None,
                )
                return self._ok({"evidence_pack": pack}, warnings=_coerce_warnings(pack) + _coerce_gaps(pack))
            return self._error("Unknown tool: %s" % name, error_type="UnknownTool")
        except (OSError, QueryError, ValueError, KeyError) as exc:
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
    ) -> dict[str, Any]:
        result = {
            "ok": True,
            "pack_root": str(self.pack_root.resolve()) if self.pack_root.exists() else str(self.pack_root),
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
]


if __name__ == "__main__":
    raise SystemExit(main())
