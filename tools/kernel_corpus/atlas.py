from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.kernel_corpus.errors import KernelCorpusError, QueryError
from tools.kernel_corpus.query import (
    corpus_status,
    find_functions_by_name,
    get_neighbors,
    search_by_import,
    search_by_string,
    search_functions,
)

DEFAULT_LIMIT = 24
MAX_LIMIT = 80
HUB_ROOT_LIMIT = 8
DEFAULT_PAGE_CHARS = 12000
MAX_PAGE_CHARS = 50000
ATLAS_DIR_PARTS = ("reports", "atlas")
SearchCache = dict[tuple[Any, ...], Any]


@dataclass(frozen=True)
class SubsystemSpec:
    filename: str
    title: str
    description: str
    query_terms: tuple[str, ...]
    priority_names: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    name_regex: str = ""
    import_terms: tuple[str, ...] = ()
    string_terms: tuple[str, ...] = ()
    lifecycle_topics: tuple[str, ...] = ()


SUBSYSTEMS: tuple[SubsystemSpec, ...] = (
    SubsystemSpec(
        filename="process.md",
        title="Process",
        description="Process object creation, lookup, notification, exit, rundown, and delete paths.",
        query_terms=("process", "create process", "exit process", "delete process"),
        priority_names=(
            "NtCreateUserProcess",
            "NtCreateProcess",
            "NtCreateProcessEx",
            "ZwCreateUserProcess",
            "PspAllocateProcess",
            "PspInsertProcess",
            "PsLookupProcessByProcessId",
            "PsSetCreateProcessNotifyRoutine",
            "PspCallProcessNotifyRoutines",
            "PspExitProcess",
            "NtTerminateProcess",
            "PspRundownSingleProcess",
            "PspProcessDelete",
        ),
        tags=("process_thread",),
        name_regex=r"^(Nt|Zw|Ps|Psp).*(Process|Silo)",
        import_terms=("PsSetCreateProcessNotifyRoutine", "PsLookupProcessByProcessId"),
        string_terms=("Process",),
        lifecycle_topics=("process_object",),
    ),
    SubsystemSpec(
        filename="thread.md",
        title="Thread",
        description="Thread object creation, notification, termination, lookup, and delete paths.",
        query_terms=("thread", "create thread", "exit thread", "delete thread"),
        priority_names=(
            "NtCreateThread",
            "NtCreateThreadEx",
            "ZwCreateThreadEx",
            "PspCreateThread",
            "PspInsertThread",
            "PsLookupThreadByThreadId",
            "PsSetCreateThreadNotifyRoutine",
            "PspExitThread",
            "NtTerminateThread",
            "PspThreadDelete",
        ),
        tags=("process_thread",),
        name_regex=r"^(Nt|Zw|Ps|Psp).*(Thread|Teb|Apc)",
        import_terms=("PsSetCreateThreadNotifyRoutine", "PsLookupThreadByThreadId"),
        string_terms=("Thread",),
        lifecycle_topics=("thread_object",),
    ),
    SubsystemSpec(
        filename="object-manager.md",
        title="Object Manager",
        description="Object insertion, reference, dereference, handles, callbacks, and object namespaces.",
        query_terms=("object", "handle", "reference object", "dereference object", "insert object"),
        priority_names=(
            "ObInsertObject",
            "ObInsertObjectEx",
            "ObReferenceObjectByHandle",
            "ObReferenceObjectByPointer",
            "ObfReferenceObject",
            "ObDereferenceObject",
            "ObfDereferenceObject",
            "NtDuplicateObject",
            "NtMakeTemporaryObject",
        ),
        tags=("object_manager", "object_callback"),
        name_regex=r"^(Ob|Obp|Nt|Zw).*(Object|Handle|Directory|SymbolicLink)",
        import_terms=("ObInsertObject", "ObReferenceObject", "ObDereferenceObject"),
        string_terms=("Object", "Handle"),
    ),
    SubsystemSpec(
        filename="memory.md",
        title="Memory",
        description="Pool allocation, sections, virtual memory, mappings, MDLs, and memory-manager helpers.",
        query_terms=("memory", "pool", "allocate", "section", "map view", "virtual memory"),
        priority_names=(
            "NtAllocateVirtualMemory",
            "ZwAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "NtMapViewOfSection",
            "MmMapViewInSystemSpace",
            "MmMapLockedPagesSpecifyCache",
            "ExAllocatePool2",
            "ExFreePool",
            "MmProbeAndLockPages",
        ),
        tags=("memory",),
        name_regex=r"^(Mm|Mi|Ex|Nt|Zw).*(Memory|Pool|Section|Map|View|Virtual|Mdl)",
        import_terms=("ExAllocatePool", "ExFreePool", "MmMap", "MmProbe", "MmCopy"),
        string_terms=("Memory", "Section"),
    ),
    SubsystemSpec(
        filename="io-manager.md",
        title="I/O Manager",
        description="Driver dispatch, device objects, IRP flow, IOCTL handling, and file operations.",
        query_terms=("io", "irp", "ioctl", "device control", "dispatch", "file object"),
        priority_names=(
            "IoCreateDevice",
            "IoDeleteDevice",
            "IoCreateDriver",
            "IoCallDriver",
            "IofCallDriver",
            "IoCompleteRequest",
            "IofCompleteRequest",
            "NtDeviceIoControlFile",
            "NtCreateFile",
            "NtReadFile",
            "NtWriteFile",
        ),
        tags=("io_manager", "dispatch", "ioctl"),
        name_regex=r"^(Io|Iop|Nt|Zw).*(Device|Driver|File|Irp|Io|Volume)",
        import_terms=("IoCreateDevice", "IoCallDriver", "IoCompleteRequest", "IoControl"),
        string_terms=("IRP_MJ_DEVICE_CONTROL", "DeviceIoControl", "IOCTL"),
    ),
    SubsystemSpec(
        filename="registry.md",
        title="Registry",
        description="Configuration manager and registry key/value query, set, notification, and hive paths.",
        query_terms=("registry", "key", "value key", "hive", "configuration manager"),
        priority_names=(
            "NtCreateKey",
            "NtOpenKey",
            "NtQueryKey",
            "NtQueryValueKey",
            "NtSetValueKey",
            "NtDeleteKey",
            "CmRegisterCallback",
            "CmRegisterCallbackEx",
        ),
        tags=("registry", "configuration_manager"),
        name_regex=r"^(Cm|Cmp|Nt|Zw).*(Key|Value|Hive|Registry)",
        import_terms=("ZwQueryValueKey", "ZwSetValueKey", "CmRegisterCallback"),
        string_terms=("Registry", "Hive"),
    ),
    SubsystemSpec(
        filename="security.md",
        title="Security",
        description="Tokens, privileges, access checks, auditing, security descriptors, and subject context.",
        query_terms=("security", "token", "privilege", "access check", "audit", "subject context"),
        priority_names=(
            "SeAccessCheck",
            "SeCaptureSubjectContext",
            "SePrivilegeCheck",
            "SeTokenIsAdmin",
            "PsReferencePrimaryToken",
            "PsDereferencePrimaryToken",
            "NtOpenProcessToken",
            "NtAdjustPrivilegesToken",
        ),
        tags=("security", "token"),
        name_regex=r"^(Se|Sep|Nt|Zw|Ps).*(Token|Security|Privilege|Access|Audit|Subject)",
        import_terms=("SeAccessCheck", "SeCaptureSubjectContext", "PsReferencePrimaryToken"),
        string_terms=("Security", "Token", "Privilege"),
    ),
    SubsystemSpec(
        filename="etw-wmi.md",
        title="ETW/WMI",
        description="Event tracing, WMI providers, logger state, and instrumentation callbacks.",
        query_terms=("etw", "wmi", "trace", "event", "logger"),
        priority_names=(
            "EtwRegister",
            "EtwUnregister",
            "EtwWrite",
            "EtwpTraceKernelEvent",
            "WmiTraceMessage",
            "WmipRegisterProvider",
            "NtTraceEvent",
        ),
        tags=("etw", "wmi", "telemetry"),
        name_regex=r"^(Etw|Etwp|Wmi|Wmip|Nt|Zw).*(Trace|Event|Logger|Wmi)",
        import_terms=("Etw", "Wmi"),
        string_terms=("ETW", "WMI", "Trace"),
    ),
    SubsystemSpec(
        filename="driver-load-unload.md",
        title="Driver Load/Unload",
        description="Driver image load, driver object initialization, unload, and load-image notifications.",
        query_terms=("driver", "load image", "unload", "driver object", "DriverEntry"),
        priority_names=(
            "IopLoadDriver",
            "IopUnloadDriver",
            "IoCreateDriver",
            "IoDeleteDriver",
            "PsSetLoadImageNotifyRoutine",
            "PsRemoveLoadImageNotifyRoutine",
            "MmLoadSystemImage",
            "MmUnloadSystemImage",
        ),
        tags=("driver", "image_load", "callback"),
        name_regex=r"^(Iop|Io|Mm|Ps|Psp|Nt|Zw).*(Driver|Load|Unload|Image)",
        import_terms=("PsSetLoadImageNotifyRoutine", "IoCreateDriver", "IoDeleteDriver"),
        string_terms=("DriverEntry", "Unload", "LoadImage"),
    ),
)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = generate_atlas(
            args.pack_root,
            args.output_dir,
            limit=args.limit,
        )
    except KernelCorpusError as exc:
        print("Kernel subsystem atlas failed: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True))
    return 0


def generate_atlas(
    pack_root: str | Path,
    output_dir: str | Path,
    *,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    bounded_limit = _bounded_int(limit, DEFAULT_LIMIT, MAX_LIMIT)
    status = corpus_status(pack_root)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    pages = []
    search_cache: SearchCache = {}
    for spec in SUBSYSTEMS:
        page = build_subsystem_page(
            pack_root,
            spec,
            status=status,
            generated_at=generated_at,
            limit=bounded_limit,
            search_cache=search_cache,
        )
        path = out_dir / spec.filename
        path.write_text(page["markdown"], encoding="utf-8")
        pages.append(
            {
                "title": spec.title,
                "filename": spec.filename,
                "path": str(path.resolve()),
                "function_count": page["function_count"],
                "hub_count": page["hub_count"],
                "gap_count": page["gap_count"],
            }
        )
    return {
        "ok": True,
        "pack_root": str(status.get("pack_root", Path(pack_root).resolve())),
        "output_dir": str(out_dir.resolve()),
        "generated_at": generated_at,
        "page_count": len(pages),
        "pages": pages,
    }


def default_atlas_dir(pack_root: str | Path) -> Path:
    path = Path(pack_root)
    for part in ATLAS_DIR_PARTS:
        path = path / part
    return path


def list_atlas_pages(pack_root: str | Path) -> dict[str, Any]:
    status = corpus_status(pack_root)
    atlas_dir = default_atlas_dir(status.get("pack_root", pack_root))
    warnings = []
    pages = []
    if not atlas_dir.is_dir():
        warnings.append("Atlas directory does not exist: %s" % atlas_dir)
    else:
        for path in sorted(atlas_dir.glob("*.md"), key=lambda item: item.name.lower()):
            pages.append(_atlas_page_metadata(path))
    return {
        "ok": True,
        "pack_root": str(status.get("pack_root", Path(pack_root).resolve())),
        "atlas_dir": str(atlas_dir.resolve()),
        "page_count": len(pages),
        "pages": pages,
        "warnings": warnings,
    }


def get_atlas_page(
    pack_root: str | Path,
    page: str,
    *,
    max_chars: int = DEFAULT_PAGE_CHARS,
) -> dict[str, Any]:
    status = corpus_status(pack_root)
    atlas_dir = default_atlas_dir(status.get("pack_root", pack_root))
    filename = _safe_page_filename(page)
    path = atlas_dir / filename
    if not path.is_file():
        raise QueryError("Atlas page was not found: %s" % path)
    bounded_max_chars = _bounded_int(max_chars, DEFAULT_PAGE_CHARS, MAX_PAGE_CHARS)
    markdown = path.read_text(encoding="utf-8")
    truncated = len(markdown) > bounded_max_chars
    return {
        "ok": True,
        "pack_root": str(status.get("pack_root", Path(pack_root).resolve())),
        "metadata": _atlas_page_metadata(path),
        "markdown": markdown[:bounded_max_chars],
        "max_chars": bounded_max_chars,
        "truncated": truncated,
    }


def build_subsystem_page(
    pack_root: str | Path,
    spec: SubsystemSpec,
    *,
    status: dict[str, Any],
    generated_at: str,
    limit: int,
    search_cache: SearchCache | None = None,
) -> dict[str, Any]:
    cache = search_cache if search_cache is not None else {}
    candidates = _collect_candidates(pack_root, spec, limit=limit, search_cache=cache)
    selected = sorted(candidates.values(), key=_candidate_sort_key)[:limit]
    hubs = _collect_hubs(pack_root, selected, spec, search_cache=cache)
    lifecycle_packs = _find_lifecycle_packs(status, spec.lifecycle_topics)
    gaps = _gaps_for_page(status, spec, selected, hubs, lifecycle_packs)
    markdown = _render_page(
        spec,
        status=status,
        generated_at=generated_at,
        functions=selected,
        hubs=hubs,
        lifecycle_packs=lifecycle_packs,
        gaps=gaps,
    )
    return {
        "markdown": markdown,
        "function_count": len(selected),
        "hub_count": len(hubs),
        "gap_count": len(gaps),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate deterministic Kernel Corpus subsystem atlas Markdown pages.")
    parser.add_argument("--pack-root", required=True, help="Kernel Corpus pack root.")
    parser.add_argument("--output-dir", required=True, help="Atlas output directory.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum high-signal functions per page.")
    return parser


def _collect_candidates(
    pack_root: str | Path,
    spec: SubsystemSpec,
    *,
    limit: int,
    search_cache: SearchCache,
) -> dict[str, dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    query_limit = max(limit, min(MAX_LIMIT, limit * 2))
    for name in spec.priority_names:
        key = ("exact_name", str(pack_root), name, query_limit)
        for function in _cached(search_cache, key, lambda name=name: find_functions_by_name(pack_root, name, limit=query_limit)):
            _merge_candidate(candidates, function, "priority_name:%s" % name, spec)
    for term in spec.query_terms:
        key = ("query", str(pack_root), term, query_limit)
        for function in _cached(search_cache, key, lambda term=term: search_functions(pack_root, query=term, limit=query_limit)):
            _merge_candidate(candidates, function, "query:%s" % term, spec)
    for tag in spec.tags:
        key = ("tag", str(pack_root), tag, query_limit)
        for function in _cached(search_cache, key, lambda tag=tag: search_functions(pack_root, tags=[tag], limit=query_limit)):
            _merge_candidate(candidates, function, "tag:%s" % tag, spec)
    if spec.name_regex:
        key = ("name_regex", str(pack_root), spec.name_regex, query_limit)
        for function in _cached(search_cache, key, lambda: search_functions(pack_root, name_regex=spec.name_regex, limit=query_limit)):
            _merge_candidate(candidates, function, "name_regex:%s" % spec.name_regex, spec)
    for term in spec.import_terms:
        key = ("import", str(pack_root), term, query_limit)
        for function in _cached(search_cache, key, lambda term=term: search_by_import(pack_root, term, limit=query_limit)):
            _merge_candidate(candidates, function, "import:%s" % term, spec)
    for term in spec.string_terms:
        key = ("string", str(pack_root), term, query_limit)
        for function in _cached(search_cache, key, lambda term=term: search_by_string(pack_root, term, limit=query_limit)):
            _merge_candidate(candidates, function, "string:%s" % term, spec)
    return candidates


def _merge_candidate(
    candidates: dict[str, dict[str, Any]],
    function: dict[str, Any],
    reason: str,
    spec: SubsystemSpec,
) -> None:
    ea = str(function.get("ea", ""))
    if not ea:
        return
    existing = candidates.setdefault(
        ea,
        {
            "ea": ea,
            "name": str(function.get("name", "")),
            "tags": [],
            "artifacts": {},
            "why_selected": set(),
            "score": 0.0,
            "warning_count": int(function.get("warning_count", 0) or 0),
        },
    )
    existing["name"] = existing["name"] or str(function.get("name", ""))
    existing["tags"] = sorted(set(existing["tags"]).union(str(tag) for tag in function.get("tags", []) if str(tag)))
    artifacts = function.get("artifacts", {}) if isinstance(function.get("artifacts"), dict) else {}
    existing["artifacts"].update({str(key): str(value) for key, value in artifacts.items() if str(value)})
    existing["why_selected"].add(reason)
    for item in function.get("why_selected", []):
        if str(item):
            existing["why_selected"].add(str(item))
    existing["score"] = _score_candidate(existing, spec)
    existing["warning_count"] = max(existing["warning_count"], int(function.get("warning_count", 0) or 0))


def _score_candidate(candidate: dict[str, Any], spec: SubsystemSpec) -> float:
    name = str(candidate.get("name", "")).lower()
    tags = set(candidate.get("tags", []))
    why = set(candidate.get("why_selected", set()))
    score = 0.05
    priority_names = {item.lower() for item in spec.priority_names}
    if name in priority_names:
        score += 0.45
    elif any(item in name for item in priority_names):
        score += 0.20
    for term in spec.query_terms:
        if _text_term_match(name, term):
            score += 0.16
    if tags.intersection(spec.tags):
        score += 0.16
    if any(item.startswith("name_regex:") for item in why):
        score += 0.14
    if any(item.startswith("priority_name:") for item in why):
        score += 0.18
    if any(item.startswith("import:") for item in why):
        score += 0.10
    if any(item.startswith("string:") for item in why):
        score += 0.08
    if any(item.startswith("query:") for item in why):
        score += 0.08
    if any(item.startswith("tag:") for item in why):
        score += 0.06
    if name.startswith(("nt", "zw", "ps", "psp", "ob", "obp", "mm", "mi", "io", "iop", "cm", "cmp", "se", "sep", "etw", "etwp", "wmi", "wmip")):
        score += 0.10
    warning_count = int(candidate.get("warning_count", 0) or 0)
    if warning_count:
        score -= min(0.05, warning_count * 0.01)
    return max(0.01, min(0.99, score))


def _collect_hubs(
    pack_root: str | Path,
    functions: list[dict[str, Any]],
    spec: SubsystemSpec,
    *,
    search_cache: SearchCache,
) -> list[dict[str, Any]]:
    hubs: dict[str, dict[str, Any]] = {}
    selected_eas = {str(function.get("ea", "")) for function in functions if str(function.get("ea", ""))}
    for root in functions[:HUB_ROOT_LIMIT]:
        try:
            root_ea = str(root["ea"])
            key = ("neighbors", str(pack_root), root_ea, "both", 1, 40)
            neighbors = _cached(
                search_cache,
                key,
                lambda root_ea=root_ea: get_neighbors(pack_root, root_ea, direction="both", depth=1, limit=40),
            )
        except QueryError:
            continue
        for node in neighbors.get("nodes", []):
            if not isinstance(node, dict):
                continue
            ea = str(node.get("ea", ""))
            if not ea:
                continue
            hub = hubs.setdefault(
                ea,
                {
                    "ea": ea,
                    "name": str(node.get("name", "")),
                    "tags": [str(tag) for tag in node.get("tags", []) if str(tag)],
                    "artifacts": node.get("artifacts", {}) if isinstance(node.get("artifacts"), dict) else {},
                    "caller_edges": 0,
                    "callee_edges": 0,
                    "roots": set(),
                    "score": 0,
                },
            )
            hub["roots"].add(str(root.get("name", root.get("ea", ""))))
        for edge in neighbors.get("edges", []):
            if not isinstance(edge, dict):
                continue
            src = str(edge.get("src_ea", ""))
            dst = str(edge.get("dst_ea", ""))
            if src in hubs:
                hubs[src]["callee_edges"] += 1
                hubs[src]["score"] += 1
            if dst in hubs:
                hubs[dst]["caller_edges"] += 1
                hubs[dst]["score"] += 1
    result = sorted(
        hubs.values(),
        key=lambda item: (-int(item["score"]), str(item["name"]), str(item["ea"])),
    )
    for hub in result:
        hub["roots"] = sorted(hub["roots"])
    filtered = [
        hub
        for hub in result
        if not _is_noisy_generic_hub(hub) and _hub_is_relevant(hub, spec, selected_eas)
    ]
    return filtered[:10]


def _cached(cache: SearchCache, key: tuple[Any, ...], callback: Callable[[], Any]) -> Any:
    if key not in cache:
        cache[key] = callback()
    return cache[key]


def _is_noisy_generic_hub(hub: dict[str, Any]) -> bool:
    name = str(hub.get("name", "") or "")
    lowered = name.lower()
    if re.match(r"^mem(set|cpy|move|cmp|chr)(?:_\\d+)?$", lowered):
        return True
    if lowered.startswith(("_security_", "__security_", "__guard_")):
        return True
    if lowered.startswith("feature_") or "__private_isenabled" in lowered:
        return True
    if lowered in {
        "kebugcheck",
        "kebugcheckex",
        "exfreepool",
        "exfreepool2",
        "exfreepoolwithtag",
        "exallocatepool",
        "exallocatepool2",
        "exallocatepoolwithtag",
        "exallocatepoolwithtagpriority",
    }:
        return True
    if re.match(r"^dif[A-Z].*Wrapper$", name, flags=re.IGNORECASE):
        return True
    return False


def _hub_is_relevant(hub: dict[str, Any], spec: SubsystemSpec, selected_eas: set[str]) -> bool:
    ea = str(hub.get("ea", ""))
    name = str(hub.get("name", ""))
    if ea in selected_eas and _hub_name_matches_spec(name, spec):
        return True
    return _hub_name_matches_spec(name, spec)


def _hub_name_matches_spec(name: str, spec: SubsystemSpec) -> bool:
    if any(name.lower() == item.lower() or item.lower() in name.lower() for item in spec.priority_names):
        return True
    if any(_text_term_match(name.lower(), term) for term in spec.query_terms):
        return True
    if any(_text_term_match(name.lower(), term) for term in spec.import_terms + spec.string_terms):
        return True
    if spec.name_regex and re.search(spec.name_regex, name):
        return True
    return False


def _find_lifecycle_packs(status: dict[str, Any], topics: tuple[str, ...]) -> list[dict[str, Any]]:
    pack_root = Path(str(status.get("pack_root", "")))
    result = []
    for topic in topics:
        path = pack_root / "evidence-packs" / ("%s.json" % topic)
        if not path.is_file():
            result.append(
                {
                    "topic": topic,
                    "available": False,
                    "path": str(path.resolve()),
                    "summary": "",
                }
            )
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            result.append(
                {
                    "topic": topic,
                    "available": False,
                    "path": str(path.resolve()),
                    "summary": "could not read: %s" % exc,
                }
            )
            continue
        summary = data.get("summary", {}) if isinstance(data, dict) else {}
        result.append(
            {
                "topic": topic,
                "available": True,
                "path": str(path.resolve()),
                "summary": "selected=%s edges=%s" % (
                    summary.get("selected_function_count", ""),
                    summary.get("edge_count", ""),
                ),
            }
        )
    return result


def _gaps_for_page(
    status: dict[str, Any],
    spec: SubsystemSpec,
    functions: list[dict[str, Any]],
    hubs: list[dict[str, Any]],
    lifecycle_packs: list[dict[str, Any]],
) -> list[str]:
    gaps = []
    if not functions:
        gaps.append("No high-signal functions matched the configured search criteria for this subsystem.")
    if functions and not hubs:
        gaps.append("No caller/callee hubs were found from the selected functions within depth 1.")
    missing_lifecycle = [item["topic"] for item in lifecycle_packs if not item["available"]]
    if missing_lifecycle:
        gaps.append("Missing lifecycle evidence pack(s): %s." % ", ".join(missing_lifecycle))
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    skipped_count = int(manifest.get("skipped_count", 0) or 0)
    if skipped_count:
        gaps.append("Source corpus reports skipped functions: %d." % skipped_count)
    if len(functions) >= DEFAULT_LIMIT:
        gaps.append("Function list may be capped; rerun with a higher --limit for deeper review.")
    if not spec.tags and not spec.import_terms and not spec.string_terms:
        gaps.append("Subsystem definition uses query/name criteria only; consider adding tags or import/string terms.")
    return gaps


def _render_page(
    spec: SubsystemSpec,
    *,
    status: dict[str, Any],
    generated_at: str,
    functions: list[dict[str, Any]],
    hubs: list[dict[str, Any]],
    lifecycle_packs: list[dict[str, Any]],
    gaps: list[str],
) -> str:
    manifest = status.get("manifest", {}) if isinstance(status.get("manifest"), dict) else {}
    lines = [
        "# %s Subsystem Atlas" % spec.title,
        "",
        "Generated: `%s`" % generated_at,
        "",
        "## Corpus Identity",
        "",
        "- Pack root: `%s`" % status.get("pack_root", ""),
        "- Schema: `%s`" % status.get("schema_version", ""),
        "- Target: `%s`" % manifest.get("target_path", ""),
        "- Functions: `%s`" % manifest.get("function_count", ""),
        "- Skipped: `%s`" % manifest.get("skipped_count", ""),
        "- Manifest: `%s`" % status.get("manifest_path", ""),
        "- SQLite: `%s`" % status.get("sqlite_path", ""),
        "",
        "## Search Criteria",
        "",
        "- Description: %s" % spec.description,
        "- Priority names: %s" % _inline_list(spec.priority_names),
        "- Query terms: %s" % _inline_list(spec.query_terms),
        "- Tags: %s" % _inline_list(spec.tags),
        "- Name regex: `%s`" % (spec.name_regex or "<none>"),
        "- Import terms: %s" % _inline_list(spec.import_terms),
        "- String terms: %s" % _inline_list(spec.string_terms),
        "",
        "## High-Signal Functions",
        "",
    ]
    if not functions:
        lines.append("- No matching functions selected.")
    else:
        for function in functions:
            lines.extend(_function_lines(function))
    lines.extend(
        [
            "",
            "## Major Caller/Callee Hubs",
            "",
        ]
    )
    if not hubs:
        lines.append("- No hubs found from selected functions.")
    else:
        for hub in hubs:
            lines.extend(_hub_lines(hub))
    lines.extend(
        [
            "",
            "## Lifecycle Evidence Packs",
            "",
        ]
    )
    if not lifecycle_packs:
        lines.append("- No lifecycle evidence pack configured for this subsystem.")
    else:
        for item in lifecycle_packs:
            if item["available"]:
                lines.append("- `%s`: available at `%s` (%s)" % (item["topic"], item["path"], item["summary"]))
            else:
                suffix = " %s" % item["summary"] if item["summary"] else ""
                lines.append("- `%s`: missing at `%s`.%s" % (item["topic"], item["path"], suffix))
    lines.extend(
        [
            "",
            "## Gaps And Uncertainty",
            "",
        ]
    )
    if not gaps:
        lines.append("- No generation gaps detected; still verify critical claims against function artifacts.")
    else:
        for gap in gaps:
            lines.append("- %s" % gap)
    lines.extend(
        [
            "",
            "## Review Rule",
            "",
            "Treat this page as a retrieval map. Do not claim subsystem behavior is proven unless the cited function artifacts or edges support it.",
            "",
        ]
    )
    return "\n".join(lines)


def _function_lines(function: dict[str, Any]) -> list[str]:
    artifacts = function.get("artifacts", {}) if isinstance(function.get("artifacts"), dict) else {}
    summary = artifacts.get("summary", "")
    cleaned = artifacts.get("cleaned_pseudocode", "")
    tags = ", ".join(function.get("tags", [])) or "<none>"
    why = ", ".join(sorted(function.get("why_selected", set()))) or "<none>"
    return [
        "- `%s` `%s` score=%.2f tags=%s" % (
            function.get("ea", ""),
            function.get("name", ""),
            float(function.get("score", 0.0)),
            tags,
        ),
        "  - Summary: `%s`" % summary,
        "  - Cleaned: `%s`" % cleaned,
        "  - Why selected: %s" % why,
    ]


def _hub_lines(hub: dict[str, Any]) -> list[str]:
    artifacts = hub.get("artifacts", {}) if isinstance(hub.get("artifacts"), dict) else {}
    roots = ", ".join(hub.get("roots", [])) or "<none>"
    return [
        "- `%s` `%s` callers=%d callees=%d roots=%s" % (
            hub.get("ea", ""),
            hub.get("name", ""),
            int(hub.get("caller_edges", 0) or 0),
            int(hub.get("callee_edges", 0) or 0),
            roots,
        ),
        "  - Summary: `%s`" % artifacts.get("summary", ""),
    ]


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[float, str, str]:
    return (-float(candidate.get("score", 0.0)), str(candidate.get("name", "")), str(candidate.get("ea", "")))


def _text_term_match(text: str, term: str) -> bool:
    lowered = term.lower()
    if lowered in text:
        return True
    tokens = [item for item in lowered.replace("_", " ").split() if item]
    return bool(tokens) and all(token in text for token in tokens)


def _inline_list(values: tuple[str, ...]) -> str:
    if not values:
        return "`<none>`"
    return ", ".join("`%s`" % item for item in values)


def _safe_page_filename(page: str) -> str:
    text = str(page or "").strip()
    if not text:
        raise QueryError("Atlas page name is required")
    normalized = text.replace("\\", "/")
    if "/" in normalized or normalized.startswith("."):
        raise QueryError("Atlas page name must be a filename, not a path: %s" % text)
    if not normalized.lower().endswith(".md"):
        normalized = "%s.md" % normalized
    if Path(normalized).name != normalized:
        raise QueryError("Atlas page name must be a filename, not a path: %s" % text)
    return normalized


def _atlas_page_metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "filename": path.name,
        "path": str(path.resolve()),
        "size": int(stat.st_size),
        "last_write_time": datetime.fromtimestamp(stat.st_mtime, timezone.utc).replace(microsecond=0).isoformat(),
        "is_kernel_corpus_atlas_page": _looks_like_atlas_page(path),
    }


def _looks_like_atlas_page(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            sample = handle.read(8192)
    except OSError:
        return False
    return (
        "Subsystem Atlas" in sample
        and "## Corpus Identity" in sample
        and "## Review Rule" in sample
    )


def _bounded_int(value: int, default: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if result <= 0:
        result = default
    return min(result, maximum)


if __name__ == "__main__":
    raise SystemExit(main())
