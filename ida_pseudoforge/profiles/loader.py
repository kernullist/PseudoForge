from __future__ import annotations

import json
from functools import lru_cache
from typing import Any
from pathlib import Path


PROFILE_DIR = Path(__file__).resolve().parent
PROFILE_MANIFEST_NAME = "profiles_manifest.json"
KERNEL_API_PROFILE_NAME = "kernel_api.json"
KERNEL_API_FAMILY_FILES = {
    "functions": "kernel_functions.json",
    "enums": "kernel_enums.json",
    "structures": "kernel_structures.json",
    "aliases": "kernel_aliases.json",
    "macros": "kernel_macros.json",
    "symbols": "kernel_symbol_index.json",
    "indices": "kernel_indices.json",
}
_PROFILE_LOAD_WARNINGS: dict[str, str] = {}
_ACTIVE_PROFILE_NAMES: set[str] = set()


@lru_cache(maxsize=None)
def load_json_profile(name: str) -> Any:
    _ACTIVE_PROFILE_NAMES.add(name)
    path = PROFILE_DIR / name
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        _PROFILE_LOAD_WARNINGS.pop(name, None)
        return payload
    except FileNotFoundError:
        _record_profile_warning(name, "missing profile file: %s" % path)
        return {}
    except json.JSONDecodeError as exc:
        _record_profile_warning(
            name,
            "invalid JSON in %s at line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg),
        )
        return {}
    except OSError as exc:
        _record_profile_warning(name, "profile read failed for %s: %s" % (path, exc))
        return {}


@lru_cache(maxsize=None)
def load_profile(name: str) -> dict[str, str]:
    data = load_json_profile(name)
    if not isinstance(data, dict):
        _record_profile_warning(name, "profile root must be a JSON object, got %s" % type(data).__name__)
        return {}
    return {str(key): str(value) for key, value in data.items()}


@lru_cache(maxsize=None)
def load_kernel_api_family(family: str) -> dict[str, Any]:
    family_name = str(family or "").strip()
    if not family_name:
        return {}

    split_name = KERNEL_API_FAMILY_FILES.get(family_name)
    if split_name and (PROFILE_DIR / split_name).exists():
        return _load_kernel_api_family_file(split_name, family_name)

    data = load_json_profile(KERNEL_API_PROFILE_NAME)
    if not isinstance(data, dict):
        _record_profile_warning(
            KERNEL_API_PROFILE_NAME,
            "kernel API profile root must be a JSON object, got %s" % type(data).__name__,
        )
        return {}
    family_data = data.get(family_name, {})
    if not isinstance(family_data, dict):
        _record_profile_warning(
            KERNEL_API_PROFILE_NAME,
            "kernel API family %s must be a JSON object, got %s" % (family_name, type(family_data).__name__),
        )
        return {}
    return family_data


def profile_load_warnings() -> list[str]:
    return [_PROFILE_LOAD_WARNINGS[name] for name in sorted(_PROFILE_LOAD_WARNINGS)]


def active_profile_manifests() -> list[dict[str, Any]]:
    result = []
    for name in sorted(_ACTIVE_PROFILE_NAMES):
        manifest = profile_manifest(name)
        if manifest:
            result.append(manifest)
    return result


def profile_manifest(name: str) -> dict[str, Any]:
    profiles = _profiles_manifest_entries()
    entry = profiles.get(name)
    if not isinstance(entry, dict):
        return {}
    result = dict(entry)
    result["name"] = name
    return result


def clear_profile_caches() -> None:
    load_json_profile.cache_clear()
    load_profile.cache_clear()
    load_kernel_api_family.cache_clear()
    load_profiles_manifest.cache_clear()
    get_system_information_class_value.cache_clear()
    get_process_information_class_value.cache_clear()
    _PROFILE_LOAD_WARNINGS.clear()
    _ACTIVE_PROFILE_NAMES.clear()


@lru_cache(maxsize=None)
def load_profiles_manifest() -> dict[str, Any]:
    path = PROFILE_DIR / PROFILE_MANIFEST_NAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        _record_profile_warning(
            PROFILE_MANIFEST_NAME,
            "invalid JSON in %s at line %d column %d: %s"
            % (path, exc.lineno, exc.colno, exc.msg),
        )
        return {}
    except OSError as exc:
        _record_profile_warning(
            PROFILE_MANIFEST_NAME,
            "profile manifest read failed for %s: %s" % (path, exc),
        )
        return {}
    if not isinstance(payload, dict):
        _record_profile_warning(
            PROFILE_MANIFEST_NAME,
            "profile manifest root must be a JSON object, got %s" % type(payload).__name__,
        )
        return {}
    return payload


def _profiles_manifest_entries() -> dict[str, Any]:
    manifest = load_profiles_manifest()
    profiles = manifest.get("profiles", {}) if isinstance(manifest, dict) else {}
    return profiles if isinstance(profiles, dict) else {}


def _load_kernel_api_family_file(name: str, family: str) -> dict[str, Any]:
    data = load_json_profile(name)
    if not isinstance(data, dict):
        _record_profile_warning(name, "profile root must be a JSON object, got %s" % type(data).__name__)
        return {}
    if family in data:
        nested = data.get(family)
        if isinstance(nested, dict):
            return nested
        _record_profile_warning(
            name,
            "kernel API family %s must be a JSON object, got %s" % (family, type(nested).__name__),
        )
        return {}
    return data


def _record_profile_warning(name: str, message: str) -> None:
    _PROFILE_LOAD_WARNINGS[name] = "PseudoForge profile load warning: %s: %s" % (name, message)


def get_status_name(literal: str | int) -> str:
    return load_profile("status_codes.json").get(str(literal), "")


def get_system_information_class_name(value: int) -> str:
    return load_profile("system_information_class.json").get(str(value), "")


def get_process_information_class_name(value: int) -> str:
    return load_profile("process_information_class.json").get(str(value), "")


@lru_cache(maxsize=None)
def get_system_information_class_value(name: str) -> int | None:
    target = str(name or "").strip()
    if not target:
        return None
    for value, enum_name in load_profile("system_information_class.json").items():
        if enum_name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None


@lru_cache(maxsize=None)
def get_process_information_class_value(name: str) -> int | None:
    target = str(name or "").strip()
    if not target:
        return None
    for value, enum_name in load_profile("process_information_class.json").items():
        if enum_name == target:
            try:
                return int(value)
            except ValueError:
                return None
    return None
