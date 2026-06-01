from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from ida_pseudoforge.core.kernel_api import (
    decode_pool_tag_literal,
    kernel_structure_metadata,
    kernel_type_alias_metadata,
)
from ida_pseudoforge.core.kernel_semantics import looks_like_driver_entry
from ida_pseudoforge.core.normalize import extract_parameters_from_signature
from ida_pseudoforge.core.plan_schema import CleanPlan, FunctionCapture


@dataclass(frozen=True)
class KernelRewriteRule:
    name: str
    requires_comment_kind: str
    pattern: str
    replacement: str
    flags: int = re.MULTILINE


@dataclass(frozen=True)
class ProfileLayoutField:
    name: str
    type_text: str
    offset: int
    size: int
    align: int


_PROFILE_POINTER_SIZE = 8
_OB_PRE_OPERATION_INFORMATION = "OB_PRE_OPERATION_INFORMATION"
_OB_PRE_CREATE_HANDLE_INFORMATION = "OB_PRE_CREATE_HANDLE_INFORMATION"
_OB_PRE_DUPLICATE_HANDLE_INFORMATION = "OB_PRE_DUPLICATE_HANDLE_INFORMATION"
_POINTER_SIZED_CAST_PATTERN = (
    r"(?:HANDLE|PVOID|ULONG_PTR|UINT_PTR|DWORD_PTR|LONG_PTR|INT_PTR|SIZE_T|SSIZE_T|"
    r"ULONGLONG|LONG64|ULONG64|(?:__int64|_QWORD|void)\s*\*)"
)


INFERRED_PROVIDER_TYPE = "\n".join(
    [
        "// PseudoForge: inferred record layout from LIST_ENTRY and pool allocation usage.",
        "typedef struct _INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD",
        "{",
        "  ULONG ProviderSignature;",
        "  PVOID FirmwareTableHandler;",
        "  PDRIVER_OBJECT DriverObject;",
        "  LIST_ENTRY Link;",
        "} INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD;",
        "",
    ]
)

INFERRED_OB_PROCESS_RULE_RECORD_TYPE = "\n".join(
    [
        "// PseudoForge: inferred OB callback process-rule record from LIST_ENTRY walk and allocation layout.",
        "typedef struct _INFERRED_OB_PROCESS_RULE_RECORD",
        "{",
        "  LIST_ENTRY Link;",
        "  HANDLE ProcessId;",
        "  ULONG HitCount;",
        "  BOOLEAN AutoAdded;",
        "  UCHAR Reserved[3];",
        "  LARGE_INTEGER LastSeenTime;",
        "} INFERRED_OB_PROCESS_RULE_RECORD;",
        "",
    ]
)

INFERRED_OB_CALLBACK_EVENT_RECORD_TYPE = "\n".join(
    [
        "// PseudoForge: inferred OB callback event record from lookaside allocation and fixed field writes.",
        "typedef struct _INFERRED_OB_CALLBACK_EVENT_RECORD",
        "{",
        "  LIST_ENTRY Link;",
        "  ULONG RecordSize;",
        "  ULONG EventCode;",
        "  ULONG CallerProcessId;",
        "  ULONG CallerThreadId;",
        "  ULONG SubjectProcessId;",
        "  NTSTATUS Status;",
        "  ULONGLONG Sequence;",
        "  LONGLONG Timestamp;",
        "} INFERRED_OB_CALLBACK_EVENT_RECORD;",
        "",
    ]
)

INFERRED_DRIVER_DEVICE_EXTENSION_TYPE = "\n".join(
    [
        "// PseudoForge: inferred driver device extension from DriverEntry offset usage.",
        "// Preview-only: this does not imply the original source struct name or sizeof expression.",
        "typedef struct _INFERRED_DRIVER_DEVICE_EXTENSION",
        "{",
        "  ULONG Signature;",
        "  PDEVICE_OBJECT DeviceObject;",
        "  FAST_MUTEX StateLock;",
        "  FAST_MUTEX AccessListLock;",
        "  KSPIN_LOCK EventLock;",
        "  LIST_ENTRY EventList;",
        "  LIST_ENTRY ProcessWhitelist;",
        "  LIST_ENTRY ProcessBlacklist;",
        "  NPAGED_LOOKASIDE_LIST RecordLookaside;",
        "  NPAGED_LOOKASIDE_LIST ProcessRuleLookaside;",
        "  KTIMER Timer;",
        "  KDPC TimerDpc;",
        "  PIO_WORKITEM WorkItem;",
        "  KEVENT WorkItemIdleEvent;",
        "  EX_RUNDOWN_REF Rundown;",
        "  ERESOURCE Resource;",
        "  UNICODE_STRING RegistryPath;",
        "  ULONG MaxRecords;",
        "  UCHAR ReservedTail[0x5C];",
        "} INFERRED_DRIVER_DEVICE_EXTENSION;",
        "",
        "",
    ]
)


KERNEL_REWRITE_RULES = [
    KernelRewriteRule(
        "provider-record-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)_DWORD\s+\*providerRecord(\s*;[^\n]*)$",
        r"\1INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD *providerRecord\2",
    ),
    KernelRewriteRule(
        "provider-link-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)_DWORD\s+\*providerLink(\s*;[^\n]*)$",
        r"\1LIST_ENTRY *providerLink\2",
    ),
    KernelRewriteRule(
        "next-link-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)__int64\s+nextLink(\s*;[^\n]*)$",
        r"\1LIST_ENTRY *nextLink\2",
    ),
    KernelRewriteRule(
        "previous-link-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)_QWORD\s+\*previousLink(\s*;[^\n]*)$",
        r"\1LIST_ENTRY *previousLink\2",
    ),
    KernelRewriteRule(
        "new-provider-record-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)__int64\s+newProviderRecord(\s*;[^\n]*)$",
        r"\1INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD *newProviderRecord\2",
    ),
    KernelRewriteRule(
        "new-provider-link-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)_QWORD\s+\*newProviderLink(\s*;[^\n]*)$",
        r"\1LIST_ENTRY *newProviderLink\2",
    ),
    KernelRewriteRule(
        "tail-link-declaration",
        "inferred_record_layout",
        r"(?m)^(\s*)_QWORD\s+\*tailLink(\s*;[^\n]*)$",
        r"\1LIST_ENTRY *tailLink\2",
    ),
    KernelRewriteRule(
        "list-head-containing-record",
        "inferred_record_layout",
        r"providerRecord\s*=\s*\([^)]*\*\)\(\s*ExpFirmwareTableProviderListHead\s*-\s*24(?:LL)?\s*\)",
        (
            "providerRecord = CONTAINING_RECORD(ExpFirmwareTableProviderListHead, "
            "INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link)"
        ),
    ),
    KernelRewriteRule(
        "next-containing-record",
        "inferred_record_layout",
        r"providerRecord\s*=\s*\([^)]*\*\)\(\s*\*\(_QWORD\s+\*\)providerLink\s*-\s*24(?:LL)?\s*\)",
        (
            "providerRecord = CONTAINING_RECORD(providerLink->Flink, "
            "INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link)"
        ),
    ),
    KernelRewriteRule(
        "record-link-address",
        "inferred_record_layout",
        r"\bproviderLink\s*=\s*providerRecord\s*\+\s*6\s*;",
        "providerLink = &providerRecord->Link;",
    ),
    KernelRewriteRule(
        "list-head-end-test",
        "inferred_record_layout",
        r"&ExpFirmwareTableProviderListHead\s*==\s*\(__int64\s+\*\)\(providerRecord\s*\+\s*6\)",
        "&ExpFirmwareTableProviderListHead == providerLink",
    ),
    KernelRewriteRule(
        "provider-signature-field",
        "inferred_record_layout",
        r"\*providerRecord == pTableHandler->ProviderSignature",
        "providerRecord->ProviderSignature == pTableHandler->ProviderSignature",
    ),
    KernelRewriteRule(
        "provider-driver-object-field",
        "inferred_record_layout",
        r"\(PVOID\)\*\(\(_QWORD \*\)providerRecord \+ 2\)",
        "(PVOID)providerRecord->DriverObject",
    ),
    KernelRewriteRule(
        "provider-driver-object-deref-field",
        "inferred_record_layout",
        r"\*\(\(PVOID \*\)providerRecord \+ 2\)",
        "providerRecord->DriverObject",
    ),
    KernelRewriteRule(
        "provider-blink-field",
        "inferred_record_layout",
        r"\*\(\(_QWORD \*\)providerRecord \+ 4\)",
        "providerRecord->Link.Blink",
    ),
    KernelRewriteRule(
        "new-provider-link-address",
        "inferred_record_layout",
        r"\bnewProviderLink\s*=\s*\(_QWORD\s+\*\)\(newProviderRecord\s*\+\s*24\)\s*;",
        "newProviderLink = &newProviderRecord->Link;",
    ),
    KernelRewriteRule(
        "new-provider-signature-field",
        "inferred_record_layout",
        r"\*\(_DWORD\s+\*\)newProviderRecord",
        "newProviderRecord->ProviderSignature",
    ),
    KernelRewriteRule(
        "new-provider-handler-field",
        "inferred_record_layout",
        r"\*\(_QWORD\s+\*\)\(newProviderRecord\s*\+\s*8\)",
        "newProviderRecord->FirmwareTableHandler",
    ),
    KernelRewriteRule(
        "new-provider-driver-object-field",
        "inferred_record_layout",
        r"\*\(_QWORD\s+\*\)\(newProviderRecord\s*\+\s*16\)",
        "newProviderRecord->DriverObject",
    ),
    KernelRewriteRule(
        "new-provider-flink-field",
        "inferred_record_layout",
        r"\*\(_QWORD\s+\*\)\(newProviderRecord\s*\+\s*24\)",
        "newProviderRecord->Link.Flink",
    ),
    KernelRewriteRule(
        "new-provider-blink-field",
        "inferred_record_layout",
        r"\*\(_QWORD\s+\*\)\(newProviderRecord\s*\+\s*32\)",
        "newProviderRecord->Link.Blink",
    ),
    KernelRewriteRule(
        "new-provider-link-offset",
        "inferred_record_layout",
        r"\bnewProviderRecord\s*\+\s*24\b",
        "&newProviderRecord->Link",
    ),
    KernelRewriteRule(
        "provider-flink-load",
        "inferred_record_layout",
        r"\*\(_QWORD \*\)providerLink",
        "providerLink->Flink",
    ),
    KernelRewriteRule(
        "provider-flink-blink-check",
        "inferred_record_layout",
        r"\*\(_DWORD \*\*\)\(providerLink->Flink \+ 8LL\) == providerLink",
        "providerLink->Flink->Blink == providerLink",
    ),
    KernelRewriteRule(
        "previous-flink-check",
        "inferred_record_layout",
        r"\(_DWORD \*\)\*previousLink == providerLink",
        "previousLink->Flink == providerLink",
    ),
    KernelRewriteRule(
        "previous-flink-store",
        "inferred_record_layout",
        r"\*previousLink = nextLink;",
        "previousLink->Flink = nextLink;",
    ),
    KernelRewriteRule(
        "next-blink-store",
        "inferred_record_layout",
        r"\*\(_QWORD \*\)\(nextLink \+ 8\) = previousLink;",
        "nextLink->Blink = previousLink;",
    ),
    KernelRewriteRule(
        "tail-flink-check",
        "inferred_record_layout",
        r"\*\(__int64 \*\*\)qword_[0-9A-Fa-f]+ != &ExpFirmwareTableProviderListHead",
        "tailLink->Flink != &ExpFirmwareTableProviderListHead",
    ),
    KernelRewriteRule(
        "new-link-flink-store",
        "inferred_record_layout",
        r"\*newProviderLink = &ExpFirmwareTableProviderListHead;",
        "newProviderLink->Flink = &ExpFirmwareTableProviderListHead;",
    ),
    KernelRewriteRule(
        "new-link-blink-store",
        "inferred_record_layout",
        r"newProviderLink\[1\] = tailLink;",
        "newProviderLink->Blink = tailLink;",
    ),
    KernelRewriteRule(
        "tail-flink-store",
        "inferred_record_layout",
        r"\*tailLink = newProviderLink;",
        "tailLink->Flink = newProviderLink;",
    ),
    KernelRewriteRule(
        "tail-link-cast",
        "inferred_record_layout",
        r"tailLink = \(_QWORD \*\)",
        "tailLink = (LIST_ENTRY *)",
    ),
]


def apply_kernel_rewrites(text: str, plan: CleanPlan) -> str:
    comment_kinds = _comment_kinds(plan)
    if not comment_kinds:
        return text

    result = text
    for rule in KERNEL_REWRITE_RULES:
        if rule.requires_comment_kind not in comment_kinds:
            continue
        result = re.sub(rule.pattern, rule.replacement, result, flags=rule.flags)

    if "inferred_record_layout" in comment_kinds:
        result = _rewrite_provider_list_traversal(result)
        result = _rewrite_list_macros(result)
        result = _hoist_provider_error_labels(result)

    result = _annotate_suspicious_call_targets(result, plan)

    if "inferred_record_layout" in comment_kinds and "INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD" in result:
        result = INFERRED_PROVIDER_TYPE + result
    return result


def apply_known_kernel_struct_rewrites(text: str, capture: FunctionCapture) -> str:
    result = text
    if looks_like_driver_entry(capture):
        result = _rewrite_driver_entry_device_extension(result)
    result = _rewrite_ob_callback_registration_setup(result)
    if not _looks_like_object_pre_operation_callback(capture) and not re.search(
        r"\b(?:preOperationInfo|operationInformation|OperationInformation|preInfo)\b",
        result,
    ):
        return result
    return _rewrite_ob_pre_operation_field_loads(result)


def _rewrite_ob_callback_registration_setup(text: str) -> str:
    if "ObRegisterCallbacks" not in text or "OperationRegistration" not in text:
        return text
    registration = _ob_operation_registration_variable(text)
    if not registration:
        return text

    escaped = re.escape(registration)
    if (
        re.search(
            r"(?m)^\s*_QWORD\s+%s\s*\[\s*4\s*\]\s*;[^\n]*$" % escaped,
            text,
        )
        is None
    ):
        return _rewrite_packed_ob_operation_registration(text, registration)

    result = re.sub(
        r"(?m)^(?P<indent>\s*)_QWORD\s+%s\s*\[\s*4\s*\](?P<suffix>\s*;[^\n]*)$" % escaped,
        r"\g<indent>OB_OPERATION_REGISTRATION %s\g<suffix>" % registration,
        text,
        count=1,
    )
    result = re.sub(
        r"\bmemset\s*\(\s*%s\s*," % escaped,
        "memset(&%s," % registration,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*\[\s*0\s*\]\s*=\s*(?P<value>[^;]+);$" % escaped,
        r"\g<indent>%s.ObjectType = \g<value>;" % registration,
        result,
    )

    def replace_operations(match: re.Match[str]) -> str:
        value = _parse_int_literal(match.group("value"))
        if value is None:
            formatted = match.group("value")
        else:
            formatted = _format_ob_operations(value)
        return "%s%s.Operations = %s;" % (match.group("indent"), registration, formatted)

    result = re.sub(
        r"(?m)^(?P<indent>\s*)LODWORD\s*\(\s*%s\s*\[\s*1\s*\]\s*\)\s*=\s*"
        r"(?P<value>[^;]+);$" % escaped,
        replace_operations,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*\[\s*1\s*\]\s*=\s*(?P<value>[^;]+);$" % escaped,
        replace_operations,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*\[\s*2\s*\]\s*=\s*(?P<value>[^;]+);$" % escaped,
        r"\g<indent>%s.PreOperation = \g<value>;" % registration,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*\[\s*3\s*\]\s*=\s*(?:0|0LL|0i64|NULL|nullptr)\s*;$" % escaped,
        r"\g<indent>%s.PostOperation = NULL;" % registration,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*\[\s*3\s*\]\s*=\s*(?P<value>[^;]+);$" % escaped,
        r"\g<indent>%s.PostOperation = \g<value>;" % registration,
        result,
    )
    result = re.sub(
        r"\b(?P<callback>[A-Za-z_][A-Za-z0-9_]*)\.OperationRegistration\s*=\s*"
        r"\(\s*OB_OPERATION_REGISTRATION\s*\*\s*\)%s\s*;" % escaped,
        r"\g<callback>.OperationRegistration = &%s;" % registration,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<callback>[A-Za-z_][A-Za-z0-9_]*)\.Version\s*=\s*256\s*;$",
        r"\g<indent>\g<callback>.Version = OB_FLT_REGISTRATION_VERSION;",
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)qmemcpy\s*\(\s*&(?P<callback>[A-Za-z_][A-Za-z0-9_]*)\.Altitude\s*,\s*"
        r"&(?P<altitude>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*sizeof\(\s*(?P=callback)\.Altitude\s*\)\s*\)\s*;$",
        r"\g<indent>\g<callback>.Altitude = \g<altitude>;",
        result,
    )
    return result


def _rewrite_packed_ob_operation_registration(text: str, registration: str) -> str:
    escaped = re.escape(registration)
    declaration = re.search(
        r"(?m)^(?P<indent>\s*)__int128\s+%s(?P<suffix>\s*;[^\n]*)\n"
        r"(?P=indent)__int128\s+(?P<tail>[A-Za-z_][A-Za-z0-9_]*)(?P<tail_suffix>\s*;[^\n]*)$"
        % escaped,
        text,
    )
    if declaration is None:
        return text
    tail = declaration.group("tail")
    tail_escaped = re.escape(tail)
    result = re.sub(
        r"(?m)^(?P<indent>\s*)__int128\s+%s(?P<suffix>\s*;[^\n]*)\n"
        r"(?P=indent)__int128\s+%s\s*;[^\n]*$" % (escaped, tail_escaped),
        r"\g<indent>OB_OPERATION_REGISTRATION %s\g<suffix>" % registration,
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*=\s*(?:0|0LL|0i64|NULL|nullptr)\s*;$" % escaped,
        r"\g<indent>memset(&%s, 0, sizeof(%s));" % (registration, registration),
        result,
        count=1,
    )
    result = re.sub(
        r"(?m)^\s*%s\s*=\s*(?:0|0LL|0i64|NULL|nullptr)\s*;\n?" % tail_escaped,
        "",
        result,
        count=1,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)\*\(\s*_QWORD\s+\*\s*\)&%s\s*=\s*(?P<value>[^;]+);$" % escaped,
        r"\g<indent>%s.ObjectType = \g<value>;" % registration,
        result,
    )

    def replace_operations(match: re.Match[str]) -> str:
        value = _parse_int_literal(match.group("value"))
        formatted = match.group("value") if value is None else _format_ob_operations(value)
        return "%s%s.Operations = %s;" % (match.group("indent"), registration, formatted)

    result = re.sub(
        r"(?m)^(?P<indent>\s*)DWORD2\s*\(\s*%s\s*\)\s*=\s*(?P<value>[^;]+);$" % escaped,
        replace_operations,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)\*\(\s*_QWORD\s+\*\s*\)&%s\s*=\s*(?P<value>[^;]+);$" % tail_escaped,
        r"\g<indent>%s.PreOperation = \g<value>;" % registration,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)\*\(\(\s*_QWORD\s+\*\s*\)&%s\s*\+\s*1\s*\)\s*=\s*"
        r"(?:0|0LL|0i64|NULL|nullptr)\s*;$" % tail_escaped,
        r"\g<indent>%s.PostOperation = NULL;" % registration,
        result,
    )
    result = re.sub(
        r"\b(?P<callback>[A-Za-z_][A-Za-z0-9_]*)\.OperationRegistration\s*=\s*"
        r"\(\s*OB_OPERATION_REGISTRATION\s*\*\s*\)&%s\s*;" % escaped,
        r"\g<callback>.OperationRegistration = &%s;" % registration,
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)\*\(\s*_DWORD\s+\*\s*\)&(?P<callback>[A-Za-z_][A-Za-z0-9_]*)\.Version\s*=\s*"
        r"(?P<value>[^;]+);$",
        _replace_packed_ob_callback_version,
        result,
    )
    return result


def _replace_packed_ob_callback_version(match: re.Match[str]) -> str:
    value = _parse_int_literal(match.group("value"))
    if value is None:
        return match.group(0)
    version = value & 0xFFFF
    count = (value >> 16) & 0xFFFF
    if version != 0x100 or count == 0:
        return match.group(0)
    indent = match.group("indent")
    callback = match.group("callback")
    return (
        "%s%s.Version = OB_FLT_REGISTRATION_VERSION;\n"
        "%s%s.OperationRegistrationCount = %d;"
    ) % (indent, callback, indent, callback, count)


def _ob_operation_registration_variable(text: str) -> str:
    match = re.search(
        r"\bOperationRegistration\s*=\s*\(\s*OB_OPERATION_REGISTRATION\s*\*\s*\)"
        r"&?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        text,
    )
    if match is not None:
        return match.group("name")
    match = re.search(
        r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*0\s*\]\s*=\s*Ps[A-Za-z0-9_]*Type\s*;",
        text,
    )
    if match is not None:
        return match.group("name")
    return ""


def _format_ob_operations(value: int) -> str:
    names = []
    remaining = value
    if remaining & 1:
        names.append("OB_OPERATION_HANDLE_CREATE")
        remaining &= ~1
    if remaining & 2:
        names.append("OB_OPERATION_HANDLE_DUPLICATE")
        remaining &= ~2
    if remaining:
        names.append("0x%X" % remaining)
    if not names:
        return "0"
    return " | ".join(names)


def _parse_int_literal(text: str) -> int | None:
    value = text.strip()
    value = re.sub(r"(?i)(ui64|i64|ull|llu|ll|ul|lu|u|l)$", "", value).strip()
    try:
        return int(value, 0)
    except ValueError:
        return None


def _rewrite_driver_entry_device_extension(text: str) -> str:
    extension = _driver_extension_variable(text)
    if not extension:
        return text
    if not _has_dword_driver_extension_declaration(text, extension):
        return text

    result = _rewrite_driver_extension_declaration(text, extension)
    result = _rewrite_driver_extension_scalar_fields(result, extension)
    result = _rewrite_driver_extension_pointer_fields(result, extension)
    result = _rewrite_driver_extension_address_fields(result, extension)
    result = _rewrite_driver_extension_initializer_calls(result, extension)

    if "INFERRED_DRIVER_DEVICE_EXTENSION" in result and not result.startswith(
        "// PseudoForge: inferred driver device extension"
    ):
        result = INFERRED_DRIVER_DEVICE_EXTENSION_TYPE + result.lstrip("\r\n")
    return result


def _driver_extension_variable(text: str) -> str:
    match = re.search(
        r"(?m)^\s*(?P<extension>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"[A-Za-z_][A-Za-z0-9_]*->DeviceExtension\s*;",
        text,
    )
    if match is None:
        return ""
    return match.group("extension")


def _has_dword_driver_extension_declaration(text: str, extension: str) -> bool:
    return (
        re.search(
            r"(?m)^\s*_DWORD\s+\*%s\s*;[^\n]*$" % re.escape(extension),
            text,
        )
        is not None
    )


def _rewrite_driver_extension_declaration(text: str, extension: str) -> str:
    return re.sub(
        r"(?m)^(?P<indent>\s*)_DWORD\s+\*%s(?P<suffix>\s*;[^\n]*)$" % re.escape(extension),
        r"\g<indent>INFERRED_DRIVER_DEVICE_EXTENSION *%s\g<suffix>" % extension,
        text,
        count=1,
    )


def _rewrite_driver_extension_scalar_fields(text: str, extension: str) -> str:
    escaped = re.escape(extension)

    def replace_signature(match: re.Match[str]) -> str:
        literal = match.group("literal")
        tag = decode_pool_tag_literal(literal)
        value = literal
        if tag:
            value = "POOL_TAG('%s', '%s', '%s', '%s')" % (tag[0], tag[1], tag[2], tag[3])
        return "%s%s->Signature = %s;" % (match.group("indent"), extension, value)

    result = re.sub(
        r"(?m)^(?P<indent>\s*)\*%s\s*=\s*"
        r"(?P<literal>(?:0x[0-9A-Fa-f]+|\d+)(?:uLL|ULL|LL|i64|u|U|L)?)\s*;" % escaped,
        replace_signature,
        text,
        count=1,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)%s\s*\[\s*184\s*\]\s*=" % escaped,
        r"\g<indent>%s->MaxRecords =" % extension,
        result,
    )
    result = re.sub(
        r"\bmemset\s*\(\s*%s\s*\+\s*180\s*,\s*0\s*,\s*0x10(?:u|U)?(?:LL|ULL|i64|L)?\s*\)"
        % escaped,
        "memset(&%s->RegistryPath, 0, sizeof(%s->RegistryPath))" % (extension, extension),
        result,
    )
    return result


def _rewrite_driver_extension_pointer_fields(text: str, extension: str) -> str:
    escaped = re.escape(extension)
    fields = {
        "1": "DeviceObject",
        "72": "WorkItem",
        "91": "RegistryPath.Buffer",
    }
    result = text
    for index, field_name in fields.items():
        result = re.sub(
            r"\*\(\(\s*(?:_QWORD|PIO_WORKITEM|PVOID)\s+\*\)\s*%s\s*\+\s*%s\s*\)"
            % (escaped, index),
            "%s->%s" % (extension, field_name),
            result,
        )
    return result


def _rewrite_driver_extension_address_fields(text: str, extension: str) -> str:
    escaped = re.escape(extension)
    result = text
    cast_replacements = [
        (r"\(\s*PKSPIN_LOCK\s*\)\s*%s\s*\+\s*16\b", "EventLock"),
        (r"\(\s*PNPAGED_LOOKASIDE_LIST\s*\)\s*\(\s*%s\s*\+\s*48\s*\)", "RecordLookaside"),
        (r"\(\s*PNPAGED_LOOKASIDE_LIST\s*\)\s*\(\s*%s\s*\+\s*80\s*\)", "ProcessRuleLookaside"),
        (r"\(\s*PKTIMER\s*\)\s*%s\s*\+\s*7\b", "Timer"),
        (r"\(\s*PRKDPC\s*\)\s*%s\s*\+\s*8\b", "TimerDpc"),
        (r"\(\s*PRKEVENT\s*\)\s*\(\s*%s\s*\+\s*146\s*\)", "WorkItemIdleEvent"),
        (r"\(\s*PEX_RUNDOWN_REF\s*\)\s*%s\s*\+\s*76\b", "Rundown"),
        (r"\(\s*PERESOURCE\s*\)\s*\(\s*%s\s*\+\s*154\s*\)", "Resource"),
    ]
    for pattern, field_name in cast_replacements:
        result = re.sub(pattern % escaped, "&%s->%s" % (extension, field_name), result)

    offset_replacements = {
        "4": "StateLock",
        "18": "AccessListLock",
        "34": "EventList",
        "38": "ProcessWhitelist",
        "42": "ProcessBlacklist",
        "48": "RecordLookaside",
        "80": "ProcessRuleLookaside",
        "146": "WorkItemIdleEvent",
        "154": "Resource",
        "180": "RegistryPath",
    }
    for offset, field_name in offset_replacements.items():
        result = re.sub(
            r"\b%s\s*\+\s*%s\b" % (escaped, offset),
            "&%s->%s" % (extension, field_name),
            result,
        )
    return result


def _rewrite_driver_extension_initializer_calls(text: str, extension: str) -> str:
    escaped = re.escape(extension)
    result = text
    fast_mutex_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)sub_[0-9A-Fa-f]+\s*\(\s*&%s->(?P<field>StateLock|AccessListLock)\s*\)\s*;"
        % escaped
    )
    result = fast_mutex_pattern.sub(
        r"\g<indent>ExInitializeFastMutex(&%s->\g<field>);" % extension,
        result,
    )
    list_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)sub_[0-9A-Fa-f]+\s*\(\s*&%s->"
        r"(?P<field>EventList|ProcessWhitelist|ProcessBlacklist)\s*\)\s*;" % escaped
    )
    result = list_pattern.sub(
        r"\g<indent>InitializeListHead(&%s->\g<field>);" % extension,
        result,
    )
    return result


def _comment_kinds(plan: CleanPlan) -> set[str]:
    return {str(comment.get("kind", "")) for comment in plan.comments}


def _looks_like_object_pre_operation_callback(capture: FunctionCapture) -> bool:
    function_name = capture.name or ""
    if function_name.endswith("ObjectPreOperation"):
        return True
    if _has_known_ob_pre_operation_signature(capture):
        return True
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 2:
        return False
    operation_info = params[1][0]
    return _has_ob_pre_operation_field_evidence(capture.pseudocode, operation_info)


def _has_known_ob_pre_operation_signature(capture: FunctionCapture) -> bool:
    prototype = capture.prototype or ""
    if "OB_PREOP_CALLBACK_STATUS" in prototype and "PRE_OPERATION" in prototype:
        return True
    return False


@lru_cache(maxsize=None)
def _profile_structure_layout(structure_name: str) -> tuple[ProfileLayoutField, ...]:
    metadata = kernel_structure_metadata(structure_name)
    fields = metadata.get("fields", [])
    if not isinstance(fields, list):
        return ()

    offset = 0
    result: list[ProfileLayoutField] = []
    for field in fields:
        if not isinstance(field, dict):
            continue
        name = str(field.get("name", "")).strip()
        if not name:
            continue
        type_text = _clean_profile_type(str(field.get("type", "")))
        size, align = _profile_type_layout(type_text, str(field.get("array", "")))
        offset = _align_up(offset, align)
        result.append(ProfileLayoutField(name, type_text, offset, size, align))
        offset += size
    return tuple(result)


def _profile_field_by_name(structure_name: str, field_name: str) -> ProfileLayoutField | None:
    for field in _profile_structure_layout(structure_name):
        if field.name == field_name:
            return field
    return None


def _profile_field_offset(structure_name: str, field_name: str) -> int | None:
    field = _profile_field_by_name(structure_name, field_name)
    return field.offset if field is not None else None


def _profile_type_layout(type_text: str, array_text: str = "") -> tuple[int, int]:
    resolved_type = _resolve_profile_alias(_clean_profile_type(type_text))
    if "*" in resolved_type:
        size, align = _PROFILE_POINTER_SIZE, _PROFILE_POINTER_SIZE
    else:
        size, align = _scalar_profile_type_layout(resolved_type)
    count = _profile_array_count(array_text)
    return max(size * count, 1), max(align, 1)


def _scalar_profile_type_layout(type_text: str) -> tuple[int, int]:
    normalized = _clean_profile_type(type_text).upper()
    if normalized in {"BOOLEAN", "BYTE", "CHAR", "CCHAR", "INT8", "UCHAR", "UINT8"}:
        return 1, 1
    if normalized in {"SHORT", "USHORT", "WCHAR", "WORD", "INT16", "UINT16"}:
        return 2, 2
    if normalized in {
        "__INT64",
        "INT64",
        "LONGLONG",
        "LONG64",
        "LONG_PTR",
        "PHYSICAL_ADDRESS",
        "SIZE_T",
        "SSIZE_T",
        "UINT64",
        "ULONG64",
        "ULONG_PTR",
        "ULONGLONG",
    }:
        return 8, 8
    return 4, 4


def _clean_profile_type(type_text: str) -> str:
    text = str(type_text or "")
    text = re.sub(r"\b(?:IN|OUT|OPTIONAL|CONST)\b", " ", text)
    text = re.sub(r"_[A-Za-z0-9]+_\s*(?:\([^)]*\))?", " ", text)
    text = re.sub(r"\b(?:const|volatile|struct|union|enum)\b", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _resolve_profile_alias(type_text: str) -> str:
    resolved = _clean_profile_type(type_text)
    seen: set[str] = set()
    while resolved and resolved not in seen:
        seen.add(resolved)
        metadata = kernel_type_alias_metadata(resolved)
        target = _clean_profile_type(str(metadata.get("target", ""))) if metadata else ""
        if not target or target == resolved:
            break
        resolved = target
    return resolved


def _profile_array_count(array_text: str) -> int:
    match = re.fullmatch(r"\[\s*(?P<count>\d+)\s*\]", str(array_text or "").strip())
    if match is None:
        return 1
    return max(int(match.group("count"), 10), 1)


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _profile_field_qword_sources(variable: str, structure_name: str, field_name: str) -> list[str]:
    field = _profile_field_by_name(structure_name, field_name)
    if field is None:
        return []

    escaped = re.escape(variable)
    sources = [
        r"\b%s->%s\b" % (escaped, re.escape(field.name)),
        r"\*\(_QWORD\s+\*\)\(\s*%s\s*\+\s*%s\s*\)"
        % (escaped, _literal_offset_pattern(field.offset)),
    ]
    if field.offset % _PROFILE_POINTER_SIZE == 0:
        sources.append(
            r"\*\(\(_QWORD\s+\*\)\s*%s\s*\+\s*%d\s*\)"
            % (escaped, field.offset // _PROFILE_POINTER_SIZE)
        )
    return sources


def _literal_offset_pattern(offset: int) -> str:
    return r"%d(?:LL|i64|L)?" % offset


def _field_access(variable: str, field: ProfileLayoutField) -> str:
    return "%s->%s" % (variable, field.name)


def _field_access_with_optional_cast(variable: str, field: ProfileLayoutField, requested_type: str) -> str:
    access = _field_access(variable, field)
    requested = re.sub(r"\s+", " ", requested_type).strip()
    if not requested or requested == "PVOID" or requested == field.type_text:
        return access
    return "(%s)%s" % (requested, access)


def _profile_backed_field_load_pattern(
    variable: str,
    structure_name: str,
    field_name: str,
) -> re.Pattern[str]:
    field = _profile_field_by_name(structure_name, field_name)
    if field is None:
        return re.compile(r"(?!x)x")

    escaped = re.escape(variable)
    alternatives = [
        r"\*\(_QWORD\s+\*\)\(\s*%s\s*\+\s*%s\s*\)"
        % (escaped, _literal_offset_pattern(field.offset)),
        r"\*\(\s*(?:P[A-Za-z_][A-Za-z0-9_]*|struct\s+_[A-Za-z_][A-Za-z0-9_]*\s*\*)"
        r"\s*\*?\s*\)\(\s*%s\s*\+\s*%s\s*\)"
        % (escaped, _literal_offset_pattern(field.offset)),
    ]
    if field.offset % _PROFILE_POINTER_SIZE == 0:
        index = field.offset // _PROFILE_POINTER_SIZE
        alternatives.extend(
            [
                r"\*\(\(_QWORD\s+\*\)\s*%s\s*\+\s*%d\s*\)" % (escaped, index),
                r"\*\(\(\s*(?:P[A-Za-z_][A-Za-z0-9_]*|struct\s+_[A-Za-z_][A-Za-z0-9_]*\s*\*)"
                r"\s+\*\s*\)\s*%s\s*\+\s*%d\s*\)" % (escaped, index),
            ]
        )
    return re.compile("|".join("(?:%s)" % pattern for pattern in alternatives))


def _profile_field_is_pointer(field: ProfileLayoutField) -> bool:
    return "*" in _resolve_profile_alias(field.type_text)


def _ob_pre_operation_operation_check_pattern(variable: str) -> re.Pattern[str]:
    field = _profile_field_by_name(_OB_PRE_OPERATION_INFORMATION, "Operation")
    if field is None:
        return re.compile(r"(?!x)x")

    escaped = re.escape(variable)
    comparisons = []
    if field.offset == 0:
        comparisons.append(r"\*\(_DWORD\s+\*\)\s*%s\b\s*==\s*[12]\b" % escaped)
    else:
        comparisons.append(
            r"\*\(_DWORD\s+\*\)\(\s*%s\s*\+\s*%s\s*\)\s*==\s*[12]\b"
            % (escaped, _literal_offset_pattern(field.offset))
        )
    if field.offset % 4 == 0:
        comparisons.append(
            r"\*\(\(_DWORD\s+\*\)\s*%s\s*\+\s*%d\s*\)\s*==\s*[12]\b"
            % (escaped, field.offset // 4)
        )
    comparisons.append(r"\b%s->%s\s*==\s*[12]\b" % (escaped, re.escape(field.name)))
    return re.compile("|".join("(?:%s)" % pattern for pattern in comparisons))


def _has_ob_pre_operation_field_evidence(text: str, variable: str) -> bool:
    escaped = re.escape(variable)
    operation_check = _ob_pre_operation_operation_check_pattern(variable).search(text)
    desired_access_load = _ob_pre_operation_desired_access_pattern(variable).search(text)
    object_load = re.search(r"\b%s->Object\b" % escaped, text) or _profile_backed_field_load_pattern(
        variable,
        _OB_PRE_OPERATION_INFORMATION,
        "Object",
    ).search(text)
    return bool(operation_check and (desired_access_load or object_load))


def _rewrite_ob_pre_operation_field_loads(text: str) -> str:
    candidate_pattern = re.compile(
        r"\b(?P<var>(?:preOperationInfo|operationInformation|OperationInformation|preInfo))\b"
    )
    candidates = sorted({match.group("var") for match in candidate_pattern.finditer(text)}, key=len, reverse=True)
    if not candidates:
        return text

    result = text
    for variable in candidates:
        if not _has_ob_pre_operation_variable_evidence(result, variable):
            continue
        result = _rewrite_ob_pre_operation_desired_access_loads(result, variable)
        result = _rewrite_ob_pre_operation_access_mask_zero_init(result, variable)
        result = _rewrite_profile_backed_field_loads(result, variable, _OB_PRE_OPERATION_INFORMATION)
    result = _rewrite_ob_pre_operation_inferred_records(result)
    return result


def _has_ob_pre_operation_variable_evidence(text: str, variable: str) -> bool:
    escaped = re.escape(variable)
    if re.search(r"\bPOB_PRE_OPERATION_INFORMATION\s+%s\b" % escaped, text):
        return True
    if re.search(r"\b%s->(?:Operation|Object|ObjectType|CallContext|Parameters)\b" % escaped, text):
        return True
    operation_check = _ob_pre_operation_operation_check_pattern(variable).search(text)
    desired_access_load = _ob_pre_operation_desired_access_pattern(variable).search(text)
    object_load = _profile_backed_field_load_pattern(variable, _OB_PRE_OPERATION_INFORMATION, "Object").search(text)
    return bool(operation_check and (desired_access_load or object_load))


def _rewrite_profile_backed_field_loads(text: str, variable: str, structure_name: str) -> str:
    result = text
    fields = sorted(_profile_structure_layout(structure_name), key=lambda field: field.offset, reverse=True)
    for field in fields:
        result = _rewrite_profile_qword_field_load(result, variable, field)
        result = _rewrite_profile_typed_pointer_field_load(result, variable, field)
        result = _rewrite_profile_dword_field_load(result, variable, field)
    return result


def _rewrite_profile_qword_field_load(text: str, variable: str, field: ProfileLayoutField) -> str:
    if field.size != _PROFILE_POINTER_SIZE:
        return text

    escaped = re.escape(variable)
    result = re.sub(
        r"\*\(_QWORD\s+\*\)\(\s*%s\s*\+\s*%s\s*\)" % (escaped, _literal_offset_pattern(field.offset)),
        _field_access(variable, field),
        text,
    )
    if field.offset % _PROFILE_POINTER_SIZE != 0:
        return result
    return re.sub(
        r"\*\(\(_QWORD\s+\*\)\s*%s\s*\+\s*%d\s*\)" % (escaped, field.offset // _PROFILE_POINTER_SIZE),
        _field_access(variable, field),
        result,
    )


def _rewrite_profile_typed_pointer_field_load(text: str, variable: str, field: ProfileLayoutField) -> str:
    if not _profile_field_is_pointer(field):
        return text

    escaped = re.escape(variable)
    pointer_type = r"(?:P[A-Za-z_][A-Za-z0-9_]*|struct\s+_[A-Za-z_][A-Za-z0-9_]*\s*\*)"
    byte_pattern = re.compile(
        r"\*\(\s*(?P<type>%s)\s*\*?\s*\)\(\s*%s\s*\+\s*%s\s*\)"
        % (pointer_type, escaped, _literal_offset_pattern(field.offset))
    )
    result = byte_pattern.sub(
        lambda match: _field_access_with_optional_cast(variable, field, match.group("type")),
        text,
    )
    if field.offset % _PROFILE_POINTER_SIZE != 0:
        return result

    index_pattern = re.compile(
        r"\*\(\(\s*(?P<type>%s)\s+\*\s*\)\s*%s\s*\+\s*%d\s*\)"
        % (pointer_type, escaped, field.offset // _PROFILE_POINTER_SIZE)
    )
    return index_pattern.sub(
        lambda match: _field_access_with_optional_cast(variable, field, match.group("type")),
        result,
    )


def _rewrite_profile_dword_field_load(text: str, variable: str, field: ProfileLayoutField) -> str:
    if field.size != 4:
        return text

    escaped = re.escape(variable)
    replacement = _field_access(variable, field)
    if field.offset == 0:
        result = re.sub(r"\*\(_DWORD\s+\*\)\s*%s\b" % escaped, replacement, text)
    else:
        result = re.sub(
            r"\*\(_DWORD\s+\*\)\(\s*%s\s*\+\s*%s\s*\)" % (escaped, _literal_offset_pattern(field.offset)),
            replacement,
            text,
        )
    if field.offset % 4 != 0:
        return result
    return re.sub(
        r"\*\(\(_DWORD\s+\*\)\s*%s\s*\+\s*%d\s*\)" % (escaped, field.offset // 4),
        replacement,
        result,
    )


def _rewrite_ob_pre_operation_inferred_records(text: str) -> str:
    process_vars = _infer_ob_process_rule_record_vars(text)
    event_vars = _infer_ob_callback_event_record_vars(text)
    if not process_vars and not event_vars:
        return text

    result = text
    for variable in sorted(process_vars, key=len, reverse=True):
        result = _rewrite_ob_process_rule_record_var(result, variable)
    for variable in sorted(event_vars, key=len, reverse=True):
        result = _rewrite_ob_callback_event_record_var(result, variable)
    result = _prepend_ob_inferred_record_types(result, bool(process_vars), bool(event_vars))
    return result


def _infer_ob_process_rule_record_vars(text: str) -> set[str]:
    result: set[str] = set()
    for match in re.finditer(r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\[2\]\s*(?:==|!=)\s*[A-Za-z_][A-Za-z0-9_]*", text):
        variable = match.group("var")
        if re.search(r"\+\+\*\(\(_DWORD\s+\*\)%s\s*\+\s*6\s*\)" % re.escape(variable), text) and re.search(
            r"KeQuerySystemTimePrecise\(\s*%s\s*\+\s*4\s*\)" % re.escape(variable),
            text,
        ):
            result.add(variable)
    for match in re.finditer(r"\bmemset\(\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*0\s*,\s*0x28uLL\s*\);", text):
        variable = match.group("var")
        evidence = [
            r"\*\(\(_QWORD\s+\*\)%s\s*\+\s*2\s*\)\s*=",
            r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*6\s*\)\s*=",
            r"\b%s\[28\]\s*=",
            r"KeQuerySystemTimePrecise\(\s*%s\s*\+\s*32\s*\)",
        ]
        if all(re.search(pattern % re.escape(variable), text) for pattern in evidence):
            result.add(variable)
    return result


def _infer_ob_callback_event_record_vars(text: str) -> set[str]:
    result: set[str] = set()
    for match in re.finditer(r"\bmemset\(\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*0\s*,\s*0x38uLL\s*\);", text):
        variable = match.group("var")
        evidence = [
            r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*4\s*\)\s*=",
            r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*5\s*\)\s*=",
            r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*6\s*\)\s*=",
            r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*9\s*\)\s*=",
            r"\*\(\(_QWORD\s+\*\)%s\s*\+\s*5\s*\)\s*=",
            r"\*\(\(_QWORD\s+\*\)%s\s*\+\s*6\s*\)\s*=",
        ]
        if all(re.search(pattern % re.escape(variable), text) for pattern in evidence):
            result.add(variable)
    return result


def _rewrite_ob_process_rule_record_var(text: str, variable: str) -> str:
    escaped = re.escape(variable)
    result = _rewrite_declaration_type(text, variable, "INFERRED_OB_PROCESS_RULE_RECORD")
    result = re.sub(
        r"\b%s\s*=\s*\(char\s+\*\)\s*ExAllocateFromNPagedLookasideList\(" % escaped,
        "%s = (INFERRED_OB_PROCESS_RULE_RECORD *)ExAllocateFromNPagedLookasideList(" % variable,
        result,
    )
    result = re.sub(
        r"\b%s\s*=\s*\*\(__int64\s+\*\*\)\((?P<head>[^)]+)\)" % escaped,
        r"%s = (INFERRED_OB_PROCESS_RULE_RECORD *)*(LIST_ENTRY **)(\g<head>)" % variable,
        result,
    )
    result = re.sub(
        r"\b%s\s*!=\s*\(__int64\s+\*\)\((?P<head>[^)]+)\)" % escaped,
        r"%s != (INFERRED_OB_PROCESS_RULE_RECORD *)(\g<head>)" % variable,
        result,
    )
    result = re.sub(
        r"\b%s\s*=\s*\(__int64\s+\*\)\*%s\b" % (escaped, escaped),
        "%s = (INFERRED_OB_PROCESS_RULE_RECORD *)%s->Link.Flink" % (variable, variable),
        result,
    )
    replacements = [
        (r"\(%s\)\s*%s\[2\]" % (_POINTER_SIZED_CAST_PATTERN, escaped), "%s->ProcessId" % variable),
        (r"\+\+\*\(\(_DWORD\s+\*\)%s\s*\+\s*6\s*\)" % escaped, "++%s->HitCount" % variable),
        (r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*6\s*\)" % escaped, "%s->HitCount" % variable),
        (r"\*\(\(_QWORD\s+\*\)%s\s*\+\s*2\s*\)" % escaped, "%s->ProcessId" % variable),
        (r"\b%s\[28\]" % escaped, "%s->AutoAdded" % variable),
        (r"KeQuerySystemTimePrecise\(\s*%s\s*\+\s*4\s*\)" % escaped, "KeQuerySystemTimePrecise(&%s->LastSeenTime)" % variable),
        (r"KeQuerySystemTimePrecise\(\s*%s\s*\+\s*32\s*\)" % escaped, "KeQuerySystemTimePrecise(&%s->LastSeenTime)" % variable),
        (r"memset\(\s*%s\s*,\s*0\s*,\s*0x28uLL\s*\)" % escaped, "memset(%s, 0, sizeof(*%s))" % (variable, variable)),
    ]
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result)
    result = _rewrite_ob_process_rule_record_list_loop(result, variable)
    return result


def _rewrite_ob_process_rule_record_list_loop(text: str, variable: str) -> str:
    link_name = _record_link_name(variable)
    if re.search(r"\b%s\b" % re.escape(link_name), text):
        return text

    escaped = re.escape(variable)
    pattern = re.compile(
        r"(?m)^"
        r"(?P<indent>\s*)for \( "
        r"%s = \(INFERRED_OB_PROCESS_RULE_RECORD \*\)\*\(LIST_ENTRY \*\*\)\((?P<head>[^)]+)\); "
        r"%s != \(INFERRED_OB_PROCESS_RULE_RECORD \*\)\((?P=head)\); "
        r"%s = \(INFERRED_OB_PROCESS_RULE_RECORD \*\)%s->Link\.Flink \)\n"
        r"(?P<brace_indent>\s*)\{\n"
        % (escaped, escaped, escaped, escaped)
    )
    match = pattern.search(text)
    if match is None:
        return text

    body_indent = match.group("brace_indent") + "  "
    replacement = (
        "%sfor ( %s = *(LIST_ENTRY **)(%s); %s != (LIST_ENTRY *)(%s); %s = %s->Flink )\n"
        "%s{\n"
        "%s%s = CONTAINING_RECORD(%s, INFERRED_OB_PROCESS_RULE_RECORD, Link);\n"
        % (
            match.group("indent"),
            link_name,
            match.group("head"),
            link_name,
            match.group("head"),
            link_name,
            link_name,
            match.group("brace_indent"),
            body_indent,
            variable,
            link_name,
        )
    )
    result = pattern.sub(replacement, text, count=1)
    return _insert_record_link_declaration(result, variable, link_name)


def _record_link_name(variable: str) -> str:
    if variable.endswith("Entry"):
        return variable[: -len("Entry")] + "Link"
    if variable.endswith("Record"):
        return variable[: -len("Record")] + "Link"
    return variable + "Link"


def _insert_record_link_declaration(text: str, variable: str, link_name: str) -> str:
    return re.sub(
        r"(?m)^(?P<indent>\s*)INFERRED_OB_PROCESS_RULE_RECORD\s+\*%s(?P<suffix>\s*;[^\n]*)$"
        % re.escape(variable),
        r"\g<indent>INFERRED_OB_PROCESS_RULE_RECORD *%s\g<suffix>\n\g<indent>LIST_ENTRY *%s;"
        % (variable, link_name),
        text,
        count=1,
    )


def _rewrite_ob_callback_event_record_var(text: str, variable: str) -> str:
    escaped = re.escape(variable)
    result = _rewrite_declaration_type(text, variable, "INFERRED_OB_CALLBACK_EVENT_RECORD")
    result = re.sub(
        r"\b%s\s*=\s*ExAllocateFromNPagedLookasideList\(" % escaped,
        "%s = (INFERRED_OB_CALLBACK_EVENT_RECORD *)ExAllocateFromNPagedLookasideList(" % variable,
        result,
    )
    result = re.sub(
        r"memset\(\s*%s\s*,\s*0\s*,\s*0x38uLL\s*\)" % escaped,
        "memset(%s, 0, sizeof(*%s))" % (variable, variable),
        result,
    )
    dword_fields = {
        4: "RecordSize",
        5: "EventCode",
        6: "CallerProcessId",
        7: "CallerThreadId",
        8: "SubjectProcessId",
        9: "Status",
    }
    for index, field in dword_fields.items():
        result = re.sub(
            r"\*\(\(_DWORD\s+\*\)%s\s*\+\s*%d\s*\)" % (escaped, index),
            "%s->%s" % (variable, field),
            result,
        )
    result = re.sub(
        r"\*\(\(_QWORD\s+\*\)%s\s*\+\s*5\s*\)" % escaped,
        "%s->Sequence" % variable,
        result,
    )
    result = re.sub(
        r"\*\(\(_QWORD\s+\*\)%s\s*\+\s*6\s*\)" % escaped,
        "%s->Timestamp" % variable,
        result,
    )
    return result


def _rewrite_declaration_type(text: str, variable: str, type_name: str) -> str:
    return re.sub(
        r"(?m)^(?P<indent>\s*)(?:__int64\s+\*|char\s+\*|void\s+\*|PVOID\s+)%s(?P<suffix>\s*;[^\n]*)$"
        % re.escape(variable),
        r"\g<indent>%s *%s\g<suffix>" % (type_name, variable),
        text,
        count=1,
    )


def _prepend_ob_inferred_record_types(text: str, include_process: bool, include_event: bool) -> str:
    parts = []
    if include_process and "typedef struct _INFERRED_OB_PROCESS_RULE_RECORD" not in text:
        parts.append(INFERRED_OB_PROCESS_RULE_RECORD_TYPE)
    if include_event and "typedef struct _INFERRED_OB_CALLBACK_EVENT_RECORD" not in text:
        parts.append(INFERRED_OB_CALLBACK_EVENT_RECORD_TYPE)
    if not parts:
        return text
    return "".join(parts) + text


def _rewrite_ob_pre_operation_desired_access_loads(text: str, variable: str) -> str:
    pattern = _ob_pre_operation_desired_access_pattern(variable)
    if pattern.search(text) is None:
        return text

    lines = text.splitlines()
    updated_lines = []
    for index, line in enumerate(lines):
        context = "\n".join(lines[max(0, index - 6) : index + 1])
        member, field = _ob_pre_operation_parameters_member(context, variable)
        replacement = "%s->Parameters->%s.%s" % (variable, member, field)
        updated_lines.append(pattern.sub(replacement, line))
    return "\n".join(updated_lines)


def _ob_pre_operation_desired_access_pattern(variable: str) -> re.Pattern[str]:
    parameter_sources = _profile_field_qword_sources(variable, _OB_PRE_OPERATION_INFORMATION, "Parameters")
    original_offsets = _ob_pre_operation_original_desired_access_offsets()
    if not parameter_sources or not original_offsets:
        return re.compile(r"(?!x)x")

    source_pattern = "|".join("(?:%s)" % source for source in parameter_sources)
    offset_pattern = "|".join(_literal_offset_pattern(offset) for offset in original_offsets)
    return re.compile(
        r"\*\(_DWORD\s+\*\)\(\s*(?:%s)\s*\+\s*(?:%s)\s*\)"
        % (source_pattern, offset_pattern)
    )


@lru_cache(maxsize=None)
def _ob_pre_operation_original_desired_access_offsets() -> tuple[int, ...]:
    offsets = []
    for structure_name in (
        _OB_PRE_CREATE_HANDLE_INFORMATION,
        _OB_PRE_DUPLICATE_HANDLE_INFORMATION,
    ):
        offset = _profile_field_offset(structure_name, "OriginalDesiredAccess")
        if offset is not None:
            offsets.append(offset)
    return tuple(sorted(set(offsets)))


def _rewrite_ob_pre_operation_access_mask_zero_init(text: str, variable: str) -> str:
    access_names = {
        match.group("target")
        for match in re.finditer(
            r"\b(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s->Parameters->"
            r"(?:CreateHandleInformation|DuplicateHandleInformation)\.OriginalDesiredAccess\s*;"
            % re.escape(variable),
            text,
        )
    }
    if not access_names:
        return text

    result = text
    for name in sorted(access_names, key=len, reverse=True):
        if re.search(r"\b%s\s*&\s*0x[0-9A-Fa-f]+" % re.escape(name), result) is None:
            continue
        result = re.sub(
            r"(?m)^(?P<indent>\s*)LOBYTE\(\s*%s\s*\)\s*=\s*0\s*;\s*$" % re.escape(name),
            r"\g<indent>%s = 0;" % name,
            result,
            count=1,
        )
    return result


def _ob_pre_operation_parameters_member(context: str, variable: str) -> tuple[str, str]:
    create_member = _ob_pre_operation_member_name(_OB_PRE_CREATE_HANDLE_INFORMATION)
    duplicate_member = _ob_pre_operation_member_name(_OB_PRE_DUPLICATE_HANDLE_INFORMATION)
    access_field = _ob_pre_operation_original_desired_access_field_name()
    if re.search(r"\bOB_OPERATION_HANDLE_DUPLICATE\b", context):
        return duplicate_member, access_field
    if re.search(r"\bOB_OPERATION_HANDLE_CREATE\b", context):
        return create_member, access_field
    if re.search(r"\*\(_DWORD\s+\*\)\s*%s\b\s*==\s*2(?:u|U|l|L|ll|LL)?\b" % re.escape(variable), context):
        return duplicate_member, access_field
    if re.search(r"%s->Operation\s*==\s*2(?:u|U|l|L|ll|LL)?\b" % re.escape(variable), context):
        return duplicate_member, access_field
    return create_member, access_field


def _ob_pre_operation_member_name(structure_name: str) -> str:
    name = structure_name
    if name.startswith("OB_PRE_"):
        name = name[len("OB_PRE_") :]
    if name.endswith("_INFORMATION"):
        name = name[: -len("_INFORMATION")]
    parts = [part for part in name.split("_") if part]
    return "".join(part[:1] + part[1:].lower() for part in parts) + "Information"


def _ob_pre_operation_original_desired_access_field_name() -> str:
    for structure_name in (
        _OB_PRE_CREATE_HANDLE_INFORMATION,
        _OB_PRE_DUPLICATE_HANDLE_INFORMATION,
    ):
        field = _profile_field_by_name(structure_name, "OriginalDesiredAccess")
        if field is not None:
            return field.name
    return "OriginalDesiredAccess"


def _rewrite_provider_list_traversal(text: str) -> str:
    result = _insert_provider_list_head_declaration(text)
    result = _insert_provider_list_head_assignment(result)
    result = _rewrite_provider_for_loop(result)
    result = _rewrite_provider_list_head_uses(result)
    return result


def _insert_provider_list_head_declaration(text: str) -> str:
    if "providerListHead" in text:
        return text
    return re.sub(
        r"(?m)^(\s*)LIST_ENTRY \*providerLink(\s*;[^\n]*\n)",
        r"\1LIST_ENTRY *providerLink\2\1LIST_ENTRY *providerListHead;\n",
        text,
        count=1,
    )


def _insert_provider_list_head_assignment(text: str) -> str:
    if "providerListHead = (LIST_ENTRY *)&ExpFirmwareTableProviderListHead;" in text:
        return text

    def repl(match: re.Match[str]) -> str:
        indent = match.group("indent")
        return match.group(0) + indent + "providerListHead = (LIST_ENTRY *)&ExpFirmwareTableProviderListHead;\n"

    return re.sub(
        r"(?m)^(?P<indent>\s*)ExAcquireResourceExclusiveLite\(&ExpFirmwareTableResource,\s*1u\);\n",
        repl,
        text,
        count=1,
    )


def _rewrite_provider_for_loop(text: str) -> str:
    pattern = re.compile(
        r"for \( providerRecord = CONTAINING_RECORD\(ExpFirmwareTableProviderListHead, "
        r"INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link\); ; "
        r"providerRecord = CONTAINING_RECORD\(providerLink->Flink, "
        r"INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link\) \)\n"
        r"(?P<brace_indent>\s*)\{\n"
        r"(?P<body_indent>\s*)providerLink = &providerRecord->Link;\n"
        r"(?P=body_indent)if \( &ExpFirmwareTableProviderListHead == providerLink \)\n"
        r"(?P<break_indent>\s*)break;\n"
    )

    def repl(match: re.Match[str]) -> str:
        body_indent = match.group("body_indent")
        return (
            "for ( providerLink = providerListHead->Flink; providerLink != providerListHead; "
            "providerLink = providerLink->Flink )\n"
            + match.group("brace_indent")
            + "{\n"
            + body_indent
            + "providerRecord = CONTAINING_RECORD(providerLink, INFERRED_EXP_FIRMWARE_TABLE_PROVIDER_RECORD, Link);\n"
        )

    return pattern.sub(repl, text, count=1)


def _rewrite_provider_list_head_uses(text: str) -> str:
    replacements = [
        (r"\(PVOID\)providerRecord->DriverObject", "providerRecord->DriverObject"),
        (r"providerLink->Flink->Blink == providerLink", "nextLink->Blink == providerLink"),
        (r"previousLink = \(_QWORD \*\)providerRecord->Link.Blink;", "previousLink = providerLink->Blink;"),
        (r"tailLink = \(LIST_ENTRY \*\)qword_[A-Fa-f0-9]+;", "tailLink = providerListHead->Blink;"),
        (r"tailLink->Flink != &ExpFirmwareTableProviderListHead", "tailLink->Flink != providerListHead"),
        (r"newProviderLink->Flink = &ExpFirmwareTableProviderListHead;", "newProviderLink->Flink = providerListHead;"),
        (r"qword_[A-Fa-f0-9]+ = \(__int64\)newProviderLink;", "providerListHead->Blink = newProviderLink;"),
    ]
    result = text
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result)
    return result


def _rewrite_list_macros(text: str) -> str:
    result = re.sub(
        r"(?m)^(?P<indent>\s*)newProviderRecord->Link.Blink = &newProviderRecord->Link;\n"
        r"(?P=indent)newProviderRecord->Link.Flink = &newProviderRecord->Link;",
        r"\g<indent>InitializeListHead(newProviderLink);",
        text,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)previousLink->Flink = nextLink;\n"
        r"(?P=indent)nextLink->Blink = previousLink;",
        r"\g<indent>RemoveEntryList(providerLink);",
        result,
    )
    result = re.sub(
        r"(?m)^(?P<indent>\s*)newProviderLink->Flink = providerListHead;\n"
        r"(?P=indent)newProviderLink->Blink = tailLink;\n"
        r"(?P=indent)tailLink->Flink = newProviderLink;\n"
        r"(?P=indent)providerListHead->Blink = newProviderLink;",
        r"\g<indent>InsertTailList(providerListHead, newProviderLink);",
        result,
    )
    return result


def _hoist_provider_error_labels(text: str) -> str:
    if "LABEL_19:" not in text or "LABEL_21:" not in text or "LABEL_22:" not in text:
        return text

    result, moved_failfast = _replace_embedded_provider_failfast_label(text)
    result, moved_invalid_parameter = _replace_embedded_provider_invalid_parameter_label(result)
    if not moved_failfast or not moved_invalid_parameter:
        return text

    return _insert_provider_tail_error_labels(result)


def _replace_embedded_provider_failfast_label(text: str) -> tuple[str, bool]:
    pattern = re.compile(
        r"(?m)^LABEL_19:\n"
        r"(?P<call_indent>[ \t]+)__fastfail\(3u\);",
    )
    match = pattern.search(text)
    if match is None:
        return text, False

    replacement = match.group("call_indent") + "goto LABEL_19;"
    return pattern.sub(replacement, text, count=1), True


def _replace_embedded_provider_invalid_parameter_label(text: str) -> tuple[str, bool]:
    pattern = re.compile(
        r"(?m)^(?P<if_indent>[ \t]*)if \( !pTableHandler->Register \)\n"
        r"(?P=if_indent)\{\n"
        r"(?P<label_indent>[ \t]*)LABEL_21:\n"
        r"(?P<body_indent>[ \t]+)status = STATUS_INVALID_PARAMETER;\n"
        r"(?P=body_indent)goto LABEL_22;\n"
        r"(?P=if_indent)\}",
    )
    match = pattern.search(text)
    if match is None:
        return text, False

    if_indent = match.group("if_indent")
    body_indent = match.group("body_indent")
    replacement = "\n".join(
        [
            if_indent + "if ( !pTableHandler->Register )",
            if_indent + "{",
            body_indent + "goto LABEL_21;",
            if_indent + "}",
        ]
    )
    return pattern.sub(replacement, text, count=1), True


def _insert_provider_tail_error_labels(text: str) -> str:
    pattern = re.compile(
        r"(?m)^(?P<label_indent>[ \t]*)LABEL_22:\n"
        r"(?P<body_indent>[ \t]*)(?P<release>ExReleaseResourceLite[^\n]*;\n"
        r"(?P=body_indent)KeLeaveCriticalRegion\(\);\n"
        r"(?P=body_indent)return status;)",
    )
    match = pattern.search(text)
    if match is None:
        return text

    label_indent = match.group("label_indent")
    body_indent = match.group("body_indent") or "  "
    replacement = "\n".join(
        [
            label_indent + "LABEL_22:",
            body_indent + match.group("release"),
            label_indent + "LABEL_21:",
            body_indent + "status = STATUS_INVALID_PARAMETER;",
            body_indent + "goto LABEL_22;",
            label_indent + "LABEL_19:",
            body_indent + "__fastfail(3u);",
        ]
    )
    return pattern.sub(replacement, text, count=1)


def _annotate_suspicious_call_targets(text: str, plan: CleanPlan) -> str:
    if not any("Potential bad call target PsReferenceSiloContext" in warning for warning in plan.warnings):
        return text
    if "likely object reference paired with ObfDereferenceObject" in text:
        return text
    return re.sub(
        r"(?m)^(?P<indent>\s*)PsReferenceSiloContext\(newProviderRecord->DriverObject\);",
        (
            r"\g<indent>// PseudoForge: likely object reference paired with ObfDereferenceObject.\n"
            r"\g<indent>// PseudoForge: original recovered call target was PsReferenceSiloContext.\n"
            r"\g<indent>PsReferenceSiloContext(newProviderRecord->DriverObject);"
        ),
        text,
        count=1,
    )
