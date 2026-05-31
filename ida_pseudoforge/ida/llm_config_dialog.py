from __future__ import annotations

import hashlib
import threading
from copy import deepcopy

from ida_pseudoforge.config import (
    DEFAULT_MODEL,
    LlmConfig,
    PseudoForgeConfig,
    get_provider_api_key,
    masked_key,
    set_provider_api_key,
)
from ida_pseudoforge.logging import log_checkpoint, trace_scope
from ida_pseudoforge.models.model_discovery import ModelDiscoveryResult, discover_provider_models
from ida_pseudoforge.models.provider_registry import (
    CLI_PROVIDERS,
    HTTP_PROVIDERS,
    PROVIDER_ORDER,
    normalize_provider,
    provider_defaults,
    provider_label,
    provider_model_options,
)

try:
    import ida_kernwin  # type: ignore
except Exception:
    ida_kernwin = None


_MODEL_DISCOVERY_CACHE: dict[tuple[str, str, str], ModelDiscoveryResult] = {}
_MODEL_DISCOVERY_INFLIGHT: set[tuple[str, str, str]] = set()
_MODEL_DISCOVERY_LOCK = threading.Lock()


def ask_llm_config(current_config: PseudoForgeConfig, warn) -> PseudoForgeConfig | None:
    if ida_kernwin is None:
        return current_config

    updated_config = deepcopy(current_config)
    current = updated_config.llm

    log_checkpoint("config.ask_enabled.before")
    enabled_choice = ida_kernwin.ask_yn(
        1 if current.enabled else 0,
        "Enable PseudoForge LLM rename assist?",
    )
    log_checkpoint("config.ask_enabled.after", value=enabled_choice)
    if enabled_choice < 0:
        return None

    current_provider = normalize_provider(current.provider)
    log_checkpoint("config.ask_provider.before", current=current_provider)
    provider = ask_provider(current_provider, warn)
    log_checkpoint("config.ask_provider.after", provider=provider)
    if provider is None:
        return None
    defaults = provider_defaults(provider)
    provider_changed = provider != current_provider

    base_url = ""
    command_template = ""

    if provider in HTTP_PROVIDERS:
        log_checkpoint("config.ask_base_url.before", provider=provider)
        base_url = ida_kernwin.ask_str(
            _current_or_default(current.base_url, defaults.base_url, provider_changed),
            0,
            "%s base URL" % provider_label(provider),
        )
        log_checkpoint("config.ask_base_url.after", provider=provider, has_value=base_url is not None)
        if base_url is None:
            return None

        if enabled_choice == 1 and not get_provider_api_key(updated_config, provider):
            log_checkpoint("config.ask_api_key.before", provider=provider)
            key_prompt = "%s API key (required to fetch model list)" % provider_label(provider)
            api_key_input = ida_kernwin.ask_str("", 0, key_prompt)
            log_checkpoint("config.ask_api_key.after", provider=provider, provided=bool(api_key_input))
            if api_key_input is None:
                return None
            if not api_key_input:
                warn("PseudoForge API key is required for %s." % provider_label(provider))
                return None
            set_provider_api_key(updated_config, provider, api_key_input)

    with trace_scope("config.discover_models", provider=provider):
        model_options = _model_options_for_dialog(
            provider,
            base_url=base_url or defaults.base_url,
            api_key=get_provider_api_key(updated_config, provider),
            timeout_seconds=min(max(current.timeout_seconds, 5), 60),
        )
    if model_options.warning:
        warn(
            "PseudoForge model discovery used fallback for %s: %s"
            % (provider_label(provider), model_options.warning)
        )

    log_checkpoint("config.ask_model.before", provider=provider, model_count=len(model_options.models))
    model = ask_model(
        provider,
        _current_or_default(current.model, defaults.model, provider_changed),
        model_options.models,
        model_options.source,
        warn,
    )
    log_checkpoint("config.ask_model.after", provider=provider, model=model)
    if model is None:
        return None

    if provider in CLI_PROVIDERS:
        log_checkpoint("config.ask_command.before", provider=provider)
        command_template = ida_kernwin.ask_str(
            _current_or_default(current.command_template, defaults.command_template, provider_changed),
            0,
            "%s command template" % provider_label(provider),
        )
        log_checkpoint("config.ask_command.after", provider=provider, has_value=command_template is not None)
        if command_template is None:
            return None

    log_checkpoint("config.ask_timeout.before")
    timeout_text = ida_kernwin.ask_str(
        str(current.timeout_seconds),
        0,
        "Request timeout seconds",
    )
    log_checkpoint("config.ask_timeout.after", has_value=timeout_text is not None)
    if timeout_text is None:
        return None

    try:
        timeout_seconds = int(timeout_text)
    except ValueError:
        timeout_seconds = current.timeout_seconds
    timeout_seconds = min(max(timeout_seconds, 5), 600)

    configured_base_url = (base_url or defaults.base_url).rstrip("/") if provider in HTTP_PROVIDERS else ""

    updated_config.llm = LlmConfig(
        enabled=enabled_choice == 1,
        provider=provider,
        base_url=configured_base_url,
        model=model or defaults.model or DEFAULT_MODEL,
        timeout_seconds=timeout_seconds,
        command_template=command_template or defaults.command_template,
        extra_headers=current.extra_headers,
    )
    return updated_config


def ask_provider(current_provider: str, warn) -> str | None:
    choices = ["%s (%s)" % (provider_label(provider), provider) for provider in PROVIDER_ORDER]
    try:
        selected_index = PROVIDER_ORDER.index(current_provider)
    except ValueError:
        selected_index = 0

    form = None
    try:
        form = ida_kernwin.Form(
            r"""BUTTON YES* OK
BUTTON CANCEL Cancel
PseudoForge LLM provider

<Provider:{provider}>
""",
            {
                "provider": ida_kernwin.Form.DropdownListControl(
                    items=choices,
                    readonly=True,
                    selval=selected_index,
                    swidth=70,
                ),
            },
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            return None

        selected = int(form.provider.value)
        if selected < 0 or selected >= len(PROVIDER_ORDER):
            warn("Invalid PseudoForge LLM provider selection.")
            return None
        return PROVIDER_ORDER[selected]
    finally:
        if form is not None:
            try:
                form.Free()
            except Exception:
                pass


def ask_model(
    provider: str,
    current_model: str,
    models: list[str],
    source: str,
    warn,
) -> str | None:
    choices = list(models)
    if current_model and current_model not in choices:
        choices.insert(0, current_model)

    try:
        selected_index = choices.index(current_model)
    except ValueError:
        selected_index = 0

    form = None
    try:
        form = ida_kernwin.Form(
            r"""BUTTON YES* OK
BUTTON CANCEL Cancel
PseudoForge LLM model

Catalog: %s
<Model:{model}>
""" % source,
            {
                "model": ida_kernwin.Form.DropdownListControl(
                    items=choices,
                    readonly=True,
                    selval=selected_index,
                    swidth=70,
                ),
            },
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            return None

        selected = int(form.model.value)
        if selected < 0 or selected >= len(choices):
            warn("Invalid PseudoForge LLM model selection.")
            return None
        return choices[selected]
    finally:
        if form is not None:
            try:
                form.Free()
            except Exception:
                pass


def format_llm_summary(config: LlmConfig, full_config: PseudoForgeConfig | None = None) -> str:
    provider = normalize_provider(config.provider)
    lines = [
        "Provider: %s (%s)" % (provider_label(provider), provider),
        "Model: %s" % config.model,
        "Timeout: %d seconds" % config.timeout_seconds,
    ]
    if provider in HTTP_PROVIDERS:
        lines.append("Base URL: %s" % config.base_url)
        api_key = get_provider_api_key(full_config, provider) if full_config is not None else ""
        lines.append("API key: %s" % masked_key(api_key))
    if provider in CLI_PROVIDERS:
        lines.append("Command: %s" % (config.command_template or "(not set)"))
    return "\n".join(lines)


def _safe_discover_models(
    provider: str,
    base_url: str = "",
    api_key: str = "",
    timeout_seconds: int = 15,
) -> ModelDiscoveryResult:
    try:
        return discover_provider_models(
            provider,
            base_url=base_url,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        return ModelDiscoveryResult(
            models=list(provider_model_options(provider)),
            source="static fallback",
            warning="model discovery failed: %s" % exc,
        )


def _model_options_for_dialog(
    provider: str,
    base_url: str = "",
    api_key: str = "",
    timeout_seconds: int = 15,
) -> ModelDiscoveryResult:
    normalized = normalize_provider(provider)
    key = _model_discovery_cache_key(normalized, base_url, api_key)
    with _MODEL_DISCOVERY_LOCK:
        cached = _MODEL_DISCOVERY_CACHE.get(key)
    if cached is not None:
        if cached.warning or cached.source.startswith("static fallback"):
            _start_model_discovery_refresh(
                normalized,
                key,
                base_url=base_url,
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
        return cached
    _start_model_discovery_refresh(
        normalized,
        key,
        base_url=base_url,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )
    return ModelDiscoveryResult(
        models=list(provider_model_options(normalized)),
        source="static fallback (background refresh pending)",
    )


def _start_model_discovery_refresh(
    provider: str,
    key: tuple[str, str, str],
    base_url: str = "",
    api_key: str = "",
    timeout_seconds: int = 15,
) -> bool:
    with _MODEL_DISCOVERY_LOCK:
        if key in _MODEL_DISCOVERY_INFLIGHT:
            return False
        _MODEL_DISCOVERY_INFLIGHT.add(key)

    def refresh() -> None:
        log_checkpoint("config.model_discovery.refresh.before", provider=provider)
        try:
            result = _safe_discover_models(
                provider,
                base_url=base_url,
                api_key=api_key,
                timeout_seconds=timeout_seconds,
            )
            with _MODEL_DISCOVERY_LOCK:
                _MODEL_DISCOVERY_CACHE[key] = result
            log_checkpoint(
                "config.model_discovery.refresh.after",
                provider=provider,
                source=result.source,
                models=len(result.models),
                warning=bool(result.warning),
            )
        finally:
            with _MODEL_DISCOVERY_LOCK:
                _MODEL_DISCOVERY_INFLIGHT.discard(key)

    thread = threading.Thread(
        target=refresh,
        name="PseudoForge-model-discovery-%s" % provider,
        daemon=True,
    )
    thread.start()
    return True


def _model_discovery_cache_key(provider: str, base_url: str, api_key: str) -> tuple[str, str, str]:
    key_hash = hashlib.sha256(api_key.encode("utf-8", errors="replace")).hexdigest() if api_key else ""
    return (
        normalize_provider(provider),
        str(base_url or "").rstrip("/"),
        key_hash,
    )


def _reset_model_discovery_cache_for_tests() -> None:
    with _MODEL_DISCOVERY_LOCK:
        _MODEL_DISCOVERY_CACHE.clear()
        _MODEL_DISCOVERY_INFLIGHT.clear()


def _current_or_default(current_value: str, default_value: str, provider_changed: bool) -> str:
    if provider_changed:
        return default_value
    return current_value or default_value
