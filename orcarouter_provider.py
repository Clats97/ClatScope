"""OrcaRouter Cyber Inference — named model provider for ClatScope Info Tool.

OrcaRouter (https://www.orcarouter.ai) is an OpenAI-compatible gateway that
routes many model vendors behind a single endpoint.  This module registers it
as a first-class, named provider next to the tool's built-in Perplexity path:

    display name : OrcaRouter Cyber Inference
    inference    : https://api.orcarouter.ai/v1  (chat completions, model list)
    auth origin  : https://www.orcarouter.ai     (key console, never used here)

The provider is aimed at security teams that do authorized, scoped security
work: the OrcaCyber models are released for gated security teams, and the same
endpoint carries OrcaRouter's gateway controls for defensive workflows.

Everything the tool needs lives here so the 16 AI call sites in
``ClatScope Info Tool (1.21).py`` share one request path:

* :func:`post_chat`   — the single dispatch seam; a pure passthrough to the
  original Perplexity call while OrcaRouter is not the selected provider.
* :func:`list_models` — live ``GET /v1/models`` discovery with per-capability
  filtering and a bounded, verified cold-start seed.
* :class:`CredentialStore` — the one credential seam.  Keys come from
  ``ORCAROUTER_API_KEY``, the in-source constant the tool already uses for
  provider keys, or a key typed at runtime.  Keys are never written to disk,
  never printed, and never placed in a URL.

Non-interactive use (also discoverable from ``--help``)::

    python3 -m orcarouter_provider status
    python3 -m orcarouter_provider models --capability chat
    python3 -m orcarouter_provider select --provider orcarouter --model orcarouter/auto
    python3 -m orcarouter_provider set-key      # reads the key from stdin
    python3 -m orcarouter_provider clear-key
    python3 -m orcarouter_provider chat --prompt "hello"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import requests

# --------------------------------------------------------------------------- #
# Provider identity
# --------------------------------------------------------------------------- #

PROVIDER_ID = "orcarouter"
PROVIDER_NAME = "OrcaRouter Cyber Inference"
PROVIDER_SUMMARY = (
    "Named security-inference provider for red and blue teams doing authorized, "
    "scoped work, served over OrcaRouter's OpenAI-compatible gateway."
)
PROVIDER_HOMEPAGE = "https://www.orcarouter.ai"
PROVIDER_DOCS = "https://docs.orcarouter.ai"
PROVIDER_CHAT_DOCS = "https://docs.orcarouter.ai/api-reference/chat/create-a-chat-completion"
PROVIDER_CYBER_DOCS = "https://docs.orcarouter.ai/getting-started/cyber-models"
PROVIDER_CYBER_PAGE = "https://www.orcarouter.ai/cyber"
PROVIDER_CYBER_MODELS = "https://www.orcarouter.ai/models?tier=cyber"
PROVIDER_CONSOLE_KEYS = "https://www.orcarouter.ai/console/token"

API_BASE_URL = "https://api.orcarouter.ai/v1"
AUTH_BASE_URL = "https://www.orcarouter.ai"

KEY_ENV_VAR = "ORCAROUTER_API_KEY"
KEY_PLACEHOLDER = "INSERT API KEY HERE"
KEY_PREFIX = "sk-orca-"

DEFAULT_MODEL = "orcarouter/auto"
FALLBACK_MODEL = "orcarouter/fusion"
CYBER_MODEL_IDS = ("orca/orcacyber-ultra-1.0", "orca/orcacyber-zero-1.5")

PROVIDER_ENV_VAR = "CLATSCOPE_AI_PROVIDER"
MODEL_ENV_VAR = "ORCAROUTER_MODEL"
CONFIG_ENV_VAR = "CLATSCOPE_CONFIG_FILE"

BUILTIN_PROVIDER = "perplexity"
SUPPORTED_PROVIDERS = (BUILTIN_PROVIDER, PROVIDER_ID)

#: Three-tier model guidance shown in docs, status output and the picker.
MODEL_TIERS = (
    {
        "tier": "default",
        "model": DEFAULT_MODEL,
        "label": "OrcaRouter automatic routing",
        "note": "Works with any OrcaRouter key; the gateway picks the route.",
    },
    {
        "tier": "cyber",
        "model": "orca/orcacyber-ultra-1.0",
        "label": "OrcaCyber Ultra 1.0",
        "note": "Large-codebase security scanning and multi-step security reasoning.",
    },
    {
        "tier": "cyber",
        "model": "orca/orcacyber-zero-1.5",
        "label": "OrcaCyber Zero 1.5",
        "note": "OrcaCyber harness model for long, multi-step security workflows.",
    },
    {
        "tier": "fallback",
        "model": FALLBACK_MODEL,
        "label": "OrcaRouter fusion fallback",
        "note": "General-purpose fallback route.",
    },
)

# --------------------------------------------------------------------------- #
# Catalog vocabulary
# --------------------------------------------------------------------------- #

CHAT_ENDPOINT_TYPES = frozenset({"openai", "anthropic", "gemini", "openai-response"})
NON_TEXT_ENDPOINT_TYPES = frozenset({"image-generation", "openai-video", "jina-rerank"})
CAPABILITY_ENDPOINT_TYPES = {
    "chat": CHAT_ENDPOINT_TYPES,
    "embedding": frozenset({"embeddings"}),
    "image": frozenset({"image-generation"}),
    "video": frozenset({"openai-video"}),
    "rerank": frozenset({"jina-rerank"}),
}
SUPPORTED_CAPABILITIES = tuple(CAPABILITY_ENDPOINT_TYPES)
MULTIMODAL_CAPABILITIES = frozenset({"image", "audio", "video"})

MODELS_PATH = "/models"
CHAT_PATH = "/chat/completions"

#: Verified cold-start seed, used only when live discovery is unavailable.
#: Metadata here is what has been verified; nothing is inferred from a name.
SEED_MODELS: tuple[dict[str, Any], ...] = (
    {
        "id": "orcarouter/auto",
        "name": "OrcaRouter Auto",
        "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"],
        "input_modalities": ["text"],
        "reasoning_efforts": [],
    },
    {
        "id": "openai/gpt-5.5",
        "name": "OpenAI: GPT-5.5",
        "supported_endpoint_types": ["openai", "openai-response"],
        "input_modalities": ["text"],
        "reasoning_efforts": ["low", "medium", "high", "xhigh"],
    },
    {
        "id": "anthropic/claude-opus-4.8",
        "name": "Anthropic: Claude Opus 4.8",
        "supported_endpoint_types": ["anthropic", "openai"],
        "input_modalities": ["text"],
        "reasoning_efforts": [],
    },
    {
        "id": "google/gemini-3.5-flash",
        "name": "Google: Gemini 3.5 Flash",
        "supported_endpoint_types": ["gemini", "openai"],
        "input_modalities": ["text"],
        "reasoning_efforts": [],
    },
    {
        "id": "deepseek/deepseek-v4-pro",
        "name": "DeepSeek: DeepSeek V4 Pro",
        "supported_endpoint_types": ["openai", "openai-response"],
        "input_modalities": ["text"],
        "reasoning_efforts": [],
    },
)

CACHE_TTL_SECONDS = 300.0
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CATALOG_ITEMS = 500


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class OrcaRouterError(Exception):
    """Base class for provider errors that carry a user-facing message."""


class CredentialError(OrcaRouterError):
    """No usable OrcaRouter API key, or the key was rejected (terminal)."""


class CatalogError(OrcaRouterError):
    """Model discovery failed (network, HTTP status, malformed payload)."""


# --------------------------------------------------------------------------- #
# Secret handling
# --------------------------------------------------------------------------- #

_SECRET_RE = re.compile(r"sk-orca-[A-Za-z0-9._\-]+")


def mask_key(key: str | None) -> str:
    """Return a display-safe form of ``key``; never the key itself."""
    if not key:
        return "(none)"
    key = key.strip()
    if len(key) <= 12:
        return "sk-orca-…" if key.startswith("sk-orca-") else "…"
    return f"{key[:8]}…{key[-4:]}"


def redact(text: Any) -> str:
    """Mask every ``sk-orca-…`` token in ``text`` before it is printed."""
    if text is None:
        return ""
    return _SECRET_RE.sub(lambda m: mask_key(m.group(0)), str(text))


def looks_like_api_key(key: str | None) -> bool:
    """Lightweight format check only — the prefix is not proof of validity."""
    return bool(key) and key.strip().startswith(KEY_PREFIX) and len(key.strip()) > len(KEY_PREFIX)


# --------------------------------------------------------------------------- #
# Credential seam
# --------------------------------------------------------------------------- #


class CredentialSource:
    """A place a key can come from.  Read-only and side-effect free."""

    name = "source"

    def read(self) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError


class EnvVarCredentialSource(CredentialSource):
    name = "env"

    def __init__(self, env_var: str = KEY_ENV_VAR) -> None:
        self.env_var = env_var

    def read(self) -> str | None:
        return os.environ.get(self.env_var, "").strip() or None


class StaticConstantCredentialSource(CredentialSource):
    """Mirrors the in-source ``PASSWORD = "INSERT API KEY HERE"`` idiom."""

    name = "config-file-constant"

    def __init__(self, value: str | None = None) -> None:
        self.value = value

    def read(self) -> str | None:
        value = (self.value or "").strip()
        if not value or value == KEY_PLACEHOLDER:
            return None
        return value


class SessionCredentialSource(CredentialSource):
    """A key typed by the user at runtime; lives in memory for this process."""

    name = "session"

    def __init__(self) -> None:
        self.value: str | None = None

    def read(self) -> str | None:
        return self.value

    def write(self, value: str | None) -> None:
        self.value = value


@dataclass(frozen=True)
class Credential:
    """A resolved key plus the generation it belongs to."""

    value: str
    source: str
    generation: int

    def __repr__(self) -> str:  # keep the secret out of logs and tracebacks
        return f"Credential(source={self.source!r}, generation={self.generation}, key={mask_key(self.value)})"

    __str__ = __repr__


class CredentialStore:
    """The single credential seam for OrcaRouter.

    Precedence: runtime session key → ``ORCAROUTER_API_KEY`` → in-source
    constant.  A cleared store stays cleared until a new key is supplied, so
    "Clear API key" cannot silently fall back to a stale environment value.

    A rejected key is marked ``needs_reauth`` for the exact generation that
    made the failing request; a late 401 from an older generation can never
    poison a key the user has since replaced.
    """

    def __init__(self, session: SessionCredentialSource | None = None) -> None:
        self.session = session or SessionCredentialSource()
        self.env = EnvVarCredentialSource()
        self.static = StaticConstantCredentialSource()
        self.generation = 0
        self._cleared = False
        self._needs_reauth: set[int] = set()

    # -- resolution ------------------------------------------------------- #
    def resolve(self) -> Credential | None:
        if self._cleared:
            return None
        for source in (self.session, self.env, self.static):
            value = source.read()
            if not value or value == KEY_PLACEHOLDER:
                continue
            if self.generation in self._needs_reauth:
                return None
            return Credential(value=value, source=source.name, generation=self.generation)
        return None

    def is_configured(self) -> bool:
        return self.resolve() is not None

    # -- mutation --------------------------------------------------------- #
    def set_api_key(self, key: str | None, *, source: str = "session") -> Credential | None:
        value = (key or "").strip()
        if not value:
            self.clear()
            return None
        if not looks_like_api_key(value):
            raise CredentialError(
                "That does not look like an OrcaRouter API key. Keys start with "
                f"'{KEY_PREFIX}' and can be created at {PROVIDER_CONSOLE_KEYS}."
            )
        self.session.write(value)
        self.generation += 1
        self._cleared = False
        self._needs_reauth.discard(self.generation)
        return Credential(value=value, source=source, generation=self.generation)

    def clear(self) -> None:
        self.session.write(None)
        self.generation += 1
        self._cleared = True

    def reset(self) -> None:
        """Forget session state (used by tests and by provider switches)."""
        self.session.write(None)
        self.generation += 1
        self._cleared = False
        self._needs_reauth.clear()

    # -- terminal auth failure ------------------------------------------- #
    def note_auth_failure(self, credential: Credential | None) -> bool:
        """Mark exactly the generation that was rejected.  Returns True if applied."""
        if credential is None:
            return False
        if credential.generation != self.generation:
            return False  # stale failure from a superseded credential
        self._needs_reauth.add(credential.generation)
        return True

    def needs_reauth(self) -> bool:
        return self.generation in self._needs_reauth

    def status(self) -> dict[str, Any]:
        credential = self.resolve()
        return {
            "configured": credential is not None,
            "source": credential.source if credential else None,
            "masked": mask_key(credential.value) if credential else None,
            "needs_reauth": self.needs_reauth(),
            "generation": self.generation,
            "env_var": KEY_ENV_VAR,
            "console": PROVIDER_CONSOLE_KEYS,
        }


_store = CredentialStore()


def credential_store() -> CredentialStore:
    return _store


def set_static_api_key(value: str | None) -> None:
    """Called once by the tool with its in-source ``ORCAROUTER_API_KEY`` constant."""
    _store.static.value = value


def get_credential() -> Credential | None:
    return _store.resolve()


def require_credential() -> Credential:
    credential = _store.resolve()
    if credential is not None:
        return credential
    if _store.needs_reauth():
        raise CredentialError(
            "OrcaRouter rejected the stored API key (HTTP 401). Create or copy a key at "
            f"{PROVIDER_CONSOLE_KEYS}, then update it from Settings → AI Provider or with "
            f"`python3 -m orcarouter_provider set-key`. Nothing was retried automatically."
        )
    raise CredentialError(
        "OrcaRouter Cyber Inference is selected but no API key is configured. Set "
        f"{KEY_ENV_VAR}, edit the ORCAROUTER_API_KEY constant in the script, or run "
        "`python3 -m orcarouter_provider set-key`."
    )


def set_api_key(key: str | None) -> Credential | None:
    return _store.set_api_key(key)


def clear_api_key() -> None:
    _store.clear()


def credential_status() -> dict[str, Any]:
    return _store.status()


def is_configured() -> bool:
    return _store.is_configured()


# --------------------------------------------------------------------------- #
# Provider selection (non-secret, persisted separately from any key)
# --------------------------------------------------------------------------- #


def config_path() -> Path:
    override = os.environ.get(CONFIG_ENV_VAR, "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".clatscope" / "ai_provider.json"


def load_selection() -> dict[str, str]:
    path = config_path()
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {
                    "provider": str(data.get("provider") or ""),
                    "model": str(data.get("model") or ""),
                }
    except (OSError, ValueError):
        pass
    return {}


def save_selection(*, provider: str | None = None, model: str | None = None) -> dict[str, str]:
    """Persist non-secret selection only.  API keys are never written here."""
    data = load_selection()
    if provider is not None:
        data["provider"] = provider
    if model is not None:
        data["model"] = model
    path = config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass  # a read-only home must not break the tool
    return data


def active_provider() -> str:
    env = os.environ.get(PROVIDER_ENV_VAR, "").strip().lower()
    if env in SUPPORTED_PROVIDERS:
        return env
    stored = load_selection().get("provider", "").strip().lower()
    if stored in SUPPORTED_PROVIDERS:
        return stored
    return BUILTIN_PROVIDER


def is_active() -> bool:
    return active_provider() == PROVIDER_ID


def set_active_provider(name: str, *, persist: bool = True) -> str:
    normalized = (name or "").strip().lower()
    if normalized not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unknown AI provider {name!r}; expected one of {SUPPORTED_PROVIDERS}")
    if persist:
        save_selection(provider=normalized)
    return normalized


def active_model() -> str:
    env = os.environ.get(MODEL_ENV_VAR, "").strip()
    if env:
        return env
    stored = load_selection().get("model", "").strip()
    return stored or DEFAULT_MODEL


def set_active_model(model: str, *, persist: bool = True) -> str:
    value = (model or "").strip()
    if not value:
        raise ValueError("Model id must not be empty")
    if persist:
        save_selection(model=value)
    return value


def active_display_name() -> str:
    return PROVIDER_NAME if is_active() else "Perplexity"


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


def api_base_url() -> str:
    return (os.environ.get("ORCAROUTER_API_BASE_URL", "").strip() or API_BASE_URL).rstrip("/")


def auth_base_url() -> str:
    return (os.environ.get("ORCAROUTER_AUTH_BASE_URL", "").strip() or AUTH_BASE_URL).rstrip("/")


def models_url(capability: str | None = "chat") -> str:
    url = api_base_url() + MODELS_PATH
    if capability in ("chat", "embedding", "image"):
        url += f"?capability={capability}"
    return url


def chat_completions_url() -> str:
    return api_base_url() + CHAT_PATH


def _timeout_seconds() -> float:
    raw = os.environ.get("ORCAROUTER_TIMEOUT", "").strip()
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_TIMEOUT_SECONDS


def _auth_headers(credential: Credential) -> dict[str, str]:
    return {"Authorization": f"Bearer {credential.value}", "Content-Type": "application/json"}


# --------------------------------------------------------------------------- #
# Model catalog
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CatalogModel:
    id: str
    name: str = ""
    context_length: int | None = None
    max_completion_tokens: int | None = None
    endpoint_types: tuple[str, ...] = ()
    input_modalities: tuple[str, ...] = ()
    output_modalities: tuple[str, ...] = ()
    reasoning_efforts: tuple[str, ...] = ()
    supports_reasoning: bool = False
    description: str = ""
    source: str = "live"

    def supports_capability(self, capability: str = "chat") -> bool:
        types = set(self.endpoint_types)
        if capability == "chat":
            return bool(types & CHAT_ENDPOINT_TYPES) and not (types & NON_TEXT_ENDPOINT_TYPES)
        wanted = CAPABILITY_ENDPOINT_TYPES.get(capability)
        if not wanted:
            return False
        return bool(types & wanted)

    def accepts_modality(self, modality: str | None) -> bool:
        """Fail closed: an undeclared modality never matches."""
        if not modality:
            return True
        return modality in self.input_modalities


@dataclass(frozen=True)
class CatalogResult:
    models: tuple[CatalogModel, ...]
    source: str  # "live" | "last-known-good" | "verified-seed" | "none"
    degraded: bool
    error: str | None = None
    fetched_at: float = field(default_factory=time.time)

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(m.id for m in self.models)

    def describe(self) -> str:
        if self.source == "live":
            return f"{len(self.models)} model(s) from the live OrcaRouter catalog"
        if self.source in ("last-known-good", "verified-seed"):
            return (
                f"{len(self.models)} model(s) from the {self.source} fallback "
                f"(live discovery unavailable: {self.error})"
            )
        return "no compatible models"


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item) for item in value if isinstance(item, (str, int, float)))


def _modalities_from_architecture(architecture: Mapping[str, Any]) -> tuple[str, ...]:
    declared = _as_str_tuple(architecture.get("input_modalities"))
    if declared:
        return tuple(item.strip().lower() for item in declared if item)
    legacy = architecture.get("modality")
    if isinstance(legacy, str) and "->" in legacy:
        left = legacy.split("->", 1)[0]
        parts = [p.strip().lower() for p in left.split("+")]
        return tuple(p for p in parts if p)
    return ()


def parse_model(item: Mapping[str, Any], *, source: str = "live") -> CatalogModel | None:
    """Parse one catalog record, bounded and shape-checked."""
    if not isinstance(item, Mapping):
        return None
    model_id = item.get("id")
    if not isinstance(model_id, str) or not model_id.strip():
        return None
    model_id = model_id.strip()

    architecture = item.get("architecture")
    architecture = architecture if isinstance(architecture, Mapping) else {}

    endpoint_types = _as_str_tuple(item.get("supported_endpoint_types"))
    if not endpoint_types:
        endpoint_types = _as_str_tuple(item.get("endpoint_capabilities"))

    context_length = item.get("context_length")
    max_completion = item.get("max_completion_tokens")
    supported_parameters = _as_str_tuple(item.get("supported_parameters"))

    return CatalogModel(
        id=model_id,
        name=str(item.get("name") or model_id),
        context_length=int(context_length) if isinstance(context_length, (int, float)) else None,
        max_completion_tokens=int(max_completion) if isinstance(max_completion, (int, float)) else None,
        endpoint_types=endpoint_types,
        input_modalities=_modalities_from_architecture(architecture),
        output_modalities=_as_str_tuple(architecture.get("output_modalities")),
        supports_reasoning="reasoning" in supported_parameters or "reasoning_effort" in supported_parameters,
        description=str(item.get("description") or "")[:400],
        source=source,
    )


def seed_models() -> tuple[CatalogModel, ...]:
    return tuple(
        CatalogModel(
            id=entry["id"],
            name=entry.get("name", entry["id"]),
            endpoint_types=tuple(entry.get("supported_endpoint_types", ())),
            input_modalities=tuple(entry.get("input_modalities", ())),
            reasoning_efforts=tuple(entry.get("reasoning_efforts", ())),
            supports_reasoning=bool(entry.get("reasoning_efforts")),
            source="verified-seed",
        )
        for entry in SEED_MODELS
    )


def filter_models(
    models: Iterable[CatalogModel],
    capability: str = "chat",
    modality: str | None = None,
) -> tuple[CatalogModel, ...]:
    """Filter by endpoint capability first, then by declared input modality."""
    if capability not in CAPABILITY_ENDPOINT_TYPES:
        raise ValueError(f"Unsupported capability {capability!r}")
    selected = [
        model
        for model in models
        if model.supports_capability(capability) and model.accepts_modality(modality)
    ]
    return tuple(selected)


def _display_rank(model: CatalogModel) -> tuple[int, str]:
    if model.id == DEFAULT_MODEL:
        return (0, model.id)
    if model.id in CYBER_MODEL_IDS:
        return (1, model.id)
    if model.id == FALLBACK_MODEL:
        return (2, model.id)
    return (3, model.id)


def ordered_models(models: Iterable[CatalogModel]) -> tuple[CatalogModel, ...]:
    """Default route first, then cyber models, then the fallback, then the rest."""
    return tuple(sorted(models, key=_display_rank))


def _read_bounded(response: requests.Response, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > limit:
            raise CatalogError(f"catalog response exceeded {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_live_catalog(capability: str = "chat", *, timeout: float | None = None) -> tuple[CatalogModel, ...]:
    """GET {api_base}/models with the user's key.  Raises on any failure."""
    credential = require_credential()
    url = models_url(capability)
    try:
        response = requests.get(url, headers=_auth_headers(credential), timeout=timeout or _timeout_seconds(), stream=True)
    except requests.RequestException as exc:
        raise CatalogError(f"model discovery network error: {type(exc).__name__}") from None

    try:
        status = response.status_code
        if status == 401:
            _store.note_auth_failure(credential)
            raise CredentialError(
                "OrcaRouter rejected the API key while listing models (HTTP 401). "
                f"Issue a new key at {PROVIDER_CONSOLE_KEYS} and update it; no automatic retry was attempted."
            )
        if status == 403:
            raise CatalogError("model discovery refused for this key (HTTP 403)")
        if status == 429:
            raise CatalogError("model discovery rate-limited (HTTP 429)")
        if status != 200:
            raise CatalogError(f"model discovery failed with HTTP {status}")

        body = _read_bounded(response)
    finally:
        response.close()

    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise CatalogError("model discovery returned malformed JSON") from None

    if isinstance(payload, Mapping):
        raw_items = payload.get("data")
    else:
        raw_items = payload
    if not isinstance(raw_items, list):
        raise CatalogError("model discovery payload has no model list")

    models: list[CatalogModel] = []
    for item in raw_items[:MAX_CATALOG_ITEMS]:
        parsed = parse_model(item)
        if parsed is not None:
            models.append(parsed)
    return tuple(models)


_cache: dict[str, tuple[tuple[CatalogModel, ...], float]] = {}
_last_known_good: tuple[CatalogModel, ...] = ()


def reset_cache() -> None:
    global _last_known_good
    _cache.clear()
    _last_known_good = ()


def list_models(
    capability: str = "chat",
    modality: str | None = None,
    *,
    refresh: bool = False,
) -> CatalogResult:
    """Compatible models for one capability.

    Live discovery is authoritative.  When it fails, a previously successful
    response (last-known-good) or the verified seed is used, flagged degraded.
    The seed is never mixed into a successful live result.
    """
    global _last_known_good

    now = time.time()
    cached = _cache.get(capability)
    if not refresh and cached and now - cached[1] < CACHE_TTL_SECONDS:
        return CatalogResult(
            models=ordered_models(filter_models(cached[0], capability, modality)),
            source="live",
            degraded=False,
        )

    try:
        live = fetch_live_catalog(capability)
    except (CatalogError, CredentialError) as exc:
        for candidate, source in ((_last_known_good, "last-known-good"), (seed_models(), "verified-seed")):
            if not candidate:
                continue
            compatible = filter_models(candidate, capability, modality)
            if compatible:
                return CatalogResult(
                    models=ordered_models(compatible),
                    source=source,
                    degraded=True,
                    error=redact(exc),
                )
        return CatalogResult(models=(), source="none", degraded=True, error=redact(exc))

    _cache[capability] = (live, now)
    _last_known_good = live
    return CatalogResult(
        models=ordered_models(filter_models(live, capability, modality)),
        source="live",
        degraded=False,
    )


def find_model(model_id: str, models: Iterable[CatalogModel]) -> CatalogModel | None:
    for model in models:
        if model.id == model_id:
            return model
    return None


def reconcile_active_model(models: Iterable[CatalogModel]) -> tuple[str, bool]:
    """Drop a stored model that is no longer compatible with the live catalog.

    Returns ``(model_id, changed)``.  Nothing is reset when the catalog is empty
    (that means discovery failed, not that the model disappeared).
    """
    models = tuple(models)
    if not models:
        return active_model(), False
    current = active_model()
    if find_model(current, models) is not None:
        return current, False
    set_active_model(DEFAULT_MODEL)
    return DEFAULT_MODEL, True


# --------------------------------------------------------------------------- #
# Inference seam
# --------------------------------------------------------------------------- #


def build_chat_payload(payload: Mapping[str, Any], model: str | None = None) -> dict[str, Any]:
    """Copy the caller's payload and point it at the selected OrcaRouter model."""
    out = dict(payload)
    out["model"] = model or active_model()
    return out


def post_chat(
    url: str,
    headers: Mapping[str, str] | None = None,
    json: Mapping[str, Any] | None = None,
    stream: bool = False,
    timeout: float | None = None,
) -> requests.Response:
    """Send one chat request through the selected provider.

    While OrcaRouter is not selected this is a pure passthrough to the original
    call, so the built-in Perplexity behaviour is unchanged.
    """
    if not is_active():
        return requests.post(url, headers=headers, json=json, stream=stream, timeout=timeout)

    credential = require_credential()
    body = build_chat_payload(json or {})
    response = requests.post(
        chat_completions_url(),
        headers=_auth_headers(credential),
        json=body,
        stream=stream,
        timeout=timeout,
    )
    if response.status_code == 401:
        if _store.note_auth_failure(credential):
            print(
                rf"[!] > OrcaRouter rejected this API key (HTTP 401). Create a new key at "
                f"{PROVIDER_CONSOLE_KEYS}, then update it in Settings → AI Provider "
                "(automatic retry is disabled for a revoked key).",
                file=sys.stderr,
            )
    return response


# --------------------------------------------------------------------------- #
# Presentation helpers (used by the tool's menus and CLI)
# --------------------------------------------------------------------------- #


def provider_registry_entry() -> dict[str, Any]:
    """The one place the provider is described for menus, docs and status."""
    return {
        "id": PROVIDER_ID,
        "name": PROVIDER_NAME,
        "summary": PROVIDER_SUMMARY,
        "api_base_url": API_BASE_URL,
        "auth_base_url": AUTH_BASE_URL,
        "env_var": KEY_ENV_VAR,
        "key_console": PROVIDER_CONSOLE_KEYS,
        "docs": PROVIDER_HOMEPAGE,
        "api_docs": PROVIDER_CHAT_DOCS,
        "cyber_docs": PROVIDER_CYBER_DOCS,
        "cyber_page": PROVIDER_CYBER_PAGE,
        "cyber_models": PROVIDER_CYBER_MODELS,
        "default_model": DEFAULT_MODEL,
        "fallback_model": FALLBACK_MODEL,
        "cyber_models_ids": CYBER_MODEL_IDS,
    }


def catalog_line(model: CatalogModel) -> str:
    bits = [model.id]
    if model.context_length:
        bits.append(f"{model.context_length:,} ctx")
    if model.input_modalities and model.input_modalities != ("text",):
        bits.append("in: " + "+".join(model.input_modalities))
    if model.reasoning_efforts:
        bits.append("reasoning: " + "/".join(model.reasoning_efforts))
    elif model.supports_reasoning:
        bits.append("reasoning")
    return "  ".join(bits)


def status_lines() -> list[str]:
    entry = provider_registry_entry()
    status = credential_status()
    lines = [
        f"Provider        : {entry['name']} ({entry['id']})",
        f"Selected        : {active_provider()}" + ("  <- active for AI calls" if is_active() else ""),
        f"API base        : {entry['api_base_url']}",
        f"Model           : {active_model()}",
        f"API key         : {status['masked']}  [{status['source'] or 'not configured'}]",
        f"Needs re-auth   : {'yes' if status['needs_reauth'] else 'no'}",
        f"Key console     : {entry['key_console']}",
        f"Cyber provider  : {entry['cyber_page']}",
        f"Cyber models    : {entry['cyber_models']}",
        f"Docs            : {entry['api_docs']}",
    ]
    return lines


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _cmd_status(args: argparse.Namespace) -> int:
    for line in status_lines():
        print(line)
    if is_active():
        try:
            result = list_models("chat", refresh=args.refresh)
            print(f"Catalog         : {result.describe()}")
        except OrcaRouterError as exc:
            print(f"Catalog         : unavailable ({redact(exc)})")
    return 0


def _cmd_models(args: argparse.Namespace) -> int:
    result = list_models(args.capability, args.modality, refresh=args.refresh)
    if not result.models:
        print(f"No compatible models ({result.source}): {result.error or 'catalog is empty'}")
        return 1
    print(f"{result.describe()}")
    for model in result.models:
        print("  " + catalog_line(model))
    if args.json:
        print(json.dumps([m.__dict__ for m in result.models], indent=2, default=str))
    return 0


def _cmd_chat(args: argparse.Namespace) -> int:
    model = args.model or active_model()
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": args.prompt}],
        "stream": not args.no_stream,
        "max_tokens": args.max_tokens,
    }
    # Route through the same seam the tool's own features use.
    response = post_chat("https://api.perplexity.ai/chat/completions", json=payload, stream=not args.no_stream)
    if response.status_code != 200:
        print(f"HTTP {response.status_code}: {redact(response.text)[:400]}", file=sys.stderr)
        return 1
    if args.no_stream:
        data = response.json()
        print(data["choices"][0]["message"].get("content", ""))
        return 0
    for line in response.iter_lines():
        if not line:
            continue
        text = line.decode("utf-8", "replace").strip()
        if not text.startswith("data:"):
            continue
        text = text[5:].strip()
        if text == "[DONE]":
            break
        try:
            chunk = json.loads(text)
        except ValueError:
            continue
        delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content") or ""
        if delta:
            print(delta, end="", flush=True)
    print()
    return 0


def _cmd_select(args: argparse.Namespace) -> int:
    provider = set_active_provider(args.provider) if args.provider else active_provider()
    model = active_model()
    if args.model:
        result = list_models("chat")
        if result.degraded:
            print(
                f"[!] Cannot verify {args.model}: live catalog unavailable ({result.error}). "
                "Nothing was changed.",
                file=sys.stderr,
            )
            return 2
        if find_model(args.model, result.models) is None:
            print(f"[!] {args.model} is not in the current OrcaRouter chat catalog; nothing was changed.", file=sys.stderr)
            return 2
        model = set_active_model(args.model)
    print(f"provider={provider} model={model}")
    print(f"saved to {config_path()}")
    return 0


def _cmd_set_key(args: argparse.Namespace) -> int:
    print("Paste the OrcaRouter API key (input is not echoed, never stored on disk):", file=sys.stderr)
    key = sys.stdin.readline().strip()
    credential = set_api_key(key)
    if credential is None:
        print("No key entered; nothing changed.")
        return 1
    print(f"Stored in memory for this process: {mask_key(credential.value)} (source: {credential.source})")
    return 0


def _cmd_clear_key(args: argparse.Namespace) -> int:
    clear_api_key()
    print(
        "Cleared the OrcaRouter API key for this process. If it comes from "
        f"{KEY_ENV_VAR}, unset it in your shell to remove it entirely."
    )
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    entry = provider_registry_entry()
    print(f"{entry['name']} — {entry['summary']}")
    print(f"  API base      : {entry['api_base_url']}")
    print(f"  Docs          : {entry['docs']}")
    print(f"  API reference : {entry['api_docs']}")
    print(f"  Cyber docs    : {entry['cyber_docs']}")
    print(f"  Cyber         : {entry['cyber_page']}")
    print(f"  Cyber models  : {entry['cyber_models']}")
    print("  Model guidance:")
    for tier in MODEL_TIERS:
        print(f"    [{tier['tier']}] {tier['model']:<28} {tier['label']} — {tier['note']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m orcarouter_provider",
        description="OrcaRouter Cyber Inference provider for ClatScope Info Tool.",
    )
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="show provider, credential and catalog status")
    p_status.add_argument("--refresh", action="store_true", help="bypass the catalog cache")
    p_status.set_defaults(func=_cmd_status)

    p_models = sub.add_parser("models", help="list compatible models from the live catalog")
    p_models.add_argument("--capability", default="chat", choices=SUPPORTED_CAPABILITIES)
    p_models.add_argument("--modality", default=None, help="require a declared input modality")
    p_models.add_argument("--refresh", action="store_true")
    p_models.add_argument("--json", action="store_true")
    p_models.set_defaults(func=_cmd_models)

    p_chat = sub.add_parser("chat", help="send one prompt through the provider seam")
    p_chat.add_argument("--prompt", required=True)
    p_chat.add_argument("--model", default=None)
    p_chat.add_argument("--max-tokens", type=int, default=256)
    p_chat.add_argument("--no-stream", action="store_true")
    p_chat.set_defaults(func=_cmd_chat)

    p_select = sub.add_parser("select", help="choose the AI provider and model")
    p_select.add_argument("--provider", choices=SUPPORTED_PROVIDERS)
    p_select.add_argument("--model")
    p_select.set_defaults(func=_cmd_select)

    p_set = sub.add_parser("set-key", help="read an API key from stdin (memory only)")
    p_set.set_defaults(func=_cmd_set_key)

    p_clear = sub.add_parser("clear-key", help="forget the API key for this process")
    p_clear.set_defaults(func=_cmd_clear_key)

    p_info = sub.add_parser("info", help="provider description, links and model guidance")
    p_info.set_defaults(func=_cmd_info)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args))
    except OrcaRouterError as exc:
        print(f"[!] {redact(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
