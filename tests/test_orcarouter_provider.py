"""Tests for the OrcaRouter Cyber Inference provider.

No test needs a real key except the ``live_`` ones, which skip themselves when
``ORCAROUTER_API_KEY`` is absent.  Every fake key is obviously fake.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import orcarouter_provider as orp  # noqa: E402

MAIN_SCRIPT = ROOT / "ClatScope Info Tool (1.21).py"

FAKE_KEY = "sk-orca-test-0000000000000000"
SECOND_FAKE_KEY = "sk-orca-test-1111111111111111"
LIVE_KEY = os.environ.get("ORCAROUTER_API_KEY", "").strip()
LIVE_MODEL = os.environ.get("ORCAROUTER_LIVE_MODEL", "deepseek/deepseek-v4.1-flash")

# Shape mirrors a real https://api.orcarouter.ai/v1/models response (2026-10-23).
CATALOG_FIXTURE = {
    "object": "list",
    "success": True,
    "data": [
        {
            "id": "orcarouter/auto",
            "object": "model",
            "owned_by": "orcarouter",
            "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"],
        },
        {
            "id": "orca/orcacyber-ultra-1.0",
            "object": "model",
            "name": "Orca: OrcaCyber Ultra 1.0",
            "context_length": 1048576,
            "max_completion_tokens": 131072,
            "supported_endpoint_types": ["openai"],
            "endpoint_capabilities": ["chat_completions"],
            "architecture": {"modality": "text->text", "input_modalities": ["text"], "output_modalities": ["text"]},
            "supported_parameters": ["max_tokens", "reasoning", "stream", "tools"],
        },
        {
            "id": "deepseek/deepseek-v4.1-flash",
            "object": "model",
            "name": "DeepSeek: DeepSeek V4.1 Flash",
            "context_length": 1048576,
            "supported_endpoint_types": ["openai", "openai-response"],
            "architecture": {"modality": "text+image->text", "input_modalities": ["text", "image"], "output_modalities": ["text"]},
        },
        {
            "id": "vendor/text-only-chat",
            "supported_endpoint_types": ["openai"],
            "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]},
        },
        {
            "id": "vendor/no-architecture-chat",
            "supported_endpoint_types": ["openai"],
        },
        {
            "id": "vendor/embed-1",
            "supported_endpoint_types": ["embeddings"],
            "architecture": {"input_modalities": ["text"], "output_modalities": ["embedding"]},
        },
        {
            "id": "vendor/image-gen-1",
            "supported_endpoint_types": ["image-generation"],
            "architecture": {"input_modalities": ["text"], "output_modalities": ["image"]},
        },
        {
            "id": "vendor/video-1",
            "supported_endpoint_types": ["openai-video"],
            "architecture": {"input_modalities": ["text"], "output_modalities": ["video"]},
        },
        {
            "id": "vendor/rerank-1",
            "supported_endpoint_types": ["jina-rerank"],
            "architecture": {"input_modalities": ["text"], "output_modalities": ["score"]},
        },
        {"name": "record without an id"},
        "not-a-record",
    ],
}


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="", raw=None):
        self.status_code = status_code
        self.text = text
        self._raw = raw if raw is not None else json.dumps(payload or {}).encode("utf-8")
        self.closed = False

    def iter_content(self, chunk_size=8192):
        for start in range(0, len(self._raw), chunk_size):
            yield self._raw[start:start + chunk_size]

    def iter_lines(self):
        for line in self._raw.splitlines():
            yield line

    def json(self):
        return json.loads(self._raw)

    def close(self):
        self.closed = True

    def raise_for_status(self):
        if self.status_code >= 400:
            raise orp.requests.HTTPError(f"HTTP {self.status_code}")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv(orp.CONFIG_ENV_VAR, str(tmp_path / "ai_provider.json"))
    monkeypatch.delenv(orp.PROVIDER_ENV_VAR, raising=False)
    monkeypatch.delenv(orp.MODEL_ENV_VAR, raising=False)
    monkeypatch.delenv(orp.KEY_ENV_VAR, raising=False)
    monkeypatch.delenv("ORCAROUTER_API_BASE_URL", raising=False)
    monkeypatch.delenv("ORCAROUTER_AUTH_BASE_URL", raising=False)
    orp.credential_store().reset()
    orp.credential_store().static.value = None
    orp.reset_cache()
    yield
    orp.credential_store().reset()
    orp.credential_store().static.value = None
    orp.reset_cache()


def install_catalog(monkeypatch, payload=None, status=200, raw=None, record=None):
    def fake_get(url, headers=None, timeout=None, stream=False):
        if record is not None:
            record.append({"url": url, "headers": dict(headers or {}), "timeout": timeout})
        return FakeResponse(status_code=status, payload=payload, raw=raw)

    monkeypatch.setattr(orp.requests, "get", fake_get)


def install_post(monkeypatch, response=None, record=None):
    def fake_post(url, headers=None, json=None, stream=False, timeout=None):
        if record is not None:
            record.append({"url": url, "headers": dict(headers or {}), "json": json, "stream": stream, "timeout": timeout})
        return response if response is not None else FakeResponse()

    monkeypatch.setattr(orp.requests, "post", fake_post)


# --------------------------------------------------------------------------- #
# Provider registration
# --------------------------------------------------------------------------- #


def test_provider_is_named_and_points_at_orcarouter():
    entry = orp.provider_registry_entry()
    assert entry["id"] == "orcarouter"
    assert entry["name"] == "OrcaRouter Cyber Inference"
    assert entry["api_base_url"] == "https://api.orcarouter.ai/v1"
    assert entry["auth_base_url"] == "https://www.orcarouter.ai"
    assert entry["env_var"] == "ORCAROUTER_API_KEY"
    assert entry["default_model"] == "orcarouter/auto"
    assert entry["fallback_model"] == "orcarouter/fusion"
    assert "orca/orcacyber-ultra-1.0" in entry["cyber_models_ids"]
    assert "orca/orcacyber-zero-1.5" in entry["cyber_models_ids"]
    assert entry["cyber_page"] == "https://www.orcarouter.ai/cyber"
    assert entry["cyber_models"] == "https://www.orcarouter.ai/models?tier=cyber"
    assert entry["api_docs"] == "https://docs.orcarouter.ai/api-reference/chat/create-a-chat-completion"
    assert entry["cyber_docs"] == "https://docs.orcarouter.ai/getting-started/cyber-models"
    assert orp.KEY_PREFIX == "sk-orca-"


def test_model_guidance_order_is_default_cyber_fallback():
    tiers = [tier["tier"] for tier in orp.MODEL_TIERS]
    assert tiers == ["default", "cyber", "cyber", "fallback"]
    assert orp.MODEL_TIERS[0]["model"] == orp.DEFAULT_MODEL
    assert orp.MODEL_TIERS[-1]["model"] == orp.FALLBACK_MODEL


def test_origins_are_distinct_and_never_derived_from_each_other():
    assert orp.api_base_url() == "https://api.orcarouter.ai/v1"
    assert orp.auth_base_url() == "https://www.orcarouter.ai"
    assert "/v1/auth" not in orp.auth_base_url()
    assert orp.models_url("chat") == "https://api.orcarouter.ai/v1/models?capability=chat"
    assert orp.chat_completions_url() == "https://api.orcarouter.ai/v1/chat/completions"


def test_explicit_origin_overrides_win(monkeypatch):
    monkeypatch.setenv("ORCAROUTER_API_BASE_URL", "https://relay.internal.example/v1")
    monkeypatch.setenv("ORCAROUTER_AUTH_BASE_URL", "https://sso.internal.example")
    assert orp.api_base_url() == "https://relay.internal.example/v1"
    assert orp.auth_base_url() == "https://sso.internal.example"
    assert "auth" not in orp.models_url("chat").split("//", 1)[1]


# --------------------------------------------------------------------------- #
# API key credential seam
# --------------------------------------------------------------------------- #


def test_env_key_is_resolved_and_masked(monkeypatch):
    monkeypatch.setenv(orp.KEY_ENV_VAR, FAKE_KEY)
    credential = orp.get_credential()
    assert credential is not None and credential.source == "env"
    status = orp.credential_status()
    assert status["configured"] is True
    assert status["masked"] == orp.mask_key(FAKE_KEY)
    assert FAKE_KEY not in json.dumps(status)


def test_placeholder_constant_is_not_a_credential():
    orp.set_static_api_key(orp.KEY_PLACEHOLDER)
    assert orp.get_credential() is None
    assert orp.is_configured() is False


def test_static_constant_key_is_used_when_nothing_else_is_set():
    orp.set_static_api_key(FAKE_KEY)
    credential = orp.get_credential()
    assert credential is not None
    assert credential.value == FAKE_KEY
    assert credential.source == "config-file-constant"


def test_set_update_and_clear_api_key():
    first = orp.set_api_key(FAKE_KEY)
    assert first is not None and first.source == "session"
    assert orp.credential_status()["masked"] == orp.mask_key(FAKE_KEY)

    second = orp.set_api_key(SECOND_FAKE_KEY)
    assert second is not None and second.generation > first.generation
    assert orp.credential_status()["masked"] == orp.mask_key(SECOND_FAKE_KEY)

    orp.clear_api_key()
    assert orp.get_credential() is None
    assert orp.credential_status()["configured"] is False


def test_clear_does_not_silently_reuse_an_environment_key(monkeypatch):
    monkeypatch.setenv(orp.KEY_ENV_VAR, FAKE_KEY)
    orp.set_api_key(FAKE_KEY)
    orp.clear_api_key()
    assert orp.get_credential() is None


def test_malformed_key_is_rejected_without_echoing_it():
    with pytest.raises(orp.CredentialError) as excinfo:
        orp.set_api_key("not-a-real-key")
    assert "not-a-real-key" not in str(excinfo.value)
    assert orp.KEY_PREFIX in str(excinfo.value)


def test_masking_never_returns_the_full_secret():
    masked = orp.mask_key(FAKE_KEY)
    assert FAKE_KEY not in masked
    assert masked.startswith("sk-orca-")
    assert orp.redact(f"Authorization: Bearer {FAKE_KEY}") == f"Authorization: Bearer {masked}"
    assert orp.redact("plain text") == "plain text"

    credential = orp.set_api_key(FAKE_KEY)
    assert FAKE_KEY not in repr(credential)
    assert FAKE_KEY not in str(credential)


def test_rejected_key_is_terminal_and_not_retried(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    requested = []
    install_catalog(monkeypatch, status=401, payload={"error": "invalid key"}, record=requested)

    result = orp.list_models("chat")
    assert result.source == "verified-seed" and result.degraded is True
    assert len(requested) == 1, "a 401 must not be retried"
    assert orp.credential_status()["needs_reauth"] is True
    assert orp.get_credential() is None

    with pytest.raises(orp.CredentialError) as excinfo:
        orp.require_credential()
    assert "HTTP 401" in str(excinfo.value)
    assert FAKE_KEY not in str(excinfo.value)


def test_stale_auth_failure_cannot_poison_a_replaced_key(monkeypatch):
    old = orp.set_api_key(FAKE_KEY)
    new = orp.set_api_key(SECOND_FAKE_KEY)
    assert orp.credential_store().note_auth_failure(old) is False
    assert orp.credential_status()["needs_reauth"] is False
    assert orp.get_credential() is not None
    assert orp.credential_store().note_auth_failure(new) is True
    assert orp.get_credential() is None


def test_rotating_the_key_clears_old_generation_failures():
    first = orp.set_api_key(FAKE_KEY)
    orp.clear_api_key()
    second = orp.set_api_key(SECOND_FAKE_KEY)
    assert second.generation > first.generation
    assert orp.credential_store().note_auth_failure(first) is False
    assert orp.get_credential() is not None


# --------------------------------------------------------------------------- #
# Selection / persistence
# --------------------------------------------------------------------------- #


def test_selection_round_trips_without_storing_the_key():
    orp.set_active_provider("orcarouter")
    orp.set_active_model("orcarouter/auto")
    orp.set_api_key(FAKE_KEY)

    assert orp.active_provider() == "orcarouter"
    assert orp.is_active() is True
    assert orp.active_model() == "orcarouter/auto"
    assert orp.active_display_name() == "OrcaRouter Cyber Inference"

    stored = json.loads(Path(orp.config_path()).read_text(encoding="utf-8"))
    assert stored["provider"] == "orcarouter"
    assert FAKE_KEY not in json.dumps(stored)


def test_env_selection_override(monkeypatch):
    orp.set_active_provider("perplexity")
    monkeypatch.setenv(orp.PROVIDER_ENV_VAR, "orcarouter")
    assert orp.is_active() is True
    assert orp.active_display_name() == "OrcaRouter Cyber Inference"


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError):
        orp.set_active_provider("nope")


# --------------------------------------------------------------------------- #
# Catalog parsing and capability filtering
# --------------------------------------------------------------------------- #


def test_catalog_is_authoritative_and_metadata_is_preserved(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    requested = []
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE, record=requested)

    result = orp.list_models("chat")
    assert result.source == "live" and result.degraded is False
    assert requested[0]["url"] == "https://api.orcarouter.ai/v1/models?capability=chat"
    assert requested[0]["headers"]["Authorization"] == f"Bearer {FAKE_KEY}"

    ultra = orp.find_model("orca/orcacyber-ultra-1.0", result.models)
    assert ultra is not None
    assert ultra.context_length == 1048576
    assert ultra.input_modalities == ("text",)
    assert ultra.supports_reasoning is True

    # A successful live result is not padded with the verified seed.
    assert "openai/gpt-5.5" not in result.ids
    assert result.ids[0] == "orcarouter/auto"


def test_chat_filter_drops_non_text_endpoint_models(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE)
    ids = orp.list_models("chat").ids
    assert "vendor/embed-1" not in ids
    assert "vendor/image-gen-1" not in ids
    assert "vendor/video-1" not in ids
    assert "vendor/rerank-1" not in ids
    assert "vendor/text-only-chat" in ids
    assert "vendor/no-architecture-chat" in ids


def test_multimodal_filter_fails_closed(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE)
    image_ids = orp.list_models("chat", modality="image").ids
    assert image_ids == ("deepseek/deepseek-v4.1-flash",)
    assert "vendor/no-architecture-chat" not in image_ids
    assert orp.list_models("chat", modality="audio").ids == ()


@pytest.mark.parametrize(
    "capability,expected",
    [
        ("embedding", {"vendor/embed-1"}),
        ("image", {"vendor/image-gen-1"}),
        ("video", {"vendor/video-1"}),
        ("rerank", {"vendor/rerank-1"}),
    ],
)
def test_each_capability_has_its_own_filter(monkeypatch, capability, expected):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE)
    assert set(orp.list_models(capability).ids) == expected


def test_unknown_capability_is_rejected():
    with pytest.raises(ValueError):
        orp.filter_models((), "transmogrify")


def test_malformed_records_are_skipped_not_fatal(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE)
    models = orp.fetch_live_catalog("chat")
    assert all(model.id for model in models)
    assert len(models) == 9


# --------------------------------------------------------------------------- #
# Catalog failure behaviour
# --------------------------------------------------------------------------- #


def test_network_failure_falls_back_to_verified_seed_with_metadata(monkeypatch):
    orp.set_api_key(FAKE_KEY)

    def boom(*args, **kwargs):
        raise orp.requests.ConnectionError("no route to host")

    monkeypatch.setattr(orp.requests, "get", boom)
    result = orp.list_models("chat")
    assert result.source == "verified-seed" and result.degraded is True
    assert "network error" in (result.error or "")
    assert "orcarouter/auto" in result.ids
    gpt = orp.find_model("openai/gpt-5.5", result.models)
    assert gpt is not None
    assert gpt.reasoning_efforts == ("low", "medium", "high", "xhigh")
    assert gpt.input_modalities == ("text",)
    # The seed never satisfies a modality it does not declare.
    assert orp.list_models("chat", modality="image", refresh=True).ids == ()


def test_last_known_good_is_preferred_over_the_seed(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE)
    live = orp.list_models("chat", refresh=True)
    assert live.source == "live"

    def boom(*args, **kwargs):
        raise orp.requests.Timeout("timed out")

    monkeypatch.setattr(orp.requests, "get", boom)
    degraded = orp.list_models("chat", refresh=True)
    assert degraded.source == "last-known-good"
    assert degraded.ids == live.ids
    assert "openai/gpt-5.5" not in degraded.ids


def test_missing_key_falls_back_with_actionable_message():
    result = orp.list_models("chat")
    assert result.source == "verified-seed"
    assert "no API key is configured" in (result.error or "")


@pytest.mark.parametrize("status", [500, 403, 429])
def test_http_failures_degrade_gracefully(monkeypatch, status):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, status=status, payload={"error": "nope"})
    result = orp.list_models("chat")
    assert result.degraded is True
    assert result.source == "verified-seed"
    assert str(status) in (result.error or "")


def test_malformed_json_degrades_gracefully(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, raw=b"{not json")
    result = orp.list_models("chat")
    assert result.degraded is True
    assert "malformed JSON" in (result.error or "")


def test_oversized_catalog_is_bounded(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    install_catalog(monkeypatch, raw=b"x" * (orp.MAX_RESPONSE_BYTES + 10))
    with pytest.raises(orp.CatalogError):
        orp.fetch_live_catalog("chat")


def test_catalog_cache_avoids_repeat_requests(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    requested = []
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE, record=requested)
    orp.list_models("chat")
    orp.list_models("chat", modality="image")
    assert len(requested) == 1
    orp.list_models("chat", refresh=True)
    assert len(requested) == 2


# --------------------------------------------------------------------------- #
# Inference seam
# --------------------------------------------------------------------------- #


def test_builtin_provider_passthrough_is_unchanged(monkeypatch):
    orp.set_active_provider("perplexity")
    calls = []
    install_post(monkeypatch, record=calls)

    payload = {"model": "sonar-reasoning-pro", "messages": []}
    orp.post_chat(
        "https://api.perplexity.ai/chat/completions",
        headers={"Authorization": "Bearer INSERT API KEY HERE"},
        json=payload,
        stream=True,
        timeout=60,
    )
    assert calls[0]["url"] == "https://api.perplexity.ai/chat/completions"
    assert calls[0]["json"]["model"] == "sonar-reasoning-pro"
    assert calls[0]["timeout"] == 60


def test_orcarouter_rewrites_url_headers_and_model(monkeypatch):
    orp.set_active_provider("orcarouter")
    orp.set_active_model("oca/orcacyber-ultra-1.0".replace("oca/", "orca/"))
    orp.set_api_key(FAKE_KEY)
    calls = []
    install_post(monkeypatch, record=calls)

    orp.post_chat(
        "https://api.perplexity.ai/chat/completions",
        headers={"Authorization": "Bearer INSERT API KEY HERE"},
        json={"model": "sonar-reasoning-pro", "messages": [{"role": "user", "content": "hi"}]},
        stream=True,
    )
    assert calls[0]["url"] == "https://api.orcarouter.ai/v1/chat/completions"
    assert calls[0]["headers"]["Authorization"] == f"Bearer {FAKE_KEY}"
    assert calls[0]["json"]["model"] == "orca/orcacyber-ultra-1.0"
    assert calls[0]["json"]["messages"][0]["content"] == "hi"


def test_orcarouter_without_key_raises_instead_of_calling_out(monkeypatch):
    orp.set_active_provider("orcarouter")
    calls = []
    install_post(monkeypatch, record=calls)
    with pytest.raises(orp.CredentialError):
        orp.post_chat("https://api.perplexity.ai/chat/completions", json={"messages": []})
    assert calls == []


def test_chat_401_marks_reauth_and_prints_no_secret(monkeypatch, capsys):
    orp.set_active_provider("orcarouter")
    orp.set_api_key(FAKE_KEY)
    calls = []
    install_post(monkeypatch, response=FakeResponse(status_code=401, payload={"error": "revoked"}), record=calls)

    response = orp.post_chat("https://api.perplexity.ai/chat/completions", json={"messages": []})
    assert response.status_code == 401
    assert len(calls) == 1, "a revoked key must not be retried"
    assert orp.credential_status()["needs_reauth"] is True
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.err + captured.out
    assert "401" in captured.err


# --------------------------------------------------------------------------- #
# The host script's wiring
# --------------------------------------------------------------------------- #


def test_main_script_parses():
    ast.parse(MAIN_SCRIPT.read_text(encoding="utf-8"))


def test_every_ai_call_site_goes_through_the_provider_seam():
    source = MAIN_SCRIPT.read_text(encoding="utf-8")
    assert "import orcarouter_provider" in source
    assert "requests.post(PERPLEXITY_API_URL" not in source
    assert source.count("orcarouter_provider.post_chat(") >= 16
    assert source.count('"model": "sonar-reasoning-pro"') >= 16
    assert "def ai_configured()" in source
    assert "ai_provider_settings()" in source


def test_main_script_does_not_hardcode_a_real_key():
    source = MAIN_SCRIPT.read_text(encoding="utf-8")
    assert "sk-orca-" not in source
    assert 'ORCAROUTER_API_KEY = "INSERT API KEY HERE"' in source


def test_main_script_error_labels_follow_the_active_provider():
    source = MAIN_SCRIPT.read_text(encoding="utf-8")
    assert "Error from Perplexity: HTTP" not in source
    assert "orcarouter_provider.active_display_name()" in source


def test_readme_documents_the_named_provider_and_model_tiers():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "OrcaRouter Cyber Inference" in readme
    assert "https://api.orcarouter.ai/v1" in readme
    assert "https://www.orcarouter.ai/cyber" in readme
    assert "https://www.orcarouter.ai/models?tier=cyber" in readme
    assert "orcarouter/auto" in readme
    assert "orca/orcacyber-ultra-1.0" in readme
    assert "orcarouter/fusion" in readme


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def run_cli(args, tmp_path, stdin_text="", extra_env=None):
    env = dict(os.environ)
    env[orp.CONFIG_ENV_VAR] = str(tmp_path / "cli_config.json")
    env.pop(orp.KEY_ENV_VAR, None)
    env.pop(orp.PROVIDER_ENV_VAR, None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "orcarouter_provider", *args],
        cwd=str(ROOT),
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_cli_status_reports_the_named_provider(tmp_path):
    proc = run_cli(["status"], tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "OrcaRouter Cyber Inference" in proc.stdout
    assert "https://api.orcarouter.ai/v1" in proc.stdout
    assert "https://www.orcarouter.ai/cyber" in proc.stdout


def test_cli_list_models_uses_the_verified_fallback_without_a_key(tmp_path):
    proc = run_cli(["models", "--capability", "chat"], tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "verified-seed" in proc.stdout
    assert "orcarouter/auto" in proc.stdout
    assert "openai/gpt-5.5" in proc.stdout


def test_cli_set_key_reads_stdin_and_masks(tmp_path):
    proc = run_cli(["set-key"], tmp_path, stdin_text=FAKE_KEY + "\n")
    assert proc.returncode == 0, proc.stderr
    assert orp.mask_key(FAKE_KEY) in proc.stdout
    assert FAKE_KEY not in proc.stdout + proc.stderr


def test_cli_info_lists_the_three_tiers(tmp_path):
    proc = run_cli(["info"], tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "orcarouter/auto" in proc.stdout
    assert "orcacyber-ultra-1.0" in proc.stdout
    assert "orcarouter/fusion" in proc.stdout


def test_cli_refuses_a_model_it_cannot_verify(tmp_path):
    proc = run_cli(["select", "--model", "vendor/made-up-model"], tmp_path)
    assert proc.returncode == 2
    assert "not in the current" in proc.stderr or "cannot verify" in proc.stderr.lower()
    assert not (tmp_path / "cli_config.json").exists() or "made-up-model" not in (
        tmp_path / "cli_config.json"
    ).read_text(encoding="utf-8")


def test_build_chat_payload_does_not_mutate_the_caller_payload():
    original = {"model": "sonar-reasoning-pro", "messages": []}
    rewritten = orp.build_chat_payload(original, "orcarouter/auto")
    assert original["model"] == "sonar-reasoning-pro"
    assert rewritten["model"] == "orcarouter/auto"


def test_incompatible_stored_model_is_reset_to_the_default(monkeypatch):
    orp.set_api_key(FAKE_KEY)
    orp.set_active_model("vendor/retired-model")
    install_catalog(monkeypatch, payload=CATALOG_FIXTURE)
    result = orp.list_models("chat")
    model, changed = orp.reconcile_active_model(result.models)
    assert changed is True
    assert model == orp.DEFAULT_MODEL
    assert orp.active_model() == orp.DEFAULT_MODEL
    # A compatible selection is left alone.
    orp.set_active_model("orca/orcacyber-ultra-1.0")
    model, changed = orp.reconcile_active_model(result.models)
    assert changed is False and model == "orca/orcacyber-ultra-1.0"


def test_reconcile_does_not_reset_when_the_catalog_is_empty():
    orp.set_active_model("vendor/retired-model")
    model, changed = orp.reconcile_active_model(())
    assert changed is False and model == "vendor/retired-model"


# --------------------------------------------------------------------------- #
# Live checks (skip without a real key)
# --------------------------------------------------------------------------- #


needs_live = pytest.mark.skipif(not LIVE_KEY, reason="ORCAROUTER_API_KEY is not set")


@needs_live
def test_live_catalog_and_chat_through_the_provider_seam():
    orp.set_active_provider("orcarouter")
    orp.set_active_model(LIVE_MODEL)
    orp.set_api_key(LIVE_KEY)

    catalog = orp.list_models("chat", refresh=True)
    assert catalog.source == "live", catalog.error
    assert len(catalog.models) > 0
    assert all(m.supports_capability("chat") for m in catalog.models)
    assert all(not (set(m.endpoint_types) & orp.NON_TEXT_ENDPOINT_TYPES) for m in catalog.models)

    response = orp.post_chat(
        "https://api.perplexity.ai/chat/completions",
        json={
            "model": "sonar-reasoning-pro",
            "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
            "max_tokens": 16,
            "stream": False,
        },
        timeout=90,
    )
    assert response.status_code == 200, orp.redact(response.text)[:300]
    body = response.json()
    assert body["choices"], body
    assert FAKE_KEY not in json.dumps(body)


@needs_live
def test_live_multimodal_filter_is_fail_closed():
    orp.set_active_provider("orcarouter")
    orp.set_api_key(LIVE_KEY)
    catalog = orp.list_models("chat", refresh=True)
    image_models = orp.list_models("chat", modality="image")
    for model in image_models.models:
        assert "image" in model.input_modalities
    text_only = [m for m in catalog.models if "image" not in m.input_modalities]
    assert all(m.id not in image_models.ids for m in text_only)
