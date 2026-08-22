"""
Unified LLM adapter — one interface, multiple providers.
====================================================================

Purpose
-------
The platform generates ISMS documents, BSI notification drafts and site-audit
findings with an LLM. For GDPR / NIS2 reasons some customers require the data
to be processed by an **EU-based** model. This module lets the whole app switch
provider without touching the calling code:

    LLM_PROVIDER=anthropic   → Claude (default, unchanged behaviour)
    LLM_PROVIDER=mistral     → Mistral AI (France / EU data residency)

Callers ask for a logical *tier* ("small" / "large") instead of hard-coding a
model name; the adapter maps the tier to the concrete model for the active
provider. Token usage is returned uniformly so APIUsageLog keeps working.

Adding a new provider = add an entry to _MODEL_MAP and a `_generate_<name>`
function. Nothing else changes.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ── Provider / model configuration ───────────────────────────────────────────
DEFAULT_PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic").strip().lower()

# Logical tier → concrete model, per provider.
# Tiers keep call sites provider-agnostic: "small" = fast/cheap, "large" = best.
_MODEL_MAP: dict[str, dict[str, str]] = {
    "anthropic": {
        "small": os.environ.get("ANTHROPIC_MODEL_SMALL", "claude-haiku-4-5-20251001"),
        "large": os.environ.get("ANTHROPIC_MODEL_LARGE", "claude-sonnet-4-6"),
    },
    "mistral": {
        # Mistral is a French company; the API processes data in the EU and
        # offers a DPA + no-training-on-customer-data option.
        "small": os.environ.get("MISTRAL_MODEL_SMALL", "mistral-small-latest"),
        "large": os.environ.get("MISTRAL_MODEL_LARGE", "mistral-large-latest"),
    },
}


class LLMError(RuntimeError):
    """Raised when the active provider is misconfigured or the call fails."""


@dataclass
class LLMResult:
    text: str
    input_tokens: int
    output_tokens: int
    model: str
    provider: str


def resolve_model(tier: str, provider: Optional[str] = None) -> str:
    """Map a logical tier ('small'/'large') to a concrete model name."""
    provider = (provider or DEFAULT_PROVIDER).strip().lower()
    tiers = _MODEL_MAP.get(provider)
    if not tiers:
        raise LLMError(f"Unknown LLM_PROVIDER: {provider!r}")
    return tiers.get(tier) or tiers["small"]


def generate(
    *,
    user: str,
    system: Optional[str] = None,
    tier: str = "small",
    max_tokens: int = 2048,
    temperature: Optional[float] = None,
    provider: Optional[str] = None,
) -> LLMResult:
    """
    Generate text with the active provider.

    Parameters
    ----------
    user : the user message / prompt.
    system : optional system prompt.
    tier : "small" (fast) or "large" (best quality).
    max_tokens : output token cap.
    temperature : optional sampling temperature.
    provider : override LLM_PROVIDER for a single call (rarely needed).

    If the primary provider fails and LLM_FALLBACK_PROVIDER is configured (and
    differs), the call is transparently retried on the fallback provider before
    giving up. Returns an LLMResult with text and token usage; raises LLMError on
    failure so callers can keep their (content, error_message) contract.
    """
    primary = (provider or DEFAULT_PROVIDER).strip().lower()
    try:
        return _dispatch(primary, user, system, tier, max_tokens, temperature)
    except Exception as primary_exc:
        fallback = os.environ.get("LLM_FALLBACK_PROVIDER", "").strip().lower()
        if not fallback or fallback == primary:
            raise
        logger.warning(
            "LLM provider %r failed (%s) — retrying on fallback %r",
            primary, type(primary_exc).__name__, fallback,
        )
        return _dispatch(fallback, user, system, tier, max_tokens, temperature)


def _dispatch(
    provider: str,
    user: str,
    system: Optional[str],
    tier: str,
    max_tokens: int,
    temperature: Optional[float],
) -> LLMResult:
    model = resolve_model(tier, provider)
    if provider == "anthropic":
        return _generate_anthropic(user, system, model, max_tokens, temperature)
    if provider == "mistral":
        return _generate_mistral(user, system, model, max_tokens, temperature)
    raise LLMError(f"Unknown LLM_PROVIDER: {provider!r}")


# ── Anthropic (Claude) ───────────────────────────────────────────────────────
def _generate_anthropic(
    user: str,
    system: Optional[str],
    model: str,
    max_tokens: int,
    temperature: Optional[float],
) -> LLMResult:
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover
        raise LLMError(
            "anthropic-Paket nicht installiert. Fügen Sie 'anthropic' zu "
            "requirements.txt hinzu."
        ) from exc

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise LLMError(
            "ANTHROPIC_API_KEY nicht konfiguriert. Bitte setzen Sie die "
            "Umgebungsvariable auf Render."
        )

    client = anthropic.Anthropic(api_key=api_key)
    kwargs: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": user}],
    }
    if system:
        kwargs["system"] = system
    if temperature is not None:
        kwargs["temperature"] = temperature

    resp = client.messages.create(**kwargs)
    text = "".join(
        block.text for block in resp.content if getattr(block, "type", None) == "text"
    )
    return LLMResult(
        text=text,
        input_tokens=resp.usage.input_tokens,
        output_tokens=resp.usage.output_tokens,
        model=model,
        provider="anthropic",
    )


# ── Mistral AI (EU) ──────────────────────────────────────────────────────────
def _generate_mistral(
    user: str,
    system: Optional[str],
    model: str,
    max_tokens: int,
    temperature: Optional[float],
) -> LLMResult:
    try:
        from mistralai import Mistral
    except ImportError as exc:  # pragma: no cover
        raise LLMError(
            "mistralai-Paket nicht installiert. Fügen Sie 'mistralai' zu "
            "requirements.txt hinzu."
        ) from exc

    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise LLMError(
            "MISTRAL_API_KEY nicht konfiguriert. Bitte setzen Sie die "
            "Umgebungsvariable auf Render."
        )

    client = Mistral(api_key=api_key)
    messages: list[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})

    kwargs: dict = {"model": model, "messages": messages, "max_tokens": max_tokens}
    if temperature is not None:
        kwargs["temperature"] = temperature

    resp = client.chat.complete(**kwargs)
    text = resp.choices[0].message.content or ""
    usage = resp.usage
    return LLMResult(
        text=text,
        input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
        output_tokens=getattr(usage, "completion_tokens", 0) or 0,
        model=model,
        provider="mistral",
    )
