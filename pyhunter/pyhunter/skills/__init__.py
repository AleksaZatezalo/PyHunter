"""Claude API wrapper with disk-based response caching.

Design pattern: Strategy (via async_call_claude)
  Each skill module (analyze, explain, poc, demo, context) is a Strategy: it
  owns a fixed system prompt and result-parser, and delegates the actual API
  call to async_call_claude (the shared context).  Swapping a skill means
  changing its system prompt string, not touching the transport layer.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

import anthropic

_MODEL     = "claude-opus-4-6"
_PROMPTS   = Path(__file__).parent / "prompts"
_CACHE_DIR = Path.home() / ".cache" / "pyhunter"

_sync_client:  Optional[anthropic.Anthropic]      = None
_async_client: Optional[anthropic.AsyncAnthropic] = None


def _api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise EnvironmentError("ANTHROPIC_API_KEY is not set.")
    return key


def _sync() -> anthropic.Anthropic:
    global _sync_client
    if _sync_client is None:
        _sync_client = anthropic.Anthropic(api_key=_api_key())
    return _sync_client


def _async() -> anthropic.AsyncAnthropic:
    global _async_client
    if _async_client is None:
        _async_client = anthropic.AsyncAnthropic(api_key=_api_key())
    return _async_client


def load_prompt(name: str) -> str:
    """Return the contents of skills/prompts/<name>.md."""
    return (_PROMPTS / f"{name}.md").read_text()


def _cache_key(system: str, user: str) -> str:
    digest = hashlib.sha256(f"{system}\x00{user}".encode()).hexdigest()
    return digest[:24]


async def async_call_claude(system: str, user: str, max_tokens: int = 1024) -> str:
    """Call Claude with caching. Identical (system, user) pairs are served from disk."""
    key        = _cache_key(system, user)
    cache_path = _CACHE_DIR / f"{key}.txt"

    if cache_path.exists():
        return cache_path.read_text()

    message = await _async().messages.create(
        model=_MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = message.content[0].text.strip()

    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(text)
    return text
