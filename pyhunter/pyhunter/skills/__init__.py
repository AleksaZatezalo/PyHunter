"""Claude API wrapper and prompt loader."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import anthropic

_MODEL   = "claude-opus-4-5"
_PROMPTS = Path(__file__).parent / "prompts"

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


async def async_call_claude(system: str, user: str, max_tokens: int = 1024) -> str:
    message = await _async().messages.create(
        model=_MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return message.content[0].text.strip()
