"""Base Claude skill wrapper."""

from __future__ import annotations
import os
from typing import Optional

import anthropic

_client: Optional[anthropic.Anthropic] = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError("ANTHROPIC_API_KEY environment variable not set.")
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


def call_claude(system: str, user: str, max_tokens: int = 1024) -> str:
    """Send a single system+user prompt to Claude and return the text response."""
    client = _get_client()
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return message.content[0].text.strip()
