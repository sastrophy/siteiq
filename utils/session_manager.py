"""
Stateful LLM Session Manager

Manages multi-turn conversations with LLM endpoints for security testing.
Unlike the fabricated-history approach, this sends separate HTTP requests
per turn and tracks actual server responses.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests


@dataclass
class ConversationTurn:
    """A single turn in a conversation."""
    role: str  # "user" or "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)


class LLMSession:
    """Manages a stateful multi-turn LLM conversation."""

    def __init__(self, scanner, endpoint: str):
        self.scanner = scanner
        self.endpoint = endpoint
        self.history: List[ConversationTurn] = []

    def send(self, message: str) -> Optional[str]:
        """Send a message and record the turn. Returns response text or None."""
        self.history.append(ConversationTurn(role="user", content=message))

        # Build messages array from history
        messages = [{"role": t.role, "content": t.content} for t in self.history]

        # Try formats in order of likelihood
        formats = [
            {"messages": messages},
            {"messages": messages, "stream": False},
            {"prompt": self._build_prompt_string()},
            {"message": message, "conversation_id": id(self)},
        ]

        for fmt in formats:
            try:
                resp = self.scanner.post(self.endpoint, json=fmt)
                if resp and resp.status_code in [200, 201]:
                    response_text = self._extract_text(resp)
                    if response_text:
                        self.history.append(
                            ConversationTurn(role="assistant", content=response_text)
                        )
                        return response_text
            except Exception:
                continue

        return None

    def _build_prompt_string(self) -> str:
        """Build a concatenated prompt from conversation history."""
        parts = []
        for turn in self.history:
            prefix = "User" if turn.role == "user" else "Assistant"
            parts.append(f"{prefix}: {turn.content}")
        parts.append("Assistant:")
        return "\n".join(parts)

    def _extract_text(self, resp: requests.Response) -> Optional[str]:
        """Extract text content from an LLM API response."""
        try:
            if resp.headers.get("content-type", "").startswith("application/json"):
                data = resp.json()
                # OpenAI format
                if "choices" in data:
                    return data["choices"][0].get("message", {}).get("content", "")
                # Common formats
                for key in ["response", "text", "content", "answer", "output", "result"]:
                    if key in data:
                        val = data[key]
                        return val if isinstance(val, str) else json.dumps(val)
                return json.dumps(data)
            return resp.text
        except Exception:
            return resp.text if resp else None

    def get_history(self) -> List[Dict[str, str]]:
        """Return conversation history as list of dicts."""
        return [{"role": t.role, "content": t.content} for t in self.history]

    def get_turn_count(self) -> int:
        """Return number of user turns sent."""
        return sum(1 for t in self.history if t.role == "user")

    def get_last_response(self) -> Optional[str]:
        """Return the last assistant response."""
        for turn in reversed(self.history):
            if turn.role == "assistant":
                return turn.content
        return None

    def reset(self):
        """Clear conversation history."""
        self.history.clear()


class SessionManager:
    """Factory for creating LLM sessions."""

    def __init__(self):
        self.sessions: List[LLMSession] = []

    def create_session(self, scanner, endpoint: str) -> LLMSession:
        """Create a new LLM session."""
        session = LLMSession(scanner=scanner, endpoint=endpoint)
        self.sessions.append(session)
        return session

    def close_all(self):
        """Reset all sessions."""
        for session in self.sessions:
            session.reset()
        self.sessions.clear()
