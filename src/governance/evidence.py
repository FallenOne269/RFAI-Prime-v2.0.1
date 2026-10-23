"""Append-only, hash-chained evidence log.

Each event carries the SHA-256 of the previous event, so an edited, removed, inserted or
reordered event breaks the chain and ``verify_chain`` reports where. This shows tampering
within one exported log. It is not a signature: someone who can rewrite the whole file can
rebuild the whole chain, so keep the head hash somewhere the log's author cannot change.

Content minimisation: by default only a hash, a length and no text are stored for prompts,
drafts and outputs (``hash_only``). ``redacted`` keeps a short excerpt with emails, phone
numbers, long digit runs and key-like strings masked. ``raw`` keeps the text and should be
used only with a documented purpose and the customer's authorisation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Callable, Literal, Optional

ContentMode = Literal["hash_only", "redacted", "raw"]
GENESIS = "0" * 64

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[PRIVATE_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "[JWT]"),
    (re.compile(r"\b(sk|pk|rk)-[A-Za-z0-9_-]{16,}"), "[API_KEY]"),
    (re.compile(r"\b(ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}"), "[GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS_KEY]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"(?<!\w)(\+?\d[\d\s().-]{8,}\d)(?!\w)"), "[NUMBER]"),
]


def redact(text: str) -> str:
    out = text or ""
    for pat, repl in _REDACTIONS:
        out = pat.sub(repl, out)
    return out


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def content_ref(text: Optional[str], mode: ContentMode = "hash_only", excerpt_chars: int = 240) -> dict:
    text = text or ""
    ref = {"sha256": sha256_text(text), "chars": len(text), "mode": mode}
    if mode == "redacted":
        ref["excerpt"] = redact(text)[:excerpt_chars]
    elif mode == "raw":
        ref["text"] = text
    elif mode != "hash_only":
        raise ValueError(f"unknown content mode {mode!r}")
    return ref


def _event_hash(event: dict) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EvidenceLog:
    def __init__(self, run_id: str, clock: Callable[[], str] = _utc_now) -> None:
        self.run_id = run_id
        self.clock = clock
        self._events: list[dict] = []

    @property
    def events(self) -> list[dict]:
        return copy.deepcopy(self._events)  # deep copies: the log itself is append-only

    @property
    def head(self) -> str:
        return self._events[-1]["hash"] if self._events else GENESIS

    def append(self, event_type: str, payload: dict) -> dict:
        event = {
            "run_id": self.run_id,
            "seq": len(self._events),
            "ts": self.clock(),
            "type": event_type,
            "payload": json.loads(json.dumps(payload, default=str)),  # freeze to plain JSON
            "prev_hash": self.head,
        }
        event["hash"] = _event_hash(event)
        self._events.append(event)
        return copy.deepcopy(event)

    def to_json(self) -> str:
        return json.dumps({"run_id": self.run_id, "head": self.head, "events": self._events}, indent=2)


def verify_chain(events: list[dict]) -> tuple[bool, Optional[int], str]:
    """Return (ok, index_of_first_bad_event, reason)."""
    prev = GENESIS
    for i, e in enumerate(events):
        if e.get("seq") != i:
            return False, i, f"sequence number {e.get('seq')} at position {i}"
        if e.get("prev_hash") != prev:
            return False, i, "prev_hash does not match the previous event"
        if _event_hash(e) != e.get("hash"):
            return False, i, "event content does not match its hash"
        prev = e["hash"]
    return True, None, "ok"
