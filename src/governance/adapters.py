"""Model clients with the same .messages.create(model, max_tokens, messages) shape as the
anthropic SDK, so the council runs on them unchanged.

- ScriptedClient: deterministic replies from a function. No model, no network. Used by the
  tests and the offline Discovery demo.
- OpenAICompatClient: any OpenAI-compatible chat endpoint (for example llama.cpp's
  llama-server). Loopback addresses only unless allow_remote=True, so a demo cannot send
  client data to a third party by accident. No key is read unless api_key_env is named.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlparse


class _Reply:
    def __init__(self, text: str) -> None:
        self.content = [type("Block", (), {"text": text})()]


def role_of(prompt: str) -> str:
    head = prompt.split(" in the RFAI-PRIME council")[0].replace("You are the ", "").strip()
    if head.endswith("Critic"):
        return "critic:" + head[: -len(" Critic")].lower()
    return head.lower()  # "architect" or "integrator"


class ScriptedClient:
    """responder(role, prompt, n) -> str, or raises. n counts earlier calls for that role."""

    def __init__(self, responder: Callable[[str, str, int], str]) -> None:
        self.responder = responder
        self.calls: list[tuple[str, str]] = []
        self.messages = self

    def create(self, model, max_tokens, messages):
        prompt = messages[0]["content"]
        role = role_of(prompt)
        n = sum(1 for r, _ in self.calls if r == role)
        self.calls.append((role, prompt))
        return _Reply(self.responder(role, prompt, n))


def _is_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_loopback for i in infos)


class OpenAICompatClient:
    def __init__(self, url: str = "http://127.0.0.1:8080/v1/chat/completions", model_override: Optional[str] = None,
                 temperature: float = 0.0, seed: Optional[int] = 1, timeout: float = 300.0,
                 allow_remote: bool = False, api_key_env: Optional[str] = None) -> None:
        host = urlparse(url).hostname or ""
        if not allow_remote and not _is_loopback(host):
            raise ValueError(f"refusing non-loopback endpoint {host!r}; pass allow_remote=True deliberately")
        self.url = url
        self.model_override = model_override
        self.temperature = temperature
        self.seed = seed
        self.timeout = timeout
        self.api_key_env = api_key_env
        self.messages = self

    def create(self, model, max_tokens, messages):
        body = {"model": self.model_override or model, "messages": messages,
                "max_tokens": max_tokens, "temperature": self.temperature}
        if self.seed is not None:
            body["seed"] = self.seed
        headers = {"Content-Type": "application/json"}
        if self.api_key_env:
            headers["Authorization"] = "Bearer " + os.environ[self.api_key_env]
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read().decode())
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError("endpoint reply has no choices[0].message.content") from e
        return _Reply(text or "")
