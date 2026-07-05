"""Ollama client for the v2 audit paths: schema-constrained output + chat."""

import os
import json
import time
import requests
from dataclasses import dataclass


@dataclass
class LLMConfig:
    model: str
    num_ctx: int = 16384
    num_predict: int = 4096
    temperature: float = 0.0
    think: bool | None = None  # None = omit; hybrid models must set False for JSON
    url: str = "http://host.docker.internal:11434"
    timeout: int = 900


class LLMError(RuntimeError):
    pass


class OllamaClient:
    """Thin, robust wrapper around Ollama's /api/generate and /api/chat."""

    def __init__(self, config: LLMConfig):
        self.cfg = config

    # -- low level -----------------------------------------------------------

    def _options(self, temperature: float | None, num_predict: int | None) -> dict:
        return {
            "temperature": self.cfg.temperature if temperature is None else temperature,
            "num_ctx": self.cfg.num_ctx,
            "num_predict": self.cfg.num_predict if num_predict is None else num_predict,
        }

    def _post(self, endpoint: str, payload: dict) -> dict:
        """POST, retrying once without `think` for models that reject it."""
        for attempt in range(2):
            try:
                r = requests.post(
                    f"{self.cfg.url}/{endpoint}",
                    json=payload,
                    timeout=self.cfg.timeout,
                )
            except requests.exceptions.ConnectionError as e:
                raise LLMError(f"cannot reach Ollama at {self.cfg.url}: {e}")
            except requests.exceptions.Timeout:
                raise LLMError(f"Ollama timed out after {self.cfg.timeout}s ({payload.get('model')})")

            if r.status_code == 400 and "think" in payload and "think" in r.text.lower():
                payload = {k: v for k, v in payload.items() if k != "think"}
                continue
            try:
                r.raise_for_status()
            except requests.exceptions.HTTPError as e:
                raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:300]}") from e
            return r.json()
        raise LLMError("unreachable")

    # -- public --------------------------------------------------------------

    def generate_structured(
        self,
        prompt: str,
        schema: dict,
        temperature: float | None = None,
        num_predict: int | None = None,
        retries: int = 1,
    ) -> dict:
        """Generate a dict constrained to `schema`. Retries on an empty body,
        which thinking models occasionally return on the first pass."""
        payload = {
            "model": self.cfg.model,
            "prompt": prompt,
            "stream": False,
            "format": schema,
            "options": self._options(temperature, num_predict),
        }
        if self.cfg.think is not None:
            payload["think"] = self.cfg.think

        last = ""
        for _ in range(retries + 1):
            data = self._post("api/generate", payload)
            text = (data.get("response") or "").strip()
            last = text
            if not text:
                time.sleep(0.5)
                continue
            parsed = _loads(text)
            if parsed is not None:
                return parsed
        raise LLMError(f"no valid JSON from {self.cfg.model} (last body: {last[:200]!r})")

    def chat(
        self,
        messages: list[dict],
        schema: dict | None = None,
        temperature: float | None = None,
        num_predict: int | None = None,
    ) -> dict | str:
        """Chat turn for the agentic loop. Returns a dict when `schema` is set,
        else the assistant message text."""
        payload = {
            "model": self.cfg.model,
            "messages": messages,
            "stream": False,
            "options": self._options(temperature, num_predict),
        }
        if schema is not None:
            payload["format"] = schema
        if self.cfg.think is not None:
            payload["think"] = self.cfg.think

        data = self._post("api/chat", payload)
        content = ((data.get("message") or {}).get("content") or "").strip()
        if schema is None:
            return content
        parsed = _loads(content)
        if parsed is None:
            raise LLMError(f"no valid JSON from chat {self.cfg.model}: {content[:200]!r}")
        return parsed


def _loads(text: str):
    """Parse JSON, tolerating a stray <think> block or code fence."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    end = text.rfind("</think>")
    if end >= 0:
        text = text[end + len("</think>"):].strip()
    if text.startswith("```"):
        text = text.strip("`")
        nl = text.find("\n")
        if nl >= 0:
            text = text[nl + 1:]
    start = text.find("{")
    stop = text.rfind("}") + 1
    if 0 <= start < stop:
        try:
            return json.loads(text[start:stop])
        except json.JSONDecodeError:
            return None
    return None


def config_from_env(role: str = "AUDIT") -> LLMConfig:
    """LLMConfig from env, namespaced by role (AUDIT/VERIFIER/AGENT) with a
    plain fallback. Defaults to local qwen3.5:9b, thinking off."""
    def g(suffix: str, default: str) -> str:
        return os.environ.get(f"{role}_{suffix}", os.environ.get(suffix, default))

    think_raw = g("THINK", "false").lower()
    think = None if think_raw in ("", "none", "auto") else (think_raw == "true")

    return LLMConfig(
        model=g("MODEL", "qwen3.5:9b"),
        num_ctx=int(g("NUM_CTX", "16384")),
        num_predict=int(g("NUM_PREDICT", "4096")),
        temperature=float(g("TEMPERATURE", "0.0")),
        think=think,
        url=os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434"),
        timeout=int(g("TIMEOUT", "900")),
    )
