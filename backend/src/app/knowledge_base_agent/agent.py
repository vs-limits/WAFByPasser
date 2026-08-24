"""知识库管理 Agent：LLM 浓缩提取文章中的绕过技巧。

对外提供 `extract_techniques`：给定 LLM 配置与文章原文，调用 LLM 提取
结构化技巧；LLM 不可用或调用失败时回退到确定性正则解析（parser.parse_techniques）。
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from app.knowledge_base_agent.parser import parse_techniques
from app.knowledge_base_agent.prompts import build_knowledge_base_agent_prompt

LOGGER = logging.getLogger("wafbypasser.knowledge_base_agent")


def _config_complete(config: dict[str, str] | None) -> bool:
    if not config:
        return False
    return all(config.get(key, "").strip() for key in ("base_url", "api_key", "model"))


def _chat_completion_endpoint(base_url: str) -> str:
    endpoint = base_url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint += "/chat/completions"
    return endpoint


def _post_chat_completion(config: dict[str, str], messages: list[dict[str, str]]) -> httpx.Response:
    return httpx.post(
        _chat_completion_endpoint(config["base_url"]),
        headers={"Authorization": f"Bearer {config['api_key']}"},
        json={"model": config["model"], "messages": messages, "temperature": 0.6},
        timeout=180,
    )


def _strip_json_fence(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.I)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def _extract_json_payload(message: str) -> Any:
    """Best-effort salvage of a JSON object/array from a model response.

    与 main._extract_json_payload 同构，但保持本 Agent 自包含、无反向依赖。
    """
    stripped = _strip_json_fence(message or "")
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start = stripped.find(open_ch)
        end = stripped.rfind(close_ch)
        if start != -1 and end > start:
            snippet = stripped[start : end + 1]
            try:
                return json.loads(snippet)
            except json.JSONDecodeError:
                cleaned = re.sub(r",(\s*[}\]])", r"\1", snippet)
                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    continue
    return None


def _parse_llm_response(raw_message: str, content: str) -> list[dict[str, Any]]:
    """解析 LLM 返回的 JSON；不可用则回退正则解析原文。"""
    decoded = _extract_json_payload(raw_message)
    if isinstance(decoded, dict):
        techniques = decoded.get("techniques")
        if isinstance(techniques, list):
            return [t for t in techniques if isinstance(t, dict)]
    return parse_techniques(content)


def extract_techniques(content: str, config: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """浓缩提取文章中的绕过技巧。

    LLM 配置缺失或调用/解析失败时，回退到确定性正则解析（不抛出异常）。
    """
    if not _config_complete(config):
        return parse_techniques(content)

    messages = [
        {"role": "system", "content": build_knowledge_base_agent_prompt()},
        {"role": "user", "content": content},
    ]
    try:
        response = _post_chat_completion(config, messages)
        response.raise_for_status()
        raw_message = response.json().get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as error:  # noqa: BLE001
        LOGGER.warning("knowledge base agent LLM failed: %s", error)
        return parse_techniques(content)
    return _parse_llm_response(raw_message, content)
