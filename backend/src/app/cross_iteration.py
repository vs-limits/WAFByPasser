from __future__ import annotations

import json
from itertools import product
from typing import Any

from app.encoding_agent.encoding import (
    ENCODING_CATALOG,
    encoding_chain_labels,
    expected_decode_path,
    replay_encoding_chain,
    reverse_encoding_chain,
)


def encoding_chain_key(chain: list[dict[str, str]]) -> str:
    """Return a stable identity for a deterministic encoding chain."""
    return json.dumps(chain, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def available_encoding_chains() -> list[list[dict[str, str]]]:
    """Enumerate every allowed one- and two-layer chain in a stable order.

    交叉迭代只做确定性整句编码链，因此仅枚举 `full` 模式步骤（`partial`
    模式需要按段 `segs` 信息，无法由固定链确定性重放）。
    """
    steps = [
        {"type": encoding_type, "mode": "full"}
        for encoding_type in sorted(ENCODING_CATALOG)
        if "full" in ENCODING_CATALOG[encoding_type]
    ]
    one_layer = [[step.copy()] for step in steps]
    two_layer = [[first.copy(), second.copy()] for first, second in product(steps, repeat=2)]
    return one_layer + two_layer


def build_cross_candidates(
    semantic_payload: str,
    chains: list[list[dict[str, str]]],
) -> list[dict[str, Any]]:
    """Replay and verify deterministic cross candidates before they are persisted.

    无法编码（例如字符集编码对非 ASCII 输入返回 None）或无法逆序恢复的链会被
    静默跳过，而不是整体失败。
    """
    candidates: list[dict[str, Any]] = []
    seen_contents: set[str] = set()
    for chain in chains:
        try:
            content = replay_encoding_chain(semantic_payload, chain)
        except (ValueError, UnicodeError):
            continue
        if content in seen_contents:
            continue
        try:
            if reverse_encoding_chain(content, chain) != semantic_payload:
                continue
        except (ValueError, UnicodeError):
            continue
        seen_contents.add(content)
        candidates.append(
            {
                "content": content,
                "encoding_chain": chain,
                "decode_path": expected_decode_path(chain),
                "rule_labels": encoding_chain_labels(chain),
            }
        )
    return candidates


def unused_distinct_chains(
    semantic_payload: str,
    used_chain_keys: set[str],
    used_contents: set[str],
) -> list[list[dict[str, str]]]:
    """Return unused chains that create an actual, unique encoded representation.

    无法编码或无法逆序恢复的链被跳过，不计入可用链。
    """
    eligible: list[list[dict[str, str]]] = []
    seen_contents = set(used_contents)
    for chain in available_encoding_chains():
        if encoding_chain_key(chain) in used_chain_keys:
            continue
        try:
            content = replay_encoding_chain(semantic_payload, chain)
        except (ValueError, UnicodeError):
            continue
        if content == semantic_payload or content in seen_contents:
            continue
        try:
            if reverse_encoding_chain(content, chain) != semantic_payload:
                continue
        except (ValueError, UnicodeError):
            continue
        seen_contents.add(content)
        eligible.append(chain)
    return eligible
