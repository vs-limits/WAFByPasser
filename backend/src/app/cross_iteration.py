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
    """Enumerate every allowed one- and two-layer chain in a stable order."""
    steps = [
        {"type": encoding_type, "mode": mode}
        for encoding_type in sorted(ENCODING_CATALOG)
        for mode in sorted(ENCODING_CATALOG[encoding_type])
    ]
    one_layer = [[step.copy()] for step in steps]
    two_layer = [[first.copy(), second.copy()] for first, second in product(steps, repeat=2)]
    return one_layer + two_layer


def build_cross_candidates(
    semantic_payload: str,
    chains: list[list[dict[str, str]]],
) -> list[dict[str, Any]]:
    """Replay and verify deterministic cross candidates before they are persisted."""
    candidates: list[dict[str, Any]] = []
    seen_contents: set[str] = set()
    for chain in chains:
        content = replay_encoding_chain(semantic_payload, chain)
        if content in seen_contents:
            raise ValueError("交叉候选内容重复")
        if reverse_encoding_chain(content, chain) != semantic_payload:
            raise ValueError("交叉候选无法逆向恢复语义 Payload")
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
    """Return unused chains that create an actual, unique encoded representation."""
    eligible: list[list[dict[str, str]]] = []
    seen_contents = set(used_contents)
    for chain in available_encoding_chains():
        if encoding_chain_key(chain) in used_chain_keys:
            continue
        content = replay_encoding_chain(semantic_payload, chain)
        if content == semantic_payload or content in seen_contents:
            continue
        seen_contents.add(content)
        eligible.append(chain)
    return eligible
