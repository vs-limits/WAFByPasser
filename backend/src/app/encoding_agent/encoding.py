from __future__ import annotations

import base64
import codecs
import html
import re
from typing import Any
from urllib.parse import quote, unquote_to_bytes


# This catalog is intentionally limited to representation-level encodings.  It is
# shared with forward cross iteration, so interpreter-level strategies must not
# be added here.
ENCODING_CATALOG: dict[str, set[str]] = {
    "url_percent": {"full", "special"},
    "html_entity_decimal": {"full", "special"},
    "html_entity_hex": {"full", "special"},
    "unicode_escape": {"full"},
    "json_unicode_escape": {"full"},
    "hex_text": {"full"},
    "base64": {"full"},
    "base64url": {"full"},
}

# These strategies are only available to the encoding agent for command
# injection.  They model a decoding action performed by a shell, not a general
# transport encoding, and therefore never participate in cross iteration.
INTERPRETER_ENCODING_CATALOG: dict[str, set[str]] = {
    "shell_printf_octal_command": {"command_name"},
    "shell_ansi_c_octal_command": {"command_name"},
}
ALL_ENCODING_CATALOG = {**ENCODING_CATALOG, **INTERPRETER_ENCODING_CATALOG}

ENCODING_LABELS = {
    "url_percent": "URL 百分号编码",
    "html_entity_decimal": "HTML 十进制实体",
    "html_entity_hex": "HTML 十六进制实体",
    "unicode_escape": "Unicode 转义",
    "json_unicode_escape": "JSON Unicode 转义",
    "hex_text": "十六进制文本",
    "base64": "Base64",
    "base64url": "Base64URL",
    "shell_printf_octal_command": "Shell printf 八进制命令构造",
    "shell_ansi_c_octal_command": "Shell ANSI-C 八进制命令构造",
}

MODE_LABELS = {
    "full": "全量",
    "special": "特殊字符",
    "command_name": "直接命令名",
}
HTML_SPECIALS = set("&<>\"'/=`")
SHELL_DIRECT_COMMAND = re.compile(
    r"^(?P<prefix>.*(?:;|&&|\|\||\||\n)\s*)(?P<command>[A-Za-z_][A-Za-z0-9_-]*)(?P<suffix>(?:\s.*)?)$",
    re.DOTALL,
)
SHELL_PRINTF_OCTAL_OUTPUT = re.compile(
    r"^(?P<prefix>.*(?:;|&&|\|\||\||\n)\s*)\$\(printf '(?P<octal>(?:\\[0-7]{3})+)'\)(?P<suffix>(?:\s.*)?)$",
    re.DOTALL,
)
SHELL_ANSI_C_OCTAL_OUTPUT = re.compile(
    r"^(?P<prefix>.*(?:;|&&|\|\||\||\n)\s*)\$'(?P<octal>(?:\\[0-7]{3})+)'(?P<suffix>(?:\s.*)?)$",
    re.DOTALL,
)


def _unicode_escape_character(character: str) -> str:
    codepoint = ord(character)
    return f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"


def _encode_entities(value: str, *, hexadecimal: bool, mode: str) -> str:
    encoded: list[str] = []
    for character in value:
        if mode == "special" and character not in HTML_SPECIALS:
            encoded.append(character)
        elif hexadecimal:
            encoded.append(f"&#x{ord(character):x};")
        else:
            encoded.append(f"&#{ord(character)};")
    return "".join(encoded)


def _split_shell_direct_command(value: str) -> re.Match[str]:
    match = SHELL_DIRECT_COMMAND.match(value)
    if not match:
        raise ValueError("Shell 八进制策略仅适用于“注入分隔符 + 直接命令名”的命令注入 Payload")
    return match


def _octal_encode_command(command: str) -> str:
    return "".join(f"\\{byte:03o}" for byte in command.encode("ascii"))


def _octal_decode_command(value: str) -> str:
    chunks = re.findall(r"\\([0-7]{3})", value)
    if not chunks or "".join(f"\\{chunk}" for chunk in chunks) != value:
        raise ValueError("Shell 八进制命令构造格式不正确")
    decoded = bytes(int(chunk, 8) for chunk in chunks).decode("ascii")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", decoded):
        raise ValueError("Shell 八进制构造无法还原为直接命令名")
    return decoded


def is_interpreter_encoding_step(step: dict[str, Any]) -> bool:
    return step.get("type") in INTERPRETER_ENCODING_CATALOG


def allowed_encoding_catalog(vulnerability: str, base_payload: str) -> dict[str, list[str]]:
    allowed = {encoding: sorted(modes) for encoding, modes in ENCODING_CATALOG.items()}
    if vulnerability == "command-injection":
        try:
            _split_shell_direct_command(base_payload)
        except ValueError:
            return allowed
        allowed.update({encoding: sorted(modes) for encoding, modes in INTERPRETER_ENCODING_CATALOG.items()})
    return allowed


def apply_encoding_step(value: str, step: dict[str, Any]) -> str:
    encoding_type = step.get("type")
    mode = step.get("mode")
    if encoding_type not in ALL_ENCODING_CATALOG:
        raise ValueError(f"未知编码类型：{encoding_type}")
    if mode not in ALL_ENCODING_CATALOG[encoding_type]:
        raise ValueError(f"编码 {encoding_type} 不支持模式：{mode}")

    if encoding_type == "url_percent":
        if mode == "full":
            return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))
        return quote(value, safe="-._~", encoding="utf-8", errors="strict")
    if encoding_type == "html_entity_decimal":
        return _encode_entities(value, hexadecimal=False, mode=mode)
    if encoding_type == "html_entity_hex":
        return _encode_entities(value, hexadecimal=True, mode=mode)
    if encoding_type in {"unicode_escape", "json_unicode_escape"}:
        return "".join(_unicode_escape_character(character) for character in value)
    if encoding_type == "hex_text":
        return value.encode("utf-8").hex()
    if encoding_type == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoding_type == "base64url":
        return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")

    match = _split_shell_direct_command(value)
    octal = _octal_encode_command(match["command"])
    if encoding_type == "shell_printf_octal_command":
        return f"{match['prefix']}$(printf '{octal}'){match['suffix']}"
    if encoding_type == "shell_ansi_c_octal_command":
        return f"{match['prefix']}$'{octal}'{match['suffix']}"
    raise ValueError(f"未实现编码类型：{encoding_type}")


def decode_encoding_step(value: str, step: dict[str, Any]) -> str:
    encoding_type = step["type"]
    if encoding_type == "url_percent":
        return unquote_to_bytes(value).decode("utf-8")
    if encoding_type in {"html_entity_decimal", "html_entity_hex"}:
        return html.unescape(value)
    if encoding_type in {"unicode_escape", "json_unicode_escape"}:
        return codecs.decode(value, "unicode_escape")
    if encoding_type == "hex_text":
        return bytes.fromhex(value).decode("utf-8")
    if encoding_type == "base64":
        return base64.b64decode(value, validate=True).decode("utf-8")
    if encoding_type == "base64url":
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True).decode("utf-8")
    if encoding_type == "shell_printf_octal_command":
        match = SHELL_PRINTF_OCTAL_OUTPUT.match(value)
    elif encoding_type == "shell_ansi_c_octal_command":
        match = SHELL_ANSI_C_OCTAL_OUTPUT.match(value)
    else:
        raise ValueError(f"未知解码类型：{encoding_type}")
    if not match:
        raise ValueError("Shell 八进制命令构造格式不正确")
    return f"{match['prefix']}{_octal_decode_command(match['octal'])}{match['suffix']}"


def normalize_encoding_chain(chain: Any) -> list[dict[str, str]]:
    if not isinstance(chain, list) or not 1 <= len(chain) <= 2:
        raise ValueError("encoding_chain 必须包含 1 到 2 层")
    normalized: list[dict[str, str]] = []
    for step in chain:
        if not isinstance(step, dict) or set(step) != {"type", "mode"}:
            raise ValueError("编码步骤必须且只能包含 type 和 mode")
        encoding_type = step.get("type")
        mode = step.get("mode")
        if not isinstance(encoding_type, str) or not isinstance(mode, str):
            raise ValueError("编码步骤字段必须是字符串")
        if encoding_type not in ALL_ENCODING_CATALOG or mode not in ALL_ENCODING_CATALOG[encoding_type]:
            raise ValueError(f"不支持的编码步骤：{encoding_type}/{mode}")
        normalized.append({"type": encoding_type, "mode": mode})
    if any(is_interpreter_encoding_step(step) for step in normalized) and len(normalized) != 1:
        raise ValueError("Shell 解释器级编码策略第一版仅允许单层使用")
    return normalized


def replay_encoding_chain(base_payload: str, chain: list[dict[str, str]]) -> str:
    value = base_payload
    for step in chain:
        value = apply_encoding_step(value, step)
    return value


def reverse_encoding_chain(encoded_payload: str, chain: list[dict[str, str]]) -> str:
    value = encoded_payload
    for step in reversed(chain):
        value = decode_encoding_step(value, step)
    return value


def expected_decode_path(chain: list[dict[str, str]]) -> list[str]:
    return [step["type"] for step in reversed(chain)]


def encoding_chain_labels(chain: list[dict[str, str]]) -> list[str]:
    return [f"{ENCODING_LABELS[step['type']]} · {MODE_LABELS[step['mode']]}" for step in chain]


def encoding_strategy_prerequisites(chain: list[dict[str, str]]) -> list[str]:
    notes: list[str] = []
    for step in chain:
        if step["type"] == "shell_printf_octal_command":
            notes.append("前提：目标为支持命令替换与 printf 的 Shell（通常为 Bash）。")
        elif step["type"] == "shell_ansi_c_octal_command":
            notes.append("前提：目标 Shell 支持 Bash ANSI-C $'...' 八进制转义语法。")
    return notes


def validate_encoding_candidates(
    candidates: Any,
    base_payload: str,
    candidate_count: int,
    vulnerability: str | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(candidates, list) or len(candidates) != candidate_count:
        raise ValueError(f"模型输出必须包含恰好 {candidate_count} 条编码候选")

    validated: list[dict[str, Any]] = []
    seen_contents: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("编码候选必须是对象")
        content = candidate.get("content")
        explanation = candidate.get("explanation")
        confidence = candidate.get("confidence")
        chain = normalize_encoding_chain(candidate.get("encoding_chain"))
        decode_path = candidate.get("decode_path")

        if any(is_interpreter_encoding_step(step) for step in chain) and vulnerability != "command-injection":
            raise ValueError("Shell 八进制策略仅支持命令注入")
        if not isinstance(content, str) or not content or len(content) > 5000:
            raise ValueError("编码候选 content 不合规")
        if content in seen_contents:
            raise ValueError("编码候选内容不能重复")
        if not isinstance(explanation, str) or not explanation.strip() or len(explanation) > 1000:
            raise ValueError("编码候选 explanation 不合规")
        if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
            raise ValueError("编码候选 confidence 不合规")
        expected_path = expected_decode_path(chain)
        if decode_path != expected_path:
            raise ValueError("decode_path 与编码链逆序不一致")
        if replay_encoding_chain(base_payload, chain) != content:
            raise ValueError("候选内容无法由声明的编码链重放")
        if reverse_encoding_chain(content, chain) != base_payload:
            raise ValueError("候选内容逆向解码后未恢复基础 Payload")

        seen_contents.add(content)
        validated.append(
            {
                "content": content,
                "encoding_chain": chain,
                "decode_path": expected_path,
                "rule_labels": encoding_chain_labels(chain),
                "explanation": explanation.strip(),
                "confidence": float(confidence),
            }
        )
    return validated
