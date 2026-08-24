"""检验靶场适配器注册表。

每个 adapter 接收 ``(config_path, content, base)`` 返回 ``TargetEvidence``。
新增靶场 = 加一个 ``run_*`` 函数 + 在 ``ADAPTERS`` / ``DEFAULT_RANGE`` 注册，
再在 ``config/.env.example`` 补充 ``RANGE_*`` 配置，无需改动判定层。
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote, urljoin

import httpx
from dotenv import load_dotenv

from app.waf_testing import (
    WafConfig,
    classify,
    ensure_low_security,
    login,
    same_origin,
    verify_execution,
)


@dataclass(frozen=True)
class TargetEvidence:
    """一次靶场请求的原始证据，喂给 LLM 判定。"""

    target_key: str
    vulnerability: str
    request_summary: str
    http_status: int
    response_excerpt: str
    response_headers: str = ""
    outcome: str = "application_response"
    evidence: str = ""
    baseline_excerpt: str = ""
    sent_body: str = ""
    request_digest: str = ""


AdapterFn = Callable[[str, str, dict[str, Any]], TargetEvidence]

# 已有合法 %HH 序列（编码 Agent 产物），传输时保留，避免二次编码。
_EXISTING_PCT = re.compile(r"%[0-9a-fA-F]{2}")


def _encode_form_once(value: str) -> str:
    """只编码一次的 x-www-form-urlencoded 传输：保留已有合法 %HH，其余非安全字符编码。"""
    parts: list[str] = []
    cursor = 0
    for match in _EXISTING_PCT.finditer(value):
        if match.start() > cursor:
            parts.append(quote(value[cursor:match.start()], safe=""))
        parts.append(match.group(0).upper())
        cursor = match.end()
    if cursor < len(value):
        parts.append(quote(value[cursor:], safe=""))
    return "".join(parts)


def _request_digest(method: str, url: str, body: str = "") -> str:
    digest = hashlib.sha256(f"{method} {url} body={body}".encode("utf-8")).hexdigest()
    return digest


def _delivery_kind(delivery: str) -> str:
    """归一化自由文本投递上下文为粗粒度类别。

    仅把「无法被任何固定靶场入口承载」的上下文判为不兼容，其余 fail-open，
    避免误拒存量 URL路径 / 表单字段 等历史 payload。
    """
    d = (delivery or "").strip()
    if "JSON 请求体" in d or "JSON请求体" in d or "请求头" in d or "Cookie" in d:
        return "unsupported"
    return "compatible"


def _is_delivery_compatible(vulnerability: str, delivery: str) -> bool:
    return _delivery_kind(delivery) != "unsupported"


def _excerpt(text: str | None, limit: int = 4000) -> str:
    return (text or "")[:limit]


def _headers_text(headers: Any) -> str:
    if headers is None:
        return ""
    items = []
    for key, value in getattr(headers, "items", lambda: [])():
        items.append(f"{key}: {value}")
    return "\n".join(items)[:2000]


def _load_range_config(config_path: str, prefix: str, fallback_prefix: str = "") -> tuple[str, str, str]:
    """读取一个 DVWA 型靶场的 base_url / username / password。

    只使用检验靶场注册表（``{prefix}_DVWA_BASE_URL`` + ``RANGE_DVWA_*``）。
    """
    load_dotenv(config_path)
    base_url = os.getenv(f"{prefix}_DVWA_BASE_URL", "").strip()
    # 账号优先级：目标专用账号 -> 通用 RANGE_DVWA_*。
    username = (
        os.getenv(f"{prefix}_USERNAME", "").strip()
        or os.getenv("RANGE_DVWA_USERNAME", "").strip()
    )
    password = (
        os.getenv(f"{prefix}_PASSWORD", "").strip()
        or os.getenv("RANGE_DVWA_PASSWORD", "").strip()
    )
    return base_url.rstrip("/"), username, password


def _dvwa_client(
    base_url: str, username: str, password: str, host: str = ""
) -> tuple[httpx.Client, WafConfig]:
    """登录 DVWA 并设置 Low 安全等级，返回带会话 Cookie 的客户端。

    提供 ``host`` 时，所有请求（含登录）都携带自定义 Host 头——用于直连源站 IP、
    经 WAF 按 Host 路由的场景；登录成功后 httpx 自动保存会话 PHPSESSID 与
    security=low Cookie。
    """
    headers = {"User-Agent": "WAFByPasser-Verify/1.0"}
    if host:
        headers["Host"] = host
    client = httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=headers)
    config = WafConfig(base_url=base_url, username=username, password=password)
    login(client, config)
    ensure_low_security(client, config)
    return client, config


def _dvwa_direct_client(base_url: str, host: str, cookie: str) -> httpx.Client:
    """直连源站 IP + 自定义 Host 头 + 预置会话 Cookie（跳过登录）。

    用于「套了 WAF 的 DVWA」——登录流程会被 WAF 干扰，只能直接带静态会话访问。
    """
    headers = {
        "Host": host,
        "Cookie": cookie,
        "User-Agent": "WAFByPasser-Verify/1.0",
    }
    return httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=headers, follow_redirects=False)


def _load_dvwa_waf_config(config_path: str, prefix: str) -> dict[str, str]:
    """读取一个「套了 WAF 的 DVWA」靶场配置。

    返回 base_url / username / password / host / cookie；``host`` 与 ``cookie``
    均配置时才启用「直连 + 静态 Cookie」通道（跳过登录），否则回退账密登录。
    """
    base_url, username, password = _load_range_config(config_path, prefix)
    load_dotenv(config_path)
    host = os.getenv(f"{prefix}_HOST", "").strip()
    cookie = os.getenv(f"{prefix}_COOKIE", "").strip()
    return {
        "base_url": base_url.rstrip("/"),
        "username": username,
        "password": password,
        "host": host,
        "cookie": cookie,
    }


def _load_cmdi_config(config_path: str) -> dict[str, str]:
    """读取命令注入靶场配置（base_url / 账密 / 直连 Host+Cookie / 前缀模板）。"""
    cfg = _load_dvwa_waf_config(config_path, "RANGE_CMDI")
    load_dotenv(config_path)
    cfg["prefix"] = os.getenv("RANGE_CMDI_PREFIX", "").strip() or CMDI_PREFIX
    return cfg


# =============================================================================
# 命令注入（DVWA POST）
# =============================================================================

CMDI_PATH = "/vulnerabilities/exec/"
CMDI_FIELD = "ip"
CMDI_PREFIX = "-c 1 127.0.0.1;"


def run_command_injection(
    config_path: str,
    content: str,
    base: dict[str, Any],
    *,
    candidate_kind: str = "",
    delivery: str = "",
    verification_spec: dict[str, Any] | None = None,
    **_kwargs: Any,
) -> TargetEvidence:
    if not _is_delivery_compatible("command-injection", delivery):
        return _unsupported_context_evidence(
            "command-injection-dvwa",
            "command-injection",
            f"投递上下文 {delivery!r} 与命令注入靶场 POST 表单入口不兼容",
        )
    cfg = _load_cmdi_config(config_path)
    base_url = cfg["base_url"]
    if not base_url:
        return _error_evidence(
            "command-injection-dvwa",
            "command-injection",
            "命令注入靶场未配置（缺少 RANGE_CMDI_DVWA_BASE_URL）",
        )
    direct = bool(cfg["host"] and cfg["cookie"])
    if not direct and (not cfg["username"] or not cfg["password"]):
        return _error_evidence(
            "command-injection-dvwa",
            "command-injection",
            "命令注入靶场未配置（缺少 RANGE_DVWA_USERNAME / PASSWORD 或 RANGE_CMDI_HOST / COOKIE）",
        )
    if direct:
        # 套 WAF 的 DVWA：直连源站 IP + 自定义 Host 头 + 预置会话 Cookie，跳过登录。
        url = f"{base_url}{CMDI_PATH}"
        client = _dvwa_direct_client(base_url, cfg["host"], cfg["cookie"])
    else:
        # 普通 DVWA：账密登录获取会话；配置了 Host 则直连源站 + 自定义 Host 头。
        try:
            client, config = _dvwa_client(
                base_url, cfg["username"], cfg["password"], host=cfg["host"]
            )
        except Exception as exc:  # noqa: BLE001
            return _error_evidence("command-injection-dvwa", "command-injection", str(exc))
        url = same_origin(config, CMDI_PATH)
    try:
        prefix = cfg["prefix"]
        if candidate_kind in {"encoding_candidates", "cross_candidates"}:
            # 编码/交叉候选：已含 %HH 的 payload 原样入 ip 字段，不前置模板、不剥分隔符，
            # 用「只编码一次」传输避免二次 URL 编码导致靶场解析不出命令。
            body = f"ip={_encode_form_once(content)}&Submit=Submit"
            response = client.post(
                url,
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            sent_body = content
            request_summary = f"POST {CMDI_PATH} ip=<encoded payload>"
        else:
            # 语义候选：剥掉前导分隔符（; | & 等），避免与 prefix 的 `;` 拼成
            # `;;`（shell case 终止符，会导致命令不执行）。
            stripped = content.lstrip(";|&\r\n\t ")
            data = {CMDI_FIELD: f"{prefix}{stripped}", "Submit": "Submit"}
            response = client.post(url, data=data)
            sent_body = f"{prefix}{stripped}"
            request_summary = f"POST {CMDI_PATH} ip={prefix}{content}"
        result, evidence = classify(response, "命令注入请求已到达应用")
        if result == "application_response":
            result, evidence = verify_execution(response.text, verification_spec, content)
        return TargetEvidence(
            target_key="command-injection-dvwa",
            vulnerability="command-injection",
            request_summary=request_summary,
            http_status=response.status_code,
            response_excerpt=_excerpt(response.text),
            response_headers=_headers_text(response.headers),
            outcome=result,
            evidence=evidence,
            sent_body=sent_body,
            request_digest=_request_digest("POST", url, sent_body),
        )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("command-injection-dvwa", "command-injection", str(exc))
    finally:
        client.close()


# =============================================================================
# XSS（DVWA 反射型，Playwright 捕获 dialog；降级 httpx GET）
# =============================================================================

XSS_PATH = "/vulnerabilities/xss_r/"
XSS_FIELD = "name"


def run_xss(
    config_path: str,
    content: str,
    base: dict[str, Any],
    *,
    delivery: str = "",
    verification_spec: dict[str, Any] | None = None,
    **_kwargs: Any,
) -> TargetEvidence:
    if not _is_delivery_compatible("xss", delivery):
        return _unsupported_context_evidence(
            "xss-dvwa",
            "xss",
            f"投递上下文 {delivery!r} 与 XSS 靶场入口不兼容",
        )
    cfg = _load_dvwa_waf_config(config_path, "RANGE_XSS")
    base_url = cfg["base_url"]
    if not base_url:
        return _error_evidence(
            "xss-dvwa",
            "xss",
            "XSS 靶场未配置（缺少 RANGE_XSS_DVWA_BASE_URL）",
        )
    direct = bool(cfg["host"] and cfg["cookie"])
    if not direct and (not cfg["username"] or not cfg["password"]):
        return _error_evidence(
            "xss-dvwa",
            "xss",
            "XSS 靶场未配置（缺少 RANGE_DVWA_USERNAME / PASSWORD 或 RANGE_XSS_HOST / COOKIE）",
        )
    if direct:
        # 套 WAF 的 DVWA：直连源站 + 自定义 Host + 预置 Cookie，跳过登录/Playwright。
        return _run_xss_httpx_direct(base_url, cfg["host"], cfg["cookie"], content)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _run_xss_httpx(base_url, cfg["username"], cfg["password"], content, delivery)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            dialogs: list[str] = []
            page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
            page.goto(urljoin(f"{base_url}/", "/login.php"), wait_until="domcontentloaded")
            page.locator("input[name='username']").fill(cfg["username"])
            page.locator("input[name='password']").fill(cfg["password"])
            page.locator("input[type='submit']").click()
            page.goto(urljoin(f"{base_url}/", "/security.php"), wait_until="domcontentloaded")
            page.locator("select[name='security']").select_option("low")
            page.locator("input[name='seclev_submit']").click()
            page.goto(urljoin(f"{base_url}/", XSS_PATH), wait_until="domcontentloaded")
            field = page.locator("input[name='name']")
            if field.count():
                field.fill(content)
                page.locator("input[type='submit']").click()
                page.wait_for_timeout(500)
            html = page.content()
            browser.close()
        outcome = "execution_confirmed" if dialogs else "application_response"
        evidence = f"捕获到 XSS 对话框：{dialogs[0]}" if dialogs else "页面已返回，但未捕获 JavaScript 对话框"
        return TargetEvidence(
            target_key="xss-dvwa",
            vulnerability="xss",
            request_summary=f"GET {XSS_PATH}?{XSS_FIELD}=<payload>",
            http_status=200,
            response_excerpt=_excerpt(html),
            outcome=outcome,
            evidence=evidence,
            sent_body=content,
            request_digest=_request_digest("GET", urljoin(f"{base_url}/", XSS_PATH), content),
        )
    except Exception as exc:  # noqa: BLE001
        return _error_evidence("xss-dvwa", "xss", str(exc))


def _run_xss_playwright_direct(
    base_url: str, host: str, cookie: str, content: str
) -> tuple[str, str, str]:
    """套 WAF 的 XSS 执行验证：Playwright + host-resolver-rules 直连源站 IP。

    浏览器无法像 httpx 那样直接覆盖 Host 头，需用 ``--host-resolver-rules=MAP
    <host> <ip>`` 把域名解析指到源站 IP，从而发出「域名 Host 头 + 源站 IP」的
    请求，与 curl 直连行为一致。捕获 JS dialog 以确定性确认 XSS 执行。

    返回 ``(outcome, evidence, html)``；捕获到 dialog 即 ``execution_confirmed``。
    """
    from urllib.parse import urlparse

    ip = (urlparse(base_url).hostname or "").strip()
    if not ip:
        return "application_response", "直连源站 IP 解析失败，跳过浏览器执行验证", ""

    cookies: list[dict[str, str]] = []
    for part in (cookie or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        cookies.append(
            {"name": key.strip(), "value": value.strip(), "domain": host, "path": "/"}
        )

    url = f"http://{host}{XSS_PATH}?{XSS_FIELD}={_encode_form_once(content)}"
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "application_response", "未安装 Playwright，跳过浏览器执行验证", ""

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, args=[f"--host-resolver-rules=MAP {host} {ip}"]
        )
        context = browser.new_context()
        if cookies:
            context.add_cookies(cookies)
        page = context.new_page()
        dialogs: list[str] = []
        page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        html = page.content()
        browser.close()
    if dialogs:
        return "execution_confirmed", f"捕获到 XSS 对话框：{dialogs[0]}", html
    return "application_response", "页面已返回，但未捕获 JavaScript 对话框", html


def _run_xss_httpx_direct(base_url: str, host: str, cookie: str, content: str) -> TargetEvidence:
    """套 WAF 的 XSS 直连通道：GET 反射型，用预置 Cookie + 自定义 Host。

    先用 httpx 判绕过（403/拦截页快速短路）；放行后启动 Playwright 捕获 dialog
    以确定性确认 XSS 执行，实现「可绕过 + 可执行」闭环。
    """
    url = f"{base_url}{XSS_PATH}"
    try:
        client = _dvwa_direct_client(base_url, host, cookie)
    except Exception as exc:  # noqa: BLE001
        return _error_evidence("xss-dvwa", "xss", str(exc))
    try:
        response = client.get(url, params={XSS_FIELD: content})
        result, evidence = classify(response, "XSS 请求已到达应用（直连 + Host + Cookie）")
        outcome = result
        html = response.text
        # 放行时补一次浏览器执行验证；失败/无 Playwright 则降级为 httpx 判定。
        if result == "application_response":
            try:
                outcome, evidence, pw_html = _run_xss_playwright_direct(
                    base_url, host, cookie, content
                )
                if pw_html:
                    html = pw_html
            except Exception:  # noqa: BLE001
                pass
        return TargetEvidence(
            target_key="xss-dvwa",
            vulnerability="xss",
            request_summary=f"GET {XSS_PATH}?{XSS_FIELD}=<payload>  Host: {host}",
            http_status=response.status_code,
            response_excerpt=_excerpt(html),
            response_headers=_headers_text(response.headers),
            outcome=outcome,
            evidence=evidence,
            sent_body=content,
            request_digest=_request_digest("GET", url, content),
        )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("xss-dvwa", "xss", str(exc))
    finally:
        client.close()


def _run_xss_httpx(base_url: str, username: str, password: str, content: str, delivery: str = "") -> TargetEvidence:
    try:
        client, config = _dvwa_client(base_url, username, password)
    except Exception as exc:  # noqa: BLE001
        return _error_evidence("xss-dvwa", "xss", str(exc))
    try:
        url = same_origin(config, XSS_PATH)
        response = client.get(url, params={XSS_FIELD: content}, follow_redirects=False)
        result, evidence = classify(response, "XSS 请求已到达应用（降级 HTTP GET，未捕获 dialog）")
        return TargetEvidence(
            target_key="xss-dvwa",
            vulnerability="xss",
            request_summary=f"GET {XSS_PATH}?{XSS_FIELD}=<payload>",
            http_status=response.status_code,
            response_excerpt=_excerpt(response.text),
            response_headers=_headers_text(response.headers),
            outcome=result,
            evidence=evidence,
            sent_body=content,
            request_digest=_request_digest("GET", url, content),
        )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("xss-dvwa", "xss", str(exc))
    finally:
        client.close()


# =============================================================================
# SQL 注入（sqli-labs 多关卡路由）
# =============================================================================

# 注入类型 -> (默认 Less, 该类型的 Less 路由 {less: (path, param)})
# 基础 URL 由 RANGE_SQLI_BASE_URL 提供，不含 /Less-*。
LESS_ROUTES: dict[str, tuple[int, dict[int, tuple[str, str]]]] = {
    "union": (1, {1: ("/Less-1/", "id"), 2: ("/Less-2/", "id"), 3: ("/Less-3/", "id")}),
    "error": (1, {1: ("/Less-1/", "id"), 5: ("/Less-5/", "id"), 6: ("/Less-6/", "id")}),
    "boolean": (8, {8: ("/Less-8/", "id"), 11: ("/Less-11/", "uname"), 12: ("/Less-12/", "uname")}),
    "time": (9, {9: ("/Less-9/", "id"), 10: ("/Less-10/", "id")}),
    "stacked": (38, {38: ("/Less-38/", "id")}),
}

_SQL_UNION = re.compile(r"\bUNION\b", re.IGNORECASE)
_SQL_TIME = re.compile(r"\bSLEEP\b|\bBENCHMARK\b|\bpg_sleep\b|\bWAITFOR\b", re.IGNORECASE)
_SQL_BOOL = re.compile(r"\bIF\s*\(|\bAND\b|\bOR\b|/\*|\*/|--", re.IGNORECASE)
_SQL_STACKED = re.compile(r";\s*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b", re.IGNORECASE)


def classify_sqli_injection_type(content: str) -> str:
    """确定性判断 SQL 注入类型，用于选择 sqli-labs 关卡。"""
    if _SQL_UNION.search(content):
        return "union"
    if _SQL_TIME.search(content):
        return "time"
    if _SQL_STACKED.search(content):
        return "stacked"
    if _SQL_BOOL.search(content):
        return "boolean"
    return "union"


def _pick_lesson(injection_type: str, lesson_hint: Any = None) -> int:
    if isinstance(lesson_hint, int) and lesson_hint > 0:
        return lesson_hint
    return LESS_ROUTES.get(injection_type, ("union", {}))[0]


def run_sqli(
    config_path: str,
    content: str,
    base: dict[str, Any],
    *,
    lesson_hint: Any = None,
    delivery: str = "",
    verification_spec: dict[str, Any] | None = None,
    **_kwargs: Any,
) -> TargetEvidence:
    if not _is_delivery_compatible("sql-injection", delivery):
        return _unsupported_context_evidence(
            "sqli-labs",
            "sql-injection",
            f"投递上下文 {delivery!r} 与 SQL 靶场入口不兼容",
        )
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_SQLI_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        return _error_evidence(
            "sqli-labs",
            "sql-injection",
            "SQL 靶场未配置（缺少 RANGE_SQLI_BASE_URL）",
        )
    host = os.getenv("RANGE_SQLI_HOST", "").strip()
    injection_type = classify_sqli_injection_type(content)
    lesson = _pick_lesson(injection_type, lesson_hint)
    path, param = LESS_ROUTES.get(injection_type, LESS_ROUTES["union"])[1].get(
        lesson, (f"/Less-{lesson}/", "id")
    )
    url = f"{base_url}{path}"
    timeout = httpx.Timeout(20, connect=5)
    headers = {"User-Agent": "WAFByPasser-Verify/1.0"}
    if host:
        headers["Host"] = host
    try:
        with httpx.Client(timeout=timeout, headers=headers) as client:
            baseline = client.get(url, params={param: "1"}, follow_redirects=False)
            response = client.get(url, params={param: content}, follow_redirects=False)
            result, evidence = classify(response, "SQL 请求已到达 sqli-labs 应用")
            return TargetEvidence(
                target_key="sqli-labs",
                vulnerability="sql-injection",
                request_summary=f"GET {url}?{param}=<payload> (Less-{lesson}, type={injection_type})",
                http_status=response.status_code,
                response_excerpt=_excerpt(response.text),
                response_headers=_headers_text(response.headers),
                outcome=result,
                evidence=evidence,
                baseline_excerpt=_excerpt(baseline.text),
                sent_body=content,
                request_digest=_request_digest("GET", url, content),
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("sqli-labs", "sql-injection", str(exc))


# =============================================================================
# log4j2（Solr action 参数，仅判绕过，执行需人工验证）
# =============================================================================

# 注意：/solr/admin/cores 这条路径被腾讯云 WAF 整体封禁（连基线 action=STATUS 也 403），
# 无法用于「绕过 vs 拦截」判定。改用 /solr/admin/info/system（基线放行、jndi 按内容拦截）。
LOG4J_PATH = "/solr/admin/info/system"
LOG4J_PARAM = "action"


def run_log4j(
    config_path: str,
    content: str,
    base: dict[str, Any],
    *,
    delivery: str = "",
    verification_spec: dict[str, Any] | None = None,
    **_kwargs: Any,
) -> TargetEvidence:
    if not _is_delivery_compatible("log4j", delivery):
        return _unsupported_context_evidence(
            "log4j-solr",
            "log4j",
            f"投递上下文 {delivery!r} 与 log4j 靶场入口不兼容",
        )
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_LOG4J_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        return _error_evidence(
            "log4j-solr",
            "log4j",
            "log4j 靶场未配置（缺少 RANGE_LOG4J_BASE_URL）",
        )
    host = os.getenv("RANGE_LOG4J_HOST", "").strip()
    url = f"{base_url}{LOG4J_PATH}"
    headers = {"User-Agent": "WAFByPasser-Verify/1.0"}
    if host:
        headers["Host"] = host
    try:
        with httpx.Client(
            timeout=httpx.Timeout(20, connect=5),
            headers=headers,
        ) as client:
            response = client.get(url, params={LOG4J_PARAM: content}, follow_redirects=False)
            result, evidence = classify(response, "log4j 请求已到达 Solr 应用")
            # log4j2 的 jndi 触发需 OOB 回调，单靠 HTTP 响应无法确认执行。
            # 这里只判「绕过成功/失败」；执行结果交由人工验证。
            return TargetEvidence(
                target_key="log4j-solr",
                vulnerability="log4j",
                request_summary=f"GET {url}?{LOG4J_PARAM}=<payload>",
                http_status=response.status_code,
                response_excerpt=_excerpt(response.text),
                response_headers=_headers_text(response.headers),
                outcome=result,
                evidence=evidence,
                sent_body=content,
                request_digest=_request_digest("GET", url, content),
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("log4j-solr", "log4j", str(exc))


# =============================================================================
# file-upload（upload-labs：php 8005 + jsp 8007，上传 + 访问确认执行）
# =============================================================================

# jsp 关卡 → 上传接口路径（POST multipart，字段名 `file`，回显「上传成功: uploads/<文件名>」）
PASS_ROUTES: dict[int, str] = {
    1: "/pass01.jsp", 2: "/pass02.jsp", 3: "/pass03.jsp", 4: "/pass04.jsp",
    5: "/pass05.jsp", 6: "/pass06.jsp", 7: "/pass07.jsp", 8: "/pass08.jsp",
    9: "/pass09.jsp", 10: "/pass10.jsp",
}
# php 关卡 → 上传接口路径（POST multipart，字段名 `upload_file`）
PHP_PASS_ROUTES: dict[int, str] = {
    n: f"/Pass-{n:02d}/index.php" for n in range(1, 21)
}
DEFAULT_PASS = 1
JSP_UPLOAD_ACCESS_SUBDIR = "/uploads"
PHP_UPLOAD_ACCESS_SUBDIR = "/upload"
JSP_UPLOAD_FILE_FIELD = "file"
PHP_UPLOAD_FILE_FIELD = "upload_file"
DEFAULT_JSP_UPLOAD_FILENAME = "shell.jsp"
DEFAULT_PHP_UPLOAD_FILENAME = "shell.php"

# 判定上传「成功」的回显特征（jsp 回显「上传成功: uploads/...」；php 回显图片路径）
_UPLOAD_SUCCESS_MARKERS = ("上传成功", "uploads/", "/upload/")

# 判定 payload 语言的确定性特征：PHP webshell 通常含 `<?php` / `<?=`；
# JSP webshell 通常含 `<%` / `%>` 或 ProcessBuilder/Runtime。
_PHP_WEBSHELL_RE = re.compile(r"<\?php|<\?=", re.IGNORECASE)
_JSP_WEBSHELL_RE = re.compile(r"<%|ProcessBuilder|Runtime\.getRuntime|\.jspx", re.IGNORECASE)


def _upload_language(content: str) -> str:
    """根据 payload 内容确定上传靶场语言：php / jsp。"""
    if _PHP_WEBSHELL_RE.search(content):
        return "php"
    if _JSP_WEBSHELL_RE.search(content):
        return "jsp"
    # 无法确定性判断时按扩展名/内容兜底：默认 jsp（历史 upload 靶场即 jsp）。
    return "jsp"


def _pick_upload_pass(content: str, language: str, lesson_hint: Any = None) -> int:
    """根据 payload 内容启发式判断上传关卡；lesson_hint 优先。

    php upload-labs 1–20 关；jsp upload-labs 1–10 关。
    """
    routes = PHP_PASS_ROUTES if language == "php" else PASS_ROUTES
    if isinstance(lesson_hint, int) and lesson_hint in routes:
        return lesson_hint
    lower = content.lower()
    if language == "jsp":
        if "processbuilder" in lower or "runtime" in lower:
            return 6
        if ".jspx" in lower:
            return 3
    else:
        # php upload-labs 关卡启发：文件名后缀 / 内容过滤等，默认 Pass-01。
        if ".phtml" in lower or ".pht" in lower:
            return 3
    return DEFAULT_PASS


def _run_upload_target(
    config_path: str,
    content: str,
    base: dict[str, Any],
    *,
    language: str,
    lesson_hint: Any = None,
    delivery: str = "",
    verification_spec: dict[str, Any] | None = None,
) -> TargetEvidence:
    target_key = "file-upload-php" if language == "php" else "file-upload-jsp"
    if not _is_delivery_compatible("file-upload", delivery):
        return _unsupported_context_evidence(
            target_key, "file-upload",
            f"投递上下文 {delivery!r} 与文件上传靶场入口不兼容",
        )
    load_dotenv(config_path)
    if language == "php":
        base_url = os.getenv("RANGE_UPLOAD_PHP_BASE_URL", "").strip().rstrip("/")
        host = os.getenv("RANGE_UPLOAD_PHP_HOST", "").strip()
        field = os.getenv("RANGE_UPLOAD_PHP_FILE_FIELD", PHP_UPLOAD_FILE_FIELD)
        filename = os.getenv("RANGE_UPLOAD_PHP_FILENAME", DEFAULT_PHP_UPLOAD_FILENAME)
        access_subdir = PHP_UPLOAD_ACCESS_SUBDIR
        routes = PHP_PASS_ROUTES
        env_missing = "文件上传（php）靶场未配置（缺少 RANGE_UPLOAD_PHP_BASE_URL）"
    else:
        base_url = os.getenv("RANGE_UPLOAD_JSP_BASE_URL", "").strip().rstrip("/")
        host = os.getenv("RANGE_UPLOAD_JSP_HOST", "").strip()
        field = os.getenv("RANGE_UPLOAD_JSP_FILE_FIELD", JSP_UPLOAD_FILE_FIELD)
        filename = os.getenv("RANGE_UPLOAD_JSP_FILENAME", DEFAULT_JSP_UPLOAD_FILENAME)
        access_subdir = JSP_UPLOAD_ACCESS_SUBDIR
        routes = PASS_ROUTES
        env_missing = "文件上传（jsp）靶场未配置（缺少 RANGE_UPLOAD_JSP_BASE_URL）"
    if not base_url:
        return _error_evidence(target_key, "file-upload", env_missing)
    lesson = _pick_upload_pass(content, language, lesson_hint)
    upload_path = routes[lesson]
    access_url = f"{base_url}{access_subdir}/{filename}"
    headers = {"User-Agent": "WAFByPasser-Verify/1.0"}
    if host:
        headers["Host"] = host

    try:
        with httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=headers) as client:
            # 1. multipart 上传 webshell 到对应关卡
            upload_response = client.post(
                f"{base_url}{upload_path}",
                files={field: (filename, content.encode("utf-8"), "application/octet-stream")},
                follow_redirects=False,
            )
            result, evidence = classify(upload_response, "文件上传请求已到达应用")
            if result != "application_response":
                return TargetEvidence(
                    target_key=target_key,
                    vulnerability="file-upload",
                    request_summary=f"POST {base_url}{upload_path} file={filename}",
                    http_status=upload_response.status_code,
                    response_excerpt=_excerpt(upload_response.text),
                    response_headers=_headers_text(upload_response.headers),
                    outcome=result,
                    evidence=evidence,
                    sent_body=content,
                    request_digest=_request_digest("POST", f"{base_url}{upload_path}", content),
                )

            # 2. 上传回显成功特征才继续访问确认执行；否则视为验证失败
            upload_body = upload_response.text
            if not any(marker in upload_body for marker in _UPLOAD_SUCCESS_MARKERS):
                return TargetEvidence(
                    target_key=target_key,
                    vulnerability="file-upload",
                    request_summary=f"POST {base_url}{upload_path} file={filename}",
                    http_status=upload_response.status_code,
                    response_excerpt=_excerpt(upload_body),
                    response_headers=_headers_text(upload_response.headers),
                    outcome="application_response",
                    evidence=f"上传未成功（关卡 pass{lesson:02d}）：{_excerpt(upload_body, 200)}",
                    sent_body=content,
                    request_digest=_request_digest("POST", f"{base_url}{upload_path}", content),
                )

            # 3. 访问上传后的文件，确认可执行。仅访问响应命中确定性 marker/regex 才算确认。
            access_response = client.get(access_url, follow_redirects=False)
            access_result, access_evidence = classify(access_response, "已访问上传后的文件")
            outcome = access_result
            if access_result == "application_response" and verification_spec:
                outcome, access_evidence = verify_execution(
                    access_response.text, verification_spec, content
                )
            evidence = (
                f"上传成功（pass{lesson:02d}）；访问 {access_url} 结果：{access_evidence}"
                if outcome == "application_response"
                else access_evidence
            )
            return TargetEvidence(
                target_key=target_key,
                vulnerability="file-upload",
                request_summary=f"POST {base_url}{upload_path} file={filename}；GET {access_url}",
                http_status=access_response.status_code,
                response_excerpt=_excerpt(access_response.text),
                response_headers=_headers_text(access_response.headers),
                outcome=outcome,
                evidence=evidence,
                baseline_excerpt=_excerpt(upload_body),
                sent_body=content,
                request_digest=_request_digest("GET", access_url, content),
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence(target_key, "file-upload", str(exc))


def run_file_upload(
    config_path: str,
    content: str,
    base: dict[str, Any],
    *,
    lesson_hint: Any = None,
    delivery: str = "",
    verification_spec: dict[str, Any] | None = None,
    **_kwargs: Any,
) -> TargetEvidence:
    """文件上传：按 payload 语言路由到 php（8005）或 jsp（8007）upload-labs 靶场。"""
    language = _upload_language(content)
    return _run_upload_target(
        config_path,
        content,
        base,
        language=language,
        lesson_hint=lesson_hint,
        delivery=delivery,
        verification_spec=verification_spec,
    )


# =============================================================================
# 注册表
# =============================================================================

def _error_evidence(target_key: str, vulnerability: str, message: str) -> TargetEvidence:
    return TargetEvidence(
        target_key=target_key,
        vulnerability=vulnerability,
        request_summary="",
        http_status=0,
        response_excerpt="",
        outcome="request_error",
        evidence=message,
    )


def _unsupported_context_evidence(target_key: str, vulnerability: str, message: str) -> TargetEvidence:
    return TargetEvidence(
        target_key=target_key,
        vulnerability=vulnerability,
        request_summary="",
        http_status=0,
        response_excerpt="",
        outcome="unsupported_context",
        evidence=message,
    )


ADAPTERS: dict[str, AdapterFn] = {
    "command-injection": run_command_injection,
    "xss": run_xss,
    "sql-injection": run_sqli,
    "log4j": run_log4j,
    "file-upload": run_file_upload,
}

# 每个漏洞类型的默认靶场 key（未来多靶场时可按需扩展）。
DEFAULT_RANGE: dict[str, str] = {
    "command-injection": "command-injection-dvwa",
    "xss": "xss-dvwa",
    "sql-injection": "sqli-labs",
    "log4j": "log4j-solr",
    "file-upload": "file-upload",
}


def _cmdi_target(config_path: str) -> dict[str, Any]:
    cfg = _load_cmdi_config(config_path)
    base_url = cfg["base_url"]
    configured = bool(
        base_url
        and (
            (cfg["host"] and cfg["cookie"])
            or (cfg["username"] and cfg["password"])
        )
    )
    return {
        "key": "command-injection-dvwa",
        "label": "命令注入靶场（DVWA）",
        "vulnerability": "command-injection",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": configured,
        "method": "POST",
        "injection_point": f"/vulnerabilities/exec/  ip={CMDI_PREFIX}<payload>",
    }


def _xss_target(config_path: str) -> dict[str, Any]:
    cfg = _load_dvwa_waf_config(config_path, "RANGE_XSS")
    base_url = cfg["base_url"]
    configured = bool(
        base_url
        and (
            (cfg["host"] and cfg["cookie"])
            or (cfg["username"] and cfg["password"])
        )
    )
    return {
        "key": "xss-dvwa",
        "label": "XSS 靶场（DVWA）",
        "vulnerability": "xss",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": configured,
        "method": "GET",
        "injection_point": f"/vulnerabilities/xss_r/?name=<payload>",
    }


def _sqli_target(config_path: str) -> dict[str, Any]:
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_SQLI_BASE_URL", "").strip().rstrip("/")
    return {
        "key": "sqli-labs",
        "label": "SQL 注入靶场（sqli-labs）",
        "vulnerability": "sql-injection",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": bool(base_url),
        "method": "GET",
        "injection_point": f"/Less-N/?id=<payload>",
    }


def _log4j_target(config_path: str) -> dict[str, Any]:
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_LOG4J_BASE_URL", "").strip().rstrip("/")
    return {
        "key": "log4j-solr",
        "label": "log4j2 靶场（Solr）",
        "vulnerability": "log4j",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": bool(base_url),
        "method": "GET",
        "injection_point": f"/solr/admin/info/system?action=<payload>",
    }


def _upload_target(config_path: str) -> dict[str, Any]:
    load_dotenv(config_path)
    php_url = os.getenv("RANGE_UPLOAD_PHP_BASE_URL", "").strip().rstrip("/")
    jsp_url = os.getenv("RANGE_UPLOAD_JSP_BASE_URL", "").strip().rstrip("/")
    configured = bool(php_url or jsp_url)
    base_url = jsp_url or php_url
    return {
        "key": "file-upload",
        "label": "文件上传靶场（PHP + JSP）",
        "vulnerability": "file-upload",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": configured,
        "method": "POST",
        "injection_point": "php=/Pass-NN/index.php file=<shell.php>；jsp=/passNN.jsp file=<shell.jsp>（按 payload 语言路由）",
    }


# 靶场注册表：key → 元信息提供函数（惰性读取 .env，避免导入期依赖 config）。
TARGET_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {
    "command-injection-dvwa": _cmdi_target,
    "xss-dvwa": _xss_target,
    "sqli-labs": _sqli_target,
    "log4j-solr": _log4j_target,
    "file-upload": _upload_target,
}


def verification_targets(config_path: str) -> list[dict[str, Any]]:
    """返回所有已注册检验靶场的元信息（供前端靶场页展示）。"""
    return [provider(config_path) for provider in TARGET_REGISTRY.values()]


# 靶场 key -> 漏洞类型（用于校验任务快照中的 target_key 是否匹配）。
TARGET_KEY_VULNERABILITY: dict[str, str] = {
    "command-injection-dvwa": "command-injection",
    "xss-dvwa": "xss",
    "sqli-labs": "sql-injection",
    "log4j-solr": "log4j",
    "file-upload": "file-upload",
    "file-upload-php": "file-upload",
    "file-upload-jsp": "file-upload",
}


def resolve_adapter(vulnerability: str, target_key: str = "") -> tuple[str, AdapterFn]:
    """解析漏洞类型到 adapter 函数；未知类型抛 ValueError。

    若提供的 target_key 与其漏洞类型不匹配，则回退到该漏洞类型的默认靶场。
    """
    adapter = ADAPTERS.get(vulnerability)
    if adapter is None:
        raise ValueError(f"暂不支持对漏洞类型 {vulnerability} 的自动检验")
    if target_key and TARGET_KEY_VULNERABILITY.get(target_key) != vulnerability:
        target_key = ""
    key = target_key or DEFAULT_RANGE.get(vulnerability, vulnerability)
    return key, adapter
