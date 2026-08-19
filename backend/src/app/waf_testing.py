"""Strictly scoped WAF test runners.

DVWA + SafeLine:  form-based with login/session management.
Tencent Cloud WAF: direct HTTP request with custom Host header.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx
from dotenv import load_dotenv


SUPPORTED = {
    "command-injection": "/vulnerabilities/exec/",
    "sql-injection": "/vulnerabilities/sqli/",
    "xss": "/vulnerabilities/xss_r/",
}
# Separate registry for direct-URL WAF targets (non-DVWA)
DIRECT_WAF_TARGETS: dict[str, dict[str, str]] = {
    "tencent-waf": {
        "label": "腾讯云 WAF",
        "description": "直接 URL 请求 + 自定义 Host 头，200=放行，403=拦截",
    },
}
BLOCK_STATUSES = {403, 406, 429}
BLOCK_MARKERS = ("safeline", "waf blocked", "access denied", "request blocked")


@dataclass(frozen=True)
class WafConfig:
    base_url: str
    username: str
    password: str


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self.current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.current = {"action": values.get("action", ""), "method": values.get("method", "get").lower(), "inputs": []}
        elif tag in {"input", "textarea", "select"} and self.current is not None and values.get("name"):
            self.current["inputs"].append(values["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


def load_config(config_path: str) -> WafConfig:
    load_dotenv(config_path)
    base_url = os.getenv("WAF_DVWA_BASE_URL", "").rstrip("/")
    username = os.getenv("WAF_DVWA_USERNAME", "")
    password = os.getenv("WAF_DVWA_PASSWORD", "")
    if not base_url or not username or not password:
        raise RuntimeError("WAF 测试场配置不完整，请填写 WAF_DVWA_BASE_URL、USERNAME 和 PASSWORD")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("WAF_DVWA_BASE_URL 必须是完整 HTTP(S) 地址")
    return WafConfig(base_url=base_url, username=username, password=password)


def same_origin(config: WafConfig, url: str) -> str:
    resolved = urljoin(f"{config.base_url}/", url)
    base = urlparse(config.base_url)
    target = urlparse(resolved)
    if (target.scheme, target.netloc) != (base.scheme, base.netloc):
        raise RuntimeError("测试场拒绝跨源跳转")
    return resolved


def _request(client: httpx.Client, config: WafConfig, method: str, url: str, **kwargs: object) -> httpx.Response:
    response = client.request(method, same_origin(config, url), follow_redirects=False, **kwargs)
    if response.is_redirect:
        location = response.headers.get("location", "")
        same_origin(config, location)
        response = client.request("GET", same_origin(config, location), follow_redirects=False)
    return response


def login(client: httpx.Client, config: WafConfig) -> None:
    page = _request(client, config, "GET", "/login.php")
    if page.status_code != 200:
        raise RuntimeError(f"DVWA 登录页不可用（HTTP {page.status_code}）")
    token = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", page.text, re.I)
    data = {"username": config.username, "password": config.password, "Login": "Login"}
    if token:
        data["user_token"] = token.group(1)
    response = _request(client, config, "POST", "/login.php", data=data)
    if response.status_code >= 400 or "login.php" in response.headers.get("location", ""):
        raise RuntimeError("DVWA 登录失败，请检查账号、密码或雷池策略")


def security_is_low(html: str) -> bool:
    return bool(
        re.search(r"Security level is currently:\s*<em>\s*low\s*</em>", html, re.I)
        or re.search(r"<option\b[^>]*value=['\"]low['\"][^>]*selected", html, re.I)
        or re.search(r"<option\b[^>]*selected[^>]*value=['\"]low['\"]", html, re.I)
    )


def ensure_low_security(client: httpx.Client, config: WafConfig) -> None:
    """Set Low only inside this backend-owned DVWA session, then verify it."""
    page = _request(client, config, "GET", "/security.php")
    if page.status_code != 200:
        raise RuntimeError(f"DVWA security 页面不可用（HTTP {page.status_code}）")
    token = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", page.text, re.I)
    data = {"security": "low", "seclev_submit": "Submit"}
    if token:
        data["user_token"] = token.group(1)
    updated = _request(client, config, "POST", "/security.php", data=data)
    confirmed = _request(client, config, "GET", "/security.php")
    if updated.status_code >= 400 or not security_is_low(confirmed.text):
        raise RuntimeError("后端 DVWA 会话无法设置为 Low，请检查雷池策略或 DVWA 配置")


def parse_target_form(html: str, vulnerability: str) -> dict[str, object]:
    parser = FormParser()
    parser.feed(html)
    expected = {"command-injection": "ip", "sql-injection": "id", "xss": "name"}[vulnerability]
    for form in parser.forms:
        if expected in form["inputs"]:
            return form
    raise RuntimeError(f"未找到 DVWA {vulnerability} 的预期输入字段 {expected}")


def preflight(config_path: str) -> dict[str, object]:
    config = load_config(config_path)
    timeout = httpx.Timeout(20, connect=5)
    with httpx.Client(timeout=timeout, headers={"User-Agent": "WAFByPasser-DVWA-Test/1.0"}) as client:
        login(client, config)
        ensure_low_security(client, config)
        mappings: dict[str, object] = {}
        for vulnerability, path in SUPPORTED.items():
            response = _request(client, config, "GET", path)
            if response.status_code != 200:
                raise RuntimeError(f"DVWA {vulnerability} 页面不可用（HTTP {response.status_code}）")
            form = parse_target_form(response.text, vulnerability)
            mappings[vulnerability] = {"path": path, "method": form["method"], "field": {"command-injection": "ip", "sql-injection": "id", "xss": "name"}[vulnerability]}
    return {"configured": True, "base_url": config.base_url, "security": "low", "mappings": mappings}


def classify(response: httpx.Response, evidence: str = "") -> tuple[str, str]:
    body = response.text.lower()
    if response.status_code in BLOCK_STATUSES or any(marker in body for marker in BLOCK_MARKERS):
        return "waf_blocked", f"HTTP {response.status_code}；检测到 WAF 拦截特征"
    if response.status_code >= 400:
        return "request_error", f"HTTP {response.status_code}"
    return "application_response", evidence or f"HTTP {response.status_code}，已获得应用响应"


# Legacy marker pattern for backward-compatible *_OK detection
_LEGACY_MARKER_RE = re.compile(r"[A-Z][A-Z0-9_]{2,}_OK")


def verify_execution(
    response_text: str,
    verification_spec: dict | None,
    content: str,
) -> tuple[str, str]:
    """Verify code execution using structured verification spec.

    Prioritises structured spec over legacy marker detection.

    Returns (result, evidence) tuple.
      - result is one of: "execution_confirmed", "application_response"
      - evidence is a human-readable description
    """
    # 1. Structured verification spec (from execution goal catalog)
    if verification_spec and isinstance(verification_spec, dict):
        spec_type = verification_spec.get("type")

        if spec_type == "marker":
            marker = verification_spec.get("marker", "")
            if marker and marker in response_text:
                return (
                    "execution_confirmed",
                    f"结构化验证通过：响应中发现标记 {marker}",
                )
            return (
                "application_response",
                f"结构化验证未通过：响应中未发现预期标记 {marker}",
            )

        if spec_type == "regex":
            pattern = verification_spec.get("pattern", "")
            if pattern and re.search(pattern, response_text):
                return (
                    "execution_confirmed",
                    f"结构化验证通过：响应匹配模式 {pattern}",
                )
            return (
                "application_response",
                f"结构化验证未通过：响应不匹配模式 {pattern}",
            )

        if spec_type == "combo":
            marker = verification_spec.get("marker", "")
            pattern = verification_spec.get("pattern", "")
            marker_ok = marker in response_text if marker else True
            regex_ok = bool(re.search(pattern, response_text)) if pattern else True
            if marker_ok and regex_ok:
                return (
                    "execution_confirmed",
                    f"组合验证通过 (marker={'OK' if marker_ok else 'N/A'}, regex={'OK' if regex_ok else 'N/A'})",
                )
            return (
                "application_response",
                f"组合验证未通过 (marker={'OK' if marker_ok else 'FAIL'}, regex={'OK' if regex_ok else 'FAIL'})",
            )

    # 2. Legacy fallback: *_OK marker detection
    marker = _LEGACY_MARKER_RE.search(content)
    if marker and marker.group(0) in response_text:
        return (
            "execution_confirmed",
            f"Legacy 回显标记检测：{marker.group(0)}",
        )

    return ("application_response", "已获得应用响应，但未匹配任何验证规则")


def run_http_test(
    config_path: str,
    vulnerability: str,
    content: str,
    verification_spec: dict | None = None,
) -> dict[str, object]:
    config = load_config(config_path)
    if vulnerability not in {"command-injection", "sql-injection"}:
        raise RuntimeError("该漏洞类型必须使用浏览器执行器")
    field = "ip" if vulnerability == "command-injection" else "id"
    timeout = httpx.Timeout(20, connect=5)
    with httpx.Client(timeout=timeout, headers={"User-Agent": "WAFByPasser-DVWA-Test/1.0"}) as client:
        login(client, config)
        ensure_low_security(client, config)
        page = _request(client, config, "GET", SUPPORTED[vulnerability])
        parse_target_form(page.text, vulnerability)
        if vulnerability == "command-injection":
            response = _request(client, config, "POST", SUPPORTED[vulnerability], data={field: content, "Submit": "Submit"})
            result, evidence = classify(response, "命令注入请求已到达应用")
            if result == "application_response":
                result, evidence = verify_execution(response.text, verification_spec, content)
        else:
            baseline = _request(client, config, "GET", SUPPORTED[vulnerability], params={field: "1", "Submit": "Submit"})
            response = _request(client, config, "GET", SUPPORTED[vulnerability], params={field: content, "Submit": "Submit"})
            result, evidence = classify(response)
            if result == "application_response":
                evidence = "已获得应用响应；与基线响应{}。需人工确认 SQL 注入是否成功".format("不同" if response.text != baseline.text else "相同")
        return {"result": result, "evidence": evidence, "http_status": response.status_code, "response_excerpt": response.text[:4000], "request_summary": f"{field}={content}"}


def run_xss_test(config_path: str, content: str) -> dict[str, object]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise RuntimeError("未安装 Playwright；请安装依赖并执行 playwright install chromium") from error
    config = load_config(config_path)
    dialogs: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
        page.goto(same_origin(config, "/login.php"), wait_until="domcontentloaded")
        page.locator("input[name='username']").fill(config.username)
        page.locator("input[name='password']").fill(config.password)
        page.locator("input[type='submit']").click()
        page.goto(same_origin(config, "/security.php"), wait_until="domcontentloaded")
        page.locator("select[name='security']").select_option("low")
        page.locator("input[name='seclev_submit']").click()
        page.goto(same_origin(config, "/security.php"), wait_until="domcontentloaded")
        if "security level is currently: <em>low</em>" not in page.content().lower():
            browser.close()
            raise RuntimeError("浏览器 DVWA 会话无法设置为 Low")
        page.goto(same_origin(config, SUPPORTED["xss"]), wait_until="domcontentloaded")
        field = page.locator("input[name='name']")
        if not field.count():
            browser.close()
            raise RuntimeError("未找到 DVWA XSS 预期 name 字段")
        field.fill(content)
        page.locator("input[type='submit']").click()
        page.wait_for_timeout(500)
        html = page.content()
        browser.close()
    result = "execution_confirmed" if dialogs else "application_response"
    evidence = f"捕获到 XSS 对话框：{dialogs[0]}" if dialogs else "页面已返回，但未捕获 JavaScript 对话框；需人工确认"
    return {"result": result, "evidence": evidence, "http_status": 200, "response_excerpt": html[:4000], "request_summary": "name=<候选内容>"}


# =============================================================================
# Tencent Cloud WAF — direct HTTP test (no DVWA dependency)
# =============================================================================

@dataclass(frozen=True)
class TencentWafConfig:
    """Configuration for Tencent Cloud WAF direct-URL testing.

    Requests are sent to ``http://{ip}/{payload}`` with ``Host: {host}``.
    """

    ip: str
    host: str


def load_tencent_waf_config(config_path: str) -> TencentWafConfig | None:
    """Load Tencent Cloud WAF configuration from .env.

    Returns None when the env vars are not set (target not configured yet).
    """
    load_dotenv(config_path)
    ip = os.getenv("TENCENT_WAF_IP", "").strip()
    host = os.getenv("TENCENT_WAF_HOST", "").strip()
    if not ip or not host:
        return None
    parsed = urlparse(f"http://{ip}")
    if not parsed.netloc:
        raise RuntimeError("TENCENT_WAF_IP 格式无效，请填写 IP 地址或域名")
    return TencentWafConfig(ip=ip, host=host)


# Tencent Cloud WAF 拦截页的特征字符串。腾讯云 WAF 在部分策略下会用
# HTTP 200 回一个"访问拦截"的 block-page，所以仅凭状态码不能判定放行，
# 必须先扫响应体。
_TENCENT_BLOCK_MARKERS = (
    "腾讯云waf",
    "访问拦截",
    "web应用防护",
    "web应用防护服务",
    "您提交的请求可能对网站造成威胁",
    "无法访问",
    "cos.accelerate.myqcloud.com/block-pages",
    "block-pages/static",
)


def _classify_tencent_response(response: httpx.Response) -> tuple[str, str]:
    """Classify a Tencent WAF test response.

    Returns (result, evidence):
      - 'waf_bypassed'  – 无拦截页特征、状态码正常
      - 'waf_blocked'   – 状态码或响应体命中 WAF 拦截特征
      - 'request_error'  – 其它错误
      - 'unknown'        – 无法判定
    """
    status = response.status_code
    body = response.text[:4000].lower() if response.text else ""

    # 1. Body 特征优先——Tencent WAF 会用 200 送 block-page，状态码不可信
    if any(marker in body for marker in _TENCENT_BLOCK_MARKERS):
        return ("waf_blocked", f"HTTP {status}，响应体命中 Tencent WAF 拦截页特征")
    if any(marker in body for marker in BLOCK_MARKERS):
        return ("waf_blocked", f"HTTP {status}，响应体含通用 WAF 拦截特征")

    # 2. 状态码显式拦截
    if status in BLOCK_STATUSES:
        return ("waf_blocked", f"HTTP {status} — WAF 拦截")

    # 3. 到这一步 body 干净，状态码也不是拦截码，才认为是真放行
    if status == 200:
        return ("waf_bypassed", "HTTP 200 且响应体无拦截页特征 — WAF 放行")

    if status >= 400:
        return ("request_error", f"HTTP {status} — 请求异常或后端拒绝")

    return ("unknown", f"HTTP {status}")


# RFC 3986 pchar: unreserved + sub-delims + ":" + "@" + "/"
# Matches what curl leaves unencoded in a URL path — anything outside
# this set (spaces, `\`, `|`, `<`, `>`, `?`, `#`, `"`, control bytes …)
# gets percent-encoded. Existing %XX sequences from the encoding agent
# are preserved verbatim so their bypass intent is not corrupted.
_PATH_SAFE = "/!$&'()*+,;=:@"
_EXISTING_PCT = re.compile(r"%[0-9a-fA-F]{2}")


def _percent_encode_path(payload: str) -> str:
    parts: list[str] = []
    cursor = 0
    for match in _EXISTING_PCT.finditer(payload):
        if match.start() > cursor:
            parts.append(quote(payload[cursor:match.start()], safe=_PATH_SAFE))
        parts.append(match.group(0).upper())
        cursor = match.end()
    if cursor < len(payload):
        parts.append(quote(payload[cursor:], safe=_PATH_SAFE))
    return "".join(parts)


def run_tencent_waf_test(
    config_path: str,
    content: str,
    *,
    delivery: str = "",
    vulnerability: str = "",
) -> dict[str, Any]:
    """Send a payload to the Tencent Cloud WAF and classify the result.

    The payload (``content``) is placed into the URL path after a leading ``/``.
    A custom ``Host`` header is sent so the WAF routes to the right virtual
    host.  No session, login or form logic is needed.

    Returns the standard outcome dict with result/evidence/http_status/...
    """
    config = load_tencent_waf_config(config_path)
    if not config:
        return {
            "result": "request_error",
            "evidence": "腾讯云 WAF 未配置（缺少 TENCENT_WAF_IP / TENCENT_WAF_HOST）",
            "http_status": 0,
            "response_excerpt": "",
            "request_summary": "",
        }

    # Strip leading / if any (content may already have a path separator)
    payload_path = content.lstrip("/")

    # Percent-encode unsafe characters so the tool's request matches what
    # curl/browsers send. Preserves existing %XX from the encoding agent.
    payload_path = _percent_encode_path(payload_path)

    url = f"http://{config.ip}/{payload_path}"
    headers = {
        "Host": config.host,
        "User-Agent": "WAFByPasser-Tencent-WAF/1.0",
    }

    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            response = client.get(url, headers=headers)
            result, evidence = _classify_tencent_response(response)
            return {
                "result": result,
                "evidence": evidence,
                "http_status": response.status_code,
                "response_excerpt": response.text[:4000],
                "request_summary": f"GET {url}  Host: {config.host}",
            }
    except httpx.ConnectError as exc:
        return {
            "result": "request_error",
            "evidence": f"无法连接到腾讯云 WAF 后端 {config.ip}：{exc}",
            "http_status": 0,
            "response_excerpt": "",
            "request_summary": f"GET {url}  Host: {config.host}",
        }
    except httpx.ReadTimeout:
        return {
            "result": "request_error",
            "evidence": f"腾讯云 WAF 请求超时（15 秒）：{url}",
            "http_status": 0,
            "response_excerpt": "",
            "request_summary": f"GET {url}  Host: {config.host}",
        }


def tencent_waf_preflight(config_path: str) -> dict[str, Any]:
    """Verify the Tencent Cloud WAF target is reachable before any test."""
    config = load_tencent_waf_config(config_path)
    if not config:
        return {
            "configured": False,
            "error": "腾讯云 WAF 未配置（缺少 TENCENT_WAF_IP / TENCENT_WAF_HOST）",
        }
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(
                f"http://{config.ip}/",
                headers={"Host": config.host, "User-Agent": "WAFByPasser-Tencent-WAF/1.0"},
            )
            return {
                "configured": True,
                "ip": config.ip,
                "host": config.host,
                "preflight_status": response.status_code,
                "preflight_result": _classify_tencent_response(response)[0],
            }
    except Exception as exc:
        return {"configured": True, "ip": config.ip, "host": config.host, "error": str(exc)}
