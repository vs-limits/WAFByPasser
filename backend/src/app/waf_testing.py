"""Strictly scoped WAF test runners.

DVWA + SafeLine:  form-based with login/session management.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from dotenv import load_dotenv


SUPPORTED = {
    "command-injection": "/vulnerabilities/exec/",
    "sql-injection": "/vulnerabilities/sqli/",
    "xss": "/vulnerabilities/xss_r/",
}
BLOCK_STATUSES = {403, 406, 429}
BLOCK_MARKERS = ("safeline", "waf blocked", "access denied", "request blocked")

# 腾讯云 WAF 拦截页的特征字符串。腾讯云 WAF 在部分策略下会用 HTTP 200
# 回一个"访问拦截"的 block-page，所以仅凭状态码不能判定放行，必须先扫响应体。
TENCENT_BLOCK_MARKERS = (
    "腾讯云waf",
    "访问拦截",
    "web应用防护",
    "web应用防护服务",
    "您提交的请求可能对网站造成威胁",
    "无法访问",
    "cos.accelerate.myqcloud.com/block-pages",
    "block-pages/static",
)


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
    if response.status_code in BLOCK_STATUSES:
        return "waf_blocked", f"HTTP {response.status_code}；检测到 WAF 拦截特征"
    if any(marker in body for marker in BLOCK_MARKERS):
        return "waf_blocked", f"HTTP {response.status_code}；检测到 WAF 拦截特征"
    if any(marker in body for marker in TENCENT_BLOCK_MARKERS):
        return "waf_blocked", f"HTTP {response.status_code}；响应体命中腾讯云 WAF 拦截页特征"
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
