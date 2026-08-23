"""检验靶场适配器注册表。

每个 adapter 接收 ``(config_path, content, base)`` 返回 ``TargetEvidence``。
新增靶场 = 加一个 ``run_*`` 函数 + 在 ``ADAPTERS`` / ``DEFAULT_RANGE`` 注册，
再在 ``config/.env.example`` 补充 ``RANGE_*`` 配置，无需改动判定层。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urljoin

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


AdapterFn = Callable[[str, str, dict[str, Any]], TargetEvidence]


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

    优先 ``{prefix}_DVWA_BASE_URL``，其次回退到现有 ``WAF_DVWA_*``。
    """
    load_dotenv(config_path)
    base_url = (
        os.getenv(f"{prefix}_DVWA_BASE_URL", "").strip()
        or os.getenv("WAF_DVWA_BASE_URL", "").strip()
    )
    username = (
        os.getenv(f"{prefix}_USERNAME", "").strip()
        or os.getenv("WAF_DVWA_USERNAME", "").strip()
    )
    password = (
        os.getenv(f"{prefix}_PASSWORD", "").strip()
        or os.getenv("WAF_DVWA_PASSWORD", "").strip()
    )
    return base_url.rstrip("/"), username, password


def _dvwa_client(base_url: str, username: str, password: str) -> tuple[httpx.Client, WafConfig]:
    client = httpx.Client(
        timeout=httpx.Timeout(20, connect=5),
        headers={"User-Agent": "WAFByPasser-Verify/1.0"},
    )
    config = WafConfig(base_url=base_url, username=username, password=password)
    login(client, config)
    ensure_low_security(client, config)
    return client, config


# =============================================================================
# 命令注入（DVWA POST）
# =============================================================================

CMDI_PATH = "/vulnerabilities/exec/"
CMDI_FIELD = "ip"
CMDI_PREFIX = "-c 127.0.0.1;"


def run_command_injection(config_path: str, content: str, base: dict[str, Any], **_kwargs: Any) -> TargetEvidence:
    base_url, username, password = _load_range_config(config_path, "RANGE_CMDI")
    if not base_url or not username or not password:
        return _error_evidence(
            "command-injection-dvwa",
            "command-injection",
            "命令注入靶场未配置（缺少 RANGE_CMDI_DVWA_BASE_URL / RANGE_DVWA_USERNAME / PASSWORD）",
        )
    verification_spec = (base or {}).get("verification_spec")
    try:
        client, config = _dvwa_client(base_url, username, password)
    except Exception as exc:  # noqa: BLE001
        return _error_evidence("command-injection-dvwa", "command-injection", str(exc))
    try:
        # 剥掉 payload 前导分隔符（; | & 等），避免与 CMDI_PREFIX 的 `;` 拼成
        # `;;`（shell case 终止符，会导致命令不执行）。
        stripped = content.lstrip(";|&\r\n\t ")
        data = {CMDI_FIELD: f"{CMDI_PREFIX}{stripped}", "Submit": "Submit"}
        response = client.post(
            same_origin(config, CMDI_PATH), data=data, follow_redirects=False
        )
        result, evidence = classify(response, "命令注入请求已到达应用")
        if result == "application_response":
            result, evidence = verify_execution(response.text, verification_spec, content)
        return TargetEvidence(
            target_key="command-injection-dvwa",
            vulnerability="command-injection",
            request_summary=f"POST {CMDI_PATH} ip={CMDI_PREFIX}{content}",
            http_status=response.status_code,
            response_excerpt=_excerpt(response.text),
            response_headers=_headers_text(response.headers),
            outcome=result,
            evidence=evidence,
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


def run_xss(config_path: str, content: str, base: dict[str, Any], **_kwargs: Any) -> TargetEvidence:
    base_url, username, password = _load_range_config(config_path, "RANGE_XSS")
    if not base_url or not username or not password:
        return _error_evidence(
            "xss-dvwa",
            "xss",
            "XSS 靶场未配置（缺少 RANGE_XSS_DVWA_BASE_URL / RANGE_DVWA_USERNAME / PASSWORD）",
        )
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _run_xss_httpx(base_url, username, password, content)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            dialogs: list[str] = []
            page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.accept()))
            page.goto(urljoin(f"{base_url}/", "/login.php"), wait_until="domcontentloaded")
            page.locator("input[name='username']").fill(username)
            page.locator("input[name='password']").fill(password)
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
        )
    except Exception as exc:  # noqa: BLE001
        return _error_evidence("xss-dvwa", "xss", str(exc))


def _run_xss_httpx(base_url: str, username: str, password: str, content: str) -> TargetEvidence:
    try:
        client, config = _dvwa_client(base_url, username, password)
    except Exception as exc:  # noqa: BLE001
        return _error_evidence("xss-dvwa", "xss", str(exc))
    try:
        response = client.get(
            same_origin(config, XSS_PATH), params={XSS_FIELD: content}, follow_redirects=False
        )
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


def run_sqli(config_path: str, content: str, base: dict[str, Any], lesson_hint: Any = None) -> TargetEvidence:
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_SQLI_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        return _error_evidence(
            "sqli-labs",
            "sql-injection",
            "SQL 靶场未配置（缺少 RANGE_SQLI_BASE_URL）",
        )
    injection_type = classify_sqli_injection_type(content)
    lesson = _pick_lesson(injection_type, lesson_hint)
    path, param = LESS_ROUTES.get(injection_type, LESS_ROUTES["union"])[1].get(
        lesson, (f"/Less-{lesson}/", "id")
    )
    url = f"{base_url}{path}"
    timeout = httpx.Timeout(20, connect=5)
    try:
        with httpx.Client(timeout=timeout, headers={"User-Agent": "WAFByPasser-Verify/1.0"}) as client:
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
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("sqli-labs", "sql-injection", str(exc))


# =============================================================================
# log4j2（Solr action 参数，仅判绕过，执行需人工验证）
# =============================================================================

LOG4J_PATH = "/solr/admin/cores"
LOG4J_PARAM = "action"


def run_log4j(config_path: str, content: str, base: dict[str, Any], **_kwargs: Any) -> TargetEvidence:
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_LOG4J_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        return _error_evidence(
            "log4j-solr",
            "log4j",
            "log4j 靶场未配置（缺少 RANGE_LOG4J_BASE_URL）",
        )
    url = f"{base_url}{LOG4J_PATH}"
    try:
        with httpx.Client(
            timeout=httpx.Timeout(20, connect=5),
            headers={"User-Agent": "WAFByPasser-Verify/1.0"},
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
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("log4j-solr", "log4j", str(exc))


# =============================================================================
# file-upload（jsp-upload-labs：10 关，上传 + 访问确认执行）
# =============================================================================

# 关卡 → 上传接口路径（POST multipart，字段名 `file`，回显「上传成功: uploads/<文件名>」）
PASS_ROUTES: dict[int, str] = {
    1: "/pass01.jsp", 2: "/pass02.jsp", 3: "/pass03.jsp", 4: "/pass04.jsp",
    5: "/pass05.jsp", 6: "/pass06.jsp", 7: "/pass07.jsp", 8: "/pass08.jsp",
    9: "/pass09.jsp", 10: "/pass10.jsp",
}
DEFAULT_PASS = 1
UPLOAD_ACCESS_SUBDIR = "/uploads"
UPLOAD_FILE_FIELD = "file"
DEFAULT_UPLOAD_FILENAME = "shell.jsp"


def _pick_pass(content: str, lesson_hint: Any = None) -> int:
    """根据 payload 内容启发式判断上传关卡；lesson_hint 优先。

    内容特征 → 关卡：
      - 含 `ProcessBuilder` / `Runtime`（等价 API）→ pass06（内容过滤）
      - 含 `.jspx` → pass03（后缀黑名单）
    """
    if isinstance(lesson_hint, int) and lesson_hint in PASS_ROUTES:
        return lesson_hint
    lower = content.lower()
    if "processbuilder" in lower or "runtime" in lower:
        return 6
    if ".jspx" in lower:
        return 3
    return DEFAULT_PASS


def run_file_upload(config_path: str, content: str, base: dict[str, Any], lesson_hint: Any = None) -> TargetEvidence:
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_UPLOAD_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        return _error_evidence(
            "file-upload-jsp",
            "file-upload",
            "文件上传靶场未配置（缺少 RANGE_UPLOAD_BASE_URL）",
        )
    lesson = _pick_pass(content, lesson_hint)
    upload_path = PASS_ROUTES[lesson]
    filename = os.getenv("RANGE_UPLOAD_FILENAME", DEFAULT_UPLOAD_FILENAME)
    field = os.getenv("RANGE_UPLOAD_FILE_FIELD", UPLOAD_FILE_FIELD)
    access_url = f"{base_url}{UPLOAD_ACCESS_SUBDIR}/{filename}"

    try:
        with httpx.Client(
            timeout=httpx.Timeout(20, connect=5),
            headers={"User-Agent": "WAFByPasser-Verify/1.0"},
        ) as client:
            # 1. multipart 上传 JSP webshell 到对应关卡
            upload_response = client.post(
                f"{base_url}{upload_path}",
                files={field: (filename, content.encode("utf-8"), "application/octet-stream")},
                follow_redirects=False,
            )
            result, evidence = classify(upload_response, "文件上传请求已到达应用")
            if result != "application_response":
                return TargetEvidence(
                    target_key="file-upload-jsp",
                    vulnerability="file-upload",
                    request_summary=f"POST {base_url}{upload_path} file={filename}",
                    http_status=upload_response.status_code,
                    response_excerpt=_excerpt(upload_response.text),
                    response_headers=_headers_text(upload_response.headers),
                    outcome=result,
                    evidence=evidence,
                )

            # 2. 上传回显「上传成功」才继续访问确认执行；否则视为验证失败
            upload_body = upload_response.text
            if "上传成功" not in upload_body:
                return TargetEvidence(
                    target_key="file-upload-jsp",
                    vulnerability="file-upload",
                    request_summary=f"POST {base_url}{upload_path} file={filename}",
                    http_status=upload_response.status_code,
                    response_excerpt=_excerpt(upload_body),
                    response_headers=_headers_text(upload_response.headers),
                    outcome="application_response",
                    evidence=f"上传未成功（关卡 pass{lesson:02d}）：{_excerpt(upload_body, 200)}",
                )

            # 3. 访问上传后的文件，确认可执行
            access_response = client.get(access_url, follow_redirects=False)
            access_result, access_evidence = classify(access_response, "已访问上传后的文件")
            outcome = access_result
            evidence = (
                f"上传成功（pass{lesson:02d}）；访问 {access_url} 结果：{access_evidence}"
                if access_result == "application_response"
                else access_evidence
            )
            return TargetEvidence(
                target_key="file-upload-jsp",
                vulnerability="file-upload",
                request_summary=f"POST {base_url}{upload_path} file={filename}；GET {access_url}",
                http_status=access_response.status_code,
                response_excerpt=_excerpt(access_response.text),
                response_headers=_headers_text(access_response.headers),
                outcome=outcome,
                evidence=evidence,
                baseline_excerpt=_excerpt(upload_body),
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        return _error_evidence("file-upload-jsp", "file-upload", str(exc))


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
    "file-upload": "file-upload-jsp",
}


def _cmdi_target(config_path: str) -> dict[str, Any]:
    base_url, username, password = _load_range_config(config_path, "RANGE_CMDI")
    return {
        "key": "command-injection-dvwa",
        "label": "命令注入靶场（DVWA）",
        "vulnerability": "command-injection",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": bool(base_url and username and password),
        "method": "POST",
        "injection_point": f"/vulnerabilities/exec/  ip={CMDI_PREFIX}<payload>",
    }


def _xss_target(config_path: str) -> dict[str, Any]:
    base_url, username, password = _load_range_config(config_path, "RANGE_XSS")
    return {
        "key": "xss-dvwa",
        "label": "XSS 靶场（DVWA）",
        "vulnerability": "xss",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": bool(base_url and username and password),
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
        "injection_point": f"/solr/admin/cores?action=<payload>",
    }


def _upload_target(config_path: str) -> dict[str, Any]:
    load_dotenv(config_path)
    base_url = os.getenv("RANGE_UPLOAD_BASE_URL", "").strip().rstrip("/")
    return {
        "key": "file-upload-jsp",
        "label": "文件上传靶场（JSP）",
        "vulnerability": "file-upload",
        "base_url": base_url,
        "waf": "腾讯云 WAF",
        "configured": bool(base_url),
        "method": "POST",
        "injection_point": f"/passNN.jsp file=<webshell.jsp>（10 关，LLM 路由关卡）",
    }


# 靶场注册表：key → 元信息提供函数（惰性读取 .env，避免导入期依赖 config）。
TARGET_REGISTRY: dict[str, Callable[[str], dict[str, Any]]] = {
    "command-injection-dvwa": _cmdi_target,
    "xss-dvwa": _xss_target,
    "sqli-labs": _sqli_target,
    "log4j-solr": _log4j_target,
    "file-upload-jsp": _upload_target,
}


def verification_targets(config_path: str) -> list[dict[str, Any]]:
    """返回所有已注册检验靶场的元信息（供前端靶场页展示）。"""
    return [provider(config_path) for provider in TARGET_REGISTRY.values()]


def resolve_adapter(vulnerability: str, target_key: str = "") -> tuple[str, AdapterFn]:
    """解析漏洞类型到 adapter 函数；未知类型抛 ValueError。"""
    adapter = ADAPTERS.get(vulnerability)
    if adapter is None:
        raise ValueError(f"暂不支持对漏洞类型 {vulnerability} 的自动检验")
    key = target_key or DEFAULT_RANGE.get(vulnerability, vulnerability)
    return key, adapter
