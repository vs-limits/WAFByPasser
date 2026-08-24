"""对套了 WAF 的 DVWA 靶场实测 cat /etc/passwd 与 alert(1)，观察是否 403 拦截。"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx
from dotenv import load_dotenv
from app.waf_testing import WafConfig, classify, ensure_low_security, login, same_origin
from app.verification_agent.adapters import _load_range_config

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / ".env"
load_dotenv(CONFIG_PATH)
UA = {"User-Agent": "WAFByPasser-Waf403/1.0"}


def show(resp, label):
    body = resp.text
    result, evidence = classify(resp, "")
    print(f"\n[{label}] HTTP {resp.status_code}  classify={result}")
    print(f"  evidence: {evidence}")
    print(f"  body[:300]: {body[:300]!r}")
    return result


def main():
    cmdi_base, user, pw = _load_range_config(str(CONFIG_PATH), "RANGE_CMDI")
    xss_base, _, _ = _load_range_config(str(CONFIG_PATH), "RANGE_XSS")
    print(f"cmdi_base={cmdi_base}  xss_base={xss_base}  user={user}")

    client = httpx.Client(timeout=httpx.Timeout(20, connect=5), headers=UA, follow_redirects=False)
    try:
        cfg = WafConfig(base_url=cmdi_base, username=user, password=pw)
        login(client, cfg)
        ensure_low_security(client, cfg)

        # 命令注入：cat /etc/passwd
        url = same_origin(cfg, "/vulnerabilities/exec/")
        r1 = client.post(url, data={"ip": "-c 1 127.0.0.1;cat /etc/passwd", "Submit": "Submit"})
        show(r1, "cmdi: cat /etc/passwd")

        # XSS：alert(1)
        xurl = same_origin(cfg, "/vulnerabilities/xss_r/")
        r2 = client.get(xurl, params={"name": "<script>alert(1)</script>"})
        show(r2, "xss: alert(1)")

        # 基线对照：无害值
        r3 = client.post(url, data={"ip": "127.0.0.1", "Submit": "Submit"})
        show(r3, "cmdi baseline: 127.0.0.1")

        # 执行/反射标志验证
        import re
        b1 = r1.text
        print("\n=== cmdi cat /etc/passwd 执行标志 ===")
        for m in ["root:x:0:0", "www-data", "daemon:x", "nobody:x", "bin/x", "uid="]:
            print(f"  {m!r}: {m in b1}")
        pre = re.findall(r"<pre>(.*?)</pre>", b1, re.S)
        print("  <pre> 区块:", pre[:1])

        b2 = r2.text
        print("\n=== xss alert(1) 反射标志 ===")
        print("  <script>alert(1)</script> in body:", "<script>alert(1)</script>" in b2)
        print("  alert(1) in body:", "alert(1)" in b2)
        idx = b2.find("alert(1)")
        print("  反射片段:", repr(b2[idx - 40:idx + 60]) if idx >= 0 else "N/A")
    except Exception as exc:
        print(f"FAILED: {exc!r}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
