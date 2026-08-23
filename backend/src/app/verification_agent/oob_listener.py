"""OOB 外带回连监听服务（独立部署，运行在公网可达的服务器上）。

仅用 Python 标准库，无需 pip 依赖。监听一个 HTTP 端口，接收靶场执行后外发
的回连请求（XSS Cookie 外带等），按 `id` token 记录，供本地 WAFByPasser 后端
查询「某条 payload 是否收到了回连」。

部署（在远端服务器 8.129.25.140 上）：
    python3 oob_listener.py --host 0.0.0.0 --port 12345 --log /tmp/oob.log
后台常驻：
    nohup python3 oob_listener.py --host 0.0.0.0 --port 12345 > /tmp/oob.log 2>&1 &

回连请求约定（由检验侧智能注入的 payload 发出）：
    GET /?id=<token>&c=<外带数据>          # 记录回调
查询端点（本地后端调用）：
    GET /api/oob/check?token=<token>       # 返回 {found, data, timestamp}
    POST /api/oob/clear?token=<token>      # 清除某 token（可选）
"""

from __future__ import annotations

import argparse
import json
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class OobStore:
    """线程安全的内存回调存储。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._callbacks: dict[str, dict] = {}

    def record(self, token: str, data: str) -> None:
        with self._lock:
            # 保留第一次回连；后续追加 data 到历史（可选，简化：只保留首次）
            if token not in self._callbacks:
                self._callbacks[token] = {
                    "data": data,
                    "timestamp": time.time(),
                }

    def check(self, token: str) -> dict:
        with self._lock:
            entry = self._callbacks.get(token)
            if not entry:
                return {"found": False}
            return {
                "found": True,
                "data": entry["data"],
                "timestamp": entry["timestamp"],
            }

    def clear(self, token: str) -> bool:
        with self._lock:
            return self._callbacks.pop(token, None) is not None


STORE = OobStore()


class OobHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/api/oob/check":
            token = (params.get("token") or [""])[0]
            self._send_json(STORE.check(token))
            return

        # 回连请求：/?id=<token>&c=<data> 或任何带 id 的 GET
        token = (params.get("id") or params.get("token") or [""])[0]
        if token:
            data = (params.get("c") or params.get("data") or [""])[0]
            STORE.record(token, data)
            self._send_json({"ok": True})
            return

        self._send_json({"ok": True, "hint": "OOB listener"}, 200)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/api/oob/clear":
            token = (params.get("token") or [""])[0]
            self._send_json({"cleared": STORE.clear(token)})
            return
        self._send_json({"ok": True}, 200)

    def log_message(self, format: str, *args) -> None:
        # 精简日志，避免刷屏
        print(f"[oob] {self.address_string()} {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OOB 外带回连监听服务")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=12345)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), OobHandler)
    print(f"OOB listener running on {args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
