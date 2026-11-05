"""FreeNode Hub — 公共工具：受限 HTTP 抓取、日志脱敏、指纹。

安全约定：
  * 任何网络抓取都有 超时 / 大小上限 / 重试上限，防止被上游拖死或 OOM。
  * 日志中不得出现节点密码 / UUID / 用户名，统一通过 scrub() 兜底。
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import time
import urllib.error
import urllib.request

USER_AGENT = "FreeNodeHub/1.0 (+https://github.com/; free node aggregator)"

_SECRET_KEYS = (
    "password", "passwd", "uuid", "auth-str", "auth_str", "obfs-password",
    "obfs_password", "username", "token", "public-key", "private-key",
)

_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|uuid|auth-str|obfs-password|username|token)\b\s*[:=]\s*\S+"),
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
]


def scrub(text: str) -> str:
    """把可能混入日志的凭据替换掉。只用于日志，不用于数据。"""
    out = str(text)
    for rx in _SECRET_PATTERNS:
        out = rx.sub(lambda m: f"{m.group(1)}=***" if m.groups() else "***", out)
    return out


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub(record.msg)
        if record.args:
            try:
                record.args = tuple(
                    scrub(a) if isinstance(a, str) else a for a in record.args
                )
            except Exception:
                pass
        return True


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("fnh")
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    handler.addFilter(ScrubFilter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


LOG = setup_logging()


_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_ENV_OPENER = urllib.request.build_opener()


def fetch(
    url: str,
    *,
    timeout: int = 60,
    max_bytes: int = 8_000_000,
    retries: int = 3,
    backoff: float = 2.0,
    use_env_proxy: bool = False,
) -> tuple[bytes | None, str | None, int | None]:
    """下载一个 URL。

    返回 (data, error, http_status)。任何失败都返回 (None, 原因, 状态码或 None)。
    只在内存中处理，不落盘，不执行内容。

    默认 **忽略** HTTP_PROXY/HTTPS_PROXY 环境变量直连：实测某些中间代理会
    对 raw.githubusercontent 做 TLS 拦截并断连（RemoteDisconnected），
    直连反而稳定。
    """
    opener = _ENV_OPENER if use_env_proxy else _DIRECT_OPENER
    last_err: str | None = None
    status: int | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/yaml, text/plain, application/yaml, */*",
                    "Cache-Control": "no-cache",
                },
            )
            with opener.open(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None)
                buf = bytearray()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        return None, f"响应超过上限 {max_bytes} 字节", status
                return bytes(buf), None, status
        except urllib.error.HTTPError as e:
            status = e.code
            last_err = f"HTTP {e.code}"
            if 400 <= e.code < 500:
                break  # 客户端错误不重试
        except Exception as e:  # noqa: BLE001 - 上游不可控
            last_err = f"{type(e).__name__}: {e}"
        if attempt < retries:
            time.sleep(backoff * attempt)
    return None, last_err or "unknown error", status


def fingerprint(obj: dict) -> str:
    """按 协议+地址+端口+认证参数 生成去重指纹。"""
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def write_json(path, data) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")
