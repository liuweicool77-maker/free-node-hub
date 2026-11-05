"""用真实的 Mihomo 内核校验配置。

`mihomo -t` 会完整走一遍配置解析 + 代理实例化，能在节点写进产物之前
拦住 90% 以上的结构性错误（缺字段、类型不对、加密方式不支持、组引用不存在）。
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

from common import scrub

PROBE_GROUP = "FNH-VALIDATE"


def _run(mihomo: str, cfg_path: str, workdir: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [mihomo, "-t", "-d", workdir, "-f", cfg_path],
            capture_output=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return False, "内核校验超时（>180s）"
    except OSError as e:
        # 内核路径不是可执行文件 / 权限不足 / 架构不匹配
        return False, f"内核无法执行：{type(e).__name__}: {e}"
    out = (proc.stdout or b"").decode("utf-8", "replace") + (proc.stderr or b"").decode("utf-8", "replace")
    out = scrub(out).strip()
    ok = proc.returncode == 0 and "test is successful" in out
    return ok, out[-4000:]


def validate_proxies(mihomo: str, proxies: list[dict], workdir: str | None = None) -> tuple[bool, str]:
    """把 proxies 塞进一个最小可用配置做校验。"""
    tmp = workdir or tempfile.mkdtemp(prefix="fnh-val-")
    os.makedirs(tmp, exist_ok=True)
    cfg = {
        "mixed-port": 17899,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [{"name": PROBE_GROUP, "type": "select", "proxies": ["DIRECT"]}],
        "rules": ["MATCH,DIRECT"],
    }
    path = os.path.join(tmp, "validate.yaml")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    return _run(mihomo, path, tmp)


def validate_file(mihomo: str, yaml_path: str) -> tuple[bool, str]:
    workdir = os.path.dirname(os.path.abspath(yaml_path)) or "."
    return _run(mihomo, yaml_path, workdir)
