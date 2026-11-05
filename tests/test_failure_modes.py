"""故障场景回归测试（离线可跑，不依赖外网）。

覆盖验收清单：
  * GitHub Raw 下载失败 → 回退源缓存，不清空产物
  * 免费节点从 N 个降到 0 个 → 门禁拦截，旧产物字节级不变
  * 探测内核无法启动 → Prober 抛错（配合 decide_publish 判定为不发布）
  * provider 拉取失败（付费线路全挂） → 内核继续用本地缓存里的旧节点
  * 配置校验失败 → 不落盘
  * 客户端脚本幂等（重复执行结果一致）

用法：
    python tests/test_failure_modes.py --mihomo ./bin/mihomo [--mmdb Country.mmdb]
不带 --mihomo 时只会跳过需要内核的用例。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

CASES = []
CTX: dict = {"mihomo": None, "mmdb": None}


def case(fn):
    CASES.append(fn)
    return fn


def need_mihomo() -> bool:
    return bool(CTX.get("mihomo"))


VALID_FIXTURE = """
proxies:
  - {name: a, type: ss, server: 8.8.8.8, port: 8388, cipher: aes-256-gcm, password: p1}
  - {name: b, type: ss, server: 1.1.1.1, port: 8388, cipher: aes-256-gcm, password: p2}
  - {name: c, type: trojan, server: t.example.com, port: 443, password: p3, sni: t.example.com}
  - {name: d, type: vless, server: v.example.com, port: 443,
     uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, servername: v.example.com}
"""

GARBAGE_FIXTURE = """
proxies:
  - {name: x, type: ss, server: 10.0.0.1, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: y, type: obfs4, server: 8.8.8.8, port: 1}
  - {name: z, type: http, server: h.example.com, port: 8080, tls: false}
"""

PREVIOUS_OUT = """
proxies:
  - {name: prev-1, type: ss, server: 9.9.9.9, port: 8388, cipher: aes-256-gcm, password: q1}
  - {name: prev-2, type: ss, server: 9.9.9.8, port: 8388, cipher: aes-256-gcm, password: q2}
"""


def _sources(url: str, min_publish: int = 1, max_nodes: int = 50) -> str:
    return yaml.safe_dump(
        {
            "sources": [{
                "id": "fx", "name": "fixture", "url": url,
                "license": "MIT", "redistribute": True,
                "max_nodes": max_nodes, "enabled": True,
            }],
            "limits": {"total_max": 50, "min_publish": min_publish,
                       "min_ratio_vs_previous": 0.5},
        },
        allow_unicode=True, sort_keys=False,
    )


def _run_build(work: str, *, sources_path: str, no_probe: bool = True,
               mihomo: str | None = None) -> tuple[int, str]:
    cmd = [
        sys.executable, os.path.join(ROOT, "src", "build.py"),
        "--sources", sources_path,
        "--out", os.path.join(work, "out.yaml"),
        "--stats", os.path.join(work, "stats.json"),
        "--mmdb", CTX["mmdb"] or os.path.join(ROOT, "Country.mmdb"),
        "--geo-cache", os.path.join(work, "geo.json"),
        "--cache-dir", os.path.join(work, "raw"),
    ]
    if mihomo:
        cmd += ["--mihomo", mihomo]
    if no_probe:
        cmd += ["--no-probe"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _stage(work: str, fixture_text: str, *, with_previous: bool = True) -> str:
    """准备一个可离线运行的工作目录，返回 sources.yaml 路径。"""
    fx = os.path.join(work, "fixture.yaml")
    with open(fx, "w", encoding="utf-8") as f:
        f.write(fixture_text)
    out = os.path.join(work, "out.yaml")
    with open(out, "w", encoding="utf-8") as f:
        f.write(PREVIOUS_OUT if with_previous else "")
    src = os.path.join(work, "sources.yaml")
    with open(src, "w", encoding="utf-8") as f:
        f.write(_sources("file:///" + fx.replace("\\", "/")))
    return src


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ------------------------------------------------------------------ 用例

@case
def test_raw_download_failure_falls_back_to_cache():
    """GitHub Raw 拉不到时，用源缓存继续构建，不清空产物。"""
    work = tempfile.mkdtemp(prefix="fnh-fm-")
    src = _stage(work, VALID_FIXTURE, with_previous=False)
    # 先放一份缓存，然后把 url 改成不可达地址
    cache = os.path.join(work, "raw")
    os.makedirs(cache, exist_ok=True)
    with open(os.path.join(cache, "fx.yaml"), "w", encoding="utf-8") as f:
        f.write(VALID_FIXTURE)
    with open(src, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    doc["sources"][0]["url"] = "http://127.0.0.1:1/never.yaml"
    with open(src, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)

    code, log = _run_build(work, sources_path=src, mihomo=CTX["mihomo"])
    assert code == 0, f"应靠缓存发布，实际退出码 {code}\n{log[-1500:]}"
    stats = json.load(open(os.path.join(work, "stats.json"), encoding="utf-8"))
    assert stats["sources"][0]["from_cache"] is True, stats["sources"][0]
    published = len(yaml.safe_load(_read(os.path.join(work, "out.yaml")))["proxies"])
    assert published >= 3, f"缓存回退后应发布多个节点，实际 {published}"


@case
def test_all_nodes_gone_keeps_previous_file_byte_identical():
    """节点数掉到 0：门禁拦截，旧产物必须字节级不变。"""
    work = tempfile.mkdtemp(prefix="fnh-fm-")
    src = _stage(work, GARBAGE_FIXTURE, with_previous=True)
    out = os.path.join(work, "out.yaml")
    before = _read(out)
    code, log = _run_build(work, sources_path=src, mihomo=CTX["mihomo"])
    assert code == 2, f"应被门禁拦截（退出码 2），实际 {code}\n{log[-1500:]}"
    assert _read(out) == before, "门禁拦截后旧产物被改写了"
    stats = json.load(open(os.path.join(work, "stats.json"), encoding="utf-8"))
    assert stats["gate"]["decision"].startswith("blocked"), stats["gate"]


@case
def test_count_drop_below_ratio_keeps_previous():
    """节点数相对上一版骤降：拦截而不是覆盖。"""
    work = tempfile.mkdtemp(prefix="fnh-fm-")
    src = _stage(work, VALID_FIXTURE, with_previous=True)
    # 上一版放 20 个，本轮只有 4 个可用 → 4 < 20*0.5=10
    big = {"proxies": [
        {"name": f"p{i}", "type": "ss", "server": f"9.9.9.{i}", "port": 8388,
         "cipher": "aes-256-gcm", "password": "q"} for i in range(20)
    ]}
    out = os.path.join(work, "out.yaml")
    with open(out, "w", encoding="utf-8") as f:
        yaml.safe_dump(big, f, sort_keys=False)
    before = _read(out)
    code, log = _run_build(work, sources_path=src, mihomo=CTX["mihomo"])
    assert code == 2, f"应拦截，实际 {code}\n{log[-1200:]}"
    assert _read(out) == before


@case
def test_invalid_config_blocks_publish():
    """配置校验不通过（内核拒绝）时必须不落盘。"""
    if not need_mihomo():
        return
    work = tempfile.mkdtemp(prefix="fnh-fm-")
    src = _stage(work, VALID_FIXTURE, with_previous=False)
    out = os.path.join(work, "out.yaml")
    before = _read(out)
    bogus = os.path.join(work, "not-a-core.txt")
    with open(bogus, "w", encoding="utf-8") as f:
        f.write("not a binary")
    code, log = _run_build(work, sources_path=src, mihomo=bogus)
    assert code == 3, f"校验失败应退出 3，实际 {code}\n{log[-1200:]}"
    assert _read(out) == before, "校验失败后仍写入了产物"


@case
def test_prober_raises_when_kernel_cannot_start():
    """探测内核起不来时必须抛错，交由门禁拦截，而不是当成'0 个存活'。"""
    from probe import Prober
    work = tempfile.mkdtemp(prefix="fnh-fm-")
    bogus = os.path.join(work, "not-a-core.txt")
    with open(bogus, "w", encoding="utf-8") as f:
        f.write("not a binary")
    p = Prober(bogus)
    raised = False
    try:
        p.start([{"name": "x", "type": "ss", "server": "8.8.8.8", "port": 8388,
                  "cipher": "aes-256-gcm", "password": "p"}])
    except Exception:
        raised = True
    finally:
        p.stop()
    assert raised, "内核无法启动却没有抛错"


@case
def test_provider_survives_dead_upstream_using_cache():
    """两阶段实验：先让内核自己拉一次写缓存，再断源重启，验证是否回退缓存。

    阶段 A：本地起一个 HTTP 服务提供订阅 → 内核成功拉取并写缓存
    阶段 B：关掉服务（模拟付费线路全挂 / 订阅更新失败）→ 重启内核
            → 必须仍能拿到阶段 A 缓存里的节点，且缓存文件不被改写
    """
    if not need_mihomo():
        return
    import functools
    import http.server
    import socketserver
    import threading
    import time

    from probe import _api, _free_port, SECRET

    work = tempfile.mkdtemp(prefix="fnh-fm-")
    os.makedirs(os.path.join(work, "providers"), exist_ok=True)
    src = os.path.join(work, "free.yaml")
    with open(src, "w", encoding="utf-8") as f:
        f.write(VALID_FIXTURE)

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):  # 静音
            pass

    srv_port = _free_port()
    handler = functools.partial(Quiet, directory=work)
    httpd = socketserver.TCPServer(("127.0.0.1", srv_port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    api_port = _free_port()
    cfg = {
        "mixed-port": _free_port(),
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": SECRET,
        "proxies": [{"name": "dead-line", "type": "socks5", "server": "127.0.0.1",
                     "port": 1, "username": "u", "password": "p", "tls": True}],
        "proxy-groups": [
            {"name": "GROUPDL", "type": "select", "proxies": ["DIRECT", "dead-line"]},
            {"name": "USE", "type": "select", "use": ["cacheprov"]},
        ],
        "proxy-providers": {
            "cacheprov": {
                "type": "http",
                "url": f"http://127.0.0.1:{srv_port}/free.yaml",
                "path": "./providers/free.yaml",
                "interval": 3600,
                "proxy": "GROUPDL",
            }
        },
        "rules": ["MATCH,USE"],
    }
    cfg_path = os.path.join(work, "cfg.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)
    cache_file = os.path.join(work, "providers", "free.yaml")

    def boot(seconds: float):
        log = open(os.path.join(work, "core.log"), "a", encoding="utf-8")
        proc = subprocess.Popen([CTX["mihomo"], "-d", work, "-f", cfg_path],
                                stdout=log, stderr=subprocess.STDOUT, cwd=work)
        got = []
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                have = set(_api(api_port, "/proxies").get("proxies", {}))
                got = sorted(have & {"a", "b", "c"})
                if len(got) == 3:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        return proc, got, log

    # ---- 阶段 A：源可用，内核自己写缓存
    proc, got_a, log = boot(30)
    try:
        assert len(got_a) == 3, f"阶段 A 未能从订阅加载节点：{got_a}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        log.close()

    deadline = time.time() + 10
    while time.time() < deadline and not os.path.exists(cache_file):
        time.sleep(0.5)
    assert os.path.exists(cache_file), "内核没有把拉取结果写成本地缓存"
    cached = _read(cache_file)
    assert b"name: a" in cached, f"缓存内容异常：{cached[:200]}"

    # ---- 阶段 B：源断开（模拟付费线路全挂 + 订阅更新失败），重启内核
    httpd.shutdown()
    httpd.server_close()

    proc, got_b, log = boot(30)
    try:
        if len(got_b) != 3:
            try:
                tail = open(os.path.join(work, "core.log"), encoding="utf-8",
                            errors="replace").read()[-1200:]
            except Exception:
                tail = "(无日志)"
            raise AssertionError(
                f"源断开后内核没有回退到缓存，只看到 {got_b}\n---- core.log ----\n{tail}"
            )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        log.close()

    assert _read(cache_file) == cached, "回退缓存后缓存文件被改写"


@case
def test_client_script_is_idempotent():
    """把脚本输出再喂回脚本，结果必须完全一致（防止重复注入）。"""
    node = shutil.which("node")
    if not node:
        return
    base = {
        "mixed-port": 7897, "mode": "rule",
        "proxies": [{"name": "香港01", "type": "ss", "server": "1.2.3.4", "port": 1,
                     "cipher": "aes-256-gcm", "password": "p"}],
        "proxy-groups": [
            {"name": "BoostNet", "type": "select", "proxies": ["自动选择", "DIRECT", "香港01"]},
            {"name": "自动选择", "type": "url-test", "proxies": ["香港01"]},
        ],
        "rules": ["DOMAIN,keep.me,DIRECT", "MATCH,BoostNet"],
    }
    work = tempfile.mkdtemp(prefix="fnh-fm-")
    script = os.path.join(ROOT, "tools", "clash-verge", "Script.js")
    harness = os.path.join(ROOT, "tools", "clash-verge", "harness.js")
    cur = os.path.join(work, "c1.json")
    json.dump(base, open(cur, "w", encoding="utf-8"), ensure_ascii=False)
    outs = []
    for i in (1, 2):
        nxt = os.path.join(work, f"c{i + 1}.json")
        out = os.path.join(work, f"o{i}.json")
        r = subprocess.run([node, harness, cur, script, out],
                           capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 0, r.stderr
        outs.append(json.load(open(out, encoding="utf-8")))
        cur = out
    assert outs[0] == outs[1], "脚本不幂等：第二次执行产生了不同结果"
    groups = [g["name"] for g in outs[1]["proxy-groups"]]
    assert len(groups) == len(set(groups)), f"存在重复组：{groups}"
    main = [g for g in outs[1]["proxy-groups"] if g["name"] == "BoostNet"][0]
    assert main["proxies"][0] == "自动选择", "付费节点顺序被改动"
    assert "DOMAIN,keep.me,DIRECT" in outs[1]["rules"], "原有规则被删除"


# ------------------------------------------------------------------ 运行器

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mihomo", default="")
    ap.add_argument("--mmdb", default="")
    args = ap.parse_args()

    if args.mihomo:
        CTX["mihomo"] = os.path.abspath(args.mihomo)
    if args.mmdb:
        CTX["mmdb"] = os.path.abspath(args.mmdb)
    elif os.path.exists(os.path.join(ROOT, "Country.mmdb")):
        CTX["mmdb"] = os.path.join(ROOT, "Country.mmdb")

    print(f"内核: {CTX['mihomo'] or '(未提供，相关用例跳过)'}")
    failed = skipped = 0
    for fn in CASES:
        try:
            fn()
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
        else:
            print(f"ok    {fn.__name__}")
    print(f"\n{len(CASES) - failed}/{len(CASES)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
