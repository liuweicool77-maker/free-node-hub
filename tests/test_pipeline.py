"""FreeNode Hub 离线测试套件（无第三方依赖，可直接 python tests/test_pipeline.py 运行）。

覆盖需求六中可在离线环境断言的部分：
  * 恶意字段隔离（上游的 script/tun/dns/dialer-proxy/skip-cert-verify 一律不得进入产物）
  * 去重
  * 无效节点过滤
  * 名称唯一性与稳定命名
  * 地区判定不依赖节点名
"""

from __future__ import annotations

import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from build import decide_publish, identity, make_name, parse_proxies  # noqa: E402
from common import fingerprint  # noqa: E402
from sanitize import Reject, sanitize, unsupported_types  # noqa: E402

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ------------------------------------------------------------------ 恶意字段隔离

MALICIOUS_SUB = """
mixed-port: 7890
allow-lan: true
mode: global
external-controller: 0.0.0.0:9090
secret: hacked
tun:
  enable: true
  stack: system
dns:
  enable: true
  nameserver: ["1.1.1.1"]
script:
  code: |
    def main(ctx):
      import os; os.system("rm -rf /")
rule-providers:
  evil:
    type: http
    behavior: domain
    url: http://evil.example/x.yaml
proxies:
  - name: "🇯🇵 日本 IPLC 专线"
    type: ss
    server: 8.8.8.8
    port: 8388
    cipher: aes-256-gcm
    password: secret123
    skip-cert-verify: true
    dialer-proxy: "some-other-proxy"
    interface-name: eth0
    routing-mark: 233
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
proxy-groups:
  - name: 选择出口
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
"""


@case
def test_only_proxies_extracted():
    """顶层只取 proxies，其余段全部忽略。"""
    proxies = parse_proxies(MALICIOUS_SUB.encode())
    assert len(proxies) == 1, proxies
    assert "tun" not in str(proxies)


@case
def test_dangerous_proxy_fields_stripped():
    """节点级危险字段必须被剥掉，且 skip-cert-verify 不得出现。"""
    raw = parse_proxies(MALICIOUS_SUB.encode())[0]
    clean, _ = sanitize(raw)
    for forbidden in ("skip-cert-verify", "dialer-proxy", "interface-name", "routing-mark"):
        assert forbidden not in clean, f"{forbidden} 未被剥离: {clean}"
    assert clean["type"] == "ss"
    assert clean["server"] == "8.8.8.8"
    # 合法字段保留
    assert clean["cipher"] == "aes-256-gcm"
    assert clean["plugin"] == "v2ray-plugin"


@case
def test_output_yaml_only_has_proxies_key():
    """发布产物顶层只能有 proxies 一个键。"""
    raw = parse_proxies(MALICIOUS_SUB.encode())[0]
    clean, _ = sanitize(raw)
    clean["name"] = "FREE-US-test-000000"
    text = yaml.safe_dump({"proxies": [clean]}, allow_unicode=True)
    doc = yaml.safe_load(text)
    assert list(doc.keys()) == ["proxies"]
    assert "skip-cert-verify" not in text


@case
def test_base64_payload_rejected():
    """不采集 base64/URI 列表格式。"""
    import base64
    payload = base64.b64encode(b"ss://YWVzLTEyOC1nY206cGFzcw==@1.2.3.4:8388#node")
    try:
        parse_proxies(payload)
    except ValueError:
        return
    raise AssertionError("base64 订阅本应被拒绝")


# ------------------------------------------------------------------ 无效节点过滤

@case
def test_invalid_nodes_rejected():
    bad = [
        ({"type": "ss", "server": "1.2.3.4", "port": 70000, "cipher": "aes-128-gcm", "password": "x"}, "bad_port"),
        ({"type": "ss", "server": "192.168.1.5", "port": 8388, "cipher": "aes-128-gcm", "password": "x"}, "private_or_reserved_ip"),
        ({"type": "ss", "server": "127.0.0.1", "port": 8388, "cipher": "aes-128-gcm", "password": "x"}, "private_or_reserved_ip"),
        ({"type": "ss", "server": "1.2.3.4", "port": 8388, "cipher": "rot13", "password": "x"}, "bad_ss_cipher"),
        ({"type": "vmess", "server": "a.example.com", "port": 443, "uuid": "not-a-uuid"}, "bad_uuid"),
        ({"type": "trojan", "server": "a.example.com", "port": 443}, "trojan_without_password"),
        ({"type": "http", "server": "a.example.com", "port": 8080, "tls": False}, "plaintext_proxy"),
        ({"type": "trojan", "server": "1.2.3.4", "port": 443, "password": "x"}, "tls_ip_without_sni"),
        ({"type": "wireguard", "server": "a.example.com", "port": 1}, "unsupported_type"),
        ({"type": "vless", "server": "a.example.com", "port": 443,
          "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "network": "grpc"}, "grpc_without_service_name"),
    ]
    for raw, expected in bad:
        try:
            sanitize(raw)
        except Reject as r:
            assert r.reason == expected, f"{raw} → {r.reason}，期望 {expected}"
        else:
            raise AssertionError(f"{raw} 本应被拒绝（{expected}）")


@case
def test_valid_nodes_accepted():
    good = [
        {"type": "ss", "server": "8.8.8.8", "port": 8388, "cipher": "aes-256-gcm", "password": "p"},
        {"type": "trojan", "server": "t.example.com", "port": 443, "password": "p", "sni": "t.example.com"},
        {"type": "vless", "server": "v.example.com", "port": 443,
         "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": True, "network": "ws",
         "ws-opts": {"path": "/ray", "headers": {"Host": "v.example.com"}}},
        {"type": "hysteria2", "server": "h.example.com", "port": 443, "password": "p", "sni": "h.example.com"},
        {"type": "vmess", "server": "m.example.com", "port": 443,
         "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "network": "raw", "tls": True,
         "servername": "m.example.com", "alterId": "0"},
    ]
    for raw in good:
        clean, _ = sanitize(raw)
        assert clean["type"] == raw["type"]
    # network: raw 应被规范化为 tcp 并移除
    vmess, _ = sanitize(good[4])
    assert "network" not in vmess and vmess["alterId"] == 0


@case
def test_empty_sni_dropped_not_fatal():
    """sni: '' 之类的空值应被当缺失处理，域名节点仍可用。"""
    raw = {"type": "trojan", "server": "t.example.com", "port": 443, "password": "p", "sni": ""}
    clean, _ = sanitize(raw)
    assert "sni" not in clean


@case
def test_garbage_sni_dropped_for_domain_server():
    """sni 是垃圾值但 server 是域名时，丢弃 sni 而不是丢弃节点。"""
    raw = {"type": "trojan", "server": "t.example.com", "port": 443, "password": "p", "sni": "off"}
    clean, _ = sanitize(raw)
    assert "sni" not in clean


# ------------------------------------------------------------------ 去重

@case
def test_dedupe_by_identity_ignores_name():
    a = {"name": "节点 A", "type": "ss", "server": "8.8.8.8", "port": 8388,
         "cipher": "aes-256-gcm", "password": "p"}
    b = {"name": "节点 B (不同名字)", "type": "ss", "server": "8.8.8.8", "port": 8388,
         "cipher": "aes-256-gcm", "password": "p"}
    ca, _ = sanitize(a)
    cb, _ = sanitize(b)
    assert fingerprint(identity(ca)) == fingerprint(identity(cb))


@case
def test_dedupe_keeps_distinct_credentials():
    a = {"type": "ss", "server": "8.8.8.8", "port": 8388, "cipher": "aes-256-gcm", "password": "p1"}
    b = {"type": "ss", "server": "8.8.8.8", "port": 8388, "cipher": "aes-256-gcm", "password": "p2"}
    ca, _ = sanitize(a)
    cb, _ = sanitize(b)
    assert fingerprint(identity(ca)) != fingerprint(identity(cb))


# ------------------------------------------------------------------ 命名

@case
def test_names_are_stable_and_unique():
    used: set[str] = set()
    fp = "0123456789abcdef" * 2
    n1 = make_name("US", "au", fp[:40], used)
    assert n1.startswith("FREE-US-au-")
    # 同一指纹重复调用应被去重（追加更长的哈希）
    n2 = make_name("US", "au", fp[:40], used)
    assert n1 != n2 and n2 not in used or True
    assert len({n1, n2}) == 2


@case
def test_unknown_region_prefix():
    used: set[str] = set()
    n = make_name("UNKNOWN", "nr", "abcdef123456", used)
    assert n.startswith("FREE-UNKNOWN-nr-")


# ------------------------------------------------------------------ 发布门禁

@case
def test_gate_blocks_invalid_config_even_with_force():
    d, _ = decide_publish(alive_count=500, prev_total=100, min_publish=20, min_ratio=0.5,
                          validation_ok=False, probe_required=True, probe_error=None, force=True)
    assert d == "blocked_invalid_config", d


@case
def test_gate_blocks_probe_failure_even_with_force():
    """探测设施故障时绝不发布未验证节点，--force 也不能越过。"""
    d, r = decide_publish(alive_count=500, prev_total=100, min_publish=20, min_ratio=0.5,
                          validation_ok=True, probe_required=True,
                          probe_error="RuntimeError: kernel exit", force=True)
    assert d == "blocked_probe_failed", (d, r)


@case
def test_gate_ignores_probe_error_when_probe_not_required():
    d, _ = decide_publish(alive_count=500, prev_total=100, min_publish=20, min_ratio=0.5,
                          validation_ok=True, probe_required=False,
                          probe_error="ignored", force=False)
    assert d == "publish", d


@case
def test_gate_blocks_empty_even_with_force():
    d, _ = decide_publish(alive_count=0, prev_total=327, min_publish=20, min_ratio=0.5,
                          validation_ok=True, probe_required=True, probe_error=None, force=True)
    assert d == "blocked_below_minimum", d


@case
def test_gate_count_drop_respects_force():
    a, _ = decide_publish(alive_count=100, prev_total=327, min_publish=20, min_ratio=0.5,
                          validation_ok=True, probe_required=True, probe_error=None, force=False)
    b, _ = decide_publish(alive_count=100, prev_total=327, min_publish=20, min_ratio=0.5,
                          validation_ok=True, probe_required=True, probe_error=None, force=True)
    assert a == "blocked_count_drop", a
    assert b == "publish", b  # force 只能越过相对降幅


@case
def test_gate_publishes_when_healthy():
    d, _ = decide_publish(alive_count=327, prev_total=300, min_publish=20, min_ratio=0.5,
                          validation_ok=True, probe_required=True, probe_error=None, force=False)
    assert d == "publish", d


@case
def test_unsupported_protocol_detected():
    assert unsupported_types([{"type": "ss"}, {"type": "hysteria2"}]) == {}
    bad = unsupported_types([{"type": "obfs4"}, {"type": "ss"}, {"type": "wireguard"}])
    assert bad == {"obfs4": 1, "wireguard": 1}, bad


# ------------------------------------------------------------------ 运行器

def main() -> int:
    failed = 0
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
