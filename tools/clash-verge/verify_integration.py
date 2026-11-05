"""离线验证 Clash Verge 集成脚本：不碰线上配置，纯沙箱推演。

流程：
    真实运行时配置 (clash-verge.yaml)
        → 转 JSON
        → 用 Node 执行真实的 Script.js main()
        → 结构断言（provider 存在、组不重复、无循环引用、付费组未被破坏）
        → 交给 Mihomo 内核 -t 校验
        → 再把 provider 换成本地产物文件，二次校验（模拟真实加载）

用法：
    python tools/clash-verge/verify_integration.py \
        --config "%APPDATA%/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml" \
        --mihomo "C:/Program Files/Clash Verge/verge-mihomo.exe" \
        --provider dist/free-proxies.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "..", "src"))

from validate import validate_file  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="当前生效的运行时配置 yaml")
    ap.add_argument("--script", default=os.path.join(HERE, "Script.js"))
    ap.add_argument("--mihomo", required=True)
    ap.add_argument("--provider", default="dist/free-proxies.yaml")
    ap.add_argument("--mmdb", default="Country.mmdb", help="配置里含 GEOIP 规则，校验必须有 MMDB")
    ap.add_argument("--keep", action="store_true", help="保留中间文件")
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="fnh-integ-")
    cfg_json = os.path.join(workdir, "config.json")
    out_json = os.path.join(workdir, "merged.json")

    # mihomo 以 -d workdir 为工作目录，MMDB 与 file provider 都必须在其内部
    if os.path.exists(args.mmdb):
        import shutil
        shutil.copy2(args.mmdb, os.path.join(workdir, "Country.mmdb"))
    local_provider = os.path.join(workdir, "free-proxies.yaml")
    import shutil
    shutil.copy2(args.provider, local_provider)

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    with open(cfg_json, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)

    print("== 1. 执行 Script.js ==")
    proc = subprocess.run(
        ["node", os.path.join(HERE, "harness.js"), cfg_json, args.script, out_json],
        capture_output=True, text=True, encoding="utf-8",
    )
    print(proc.stdout.strip())
    if proc.returncode != 0:
        print(proc.stderr.strip())
        return 1

    with open(out_json, encoding="utf-8") as f:
        merged = json.load(f)

    print("\n== 2. 结构断言 ==")
    ok = True
    providers = merged.get("proxy-providers") or {}
    if "free-node-hub" not in providers:
        print("FAIL provider 未注入"); ok = False
    else:
        p = providers["free-node-hub"]
        print(f"  provider: type={p.get('type')} interval={p.get('interval')} "
              f"health-check={p.get('health-check', {}).get('enable')}")

    orig_groups = {g["name"]: set(g.get("proxies") or []) for g in cfg.get("proxy-groups") or []}
    new_groups = {g["name"]: g for g in merged.get("proxy-groups") or []}
    for name, members in orig_groups.items():
        if name not in new_groups:
            print(f"FAIL 原有代理组 {name} 丢失"); ok = False
            continue
        lost = members - set(new_groups[name].get("proxies") or [])
        if lost:
            print(f"FAIL 代理组 {name} 丢失成员: {sorted(lost)[:5]}"); ok = False
    if orig_groups:
        print(f"  原有 {len(orig_groups)} 个代理组全部保留，成员无丢失")

    if cfg.get("rules") != merged.get("rules"):
        # 只允许前置新增，不允许删改
        added = [r for r in merged["rules"] if r not in (cfg.get("rules") or [])]
        removed = [r for r in (cfg.get("rules") or []) if r not in merged["rules"]]
        if removed:
            print(f"FAIL 原规则被删除 {len(removed)} 条"); ok = False
        else:
            print(f"  规则：原 {len(cfg.get('rules') or [])} 条全保留，前置新增 {len(added)} 条")

    for key in ("tun", "dns", "mode", "mixed-port"):
        if cfg.get(key) != merged.get(key):
            print(f"FAIL 顶层 {key} 被改动"); ok = False
    if ok:
        print("  tun / dns / mode / 端口 均未被改动")

    print("\n== 3. 内核校验（provider 指向真实 URL，测试拉取失败的容错） ==")
    ok1, msg1 = validate_file(args.mihomo, out_json)
    print("  " + ("通过" if ok1 else "失败"))
    if not ok1:
        print(msg1[-1200:])

    print("\n== 4. 内核校验（provider 指向本地产物，模拟真实加载） ==")
    merged["proxy-providers"]["free-node-hub"] = {"type": "file", "path": local_provider}
    local_json = os.path.join(workdir, "merged-local.json")
    with open(local_json, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False)
    ok2, msg2 = validate_file(args.mihomo, local_json)
    print("  " + ("通过" if ok2 else "失败"))
    if not ok2:
        print(msg2[-1500:])

    print("\n== 5. 空 provider 故障测试（免费源全挂） ==")
    empty = os.path.join(workdir, "empty.yaml")
    with open(empty, "w", encoding="utf-8") as f:
        f.write("proxies: []\n")
    merged["proxy-providers"]["free-node-hub"] = {"type": "file", "path": empty}
    empty_json = os.path.join(workdir, "merged-empty.json")
    with open(empty_json, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False)
    ok3, msg3 = validate_file(args.mihomo, empty_json)
    print("  " + ("通过（空组不影响解析）" if ok3 else "失败"))
    if not ok3:
        print(msg3[-1500:])

    print(f"\n中间文件: {workdir}")
    print("结论:", "全部通过" if (ok and ok1 and ok2 and ok3) else "存在失败项")
    return 0 if (ok and ok1 and ok2 and ok3) else 1


if __name__ == "__main__":
    sys.exit(main())
