# FreeNode Hub

把多个公开免费节点源聚合成**一个长期固定的 Clash/Mihomo 订阅 URL**，每 6 小时自动更新。

- 产物：`dist/free-proxies.yaml`（**只有一个顶层 `proxies` 字段**，不含规则/DNS/TUN/脚本）
- 运行方式：GitHub Actions 定时构建，无服务器、无需常开设备
- 接入方式：Clash Verge Rev 的全局扩展脚本，作为**独立 proxy-provider**接入，不动现有付费订阅

> A self-hosted aggregator that turns several public free-node sources into one stable
> Clash/Mihomo subscription URL, rebuilt by GitHub Actions every 6 hours.
> Output contains nothing but a top-level `proxies` list.

---

## 1. 它做了什么

```
3 个公开源 ──抓取(限大小/超时/重试)──> 只取 proxies
   └─> 字段白名单清洗（剥离 skip-cert-verify / dialer-proxy / script 等）
   └─> 结构校验（协议、端口、地址、UUID、TLS 参数）
   └─> 指纹去重（协议+端点+认证参数）
   └─> GeoIP 判定地区（不看节点名）
   └─> 单源/总量配额
   └─> Mihomo 内核 -t 校验
   └─> 真实代理探测（真跑一次 HTTP 204）
   └─> 发布门禁（数量骤降/校验失败 → 保留旧版本）
   └─> dist/free-proxies.yaml
```

## 2. 数据来源

| ID | 仓库 | 订阅地址 | 许可 | 是否进入公开产物 |
| --- | --- | --- | --- | --- |
| `au` | [Au1rxx/free-vpn-subscriptions](https://github.com/Au1rxx/free-vpn-subscriptions) | `raw…/output/clash.yaml` | MIT | ✅ 是 |
| `zh` | [zhuhaiuk/free-nodes](https://github.com/zhuhaiuk/free-nodes) | `raw…/clash_config.yaml` | 未声明 | ❌ 否 |
| `nr` | [nodesradar/nodesradar-en](https://github.com/nodesradar/nodesradar-en) | `https://radarhub.top/clash.yaml` | 未声明 | ❌ 否 |

只采集这些源明确公开的免费节点；不触碰任何付费、鉴权或私人订阅。

**关于再分发**：未声明许可 ≠ 已获得再分发授权。`config/sources.yaml` 里每个源都有
`redistribute` 开关，默认 `false`；只有明确许可允许的来源才会进入这个**公开**仓库的产物。
要让 `zh` / `nr` 参与，请先自行确认其条款，再把对应的 `redistribute` 改成 `true`。
被排除的来源会在 `stats.json` 的 `sources_excluded_by_license` 里列出，不会静默消失。

## 3. 目录

```
config/sources.yaml          来源清单、单源配额、发布阈值
src/common.py                受限 HTTP 抓取、日志脱敏、指纹
src/sanitize.py              字段白名单 + 结构与 TLS 校验
src/geo.py                   地区判定（GeoIP + DNS 缓存）
src/validate.py              Mihomo 内核 -t 校验
src/probe.py                 真实代理探测（内核 API delay 测试）
src/build.py                 流水线主程序
tools/prepare_deps.sh        下载 Mihomo 内核与 Country.mmdb
tools/clash-verge/           客户端集成脚本 + 离线验证工具
tests/test_pipeline.py       离线单测：清洗/去重/门禁/协议（无第三方依赖）
tests/test_failure_modes.py  故障回归：下载失败/0 节点/内核起不来/缓存保全/脚本幂等
dist/free-proxies.yaml       发布产物
dist/stats.json              每轮统计
```

## 4. 本地运行

```bash
pip install -r requirements.txt
# 需要 Mihomo 内核与 Country.mmdb
bash tools/prepare_deps.sh bin

python tests/test_pipeline.py          # 离线单测
python src/build.py \
  --mmdb Country.mmdb --mihomo ./bin/mihomo \
  --summary /tmp/summary.md
```

常用开关：

| 参数 | 作用 |
| --- | --- |
| `--no-probe` | 跳过真实代理探测，只做结构校验（快） |
| `--probe-limit N` | 最多探测多少个节点 |
| `--force` | 忽略数量下降门禁（仅排障） |
| `--cache-dir` / `--cache-max-age-h` | 源缓存目录与有效期（默认 48 小时，仅在线抓取失败时回退） |
| `--use-env-proxy` | 抓取时使用系统代理环境变量（默认直连） |

退出码：`0` 成功 / `2` 数量门禁拦截 / `3` 内核校验失败 / `1` 致命错误。

## 5. 接入 Clash Verge Rev

本仓库按**公开仓库**部署，订阅地址是固定的 raw 直链，**不需要任何 token，也不会过期**：

```
https://raw.githubusercontent.com/<owner>/free-node-hub/main/dist/free-proxies.yaml
```

1. 打开 Clash Verge → **设置 → 配置 → 全局扩展脚本**（Merge/Script 覆写）。
2. 把 `tools/clash-verge/Script.js` 全文粘贴进去，只改 `FNH_OWNER`（你的 GitHub 用户名）。
3. 保存后 Clash Verge 会重建配置并热加载，无需重启。

脚本做三件事，全部是"只增加、不替换"：

- 写入一个 `proxy-providers.free-node-hub`（`interval: 21600`，health-check 为 Mihomo 官方写法）
- 新增 8 个免费组，其中 **`免费节点-本地优选`** 是重点：
  `url-test` + `lazy: false` + `interval: 1800` + `expected-status: 204`，
  内核启动后持续在**本机**实测，每 30 分钟全量重测并自动切到当前最快的节点。
  完全用内核原生能力，没有常驻 Python 进程，也不需要你手动重选。
- 新增内部组 **`订阅更新出口`**（`fallback`：`自动选择` → `DIRECT`），作为 provider 的拉取出口：
  内核拉订阅是**自己直连**、不走系统代理，而 `raw.githubusercontent.com` 在国内基本连不上；
  绑死付费线路又会在机场挂掉时彻底断更。用 fallback 优先走付费、付费不通落直连，
  且**不引用任何免费节点**，不会形成"免费组 → provider → 免费组"的循环依赖。
- 追加 7 个代理组：`免费节点-AUTO` / `免费节点-手动` / `免费香港` / `免费日本` / `免费美国` / `免费新加坡` / `免费台湾`
- 把这 7 个组**追加到主选择组（`MATCH` 指向的 select 组）的末尾**

原有 proxies、规则、DNS、TUN、端口、付费代理组全部不动；当前选中的付费节点也不会变。
免费源整体挂掉时，provider 拉取失败 → 组内为空 → Mihomo 允许空组，配置不会解析失败，
付费线路照常可用。

改完脚本后可以**离线验证**，不用真的应用：

```bash
python tools/clash-verge/verify_integration.py \
  --config "%APPDATA%/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml" \
  --mihomo "C:/Program Files/Clash Verge/verge-mihomo.exe"
```

它会执行真实的 `Script.js`，断言"原组不丢、规则不减、tun/dns 不变"，再跑三遍内核校验
（真实 URL / 本地产物 / 空 provider 故障）。

> 若哪天把仓库改成私有，`raw` 直链会 404。此时改用 GitHub Contents API 并带只读 PAT，
> 写法见 `Script.js` 中被注释掉的那两行——注意 Mihomo 要求 `header` 的值是**字符串数组**，
> 写成裸字符串会报 `is not a slice`。

## 6. 失败与回滚

| 场景 | 行为 |
| --- | --- |
| 某个源下载失败 | 回退 48 小时内的源缓存，`stats.json` 标注 `from_cache`；再失败则该源计 0，其余源继续 |
| 全部源失败 | 发布门禁拦截，**保留上一版 `dist/free-proxies.yaml`**，退出码 2 |
| 节点数骤降（< 上一版 50%） | 同上，退出码 2 |
| 内核校验失败 | 同上，退出码 3 |
| **探测内核起不来 / 节点未全部加载 / API 异常** | **直接中止发布，保留上一版**，退出码 2，`gate.decision=blocked_probe_failed` |
| 免费节点全挂（0 个） | 门禁拦截；客户端侧组为空但不报错，付费线路不受影响 |
| 客户端拉取订阅失败 | 内核继续用 `./providers/free-node-hub.yaml` 里的**上一份缓存**，不会清空 |

**`--force` 的边界**：只能跳过"相对上一版的降幅"判断。以下三条它一律越不过去——
配置校验失败、探测设施故障、低于绝对下限 `min_publish`（默认为 20）。所以它永远不会发出空订阅。

`--no-probe` 只用于人工排障，产出的 `stats.json` 会明确记 `probe.enabled: false`，
不会被当成"已探测"。定时任务永远走带探测的路径。

GitHub 侧回滚：

```bash
git revert <commit>        # 或者
git checkout <上一个好版本> -- dist/free-proxies.yaml && git commit -m "rollback"
```

客户端侧回滚：把全局扩展脚本里 `FNH.url` 清空或删除整段 `injectFreeNodes` 调用即可，
付费订阅不受任何影响。彻底回到初始状态：恢复 `_backup/clash-verge-config-*.zip`。

## 7. 定时任务被自动停用的应对

GitHub 对**连续 60 天无提交**的仓库会停用 schedule。本仓库每次节点集合变化都会产生一次
真实提交（免费节点天然高频变动），通常不会触发；即便如此仍提供两条恢复路径：

1. 仓库页面 **Actions → Update free node subscription → Enable workflow**
2. 命令行：`gh workflow enable update-nodes.yml`

**不会**为了"保持活跃"而制造空提交。若真被停用，最直接的信号是客户端里免费节点列表长时间不变
（超过 24 小时未变化即需检查）。

## 8. 连续失败告警（不花钱）

每次运行结束都会检查：若**本次失败 + 最近两次也失败**，就自动开一个带 `build-failure`
标签的 Issue，标题为「构建连续失败：免费节点订阅可能已停止更新」，正文带最近三次结论和
本次运行链接；下一次成功构建会**自动关闭**该 Issue。

没有引入任何第三方监控服务，用的就是 GitHub 自己的 Issue 和 `GITHUB_TOKEN`（权限只要
`issues: write`）。关掉桌面通知也能在仓库首页看到这个 Issue。

## 9. 已知限制

- 探测在 GitHub 云端执行，**只证明"从 GitHub runner 可达"，不等于你本机可用**。
  国内网络对同一节点可达性差异可能很大，所以免费节点定位是"备用线路"，不是主力线路。
- 上游未声明许可，节点可用性与合法性由上游负责；本项目只做技术聚合。
- 免费节点带宽、稳定性、隐私均无保障，不要用免费节点登录敏感账号。
- `dist/free-proxies.yaml` 是公开的，任何人都能读到里面的节点凭据——但这正是上游的发布形态。

## 10. 实测数据（2026-11-05，首次上线）

| 环节 | 数字 |
| --- | --- |
| 三源原始节点 | 2281（zh 30 / au 1751 / nr 500） |
| 清洗通过 | 646 |
| 单源配额裁剪后 | 573（zh 6 / au 320 / nr 320） |
| 跨源去重移除 | 73 |
| GeoIP 定位 | 457 个地址，424 个定位成功，33 个 Unknown |
| GitHub 云端真实探测 | **573 → 327 存活（57%）** |
| 单次 Actions 耗时 | 约 1–1.5 分钟 |
| 发布产物大小 | 57.7 KB / 327 个节点 |
| **本机（国内直连）实测可用** | **9 / 327 = 2%**（IT 7、US 1、CN 1） |

最后一行是这个系统最重要的一个数字：**云端 57% 通过率，到你本机只剩 2%**。
原因很直接——CI 在美国 Azure 机房，国内直连海外免费节点的成功率天然低一个数量级。
所以免费节点的定位只能是"付费线路挂了时的应急备胎"，不能当主力。

## 11. 长期维护评估（客观）

真正需要人动手的只有下面这些，其余全自动：

| 事项 | 频率 | 不做会怎样 |
| --- | --- | --- |
| 上游源失效（仓库改名/停更/改结构） | 不可预期 | 该源计 0，其余源照常；`stats.json` 与 Actions 摘要会显示 `FAIL`，需要补一个新源到 `config/sources.yaml` |
| 定时任务被 GitHub 停用 | 60 天无提交才可能 | 见第 7 节，一键重新启用 |
| Actions 用量 | 每 6 小时约 5–8 分钟 | 公开仓库的 Actions 分钟数不计量，**零成本** |

**没有**需要常开的设备、没有需要守着的进程、没有需要定期手工点"更新"的按钮。
主要的不确定性来自上游免费源本身——这类源天然短命，这也是为什么本系统把"源失效"设计成
可降级而不是可崩溃。

## 12. 许可

本仓库代码 MIT。`dist/` 下的节点数据版权归各上游来源所有，本项目不主张任何权利。
