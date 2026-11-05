// ============================================================================
// Clash Verge Rev 全局扩展脚本（Merge/Script 覆写机制）
//
// 作用：
//   1) 【已有】家庭内网 / M365 / OneDrive 直连规则修补（2026-11-05）
//   2) 【新增】FreeNode Hub 免费节点集成（独立 proxy-provider + 独立代理组）
//
// 设计约束：
//   * 只"增加"，不"替换"：付费订阅的 proxies / 规则 / DNS / TUN 一概不碰。
//   * 幂等：反复执行不会产生重复 provider、重复组、重复成员。
//   * 失败安全：整段包在 try/catch 里；注入失败只是没有免费节点，
//     绝不让配置生成整体报错导致断网。
//   * 组内可能一个节点都没有（免费源挂了）——Mihomo 允许空组，不会导致解析失败；
//     同时每个组都挂了 DIRECT 兜底，避免"选中一个空组"时无路可走。
// ============================================================================

// ---- FreeNode Hub 配置：只需要改用户名这一处 ---------------------------------
// 【必改】你的 GitHub 用户名
var FNH_OWNER = "liuweicool77-maker";
// 仓库名（一般不用改）
var FNH_REPO = "free-node-hub";

var FNH = {
  // 公开仓库：raw 直链即可，无需任何 token，也不会过期
  url: "https://raw.githubusercontent.com/" + FNH_OWNER + "/" + FNH_REPO +
       "/main/dist/free-proxies.yaml",
  // 如果 raw.githubusercontent 被墙/超时，可临时换成 jsDelivr CDN（分支缓存约 12 小时）：
  // url: "https://cdn.jsdelivr.net/gh/" + FNH_OWNER + "/" + FNH_REPO + "@main/dist/free-proxies.yaml",
  //
  // 若将来改成私有仓库，则改用下面两行（需自行填 PAT，注意 Mihomo 要求 header 值为字符串数组）：
  // url: "https://api.github.com/repos/" + FNH_OWNER + "/" + FNH_REPO + "/contents/dist/free-proxies.yaml?ref=main",
  // header: { Authorization: ["Bearer github_pat_xxx"], Accept: ["application/vnd.github.raw"] },
  providerName: "free-node-hub",
  providerPath: "./providers/free-node-hub.yaml",
  updateInterval: 21600,          // 6 小时，与 Actions 同频
  healthCheckUrl: "http://www.gstatic.com/generate_204",
  healthCheckInterval: 600,
  // 组定义：filter 只匹配我们自己的命名规则 FREE-<地区>-<来源>-<哈希>，
  // 不会误抓到付费节点，也不依赖上游节点名。
  groups: [
    { name: "免费节点-AUTO", type: "url-test" },
    { name: "免费节点-手动", type: "select" },
    { name: "免费香港", type: "url-test", filter: "^FREE-HK-" },
    { name: "免费日本", type: "url-test", filter: "^FREE-JP-" },
    { name: "免费美国", type: "url-test", filter: "^FREE-US-" },
    { name: "免费新加坡", type: "url-test", filter: "^FREE-SG-" },
    { name: "免费台湾", type: "url-test", filter: "^FREE-TW-" }
  ]
};
// ---------------------------------------------------------------------------

function main(config, profileName) {
  // ===== 第一段：内网 / M365 / OneDrive 规则修补（原有逻辑，保持不变） =====
  try {
    const wanted = [
      "DOMAIN,n1.7713456.xyz,DIRECT",
      "DOMAIN,nas.7713456.xyz,DIRECT",
      "DOMAIN,ai.7713456.xyz,DIRECT",
      "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
      "IP-CIDR,192.168.2.0/24,DIRECT,no-resolve"
    ];
    const rules = Array.isArray(config.rules) ? config.rules : [];
    const missing = wanted.filter(function (r) {
      return rules.indexOf(r) === -1;
    });
    config.rules = missing.concat(rules);
  } catch (e) {
    // 异常不阻断配置加载
  }

  // ===== 第二段：FreeNode Hub 免费节点注入（新增） =====
  try {
    injectFreeNodes(config);
  } catch (e) {
    // 免费节点是附加能力：注入失败必须静默降级，保证付费线路照常可用
  }

  return config;
}

function injectFreeNodes(config) {
  if (!config || typeof config !== "object") return;

  var groupList = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  var wantedNames = FNH.groups.map(function (g) { return g.name; });

  // --- 1) provider：覆盖式写入，天然幂等 ---
  if (!config["proxy-providers"] || typeof config["proxy-providers"] !== "object") {
    config["proxy-providers"] = {};
  }
  config["proxy-providers"][FNH.providerName] = {
    type: "http",
    url: FNH.url,
    path: FNH.providerPath,
    interval: FNH.updateInterval,
    "health-check": {
      enable: true,
      url: FNH.healthCheckUrl,
      interval: FNH.healthCheckInterval,
      lazy: true
    }
  };
  if (FNH.header) {
    config["proxy-providers"][FNH.providerName].header = FNH.header;
  }

  // --- 2) 组：先剔除同名旧组再重建，避免订阅更新后重复注入 ---
  var kept = groupList.filter(function (g) {
    return !g || wantedNames.indexOf(g.name) === -1;
  });

  var built = FNH.groups.map(function (spec) {
    var g = { name: spec.name, type: spec.type, use: [FNH.providerName] };
    if (spec.filter) g.filter = spec.filter;
    if (spec.type !== "select") {
      g.url = FNH.healthCheckUrl;
      g.interval = FNH.healthCheckInterval;
      g.tolerance = 50;
      g.lazy = true;
    }
    return g;
  });

  // 手动组做成"总入口"：地区组 + DIRECT + provider 全部节点
  var manual = built.filter(function (g) { return g.name === "免费节点-手动"; })[0];
  if (manual) {
    manual.proxies = ["免费节点-AUTO", "免费香港", "免费日本", "免费美国",
                      "免费新加坡", "免费台湾", "DIRECT"];
  }

  config["proxy-groups"] = kept.concat(built);

  // --- 3) 挂到主选择组：找 MATCH 指向的 select 组，把免费组追加到末尾 ---
  var rules = Array.isArray(config.rules) ? config.rules : [];
  var target = null;
  for (var i = rules.length - 1; i >= 0; i--) {
    var line = String(rules[i] || "").trim();
    if (line.indexOf("MATCH") === 0) {
      var parts = line.split(",");
      target = (parts[1] || "").trim();
      break;
    }
  }

  var all = config["proxy-groups"];
  var mainGroup = null;
  for (var j = 0; j < all.length; j++) {
    if (all[j] && all[j].name === target && all[j].type === "select") { mainGroup = all[j]; break; }
  }
  if (!mainGroup) {
    for (var k = 0; k < all.length; k++) {
      if (all[k] && all[k].type === "select") { mainGroup = all[k]; break; }
    }
  }
  if (!mainGroup) return;

  var members = Array.isArray(mainGroup.proxies) ? mainGroup.proxies.slice() : [];
  // 去掉历史残留的同名项，再统一追加到末尾（付费线路保持在列表最前）
  members = members.filter(function (n) { return wantedNames.indexOf(n) === -1; });
  mainGroup.proxies = members.concat(wantedNames);
}
