// 离线模拟 Clash Verge Rev 的全局扩展脚本执行环境。
// 用法: node harness.js <config.json> <Script.js> <out.json>
// 只做一件事：把真实的 Script.js 的 main() 套到真实配置上，输出合并后的配置。

const fs = require("fs");
const vm = require("vm");

const [, , cfgPath, scriptPath, outPath] = process.argv;
if (!cfgPath || !scriptPath || !outPath) {
  console.error("用法: node harness.js <config.json> <Script.js> <out.json>");
  process.exit(2);
}

const config = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
const source = fs.readFileSync(scriptPath, "utf8");

const sandbox = { console: console };
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: "Script.js" });

if (typeof sandbox.main !== "function") {
  console.error("Script.js 中没有 main() 函数");
  process.exit(3);
}

let result;
try {
  result = sandbox.main(config, "BoostNet");
} catch (e) {
  console.error("main() 抛出异常：", e && e.message);
  process.exit(4);
}

fs.writeFileSync(outPath, JSON.stringify(result, null, 2), "utf8");

// 诊断输出
const groups = result["proxy-groups"] || [];
const providers = result["proxy-providers"] || {};
const names = groups.map((g) => g.name);
const dupGroups = names.filter((n, i) => names.indexOf(n) !== i);
const mainGroup = groups.filter((g) => g.name === "BoostNet")[0];
const freeMembers = (mainGroup && mainGroup.proxies ? mainGroup.proxies : []).filter(
  (n) => String(n).indexOf("免费") === 0
);

console.log("providers:", Object.keys(providers).join(",") || "(none)");
console.log("groups:", groups.length, "| 重复组名:", dupGroups.length ? dupGroups.join(",") : "无");
console.log("BoostNet 成员数:", mainGroup ? (mainGroup.proxies || []).length : 0);
console.log("BoostNet 中的免费成员:", freeMembers.join(" | ") || "(none)");
console.log("BoostNet 前三项:", mainGroup ? (mainGroup.proxies || []).slice(0, 3).join(" | ") : "-");
const manual = groups.filter((g) => g.name === "免费节点-手动")[0];
console.log("免费节点-手动 成员:", manual ? (manual.proxies || []).join(" | ") : "(missing)");
const selfRef = groups.filter((g) => (g.proxies || []).indexOf(g.name) !== -1).map((g) => g.name);
console.log("自引用组（循环）:", selfRef.length ? selfRef.join(",") : "无");
