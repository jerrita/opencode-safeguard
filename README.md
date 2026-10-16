# opencode-safeguard

OpenCode V2 插件：在内容传给 LLM 之前做敏感信息脱敏，工具在本地执行前还原真值，操作不受影响。

## 原理

- **LLM 边界脱敏**：`session.hook("context" / "compaction" / "generate" / "title")` 改写发往模型的 `system` + `messages`（含用户 prompt、tool 输出回放、tool call 参数），只影响本次请求，不改持久化历史。
- **本地执行还原**：`tool.hook("execute.before")` 把占位符换回真值后再执行，bash/write/edit 拿到真实 secret。
- **Vault 映射**：内存 `Map<真值, __SG_<TYPE>_<N>__>`，按 session 隔离、同值同占位符、进程生命周期持有、不落盘。
- `prompt` hook 不做脱敏（它会改持久化输入，真值丢失后无法还原）；`tool.execute.after` 不改输出（下次 context hook 会再次脱敏）。

## 检测范围

1. `.env` 精确值（默认 `.env,.env.local,.env.production`）
2. 内置高可信 pattern：AWS、GitHub、Stripe、OpenAI、Anthropic、Slack、JWT、PEM 私钥、Bearer、连接串、`password|secret|token|api_key` 赋值形
3. Vendored 规则：构建时从 `gitleaks v8.30.1` 默认配置（MIT）转换的 221 条 provider 规则，随包发布、运行时零依赖零网络；gitleaks 的 allowlist/stopwords/keywords 一并转换，用于误杀控制与热路径预过滤
4. 高熵兜底：长度≥20 + Shannon 熵≥4.5 + 多字符集（可调）

更新 vendored 规则：`npm run vendor-rules [-- --ref vX.Y.Z]`（需网络，生成 `src/vendored-rules.ts` 后提交）。

## 开关与配置

只有一个命令项：`/safeguard`（TUI）。执行后打开配置菜单：启用/禁用、审计日志开关、检测灵敏度（strict/balanced/relaxed）。侧边栏底部常驻显示 `safeguard on/off`。

| 方式 | 说明 |
|---|---|
| `/safeguard` | TUI 配置菜单（推荐） |
| 环境变量 | `OPENCODE_SAFEGUARD_ENABLED=0` 关闭，`=1` 开启；作为启动默认值，可被菜单覆盖 |

运行时优先级：配置菜单（持久化到 storage）> 环境变量 > 插件 `options.enabled` > 默认开启。无 TUI 环境（headless）下用环境变量开关。

## 架构

- `src/index.ts` 服务端插件：LLM 边界脱敏 + 本地执行还原，状态由内存对象持有，经 RPC 读写。
- `src/rpc.ts` 共享 RPC 契约（`getState/setEnabled/setAudit/setSensitivity` + `updated` 事件），经 `./rpc` 导出。
- `src/tui.tsx` TUI 插件（经 `./tui` 导出）：注册 `/safeguard`、配置菜单、`sidebar.footer` 状态位。经 RPC 与服务端通信，支持远端 server。

## 安装

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    [{ "package": "opencode-safeguard", "options": {
      "enabled": true,
      "envFiles": [".env", ".env.local"],
      "extraValues": [],
      "minValueLength": 6,
      "minEntropy": 4.5,
      "minTokenLength": 20
    } }]
  ]
}
```

## 开发

```sh
npm install
npm test
npm run build
```
