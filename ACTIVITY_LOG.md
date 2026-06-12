# SRC Hunter MCP Server — 项目活动日志

> **目的**：记录每个会话的所有代码变更、决策和交付物。
> **更新规则**：每次完成一个功能点后立即追加。

---

## 会话总览

| 会话 | 负责人 | 模块 | 文件 | 状态 |
|------|--------|------|------|------|
| **A** | Claude (当前) | Recon + Report + Engine | `recon.py`, `report.py`, `server.py`, `executor.py`, `cache.py`, `validators.py` | ✅ 6/6 Tool 完成 |
| **B** | Claude | 指纹识别 | `fingerprint.py` | 🔄 进行中 |
| **C** | Claude | 漏洞检测 | `vuln.py` | 🔄 进行中 |

---

## 会话 A（当前）— 详细记录

### 2026-06-12

#### Commit `92c64f6` — v0.1.0: 项目初始化
- 创建项目骨架（pyproject.toml, .gitignore, README.md, PROGRESS.md）
- 实现 `subdomain_enum` Tool：crt.sh API 查询 + 去重 + 缓存 + 重试
- 实现 `validators.py`：域名/URL 校验，拦截 localhost/内网域
- 实现 `cache.py`：10min TTL 内存缓存
- 实现 `server.py`：MCP SDK 1.27 list_tools/call_tool 模式
- 测试：`test_recon.py`（13 个）+ `test_integration.py`（4 个含 crt.sh 真 API）
- 配置：`claude mcp add srchunter` 写入 `.claude.json`

#### Commit `09566a3` — docs: 多会话并行开发规范
- 编写 `TOOLS_SPEC.md`：12 个 Tool 的接口契约（inputSchema + output JSON）
- 编写 `SESSION_PROMPTS.md`：B/C 会话启动文案
- 决策：B → fingerprint.py，C → vuln.py，A → recon/report/engine
- 规则：单文件独占、接口先行、先读后写、提交即推送

#### Commit `d780526` — v0.2.0: Recon 扩展 + Report + Executor
- **resolve_targets**：异步 DNS 解析 + CDN 检测（22 个 CNAME 模式 + CF/Fastly IP 前缀）
- **port_scan**：TCP connect 扫描，top-20/100 预设 + 自定义列表/范围
- **http_probe**：HTTP/HTTPS 探活，提取 title/server/content-length
- **analyze_surface**：关联分析 recon + fingerprint + vuln，优先级评分
- **generate_report**：Markdown / JSON SRC 漏洞报告
- **executor.py**：异步 subprocess 封装，超时/输出截断/无 shell 注入
- 测试：`test_recon_new.py`（19 个）+ `test_report.py`（11 个）
- 全量测试：35→46 passed

#### Commit `68c1ca6` — docs: 进度更新
- 更新 PROGRESS.md 需求状态

---

## 会话 B — 详细记录

> ⏳ 等待 B 会话提交后填写

---

## 会话 C — 详细记录

> ⏳ 等待 C 会话提交后填写

---

## 合并记录

> ⏳ 等待 B/C 完成后，由 A 会话合并 server.py dispatch 路由

---

## 当前技术栈

| 层 | 技术 | 版本 |
|----|------|------|
| Python | 3.13.12 | — |
| MCP SDK | `mcp` | 1.27.1 |
| HTTP | `httpx` | 0.28.1 |
| 测试 | `pytest` | 9.0.3 |
| 异步 | `pytest-asyncio` | 1.4.0 |

## 当前文件清单

```
src/srchunter/
├── __init__.py
├── server.py              # MCP 入口，6 Tool dispatch
├── tools/
│   ├── __init__.py
│   ├── recon.py           # subdomain_enum / resolve_targets / port_scan / http_probe
│   ├── report.py          # analyze_surface / generate_report
│   ├── fingerprint.py     # ⬜ B 会话待提交
│   └── vuln.py            # ⬜ C 会话待提交
├── engine/
│   ├── __init__.py
│   ├── cache.py           # 10min TTL 会话缓存
│   └── executor.py        # 异步 subprocess 封装
└── utils/
    ├── __init__.py
    └── validators.py      # 域名/URL 校验
```
