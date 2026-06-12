# SRC Hunter MCP Server — 项目进度

## 版本：0.2.0-alpha

---

## 需求清单

### Phase 1: MVP — 资产收集基础能力

| ID | 需求 | 状态 | 备注 |
|----|------|------|------|
| R1.1 | `subdomain_enum` Tool — crt.sh 查询 | ✅ 已实现 | 纯 Python，含缓存/重试/校验 |
| R1.2 | 域名输入校验 | ✅ 已实现 | 阻止 localhost/内网域名 |
| R1.3 | crt.sh 结果解析与去重 | ✅ 已实现 | 处理 CN + SAN 字段 |
| R1.4 | 结果缓存 | ✅ 已实现 | 10min TTL，同 session 免重复查询 |
| R1.5 | 单元测试 | ✅ 已实现 | 6 个解析测试 + 校验集成测试 |
| R1.6 | 在 Claude Code 中集成验证 | ⬜ 待验证 | MCP server 已注册，需重启会话加载 |

### Phase 2: 资产收集扩展

| ID | 需求 | 状态 |
|----|------|------|
| R2.1 | `resolve_targets` Tool — DNS解析+CDN检测 | ✅ 已实现 | DNS + 22 CNAME 模式 + CF/Fastly IP 前缀 |
| R2.2 | `port_scan` Tool — 端口扫描 | ✅ 已实现 | TCP connect，top-20/100 预设 + 自定义 |
| R2.3 | `http_probe` Tool — HTTP探活 | ✅ 已实现 | HTTP/S 探活 + title/server/content-length |

### Phase 3: 指纹识别

| ID | 需求 | 状态 |
|----|------|------|
| R3.1 | `tech_detect` Tool — 技术栈识别 | ✅ |
| R3.2 | `fingerprint_services` Tool — 服务指纹 | ✅ |
| R3.3 | `identify_waf` Tool — WAF检测 | ✅ |

### Phase 4: 漏洞检测

| ID | 需求 | 状态 |
|----|------|------|
| R4.1 | `check_misconfig` Tool | ⬜ |
| R4.2 | `run_nuclei` Tool | ⬜ |
| R4.3 | `check_exploitable` Tool | ⬜ |

### Phase 5: 结果输出

| ID | 需求 | 状态 |
|----|------|------|
| R5.1 | `analyze_surface` Tool | ✅ 已实现 | 关联分析 + 优先级评分 |
| R5.2 | `generate_report` Tool | ✅ 已实现 | Markdown / JSON SRC 报告 |

---

## 变更日志

### 2026-06-12 — v0.1.0-alpha (项目初始化 + MCP 集成配置)

**新建文件：**
- `pyproject.toml` — 项目配置，依赖 mcp + httpx
- `src/srchunter/server.py` — MCP Server 入口，list_tools/call_tool 模式
- `src/srchunter/tools/recon.py` — subdomain_enum 实现
- `src/srchunter/engine/cache.py` — 会话缓存
- `src/srchunter/utils/validators.py` — 输入校验
- `tests/test_recon.py` — 单元测试（13个）
- `tests/test_integration.py` — 集成测试（4个，含 crt.sh 真 API）
- `tests/conftest.py` — 共享 fixture / --run-live 标志
- `README.md` — 项目文档
- `PROGRESS.md` — 本文件

**已实现功能：**
- `subdomain_enum` Tool：crt.sh + 去重 + 缓存 + 重试，API SDK 1.27 兼容
- 域名校验：阻止 localhost/内网域/非法格式
- MCP Server 启动正常（exit 0）
- 测试覆盖：16 passed + 1 crt.sh live passed
- Claude Code MCP 配置已注册（`claude mcp add srchunter`），待重启会话加载

### 2026-06-12 — v0.2.0-alpha (Recon 完整 + Report + 并行开发体系)

**新建文件：**
- `src/srchunter/tools/recon.py` — 新增 resolve_targets / port_scan / http_probe
- `src/srchunter/tools/report.py` — analyze_surface / generate_report
- `src/srchunter/engine/executor.py` — 外部工具执行封装（async subprocess）
- `tests/test_recon_new.py` — 19 个新测试（CDN 检测/端口解析/调度）
- `TOOLS_SPEC.md` — 12 Tool 接口契约，多会话并行开发规范
- `SESSION_PROMPTS.md` — B/C 会话启动文案

**A 会话（当前）已完成：**
- Recon：4/4 Tool ✅ （subdomain_enum / resolve_targets / port_scan / http_probe）
- Report：2/2 Tool ✅ （analyze_surface / generate_report）
- Engine：executor.py + cache.py + validators.py
- Server：dispatch 覆盖 6 个 Tool
- 测试：35 passed + 1 skipped
- GitHub：已推送，待 B/C 会话完成 fingerprint + vuln 后合并

**B/C 会话进行中：**
- B：fingerprint.py（tech_detect / fingerprint_services / identify_waf）
- C：vuln.py（check_misconfig / run_nuclei / check_exploitable）
