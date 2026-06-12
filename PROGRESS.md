# SRC Hunter MCP Server — 项目进度

## 版本：0.1.0-alpha

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
| R2.1 | `resolve_targets` Tool — DNS解析+CDN检测 | ⬜ |
| R2.2 | `port_scan` Tool — 端口扫描 | ⬜ |
| R2.3 | `http_probe` Tool — HTTP探活 | ⬜ |

### Phase 3: 指纹识别

| ID | 需求 | 状态 |
|----|------|------|
| R3.1 | `tech_detect` Tool — 技术栈识别 | ⬜ |
| R3.2 | `fingerprint_services` Tool — 服务指纹 | ⬜ |
| R3.3 | `identify_waf` Tool — WAF检测 | ⬜ |

### Phase 4: 漏洞检测

| ID | 需求 | 状态 |
|----|------|------|
| R4.1 | `check_misconfig` Tool | ⬜ |
| R4.2 | `run_nuclei` Tool | ⬜ |
| R4.3 | `check_exploitable` Tool | ⬜ |

### Phase 5: 结果输出

| ID | 需求 | 状态 |
|----|------|------|
| R5.1 | `analyze_surface` Tool | ⬜ |
| R5.2 | `generate_report` Tool | ⬜ |

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

**下一步：**
- 重启 Claude Code 会话，在 Agent 对话中实际调用 subdomain_enum
- 开始 Phase 1 LLM 理论学习
