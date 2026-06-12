# SRC Hunter MCP Server — 项目活动日志

> **目的**：记录每个会话的所有代码变更、决策和交付物。
> **更新规则**：每次完成一个功能点后立即追加。

---

## 会话总览

| 会话 | 负责人 | 模块 | 文件 | 状态 |
|------|--------|------|------|------|
| **A** | Claude (当前) | Recon + Report + Engine | `recon.py`, `report.py`, `server.py`, `executor.py`, `cache.py`, `validators.py` | ✅ 6/6 Tool 完成 |
| **B** | Claude | 指纹识别 | `fingerprint.py` | ✅ 3/3 Tool 完成 |
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

### 2026-06-12

#### Commit — v0.2.1: Fingerprint 三 Tool 完成
- 新建 `src/srchunter/tools/fingerprint.py`（~600 行），纯 Python 实现
- **tech_detect**：HTTP 响应分析（Server/X-Powered-By/Set-Cookie）+ HTML 脚本/元标签/生成器解析
  - 33 个服务器签名（nginx/apache/iis/cloudflare/gws/caddy…）
  - 17 个 JS 库模式（jQuery/React/Vue/Angular/Bootstrap/Next.js/Nuxt.js…）
  - 10 个 CMS 元生成器（WordPress/Drupal/Joomla/Hugo/Gatsby…）
  - 9 个 Cookie 检测（PHPSESSID/JSESSIONID/.AspNet./laravel_session…）
  - 7 个 X-Powered-By 模式 + CDN 头检测
  - 置信度：high（≥4 指标）/ medium（≥2）/ low
- **fingerprint_services**：TCP 横幅抓取 + 服务识别
  - 30+ 服务签名（SSH/HTTP/MySQL/PostgreSQL/Redis/MongoDB/FTP/SMTP/RDP/VNC…）
  - Web 端口特殊处理：发送最小化 HTTP GET 抓取 Server 头
  - 端口→服务回退映射（50+ 常见端口）
  - CPE 输出（`cpe:/a:openssh:openssh:8.9`）
- **identify_waf**：WAF/CDN 检测
  - 22 个 WAF 签名（Cloudflare/Akamai/AWS/Fastly/Sucuri/Imperva/F5/FortiWeb/ModSecurity/NAXSI/Wallarm…）
  - 检测维度：header_name / header_value / cookie / body / status
  - 最佳匹配算法（最多指标 + 最高置信度）
  - 各 WAF 绕过建议中文提示
- **server.py** 更新：注册 FINGERPRINT_TOOLS + dispatch_fingerprint_tool 路由
- **测试**：`tests/test_fingerprint.py`（46 个测试）
  - 离线解析测试：7 服务器 + 6 JS + 3 CMS + 5 Cookie + 4 X-Powered-By + 3 CDN
  - 横幅解析测试：7 个（SSH/HTTP/FTP/空横幅/MySQL/SMTP）
  - Dispatch 测试：tech_detect + identify_waf + fingerprint_services + 错误处理
  - Tool 定义测试：schema 完整性 + 3 个 Tool 名称验证
- 全量测试：92 passed + 1 skipped

---

## 会话 C — 详细记录

> ⏳ 等待 C 会话提交后填写

---

## 已知问题 & 注意事项

### ⚠️ pip install -e 冲突
多个会话的 `pip install -e .` 会互相覆盖 Python site-packages 中的包指针。
**规则**：只有 A 会话（主目录 `D:/Code/srchunter-mcp`）执行 `pip install -e .`。
B/C 会话直接通过 `PYTHONPATH` 或 `python -m pytest` 从自己的目录运行测试。

### 测试运行方式（B/C 会话）
```bash
# B 会话 — 在自己的目录运行，不要 pip install
cd D:/Code/srchunter-mcp-b
set PYTHONPATH=D:/Code/srchunter-mcp-b/src
python -m pytest tests/ -v

# C 会话同理
cd D:/Code/srchunter-mcp-c
set PYTHONPATH=D:/Code/srchunter-mcp-c/src
python -m pytest tests/ -v
```

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
│   ├── fingerprint.py     # ✅ B 会话已完成
│   └── vuln.py            # ⬜ C 会话待提交
├── engine/
│   ├── __init__.py
│   ├── cache.py           # 10min TTL 会话缓存
│   └── executor.py        # 异步 subprocess 封装
└── utils/
    ├── __init__.py
    └── validators.py      # 域名/URL 校验
```
