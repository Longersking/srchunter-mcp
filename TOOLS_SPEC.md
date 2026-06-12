# SRC Hunter MCP Server — Tool Interface Specification v0.2.0

> **这是三会话并行开发的唯一契约。**
> 每个 Tool 的 name、inputSchema、output JSON 格式在此锁定。
> 修改定义必须先更新本文档，再改代码。

---

## 共享约定

### 所有 Tool 必须遵守

1. **返回值**统一为 `list[TextContent]`，content.text 是 JSON 字符串
2. **输入校验**通过 `src/srchunter/utils/validators.py` 的方法（`validate_domain`、`validate_url`）
3. **缓存**通过 `src/srchunter/engine/cache.py` 的 `get_cache()` 获取单例
4. **Tool 定义**放在各自模块的 `*_TOOLS` 常量中，格式：
   ```python
   MODULE_TOOLS = [
       Tool( 
           name="tool_name",
           description="...",
           inputSchema={
               "type": "object",
               "properties": {...},
               "required": [...],
           },
       ),
   ]
   ```
5. **调度函数**签名：`async def dispatch_xxx_tool(name: str, arguments: dict) -> list[TextContent]`
6. **server.py** 中注册：`all_tools.extend(XXX_TOOLS)` + dispatch 路由
7. **禁止**在 Tool 中执行破坏性操作（getshell、写文件、大规模扫描）。验证性载荷仅用于证明漏洞存在。
8. **外部工具依赖**用 `engine/executor.py`（待 A 会话创建）统一封装，不要自己写 subprocess 调用。

### 命名规范

- Tool name: `snake_case`，动作_对象（如 `subdomain_enum`、`tech_detect`）
- 模块文件: `tools/<domain>.py`（recon / fingerprint / vuln / report）
- Tool 列表常量: `RECON_TOOLS` / `FINGERPRINT_TOOLS` / `VULN_TOOLS` / `REPORT_TOOLS`
- Dispatch 函数: `dispatch_recon_tool` / `dispatch_fingerprint_tool` 等

---

## Phase 1: 资产收集 Recon（会话 A）

| Tool | 状态 |
|------|------|
| `subdomain_enum` | ✅ 已实现 |
| `resolve_targets` | ⬜ A-2 |
| `port_scan` | ⬜ A-3 |
| `http_probe` | ⬜ A-4 |

### subdomain_enum ✅

```json
// Input
{ "domain": "example.com" }

// Output
{
  "query_domain": "example.com",
  "subdomains": [{"domain": "www.example.com", "source": "crtsh"}],
  "count": 1,
  "elapsed": 1.23,
  "cached": false
}
```

### resolve_targets ⬜

```json
// Input
{
  "targets": ["www.example.com", "api.example.com"],
  "use_cdn_check": true
}

// Output
{
  "resolved": [
    {
      "domain": "www.example.com",
      "ips": ["93.184.216.34"],
      "cdn": false,
      "cdn_provider": null,
      "cname": null
    }
  ],
  "unresolved": ["api.example.com"],
  "count": 1,
  "elapsed": 2.5
}
```

### port_scan ⬜

```json
// Input
{
  "hosts": ["93.184.216.34"],
  "ports": "top-100",
  "rate": 1000
}

// Output
{
  "open_ports": [
    {"host": "93.184.216.34", "port": 80, "service": "http", "banner": "HTTP/1.1 200 OK"}
  ],
  "scan_time": 5.2,
  "hosts_scanned": 1,
  "ports_scanned": 100,
  "open_count": 1
}
```

### http_probe ⬜

```json
// Input
{
  "targets": ["www.example.com", "192.168.1.1:8080"],
  "ports": [80, 443, 8080, 8443]
}

// Output
{
  "live_urls": [
    {
      "url": "https://www.example.com",
      "status_code": 200,
      "title": "Example Domain",
      "content_length": 1256,
      "server": "ECS (dce/269A)",
      "redirect_url": null
    }
  ],
  "dead": ["http://192.168.1.1:8080"],
  "live_count": 1,
  "elapsed": 3.1
}
```

---

## Phase 2: 指纹识别 Fingerprint（会话 B）

| Tool | 状态 |
|------|------|
| `tech_detect` | ⬜ B-1 |
| `fingerprint_services` | ⬜ B-2 |
| `identify_waf` | ⬜ B-3 |

### ⚠️ 关键：B 会话需要先等 A 写完 `engine/executor.py`

> `executor.py` 封装外部工具调用。如果等不及，可以先写「纯 Python 实现」版本，后期再接入外部工具。

### tech_detect ⬜

```json
// Input
{
  "urls": ["https://www.example.com"]
}

// Output
{
  "results": [
    {
      "url": "https://www.example.com",
      "tech_stack": {
        "web_servers": [{"name": "ECS", "version": null}],
        "javascript": [{"name": "jQuery", "version": "3.7.1"}],
        "cdn": [{"name": "Cloudflare", "version": null}]
      },
      "confidence": "medium"
    }
  ],
  "elapsed": 4.2
}
```

### fingerprint_services ⬜

```json
// Input
{
  "hosts": ["93.184.216.34"],
  "ports": [80, 443, 22]
}

// Output
{
  "services": [
    {
      "host": "93.184.216.34",
      "port": 80,
      "service": "http",
      "version": "nginx/1.18.0",
      "cpe": "cpe:/a:nginx:nginx:1.18.0"
    }
  ],
  "elapsed": 6.8
}
```

### identify_waf ⬜

```json
// Input
{
  "urls": ["https://www.example.com"]
}

// Output
{
  "results": [
    {
      "url": "https://www.example.com",
      "waf_name": "Cloudflare",
      "confidence": "high",
      "indicators": ["cf-ray header", "server: cloudflare"],
      "bypass_suggestion": "尝试源服务器直连"
    }
  ],
  "elapsed": 3.5
}
```

---

## Phase 3: 漏洞检测 Vuln（会话 C）

| Tool | 状态 |
|------|------|
| `check_misconfig` | ⬜ C-1 |
| `run_nuclei` | ⬜ C-2 |
| `check_exploitable` | ⬜ C-3 |

### ⚠️ check_exploitable 安全约束

- 默认 **disabled**（MCP Server 层控制，可通过配置开启）
- 仅发最小验证载荷（如 XSS: `<script>alert(1)</script>`，SQLi: `' OR '1'='1`）
- 禁止执行命令、写文件、读取敏感路径
- 载荷列表写死在代码中，不允许模型传入自定义载荷

### check_misconfig ⬜

```json
// Input
{
  "urls": ["https://www.example.com"],
  "checks": ["git", "ds_store", "backup", "cors", "directory_listing"]
}

// Output
{
  "findings": [
    {
      "url": "https://www.example.com",
      "type": "git_exposure",
      "severity": "high",
      "description": ".git 目录可通过 /.git/HEAD 访问",
      "evidence": "ref: refs/heads/main",
      "remediation": "在 Web 服务器配置中禁止访问 .git 目录"
    }
  ],
  "total_checks": 5,
  "findings_count": 1,
  "elapsed": 8.3
}
```

### run_nuclei ⬜

```json
// Input
{
  "urls": ["https://www.example.com"],
  "templates": ["cves", "exposures"],
  "severity": "medium,critical,high"
}

// Output
{
  "findings": [
    {
      "url": "https://www.example.com",
      "template_id": "CVE-2023-XXXXX",
      "name": "Example CVE Detection",
      "severity": "critical",
      "matched_at": "https://www.example.com/vuln-endpoint",
      "description": "...",
      "remediation": "..."
    }
  ],
  "findings_count": 1,
  "elapsed": 12.5
}
```

### check_exploitable ⬜

```json
// Input
{
  "url": "https://www.example.com/search",
  "vuln_type": "xss",
  "method": "GET",
  "params": {"q": "test"}
}

// Output
{
  "is_vulnerable": true,
  "confidence": "high",
  "vuln_type": "xss",
  "poc": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
  "evidence": "payload reflected unescaped in response body at line 245",
  "request_dump": "GET /search?q=... HTTP/1.1\nHost: ...",
  "response_snippet": "<script>alert(1)</script> found in <div>"
}
```

---

## Phase 4: 结果输出 Report（会话 A 兼）

| Tool | 状态 |
|------|------|
| `analyze_surface` | ⬜ A-5 |
| `generate_report` | ⬜ A-6 |

### analyze_surface ⬜

```json
// Input
{
  "subdomains": [{...}],
  "live_urls": [{...}],
  "tech_results": [{...}],
  "vuln_findings": [{...}]
}

// Output
{
  "attack_surface": [
    {
      "target": "www.example.com",
      "urls": ["https://www.example.com"],
      "ports": [80, 443],
      "services": ["nginx/1.18.0"],
      "tech_stack": ["jQuery 3.7.1"],
      "vulnerabilities": [{"type": "cors_misconfig", "severity": "low"}],
      "priority": "low"
    }
  ],
  "summary": {
    "total_targets": 1,
    "high_priority": 0,
    "medium_priority": 0,
    "low_priority": 1
  }
}
```

### generate_report ⬜

```json
// Input
{
  "findings": [{...}],
  "target": "example.com",
  "format": "md"
}

// Output (text/markdown, not JSON wrapped — content.type = "text")
"# SRC Vulnerability Report: example.com\n\n## Finding 1: CORS Misconfiguration\n..."
```

---

## server.py dispatch 路由（A 会话维护）

```python
# 当前路由表 — 每次新加 Tool 后 A 会话更新此处

TOOL_DISPATCH = {
    # Recon
    "subdomain_enum":        dispatch_recon_tool,
    "resolve_targets":       dispatch_recon_tool,
    "port_scan":             dispatch_recon_tool,
    "http_probe":            dispatch_recon_tool,
    # Fingerprint
    "tech_detect":           dispatch_fingerprint_tool,
    "fingerprint_services":  dispatch_fingerprint_tool,
    "identify_waf":          dispatch_fingerprint_tool,
    # Vuln
    "check_misconfig":       dispatch_vuln_tool,
    "run_nuclei":            dispatch_vuln_tool,
    "check_exploitable":     dispatch_vuln_tool,
    # Report
    "analyze_surface":       dispatch_report_tool,
    "generate_report":       dispatch_report_tool,
}
```

---

## 会话分工

| 会话 | 负责 | 文件 |
|------|------|------|
| **A（当前）** | Recon 扩展 + server.py + executor.py | `tools/recon.py`, `engine/executor.py`, `server.py`, `tools/report.py` |
| **B** | 指纹识别 | `tools/fingerprint.py`（新建） |
| **C** | 漏洞检测 | `tools/vuln.py`（新建） |

### B 会话任务清单
1. 读 `TOOLS_SPEC.md`、`server.py`、`validators.py`、`cache.py`
2. 新建 `src/srchunter/tools/fingerprint.py`
3. 实现 `FINGERPRINT_TOOLS` + `dispatch_fingerprint_tool`
4. 实现三个 handler：`handle_tech_detect`、`handle_fingerprint_services`、`handle_identify_waf`
5. 新建 `tests/test_fingerprint.py`，覆盖解析逻辑
6. 提交 PR

### C 会话任务清单
1. 读 `TOOLS_SPEC.md`、`server.py`、`validators.py`、`cache.py`
2. 新建 `src/srchunter/tools/vuln.py`
3. 实现 `VULN_TOOLS` + `dispatch_vuln_tool`
4. 实现三个 handler：`handle_check_misconfig`、`handle_run_nuclei`、`handle_check_exploitable`
5. `check_exploitable` 默认 disabled，安全约束见上文
6. 新建 `tests/test_vuln.py`
7. 提交 PR
