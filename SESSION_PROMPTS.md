# 多会话并行开发 — 启动文案

> 复制对应文案，粘贴到新 Claude Code 会话中。

---

## 会话 B：指纹识别模块

```
# 你的任务：实现 Fingerprint 模块

## 先读（必须，5分钟）
请先依次读取以下文件：
1. D:/Code/srchunter-mcp/TOOLS_SPEC.md — 找到 "Phase 2: 指纹识别 Fingerprint" 部分（tech_detect / fingerprint_services / identify_waf 三个 Tool 的接口定义）
2. D:/Code/srchunter-mcp/src/srchunter/server.py — 理解 list_tools/call_tool 的 dispatch 模式
3. D:/Code/srchunter-mcp/src/srchunter/tools/recon.py — 参考现有模块的结构（TOOLS 常量 + handler + dispatch）
4. D:/Code/srchunter-mcp/src/srchunter/utils/validators.py — 使用 validate_domain / validate_url 做输入校验
5. D:/Code/srchunter-mcp/src/srchunter/engine/cache.py — 使用 get_cache() 做结果缓存

## 然后做
1. 新建 src/srchunter/tools/fingerprint.py
   - FINGERPRINT_TOOLS 常量：3个 Tool 定义（name / description / inputSchema）
   - 3个 handler 异步函数：handle_tech_detect / handle_fingerprint_services / handle_identify_waf
   - dispatch_fingerprint_tool 调度函数
   - 先纯 Python 实现（HTTP 请求分析响应头/body），不依赖外部工具
2. 新建 tests/test_fingerprint.py
   - 测试解析逻辑（类似 test_recon.py 的模式）
3. 跑通 pytest -v tests/test_fingerprint.py

## 规则
- 接口必须严格对照 TOOLS_SPEC.md 的 input/output JSON
- 编辑前先读文件确认当前内容
- 完成后告诉我你写了什么，我来合并 server.py
```

---

## 会话 C：漏洞检测模块

```
# 你的任务：实现 Vuln 模块

## 先读（必须，5分钟）
请先依次读取以下文件：
1. D:/Code/srchunter-mcp/TOOLS_SPEC.md — 找到 "Phase 3: 漏洞检测 Vuln" 部分（check_misconfig / run_nuclei / check_exploitable 三个 Tool 的接口定义）
2. D:/Code/srchunter-mcp/src/srchunter/server.py — 理解 list_tools/call_tool 的 dispatch 模式
3. D:/Code/srchunter-mcp/src/srchunter/tools/recon.py — 参考现有模块的结构
4. D:/Code/srchunter-mcp/src/srchunter/utils/validators.py — 使用 validate_url 做输入校验
5. D:/Code/srchunter-mcp/src/srchunter/engine/cache.py — 使用 get_cache()

## 然后做
1. 新建 src/srchunter/tools/vuln.py
   - VULN_TOOLS 常量：3个 Tool 定义
   - 3个 handler：handle_check_misconfig / handle_run_nuclei / handle_check_exploitable
   - dispatch_vuln_tool 调度函数
   - check_misconfig：发 HTTP 请求探测 .git/HEAD、.DS_Store、备份文件、CORS 头、目录遍历
   - run_nuclei：先放骨架（外部工具集成后续做），可以先返回占位结果
   - check_exploitable：⚠️ 安全约束 — 只发最小验证载荷（XSS/ SQLi/ SSRF 各一个），载荷写死在代码里，默认 disabled（可通过环境变量 SRCHUNTER_ENABLE_EXPLOIT=1 开启）
2. 新建 tests/test_vuln.py
3. 跑通 pytest -v tests/test_vuln.py

## 规则
- 接口必须严格对照 TOOLS_SPEC.md
- check_exploitable 必须遵守安全约束，禁用命令执行和文件读写
- 编辑前先读文件
- 完成后告诉我你写了什么，我来合并 server.py
```

---

## 我的任务（会话 A）

- engine/executor.py — 外部工具调用封装
- tools/recon.py — resolve_targets / port_scan / http_probe
- tools/report.py — analyze_surface / generate_report
- server.py 维护 — 合并 B/C 的 TOOLS + dispatch
- 测试 + 文档
