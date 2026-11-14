# logscan-agent

LLM 驱动的安全日志漏洞扫描智能体。输入日志文件，AI 自主分析并输出漏洞报告。

## 工作原理

```
日志文件 → 通用解析器(JSON/syslog/Nginx/...) → SQLite 存储
                                                    ↓
                                          LLM Agent (ReAct)
                                           ↗  ↘  ↙  ↖
                                         工具集调用循环
                                    search / stats / timeline / correlate
                                                    ↓
                                          结构化漏洞报告 (Markdown/JSON)
```

智能体使用 **ReAct 模式**：LLM 自主决定调用哪些工具、如何分析，
多轮推理后输出包含漏洞、攻击链、证据和修复建议的报告。

## 快速开始

```bash
# 1. 安装
pip install -e ".[dev]"

# 2. 配置 API Key
cp .env.example .env
# 编辑 .env 填入 OPENAI_API_KEY

# 3. 预览日志解析（不调用 LLM）
logscan preview examples/access.log

# 4. 扫描分析
logscan scan examples/access.log examples/app.json.log examples/syslog.log

# 5. 输出 JSON + 显示详细过程
logscan scan examples/ --format json --verbose -o report.json
```

## 支持的日志格式

| 格式 | 示例 | 自动识别 |
|------|------|----------|
| JSON | `{"timestamp":"...","level":"ERROR","message":"..."}` | 每行一个 JSON |
| Nginx/Apache | `192.168.1.1 - - [15/Jan/2024:...] "GET / HTTP/1.1" 200 ...` | combined log format |
| syslog | `<134>Jan 15 10:30:45 host app[pid]: msg` | 含 priority/时间戳/程序 |
| 通用 | 任意文本，自动提取时间戳和 IP | 兜底 |

## Agent 工具集

| 工具 | 功能 |
|------|------|
| `search_logs` | 全文搜索 + 字段过滤（level/ip/path/status） |
| `get_stats` | 日志统计概览（级别/状态码/IP/路径分布） |
| `get_timeline` | 指定 IP 的完整活动时间线 |
| `get_error_sample` | ERROR/CRITICAL 日志样本 |
| `get_sample` | 日志样本 |
| `correlate_events` | 关联分析（多 IP 共享路径 / IP 访问路径） |

## 检测的攻击类型

- SQL 注入（UNION SELECT / OR 1=1 / DROP TABLE / SLEEP）
- XSS（`<script>` / `onerror=` / `javascript:`）
- 路径遍历（`../` / `%2e%2e` / `/etc/passwd`）
- 暴力破解（大量 401 后成功）
- 目录扫描（大量 404）
- SSRF（云元数据 / 内网服务）
- 命令注入 / 权限提升
- 横向移动

## 配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `OPENAI_API_KEY` | - | API 密钥（必填） |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | 兼容 OpenAI 接口的任意服务 |
| `LOGSCAN_MODEL` | `gpt-4o-mini` | 模型名称 |
| `LOGSCAN_MAX_STEPS` | `20` | Agent 最大推理步数 |
| `LOGSCAN_MAX_LOG_LINES` | `50000` | 每个日志文件最大行数 |
| `LOGSCAN_DISABLE_THINKING` | `0` | 置 `1` 关闭思考型模型的思考链（显著提速） |

## 网页演示（答辩用）

浏览器里实时观看 Agent 调用工具、生成报告，适合投影/答辩展示。

```bash
python -m logscan.agentarts.runtime      # 启动后浏览器打开 http://127.0.0.1:8080/
```

- 服务监听 `0.0.0.0:8080`，**局域网内其他电脑/投影**用 `http://<本机IP>:8080/` 即可打开
- 页面上可直接切换模型（qwen3.6-35b-a3b 快 / qwen3.8-27b 准）、`mock` 兜底模式、最大步数
- 注意：模型地址是硬编码在 `runtime.DEMO_MODELS` 里的学院接口；`qwen3.8-27b` 是教育网地址，只有校园网内可达
- 也可用 `python -m logscan.agentarts.runtime` 起服务后配合 `demo.sh` 生成 Markdown 报告

## 测试

```bash
pytest
```