---
name: search-logs
description: 搜索安全日志条目。支持 FTS5 全文搜索与字段过滤（level/source_ip/path/status_code）。当需要查找特定关键词、IP 或路径的日志时调用此 Skill。
---

# search-logs

## 功能
搜索日志条目，支持按关键词全文搜索（FTS5 语法），以及按 level / source_ip / path / status_code 范围过滤。

## 参数
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| keyword | string | 否 | 全文搜索关键词，支持 FTS5 语法 |
| level | string | 否 | 日志级别：DEBUG/INFO/WARN/ERROR/CRITICAL |
| source_ip | string | 否 | 来源 IP 精确匹配 |
| path | string | 否 | 请求路径模糊匹配 |
| status_min | integer | 否 | HTTP 状态码下限 |
| status_max | integer | 否 | HTTP 状态码上限 |
| limit | integer | 否 | 返回条数上限，默认 50 |
| offset | integer | 否 | 偏移量，默认 0 |

## 输出
JSON 数组，每条包含 timestamp/level/source_ip/method/path/status_code/message。

## 环境变量
- `LOGSCAN_DB_PATH`：SQLite 数据库路径（默认 :memory:）

## 示例
```json
{"keyword": "UNION SELECT", "level": "WARN", "limit": 20}
```