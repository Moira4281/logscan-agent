---
name: correlate-events
description: 关联分析：查找多 IP 共享路径或单 IP 路径分布。当需要发现协同攻击或扫描行为时调用此 Skill。
---

# correlate-events

## 功能
关联分析：查找同时出现在多个来源 IP 中的相同请求路径，或某个 IP 访问的所有不同路径。用于发现协同攻击或扫描行为。

## 参数
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| mode | string | 是 | `shared_paths`: 找被多个 IP 访问的路径; `ip_paths`: 找某 IP 访问的所有路径 |
| source_ip | string | 否 | mode=ip_paths 时指定 IP |
| min_ips | integer | 否 | shared_paths 模式下路径至少被多少 IP 访问，默认 3 |

## 输出
- shared_paths 模式：`[{path, distinct_ips, total_requests}]`
- ip_paths 模式：`[{path, count}]`

## 环境变量
- `LOGSCAN_DB_PATH`：SQLite 数据库路径

## 示例
```json
{"mode": "shared_paths", "min_ips": 3}
```