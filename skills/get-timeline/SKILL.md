---
name: get-timeline
description: 获取指定来源 IP 的完整活动时间线（按时间正序）。当需要分析攻击者行为序列和横向移动时调用此 Skill。
---

# get-timeline

## 功能
获取指定来源 IP 的完整活动时间线（按时间正序），用于分析攻击者的行为序列和横向移动。

## 参数
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| source_ip | string | 是 | 要分析的来源 IP |
| limit | integer | 否 | 返回条数上限，默认 100 |

## 输出
JSON 数组，按时间正序排列，每条包含完整日志字段。

## 环境变量
- `LOGSCAN_DB_PATH`：SQLite 数据库路径

## 示例
```json
{"source_ip": "10.0.0.66", "limit": 50}
```