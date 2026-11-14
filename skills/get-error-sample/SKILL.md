---
name: get-error-sample
description: 获取 ERROR/CRITICAL 级别日志样本。当需要快速定位异常和错误时调用此 Skill。
---

# get-error-sample

## 功能
获取 ERROR / CRITICAL 级别日志样本，用于快速定位异常。

## 参数
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| limit | integer | 否 | 返回条数上限，默认 20 |

## 输出
JSON 数组，每条为 ERROR/CRITICAL 级别的日志。

## 环境变量
- `LOGSCAN_DB_PATH`：SQLite 数据库路径