---
name: get-stats
description: 获取日志统计概览（总数、时间范围、级别分布、状态码分布、Top IP/路径）。当需要快速了解日志全貌时调用此 Skill。
---

# get-stats

## 功能
获取日志统计概览：总数、时间范围、按级别分布、按 HTTP 状态码分布、Top 来源 IP、Top 请求路径。

## 参数
无参数。

## 输出
```json
{
  "total": 36,
  "time_range": {"min": "...", "max": "..."},
  "by_level": [{"level": "WARN", "count": 22}],
  "by_status": [{"status": 200, "count": 15}],
  "top_ips": [{"ip": "10.0.0.12", "count": 11}],
  "top_paths": [{"path": "/login", "count": 5}]
}
```

## 环境变量
- `LOGSCAN_DB_PATH`：SQLite 数据库路径