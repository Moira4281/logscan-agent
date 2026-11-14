---
name: predict-attack
description: 调用 ML 模型对日志条目做攻击分类预测。当需要对日志做联合研判（规则+模型双通道）时调用此 Skill。
---

# predict-attack

## 功能
调用 ML 模型对日志条目做攻击分类。可按 keyword/level/source_ip 过滤待预测的日志，返回每条的预测类别、置信度、是否需复核和证据。

模型无法识别 bruteforce（需关联规则），fileinclusion 会标记需复核。

## 参数
| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| keyword | string | 否 | 先按关键词过滤再预测 |
| level | string | 否 | 按级别过滤 |
| source_ip | string | 否 | 按 IP 过滤 |
| limit | integer | 否 | 预测条数上限，默认 50 |

## 输出
JSON 数组，每条包含：
- `label`: 攻击类别（sqli/xss/dirscan/rce/log4j/cookie_injection/normal）
- `confidence`: 置信度
- `review`: 是否需人工复核
- `evidence`: 命中证据
- `model_version`: 模型版本

## 环境变量
- `LOGSCAN_DB_PATH`：SQLite 数据库路径
- `PREDICT_SCRIPT`：predict.py 路径（成员A 的模型脚本）