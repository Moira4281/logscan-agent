# AgentArts Skill 注册操作指南

## 概述

本项目的 7 个安全日志分析工具已按 [Agent Skills Standard](https://agentskills.io/specification) 规范打包为 AgentArts 平台 Skill 制品包。每个 Skill 是一个 ZIP 文件，包含 `SKILL.md`（元数据+使用说明）和 `scripts/main.py`（可执行脚本）。

## Skill 清单

| Skill 名称 | 功能 | 对应源码 |
|------------|------|----------|
| search-logs | FTS5 全文搜索 + 字段过滤 | tools/builtin.py:SearchLogsTool |
| get-stats | 日志统计概览 | tools/builtin.py:GetStatsTool |
| get-timeline | 指定 IP 活动时间线 | tools/builtin.py:GetTimelineTool |
| get-error-sample | ERROR/CRITICAL 日志样本 | tools/builtin.py:GetErrorSampleTool |
| get-sample | 日志样本 | tools/builtin.py:GetSampleTool |
| correlate-events | 关联分析（多 IP/单 IP） | tools/builtin.py:CorrelateTool |
| predict-attack | ML 攻击分类预测 | tools/predict.py:PredictTool |

## 第一步：打包 Skill 制品包

```bash
bash skills/build_skills.sh
```

生成 `skills/dist/*.zip`，每个 ZIP 是一个可导入的 Skill 制品包。

## 第二步：导入 AgentArts 控制台

1. 登录 AgentArts 控制台：https://console.huaweicloud.com/agentarts/?region=cn-southwest-2#/home/overview
2. 左侧导航栏 → **资产广场** → **Skill** 页签
3. 点击 **导入 Skill**（或 **创建 Skill**）
4. 上传对应的 ZIP 文件
5. 重复步骤 3-4，导入全部 7 个 Skill

## 第三步：在智能体中关联 Skill

> **注意**：截至 2026-10-06，AgentArts 当前版本"仅支持 Skill 的导入、管理和浏览，暂不支持在智能体中调用使用"。以下步骤为平台开放后的预期操作。

1. 左侧导航栏 → **开发中心** → **智能体管理**
2. 选择或创建目标智能体 → **单智能体配置**
3. 在 **能力组件** 区域 → **技能** → **添加 Skill**
4. 从列表中选择已导入的 7 个 Skill
5. 在提示词中告知智能体何时调用各 Skill（参考下方提示词模板）
6. **提交版本** → 部署

## 提示词模板（关联 Skill 后填入智能体）

```
你是安全日志漏洞分析智能体。按以下流程使用工具分析日志：

1. 调用 get-stats 了解日志全貌（总数、级别分布、Top IP）
2. 调用 get-error-sample 获取 ERROR/CRITICAL 日志样本
3. 对可疑 IP 调用 get-timeline 获取完整活动时间线
4. 调用 search-logs 搜索特定攻击关键词（UNION SELECT、<script>、../ 等）
5. 调用 correlate-events 做关联分析（shared_paths 发现协同攻击）
6. 调用 predict-attack 对可疑日志做 ML 攻击分类预测
7. 综合规则和模型结果，输出漏洞报告（含复核状态）

输出格式：Markdown 报告，含漏洞列表、攻击链、复核建议。
```

## 环境变量配置

Skill 脚本通过环境变量获取运行时配置：

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| LOGSCAN_DB_PATH | SQLite 日志数据库路径 | :memory: |
| PREDICT_SCRIPT | predict.py 路径（ML 模型脚本） | predict.py |

在 AgentArts 运行时托管场景下，这些变量在控制台"智能体运行时详情 → 环境变量"中配置。

## 答辩说明

若答辩时被问及"Skill 是否已在平台调用"，说明：

1. **已完成**：7 个工具按 Agent Skills Standard 规范打包为平台 Skill 制品包，可导入控制台
2. **平台限制**：AgentArts 当前版本 Skill 导入/管理功能已开放，智能体调用能力即将开放
3. **保底方案**：运行时托管（app.py + /invocations）已实现完整工具调用链，不依赖 Skill 调用功能
4. **设计前瞻**：Skill 制品包规范已对齐平台标准，平台开放后可直接启用

## 文件结构

```
skills/
├── build_skills.sh              # 打包脚本
├── search-logs/
│   ├── SKILL.md                 # 技能清单（YAML frontmatter + Markdown）
│   └── scripts/main.py          # 可执行脚本
├── get-stats/
│   ├── SKILL.md
│   └── scripts/main.py
├── get-timeline/
│   ├── SKILL.md
│   └── scripts/main.py
├── get-error-sample/
│   ├── SKILL.md
│   └── scripts/main.py
├── get-sample/
│   ├── SKILL.md
│   └── scripts/main.py
├── correlate-events/
│   ├── SKILL.md
│   └── scripts/main.py
├── predict-attack/
│   ├── SKILL.md
│   └── scripts/main.py
└── dist/                        # 打包输出（build_skills.sh 生成）
    ├── search-logs.zip
    ├── get-stats.zip
    ├── ...
    └── predict-attack.zip
```