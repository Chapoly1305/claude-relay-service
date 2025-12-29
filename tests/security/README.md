# Claude Relay Service - Security Fuzzing Infrastructure

Complete automated fuzzing environment for security regression testing, focused on authentication bypass vulnerabilities.

## Quick Start

```bash
# Run full fuzzing campaign (5-10 minutes)
bash tests/security/run-all-fuzzing.sh

# Results saved to: tests/security/results/campaign-YYYYMMDD-HHMMSS/
```

## Overview

This fuzzing infrastructure provides:

- **Isolated Docker Environment**: Completely separated network, no external access
- **Regression Testing**: Validates the authenticateUserOrAdmin bypass fix stays in place
- **Automated Scanning**: OWASP ZAP baseline security assessment
- **Comprehensive Reports**: JSON and HTML reports for analysis

### What's Being Tested

- ✅ **CVE-1**: authenticateUserOrAdmin missing field validation
- ✅ **Session Injection**: Partial session attacks
- ✅ **Privilege Escalation**: Ability to gain admin access with minimal sessions
- ✅ **General Security**: OWASP ZAP baseline scanning

### Security Guarantees

- **Network Isolation**: `internal: true` - no external communication
- **Ephemeral Data**: tmpfs Redis - auto-cleanup on shutdown
- **Test Credentials**: Hardcoded test values only (no production secrets)
- **Resource Limits**: 2GB memory, 2 CPU cores per container
- **Localhost Binding**: Port 13000 bound to 127.0.0.1 only

## Architecture

```
Fuzzing Network (isolated, internal: true)
├── test_relay:13000     # Claude Relay Service (test instance)
├── test_redis:6379      # Redis (ephemeral storage)
└── zap:8080            # OWASP ZAP security scanner
```

## Files

### Core Infrastructure

| File | Purpose | Lines |
|------|---------|-------|
| `docker-compose.fuzzing.yml` | Isolated Docker environment | 150 |
| `fuzzing-tools/scripts/pre-flight-check.sh` | Safety validation | 80 |
| `run-all-fuzzing.sh` | Master orchestration | 250 |
| `seed-data.js` | Test data seeding | 200 |

### Fuzzing Tools

| File | Purpose | Lines |
|------|---------|-------|
| `fuzzing-tools/scripts/fuzz-auth-bypass.py` | Auth bypass fuzzer | 300 |
| `fuzzing-tools/scripts/run-zap.sh` | OWASP ZAP wrapper | 100 |
| `fuzzing-tools/zap/auth-config.yaml` | ZAP configuration | 80 |

### Dependencies

| File | Purpose |
|------|---------|
| `fuzzing-tools/requirements.txt` | Python packages |
| `.gitignore` | Exclude results/ |
| `README.md` | This file |

## Usage

### Full Campaign

Run the entire fuzzing workflow:

```bash
bash tests/security/run-all-fuzzing.sh
```

**Expected Output**:
```
🔒 Claude Relay Service - Security Fuzzing Campaign
==================================================
Timestamp: [date]
Results: tests/security/results/campaign-YYYYMMDD-HHMMSS

[1/8] Running pre-flight safety checks...
✓ All safety checks passed!

[2/8] Starting isolated Docker environment...
✓ Services started

... (scan progress) ...

[8/8] Cleaning up...

==================================================
Fuzzing Campaign Complete!
==================================================

Results: tests/security/results/campaign-YYYYMMDD-HHMMSS/

Generated Reports:
  ✓ auth-bypass.json (Auth tests)
  ✓ zap-report.html (ZAP HTML report)
  ✓ zap-report.json (ZAP JSON report)
  ✓ app-logs.txt (Application logs)
  ✓ summary.json (Campaign summary)

✓ SUCCESS: No vulnerabilities detected!
```

### Individual Components

#### Pre-flight Checks

```bash
bash tests/security/fuzzing-tools/scripts/pre-flight-check.sh
```

Validates:
- Docker available
- Network isolation configured
- Test credentials only (no production)
- Port 13000 available
- Resource limits set
- Not in production

#### Start Environment

```bash
# Start isolated Docker services
docker compose -f tests/security/docker-compose.fuzzing.yml up -d

# Stop and cleanup
docker compose -f tests/security/docker-compose.fuzzing.yml down -v
```

#### Seed Test Data

```bash
# Seed Redis with test sessions
node tests/security/seed-data.js

# Or with Docker
docker exec fuzzing_test_redis_1 redis-cli INFO
```

#### Run Auth Bypass Fuzzer

```bash
# Basic usage
python3 tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py

# With custom URL
python3 tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py \
  --base-url http://localhost:13000

# Save report
python3 tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py \
  --output results/auth-bypass.json

# Verbose output
python3 tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py -v
```

**Expected Output**:
```
🧪 Authentication Bypass Fuzzing
============================================================
Target: http://localhost:13000
Endpoints: 4
Test cases: 8

[*] Checking connectivity...
✓ Server is healthy

Testing: valid_admin_token
  Description: Valid complete session (baseline)
  Expected status: 200

  → /users/: ✓ (got 200)
  → /users/stats/overview: ✓ (got 200)
  ...

Testing: random_field_token
  Description: Random field only {foo: bar} (CVE-1 critical)
  Expected status: 401

  → /users/: ✓ (got 401)
  ...

============================================================
Test Summary
============================================================
Passed: 32/32
Failed: 0/32

✓ All tests passed!
   The authenticateUserOrAdmin vulnerability is fixed.
```

#### Run OWASP ZAP Baseline

```bash
# Manual run
bash tests/security/fuzzing-tools/scripts/run-zap.sh results/

# Check ZAP status
docker logs fuzzing_zap_1

# Access ZAP API (if port exposed)
curl http://localhost:8081/api/core/version
```

## Test Cases

### CVE-1: authenticateUserOrAdmin Missing Field Validation

Validates that sessions without required fields (`username`, `loginTime`) are rejected.

#### Test Sessions Created

| Token | Data | Expected | Purpose |
|-------|------|----------|---------|
| `valid_admin_token` | `{username, adminId, loginTime}` | ✓ Accept (200) | Baseline |
| `empty_session_token` | `{}` | ✗ Reject (401) | Empty object |
| `missing_username_token` | `{adminId, loginTime}` | ✗ Reject (401) | CVE-1 case |
| `missing_logintime_token` | `{username, adminId}` | ✗ Reject (401) | CVE-1 case |
| `random_field_token` | `{foo: "bar"}` | ✗ Reject (401) | CVE-1 critical |
| `expired_session_token` | Old `loginTime` | ✗ Reject (401) | Inactivity |
| `partial_adminid_token` | `{username, loginTime}` | ✗ Reject (401) | Missing ID |
| `null_values_token` | `{username: null, ...}` | ✗ Reject (401) | Null fields |

#### Tested Endpoints

- `/users/` (GET) - authenticateUserOrAdmin
- `/users/stats/overview` (GET) - authenticateUserOrAdmin
- `/admin/webhook/config` (GET) - authenticateUserOrAdmin
- `/admin/api-keys` (GET) - authenticateUserOrAdmin

**Expected Result**: All 8 test cases × 4 endpoints = 32 tests must pass

## Understanding Results

### Auth Bypass Report (auth-bypass.json)

```json
{
  "timestamp": "2025-12-29T12:00:00Z",
  "target": "http://localhost:13000",
  "summary": {
    "passed": 32,
    "failed": 0,
    "errors": 0
  },
  "vulnerable": false,
  "details": {
    "passed": [
      "valid_admin_token on /users/",
      "random_field_token on /users/ (401)",
      ...
    ],
    "failed": [],
    "errors": []
  }
}
```

**Interpretation**:
- `vulnerable: false` = Fix is working (good!)
- `vulnerable: true` = Vulnerability detected (needs investigation)
- `failed` array = Specific tests that failed

### ZAP Report

#### HTML Report (`zap-report.html`)
- Full security assessment
- Alert details with evidence
- Affected URLs
- Remediation guidance

#### JSON Report (`zap-report.json`)
```json
{
  "alerts": [
    {
      "alert": "Missing Anti-CSRF Tokens",
      "risk": "Medium",
      "confidence": "Medium",
      "count": 3,
      "urls": ["/admin/api-keys"],
      "solution": "..."
    }
  ]
}
```

### Campaign Summary (`summary.json`)

```json
{
  "campaign_id": "campaign-20251229-120000",
  "timestamp": "2025-12-29T12:00:00Z",
  "vulnerabilities_found": 0,
  "tests": {
    "auth_bypass": "passed",
    "zap_baseline": "passed"
  }
}
```

## Troubleshooting

### "Docker not found"

**Error**: Pre-flight checks fail with "Docker not found"

**Fix**:
```bash
# Install Docker: https://docs.docker.com/get-docker/
docker --version
```

### "Port 13000 already in use"

**Error**: Cannot start test_relay

**Fix**:
```bash
# Find process using port 13000
lsof -i :13000
# OR
netstat -tuln | grep 13000

# Stop the process or change port in docker-compose.fuzzing.yml
docker compose kill <container_name>
```

### "Cannot reach server"

**Error**: Auth fuzzer fails to connect

**Check**:
```bash
# Verify container is running
docker ps | grep fuzzing_test_relay

# Check health
docker exec fuzzing_test_relay_1 curl http://localhost:3000/health

# View logs
docker logs fuzzing_test_relay_1 | tail -50
```

### "ZAP scan times out"

**Error**: ZAP scan takes too long or hangs

**Fix**:
```bash
# Restart ZAP container
docker restart fuzzing_zap_1

# Check resources
docker stats fuzzing_zap_1

# Or skip ZAP (it's optional)
# Modify run-all-fuzzing.sh to skip step 6
```

### "Python not found"

**Error**: Auth fuzzer script fails

**Fix**:
```bash
# Install Python 3
python3 --version

# Or use system Python
python --version

# Install dependencies
pip install -r tests/security/fuzzing-tools/requirements.txt
```

## Network Isolation Verification

Verify fuzzing environment is truly isolated:

```bash
# This should FAIL (no external access):
docker exec fuzzing_test_relay_1 curl -f https://google.com
# Expected: curl: (7) Failed to connect to google.com port 443

# Internal network should work:
docker exec fuzzing_test_relay_1 curl -f http://test_redis:6379
# Expected: Protocol error (Redis is listening but not HTTP)

# Localhost should work:
docker exec fuzzing_test_relay_1 curl -f http://localhost:3000/health
# Expected: 200 OK with health data
```

## Performance Expectations

| Component | Time |
|-----------|------|
| Docker startup | 30-60 seconds |
| Data seeding | 5-10 seconds |
| Auth bypass fuzzing | 30-60 seconds |
| OWASP ZAP scan | 2-5 minutes |
| Total campaign | 5-10 minutes |

## Extending the Fuzzing

### Adding New Test Cases

Edit `tests/security/seed-data.js`:

```javascript
const sessions = [
  // ... existing sessions ...
  {
    token: 'my_new_test_token',
    data: { /* session data */ },
    description: 'My test case'
  }
];
```

Then update `fuzz-auth-bypass.py` test_cases dict to match.

### Adding New Endpoints

Edit `tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py`:

```python
self.endpoints = [
    '/users/',
    '/users/stats/overview',
    '/admin/webhook/config',
    '/admin/api-keys',
    '/your/new/endpoint'  # Add here
]
```

### Adding New Fuzzers

Create new Python script in `fuzzing-tools/scripts/`:

```bash
cp tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py \
   tests/security/fuzzing-tools/scripts/fuzz-your-feature.py
```

Then add to `run-all-fuzzing.sh`:

```bash
echo "[X/8] Running your fuzzer..."
python3 "$SCRIPT_DIR/fuzzing-tools/scripts/fuzz-your-feature.py" ...
```

## Safety

### Pre-deployment Checklist

Before running fuzzing:

- [ ] Not in production environment
- [ ] Port 13000 is available
- [ ] Have 4GB RAM and 5GB disk space
- [ ] Docker and Docker Compose installed
- [ ] Pre-flight checks pass

### Cleanup

Fuzzing automatically cleans up on completion:

```bash
# Manual cleanup if needed
docker compose -f tests/security/docker-compose.fuzzing.yml down -v

# Remove all results
rm -rf tests/security/results/
```

## CI/CD Integration

Future versions will include GitHub Actions integration:

```yaml
name: Security Fuzzing
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  pull_request:
    paths:
      - 'src/middleware/auth.js'
      - 'src/services/userService.js'

jobs:
  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run fuzzing campaign
        run: bash tests/security/run-all-fuzzing.sh
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: fuzzing-results
          path: tests/security/results/
```

## References

### Documentation
- [SECURITY_FINDINGS.md](./SECURITY_FINDINGS.md) - Detailed vulnerability report
- [authBypass.test.js](./authBypass.test.js) - Unit test cases
- [Claude Relay CLAUDE.md](../../CLAUDE.md) - Project documentation

### Code
- `src/middleware/auth.js:1548-1645` - authenticateUserOrAdmin implementation
- `src/middleware/auth.js:1349-1460` - authenticateAdmin (secure reference)
- `src/models/redis.js` - Redis operations

### Security Standards
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-287: Authentication Bypass](https://cwe.mitre.org/data/definitions/287.html)
- [CVE Security Scoring](https://www.first.org/cvss/)

## Support

### Getting Help

1. Check troubleshooting section above
2. Review Docker logs: `docker logs fuzzing_test_relay_1`
3. Check pre-flight: `bash tests/security/fuzzing-tools/scripts/pre-flight-check.sh`

### Reporting Issues

Found a problem? Please report to: [GitHub Issues](https://github.com/your-repo/issues)

Include:
- Output from `run-all-fuzzing.sh`
- Results from `results/campaign-*/summary.json`
- Docker version: `docker --version`
- System info: OS, CPU, RAM

## License

Same as Claude Relay Service
