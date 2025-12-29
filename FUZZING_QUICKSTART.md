# 🔒 Claude Relay Service - Fuzzing Quick Start Guide

Complete automated security fuzzing infrastructure for CVE-1 regression testing.

## ⚡ Quick Start (1 minute)

```bash
# Run the entire fuzzing campaign
bash tests/security/run-all-fuzzing.sh

# Results saved to: tests/security/results/campaign-YYYYMMDD-HHMMSS/
```

That's it! The script handles:
1. ✓ Pre-flight safety checks
2. ✓ Docker environment setup
3. ✓ Test data seeding
4. ✓ Authentication bypass fuzzing
5. ✓ OWASP ZAP scanning
6. ✓ Report generation
7. ✓ Cleanup

Expected time: **5-10 minutes**

## 📋 What Gets Tested

### CVE-1: authenticateUserOrAdmin Missing Field Validation

Tests that the recent security fix (commit 45b81bd) stays in place.

**Test Coverage**:
- 8 session variations (valid, empty, missing fields, expired, etc.)
- 4 endpoints (/users/, /users/stats/overview, /admin/webhook/config, /admin/api-keys)
- **Total: 32 test cases** across authenticateUserOrAdmin paths

**Expected Result**: All 32 tests pass ✓

## 🏗️ What Was Created

### Core Infrastructure Files

| File | Purpose |
|------|---------|
| `tests/security/docker-compose.fuzzing.yml` | Isolated Docker environment (150 lines) |
| `tests/security/run-all-fuzzing.sh` | Master orchestration script (250 lines) |
| `tests/security/seed-data.js` | Test data population (200 lines) |

### Fuzzing Tools

| File | Purpose |
|------|---------|
| `tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py` | Auth bypass fuzzer (300 lines) |
| `tests/security/fuzzing-tools/scripts/pre-flight-check.sh` | Safety validation (80 lines) |
| `tests/security/fuzzing-tools/scripts/run-zap.sh` | OWASP ZAP wrapper (100 lines) |
| `tests/security/fuzzing-tools/zap/auth-config.yaml` | ZAP configuration (80 lines) |

### Documentation & Config

| File | Purpose |
|------|---------|
| `tests/security/README.md` | Full documentation (400+ lines) |
| `tests/security/fuzzing-tools/requirements.txt` | Python dependencies |
| `tests/security/.gitignore` | Exclude results/ from git |

## 🔐 Security Guarantees

✅ **Network Isolation**: `internal: true` - no external API calls
✅ **Ephemeral Data**: tmpfs Redis - auto-cleanup on shutdown
✅ **Test Credentials**: Hardcoded test values only (not production)
✅ **Resource Limits**: 2GB RAM, 2 CPU cores per container
✅ **Localhost Binding**: Port 13000 bound to 127.0.0.1 only

## 📊 Understanding Results

### Success Example

```bash
$ bash tests/security/run-all-fuzzing.sh

🔒 Claude Relay Service - Security Fuzzing Campaign
==================================================
[1/8] Running pre-flight safety checks...
✓ All safety checks passed!

[2/8] Starting isolated Docker environment...
✓ Services started

[3/8] Waiting for services to be ready...
✓ test_relay is healthy
✓ test_redis is healthy

[4/8] Seeding test data into Redis...
✓ Test data seeded

[5/8] Running authentication bypass fuzzer...
🧪 Authentication Bypass Fuzzing
Target: http://localhost:13000
Endpoints: 4
Test cases: 8

Testing: valid_admin_token
  Description: Valid complete session (baseline)
  → /users/: ✓ (got 200)
  → /users/stats/overview: ✓ (got 200)
  ...

Testing: random_field_token
  Description: Random field only {foo: bar} (CVE-1 critical)
  → /users/: ✓ (got 401)
  ...

============================================================
Test Summary
============================================================
Passed: 32/32
Failed: 0/32

✓ All tests passed!

[6/8] Running OWASP ZAP baseline scan...
✓ ZAP scan complete

[7/8] Collecting application logs...
✓ Logs collected

[8/8] Generating summary report...
✓ Summary report generated

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

### Reports

After successful run, check:

```bash
# Auth bypass test results
cat tests/security/results/campaign-*/auth-bypass.json | jq .

# ZAP scan results
open tests/security/results/campaign-*/zap-report.html

# Campaign summary
cat tests/security/results/campaign-*/summary.json | jq .
```

## 🐛 Troubleshooting

### "Docker not found"
```bash
# Install Docker: https://docs.docker.com/get-docker/
docker --version
```

### "Port 13000 already in use"
```bash
# Find process
lsof -i :13000

# Stop container or change port in docker-compose.fuzzing.yml
```

### "Cannot reach server"
```bash
# Check container
docker ps | grep fuzzing_test_relay

# View logs
docker logs fuzzing_test_relay_1 | tail -50
```

### "Python not found"
```bash
# Install Python 3
python3 --version

# Install dependencies
pip install -r tests/security/fuzzing-tools/requirements.txt
```

## 📚 Detailed Documentation

See [tests/security/README.md](./tests/security/README.md) for:
- Architecture overview
- Individual component usage
- Test case details
- Extended troubleshooting
- How to add new tests
- CI/CD integration examples

## 🎯 Next Steps

### Run First Campaign
```bash
bash tests/security/run-all-fuzzing.sh
```

### Review Results
```bash
# JSON report with test details
jq . tests/security/results/campaign-*/auth-bypass.json

# HTML report with ZAP findings
open tests/security/results/campaign-*/zap-report.html

# Summary
cat tests/security/results/campaign-*/summary.json
```

### Schedule Regular Runs
```bash
# Manual: Run weekly
bash tests/security/run-all-fuzzing.sh

# CI/CD: (Future) Add GitHub Actions workflow
# See: tests/security/README.md for workflow config
```

### Extend Fuzzing
To add more test cases:
1. Edit `tests/security/seed-data.js` - add session variations
2. Edit `tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py` - update test_cases
3. Run campaign again

## 📖 Key Files Reference

### Infrastructure
- `tests/security/docker-compose.fuzzing.yml` - Docker setup
- `tests/security/run-all-fuzzing.sh` - Main orchestration script

### Fuzzing Logic
- `tests/security/fuzzing-tools/scripts/fuzz-auth-bypass.py` - Auth fuzzer (main work)
- `tests/security/seed-data.js` - Test data (what's being tested)

### Validation
- `tests/security/SECURITY_FINDINGS.md` - Original vulnerabilities found
- `tests/security/authBypass.test.js` - Jest unit tests (reference)

### Docs
- `tests/security/README.md` - Full documentation
- `FUZZING_QUICKSTART.md` - This file

## ✅ Verification Checklist

Before production use:

- [ ] Docker installed: `docker --version`
- [ ] 4GB RAM available: `free -h` or Activity Monitor
- [ ] 5GB disk space: `df -h /`
- [ ] Port 13000 free: `lsof -i :13000`
- [ ] Pre-flight passes: `bash tests/security/fuzzing-tools/scripts/pre-flight-check.sh`

## 🚀 Performance

| Step | Time |
|------|------|
| Docker startup | 30-60 seconds |
| Data seeding | 5-10 seconds |
| Auth fuzzing | 30-60 seconds |
| ZAP scan | 2-5 minutes |
| **Total** | **5-10 minutes** |

## 📞 Support

1. Check [tests/security/README.md](./tests/security/README.md) troubleshooting section
2. Review Docker logs: `docker logs fuzzing_test_relay_1`
3. Run pre-flight checks: `bash tests/security/fuzzing-tools/scripts/pre-flight-check.sh`

## 📝 License

Same as Claude Relay Service

---

**Ready to start?** Run this command:

```bash
bash tests/security/run-all-fuzzing.sh
```
