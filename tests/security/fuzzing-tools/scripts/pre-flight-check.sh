#!/bin/bash
#
# Pre-Flight Safety Checks for Claude Relay Fuzzing
# Validates that the fuzzing environment is safe before execution
#
# Checks:
# 1. Network isolation (internal: true)
# 2. Test credentials only (no production secrets)
# 3. Localhost binding (127.0.0.1 only)
# 4. Resource limits configured
# 5. Not running in production environment
# 6. Docker available
# 7. Required tools installed

# Don't use set -e so we can debug failures
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DOCKER_COMPOSE_FILE="$PROJECT_ROOT/tests/security/docker-compose.fuzzing.yml"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Helper functions
print_check() {
  echo -ne "  [$1/8] $2... "
}

pass() {
  echo -e "${GREEN}✓${NC}"
  ((CHECKS_PASSED++))
}

fail() {
  echo -e "${RED}✗ FAIL${NC}"
  echo -e "        $1"
  ((CHECKS_FAILED++))
  return 1
}

warn() {
  echo -e "${YELLOW}⚠${NC}"
  echo -e "        $1"
  ((CHECKS_WARNING++))
}

echo ""
echo "🔒 Claude Relay Service - Pre-Flight Safety Checks"
echo "=================================================="
echo ""

# Check 1: Docker is installed
print_check "1" "Docker installed"
if command -v docker &> /dev/null; then
  pass
else
  fail "Docker not found. Please install Docker."
  ((CHECKS_FAILED++))
fi

# Check 2: Docker Compose is installed
print_check "2" "Docker Compose installed"
if docker compose version &> /dev/null || docker-compose --version &> /dev/null; then
  pass
else
  fail "Docker Compose not found. Please install Docker Compose v2."
  ((CHECKS_FAILED++))
fi

# Check 3: Network isolation enabled
print_check "3" "Network isolation (internal: true)"
if grep -q 'internal: true' "$DOCKER_COMPOSE_FILE"; then
  pass
else
  fail "Network not isolated! Missing 'internal: true' in docker-compose.fuzzing.yml"
  ((CHECKS_FAILED++))
fi

# Check 4: Test credentials only (not production)
print_check "4" "Test credentials only"
if grep -q 'test_jwt_secret' "$DOCKER_COMPOSE_FILE" && \
   ! grep -q 'ANTHROPIC' "$DOCKER_COMPOSE_FILE"; then
  pass
else
  fail "Production credentials detected in docker-compose.fuzzing.yml!"
  echo "        Do NOT commit production secrets to this file."
  ((CHECKS_FAILED++))
fi

# Check 5: Localhost binding
print_check "5" "Localhost binding (127.0.0.1:13000)"
if grep -q '127.0.0.1:13000' "$DOCKER_COMPOSE_FILE"; then
  pass
else
  fail "Port not bound to localhost! Port should be 127.0.0.1:13000"
  echo "        This is a SECURITY issue - port is exposed!"
  ((CHECKS_FAILED++))
fi

# Check 6: Resource limits configured
print_check "6" "Resource limits configured"
if grep -q 'mem_limit:' "$DOCKER_COMPOSE_FILE"; then
  pass
else
  warn "Memory limits not configured. Fuzzing could consume excessive resources."
fi

# Check 7: Not in production
print_check "7" "Not production environment"
if [ "$NODE_ENV" != "production" ] && [ "$ENV" != "prod" ]; then
  pass
else
  fail "NODE_ENV=production detected! Refusing to run fuzzing in production."
  ((CHECKS_FAILED++))
fi

# Check 8: Port 13000 not in use
print_check "8" "Port 13000 available"
if ! netstat -tuln 2>/dev/null | grep -q ':13000 ' && \
   ! lsof -Pi :13000 -sTCP:LISTEN -t >/dev/null 2>&1; then
  pass
else
  fail "Port 13000 is already in use!"
  echo "        Stop the process using this port or change FUZZING_PORT."
  ((CHECKS_FAILED++))
fi

echo ""
echo "=================================================="
echo -e "Results: ${GREEN}$CHECKS_PASSED passed${NC}"

if [ $CHECKS_WARNING -gt 0 ]; then
  echo -e "         ${YELLOW}$CHECKS_WARNING warnings${NC}"
fi

if [ $CHECKS_FAILED -gt 0 ]; then
  echo -e "         ${RED}$CHECKS_FAILED failed${NC}"
  echo ""
  echo "Pre-flight checks FAILED! Fix the issues above and try again."
  exit 1
else
  echo ""
  echo -e "${GREEN}✓ All safety checks passed! Ready for fuzzing.${NC}"
  echo ""
fi
