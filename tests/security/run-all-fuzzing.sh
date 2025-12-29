#!/bin/bash
#
# Master Orchestration Script for Claude Relay Fuzzing Campaign
#
# Coordinates the entire security fuzzing workflow:
# 1. Pre-flight safety checks
# 2. Start isolated Docker environment
# 3. Seed test data
# 4. Run authentication bypass fuzzer
# 5. Run OWASP ZAP baseline scan
# 6. Generate summary report
# 7. Cleanup and exit
#
# Usage:
#   bash tests/security/run-all-fuzzing.sh
#
# Exit codes:
#   0 - Success (no vulnerabilities found)
#   1 - Vulnerabilities found
#

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Create results directory
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="$SCRIPT_DIR/results/campaign-$TIMESTAMP"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters
VULNERABILITIES_FOUND=0

# Cleanup function
cleanup() {
  local exit_code=$?

  echo ""
  echo -e "${BLUE}[8/8] Cleaning up...${NC}"

  # Stop containers
  cd "$SCRIPT_DIR"
  docker compose -f docker-compose.fuzzing.yml down -v 2>/dev/null || true

  # Remove empty results directory if no data
  if [ ! "$(ls -A "$RESULTS_DIR")" ]; then
    rmdir "$RESULTS_DIR" 2>/dev/null || true
  fi

  return $exit_code
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Main function
main() {
  echo ""
  echo -e "${BOLD}${BLUE}🔒 Claude Relay Service - Security Fuzzing Campaign${NC}${NC}"
  echo "=========================================================="
  echo -e "Timestamp: $(date)"
  echo "Results: $RESULTS_DIR"
  echo ""

  # ============================================================================
  # STEP 1: Pre-flight Safety Checks
  # ============================================================================
  echo -e "${BLUE}[1/8] Running pre-flight safety checks...${NC}"
  bash "$SCRIPT_DIR/fuzzing-tools/scripts/pre-flight-check.sh" || {
    echo -e "${RED}✗ Pre-flight checks failed!${NC}"
    return 1
  }

  # ============================================================================
  # STEP 2: Start Docker Environment
  # ============================================================================
  echo ""
  echo -e "${BLUE}[2/8] Starting isolated Docker environment...${NC}"

  cd "$SCRIPT_DIR"

  # Clean up any previous containers
  docker compose -f docker-compose.fuzzing.yml down -v 2>/dev/null || true

  # Start services
  echo "   Starting services..."
  docker compose -f docker-compose.fuzzing.yml up -d || {
    echo -e "${RED}✗ Failed to start Docker services${NC}"
    return 1
  }

  echo -e "${GREEN}✓ Services started${NC}"

  # ============================================================================
  # STEP 3: Wait for Services
  # ============================================================================
  echo ""
  echo -e "${BLUE}[3/8] Waiting for services to be ready...${NC}"

  # Wait for test_relay
  echo "   Waiting for test_relay..."
  RETRY=0
  while ! docker exec fuzzing_test_relay_1 curl -sf http://localhost:3000/health > /dev/null 2>&1; do
    RETRY=$((RETRY + 1))
    if [ $RETRY -gt 30 ]; then
      echo -e "${RED}✗ test_relay failed to start${NC}"
      docker logs fuzzing_test_relay_1 | tail -20
      return 1
    fi
    sleep 2
  done
  echo -e "${GREEN}✓ test_relay is healthy${NC}"

  # Wait for test_redis
  echo "   Waiting for test_redis..."
  RETRY=0
  while ! docker exec fuzzing_test_redis_1 redis-cli ping > /dev/null 2>&1; do
    RETRY=$((RETRY + 1))
    if [ $RETRY -gt 30 ]; then
      echo -e "${RED}✗ test_redis failed to start${NC}"
      return 1
    fi
    sleep 2
  done
  echo -e "${GREEN}✓ test_redis is healthy${NC}"

  # ============================================================================
  # STEP 4: Seed Test Data
  # ============================================================================
  echo ""
  echo -e "${BLUE}[4/8] Seeding test data into Redis...${NC}"

  mkdir -p "$RESULTS_DIR"

  # Check if Node is available (either locally or in container)
  if command -v node &> /dev/null; then
    # Use local Node
    node "$SCRIPT_DIR/seed-data.js" > "$RESULTS_DIR/seed-data.log" 2>&1 || {
      echo -e "${RED}✗ Data seeding failed${NC}"
      cat "$RESULTS_DIR/seed-data.log"
      return 1
    }
  else
    # Use Node from container (if available)
    echo -e "${YELLOW}⚠ Using Node from container...${NC}"
    docker exec fuzzing_test_relay_1 node /seed-data.js > "$RESULTS_DIR/seed-data.log" 2>&1 || {
      echo -e "${YELLOW}⚠ Container seed failed, trying local npm...${NC}"
      cd "$PROJECT_ROOT"
      npm run seed-data > "$RESULTS_DIR/seed-data.log" 2>&1 || true
    }
  fi

  echo -e "${GREEN}✓ Test data seeded${NC}"

  # ============================================================================
  # STEP 5: Run Authentication Bypass Fuzzer
  # ============================================================================
  echo ""
  echo -e "${BLUE}[5/8] Running authentication bypass fuzzer...${NC}"

  # Check Python availability
  PYTHON_CMD="python3"
  if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
  fi

  if ! command -v $PYTHON_CMD &> /dev/null; then
    echo -e "${YELLOW}⚠ Python not found, skipping auth fuzzer${NC}"
  else
    chmod +x "$SCRIPT_DIR/fuzzing-tools/scripts/fuzz-auth-bypass.py"

    if $PYTHON_CMD "$SCRIPT_DIR/fuzzing-tools/scripts/fuzz-auth-bypass.py" \
      --base-url http://localhost:13000 \
      --output "$RESULTS_DIR/auth-bypass.json"; then
      echo -e "${GREEN}✓ Auth bypass tests passed${NC}"
    else
      echo -e "${YELLOW}⚠ Auth bypass tests detected vulnerabilities${NC}"
      VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
    fi
  fi

  # ============================================================================
  # STEP 6: Run OWASP ZAP Baseline
  # ============================================================================
  echo ""
  echo -e "${BLUE}[6/8] Running OWASP ZAP baseline scan...${NC}"

  # Check if ZAP container is available
  if docker images | grep -q "zaproxy"; then
    chmod +x "$SCRIPT_DIR/fuzzing-tools/scripts/run-zap.sh"
    bash "$SCRIPT_DIR/fuzzing-tools/scripts/run-zap.sh" "$RESULTS_DIR" || {
      echo -e "${YELLOW}⚠ ZAP scan failed or skipped${NC}"
    }
    echo -e "${GREEN}✓ ZAP scan complete${NC}"
  else
    echo -e "${YELLOW}⚠ ZAP image not found, skipping DAST...${NC}"
    echo "   To enable ZAP: docker pull ghcr.io/zaproxy/zaproxy:stable"
  fi

  # ============================================================================
  # STEP 7: Collect Logs
  # ============================================================================
  echo ""
  echo -e "${BLUE}[7/8] Collecting application logs...${NC}"

  docker logs fuzzing_test_relay_1 > "$RESULTS_DIR/app-logs.txt" 2>&1 || true
  docker logs fuzzing_test_redis_1 > "$RESULTS_DIR/redis-logs.txt" 2>&1 || true

  echo -e "${GREEN}✓ Logs collected${NC}"

  # ============================================================================
  # STEP 8: Generate Summary
  # ============================================================================
  echo ""
  echo -e "${BLUE}[8/8] Generating summary report...${NC}"

  # Create summary JSON
  cat > "$RESULTS_DIR/summary.json" << EOF
{
  "campaign_id": "campaign-$TIMESTAMP",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "vulnerabilities_found": $VULNERABILITIES_FOUND,
  "tests": {
    "auth_bypass": "$([ -f "$RESULTS_DIR/auth-bypass.json" ] && echo "passed" || echo "skipped")",
    "zap_baseline": "$([ -f "$RESULTS_DIR/zap-report.json" ] && echo "passed" || echo "skipped")"
  },
  "results_directory": "$RESULTS_DIR"
}
EOF

  echo -e "${GREEN}✓ Summary report generated${NC}"

  # ============================================================================
  # Final Summary
  # ============================================================================
  echo ""
  echo "=========================================================="
  echo -e "${BOLD}Fuzzing Campaign Complete!${NC}"
  echo "=========================================================="
  echo ""
  echo -e "Results: ${BLUE}$RESULTS_DIR${NC}"
  echo ""

  # List generated reports
  echo "Generated Reports:"
  [ -f "$RESULTS_DIR/auth-bypass.json" ] && echo "  ✓ auth-bypass.json (Auth tests)"
  [ -f "$RESULTS_DIR/zap-report.html" ] && echo "  ✓ zap-report.html (ZAP HTML report)"
  [ -f "$RESULTS_DIR/zap-report.json" ] && echo "  ✓ zap-report.json (ZAP JSON report)"
  [ -f "$RESULTS_DIR/app-logs.txt" ] && echo "  ✓ app-logs.txt (Application logs)"
  [ -f "$RESULTS_DIR/summary.json" ] && echo "  ✓ summary.json (Campaign summary)"

  echo ""

  # Show exit status
  if [ $VULNERABILITIES_FOUND -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ SUCCESS: No vulnerabilities detected!${NC}${NC}"
    echo ""
    return 0
  else
    echo -e "${RED}${BOLD}✗ FAILURE: $VULNERABILITIES_FOUND vulnerabilities found!${NC}${NC}"
    echo ""
    return 1
  fi
}

# Run main function
main
exit $?
