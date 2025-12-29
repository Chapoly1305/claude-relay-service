#!/bin/bash
#
# OWASP ZAP Baseline Scanner for Claude Relay Service
#
# Runs ZAP baseline scanning with authentication and generates reports.
#
# Usage:
#   bash tests/security/fuzzing-tools/scripts/run-zap.sh results/
#
# Requirements:
#   - Docker with ghcr.io/zaproxy/zaproxy:stable image
#   - test_relay service running on http://test_relay:3000
#   - Network: fuzzing_net

set -e

RESULTS_DIR="${1:-.}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_DIR="$RESULTS_DIR/zap-$TIMESTAMP"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}🔐 OWASP ZAP Baseline Scan${NC}"
echo "=================================================="
echo "Report Directory: $REPORT_DIR"
echo ""

# Create report directory
mkdir -p "$REPORT_DIR"

# Verify test_relay is running
echo -e "${BLUE}[*] Checking test_relay connectivity...${NC}"
if ! docker exec fuzzing_test_relay_1 curl -sf http://localhost:3000/health > /dev/null 2>&1; then
  echo -e "${RED}✗ test_relay is not responding${NC}"
  echo "   Make sure test_relay container is running and healthy"
  exit 1
fi
echo -e "${GREEN}✓ test_relay is healthy${NC}"
echo ""

# Run ZAP baseline scan
echo -e "${BLUE}[*] Starting ZAP baseline scan...${NC}"
echo "   This may take 2-5 minutes"
echo ""

# Check if ZAP container is running
if ! docker ps | grep -q fuzzing_zap_1; then
  echo -e "${YELLOW}⚠ ZAP container not running, waiting for startup...${NC}"
  sleep 10
fi

# Wait for ZAP to be ready
echo -e "${BLUE}[*] Waiting for ZAP daemon...${NC}"
for i in {1..30}; do
  if docker exec fuzzing_zap_1 curl -sf http://localhost:8080/ > /dev/null 2>&1; then
    echo -e "${GREEN}✓ ZAP is ready${NC}"
    break
  fi
  if [ $i -eq 30 ]; then
    echo -e "${RED}✗ ZAP failed to start${NC}"
    exit 1
  fi
  sleep 2
done

echo ""

# Run the actual scan
# Using curl to invoke ZAP API since we're in docker-compose context
docker exec fuzzing_zap_1 bash -c "
  zap-baseline.py \
    -t http://test_relay:3000 \
    -r '$REPORT_DIR/zap-report.html' \
    -J '$REPORT_DIR/zap-report.json' \
    -w '$REPORT_DIR/zap-report.md' \
    -d 2>&1 || true
" || true

echo ""
echo -e "${BLUE}[*] ZAP scan completed${NC}"
echo ""

# Check if reports were generated
if [ -f "$REPORT_DIR/zap-report.json" ]; then
  echo -e "${GREEN}✓ Reports generated:${NC}"
  echo "   - HTML: $REPORT_DIR/zap-report.html"
  echo "   - JSON: $REPORT_DIR/zap-report.json"
  echo "   - Markdown: $REPORT_DIR/zap-report.md"
  echo ""

  # Parse and display summary from JSON report
  if command -v jq &> /dev/null; then
    echo -e "${BLUE}[*] Scan Summary:${NC}"

    # Try to extract alert counts
    ALERT_COUNT=$(jq '.alerts | length' "$REPORT_DIR/zap-report.json" 2>/dev/null || echo "0")
    HIGH_COUNT=$(jq '[.alerts[] | select(.risk == "High")] | length' "$REPORT_DIR/zap-report.json" 2>/dev/null || echo "0")
    MEDIUM_COUNT=$(jq '[.alerts[] | select(.risk == "Medium")] | length' "$REPORT_DIR/zap-report.json" 2>/dev/null || echo "0")

    echo "   Total Alerts: $ALERT_COUNT"
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo -e "   ${RED}High: $HIGH_COUNT${NC}"
    else
      echo "   High: $HIGH_COUNT"
    fi
    if [ "$MEDIUM_COUNT" -gt 0 ]; then
      echo -e "   ${YELLOW}Medium: $MEDIUM_COUNT${NC}"
    else
      echo "   Medium: $MEDIUM_COUNT"
    fi
  fi
else
  echo -e "${YELLOW}⚠ ZAP reports not found - scan may have failed${NC}"
  echo ""

  # Try to get logs from ZAP
  echo -e "${BLUE}[*] ZAP logs:${NC}"
  docker logs fuzzing_zap_1 2>&1 | tail -20 || true
  exit 1
fi

echo ""
echo -e "${GREEN}✓ ZAP baseline scan complete${NC}"
echo ""
