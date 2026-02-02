#!/bin/bash
# Test script for Suricata collector functionality
# Run this on the server where aisac-agent is installed

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== AISAC Suricata Collector Test ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Configuration
TEST_LOG_DIR="/tmp/aisac-suricata-test"
TEST_LOG_FILE="${TEST_LOG_DIR}/eve.json"
CONFIG_FILE="/etc/aisac/agent.yaml"

# Create test directory
mkdir -p "$TEST_LOG_DIR"
chmod 755 "$TEST_LOG_DIR"

echo -e "${YELLOW}1. Creating test Suricata EVE log file...${NC}"

# Sample Suricata EVE JSON events (realistic format)
cat > "$TEST_LOG_FILE" << 'EOF'
{"timestamp":"2025-01-22T10:00:00.000000+0000","flow_id":1234567890123456,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.100","src_port":54321,"dest_ip":"10.0.0.50","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2024001,"rev":1,"signature":"ET MALWARE Generic Trojan CnC Beacon","category":"A Network Trojan was detected","severity":1},"flow":{"pkts_toserver":5,"pkts_toclient":3,"bytes_toserver":500,"bytes_toclient":1500,"start":"2025-01-22T09:59:58.000000+0000"}}
{"timestamp":"2025-01-22T10:00:01.000000+0000","flow_id":1234567890123457,"in_iface":"eth0","event_type":"dns","src_ip":"192.168.1.101","src_port":53422,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"query","id":12345,"rrname":"malicious-domain.com","rrtype":"A","tx_id":0}}
{"timestamp":"2025-01-22T10:00:02.000000+0000","flow_id":1234567890123458,"in_iface":"eth0","event_type":"http","src_ip":"192.168.1.102","src_port":45678,"dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","http":{"hostname":"example.com","url":"/download/malware.exe","http_user_agent":"Mozilla/5.0","http_method":"GET","protocol":"HTTP/1.1","status":200,"length":102400}}
{"timestamp":"2025-01-22T10:00:03.000000+0000","flow_id":1234567890123459,"in_iface":"eth0","event_type":"tls","src_ip":"192.168.1.103","src_port":56789,"dest_ip":"172.217.14.206","dest_port":443,"proto":"TCP","tls":{"subject":"CN=*.google.com","issuerdn":"CN=GTS CA 1C3, O=Google Trust Services LLC, C=US","fingerprint":"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd","version":"TLS 1.3","sni":"www.google.com"}}
{"timestamp":"2025-01-22T10:00:04.000000+0000","flow_id":1234567890123460,"in_iface":"eth0","event_type":"alert","src_ip":"10.0.0.25","src_port":22,"dest_ip":"192.168.1.200","dest_port":65432,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2024002,"rev":1,"signature":"ET SCAN SSH Brute Force Attempt","category":"Attempted Administrator Privilege Gain","severity":2},"flow":{"pkts_toserver":100,"pkts_toclient":50,"bytes_toserver":5000,"bytes_toclient":2500,"start":"2025-01-22T09:58:00.000000+0000"}}
EOF

echo -e "${GREEN}   Created: $TEST_LOG_FILE${NC}"
echo "   Events: 5 (2 alerts, 1 dns, 1 http, 1 tls)"
echo ""

echo -e "${YELLOW}2. Checking agent configuration...${NC}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}   Config file not found: $CONFIG_FILE${NC}"
    echo -e "${YELLOW}   Creating test configuration...${NC}"

    # Backup if exists
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    cat > "$CONFIG_FILE" << EOF
# Test configuration for Suricata collector
agent:
  id: "test-agent-suricata"
  name: "Suricata Test Agent"

server:
  enabled: false

heartbeat:
  enabled: true
  interval: 60s
  url: "https://api.aisac.cisec.es/v1/heartbeat"
  api_key: "\${AISAC_API_KEY}"

collector:
  enabled: true
  tenant_id: "\${AISAC_TENANT_ID}"

  sources:
    - name: suricata-test
      type: json_file
      path: ${TEST_LOG_FILE}
      parser: suricata_eve

  output:
    type: http
    url: "https://api.aisac.cisec.es/v1/logs"
    api_key: "\${AISAC_API_KEY}"
    timeout: 30s
    retry_attempts: 3
    retry_delay: 5s

  batch:
    size: 10
    interval: 5s

  file:
    start_position: beginning
    sincedb_path: /var/lib/aisac/sincedb-test

logging:
  level: debug
  format: console
EOF
    echo -e "${GREEN}   Created test config: $CONFIG_FILE${NC}"
else
    echo -e "${GREEN}   Config exists: $CONFIG_FILE${NC}"

    # Check if collector is configured
    if grep -q "collector:" "$CONFIG_FILE"; then
        echo -e "${GREEN}   Collector section found${NC}"
    else
        echo -e "${RED}   No collector section found in config${NC}"
        echo -e "${YELLOW}   Add collector configuration to $CONFIG_FILE${NC}"
    fi
fi
echo ""

echo -e "${YELLOW}3. Checking environment variables...${NC}"

if [ -z "$AISAC_API_KEY" ]; then
    echo -e "${RED}   AISAC_API_KEY not set${NC}"
    echo "   Run: export AISAC_API_KEY='your-api-key'"
else
    echo -e "${GREEN}   AISAC_API_KEY is set${NC}"
fi

if [ -z "$AISAC_TENANT_ID" ]; then
    echo -e "${RED}   AISAC_TENANT_ID not set${NC}"
    echo "   Run: export AISAC_TENANT_ID='your-tenant-id'"
else
    echo -e "${GREEN}   AISAC_TENANT_ID is set${NC}"
fi
echo ""

echo -e "${YELLOW}4. Instructions to test:${NC}"
echo ""
echo "   a) Set environment variables (if not set):"
echo "      export AISAC_API_KEY='your-api-key'"
echo "      export AISAC_TENANT_ID='your-tenant-id'"
echo ""
echo "   b) Update config to use test log file:"
echo "      Edit $CONFIG_FILE"
echo "      Change collector.sources[0].path to: $TEST_LOG_FILE"
echo ""
echo "   c) Restart agent:"
echo "      systemctl restart aisac-agent"
echo ""
echo "   d) Watch logs:"
echo "      journalctl -u aisac-agent -f"
echo ""
echo "   e) Add more test events (to see them collected):"
echo '      echo '\''{"timestamp":"2025-01-22T10:05:00.000000+0000","event_type":"alert","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","alert":{"signature":"Test Alert"}}'\'' >> '$TEST_LOG_FILE
echo ""

echo -e "${YELLOW}5. Verify in AISAC Platform:${NC}"
echo "   - Check Events section for incoming Suricata alerts"
echo "   - Look for source: 'suricata-test'"
echo ""

echo -e "${GREEN}=== Test setup complete ===${NC}"
