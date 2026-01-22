#!/bin/bash
# Generate continuous Suricata EVE events for testing
# Usage: ./generate-suricata-events.sh [output_file] [interval_seconds]

OUTPUT_FILE="${1:-/tmp/aisac-suricata-test/eve.json}"
INTERVAL="${2:-2}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Ensure directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

echo -e "${GREEN}=== Suricata EVE Event Generator ===${NC}"
echo "Output: $OUTPUT_FILE"
echo "Interval: ${INTERVAL}s"
echo "Press Ctrl+C to stop"
echo ""

# Event types to generate
EVENT_TYPES=("alert" "dns" "http" "tls" "flow")

# Sample IPs
SRC_IPS=("192.168.1.100" "192.168.1.101" "10.0.0.25" "172.16.0.50" "192.168.10.15")
DEST_IPS=("8.8.8.8" "1.1.1.1" "93.184.216.34" "151.101.1.140" "172.217.14.206")

# Alert signatures
SIGNATURES=(
    "ET MALWARE Generic Trojan CnC Beacon"
    "ET SCAN SSH Brute Force Attempt"
    "ET POLICY Suspicious DNS Query"
    "ET WEB_SERVER SQL Injection Attempt"
    "ET EXPLOIT Possible Buffer Overflow"
    "ET TROJAN Ransomware Beacon Detected"
    "ET HUNTING Suspicious TLS Certificate"
)

CATEGORIES=(
    "A Network Trojan was detected"
    "Attempted Administrator Privilege Gain"
    "Potentially Bad Traffic"
    "Web Application Attack"
    "Attempted User Privilege Gain"
    "Malware Command and Control Activity"
    "Potential Corporate Privacy Violation"
)

count=0

while true; do
    count=$((count + 1))
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000000+0000")
    flow_id=$((1000000000000000 + RANDOM * 1000 + RANDOM))
    event_type=${EVENT_TYPES[$((RANDOM % ${#EVENT_TYPES[@]}))]}
    src_ip=${SRC_IPS[$((RANDOM % ${#SRC_IPS[@]}))]}
    dest_ip=${DEST_IPS[$((RANDOM % ${#DEST_IPS[@]}))]}
    src_port=$((RANDOM % 60000 + 1024))
    dest_port=$((RANDOM % 1000 + 1))

    case $event_type in
        alert)
            sig_idx=$((RANDOM % ${#SIGNATURES[@]}))
            signature="${SIGNATURES[$sig_idx]}"
            category="${CATEGORIES[$sig_idx]}"
            sig_id=$((2024000 + RANDOM % 100))
            severity=$((RANDOM % 3 + 1))
            action=$([ $((RANDOM % 2)) -eq 0 ] && echo "allowed" || echo "blocked")

            event=$(cat << EOF
{"timestamp":"${timestamp}","flow_id":${flow_id},"in_iface":"eth0","event_type":"alert","src_ip":"${src_ip}","src_port":${src_port},"dest_ip":"${dest_ip}","dest_port":${dest_port},"proto":"TCP","alert":{"action":"${action}","gid":1,"signature_id":${sig_id},"rev":1,"signature":"${signature}","category":"${category}","severity":${severity}}}
EOF
)
            ;;
        dns)
            domains=("malicious-domain.com" "suspicious.net" "c2-server.ru" "data-exfil.cn" "phishing-site.xyz")
            domain=${domains[$((RANDOM % ${#domains[@]}))]}
            query_type=$([ $((RANDOM % 2)) -eq 0 ] && echo "query" || echo "answer")

            event=$(cat << EOF
{"timestamp":"${timestamp}","flow_id":${flow_id},"in_iface":"eth0","event_type":"dns","src_ip":"${src_ip}","src_port":${src_port},"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","dns":{"type":"${query_type}","id":$((RANDOM % 65535)),"rrname":"${domain}","rrtype":"A","tx_id":0}}
EOF
)
            ;;
        http)
            urls=("/login.php" "/admin/config" "/download/payload.exe" "/api/data" "/wp-admin/")
            user_agents=("Mozilla/5.0" "curl/7.68.0" "python-requests/2.25.1" "Wget/1.20.3")
            url=${urls[$((RANDOM % ${#urls[@]}))]}
            ua=${user_agents[$((RANDOM % ${#user_agents[@]}))]}
            status=$((RANDOM % 5 == 0 ? 404 : 200))

            event=$(cat << EOF
{"timestamp":"${timestamp}","flow_id":${flow_id},"in_iface":"eth0","event_type":"http","src_ip":"${src_ip}","src_port":${src_port},"dest_ip":"${dest_ip}","dest_port":80,"proto":"TCP","http":{"hostname":"suspicious-host.com","url":"${url}","http_user_agent":"${ua}","http_method":"GET","protocol":"HTTP/1.1","status":${status},"length":$((RANDOM % 100000))}}
EOF
)
            ;;
        tls)
            snis=("www.google.com" "api.suspicious.net" "cdn.malware.ru" "secure.bank.com")
            sni=${snis[$((RANDOM % ${#snis[@]}))]}
            version=$([ $((RANDOM % 2)) -eq 0 ] && echo "TLS 1.2" || echo "TLS 1.3")

            event=$(cat << EOF
{"timestamp":"${timestamp}","flow_id":${flow_id},"in_iface":"eth0","event_type":"tls","src_ip":"${src_ip}","src_port":${src_port},"dest_ip":"${dest_ip}","dest_port":443,"proto":"TCP","tls":{"subject":"CN=${sni}","issuerdn":"CN=Let's Encrypt Authority X3","fingerprint":"aa:bb:cc:dd:ee:ff","version":"${version}","sni":"${sni}"}}
EOF
)
            ;;
        flow)
            event=$(cat << EOF
{"timestamp":"${timestamp}","flow_id":${flow_id},"in_iface":"eth0","event_type":"flow","src_ip":"${src_ip}","src_port":${src_port},"dest_ip":"${dest_ip}","dest_port":${dest_port},"proto":"TCP","flow":{"pkts_toserver":$((RANDOM % 100)),"pkts_toclient":$((RANDOM % 50)),"bytes_toserver":$((RANDOM % 10000)),"bytes_toclient":$((RANDOM % 5000)),"state":"closed"}}
EOF
)
            ;;
    esac

    # Append to file
    echo "$event" >> "$OUTPUT_FILE"

    # Show progress
    echo -e "${YELLOW}[$count]${NC} ${event_type}: ${src_ip}:${src_port} -> ${dest_ip}:${dest_port}"

    sleep "$INTERVAL"
done
