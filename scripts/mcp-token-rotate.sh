#!/usr/bin/env bash
# =============================================================================
# MCP Token Rotation (DRA Symmetric Chain Advance)
#
# Daily cronjob that advances the KDF chain to derive a new MCP API key.
# This provides forward secrecy: compromising the current token doesn't
# reveal past tokens (HKDF is one-way).
#
# Install as cronjob:
#   0 3 * * * /opt/aisac/scripts/mcp-token-rotate.sh >> /var/log/aisac/mcp-rotate.log 2>&1
#
# Chain advance algorithm (must match TypeScript/Go):
#   token     = HKDF(chain_key, salt="aisac-mcp-salt", info="aisac-mcp-token")
#   new_chain = HKDF(chain_key, salt="aisac-mcp-salt", info="aisac-mcp-advance")
# =============================================================================

set -euo pipefail

CONFIG_DIR="/etc/aisac"
DRA_STATE_FILE="$CONFIG_DIR/mcp-dra-state.json"
MCP_INSTALL_DIR="/opt/wazuh-mcp-server"
LOG_PREFIX="[MCP-ROTATE]"

log_info()  { echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX INFO  $*"; }
log_error() { echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX ERROR $*" >&2; }
log_ok()    { echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX OK    $*"; }

# Verify prerequisites
if [ ! -f "$DRA_STATE_FILE" ]; then
    log_error "DRA state file not found: $DRA_STATE_FILE"
    exit 1
fi

if [ ! -f "$MCP_INSTALL_DIR/.env" ]; then
    log_error "MCP Server .env not found: $MCP_INSTALL_DIR/.env"
    exit 1
fi

# Read current chain_key from DRA state
current_chain_key=$(python3 -c "import json; print(json.load(open('$DRA_STATE_FILE'))['chain_key'])" 2>/dev/null)
if [ -z "$current_chain_key" ]; then
    log_error "Could not read chain_key from DRA state"
    exit 1
fi

log_info "Advancing DRA chain..."

# Advance chain using Python HKDF (must match TypeScript/Go exactly)
advance_result=$(python3 << 'PYEOF'
import json, hashlib, hmac, base64, os

def b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (4 - len(s) % 4) if len(s) % 4 else ''
    return base64.b64decode(s)

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def hkdf_derive(ikm, salt, info, length=32):
    """HKDF-SHA256 matching Web Crypto API / Go crypto/hkdf."""
    if isinstance(salt, str):
        salt = salt.encode()
    if isinstance(info, str):
        info = info.encode()
    # Extract
    prk = hmac.new(salt if salt else b'\x00' * 32, ikm, hashlib.sha256).digest()
    # Expand
    t = b''
    okm = b''
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

chain_key_b64 = os.environ['CHAIN_KEY']
chain_key = b64url_decode(chain_key_b64)

# Derive current token
token_bytes = hkdf_derive(chain_key, 'aisac-mcp-salt', 'aisac-mcp-token', 32)
mcp_token = 'wazuh_' + b64url_encode(token_bytes)

# Advance chain (one-way = forward secrecy)
new_chain_key = hkdf_derive(chain_key, 'aisac-mcp-salt', 'aisac-mcp-advance', 32)

print(json.dumps({
    'new_chain_key': b64url_encode(new_chain_key),
    'mcp_token': mcp_token,
}))
PYEOF
)

if [ -z "$advance_result" ]; then
    log_error "Chain advance computation failed"
    exit 1
fi

new_chain_key=$(echo "$advance_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['new_chain_key'])")
new_mcp_token=$(echo "$advance_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['mcp_token'])")

if [ -z "$new_chain_key" ] || [ -z "$new_mcp_token" ]; then
    log_error "Failed to parse chain advance result"
    exit 1
fi

log_info "New token: ${new_mcp_token:0:15}..."

# Update DRA state file with new chain_key
python3 << PYEOF2
import json
with open('$DRA_STATE_FILE', 'r') as f:
    state = json.load(f)
state['chain_key'] = '$new_chain_key'
with open('$DRA_STATE_FILE', 'w') as f:
    json.dump(state, f, indent=2)
PYEOF2
chmod 600 "$DRA_STATE_FILE"

# Update MCP_API_KEY in .env
sed -i "s|^MCP_API_KEY=.*|MCP_API_KEY=${new_mcp_token}|" "$MCP_INSTALL_DIR/.env"

# Update local token file
echo "$new_mcp_token" > "$CONFIG_DIR/mcp-auth-token"
chmod 600 "$CONFIG_DIR/mcp-auth-token"

# Restart MCP Server container to pick up new key
log_info "Restarting MCP Server container..."
(cd "$MCP_INSTALL_DIR" && sudo docker compose restart 2>&1 | tail -2)

log_ok "Token rotation complete. New token active."
