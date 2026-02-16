# Agent Registration with Command Server Data

When an agent is installed, the installer registers it with the AISAC platform via `POST /v1/register`. If SOAR mode is enabled, the registration payload includes the Command Server connection details, allowing the platform to:

1. **Register the agent** in the asset inventory
2. **Store the Command Server API token** (encrypted) for future SOAR operations
3. **Enable automated incident response workflows** without additional configuration

## Security Model

- Single API key per asset (`aisac_xxx`) — scoped to one asset only
- Command Server token transmitted **once during registration** over **HTTPS**
- Platform stores token **encrypted at rest**
- `PLATFORM_API_KEY` is **no longer exposed to clients** — only used internally by N8N/services
- The `agent-webhook` endpoint remains available for internal use only

## Registration Flow

```
Installation (single key: aisac_xxx):
  1. Installer generates Agent ID + Command Server API token
  2. POST /v1/register with per-asset API key
     Body: {
       agent_id, asset_id, hostname, os, version,
       command_server: {            (optional, only if SOAR enabled)
         api_token: "token-local",
         url: "https://IP:8443",
         version: "1.0.1"
       }
     }
  3. Platform validates the per-asset API key
  4. If command_server present → encrypts token and stores it
  5. Agent + Command Server start normally
```

## Registration Payload

```json
{
  "agent_id": "agent-hostname-abc123",
  "asset_id": "63164623-15fb-4d7f-8655-f79f4338f768",
  "hostname": "prod-web-01",
  "os": "debian",
  "os_version": "12",
  "arch": "x86_64",
  "kernel": "6.1.0-18-amd64",
  "ip_address": "192.168.1.100",
  "version": "1.0.1",
  "capabilities": ["collector", "soar", "heartbeat"],
  "command_server": {
    "api_token": "aisac_server_xxx_your_token_here",
    "url": "https://148.230.125.219:8443",
    "version": "1.0.1"
  }
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | yes | Unique agent identifier |
| `asset_id` | string | yes | Asset UUID from platform |
| `hostname` | string | yes | Agent hostname |
| `os` | string | yes | OS identifier (debian, ubuntu, etc.) |
| `os_version` | string | yes | OS version |
| `arch` | string | yes | CPU architecture |
| `kernel` | string | no | Kernel version |
| `ip_address` | string | no | Primary IP address |
| `version` | string | yes | Agent version |
| `capabilities` | array | yes | Enabled features |
| `command_server` | object | no | Command Server data (only if SOAR enabled) |
| `command_server.api_token` | string | yes* | CS API token for SOAR operations |
| `command_server.url` | string | yes* | CS public URL |
| `command_server.version` | string | no | CS version |

*Required only when `command_server` object is present.

### Response

```json
{
  "success": true,
  "agent_id": "agent-hostname-abc123",
  "message": "Agent registered successfully",
  "command_server_registered": true
}
```

## Platform Integration

### Edge Function (agent-register)

The platform `agent-register` edge function should:

1. **Validate the per-asset API key** (`X-API-Key` header)
2. **Verify asset_id matches the API key** (prevent cross-asset writes)
3. **Store agent information** in the asset database
4. **If `command_server` present** → encrypt token and store it
5. **Return success response**

### SOAR Workflow Usage

When the platform needs to execute a SOAR action:

1. **Lookup agent** in database by agent_id
2. **Retrieve stored API token** (decrypt)
3. **Call Command Server** REST API with token
4. **Send command** to agent

```javascript
async function blockIP(agentId, ipAddress) {
  const agent = await db.agents.findById(agentId);
  const apiToken = decrypt(agent.command_server_token);

  const response = await fetch(`${agent.command_server_url}/api/v1/agents/${agentId}/command`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      action: 'block_ip',
      parameters: { ip_address: ipAddress }
    }),
  });

  return response.json();
}
```

## Security Considerations

1. **Per-asset key scope**: Each API key can only modify its own asset data
2. **HTTPS only**: Registration uses HTTPS to protect the token in transit
3. **Token encryption**: Platform must encrypt stored API tokens at rest
4. **Rate limiting**: Platform should rate-limit the register endpoint
5. **No PLATFORM_API_KEY on clients**: Only internal services use the platform key

## Migration from Webhook Model

| Before | After |
|--------|-------|
| Agent calls `/v1/register` (per-asset key) | Same |
| CS calls `/v1/webhooks/agent-connected` (PLATFORM_API_KEY) | Agent includes CS data in `/v1/register` |
| Client needs 2 keys | Client needs 1 key |
| PLATFORM_API_KEY exposed to clients | PLATFORM_API_KEY only internal |
| `--platform-webhook` and `--platform-api-key` flags | Removed from Command Server |

## Non-Interactive Installation

```bash
AISAC_API_KEY=aisac_xxx \
AISAC_ASSET_ID=uuid-here \
AISAC_SOAR=true \
AISAC_CS_TOKEN=your-cs-token \
AISAC_CS_URL=https://IP:8443 \
AISAC_NONINTERACTIVE=true \
sudo bash install.sh
```

## Internal Webhook (agent-webhook)

The `/v1/webhooks/agent-connected` endpoint remains available for **internal use only** (N8N, platform services). It requires `PLATFORM_API_KEY` authentication and is never called by client-installed agents.
