# Agent Registration via agent-webhook

When an agent is installed, the installer registers it with the AISAC platform via `POST /v1/agent-webhook`. The registration payload includes agent metadata and, if SOAR mode is enabled, the Command Server connection details. This allows the platform to:

1. **Register the agent** in the asset inventory
2. **Store the Command Server API token** (encrypted) for future SOAR operations
3. **Enable automated incident response workflows** without additional configuration

## Security Model

- Single API key per asset (`aisac_xxx`) — scoped to one asset only
- Command Server token transmitted **once during registration** over **HTTPS**
- Platform stores token **encrypted at rest**
- `PLATFORM_API_KEY` is **no longer exposed to clients** — only used internally by N8N/services

## Registration Flow

```
Installation (single key: aisac_xxx):
  1. Installer generates or reuses persistent Agent ID + Command Server API token
  2. POST /v1/agent-webhook with per-asset API key
     Body: {
       event: "agent_registered",
       asset_id: "uuid",
       agent_info: { agent_id, hostname, os, ... },
       command_server_token: "token",  (optional, only if SOAR enabled)
       command_server_url: "https://IP:8443"  (optional)
     }
  3. Platform validates the per-asset API key
  4. If command_server_token present -> encrypts token and stores it
  5. Agent + Command Server start normally
```

## Registration Payload

```json
{
  "event": "agent_registered",
  "asset_id": "63164623-15fb-4d7f-8655-f79f4338f768",
  "agent_info": {
    "agent_id": "agent-hostname-abc123",
    "hostname": "prod-web-01",
    "os": "debian",
    "os_version": "12",
    "arch": "x86_64",
    "kernel": "6.1.0-18-amd64",
    "ip_address": "192.168.1.100",
    "version": "1.0.1",
    "capabilities": ["collector", "soar", "heartbeat"]
  },
  "command_server_token": "aisac_server_xxx_your_token_here",
  "command_server_url": "https://148.230.125.219:8443"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event` | string | yes | Always `"agent_registered"` |
| `asset_id` | string | yes | Asset UUID from platform |
| `agent_info` | object | yes | Agent metadata |
| `agent_info.agent_id` | string | yes | Unique agent identifier (persisted across reinstalls) |
| `agent_info.hostname` | string | yes | Agent hostname |
| `agent_info.os` | string | yes | OS identifier (debian, ubuntu, etc.) |
| `agent_info.os_version` | string | yes | OS version |
| `agent_info.arch` | string | yes | CPU architecture |
| `agent_info.kernel` | string | no | Kernel version |
| `agent_info.ip_address` | string | no | Primary IP address |
| `agent_info.version` | string | yes | Agent version |
| `agent_info.capabilities` | array | yes | Enabled features |
| `command_server_token` | string | no | CS API token for SOAR operations (only if SOAR enabled) |
| `command_server_url` | string | no | CS public URL (only if SOAR enabled) |

### Response Codes

| Code | Meaning |
|------|---------|
| 201 | First registration — agent linked to asset |
| 200 | Re-registration — agent data updated |
| 404 | Asset not found — must create asset in dashboard first |
| 409 | Conflict — agent_id already belongs to a different asset |
| 401 | Invalid API key |

## Platform Behavior (agent-webhook edge function)

The `agent-webhook` edge function handles registration with upsert logic:

1. **Validate the per-asset API key** (`Authorization: Bearer aisac_xxx`)
2. **Look up asset** by `asset_id` with `maybeSingle()`
3. **If asset not found** -> return 404 (asset must exist in dashboard)
4. **If asset exists with different agent_id** -> overwrite (reinstallation scenario), but check for conflicts with other assets
5. **If agent_id belongs to another asset** -> return 409 Conflict
6. **UPDATE asset** with new agent_id, hostname, OS info, encrypted token
7. **Return 201** (first time) or **200** (re-registration)

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
3. **Token encryption**: Platform encrypts stored API tokens at rest
4. **Rate limiting**: Platform rate-limits the register endpoint
5. **No PLATFORM_API_KEY on clients**: Only internal services use the platform key
6. **Agent ID persistence**: Agent ID is persisted to `/var/lib/aisac/agent-id` and reused on reinstalls

## Non-Interactive Installation

```bash
AISAC_API_KEY=aisac_xxx \
AISAC_ASSET_ID=uuid-here \
AISAC_SOAR=true \
AISAC_CS_TOKEN=your-cs-token \
AISAC_CS_URL=https://IP:8443 \
AISAC_NONINTERACTIVE=true \
sudo -E ./scripts/install.sh
```
