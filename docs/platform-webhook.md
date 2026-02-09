# Platform Webhook - Agent Registration

When an agent connects to the Command Server, the server can automatically notify the AISAC platform via webhook. This allows the platform to:

1. **Register the agent** in the asset inventory
2. **Store the Command Server API token** for future SOAR operations
3. **Enable automated incident response workflows** without manual configuration

## Security Model

- Webhook sent **once per agent connection** over **HTTPS**
- Authenticated with **X-API-Key header** (platform API key)
- API token transmitted **securely** to the platform
- Platform stores token **encrypted** and associates it with the agent

## Configuration

### Command Server

Configure webhook during installation or add flags to systemd service:

```bash
aisac-server \
  --listen :8443 \
  --cert /etc/aisac/certs/server.crt \
  --key /etc/aisac/certs/server.key \
  --ca /etc/aisac/certs/ca.crt \
  --api-token "your-api-token" \
  --platform-webhook "https://api.aisac.cisec.es/v1/webhooks/agent-connected" \
  --platform-api-key "your-platform-api-key"
```

### Installer

The installer will prompt for webhook configuration when installing the Command Server:

```
Enable platform webhook notifications? [y/n]: y
Platform webhook URL [https://api.aisac.cisec.es/v1/webhooks/agent-connected]:
Platform API key: ********
```

## Webhook Payload

When an agent connects, the Command Server sends this payload:

```json
{
  "event": "agent_connected",
  "timestamp": "2024-12-04T12:34:56Z",
  "agent_id": "agent-uuid-here",
  "agent_info": {
    "hostname": "prod-web-01",
    "platform": "linux",
    "version": "1.0.3",
    "ip": "192.168.1.100",
    "status": "connected",
    "labels": ["production", "webserver"]
  },
  "command_server": {
    "api_token": "aisac_server_xxx_your_token_here",
    "version": "1.0.3"
  }
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `event` | string | Always "agent_connected" |
| `timestamp` | string | ISO8601 timestamp (UTC) |
| `agent_id` | string | Unique agent identifier |
| `agent_info.hostname` | string | Agent hostname |
| `agent_info.platform` | string | OS platform (linux/windows/darwin) |
| `agent_info.version` | string | Agent version |
| `agent_info.ip` | string | Agent IP address |
| `agent_info.status` | string | Connection status |
| `agent_info.labels` | array | Custom labels |
| `command_server.api_token` | string | **Command Server API token** for SOAR |
| `command_server.version` | string | Command Server version |

## Platform Integration

### Webhook Endpoint

The platform should implement a webhook endpoint that:

1. **Validates the API key** (`X-API-Key` header)
2. **Verifies the payload** (JSON schema validation)
3. **Stores the agent information** in the asset database
4. **Saves the API token** (encrypted) associated with the agent
5. **Returns 200 OK** on success

### Example Implementation (Node.js/Express)

```javascript
app.post('/v1/webhooks/agent-connected', async (req, res) => {
  // Validate API key
  const apiKey = req.headers['x-api-key'];
  if (!isValidPlatformKey(apiKey)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Parse payload
  const { agent_id, agent_info, command_server } = req.body;

  // Store agent in database
  await db.agents.upsert({
    id: agent_id,
    hostname: agent_info.hostname,
    platform: agent_info.platform,
    version: agent_info.version,
    ip: agent_info.ip,
    status: 'connected',
    labels: agent_info.labels,
    last_seen: new Date(),
    // Store API token encrypted
    command_server_token: encrypt(command_server.api_token),
    command_server_version: command_server.version,
  });

  // Trigger asset monitoring workflows
  await triggerAssetMonitoring(agent_id);

  res.json({ success: true });
});
```

### SOAR Workflow Usage

When the platform needs to execute a SOAR action:

1. **Lookup agent** in database by agent_id
2. **Retrieve stored API token** (decrypt)
3. **Call Command Server** REST API with token
4. **Send command** to agent

```javascript
// Example: Block IP via SOAR
async function blockIP(agentId, ipAddress) {
  // Get agent and token
  const agent = await db.agents.findById(agentId);
  const apiToken = decrypt(agent.command_server_token);

  // Call Command Server
  const response = await fetch(`https://server:8443/api/v1/agents/${agentId}/command`, {
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

1. **HTTPS Only**: Webhook must use HTTPS to protect the API token in transit
2. **API Key Authentication**: Platform API key must be kept secure
3. **Token Encryption**: Platform must encrypt stored API tokens at rest
4. **Rate Limiting**: Platform should rate-limit webhook endpoint
5. **Webhook Validation**: Verify webhook signature if needed
6. **Audit Logging**: Log all webhook receipts and API token usage

## Troubleshooting

### Webhook not being sent

Check Command Server logs:
```bash
journalctl -u aisac-server -f
```

Look for:
```
Platform webhook notifications enabled
Sending agent registration webhook to platform
```

### Platform returns error

Check webhook URL and API key configuration:
```bash
cat /etc/aisac-server/server-api-token
```

Verify systemd service parameters:
```bash
systemctl cat aisac-server
```

### Testing webhook manually

Send test webhook:
```bash
curl -X POST https://api.aisac.cisec.es/v1/webhooks/agent-connected \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-platform-key" \
  -d '{
    "event": "agent_connected",
    "timestamp": "2024-12-04T12:34:56Z",
    "agent_id": "test-agent",
    "agent_info": {
      "hostname": "test-host",
      "platform": "linux",
      "version": "1.0.0",
      "ip": "192.168.1.1"
    },
    "command_server": {
      "api_token": "test_token_123",
      "version": "1.0.0"
    }
  }'
```

## Benefits

✅ **Zero Manual Configuration**: No need to manually configure API tokens in n8n
✅ **Automatic Registration**: Agents automatically registered in platform
✅ **Secure Token Storage**: API tokens stored encrypted in platform
✅ **Scalable**: Supports multiple Command Servers and agents
✅ **Audit Trail**: Platform logs all agent connections
✅ **Self-Service**: IT teams can deploy agents without platform access
