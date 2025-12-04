# AISAC Agent Command Server REST API Documentation

**Version:** v1.0.0
**Base URL:** `https://command-server.aisac.local/api/v1`
**Protocol:** HTTPS only

## Table of Contents

- [Authentication](#authentication)
- [Common Response Codes](#common-response-codes)
- [Error Response Format](#error-response-format)
- [Endpoints](#endpoints)
  - [Health Check](#1-health-check)
  - [List Agents](#2-list-agents)
  - [Get Agent](#3-get-agent)
  - [Send Command](#4-send-command)
- [Available Actions](#available-actions)
- [Action Parameters Reference](#action-parameters-reference)
- [Rate Limiting](#rate-limiting)
- [Audit Logging](#audit-logging)

---

## Authentication

Most endpoints require Bearer token authentication. Include the token in the `Authorization` header:

```http
Authorization: Bearer <your-token-here>
```

**Token Types:**
- **Service Token:** For programmatic access (n8n, SOAR platform)
- **Admin Token:** For administrative operations

Tokens are configured in the server's `config.yaml` file.

---

## Common Response Codes

| Status Code | Description |
|-------------|-------------|
| `200 OK` | Request succeeded |
| `201 Created` | Resource created successfully |
| `400 Bad Request` | Invalid request parameters |
| `401 Unauthorized` | Missing or invalid authentication token |
| `403 Forbidden` | Insufficient permissions |
| `404 Not Found` | Resource not found (agent, command, etc.) |
| `422 Unprocessable Entity` | Valid JSON but invalid parameters |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Server error |
| `503 Service Unavailable` | Server is temporarily unavailable |

---

## Error Response Format

All error responses follow this structure:

```json
{
  "error": {
    "code": "agent_not_found",
    "message": "Agent with ID 'agent-123' not found",
    "details": {
      "agent_id": "agent-123",
      "timestamp": "2025-12-04T10:30:00Z"
    }
  }
}
```

**Common Error Codes:**
- `invalid_request`: Malformed request body or parameters
- `authentication_required`: Missing Authorization header
- `invalid_token`: Token is invalid or expired
- `agent_not_found`: Agent does not exist or is offline
- `agent_offline`: Agent is registered but not connected
- `action_not_allowed`: Action is disabled or not supported
- `rate_limit_exceeded`: Too many requests
- `command_timeout`: Command execution exceeded timeout
- `execution_failed`: Command failed on agent

---

## Endpoints

### 1. Health Check

Check the server's health status and basic statistics.

**Endpoint:** `GET /api/v1/health`
**Authentication:** None (public endpoint)

#### Request

```bash
curl -X GET https://command-server.aisac.local/api/v1/health
```

#### Response (200 OK)

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "build_time": "2025-12-04T08:00:00Z",
  "agent_count": 5,
  "uptime_seconds": 86400,
  "server_time": "2025-12-04T10:30:00Z"
}
```

**Response Fields:**
- `status`: Server health status (`healthy`, `degraded`, `unhealthy`)
- `version`: Server version
- `build_time`: Build timestamp
- `agent_count`: Number of currently connected agents
- `uptime_seconds`: Server uptime in seconds
- `server_time`: Current server time (ISO 8601)

#### Response (503 Service Unavailable)

```json
{
  "status": "unhealthy",
  "version": "1.0.0",
  "error": "Database connection failed"
}
```

---

### 2. List Agents

Retrieve a list of all registered agents and their connection status.

**Endpoint:** `GET /api/v1/agents`
**Authentication:** Required (Bearer token)

#### Request

```bash
curl -X GET https://command-server.aisac.local/api/v1/agents \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | No | Filter by status: `online`, `offline`, `all` (default: `all`) |
| `platform` | string | No | Filter by platform: `linux`, `windows`, `firewall` |
| `limit` | integer | No | Max results per page (default: 100, max: 1000) |
| `offset` | integer | No | Pagination offset (default: 0) |

#### Example with filters

```bash
curl -X GET "https://command-server.aisac.local/api/v1/agents?status=online&platform=linux&limit=50" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Response (200 OK)

```json
{
  "agents": [
    {
      "id": "agent-linux-001",
      "hostname": "web-server-01",
      "platform": "linux",
      "os_version": "Ubuntu 22.04 LTS",
      "agent_version": "1.0.0",
      "status": "online",
      "ip_address": "10.0.1.50",
      "last_seen": "2025-12-04T10:29:45Z",
      "connected_at": "2025-12-04T08:00:00Z",
      "enabled_actions": [
        "block_ip",
        "unblock_ip",
        "isolate_host",
        "unisolate_host",
        "disable_user",
        "kill_process"
      ],
      "tags": ["production", "web-server", "dmz"],
      "metadata": {
        "datacenter": "us-east-1",
        "environment": "production"
      }
    },
    {
      "id": "agent-windows-002",
      "hostname": "DC01",
      "platform": "windows",
      "os_version": "Windows Server 2022",
      "agent_version": "1.0.0",
      "status": "offline",
      "ip_address": "10.0.2.10",
      "last_seen": "2025-12-04T09:15:30Z",
      "connected_at": "2025-12-03T08:00:00Z",
      "enabled_actions": [
        "disable_user",
        "enable_user",
        "kill_process"
      ],
      "tags": ["production", "domain-controller"],
      "metadata": {
        "datacenter": "us-east-1",
        "environment": "production",
        "domain": "CORP"
      }
    }
  ],
  "pagination": {
    "total": 5,
    "limit": 100,
    "offset": 0
  }
}
```

**AgentInfo Fields:**
- `id`: Unique agent identifier
- `hostname`: Agent's hostname
- `platform`: Operating system platform
- `os_version`: Detailed OS version
- `agent_version`: AISAC Agent software version
- `status`: Connection status (`online`, `offline`)
- `ip_address`: Agent's IP address
- `last_seen`: Last heartbeat timestamp (ISO 8601)
- `connected_at`: Connection establishment time
- `enabled_actions`: List of actions this agent can execute
- `tags`: Custom tags for organization
- `metadata`: Additional key-value metadata

#### Response (401 Unauthorized)

```json
{
  "error": {
    "code": "authentication_required",
    "message": "Missing or invalid authorization token"
  }
}
```

---

### 3. Get Agent

Retrieve detailed information about a specific agent.

**Endpoint:** `GET /api/v1/agents/{id}`
**Authentication:** Required (Bearer token)

#### Request

```bash
curl -X GET https://command-server.aisac.local/api/v1/agents/agent-linux-001 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### Response (200 OK)

```json
{
  "id": "agent-linux-001",
  "hostname": "web-server-01",
  "platform": "linux",
  "os_version": "Ubuntu 22.04 LTS",
  "agent_version": "1.0.0",
  "status": "online",
  "ip_address": "10.0.1.50",
  "last_seen": "2025-12-04T10:29:45Z",
  "connected_at": "2025-12-04T08:00:00Z",
  "enabled_actions": [
    "block_ip",
    "unblock_ip",
    "isolate_host",
    "unisolate_host",
    "disable_user",
    "enable_user",
    "kill_process",
    "collect_forensics",
    "threat_hunt"
  ],
  "tags": ["production", "web-server", "dmz"],
  "metadata": {
    "datacenter": "us-east-1",
    "environment": "production",
    "owner": "security-team"
  },
  "statistics": {
    "total_commands_executed": 147,
    "last_command_at": "2025-12-04T09:45:00Z",
    "success_rate": 98.6
  }
}
```

#### Response (404 Not Found)

```json
{
  "error": {
    "code": "agent_not_found",
    "message": "Agent with ID 'agent-linux-001' not found",
    "details": {
      "agent_id": "agent-linux-001"
    }
  }
}
```

---

### 4. Send Command

Send an action command to a specific agent for execution.

**Endpoint:** `POST /api/v1/agents/{id}/command`
**Authentication:** Required (Bearer token)
**Content-Type:** `application/json`

#### Request

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block_ip",
    "parameters": {
      "ip_address": "192.168.1.100",
      "duration": 3600,
      "direction": "both"
    },
    "execution_id": "soar-exec-20251204-001",
    "timeout_seconds": 30
  }'
```

#### Request Body

```json
{
  "action": "block_ip",
  "parameters": {
    "ip_address": "192.168.1.100",
    "duration": 3600,
    "direction": "both"
  },
  "execution_id": "soar-exec-20251204-001",
  "timeout_seconds": 30,
  "metadata": {
    "incident_id": "INC-2025-12345",
    "playbook_id": "pb-block-malicious-ip",
    "analyst": "john.doe@company.com"
  }
}
```

**Request Fields:**
- `action` (required): Action to execute (see [Available Actions](#available-actions))
- `parameters` (required): Action-specific parameters (object)
- `execution_id` (optional): Unique execution ID from SOAR platform for tracking
- `timeout_seconds` (optional): Command timeout in seconds (default: 30, max: 300)
- `metadata` (optional): Additional context for audit logging

#### Response (200 OK)

```json
{
  "command_id": "cmd-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "sent",
  "agent_id": "agent-linux-001",
  "action": "block_ip",
  "execution_id": "soar-exec-20251204-001",
  "sent_at": "2025-12-04T10:30:00Z",
  "estimated_completion": "2025-12-04T10:30:30Z"
}
```

**Response Fields:**
- `command_id`: Unique command identifier for tracking
- `status`: Command status (`sent`, `acknowledged`, `executing`, `completed`, `failed`)
- `agent_id`: Target agent identifier
- `action`: Action being executed
- `execution_id`: SOAR execution ID (if provided)
- `sent_at`: Command send timestamp
- `estimated_completion`: Estimated completion time based on timeout

#### Response (400 Bad Request)

**Invalid parameters:**

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid action parameters",
    "details": {
      "field": "parameters.ip_address",
      "reason": "Invalid IP address format",
      "provided": "not-an-ip"
    }
  }
}
```

#### Response (404 Not Found)

**Agent not found:**

```json
{
  "error": {
    "code": "agent_not_found",
    "message": "Agent with ID 'agent-linux-001' not found or offline",
    "details": {
      "agent_id": "agent-linux-001"
    }
  }
}
```

#### Response (403 Forbidden)

**Action not enabled:**

```json
{
  "error": {
    "code": "action_not_allowed",
    "message": "Action 'threat_hunt' is not enabled on agent 'agent-linux-001'",
    "details": {
      "agent_id": "agent-linux-001",
      "action": "threat_hunt",
      "enabled_actions": ["block_ip", "unblock_ip", "isolate_host"]
    }
  }
}
```

#### Response (429 Too Many Requests)

**Rate limit exceeded:**

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded for action 'block_ip'",
    "details": {
      "limit": 10,
      "window_seconds": 60,
      "retry_after": 45
    }
  }
}
```

#### WebSocket Response Notification

After sending a command, the agent will execute it and send a response back. The server can notify via WebSocket or the response can be retrieved via the command status endpoint (future enhancement).

**Agent Response (success):**

```json
{
  "id": "resp-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "command_id": "cmd-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "success",
  "result": {
    "action": "ip_blocked",
    "ip_address": "192.168.1.100",
    "rule_id": "iptables-12345",
    "expires_at": "2025-12-04T11:30:00Z",
    "details": {
      "firewall": "iptables",
      "chain": "INPUT",
      "rule": "DROP all from 192.168.1.100"
    }
  },
  "execution_time_ms": 150,
  "completed_at": "2025-12-04T10:30:00.150Z"
}
```

**Agent Response (failure):**

```json
{
  "id": "resp-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "command_id": "cmd-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "failed",
  "error": {
    "code": "permission_denied",
    "message": "Insufficient permissions to modify firewall rules",
    "details": {
      "required_permission": "CAP_NET_ADMIN",
      "current_user": "aisac-agent"
    }
  },
  "execution_time_ms": 50,
  "completed_at": "2025-12-04T10:30:00.050Z"
}
```

---

## Available Actions

The AISAC Agent supports the following security response actions:

| Action | Description | Platforms |
|--------|-------------|-----------|
| `block_ip` | Block an IP address in the firewall | Linux, Windows, Firewall appliances |
| `unblock_ip` | Remove IP block from firewall | Linux, Windows, Firewall appliances |
| `isolate_host` | Isolate host from network | Linux, Windows |
| `unisolate_host` | Restore network connectivity | Linux, Windows |
| `disable_user` | Disable a user account | Linux, Windows, Active Directory |
| `enable_user` | Re-enable a user account | Linux, Windows, Active Directory |
| `kill_process` | Terminate a running process | Linux, Windows |
| `collect_forensics` | Collect forensic evidence | All platforms |
| `threat_hunt` | Search for indicators of compromise | All platforms |

---

## Action Parameters Reference

### block_ip

Block an IP address in the local firewall.

**Parameters:**

```json
{
  "ip_address": "192.168.1.100",
  "duration": 3600,
  "direction": "both",
  "reason": "Malicious activity detected"
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip_address` | string | Yes | IP address to block (IPv4 or IPv6) |
| `duration` | integer | No | Block duration in seconds (0 = permanent, default: 0) |
| `direction` | string | No | Traffic direction: `in`, `out`, `both` (default: `both`) |
| `reason` | string | No | Reason for blocking (for audit logs) |

**Example:**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block_ip",
    "parameters": {
      "ip_address": "203.0.113.42",
      "duration": 7200,
      "direction": "both",
      "reason": "Brute force attack detected"
    },
    "execution_id": "soar-exec-001",
    "timeout_seconds": 30
  }'
```

---

### unblock_ip

Remove an IP address block from the firewall.

**Parameters:**

```json
{
  "ip_address": "192.168.1.100"
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ip_address` | string | Yes | IP address to unblock |

**Example:**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "unblock_ip",
    "parameters": {
      "ip_address": "203.0.113.42"
    },
    "execution_id": "soar-exec-002"
  }'
```

---

### isolate_host

Isolate the host from the network by blocking all traffic except management connections.

**Parameters:**

```json
{
  "allow_ssh": true,
  "allowed_ips": ["10.0.0.1", "10.0.0.2"],
  "reason": "Ransomware detected"
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `allow_ssh` | boolean | No | Keep SSH/RDP access for management (default: `true`) |
| `allowed_ips` | array | No | IPs allowed to connect during isolation (management IPs) |
| `reason` | string | No | Reason for isolation |

**Example:**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "isolate_host",
    "parameters": {
      "allow_ssh": true,
      "allowed_ips": ["10.0.0.50"],
      "reason": "Suspected malware infection"
    },
    "execution_id": "soar-exec-003",
    "timeout_seconds": 60
  }'
```

---

### unisolate_host

Restore full network connectivity to a previously isolated host.

**Parameters:**

```json
{}
```

No parameters required.

**Example:**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "unisolate_host",
    "parameters": {},
    "execution_id": "soar-exec-004"
  }'
```

---

### disable_user

Disable a user account to prevent login.

**Parameters:**

```json
{
  "username": "john.doe",
  "force_logout": true,
  "reason": "Compromised credentials"
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | Yes | Username to disable |
| `force_logout` | boolean | No | Force logout active sessions (default: `false`) |
| `reason` | string | No | Reason for disabling |

**Example (Linux/Local User):**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "disable_user",
    "parameters": {
      "username": "jdoe",
      "force_logout": true,
      "reason": "Account compromise suspected"
    },
    "execution_id": "soar-exec-005"
  }'
```

**Example (Windows/Active Directory):**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-windows-002/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "disable_user",
    "parameters": {
      "username": "CORP\\jdoe",
      "force_logout": true,
      "reason": "Phishing victim - credential theft"
    },
    "execution_id": "soar-exec-006"
  }'
```

---

### enable_user

Re-enable a previously disabled user account.

**Parameters:**

```json
{
  "username": "john.doe"
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | Yes | Username to enable |

**Example:**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "enable_user",
    "parameters": {
      "username": "jdoe"
    },
    "execution_id": "soar-exec-007"
  }'
```

---

### kill_process

Terminate a running process by PID or process name.

**Parameters:**

```json
{
  "pid": 1234,
  "process_name": "malware.exe",
  "kill_all": false,
  "force": true
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pid` | integer | Conditional | Process ID to kill (required if `process_name` not provided) |
| `process_name` | string | Conditional | Process name to kill (required if `pid` not provided) |
| `kill_all` | boolean | No | Kill all processes matching name (default: `false`) |
| `force` | boolean | No | Force kill (SIGKILL/taskkill /F) (default: `true`) |

**Example (Kill by PID):**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "kill_process",
    "parameters": {
      "pid": 5678,
      "force": true
    },
    "execution_id": "soar-exec-008"
  }'
```

**Example (Kill by name):**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-windows-002/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "kill_process",
    "parameters": {
      "process_name": "mimikatz.exe",
      "kill_all": true,
      "force": true
    },
    "execution_id": "soar-exec-009"
  }'
```

---

### collect_forensics

Collect forensic evidence from the host for incident investigation.

**Parameters:**

```json
{
  "artifacts": ["memory", "disk", "logs", "network"],
  "output_path": "/var/aisac/forensics/incident-2025-001",
  "compress": true
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `artifacts` | array | No | Artifacts to collect (default: all available) |
| `output_path` | string | No | Output directory path (default: agent config) |
| `compress` | boolean | No | Compress output (default: `true`) |

**Available artifacts:**
- `memory`: Memory dump
- `disk`: Disk forensics (MFT, filesystem timeline)
- `logs`: System and application logs
- `network`: Network connections, ARP cache, routing table
- `processes`: Running processes, loaded modules
- `registry`: Windows registry hives (Windows only)

**Example:**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "collect_forensics",
    "parameters": {
      "artifacts": ["memory", "logs", "network"],
      "output_path": "/var/aisac/forensics/INC-2025-12345",
      "compress": true
    },
    "execution_id": "soar-exec-010",
    "timeout_seconds": 300
  }'
```

---

### threat_hunt

Search for indicators of compromise (IOCs) on the host.

**Parameters:**

```json
{
  "ioc_type": "file_hash",
  "ioc_value": "5f4dcc3b5aa765d61d8327deb882cf99",
  "search_paths": ["/home", "/tmp", "/var/www"],
  "deep_scan": false
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ioc_type` | string | Yes | IOC type: `file_hash`, `ip_address`, `domain`, `file_path`, `registry_key` |
| `ioc_value` | string | Yes | IOC value to search for |
| `search_paths` | array | No | Paths to search (default: system-wide) |
| `deep_scan` | boolean | No | Deep scan mode (slower, more thorough) (default: `false`) |

**Example (File Hash):**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "threat_hunt",
    "parameters": {
      "ioc_type": "file_hash",
      "ioc_value": "44d88612fea8a8f36de82e1278abb02f",
      "search_paths": ["/home", "/tmp"],
      "deep_scan": true
    },
    "execution_id": "soar-exec-011",
    "timeout_seconds": 600
  }'
```

**Example (IP Address in logs):**

```bash
curl -X POST https://command-server.aisac.local/api/v1/agents/agent-linux-001/command \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "threat_hunt",
    "parameters": {
      "ioc_type": "ip_address",
      "ioc_value": "203.0.113.66",
      "search_paths": ["/var/log"]
    },
    "execution_id": "soar-exec-012",
    "timeout_seconds": 300
  }'
```

---

## Rate Limiting

The API implements rate limiting to prevent abuse and ensure fair usage.

**Rate Limits:**
- **Authentication attempts:** 5 per minute per IP
- **Command execution:** 10 per minute per agent
- **List operations:** 100 per minute per token
- **Health check:** Unlimited

**Rate Limit Headers:**

```http
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1733308800
```

When rate limited, the API returns `429 Too Many Requests` with a `Retry-After` header:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 45
Content-Type: application/json

{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 10,
      "window_seconds": 60,
      "retry_after": 45
    }
  }
}
```

---

## Audit Logging

All API requests and command executions are logged for security auditing and compliance.

**Logged Information:**
- Request timestamp
- Client IP address
- Authentication token (hash)
- Endpoint accessed
- Request parameters
- Agent ID (for commands)
- Action executed
- Response status
- Execution result
- Error details (if any)

**Audit Log Format (JSON):**

```json
{
  "timestamp": "2025-12-04T10:30:00.123Z",
  "level": "info",
  "event": "command_executed",
  "client_ip": "10.0.5.100",
  "token_hash": "sha256:a1b2c3d4...",
  "endpoint": "/api/v1/agents/agent-linux-001/command",
  "method": "POST",
  "agent_id": "agent-linux-001",
  "command_id": "cmd-a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "action": "block_ip",
  "parameters": {
    "ip_address": "192.168.1.100",
    "duration": 3600
  },
  "execution_id": "soar-exec-001",
  "status": "success",
  "execution_time_ms": 150,
  "metadata": {
    "incident_id": "INC-2025-12345",
    "analyst": "john.doe@company.com"
  }
}
```

Audit logs are stored in:
- **File:** `/var/log/aisac-server/audit.log` (JSON Lines format)
- **Syslog:** Optional syslog forwarding to SIEM
- **Database:** Optional PostgreSQL audit table

---

## Integration Examples

### n8n Workflow Integration

Example n8n HTTP Request node configuration:

```json
{
  "method": "POST",
  "url": "https://command-server.aisac.local/api/v1/agents/{{$json['agent_id']}}/command",
  "authentication": "genericCredentialType",
  "genericAuthType": "httpHeaderAuth",
  "httpHeaderAuth": {
    "name": "Authorization",
    "value": "Bearer {{$credentials.aisacToken}}"
  },
  "sendBody": true,
  "bodyParameters": {
    "action": "{{$json['action']}}",
    "parameters": "{{$json['parameters']}}",
    "execution_id": "{{$workflow.id}}-{{$execution.id}}",
    "timeout_seconds": 30
  }
}
```

### Python SDK Example

```python
import requests
from typing import Dict, Any

class AISACClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def send_command(self, agent_id: str, action: str,
                     parameters: Dict[str, Any],
                     execution_id: str = None) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1/agents/{agent_id}/command"
        payload = {
            "action": action,
            "parameters": parameters,
            "execution_id": execution_id
        }

        response = requests.post(url, json=payload, headers=self.headers)
        response.raise_for_status()
        return response.json()

# Usage
client = AISACClient(
    base_url="https://command-server.aisac.local",
    token="your-api-token"
)

result = client.send_command(
    agent_id="agent-linux-001",
    action="block_ip",
    parameters={"ip_address": "192.168.1.100", "duration": 3600},
    execution_id="soar-exec-001"
)

print(f"Command sent: {result['command_id']}")
```

### Bash/curl Script Example

```bash
#!/bin/bash

API_BASE="https://command-server.aisac.local/api/v1"
TOKEN="your-api-token-here"

# Function to send command
send_command() {
    local agent_id="$1"
    local action="$2"
    local parameters="$3"

    curl -X POST "${API_BASE}/agents/${agent_id}/command" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"action\": \"${action}\",
            \"parameters\": ${parameters},
            \"execution_id\": \"script-$(date +%s)\"
        }"
}

# Block IP example
send_command "agent-linux-001" "block_ip" '{
    "ip_address": "192.168.1.100",
    "duration": 3600,
    "direction": "both"
}'
```

---

## Versioning

The API uses URL-based versioning: `/api/v1/...`

**Version History:**
- **v1.0.0** (Current): Initial release with core endpoints

**Deprecation Policy:**
- API versions are supported for minimum 12 months after deprecation notice
- Deprecated endpoints return `Deprecation` header
- Breaking changes require new version number

---

## Support and Contact

- **Documentation:** https://docs.aisac.local
- **GitHub Issues:** https://github.com/aisac/agent/issues
- **Security Issues:** security@aisac.local
- **Support:** support@aisac.local

---

**Generated:** 2025-12-04
**Version:** 1.0.0
**License:** Proprietary
