# AISAC Agent

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**AISAC Agent** is a versatile security agent written in Go that provides:

- **SOAR Response**: Execute incident response actions ordered by SOAR systems
- **SIEM Collection**: Collect and forward logs to the AISAC platform
- **Asset Monitoring**: Report agent health and system metrics via heartbeat

It can be deployed on endpoints and servers in multiple operating modes depending on your needs.

---

## Quick Install

### Linux (one command)

```bash
curl -sSL https://raw.githubusercontent.com/CISECSL/aisac-agent/main/scripts/quick-install.sh \
  -o /tmp/quick-install.sh && sudo bash /tmp/quick-install.sh
```

This downloads the latest release binary and launches the configuration wizard.

### From source (requires Go 1.21+)

```bash
git clone https://github.com/CISECSL/aisac-agent.git
cd aisac-agent
sudo ./scripts/install.sh
```

### Prerequisites

Before installing you need from the AISAC dashboard:
- **API Key** (`aisac_xxxx...`) — Dashboard > Assets > API Key
- **Asset ID** (UUID) — Dashboard > Assets > ID

> For the full step-by-step guide with all options, see **[docs/INSTALL.md](docs/INSTALL.md)**

---

## Table of Contents

- [Quick Install](#quick-install)
- [Overview](#overview)
- [Operating Modes](#operating-modes)
- [Architecture](#architecture)
- [Features](#features)
- [Configuration](#configuration)
  - [Agent Configuration](#agent-configuration)
  - [Heartbeat Configuration](#heartbeat-configuration)
  - [Collector Configuration](#collector-configuration)
  - [SOAR Configuration](#soar-configuration)
- [Supported Actions](#supported-actions)
- [REST API](#rest-api)
- [Communication Protocol](#communication-protocol)
- [Security Features](#security-features)
- [Platform Support](#platform-support)
- [Development](#development)
- [Testing](#testing)
- [Deployment](#deployment)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

AISAC Agent is part of a complete security operations platform. The agent runs on endpoints (Linux, Windows, macOS) and provides three main capabilities:

1. **SOAR Response Agent**: Connects to a central Command Server via WebSocket with mutual TLS authentication. When security incidents are detected by your SIEM/SOAR system, automated response actions are sent to agents for immediate execution.

2. **SIEM Log Collector**: Collects logs from various sources (Suricata, syslog, JSON files) and forwards them to the AISAC platform for analysis and correlation.

3. **Asset Health Monitor**: Reports agent status and system metrics (CPU, memory, disk) to the AISAC platform via heartbeat, enabling asset inventory and health monitoring.

**Key Benefits:**
- Automated incident response reduces MTTR (Mean Time To Respond)
- Centralized log collection for SIEM analysis
- Real-time asset health monitoring
- Secure communication with mTLS or API key authentication
- Cross-platform support (Linux, Windows, macOS)
- Extensible action framework
- Rate limiting and safety controls
- Audit logging for compliance

---

## Operating Modes

AISAC Agent supports flexible deployment configurations:

### Mode 1: Full SOAR Mode (Default)
The agent connects to a Command Server via WebSocket to receive and execute security actions.

```yaml
server:
  enabled: true
  url: "wss://command-server:8443/ws"
tls:
  enabled: true
  # mTLS certificates required
```

**Use case**: Endpoints requiring automated incident response capabilities.

### Mode 2: Heartbeat-Only Mode
The agent reports status to the AISAC platform without SOAR capabilities. No Command Server or mTLS certificates required.

```yaml
server:
  enabled: false

heartbeat:
  enabled: true
  url: "https://api.aisac.cisec.es/v1/heartbeat"
  api_key: "aisac_your_api_key_here"
  asset_id: "your-asset-uuid-here"
```

**Use case**: Asset monitoring without command execution, lightweight deployments.

### Mode 3: Collector Mode (SIEM)
The agent collects logs and forwards them to the AISAC platform.

```yaml
server:
  enabled: false

collector:
  enabled: true
  sources:
    - name: suricata
      type: file
      path: /var/log/suricata/eve.json
      parser: suricata_eve
  output:
    type: http
    url: "https://api.aisac.cisec.es/v1/logs"
    api_key: "aisac_your_api_key_here"
```

**Use case**: Log collection from IDS/IPS, firewalls, and system logs.

### Mode 4: Combined Mode
All features enabled together.

```yaml
server:
  enabled: true
  url: "wss://command-server:8443/ws"

heartbeat:
  enabled: true
  url: "https://api.aisac.cisec.es/v1/heartbeat"
  api_key: "aisac_your_api_key_here"
  asset_id: "your-asset-uuid-here"

collector:
  enabled: true
  # ... collector configuration
```

**Use case**: Full security operations with response, collection, and monitoring

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AISAC Platform                               │
│                (React + Supabase + Edge Functions)                  │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────┐ │
│  │ Asset Dashboard │  │  SIEM Analytics  │  │  Incident Response  │ │
│  └────────▲────────┘  └────────▲─────────┘  └──────────┬──────────┘ │
└───────────┼────────────────────┼───────────────────────┼────────────┘
            │ Heartbeat          │ Log Ingest            │ Webhook
            │ API                │ API                   ▼
            │                    │              ┌────────────────────┐
            │                    │              │  n8n Workflow      │
            │                    │              │  (Orchestration)   │
            │                    │              └─────────┬──────────┘
            │                    │                        │ REST API
            │                    │                        ▼
            │                    │              ┌────────────────────┐
            │                    │              │  Command Server    │
            │                    │              │  (WebSocket + API) │
            │                    │              └─────────┬──────────┘
            │                    │                        │ WebSocket + mTLS
            │                    │            ┌───────────┼───────────┐
            ▼                    ▼            ▼           ▼           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         AISAC Agent                                 │
│  ┌──────────────┐  ┌───────────────┐  ┌───────────────────────────┐ │
│  │   Heartbeat  │  │   Collector   │  │        Executor           │ │
│  │   (Status)   │  │    (SIEM)     │  │        (SOAR)             │ │
│  │              │  │               │  │                           │ │
│  │ • CPU/Mem    │  │ • Suricata    │  │ • Response:               │ │
│  │ • Disk       │  │ • Wazuh       │  │   block_ip, isolate_host  │ │
│  │ • Uptime     │  │ • Syslog      │  │ • Investigation:          │ │
│  │              │  │ • JSON logs   │  │   dns_lookup, check_hash  │ │
│  │              │  │ • Batching    │  │ • Forensics:              │ │
│  │              │  │               │  │   collect_forensics       │ │
│  └──────────────┘  └───────────────┘  └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Roles

- **AISAC Platform**: Web-based security operations platform with dashboards, analytics, and incident management
- **n8n Workflow Engine**: Orchestrates security workflows and triggers agent commands
- **Command Server**: Central hub for agent management and SOAR command dispatch
- **Agent - Heartbeat**: Reports agent health and system metrics to the platform
- **Agent - Collector**: Collects logs from various sources and forwards to the SIEM
- **Agent - Executor**: Executes security response actions (block IP, isolate host, etc.)

---

## Features

### SOAR Response
- **Real-time WebSocket Communication**: Persistent connections with automatic reconnection
- **Mutual TLS Authentication**: Secure agent-server authentication using mTLS
- **Action Framework**: Extensible system for implementing security actions
  - **Response Actions**: Block IP, isolate host, disable user, kill process
  - **Investigation Actions**: DNS lookup, hash reputation, IP reputation, IOC search
  - **Forensics Actions**: Collect forensic evidence, threat hunting
- **Rate Limiting**: Per-action rate limits to prevent accidental overload
- **Input Validation**: Strict validation of IP addresses, usernames, process names
- **Protected Resources**: Prevents actions on system-critical accounts and processes
- **SOAR Callbacks**: Optional webhook callbacks to external systems (n8n, SOAR platforms)
- **Platform Webhook**: Automatic agent registration when connecting to Command Server

### SIEM Collection
- **Multi-source Log Collection**: Suricata EVE, Wazuh alerts, syslog, generic JSON files
- **Smart Event Filtering**: Suricata parser filters telemetry, keeps security-relevant events
- **Efficient Batching**: Configurable batch size and flush intervals
- **Resume Support**: Sincedb tracking for position persistence across restarts
- **File Rotation Detection**: Automatically handles log rotation
- **HTTP Output**: Secure log forwarding to AISAC ingest API

### Asset Monitoring
- **Heartbeat Reporting**: Periodic status updates to AISAC platform
- **System Metrics**: CPU, memory, disk usage monitoring
- **Dynamic Intervals**: Server-controlled heartbeat frequency
- **API Key Authentication**: Simple and secure authentication

### General
- **Multiple Operating Modes**: SOAR, collector, heartbeat, or combined
- **Structured Logging**: JSON logging with zerolog
- **Cross-platform**: Native support for Linux, Windows, and macOS
- **Easy Installation**: One-command installer for Linux

---

## Supported Actions

### Response Actions

| Action | Description | Platforms | Status |
|--------|-------------|-----------|--------|
| `block_ip` | Block IP address in firewall | Linux (iptables/nftables), Windows Firewall, macOS (pf) | ✅ Stable |
| `unblock_ip` | Remove IP block from firewall | Linux (iptables/nftables), Windows Firewall, macOS (pf) | ✅ Stable |
| `isolate_host` | Isolate host from network | Linux, Windows, macOS | ✅ Stable |
| `unisolate_host` | Restore network connectivity | Linux, Windows, macOS | ✅ Stable |
| `disable_user` | Disable user account | Linux (usermod), Windows (net user/AD), macOS (dscl) | ✅ Stable |
| `enable_user` | Re-enable user account | Linux (usermod), Windows (net user/AD), macOS (dscl) | ✅ Stable |
| `kill_process` | Terminate process by name or PID | Linux, Windows, macOS | ✅ Stable |

### Investigation Actions

| Action | Description | Platforms | Status |
|--------|-------------|-----------|--------|
| `dns_lookup` | Perform DNS resolution lookup | All | ✅ Stable |
| `check_hash` | Check file hash reputation (VirusTotal, etc.) | All | ✅ Stable |
| `check_ip_reputation` | Check IP reputation against threat intelligence | All | ✅ Stable |
| `search_ioc` | Search for Indicators of Compromise on host | All | ✅ Stable |

### Forensics Actions

| Action | Description | Platforms | Status |
|--------|-------------|-----------|--------|
| `collect_forensics` | Collect forensic evidence (memory, disk artifacts) | All | ✅ Stable |
| `threat_hunt` | Search for threat indicators and suspicious activity | All | ✅ Stable |

### Action Examples

#### Block IP Address
```json
{
  "action": "block_ip",
  "parameters": {
    "ip_address": "192.168.1.100",
    "duration": 3600,
    "rule_name": "malicious_ip_block"
  }
}
```

#### Disable User Account
```json
{
  "action": "disable_user",
  "parameters": {
    "username": "compromised_user",
    "reason": "account_compromise"
  }
}
```

#### Kill Process
```json
{
  "action": "kill_process",
  "parameters": {
    "process_name": "malware.exe",
    "force": true
  }
}
```

#### DNS Lookup
```json
{
  "action": "dns_lookup",
  "parameters": {
    "hostname": "suspicious-domain.com",
    "record_type": "A"
  }
}
```

#### Check Hash Reputation
```json
{
  "action": "check_hash",
  "parameters": {
    "hash": "44d88612fea8a8f36de82e1278abb02f",
    "hash_type": "md5"
  }
}
```

#### Check IP Reputation
```json
{
  "action": "check_ip_reputation",
  "parameters": {
    "ip_address": "203.0.113.42"
  }
}
```

#### Search IOC
```json
{
  "action": "search_ioc",
  "parameters": {
    "ioc_type": "hash",
    "ioc_value": "44d88612fea8a8f36de82e1278abb02f",
    "search_paths": ["/var/log", "/tmp"]
  }
}
```

#### Collect Forensics
```json
{
  "action": "collect_forensics",
  "parameters": {
    "artifact_types": ["processes", "connections", "files"],
    "output_path": "/tmp/forensics"
  }
}
```

---

## Tech Stack

- **Language**: Go 1.21+
- **WebSocket**: [gorilla/websocket](https://github.com/gorilla/websocket)
- **HTTP Router**: [gorilla/mux](https://github.com/gorilla/mux)
- **Logging**: [zerolog](https://github.com/rs/zerolog)
- **CLI Framework**: [cobra](https://github.com/spf13/cobra)
- **Configuration**: YAML ([gopkg.in/yaml.v3](https://gopkg.in/yaml.v3))
- **Build Tool**: Makefile + [GoReleaser](https://goreleaser.com/)
- **TLS**: Go crypto/tls (mutual TLS)

---

## Build from Source

```bash
git clone https://github.com/CISECSL/aisac-agent.git
cd aisac-agent
make deps
make build
```

This creates:
- `build/aisac-agent` - Agent binary
- `build/aisac-server` - Command server binary

For detailed installation, configuration, and deployment instructions see **[docs/INSTALL.md](docs/INSTALL.md)**.

---

## Configuration

The agent is configured via YAML file (default: `/etc/aisac/agent.yaml`).

### Agent Configuration

```yaml
agent:
  # Agent ID (auto-generated if empty)
  id: ""
  # Labels for agent grouping/filtering
  labels:
    - production
    - webserver
  # Internal heartbeat interval (WebSocket ping)
  heartbeat_interval: 30s
  # Reconnection settings
  reconnect_delay: 5s
  max_reconnect_delay: 5m

logging:
  level: "info"      # debug, info, warn, error
  format: "json"     # json, text
  output: "stdout"   # stdout, file
  file: "/var/log/aisac/agent.log"
```

### Heartbeat Configuration

Report agent status and metrics to the AISAC platform:

```yaml
heartbeat:
  # Enable heartbeat reporting
  enabled: true
  # AISAC Platform heartbeat endpoint
  url: "https://api.aisac.cisec.es/v1/heartbeat"
  # API Key for authentication (format: aisac_xxxx...)
  # Get this from the AISAC Platform when registering the asset
  api_key: "aisac_your_api_key_here"
  # Asset ID (UUID from AISAC Platform)
  # This identifies the monitored asset in the platform
  asset_id: "your-asset-uuid-here"
  # Heartbeat interval (server can override via response)
  interval: 120s
  # Request timeout
  timeout: 10s
  # Skip TLS verification (NOT RECOMMENDED)
  skip_tls_verify: false
```

**Heartbeat Payload** (sent to server):
```json
{
  "asset_id": "uuid-here",
  "timestamp": "2024-12-04T12:34:56Z",
  "agent_version": "1.0.1",
  "metrics": {
    "cpu_percent": 45.2,
    "memory_percent": 68.5,
    "disk_percent": 55.0,
    "uptime_seconds": 86400
  }
}
```

### Collector Configuration

Collect and forward logs to the AISAC SIEM:

```yaml
collector:
  # Enable log collection
  enabled: true

  # Log sources to collect
  sources:
    # Suricata EVE JSON logs
    - name: suricata
      type: file
      path: /var/log/suricata/eve.json
      parser: suricata_eve
      tags:
        - security
        - ids

    # System syslog
    - name: syslog
      type: file
      path: /var/log/syslog
      parser: syslog
      tags:
        - system

    # Generic JSON logs
    - name: app_logs
      type: file
      path: /var/log/myapp/*.json
      parser: json
      tags:
        - application

  # Output configuration
  output:
    # Output type: http
    type: http
    # Ingest endpoint URL
    url: "https://api.aisac.cisec.es/v1/logs"
    # API Key for authentication
    api_key: "aisac_your_api_key_here"
    # Request timeout
    timeout: 30s
    # Number of retry attempts
    retry_attempts: 3
    # Delay between retries
    retry_delay: 5s

  # Batching configuration
  batch:
    # Number of events per batch
    size: 100
    # Maximum time before flushing (even if batch not full)
    interval: 5s

  # File reading configuration
  file:
    # Start position for new files: "end" or "beginning"
    start_position: end
    # Path to store file positions (for resume after restart)
    sincedb_path: /var/lib/aisac/sincedb.json
```

**Supported Parsers**:
| Parser | Description |
|--------|-------------|
| `suricata_eve` | Suricata EVE JSON format (filters telemetry, keeps security events) |
| `syslog` | RFC3164/RFC5424 syslog |
| `json` | Generic JSON logs |
| `wazuh` | Wazuh HIDS alerts JSON format |

**Note**: The Suricata parser automatically filters out telemetry events (flow, netflow, stats, dns, http, tls, etc.) and only processes security-relevant events (alert, anomaly, drop, pkthdr) to reduce volume and prevent event channel saturation.

### SOAR Configuration

Enable command execution from SOAR systems:

```yaml
server:
  # Enable SOAR functionality (receive commands from server)
  # Set to false to run in collector/heartbeat-only mode
  enabled: true
  # Command server WebSocket URL
  url: "wss://localhost:8443/ws"
  # Connection timeout
  connect_timeout: 30s
  write_timeout: 10s
  read_timeout: 60s

tls:
  # Enable mTLS (required when server.enabled is true)
  enabled: true
  cert_file: "/etc/aisac/certs/agent.crt"
  key_file: "/etc/aisac/certs/agent.key"
  ca_file: "/etc/aisac/certs/ca.crt"
  skip_verify: false

actions:
  # Only these actions will be executed
  enabled:
    # Response actions
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process
    # Investigation actions
    - dns_lookup
    - check_hash
    - check_ip_reputation
    - search_ioc
    # Forensics actions
    - collect_forensics
    - threat_hunt

  # Rate limits per action (prevent abuse)
  rate_limits:
    block_ip:
      max_per_minute: 10
      max_per_hour: 100
    isolate_host:
      max_per_minute: 1
      max_per_hour: 5

  default_timeout: 5m

# Optional: SOAR callback configuration
callback:
  enabled: false
  url: "https://n8n.example.com/webhook/aisac-callback"
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| **General** | | |
| `AISAC_AGENT_ID` | Agent unique identifier | `agent-prod-web01` |
| `AISAC_LOG_LEVEL` | Logging level | `info` |
| **SOAR Mode** | | |
| `AISAC_SERVER_URL` | WebSocket server URL | `wss://server:8443/ws` |
| `AISAC_CERT_FILE` | Agent certificate path | `/etc/aisac/certs/agent.crt` |
| `AISAC_KEY_FILE` | Agent private key path | `/etc/aisac/certs/agent.key` |
| `AISAC_CA_FILE` | CA certificate path | `/etc/aisac/certs/ca.crt` |
| **Heartbeat** | | |
| `AISAC_HEARTBEAT_API_KEY` | Heartbeat API key | `aisac_xxxx...` |
| `AISAC_HEARTBEAT_ASSET_ID` | Asset UUID from platform | `uuid-here` |
| **Collector** | | |
| `AISAC_COLLECTOR_API_KEY` | Collector API key | `aisac_xxxx...` |
| **Installer** | | |
| `AISAC_REGISTER_URL` | Override registration endpoint (staging) | `https://staging.api.aisac.cisec.es/v1/agent-webhook` |
| `AISAC_NONINTERACTIVE` | Run installer in non-interactive mode | `true` |

---

## REST API

The Command Server exposes a REST API for agent management and command execution.

### Authentication

All API endpoints (except `/health`) require Bearer token authentication:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  https://server:8443/api/v1/agents
```

### Endpoints

#### 1. Health Check
```http
GET /api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "agent_count": 5
}
```

#### 2. List All Agents
```http
GET /api/v1/agents
Authorization: Bearer YOUR_TOKEN
```

**Response:**
```json
[
  {
    "id": "agent-001",
    "hostname": "web-server-01",
    "platform": "linux",
    "arch": "amd64",
    "version": "1.0.0",
    "labels": ["production", "webserver"],
    "status": "connected",
    "last_seen": "2024-12-04T12:34:56Z"
  }
]
```

#### 3. Get Agent Details
```http
GET /api/v1/agents/{id}
Authorization: Bearer YOUR_TOKEN
```

**Response:**
```json
{
  "id": "agent-001",
  "hostname": "web-server-01",
  "platform": "linux",
  "arch": "amd64",
  "version": "1.0.0",
  "labels": ["production", "webserver"],
  "status": "connected",
  "last_seen": "2024-12-04T12:34:56Z"
}
```

#### 4. Send Command to Agent
```http
POST /api/v1/agents/{id}/command
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{
  "action": "block_ip",
  "parameters": {
    "ip_address": "192.168.1.100",
    "duration": 3600
  },
  "execution_id": "exec-soar-12345",
  "timeout_seconds": 30
}
```

**Response:**
```json
{
  "command_id": "cmd-1701692896123456789",
  "status": "sent"
}
```

### Example: Send Command via curl

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_SECURE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block_ip",
    "parameters": {
      "ip_address": "203.0.113.42",
      "duration": 7200,
      "rule_name": "block_malicious_ip"
    },
    "execution_id": "soar-exec-001",
    "timeout_seconds": 30
  }' \
  https://localhost:8443/api/v1/agents/agent-001/command
```

---

## Communication Protocol

### Message Types

#### Server → Agent
- `command` - Execute action
- `ping` - Connection health check
- `config_update` - Update agent configuration
- `cancel` - Cancel running command

#### Agent → Server
- `register` - Initial registration
- `response` - Action execution result
- `heartbeat` - Periodic status update
- `pong` - Ping response

### Command Message Format

```json
{
  "id": "cmd-1701692896123456789",
  "type": "command",
  "timestamp": "2024-12-04T12:34:56Z",
  "payload": {
    "id": "cmd-1701692896123456789",
    "action": "block_ip",
    "parameters": {
      "ip_address": "192.168.1.100",
      "duration": 3600
    },
    "execution_id": "exec-soar-12345",
    "timeout_seconds": 30,
    "priority": 1
  }
}
```

### Response Message Format

```json
{
  "id": "resp-1701692896987654321",
  "type": "response",
  "timestamp": "2024-12-04T12:35:02Z",
  "payload": {
    "id": "resp-1701692896987654321",
    "command_id": "cmd-1701692896123456789",
    "status": "success",
    "result": {
      "success": true,
      "message": "IP 192.168.1.100 blocked successfully",
      "details": {
        "rule_id": "aisac-block-192.168.1.100",
        "expiry": "2024-12-04T13:34:56Z"
      }
    },
    "execution_time_ms": 150
  }
}
```

---

## Security Features

### 1. Mutual TLS (mTLS) Authentication
- Both server and agents authenticate using X.509 certificates
- Prevents unauthorized agents from connecting
- Encrypts all communication

### 2. API Bearer Token Authentication
- REST API requires Bearer token for all non-health endpoints
- Token must be provided via `--api-token` flag
- Tokens should be randomly generated and securely stored

### 3. Input Validation
- IP addresses validated with CIDR notation support
- Usernames validated against allowed character sets
- Process names sanitized to prevent command injection

### 4. Protected System Resources
- System accounts (root, administrator, etc.) cannot be disabled
- Critical system processes cannot be killed
- Configurable protection lists

### 5. Rate Limiting
- Per-action rate limits (per minute and per hour)
- Prevents accidental or malicious overload
- Configurable limits per action type

### 6. Action Whitelist
- Only explicitly enabled actions can be executed
- Default-deny approach
- Per-agent action control

### 7. Audit Logging
- All actions logged with structured JSON
- Includes execution time, parameters, and results
- Suitable for SIEM integration

### 8. Timeout Protection
- Default and per-command timeouts
- Prevents hung operations
- Graceful cancellation support

---

## Platform Support

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| `block_ip` | iptables, nftables | Windows Firewall | PF (Packet Filter) |
| `unblock_ip` | iptables, nftables | Windows Firewall | PF (Packet Filter) |
| `isolate_host` | iptables | Windows Firewall | PF |
| `unisolate_host` | iptables | Windows Firewall | PF |
| `disable_user` | usermod | net user, AD | dscl |
| `enable_user` | usermod | net user, AD | dscl |
| `kill_process` | kill, pkill | taskkill | kill, pkill |

### Platform-Specific Notes

#### Linux
- Requires `root` or `sudo` privileges
- Supports both iptables and nftables
- Tested on Ubuntu 20.04+, RHEL 8+, Debian 11+

#### Windows
- Requires Administrator privileges
- Windows Firewall API integration
- Active Directory support for user management
- Tested on Windows Server 2016+, Windows 10+

#### macOS
- Requires `root` or `sudo` privileges
- Uses PF (Packet Filter) for firewall operations
- Directory Services integration
- Tested on macOS 11 (Big Sur)+

---

## Development

### Project Structure

```
aisac-agent/
├── cmd/
│   ├── agent/              # Agent entry point
│   └── server/             # Command server entry point
├── internal/
│   ├── agent/              # Agent core logic (lifecycle, connection)
│   ├── actions/            # SOAR action implementations
│   ├── callback/           # SOAR callback client
│   ├── collector/          # SIEM log collector
│   │   ├── collector.go    # Main collector component
│   │   ├── tailer.go       # File tailer with rotation
│   │   ├── parser*.go      # Log parsers (JSON, syslog, Suricata)
│   │   ├── output*.go      # Output destinations (HTTP)
│   │   ├── batcher.go      # Event batching
│   │   └── sincedb.go      # Position tracking
│   ├── config/             # Configuration management
│   ├── heartbeat/          # Platform heartbeat client
│   └── platform/           # Platform-specific code
│       ├── firewall_*.go   # Firewall operations
│       ├── user_*.go       # User management
│       └── process_*.go    # Process control
├── pkg/
│   ├── protocol/           # Communication protocol
│   └── types/              # Shared types
├── configs/                # Example configurations
├── scripts/
│   ├── install.sh          # Linux installer
│   └── gen-certs.sh        # Certificate generation
├── Makefile                # Build automation
└── go.mod
```

### Build Commands

```bash
# Build for current platform
make build

# Build agent only
make build-agent

# Build server only
make build-server

# Build for all platforms
make build-all

# Build for specific platforms
make build-linux
make build-windows
make build-darwin

# Cross-platform builds create:
# build/linux-amd64/
# build/linux-arm64/
# build/windows-amd64/
# build/darwin-amd64/
# build/darwin-arm64/
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run go vet
make vet

# Run all checks
make fmt lint vet test
```

---

## Testing

### Run All Tests

```bash
make test
```

### Run Tests with Coverage

```bash
make test-coverage
# Opens coverage.html in browser
```

### Run Specific Tests

```bash
# Test specific package
go test -v ./internal/actions

# Test specific function
go test -v ./internal/actions -run TestBlockIP

# Test with race detector
go test -v -race ./...
```

### Test Coverage Reports

```bash
make test-coverage
```

Generates:
- `coverage.out` - Coverage data
- `coverage.html` - HTML coverage report

---

## Deployment

### Linux Service (systemd)

Create `/etc/systemd/system/aisac-agent.service`:

```ini
[Unit]
Description=AISAC Security Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/aisac-agent --config /etc/aisac/agent.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable aisac-agent
sudo systemctl start aisac-agent
sudo systemctl status aisac-agent
```

### Windows Service

Use [NSSM](https://nssm.cc/) (Non-Sucking Service Manager):

```cmd
nssm install AISACAgent "C:\Program Files\AISAC\aisac-agent.exe"
nssm set AISACAgent AppParameters "--config C:\Program Files\AISAC\agent.yaml"
nssm set AISACAgent DisplayName "AISAC Security Agent"
nssm set AISACAgent Description "Automated security response agent"
nssm set AISACAgent Start SERVICE_AUTO_START
nssm start AISACAgent
```

### macOS Service (launchd)

Create `/Library/LaunchDaemons/com.aisac.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aisac.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/aisac-agent</string>
        <string>--config</string>
        <string>/etc/aisac/agent.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/aisac/agent.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/aisac/agent.log</string>
</dict>
</plist>
```

Load and start:
```bash
sudo launchctl load /Library/LaunchDaemons/com.aisac.agent.plist
sudo launchctl start com.aisac.agent
```

### Docker Deployment

Build Docker images:
```bash
make docker-build
```

Run server:
```bash
docker run -d \
  --name aisac-server \
  -p 8443:8443 \
  -v /path/to/certs:/certs \
  aisac-server:latest \
  --cert /certs/server.crt \
  --key /certs/server.key \
  --ca /certs/ca.crt \
  --api-token YOUR_TOKEN
```

Run agent:
```bash
docker run -d \
  --name aisac-agent \
  --privileged \
  -v /path/to/config:/etc/aisac \
  aisac-agent:latest \
  --config /etc/aisac/agent.yaml
```

**Note**: `--privileged` is required for firewall and system operations.

---

## Roadmap

### v1.0.0 (MVP) ✅
- [x] WebSocket connection with automatic reconnection
- [x] Basic actions: `block_ip`, `isolate_host`, `disable_user`, `kill_process`
- [x] YAML configuration
- [x] Structured logging (zerolog)
- [x] Cross-platform build

### v1.0.1 ✅
- [x] mTLS authentication
- [x] REST API with Bearer token auth
- [x] Unblock/unisolate/enable actions
- [x] Heartbeat reporting to AISAC platform
- [x] Log collector (SIEM functionality)
- [x] Multiple operating modes (SOAR, heartbeat-only, collector)
- [x] Linux installer script (`curl | bash`)
- [x] `server.enabled` flag for certificate-free deployments

### v1.1.0 (Current) ✅
- [x] Investigation actions: `dns_lookup`, `check_hash`, `check_ip_reputation`, `search_ioc`
- [x] Forensics actions: `collect_forensics`, `threat_hunt`
- [x] Wazuh log parser support
- [x] Suricata event type filtering (security events only)
- [x] Platform webhook for automatic agent registration
- [x] Command server URL population for SOAR dispatch
- [x] Enhanced debug logging for troubleshooting

### v1.2.0 (Planned) 🚧
- [ ] Prometheus metrics endpoint
- [ ] Agent auto-update mechanism
- [ ] Windows installer (MSI)
- [ ] Linux packages (deb, rpm)

### v1.3.0 (Future)
- [ ] OpenSearch output for collector
- [ ] EDR integration (CrowdStrike, SentinelOne)
- [ ] Custom action plugins
- [ ] Agent grouping and bulk operations
- [ ] Web UI for agent management
- [ ] Kubernetes operator

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Guidelines

- Follow Go best practices and idioms
- Write tests for new features
- Update documentation
- Run `make lint` and `make test` before submitting
- Use conventional commit messages

### Code Style

This project uses:
- `gofmt` for formatting
- `golangci-lint` for linting
- Go modules for dependency management

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [gorilla/websocket](https://github.com/gorilla/websocket) - WebSocket implementation
- [zerolog](https://github.com/rs/zerolog) - Fast structured logging
- [cobra](https://github.com/spf13/cobra) - CLI framework

---

## Support

For issues, questions, or contributions:
- **Issues**: [GitHub Issues](https://github.com/CISECSL/aisac-agent/issues)
- **Documentation**: [Wiki](https://github.com/CISECSL/aisac-agent/wiki)
- **Email**: support@aisac.io

---

## Related Projects

- **AISAC Platform**: Web-based security operations platform
  - Repository: `/Users/alvaromoralesmoreno/Desarrollo/aisac-39`
  - Supabase URL: `https://hsxtlxeqzmcggxwnxnol.supabase.co`

---

**Built with ❤️ for the security community**
