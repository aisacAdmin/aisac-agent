# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Description

**AISAC Agent** is a versatile security agent written in Go that provides:

1. **SOAR Response**: Execute incident response actions ordered by SOAR systems
2. **SIEM Collection**: Collect and forward logs to the AISAC platform
3. **Asset Monitoring**: Report agent health and system metrics via heartbeat

It supports multiple operating modes:
- **SOAR Mode**: Full incident response with mTLS authentication
- **Heartbeat-Only Mode**: Asset monitoring without command execution
- **Collector Mode**: Log collection and forwarding
- **Combined Mode**: All features enabled

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
            ▼                    ▼                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         AISAC Agent                                 │
│  ┌──────────────┐  ┌───────────────┐  ┌───────────────────────────┐ │
│  │   Heartbeat  │  │   Collector   │  │        Executor           │ │
│  │   (Status)   │  │    (SIEM)     │  │        (SOAR)             │ │
│  └──────────────┘  └───────────────┘  └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Tech Stack

- **Language:** Go 1.21+
- **Communication:** WebSocket (gorilla/websocket) + mTLS, HTTP REST
- **Config:** YAML + env vars
- **Logging:** zerolog
- **CLI:** cobra
- **Build:** Makefile + GoReleaser

## Project Structure

```
aisac-agent/
├── cmd/
│   ├── agent/              # Agent binary entry point
│   └── server/             # Command server entry point
├── internal/
│   ├── agent/              # Main agent logic (lifecycle, connection)
│   ├── actions/            # SOAR action modules (block_ip, isolate_host, etc.)
│   ├── callback/           # SOAR callback client
│   ├── collector/          # SIEM log collector
│   │   ├── collector.go    # Main collector component
│   │   ├── tailer.go       # File tailer with rotation detection
│   │   ├── parser*.go      # Log parsers (JSON, syslog, Suricata, Wazuh)
│   │   ├── output*.go      # Output destinations (HTTP)
│   │   ├── batcher.go      # Event batching
│   │   └── sincedb.go      # Position tracking
│   ├── config/             # Configuration loading
│   ├── heartbeat/          # Platform heartbeat client
│   └── platform/           # Platform-specific code (linux, windows, darwin)
├── pkg/
│   ├── protocol/           # Communication protocol (messages, commands)
│   └── types/              # Shared types
├── configs/                # Example configurations
├── scripts/
│   ├── install.sh          # Linux installer
│   └── gen-certs.sh        # Certificate generation
└── docs/                   # Documentation
```

## Development Commands

```bash
# Build
make build           # Compile binaries
make build-all       # Cross-platform build (Linux, Windows, macOS)

# Test
make test            # Run all tests
go test -v ./internal/actions -run TestBlockIP  # Run specific test
go test -v ./internal/collector/...             # Test collector

# Lint
make lint            # Run golangci-lint

# Run locally
make run-agent       # Run agent
make run-server      # Run command server

# Release
make docker-build    # Build Docker image
make release         # Create release with GoReleaser
```

## Key Configuration Options

### Operating Modes

```yaml
# SOAR Mode (requires mTLS certificates)
server:
  enabled: true
  url: "wss://server:8443/ws"

# Heartbeat-Only Mode (API key authentication)
server:
  enabled: false
heartbeat:
  enabled: true
  api_key: "aisac_xxx"
  asset_id: "uuid"

# Collector Mode (log forwarding)
collector:
  enabled: true
  output:
    api_key: "aisac_xxx"
```

## Communication Protocol

### Command Message (Server → Agent)
```json
{
  "id": "cmd-uuid-12345",
  "type": "execute_action",
  "action": "block_ip",
  "parameters": { "ip_address": "192.168.1.100", "duration": 3600 },
  "execution_id": "exec-uuid-from-soar",
  "timeout_seconds": 30
}
```

### Response Message (Agent → Server)
```json
{
  "id": "resp-uuid-67890",
  "command_id": "cmd-uuid-12345",
  "status": "success",
  "result": { "action": "ip_blocked", "details": {...} },
  "execution_time_ms": 150
}
```

### Heartbeat Payload (Agent → Platform)
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

## Implemented Actions

### Response Actions

| Action | Description | Platforms |
|--------|-------------|-----------|
| `block_ip` | Block IP in firewall | iptables, nftables, Windows Firewall, pf |
| `unblock_ip` | Unblock IP from firewall | iptables, nftables, Windows Firewall, pf |
| `isolate_host` | Isolate host from network | Linux, Windows, macOS |
| `unisolate_host` | Restore network connectivity | Linux, Windows, macOS |
| `disable_user` | Disable user account | Linux (usermod), Windows/AD (PowerShell), macOS (dscl) |
| `enable_user` | Enable user account | Linux, Windows, macOS |
| `kill_process` | Terminate process | Linux, Windows, macOS |

### Investigation Actions

| Action | Description | Platforms |
|--------|-------------|-----------|
| `dns_lookup` | Perform DNS resolution lookup | All |
| `check_hash` | Check file hash reputation (VirusTotal, etc.) | All |
| `check_ip_reputation` | Check IP reputation against threat intelligence | All |
| `search_ioc` | Search for Indicators of Compromise on host | All |

### Forensics Actions

| Action | Description | Platforms |
|--------|-------------|-----------|
| `collect_forensics` | Collect forensic evidence (memory, disk artifacts) | All |
| `threat_hunt` | Search for threat indicators and suspicious activity | All |

## Collector Parsers

| Parser | Description |
|--------|-------------|
| `suricata_eve` | Suricata EVE JSON format (filters telemetry, keeps security events) |
| `wazuh` | Wazuh HIDS alerts JSON format |
| `syslog` | RFC3164/RFC5424 syslog |
| `json` | Generic JSON logs |

**Note**: The Suricata parser filters out telemetry events (flow, netflow, stats, etc.) and only processes security-relevant events (alert, anomaly, drop, pkthdr).

## Security Model

- **mTLS Authentication:** Mutual TLS with private CA (SOAR mode)
- **API Key Authentication:** For heartbeat and collector (simpler modes)
- **Command Validation:** Only executes actions from `enabled` list in config
- **Rate Limiting:** Per-action rate limiting
- **Audit Logging:** All actions logged with zerolog

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AISAC_AGENT_ID` | Force a specific Agent ID (overrides persisted ID) |
| `AISAC_SERVER_URL` | Command server URL (SOAR mode) |
| `AISAC_CERT_FILE` | Path to agent certificate |
| `AISAC_KEY_FILE` | Path to private key |
| `AISAC_CA_FILE` | Path to CA certificate |
| `AISAC_LOG_LEVEL` | Log level (default: info) |
| `AISAC_HEARTBEAT_API_KEY` | Heartbeat API key |
| `AISAC_HEARTBEAT_ASSET_ID` | Asset UUID from platform |
| `AISAC_COLLECTOR_API_KEY` | Collector API key |
| `AISAC_CS_TOKEN` | Command Server API token (for SOAR) |
| `AISAC_CS_URL` | Command Server public URL (for SOAR) |
| `AISAC_REGISTER_URL` | Override registration endpoint (for staging) |
