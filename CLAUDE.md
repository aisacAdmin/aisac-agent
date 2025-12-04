# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Description

**AISAC Agent** is an automated response agent written in Go that executes security actions ordered by the AISAC SOAR system. It is deployed on endpoints and servers to execute incident response playbooks.

## Architecture

```
AISAC Platform (React + Supabase + Edge Functions)
              │
              ▼ HTTPS POST (webhook)
       n8n Workflow Engine
              │
              ▼ HTTPS/gRPC
      AISAC Command Server
       (REST API + WebSocket)
              │
              ▼ WebSocket + mTLS
    ┌─────────┼─────────┐
    ▼         ▼         ▼
  Agent     Agent     Agent
 (Linux)  (Windows) (Firewall)
```

## Tech Stack

- **Language:** Go 1.21+
- **Communication:** WebSocket (gorilla/websocket) + mTLS
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
│   ├── agent/              # Main agent logic (lifecycle, connection, heartbeat)
│   ├── actions/            # Action modules (block_ip, isolate_host, etc.)
│   ├── config/             # Configuration loading
│   ├── crypto/             # mTLS certificates
│   └── platform/           # Platform-specific code (linux, windows, firewall/)
├── pkg/
│   ├── protocol/           # Communication protocol (messages, commands)
│   └── types/              # Shared types
├── configs/                # Example configurations
└── scripts/                # Install scripts, cert generation
```

## Development Commands

```bash
# Build
make build           # Compile binaries
make build-all       # Cross-platform build (Linux, Windows, macOS)

# Test
make test            # Run all tests
go test -v ./internal/actions -run TestBlockIP  # Run specific test

# Lint
make lint            # Run golangci-lint

# Run locally
make run-agent       # Run agent
make run-server      # Run command server

# Release
make docker-build    # Build Docker image
make release         # Create release with GoReleaser
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

## Implemented Actions

| Action | Description | Platforms |
|--------|-------------|-----------|
| `block_ip` | Block IP in firewall | iptables, nftables, Windows Firewall, pfSense, Palo Alto |
| `isolate_host` | Isolate host from network | Linux, Windows |
| `disable_user` | Disable user account | Linux (usermod), Windows/AD (PowerShell) |
| `collect_forensics` | Collect forensic evidence | All |
| `threat_hunt` | Search for IOCs | All |

## Security Model

- **mTLS Authentication:** Mutual TLS with private CA
- **Command Validation:** Only executes actions from `enabled` list in config
- **Rate Limiting:** Per-action rate limiting
- **Audit Logging:** All actions logged with zerolog

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AISAC_AGENT_ID` | Agent ID (auto-generated if empty) |
| `AISAC_SERVER_URL` | Command server URL |
| `AISAC_CERT_FILE` | Path to agent certificate |
| `AISAC_KEY_FILE` | Path to private key |
| `AISAC_CA_FILE` | Path to CA certificate |
| `AISAC_LOG_LEVEL` | Log level (default: info) |
