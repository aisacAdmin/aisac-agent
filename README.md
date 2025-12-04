# AISAC Agent

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**AISAC Agent** is an automated security response agent written in Go that executes incident response actions ordered by SOAR (Security Orchestration, Automation, and Response) systems. It is deployed on endpoints and servers to execute security playbooks in real-time.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Supported Actions](#supported-actions)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Generate Certificates](#generate-certificates)
  - [Run the Server](#run-the-server)
  - [Run the Agent](#run-the-agent)
- [Configuration](#configuration)
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

AISAC Agent is part of a complete incident response automation platform. The agent runs on endpoints (Linux, Windows, macOS) and connects to a central Command Server via WebSocket with mutual TLS authentication. When security incidents are detected by your SIEM/SOAR system, automated response actions are sent to agents for immediate execution.

**Key Benefits:**
- Automated incident response reduces MTTR (Mean Time To Respond)
- Centralized command and control via REST API
- Secure communication with mTLS authentication
- Cross-platform support (Linux, Windows, macOS)
- Extensible action framework
- Rate limiting and safety controls
- Audit logging for compliance

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AISAC Platform                            │
│              (React + Supabase + Edge Functions)             │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS POST (webhook)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   n8n Workflow Engine                        │
│              (Orchestration & Automation)                    │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS/REST API
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              AISAC Command Server                            │
│          (REST API + WebSocket Server)                       │
│  • Agent Management                                          │
│  • Command Dispatch                                          │
│  • Bearer Token Authentication                               │
└────────────────────────┬────────────────────────────────────┘
                         │ WebSocket + mTLS
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    ┌────────┐      ┌────────┐      ┌────────┐
    │ Agent  │      │ Agent  │      │ Agent  │
    │(Linux) │      │(Windows)│      │(macOS) │
    └────────┘      └────────┘      └────────┘
```

### Component Roles

- **AISAC Platform**: Web-based security operations platform
- **n8n Workflow Engine**: Orchestrates security workflows and triggers agent commands
- **Command Server**: Central hub for agent management and command dispatch
- **Agents**: Deployed on endpoints to execute security actions

---

## Features

- **Real-time WebSocket Communication**: Persistent connections with automatic reconnection
- **Mutual TLS Authentication**: Secure agent-server authentication using mTLS
- **Action Framework**: Extensible system for implementing security actions
- **Rate Limiting**: Per-action rate limits to prevent accidental overload
- **Input Validation**: Strict validation of IP addresses, usernames, process names
- **Protected Resources**: Prevents actions on system-critical accounts and processes
- **Heartbeat Monitoring**: Automatic agent health checks
- **SOAR Callbacks**: Optional webhook callbacks to external systems (n8n, SOAR platforms)
- **Structured Logging**: JSON logging with zerolog
- **Cross-platform**: Native support for Linux, Windows, and macOS

---

## Supported Actions

| Action | Description | Platforms | Status |
|--------|-------------|-----------|--------|
| `block_ip` | Block IP address in firewall | Linux (iptables/nftables), Windows Firewall, macOS (pf) | ✅ Stable |
| `unblock_ip` | Remove IP block from firewall | Linux (iptables/nftables), Windows Firewall, macOS (pf) | ✅ Stable |
| `isolate_host` | Isolate host from network | Linux, Windows, macOS | ✅ Stable |
| `unisolate_host` | Restore network connectivity | Linux, Windows, macOS | ✅ Stable |
| `disable_user` | Disable user account | Linux (usermod), Windows (net user/AD), macOS (dscl) | ✅ Stable |
| `enable_user` | Re-enable user account | Linux (usermod), Windows (net user/AD), macOS (dscl) | ✅ Stable |
| `kill_process` | Terminate process by name or PID | Linux, Windows, macOS | ✅ Stable |
| `collect_forensics` | Collect forensic evidence | All | 🚧 Planned |
| `threat_hunt` | Search for IOCs (Indicators of Compromise) | All | 🚧 Planned |

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

## Quick Start

### Prerequisites

- Go 1.21 or higher
- OpenSSL (for certificate generation)
- Root/Administrator privileges (for running agents)
- Linux, Windows, or macOS

### Installation

#### Clone the Repository
```bash
git clone https://github.com/cisec/aisac-agent.git
cd aisac-agent
```

#### Download Dependencies
```bash
make deps
```

#### Build Binaries
```bash
make build
```

This creates:
- `build/aisac-agent` - Agent binary
- `build/aisac-server` - Command server binary

### Generate Certificates

For development and testing, generate self-signed certificates:

```bash
make gen-certs
# or
./scripts/gen-certs.sh
```

This generates:
- `certs/ca.crt` - Certificate Authority
- `certs/ca.key` - CA private key
- `certs/server.crt` - Server certificate
- `certs/server.key` - Server private key
- `certs/agent.crt` - Agent certificate
- `certs/agent.key` - Agent private key

**Production Note**: For production deployments, use certificates from a trusted CA or your organization's PKI.

### Run the Server

```bash
./build/aisac-server \
  --listen :8443 \
  --cert certs/server.crt \
  --key certs/server.key \
  --ca certs/ca.crt \
  --api-token YOUR_SECURE_TOKEN_HERE \
  --log-level info
```

**Important**: Replace `YOUR_SECURE_TOKEN_HERE` with a strong, randomly-generated token. This token is required for REST API authentication.

### Run the Agent

1. **Edit Configuration** (optional):
```bash
cp configs/agent.yaml /etc/aisac/agent.yaml
# Edit /etc/aisac/agent.yaml with your settings
```

2. **Start Agent**:
```bash
sudo ./build/aisac-agent --config /etc/aisac/agent.yaml
```

Or using environment variables:
```bash
export AISAC_SERVER_URL="wss://your-server:8443/ws"
export AISAC_CERT_FILE="/etc/aisac/certs/agent.crt"
export AISAC_KEY_FILE="/etc/aisac/certs/agent.key"
export AISAC_CA_FILE="/etc/aisac/certs/ca.crt"
export AISAC_LOG_LEVEL="info"

sudo ./build/aisac-agent
```

---

## Configuration

### Agent Configuration (`agent.yaml`)

```yaml
agent:
  # Agent ID (auto-generated if empty)
  id: ""
  # Labels for agent grouping/filtering
  labels:
    - production
    - webserver
  # Heartbeat interval
  heartbeat_interval: 30s
  # Reconnection settings
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  # Command server WebSocket URL
  url: "wss://localhost:8443/ws"
  connect_timeout: 30s
  write_timeout: 10s
  read_timeout: 60s

tls:
  enabled: true
  cert_file: "/etc/aisac/certs/agent.crt"
  key_file: "/etc/aisac/certs/agent.key"
  ca_file: "/etc/aisac/certs/ca.crt"
  skip_verify: false  # NOT RECOMMENDED for production

actions:
  # Only these actions will be executed
  enabled:
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process

  # Rate limits per action (prevent abuse)
  rate_limits:
    block_ip:
      max_per_minute: 10
      max_per_hour: 100
    isolate_host:
      max_per_minute: 1
      max_per_hour: 5
    disable_user:
      max_per_minute: 5
      max_per_hour: 50

  default_timeout: 5m

# Optional: SOAR callback configuration
callback:
  enabled: false
  url: "https://n8n.example.com/webhook/aisac-callback"
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s
  skip_tls_verify: false

logging:
  level: "info"      # debug, info, warn, error
  format: "json"     # json, text
  output: "stdout"   # stdout, file
  file: "/var/log/aisac/agent.log"
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AISAC_AGENT_ID` | Agent unique identifier | `agent-prod-web01` |
| `AISAC_SERVER_URL` | WebSocket server URL | `wss://server.example.com:8443/ws` |
| `AISAC_CERT_FILE` | Agent certificate path | `/etc/aisac/certs/agent.crt` |
| `AISAC_KEY_FILE` | Agent private key path | `/etc/aisac/certs/agent.key` |
| `AISAC_CA_FILE` | CA certificate path | `/etc/aisac/certs/ca.crt` |
| `AISAC_LOG_LEVEL` | Logging level | `info` |

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
│   ├── agent/              # Agent core logic
│   ├── actions/            # Action implementations
│   ├── callback/           # SOAR callback client
│   ├── config/             # Configuration management
│   └── platform/           # Platform-specific code
│       ├── firewall_linux.go
│       ├── firewall_windows.go
│       ├── firewall_darwin.go
│       ├── user_linux.go
│       ├── user_windows.go
│       ├── user_darwin.go
│       ├── process_unix.go
│       └── process_windows.go
├── pkg/
│   ├── protocol/           # Communication protocol
│   └── types/              # Shared types
├── configs/                # Example configurations
├── scripts/                # Utility scripts
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

### v1.1.0 (Current) 🚧
- [x] mTLS authentication
- [x] REST API with Bearer token auth
- [x] Unblock/unisolate/enable actions
- [ ] Linux installer (deb, rpm)
- [ ] Windows installer (MSI)

### v1.2.0 (Planned)
- [ ] Action: `collect_forensics` (memory dump, disk artifacts)
- [ ] Action: `threat_hunt` (IOC search)
- [ ] Prometheus metrics endpoint
- [ ] Agent auto-update mechanism
- [ ] Enhanced callback system (retry, circuit breaker)

### v1.3.0 (Future)
- [ ] Wazuh agent integration
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
- **Issues**: [GitHub Issues](https://github.com/cisec/aisac-agent/issues)
- **Documentation**: [Wiki](https://github.com/cisec/aisac-agent/wiki)
- **Email**: support@aisac.io

---

## Related Projects

- **AISAC Platform**: Web-based security operations platform
  - Repository: `/Users/alvaromoralesmoreno/Desarrollo/aisac-39`
  - Supabase URL: `https://hsxtlxeqzmcggxwnxnol.supabase.co`

---

**Built with ❤️ for the security community**
