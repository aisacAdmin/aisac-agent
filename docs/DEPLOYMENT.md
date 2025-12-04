# AISAC Agent - Deployment Guide

This guide covers the complete deployment process for the AISAC Agent system, including building from source, certificate setup, server and agent deployment, SOAR integration, and security hardening.

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Building from Source](#2-building-from-source)
3. [Certificate Setup](#3-certificate-setup)
4. [Server Deployment](#4-server-deployment)
5. [Agent Deployment](#5-agent-deployment)
6. [SOAR Integration](#6-soar-integration)
7. [Security Hardening](#7-security-hardening)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

### Required Software

- **Go 1.21+**: Required for building from source
- **OpenSSL**: Required for certificate generation
- **Make**: For using the provided Makefile
- **Git**: For cloning the repository

### Platform-Specific Requirements

#### Linux
- **iptables** or **nftables**: For firewall management (block_ip action)
- **systemd**: For service management (recommended)
- **Root or sudo access**: Required for most security actions

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential openssl iptables systemd

# RHEL/CentOS/Fedora
sudo dnf install -y gcc make openssl iptables systemd

# Verify Go installation
go version  # Should be 1.21 or higher
```

#### Windows
- **Windows Firewall**: Built-in, used for block_ip action
- **PowerShell 5.1+**: For Active Directory user management
- **NSSM** (optional): For service installation

```powershell
# Verify PowerShell version
$PSVersionTable.PSVersion
```

#### macOS (Development Only)
```bash
# Install build tools
xcode-select --install

# Install OpenSSL
brew install openssl
```

### Network Requirements

- **Port 8443** (default): WebSocket connections from agents to server
- **Outbound HTTPS**: Agents need to reach the command server
- **Optional**: Ports for n8n webhook callbacks (typically 443)

---

## 2. Building from Source

### Clone the Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/aisac-agent.git
cd aisac-agent

# Install dependencies
make deps
```

### Build for Current Platform

```bash
# Build both agent and server for current platform
make build

# Or build individually
make build-agent
make build-server

# Binaries will be in ./build/
ls -la build/
```

### Cross-Platform Build

Build for all supported platforms:

```bash
# Build for Linux, Windows, and macOS
make build-all

# Output structure:
# build/
# ├── linux-amd64/
# │   ├── aisac-agent
# │   └── aisac-server
# ├── linux-arm64/
# │   ├── aisac-agent
# │   └── aisac-server
# ├── windows-amd64/
# │   ├── aisac-agent.exe
# │   └── aisac-server.exe
# ├── darwin-amd64/
# │   ├── aisac-agent
# │   └── aisac-server
# └── darwin-arm64/
#     ├── aisac-agent
#     └── aisac-server
```

### Build Specific Platforms

```bash
# Linux only
make build-linux

# Windows only
make build-windows

# macOS only
make build-darwin
```

### Build with Version Information

```bash
# Build with git version info
VERSION=$(git describe --tags --always) make build

# Build production release with GoReleaser
make release
```

### Docker Build (Optional)

```bash
# Build Docker images
make docker-build

# This creates:
# - aisac-agent:VERSION
# - aisac-server:VERSION
```

---

## 3. Certificate Setup

AISAC uses mutual TLS (mTLS) for secure agent-server communication. You need to generate a Certificate Authority (CA) and certificates for both the server and agents.

### Quick Setup with Provided Script

```bash
# Generate all certificates in ./certs directory
./scripts/gen-certs.sh

# Or specify custom directory
./scripts/gen-certs.sh /etc/aisac/certs
```

This script generates:
- `ca.crt` - CA certificate (distribute to all agents and server)
- `ca.key` - CA private key (keep secure, never distribute)
- `server.crt` - Server certificate
- `server.key` - Server private key
- `agent.crt` - Agent certificate
- `agent.key` - Agent private key

### Manual CA Creation

For production environments, you may want to create certificates manually:

#### Step 1: Generate CA Private Key

```bash
# Create certificate directory
mkdir -p /etc/aisac/certs
cd /etc/aisac/certs

# Generate 4096-bit CA private key
openssl genrsa -out ca.key 4096

# Set secure permissions
chmod 600 ca.key
```

#### Step 2: Generate CA Certificate

```bash
# Create CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Security/CN=AISAC CA"

chmod 644 ca.crt
```

#### Step 3: Generate Server Certificate

```bash
# Generate server private key
openssl genrsa -out server.key 2048

# Create server certificate signing request (CSR)
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Security/CN=aisac-server.example.com"

# Create server certificate extensions
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = aisac-server.example.com
DNS.2 = localhost
IP.1 = 10.0.1.100
IP.2 = 127.0.0.1
EOF

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile server.ext

# Set permissions
chmod 600 server.key
chmod 644 server.crt

# Clean up
rm server.csr server.ext
```

#### Step 4: Generate Agent Certificate

```bash
# Generate agent private key
openssl genrsa -out agent.key 2048

# Create agent CSR
openssl req -new -key agent.key -out agent.csr \
  -subj "/C=US/ST=State/L=City/O=YourOrg/OU=Security/CN=aisac-agent"

# Create agent certificate extensions
cat > agent.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign agent certificate with CA
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out agent.crt -days 365 \
  -extfile agent.ext

# Set permissions
chmod 600 agent.key
chmod 644 agent.crt

# Clean up
rm agent.csr agent.ext ca.srl
```

### Verify Certificates

```bash
# Verify server certificate
openssl verify -CAfile ca.crt server.crt

# Verify agent certificate
openssl verify -CAfile ca.crt agent.crt

# Check certificate details
openssl x509 -in server.crt -text -noout
openssl x509 -in agent.crt -text -noout
```

### Certificate Distribution

1. **Server needs**:
   - `ca.crt` (to verify agent certificates)
   - `server.crt` (server certificate)
   - `server.key` (server private key)

2. **Each agent needs**:
   - `ca.crt` (to verify server certificate)
   - `agent.crt` (agent certificate)
   - `agent.key` (agent private key)

3. **Secure distribution**:
   ```bash
   # Copy certificates to agents securely
   scp ca.crt agent.crt agent.key user@agent-host:/etc/aisac/certs/

   # Set correct permissions on agent
   ssh user@agent-host 'chmod 600 /etc/aisac/certs/agent.key'
   ssh user@agent-host 'chmod 644 /etc/aisac/certs/*.crt'
   ```

---

## 4. Server Deployment

### Command Line Options

```bash
aisac-server --help

Flags:
  -a, --listen string           Listen address (default ":8443")
      --cert string             TLS certificate file
      --key string              TLS key file
      --ca string               CA certificate for client auth
  -l, --log-level string        Log level: debug, info, warn, error (default "info")
      --api-token string        API bearer token for REST API authentication (required)
      --allowed-origins string  Comma-separated list of allowed WebSocket origins
  -h, --help                    Help for aisac-server
  -v, --version                 Version information
```

### Manual Server Start

```bash
# Basic start (development, no TLS)
./aisac-server -a :8443 --api-token "your-secret-token-here"

# Production start with mTLS
./aisac-server \
  -a :8443 \
  --cert /etc/aisac/certs/server.crt \
  --key /etc/aisac/certs/server.key \
  --ca /etc/aisac/certs/ca.crt \
  --api-token "your-secret-token-here" \
  --log-level info
```

### Systemd Service Deployment (Linux)

#### Step 1: Install Binary

```bash
# Copy binary to system location
sudo cp build/linux-amd64/aisac-server /usr/local/bin/
sudo chmod +x /usr/local/bin/aisac-server
```

#### Step 2: Create Service User

```bash
# Create dedicated user (no login shell)
sudo useradd -r -s /bin/false aisac-server
```

#### Step 3: Setup Directories and Permissions

```bash
# Create directories
sudo mkdir -p /etc/aisac/certs
sudo mkdir -p /var/log/aisac

# Copy certificates
sudo cp certs/ca.crt certs/server.crt certs/server.key /etc/aisac/certs/

# Set ownership and permissions
sudo chown -R aisac-server:aisac-server /etc/aisac
sudo chown -R aisac-server:aisac-server /var/log/aisac
sudo chmod 700 /etc/aisac/certs
sudo chmod 600 /etc/aisac/certs/*.key
sudo chmod 644 /etc/aisac/certs/*.crt
```

#### Step 4: Create Systemd Service File

```bash
sudo nano /etc/systemd/system/aisac-server.service
```

```ini
[Unit]
Description=AISAC Command Server
Documentation=https://github.com/yourusername/aisac-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aisac-server
Group=aisac-server
ExecStart=/usr/local/bin/aisac-server \
  -a :8443 \
  --cert /etc/aisac/certs/server.crt \
  --key /etc/aisac/certs/server.key \
  --ca /etc/aisac/certs/ca.crt \
  --api-token "${API_TOKEN}" \
  --log-level info

# Environment variables
Environment="API_TOKEN=your-secret-token-here"

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/aisac

# Restart configuration
Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aisac-server

[Install]
WantedBy=multi-user.target
```

#### Step 5: Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable aisac-server

# Start service
sudo systemctl start aisac-server

# Check status
sudo systemctl status aisac-server

# View logs
sudo journalctl -u aisac-server -f
```

### Docker Deployment

#### Step 1: Create Dockerfile (if not exists)

```dockerfile
# Dockerfile.server
FROM golang:1.21-alpine AS builder

WORKDIR /build
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o aisac-server ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /build/aisac-server .

# Create directory for certificates
RUN mkdir -p /etc/aisac/certs

EXPOSE 8443

ENTRYPOINT ["/app/aisac-server"]
```

#### Step 2: Build and Run

```bash
# Build image
docker build -t aisac-server:latest -f Dockerfile.server .

# Create volume for certificates
docker volume create aisac-certs

# Copy certificates to volume
docker run --rm -v aisac-certs:/certs -v $(pwd)/certs:/source alpine \
  sh -c "cp /source/ca.crt /source/server.crt /source/server.key /certs/"

# Run container
docker run -d \
  --name aisac-server \
  -p 8443:8443 \
  -v aisac-certs:/etc/aisac/certs:ro \
  -e API_TOKEN=your-secret-token-here \
  aisac-server:latest \
  -a :8443 \
  --cert /etc/aisac/certs/server.crt \
  --key /etc/aisac/certs/server.key \
  --ca /etc/aisac/certs/ca.crt \
  --api-token "${API_TOKEN}" \
  --log-level info

# View logs
docker logs -f aisac-server
```

#### Step 3: Docker Compose (Optional)

```yaml
# docker-compose.yml
version: '3.8'

services:
  aisac-server:
    image: aisac-server:latest
    container_name: aisac-server
    ports:
      - "8443:8443"
    volumes:
      - aisac-certs:/etc/aisac/certs:ro
    environment:
      - API_TOKEN=${API_TOKEN}
    command: >
      -a :8443
      --cert /etc/aisac/certs/server.crt
      --key /etc/aisac/certs/server.key
      --ca /etc/aisac/certs/ca.crt
      --api-token "${API_TOKEN}"
      --log-level info
    restart: unless-stopped
    networks:
      - aisac-net

volumes:
  aisac-certs:
    external: true

networks:
  aisac-net:
    driver: bridge
```

```bash
# Start with docker-compose
export API_TOKEN=your-secret-token-here
docker-compose up -d

# View logs
docker-compose logs -f
```

### Verify Server Deployment

```bash
# Test health endpoint
curl -k https://localhost:8443/api/v1/health

# Expected response:
# {"status":"healthy","version":"dev","agent_count":0}

# Test API authentication
curl -k -H "Authorization: Bearer your-secret-token-here" \
  https://localhost:8443/api/v1/agents

# Expected response:
# []
```

---

## 5. Agent Deployment

### Configuration File

Create or edit `/etc/aisac/agent.yaml`:

```yaml
# AISAC Agent Configuration

agent:
  # Agent ID (auto-generated if empty)
  id: ""
  # Labels for agent grouping/filtering
  labels:
    - production
    - webserver
  # Heartbeat interval
  heartbeat_interval: 30s
  # Initial reconnect delay
  reconnect_delay: 5s
  # Maximum reconnect delay
  max_reconnect_delay: 5m

server:
  # Command server WebSocket URL
  url: "wss://aisac-server.example.com:8443/ws"
  # Connection timeout
  connect_timeout: 30s
  # Write timeout
  write_timeout: 10s
  # Read timeout
  read_timeout: 60s

tls:
  # Enable mTLS
  enabled: true
  # Agent certificate
  cert_file: "/etc/aisac/certs/agent.crt"
  # Agent private key
  key_file: "/etc/aisac/certs/agent.key"
  # CA certificate
  ca_file: "/etc/aisac/certs/ca.crt"
  # Skip certificate verification (NOT RECOMMENDED)
  skip_verify: false

actions:
  # Enabled actions (only these will be executed)
  enabled:
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process

  # Rate limits per action
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

  # Default action timeout
  default_timeout: 5m

# SOAR/n8n callback configuration
callback:
  # Enable callbacks to SOAR
  enabled: true
  # Webhook URL (n8n, SOAR platform, etc.)
  url: "https://n8n.example.com/webhook/aisac-callback"
  # Bearer token for authentication
  auth_token: "your-webhook-token"
  # Request timeout
  timeout: 30s
  # Number of retry attempts on failure
  retry_attempts: 3
  # Delay between retries
  retry_delay: 5s
  # Skip TLS verification (NOT RECOMMENDED)
  skip_tls_verify: false

logging:
  # Log level: debug, info, warn, error
  level: "info"
  # Log format: json, text
  format: "json"
  # Output: stdout, file
  output: "file"
  # Log file path (when output is "file")
  file: "/var/log/aisac/agent.log"
```

### Environment Variables

You can override configuration values with environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `AISAC_AGENT_ID` | Agent ID | `agent-web-01` |
| `AISAC_SERVER_URL` | Command server URL | `wss://server:8443/ws` |
| `AISAC_CERT_FILE` | Agent certificate path | `/etc/aisac/certs/agent.crt` |
| `AISAC_KEY_FILE` | Agent private key path | `/etc/aisac/certs/agent.key` |
| `AISAC_CA_FILE` | CA certificate path | `/etc/aisac/certs/ca.crt` |
| `AISAC_LOG_LEVEL` | Log level | `info`, `debug`, `warn`, `error` |

### Linux Deployment (systemd)

#### Step 1: Install Binary

```bash
# Copy binary to system location
sudo cp build/linux-amd64/aisac-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/aisac-agent
```

#### Step 2: Create Service User

```bash
# Create dedicated user (no login shell)
sudo useradd -r -s /bin/false aisac-agent
```

#### Step 3: Setup Directories and Permissions

```bash
# Create directories
sudo mkdir -p /etc/aisac/certs
sudo mkdir -p /var/log/aisac

# Copy configuration and certificates
sudo cp configs/agent.yaml /etc/aisac/
sudo cp certs/ca.crt certs/agent.crt certs/agent.key /etc/aisac/certs/

# Edit configuration
sudo nano /etc/aisac/agent.yaml
# Update server URL and other settings

# Set ownership and permissions
sudo chown -R root:root /etc/aisac
sudo chown -R aisac-agent:aisac-agent /var/log/aisac
sudo chmod 700 /etc/aisac/certs
sudo chmod 600 /etc/aisac/certs/*.key
sudo chmod 644 /etc/aisac/certs/*.crt
sudo chmod 644 /etc/aisac/agent.yaml
```

#### Step 4: Grant Required Capabilities

The agent needs elevated privileges for security actions:

```bash
# Option 1: Grant specific capabilities (recommended)
sudo setcap cap_net_admin,cap_sys_admin+ep /usr/local/bin/aisac-agent

# Option 2: Run as root (less secure)
# See systemd service file below
```

#### Step 5: Create Systemd Service File

```bash
sudo nano /etc/systemd/system/aisac-agent.service
```

```ini
[Unit]
Description=AISAC Security Response Agent
Documentation=https://github.com/yourusername/aisac-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Run as root (required for iptables, user management, etc.)
User=root
Group=root
ExecStart=/usr/local/bin/aisac-agent -c /etc/aisac/agent.yaml

# Security hardening (adjust based on actions needed)
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=false
ProtectHome=true

# Restart configuration
Restart=on-failure
RestartSec=10s
StartLimitInterval=60s
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aisac-agent

[Install]
WantedBy=multi-user.target
```

#### Step 6: Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable aisac-agent

# Start service
sudo systemctl start aisac-agent

# Check status
sudo systemctl status aisac-agent

# View logs
sudo journalctl -u aisac-agent -f
```

### Windows Deployment

#### Step 1: Install Binary

```powershell
# Create installation directory
New-Item -Path "C:\Program Files\AISAC" -ItemType Directory -Force

# Copy binary
Copy-Item "build\windows-amd64\aisac-agent.exe" -Destination "C:\Program Files\AISAC\"
```

#### Step 2: Setup Configuration

```powershell
# Create configuration directory
New-Item -Path "C:\ProgramData\AISAC\certs" -ItemType Directory -Force

# Copy configuration and certificates
Copy-Item "configs\agent.yaml" -Destination "C:\ProgramData\AISAC\"
Copy-Item "certs\ca.crt" -Destination "C:\ProgramData\AISAC\certs\"
Copy-Item "certs\agent.crt" -Destination "C:\ProgramData\AISAC\certs\"
Copy-Item "certs\agent.key" -Destination "C:\ProgramData\AISAC\certs\"

# Edit configuration
notepad "C:\ProgramData\AISAC\agent.yaml"
# Update paths:
#   cert_file: "C:\\ProgramData\\AISAC\\certs\\agent.crt"
#   key_file: "C:\\ProgramData\\AISAC\\certs\\agent.key"
#   ca_file: "C:\\ProgramData\\AISAC\\certs\\ca.crt"
```

#### Step 3: Install as Windows Service (using NSSM)

```powershell
# Download and install NSSM (Non-Sucking Service Manager)
# https://nssm.cc/download

# Install service
nssm install AISAC-Agent "C:\Program Files\AISAC\aisac-agent.exe"
nssm set AISAC-Agent AppParameters "-c C:\ProgramData\AISAC\agent.yaml"
nssm set AISAC-Agent DisplayName "AISAC Security Response Agent"
nssm set AISAC-Agent Description "AISAC Agent executes security actions"
nssm set AISAC-Agent Start SERVICE_AUTO_START
nssm set AISAC-Agent AppStdout "C:\ProgramData\AISAC\agent.log"
nssm set AISAC-Agent AppStderr "C:\ProgramData\AISAC\agent-error.log"

# Start service
nssm start AISAC-Agent

# Check status
nssm status AISAC-Agent

# View logs
Get-Content "C:\ProgramData\AISAC\agent.log" -Wait
```

#### Step 4: Alternative - PowerShell Service (Windows 10+)

```powershell
# Create service using New-Service
New-Service -Name "AISAC-Agent" `
  -BinaryPathName '"C:\Program Files\AISAC\aisac-agent.exe" -c "C:\ProgramData\AISAC\agent.yaml"' `
  -DisplayName "AISAC Security Response Agent" `
  -Description "AISAC Agent executes security actions" `
  -StartupType Automatic

# Start service
Start-Service -Name "AISAC-Agent"

# Check status
Get-Service -Name "AISAC-Agent"
```

#### Step 5: Configure Windows Firewall

```powershell
# Allow outbound connection to server
New-NetFirewallRule -DisplayName "AISAC Agent" `
  -Direction Outbound `
  -Program "C:\Program Files\AISAC\aisac-agent.exe" `
  -Action Allow
```

### Manual Agent Start (Testing)

```bash
# Linux
./aisac-agent -c /etc/aisac/agent.yaml -l debug

# Windows
.\aisac-agent.exe -c C:\ProgramData\AISAC\agent.yaml -l debug

# Override server URL via environment variable
export AISAC_SERVER_URL="wss://server:8443/ws"
./aisac-agent -c /etc/aisac/agent.yaml
```

---

## 6. SOAR Integration

### n8n Webhook Configuration

The AISAC Command Server provides REST API endpoints that can be called from n8n workflows to send commands to agents.

#### Step 1: Configure n8n HTTP Request Node

Create an HTTP Request node in your n8n workflow:

```json
{
  "method": "POST",
  "url": "https://aisac-server.example.com:8443/api/v1/agents/{{$json.agent_id}}/command",
  "authentication": "headerAuth",
  "headerAuth": {
    "name": "Authorization",
    "value": "Bearer your-secret-token-here"
  },
  "body": {
    "action": "block_ip",
    "parameters": {
      "ip_address": "{{$json.malicious_ip}}",
      "duration": 3600
    },
    "execution_id": "{{$json.soar_execution_id}}",
    "timeout_seconds": 30
  },
  "options": {
    "ignoreSSL": false
  }
}
```

#### Step 2: List Available Agents

```json
{
  "method": "GET",
  "url": "https://aisac-server.example.com:8443/api/v1/agents",
  "authentication": "headerAuth",
  "headerAuth": {
    "name": "Authorization",
    "value": "Bearer your-secret-token-here"
  }
}
```

Response:
```json
[
  {
    "id": "agent-web-01",
    "hostname": "web-server-01",
    "platform": "linux",
    "version": "1.0.0",
    "labels": ["production", "webserver"],
    "last_seen": "2025-12-04T10:30:00Z",
    "status": "connected"
  }
]
```

#### Step 3: Configure Agent Callback

To receive responses back in n8n, configure the agent callback in `/etc/aisac/agent.yaml`:

```yaml
callback:
  enabled: true
  url: "https://n8n.example.com/webhook/aisac-callback"
  auth_token: "your-webhook-token"
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s
```

Create a Webhook node in n8n to receive callbacks:

1. Add Webhook Trigger node
2. Set webhook path: `/webhook/aisac-callback`
3. Set authentication: Header Auth
4. Set authentication header: `Authorization: Bearer your-webhook-token`

Agent will POST to this webhook with:

```json
{
  "agent_id": "agent-web-01",
  "command_id": "cmd-12345",
  "execution_id": "soar-exec-67890",
  "action": "block_ip",
  "status": "success",
  "result": {
    "action": "ip_blocked",
    "ip_address": "192.168.1.100",
    "rule_id": "AISAC-12345",
    "details": "Successfully blocked IP 192.168.1.100"
  },
  "execution_time_ms": 150,
  "timestamp": "2025-12-04T10:30:00Z"
}
```

### Example n8n Workflow

```javascript
// Workflow: Block Malicious IP

// 1. Trigger: Webhook from SOAR/Supabase Edge Function
// Input: { "ip_address": "192.168.1.100", "agent_id": "agent-web-01" }

// 2. HTTP Request: Send block command to agent
POST https://aisac-server.example.com:8443/api/v1/agents/{{$json.agent_id}}/command
Headers: Authorization: Bearer your-secret-token-here
Body:
{
  "action": "block_ip",
  "parameters": {
    "ip_address": "{{$json.ip_address}}",
    "duration": 3600
  },
  "execution_id": "{{$json.execution_id}}",
  "timeout_seconds": 30
}

// 3. Wait for callback (Webhook Trigger)
// The agent will POST back to n8n with the result

// 4. Update SOAR database with result
// Update soar_executions table with status
```

### SOAR Platform Integration (Supabase Edge Functions)

Example Edge Function to trigger agent action:

```typescript
// supabase/functions/playbook-executor/index.ts

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"

serve(async (req) => {
  const { action, parameters, agent_id, execution_id } = await req.json()

  // Send command to AISAC Server via n8n
  const n8nResponse = await fetch("https://n8n.example.com/webhook/aisac-action", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer your-n8n-webhook-token"
    },
    body: JSON.stringify({
      action,
      parameters,
      agent_id,
      execution_id
    })
  })

  const result = await n8nResponse.json()

  return new Response(
    JSON.stringify({ success: true, command_id: result.command_id }),
    { headers: { "Content-Type": "application/json" } }
  )
})
```

---

## 7. Security Hardening

### File Permissions

Ensure proper file permissions on all systems:

```bash
# Linux
sudo chmod 700 /etc/aisac/certs
sudo chmod 600 /etc/aisac/certs/*.key
sudo chmod 644 /etc/aisac/certs/*.crt
sudo chmod 644 /etc/aisac/agent.yaml
sudo chown -R root:root /etc/aisac

# Logs
sudo chmod 750 /var/log/aisac
sudo chown -R aisac-agent:aisac-agent /var/log/aisac
```

```powershell
# Windows
icacls "C:\ProgramData\AISAC\certs" /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
icacls "C:\ProgramData\AISAC\certs\*.key" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F"
```

### Network Firewall Rules

#### Server Firewall

```bash
# Linux (iptables)
# Allow WebSocket connections from agents
sudo iptables -A INPUT -p tcp --dport 8443 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 8443 -m state --state ESTABLISHED -j ACCEPT

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Linux (firewalld)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

```powershell
# Windows
New-NetFirewallRule -DisplayName "AISAC Server" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8443 `
  -Action Allow
```

#### Agent Firewall

```bash
# Linux - Allow outbound to server
sudo iptables -A OUTPUT -p tcp --dport 8443 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp --sport 8443 -m state --state ESTABLISHED -j ACCEPT
```

### Certificate Rotation

Implement regular certificate rotation:

```bash
#!/bin/bash
# rotate-certs.sh

CERT_DIR="/etc/aisac/certs"
BACKUP_DIR="/etc/aisac/certs/backup-$(date +%Y%m%d)"

# Backup existing certificates
mkdir -p "$BACKUP_DIR"
cp -a "$CERT_DIR"/*.{crt,key} "$BACKUP_DIR/"

# Generate new certificates
./scripts/gen-certs.sh "$CERT_DIR"

# Restart services
systemctl restart aisac-server
systemctl restart aisac-agent

# Verify
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt"
openssl verify -CAfile "$CERT_DIR/ca.crt" "$CERT_DIR/agent.crt"

echo "Certificate rotation completed. Backup saved to $BACKUP_DIR"
```

Set up automated rotation with cron:

```bash
# Run certificate rotation every 6 months
0 0 1 */6 * /opt/aisac/scripts/rotate-certs.sh 2>&1 | logger -t aisac-cert-rotation
```

### API Token Management

#### Generate Strong Tokens

```bash
# Generate secure random token (Linux/macOS)
openssl rand -hex 32

# Or using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

#### Rotate API Tokens

```bash
# 1. Generate new token
NEW_TOKEN=$(openssl rand -hex 32)

# 2. Update server configuration
sudo systemctl stop aisac-server
sudo sed -i "s/API_TOKEN=.*/API_TOKEN=$NEW_TOKEN/" /etc/systemd/system/aisac-server.service
sudo systemctl daemon-reload
sudo systemctl start aisac-server

# 3. Update n8n/SOAR webhook credentials

# 4. Verify
curl -k -H "Authorization: Bearer $NEW_TOKEN" \
  https://localhost:8443/api/v1/health
```

### Rate Limiting

Configure rate limits in agent configuration to prevent abuse:

```yaml
actions:
  rate_limits:
    block_ip:
      max_per_minute: 10    # Max 10 per minute
      max_per_hour: 100     # Max 100 per hour
    isolate_host:
      max_per_minute: 1     # Max 1 per minute
      max_per_hour: 5       # Max 5 per hour
    disable_user:
      max_per_minute: 5
      max_per_hour: 50
```

### Audit Logging

Enable comprehensive audit logging:

```yaml
# agent.yaml
logging:
  level: "info"           # Use "debug" for detailed troubleshooting
  format: "json"          # JSON format for easier parsing
  output: "file"
  file: "/var/log/aisac/agent.log"
```

Set up log rotation:

```bash
# /etc/logrotate.d/aisac
/var/log/aisac/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 aisac-agent aisac-agent
    sharedscripts
    postrotate
        systemctl reload aisac-agent >/dev/null 2>&1 || true
    endscript
}
```

### SELinux/AppArmor Policies (Linux)

For enhanced security on Linux systems:

```bash
# SELinux (RHEL/CentOS)
# Create custom policy for aisac-agent
sudo semanage fcontext -a -t bin_t "/usr/local/bin/aisac-agent"
sudo restorecon -v /usr/local/bin/aisac-agent

# AppArmor (Ubuntu/Debian)
# Create profile
sudo nano /etc/apparmor.d/usr.local.bin.aisac-agent
```

---

## 8. Troubleshooting

### Common Connection Errors

#### Error: "x509: certificate signed by unknown authority"

**Cause**: Agent cannot verify server certificate with CA certificate.

**Solution**:
```bash
# Verify CA certificate is correct
openssl verify -CAfile /etc/aisac/certs/ca.crt /etc/aisac/certs/server.crt

# Ensure agent has correct CA certificate
sudo cp certs/ca.crt /etc/aisac/certs/
sudo chmod 644 /etc/aisac/certs/ca.crt

# Restart agent
sudo systemctl restart aisac-agent
```

#### Error: "connection refused"

**Cause**: Server is not running or firewall blocking connection.

**Solution**:
```bash
# Check server status
sudo systemctl status aisac-server

# Check if server is listening
sudo netstat -tlnp | grep 8443
# or
sudo ss -tlnp | grep 8443

# Check firewall rules
sudo iptables -L -n | grep 8443
sudo firewall-cmd --list-all

# Test connection
telnet aisac-server.example.com 8443
```

#### Error: "TLS handshake timeout"

**Cause**: Network latency or certificate issues.

**Solution**:
```bash
# Test TLS connection
openssl s_client -connect aisac-server.example.com:8443 \
  -cert /etc/aisac/certs/agent.crt \
  -key /etc/aisac/certs/agent.key \
  -CAfile /etc/aisac/certs/ca.crt

# Increase connection timeout in agent.yaml
server:
  connect_timeout: 60s
```

### Log Analysis

#### View Server Logs

```bash
# Systemd journal
sudo journalctl -u aisac-server -f

# Follow specific fields
sudo journalctl -u aisac-server -o json-pretty

# Last 100 lines
sudo journalctl -u aisac-server -n 100

# Since specific time
sudo journalctl -u aisac-server --since "1 hour ago"

# Search for errors
sudo journalctl -u aisac-server -p err
```

#### View Agent Logs

```bash
# Systemd journal
sudo journalctl -u aisac-agent -f

# File logs
sudo tail -f /var/log/aisac/agent.log

# Parse JSON logs with jq
sudo tail -f /var/log/aisac/agent.log | jq '.'

# Filter for errors
sudo grep "error" /var/log/aisac/agent.log | jq '.'

# Filter by action
sudo grep "block_ip" /var/log/aisac/agent.log | jq '.'
```

#### Windows Logs

```powershell
# View service logs
Get-Content "C:\ProgramData\AISAC\agent.log" -Wait

# Filter errors
Select-String -Path "C:\ProgramData\AISAC\agent.log" -Pattern "error"

# View Windows Event Log
Get-EventLog -LogName Application -Source "AISAC-Agent" -Newest 50
```

### Action Execution Failures

#### Error: "iptables: command not found"

**Cause**: iptables not installed or not in PATH.

**Solution**:
```bash
# Install iptables
sudo apt-get install iptables          # Debian/Ubuntu
sudo dnf install iptables-services     # RHEL/CentOS

# Verify installation
which iptables
iptables --version
```

#### Error: "permission denied"

**Cause**: Agent lacks required permissions.

**Solution**:
```bash
# Verify agent is running as root
ps aux | grep aisac-agent

# Check capabilities
getcap /usr/local/bin/aisac-agent

# Grant capabilities (if not running as root)
sudo setcap cap_net_admin,cap_sys_admin+ep /usr/local/bin/aisac-agent

# Or run as root (modify systemd service)
sudo nano /etc/systemd/system/aisac-agent.service
# Change: User=root
sudo systemctl daemon-reload
sudo systemctl restart aisac-agent
```

#### Error: "rate limit exceeded"

**Cause**: Too many actions executed in short time.

**Solution**:
```yaml
# Adjust rate limits in agent.yaml
actions:
  rate_limits:
    block_ip:
      max_per_minute: 20    # Increase from 10
      max_per_hour: 200     # Increase from 100
```

### Debugging Commands

#### Test Agent Registration

```bash
# Enable debug logging
./aisac-agent -c /etc/aisac/agent.yaml -l debug

# Expected output:
# {"level":"debug","agent_id":"xxx","message":"Connecting to server"}
# {"level":"info","message":"Agent registered successfully"}
# {"level":"debug","message":"Starting heartbeat"}
```

#### Test Server API

```bash
# Get server health
curl -k https://localhost:8443/api/v1/health

# List agents (requires token)
curl -k -H "Authorization: Bearer your-token" \
  https://localhost:8443/api/v1/agents

# Send test command
curl -k -X POST \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block_ip",
    "parameters": {
      "ip_address": "192.168.1.100",
      "duration": 60
    }
  }' \
  https://localhost:8443/api/v1/agents/agent-web-01/command
```

#### Verify mTLS

```bash
# Test server certificate
openssl s_client -connect aisac-server.example.com:8443 \
  -CAfile /etc/aisac/certs/ca.crt

# Test client certificate
openssl s_client -connect aisac-server.example.com:8443 \
  -cert /etc/aisac/certs/agent.crt \
  -key /etc/aisac/certs/agent.key \
  -CAfile /etc/aisac/certs/ca.crt

# Check certificate expiration
openssl x509 -in /etc/aisac/certs/agent.crt -noout -dates
openssl x509 -in /etc/aisac/certs/server.crt -noout -dates
```

### Performance Monitoring

```bash
# Monitor agent resource usage
top -p $(pgrep aisac-agent)

# Monitor network connections
watch -n 1 'netstat -an | grep 8443'

# Check disk space for logs
df -h /var/log/aisac

# Monitor log file size
du -sh /var/log/aisac/agent.log
```

### Getting Help

- **Documentation**: [GitHub Repository](https://github.com/yourusername/aisac-agent)
- **Issues**: [GitHub Issues](https://github.com/yourusername/aisac-agent/issues)
- **Logs**: Always include logs when reporting issues
- **Version**: Run `aisac-agent --version` or `aisac-server --version`

---

## Quick Reference

### Server Commands

```bash
# Start server
aisac-server -a :8443 --cert server.crt --key server.key --ca ca.crt --api-token TOKEN

# Check health
curl -k https://localhost:8443/api/v1/health

# List agents
curl -k -H "Authorization: Bearer TOKEN" https://localhost:8443/api/v1/agents
```

### Agent Commands

```bash
# Start agent
aisac-agent -c /etc/aisac/agent.yaml

# Debug mode
aisac-agent -c /etc/aisac/agent.yaml -l debug

# Version
aisac-agent --version
```

### Service Management

```bash
# Linux systemd
sudo systemctl start aisac-agent
sudo systemctl stop aisac-agent
sudo systemctl restart aisac-agent
sudo systemctl status aisac-agent
sudo journalctl -u aisac-agent -f

# Windows
Start-Service AISAC-Agent
Stop-Service AISAC-Agent
Restart-Service AISAC-Agent
Get-Service AISAC-Agent
```

---

## Next Steps

After successful deployment:

1. Test all enabled actions in a safe environment
2. Configure SOAR integration workflows
3. Set up monitoring and alerting
4. Implement certificate rotation schedule
5. Review and tune rate limits
6. Set up backup procedures for certificates and configurations
7. Document your specific deployment architecture
8. Train incident response team on AISAC usage

For production deployments, consider:
- High availability setup with multiple command servers
- Load balancing for agent connections
- Centralized logging (ELK stack, Splunk, etc.)
- Metrics collection (Prometheus, Grafana)
- Automated testing of agent actions
- Disaster recovery procedures
