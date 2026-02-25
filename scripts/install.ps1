#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AISAC Agent Installer for Windows Server

.DESCRIPTION
    Interactive installation script for Windows Server endpoints.
    Installs the AISAC security agent as a Windows Service with support
    for SOAR, SIEM collector, and heartbeat modes.

.PARAMETER Uninstall
    Remove AISAC Agent from the system.

.PARAMETER NonInteractive
    Run in non-interactive mode using environment variables.

.EXAMPLE
    .\install.ps1
    Interactive installation.

.EXAMPLE
    $env:AISAC_API_KEY = "aisac_xxx"
    $env:AISAC_ASSET_ID = "uuid-here"
    .\install.ps1 -NonInteractive
    Non-interactive installation.

.EXAMPLE
    .\install.ps1 -Uninstall
    Remove AISAC Agent.
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NonInteractive,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

$INSTALL_DIR       = "$env:ProgramFiles\AISAC"
$CONFIG_DIR        = "$env:ProgramData\AISAC"
$DATA_DIR          = "$env:ProgramData\AISAC\data"
$LOG_DIR           = "$env:ProgramData\AISAC\logs"
$CERT_DIR          = "$env:ProgramData\AISAC\certs"
$SERVICE_NAME      = "AISACAgent"
$SERVICE_DISPLAY   = "AISAC Security Agent"
$BINARY_NAME       = "aisac-agent.exe"
$SERVER_SERVICE    = "AISACServer"
$SERVER_BINARY     = "aisac-server.exe"

# Default URLs
$DEFAULT_SERVER_URL    = "wss://localhost:8443/ws"
$DEFAULT_INGEST_URL    = "https://api.aisac.cisec.es/v1/logs"
$DEFAULT_HEARTBEAT_URL = "https://api.aisac.cisec.es/v1/heartbeat"
$DEFAULT_REGISTER_URL  = "https://api.aisac.cisec.es/v1/agent-webhook"

# State
$script:REGISTRATION_SUCCESS = $false
$script:SERVICE_WAS_RUNNING  = $false

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ║              AISAC Agent Installer v1.2 (Windows)             ║" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ║   Security Information and Event Management (SIEM) Agent      ║" -ForegroundColor Cyan
    Write-Host "  ║   with Security Orchestration and Response (SOAR) Actions     ║" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ║   - Auto-registration with AISAC Platform                     ║" -ForegroundColor Cyan
    Write-Host "  ║   - Windows Event Log and Sysmon collection                   ║" -ForegroundColor Cyan
    Write-Host "  ║   - Automated incident response capabilities                  ║" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info($Message)    { Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Ok($Message)      { Write-Host "[OK]   $Message" -ForegroundColor Green }
function Write-Warn($Message)    { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err($Message)     { Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Read-Prompt {
    param(
        [string]$Message,
        [string]$Default = ""
    )
    if ($Default) {
        $answer = Read-Host "  $Message [$Default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        return $answer
    } else {
        return Read-Host "  $Message"
    }
}

function Read-SecurePrompt {
    param([string]$Message)
    $secure = Read-Host "  $Message" -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Read-YesNo {
    param(
        [string]$Message,
        [string]$Default = "n"
    )
    if ($Default -eq "y") {
        $prompt = "  $Message [Y/n]"
    } else {
        $prompt = "  $Message [y/N]"
    }
    $result = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($result)) { $result = $Default }
    return ($result -match "^[Yy]")
}

# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────────────────────────────────────────

function Test-Prerequisites {
    Write-Info "Running pre-flight checks..."

    # Check administrator privileges
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Err "This script must be run as Administrator."
        Write-Host "  Right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    Write-Ok "Running as Administrator"

    # Check Windows version
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Ok "Detected OS: $($os.Caption) ($($os.Version))"

    # Check if sc.exe is available (for service management)
    if (-not (Get-Command sc.exe -ErrorAction SilentlyContinue)) {
        Write-Err "sc.exe not found. Cannot manage Windows Services."
        exit 1
    }
    Write-Ok "Windows Service manager available"

    # Check if OpenSSL is available (needed for mTLS certificates)
    if (Get-Command openssl.exe -ErrorAction SilentlyContinue) {
        Write-Ok "OpenSSL detected"
    } else {
        Write-Warn "OpenSSL not found. Certificate generation will not be available."
        Write-Host "  Install OpenSSL from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Agent ID Generation and Registration
# ─────────────────────────────────────────────────────────────────────────────

function New-AgentId {
    $hostname = ($env:COMPUTERNAME).ToLower() -replace '[^a-z0-9-]', '-'
    $random = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    return "agent-${hostname}-${random}"
}

function Register-Agent {
    param(
        [string]$AgentId,
        [string]$ApiKey,
        [string]$AssetId,
        [string]$RegisterUrl = $DEFAULT_REGISTER_URL,
        [string]$CsApiToken  = "",
        [string]$CsUrl       = ""
    )

    Write-Info "Registering agent with AISAC platform..."
    if ($CsApiToken) {
        $tokenPreview = $CsApiToken.Substring(0, [Math]::Min(16, $CsApiToken.Length))
        Write-Info "Including Command Server data (token: ${tokenPreview}..., url: ${CsUrl})"
    } else {
        Write-Info "Registering without Command Server data (SOAR not configured)"
    }

    # Collect system information
    $hostname   = $env:COMPUTERNAME
    $osInfo     = "windows"
    $osVersion  = (Get-CimInstance Win32_OperatingSystem).Version
    $arch       = $env:PROCESSOR_ARCHITECTURE.ToLower()
    $kernel     = [System.Environment]::OSVersion.Version.ToString()

    # Map architecture
    switch ($arch) {
        "amd64" { $arch = "amd64" }
        "x86"   { $arch = "386" }
        "arm64" { $arch = "arm64" }
    }

    # Get primary IP address
    $ipAddress = ""
    try {
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -First 1).IPAddress
    } catch {
        $ipAddress = ""
    }

    # Determine capabilities
    $capabilities = @("collector", "heartbeat")
    if ($CsApiToken) {
        $capabilities = @("collector", "soar", "heartbeat")
    }

    # Build payload (agent-webhook format)
    $payload = @{
        event      = "agent_registered"
        asset_id   = $AssetId
        agent_info = @{
            agent_id     = $AgentId
            hostname     = $hostname
            os           = $osInfo
            os_version   = $osVersion
            arch         = $arch
            kernel       = $kernel
            ip_address   = $ipAddress
            version      = "1.0.1"
            capabilities = $capabilities
        }
    }

    if ($CsApiToken) {
        $payload["command_server_token"] = $CsApiToken
        $payload["command_server_url"]   = $CsUrl
    }

    $jsonPayload = $payload | ConvertTo-Json -Depth 5

    # Debug: show payload (redacted)
    $debugPayload = $jsonPayload
    if ($CsApiToken) {
        $redacted = $CsApiToken.Substring(0, [Math]::Min(8, $CsApiToken.Length)) + "...REDACTED"
        $debugPayload = $debugPayload -replace [regex]::Escape($CsApiToken), $redacted
    }
    Write-Info "Registration URL: $RegisterUrl"
    Write-Info "Registration payload:"
    Write-Host $debugPayload

    # Make registration request
    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Key"    = $ApiKey
        }
        $response = Invoke-RestMethod -Uri $RegisterUrl -Method Post -Headers $headers -Body $jsonPayload -ErrorAction Stop
        Write-Ok "Agent registered successfully with ID: $AgentId"
        $script:REGISTRATION_SUCCESS = $true
    } catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        Write-Info "Registration response (HTTP $statusCode): $($_.Exception.Message)"

        switch ($statusCode) {
            401 { Write-Warn "Registration endpoint returned 401. Continuing without registration." }
            403 { Write-Warn "Registration endpoint returned 403. Continuing without registration." }
            404 { Write-Warn "Registration endpoint not found. Agent will work in offline mode." }
            409 {
                Write-Warn "Agent ID already registered. Using existing registration."
                $script:REGISTRATION_SUCCESS = $true
            }
            default {
                Write-Warn "Registration returned code $statusCode. Continuing with local configuration."
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Certificate Generation for mTLS (SOAR mode)
# ─────────────────────────────────────────────────────────────────────────────

function New-Certificates {
    param(
        [string]$CertDir,
        [string]$ServerHostname = ""
    )

    Write-Info "Generating mTLS certificates for SOAR mode..."

    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-Err "OpenSSL is required to generate certificates but not found."
        return $false
    }

    $days = 365
    $caSubject    = "/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=AISAC CA"
    $agentSubject = "/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=$script:AGENT_ID"

    if (-not (Test-Path $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }

    # Remove old certificates
    Get-ChildItem $CertDir -Include "*.crt","*.key","*.csr","*.ext","*.srl" -Recurse -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # CA key & cert
    Write-Info "Generating CA private key..."
    & openssl genrsa -out "$CertDir\ca.key" 4096 2>$null
    Write-Info "Generating CA certificate..."
    & openssl req -new -x509 -days $days -key "$CertDir\ca.key" -out "$CertDir\ca.crt" -subj $caSubject 2>$null

    # Agent key, CSR, cert
    Write-Info "Generating agent private key..."
    & openssl genrsa -out "$CertDir\agent.key" 2048 2>$null
    & openssl req -new -key "$CertDir\agent.key" -out "$CertDir\agent.csr" -subj $agentSubject 2>$null

    # Agent extensions
    @"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"@ | Set-Content "$CertDir\agent.ext" -Encoding ASCII

    Write-Info "Generating agent certificate..."
    & openssl x509 -req -in "$CertDir\agent.csr" `
        -CA "$CertDir\ca.crt" -CAkey "$CertDir\ca.key" -CAcreateserial `
        -out "$CertDir\agent.crt" -days $days -extfile "$CertDir\agent.ext" 2>$null

    # Server certificates if hostname provided
    if ($ServerHostname) {
        $serverSubject = "/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=$ServerHostname"

        Write-Info "Generating server private key..."
        & openssl genrsa -out "$CertDir\server.key" 2048 2>$null
        & openssl req -new -key "$CertDir\server.key" -out "$CertDir\server.csr" -subj $serverSubject 2>$null

        @"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $ServerHostname
IP.1 = 127.0.0.1
IP.2 = ::1
"@ | Set-Content "$CertDir\server.ext" -Encoding ASCII

        & openssl x509 -req -in "$CertDir\server.csr" `
            -CA "$CertDir\ca.crt" -CAkey "$CertDir\ca.key" -CAcreateserial `
            -out "$CertDir\server.crt" -days $days -extfile "$CertDir\server.ext" 2>$null

        Remove-Item "$CertDir\server.csr", "$CertDir\server.ext" -Force -ErrorAction SilentlyContinue
    }

    # Cleanup temp files
    Remove-Item "$CertDir\agent.csr", "$CertDir\agent.ext" -Force -ErrorAction SilentlyContinue
    Remove-Item "$CertDir\*.srl" -Force -ErrorAction SilentlyContinue

    Write-Ok "Certificates generated in $CertDir"
    Write-Host ""
    Write-Host "  Generated files:" -ForegroundColor Cyan
    Write-Host "    - ca.crt      (CA certificate - share with server)"
    Write-Host "    - ca.key      (CA private key - keep secure!)"
    Write-Host "    - agent.crt   (Agent certificate)"
    Write-Host "    - agent.key   (Agent private key)"
    if (Test-Path "$CertDir\server.crt") {
        Write-Host "    - server.crt  (Server certificate)"
        Write-Host "    - server.key  (Server private key)"
    }
    Write-Host ""
    return $true
}

function Test-Certificates {
    param([string]$CertDir)

    if (-not (Test-Path "$CertDir\ca.crt"))    { Write-Err "CA certificate not found: $CertDir\ca.crt"; return $false }
    if (-not (Test-Path "$CertDir\agent.crt")) { Write-Err "Agent certificate not found: $CertDir\agent.crt"; return $false }
    if (-not (Test-Path "$CertDir\agent.key")) { Write-Err "Agent key not found: $CertDir\agent.key"; return $false }

    $result = & openssl verify -CAfile "$CertDir\ca.crt" "$CertDir\agent.crt" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Agent certificate verification failed - not signed by CA"
        return $false
    }
    Write-Ok "Agent certificate verified against CA"

    if (Test-Path "$CertDir\server.crt") {
        $result = & openssl verify -CAfile "$CertDir\ca.crt" "$CertDir\server.crt" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Server certificate verification failed - not signed by CA"
            return $false
        }
        Write-Ok "Server certificate verified against CA"
    }
    return $true
}

# ─────────────────────────────────────────────────────────────────────────────
# API Token Generation
# ─────────────────────────────────────────────────────────────────────────────

function New-ApiToken {
    param([string]$Password = "")

    if ($Password) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
        $hash = $sha.ComputeHash($bytes)
        return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
    } else {
        $bytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        $token = ([Convert]::ToBase64String($bytes) -replace '[^a-zA-Z0-9]', '')
        return $token.Substring(0, [Math]::Min(44, $token.Length))
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Command Server Installation
# ─────────────────────────────────────────────────────────────────────────────

function Install-CommandServer {
    param([string]$ApiToken)

    Write-Info "Installing AISAC Command Server..."

    # Compile from source if available
    $projectRoot = Split-Path -Parent $PSScriptRoot
    if ((Test-Path "$projectRoot\go.mod") -and (Test-Path "$projectRoot\cmd\server")) {
        if (Get-Command go.exe -ErrorAction SilentlyContinue) {
            Write-Info "Compiling command server from source..."
            Push-Location $projectRoot
            try {
                $env:GOOS = "windows"
                $env:GOARCH = "amd64"
                & go build -o "$INSTALL_DIR\$SERVER_BINARY" ./cmd/server/
                if ($LASTEXITCODE -ne 0) { throw "Compilation failed" }
                Write-Ok "Command server compiled successfully"
            } catch {
                Write-Err "Failed to compile command server: $_"
                return $false
            } finally {
                Pop-Location
                Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
                Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
            }
        } else {
            Write-Err "Go is required to compile the command server"
            return $false
        }
    } else {
        Write-Err "Source code not found at $projectRoot. Cannot compile command server."
        return $false
    }

    # Create Windows Service for command server
    Write-Info "Creating command server Windows Service..."

    $serverExe = "$INSTALL_DIR\$SERVER_BINARY"
    $serverArgs = "--listen :8443 --cert `"$CERT_DIR\server.crt`" --key `"$CERT_DIR\server.key`" --ca `"$CERT_DIR\ca.crt`" --api-token $ApiToken --api-mtls=false --log-level info"

    # Remove existing service if present
    $existing = Get-Service -Name $SERVER_SERVICE -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Removing existing command server service..."
        Stop-Service -Name $SERVER_SERVICE -Force -ErrorAction SilentlyContinue
        & sc.exe delete $SERVER_SERVICE | Out-Null
        Start-Sleep -Seconds 2
    }

    # Create service using sc.exe
    & sc.exe create $SERVER_SERVICE binPath= "`"$serverExe`" $serverArgs" start= auto DisplayName= "AISAC Command Server (SOAR)" | Out-Null
    & sc.exe description $SERVER_SERVICE "AISAC Command Server - receives SOAR commands from n8n and forwards to agents via mTLS" | Out-Null
    & sc.exe failure $SERVER_SERVICE reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    # Save API token
    $ApiToken | Set-Content "$CONFIG_DIR\server-api-token" -Encoding UTF8
    Write-Info "API token saved to $CONFIG_DIR\server-api-token"

    Write-Ok "Command server service installed"
    return $true
}

function Start-CommandServer {
    Write-Info "Starting command server..."
    Start-Service -Name $SERVER_SERVICE
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name $SERVER_SERVICE -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Command server is running"
        return $true
    } else {
        Write-Err "Failed to start command server"
        Write-Host "  Check Event Viewer > Windows Logs > Application for errors" -ForegroundColor Yellow
        return $false
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Directory and binary installation
# ─────────────────────────────────────────────────────────────────────────────

function New-Directories {
    Write-Info "Creating directories..."

    foreach ($dir in @($INSTALL_DIR, $CONFIG_DIR, $CERT_DIR, $DATA_DIR, $LOG_DIR)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    # Restrict config directory permissions
    $acl = Get-Acl $CONFIG_DIR
    $acl.SetAccessRuleProtection($true, $false) # disable inheritance
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $CONFIG_DIR $acl

    Write-Ok "Directories created"
}

function Install-Binary {
    Write-Info "Installing AISAC Agent binary..."

    # Stop existing service if running
    $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Info "Stopping running service to update binary..."
        Stop-Service -Name $SERVICE_NAME -Force
        $script:SERVICE_WAS_RUNNING = $true
        Start-Sleep -Seconds 2
    }

    $projectRoot = Split-Path -Parent $PSScriptRoot
    $installed = $false

    # Option 1: Compile from source
    if ((Test-Path "$projectRoot\go.mod") -and (Test-Path "$projectRoot\cmd\agent")) {
        if (Get-Command go.exe -ErrorAction SilentlyContinue) {
            Write-Info "Source code detected, compiling from source..."
            Push-Location $projectRoot
            try {
                & go build -o "$INSTALL_DIR\$BINARY_NAME" ./cmd/agent/
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok "Binary compiled successfully"
                    $installed = $true
                } else {
                    Write-Warn "Compilation failed, trying other methods..."
                }
            } catch {
                Write-Warn "Compilation failed: $_"
            } finally {
                Pop-Location
            }
        } else {
            Write-Warn "Go not installed, cannot compile from source"
        }
    }

    # Option 2: Prebuilt binary
    if (-not $installed) {
        $candidates = @(
            "$projectRoot\bin\$BINARY_NAME",
            "$projectRoot\$BINARY_NAME",
            ".\$BINARY_NAME",
            ".\bin\$BINARY_NAME"
        )

        foreach ($path in $candidates) {
            if (Test-Path $path) {
                Write-Info "Using prebuilt binary: $path"
                Copy-Item $path "$INSTALL_DIR\$BINARY_NAME" -Force
                $installed = $true
                break
            }
        }
    }

    # Option 3: Download from GitHub
    if (-not $installed) {
        Write-Info "Downloading binary from GitHub Releases..."
        $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
        $downloadUrl = "https://github.com/aisacAdmin/aisac-agent/releases/download/v1.0.1/aisac-agent-windows-${arch}.exe"

        Write-Info "Downloading from: $downloadUrl"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $downloadUrl -OutFile "$INSTALL_DIR\$BINARY_NAME" -UseBasicParsing
            Write-Ok "Binary downloaded successfully"
            $installed = $true
        } catch {
            Write-Err "Failed to download binary from GitHub Releases"
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor Yellow
            Write-Host "    1. Check releases at: https://github.com/aisacAdmin/aisac-agent/releases"
            Write-Host "    2. Cross-compile with: `$env:GOOS='windows'; go build -o aisac-agent.exe ./cmd/agent"
            exit 1
        }
    }

    if (-not $installed) {
        Write-Err "Could not find or build the agent binary"
        exit 1
    }

    Write-Ok "Binary installed to $INSTALL_DIR\$BINARY_NAME"
}

# ─────────────────────────────────────────────────────────────────────────────
# Interactive configuration
# ─────────────────────────────────────────────────────────────────────────────

function Set-AgentConfiguration {
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                      Agent Configuration                        " -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    # ── Step 1: Platform Credentials ──
    Write-Host "  --- Step 1: AISAC Platform Credentials ---" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To connect this agent to AISAC, you need:" -ForegroundColor Blue
    Write-Host "    1. API Key - from Platform > Assets > [Your Asset] > API Key" -ForegroundColor Blue
    Write-Host "    2. Asset ID - from Platform > Assets > [Your Asset] > ID" -ForegroundColor Blue
    Write-Host ""

    $script:API_KEY = Read-Prompt "API Key (format: aisac_xxxx...)"
    if ([string]::IsNullOrWhiteSpace($script:API_KEY)) {
        Write-Warn "No API Key provided. Agent will work in offline mode."
        $script:API_KEY = "aisac_your_api_key_here"
    }

    $script:ASSET_ID = Read-Prompt "Asset ID (UUID from platform)"
    if ([string]::IsNullOrWhiteSpace($script:ASSET_ID)) {
        Write-Warn "No Asset ID provided. You'll need to add it later in the config file."
        $script:ASSET_ID = "your-asset-uuid-here"
    }

    # ── Step 2: Agent ID ──
    Write-Host ""
    Write-Host "  --- Step 2: Agent ID ---" -ForegroundColor Yellow
    Write-Host ""

    $script:AGENT_ID = New-AgentId
    Write-Info "Generated Agent ID: $($script:AGENT_ID)"

    # ── Step 3: SOAR Configuration ──
    Write-Host ""
    Write-Host "  --- Step 3: SOAR Configuration (Command Server) ---" -ForegroundColor Yellow
    Write-Host "  SOAR allows receiving automated response commands from the platform." -ForegroundColor Blue
    Write-Host "  This enables n8n to send security actions to this agent." -ForegroundColor Blue
    Write-Host ""

    $script:INSTALL_COMMAND_SERVER = $false
    $script:SERVER_API_TOKEN = ""
    $script:PUBLIC_SERVER_URL = ""
    $script:SOAR_ENABLED = $false
    $script:TLS_ENABLED = $false
    $script:GENERATE_CERTS = $false
    $script:GENERATE_SERVER_CERTS = $false
    $script:SERVER_HOSTNAME = ""
    $script:SERVER_URL = $DEFAULT_SERVER_URL

    if (Read-YesNo "Enable SOAR functionality (receive commands from server)?" "n") {
        $script:SOAR_ENABLED = $true

        Write-Host ""
        Write-Host "  The Command Server receives commands from n8n and forwards them to agents." -ForegroundColor Blue
        Write-Host "  It can run on this machine or on a separate server." -ForegroundColor Blue
        Write-Host ""

        if (Read-YesNo "Install Command Server on this machine?" "y") {
            $script:INSTALL_COMMAND_SERVER = $true
            $script:SERVER_URL = "wss://localhost:8443/ws"

            Write-Host ""
            Write-Host "  API Token protects the Command Server REST API (used by n8n)." -ForegroundColor Blue
            Write-Host "  You can enter a password to derive the token, or leave empty for random." -ForegroundColor Blue
            Write-Host ""

            $tokenPassword = Read-Prompt "Password for API token (leave empty for random)"
            $script:SERVER_API_TOKEN = New-ApiToken -Password $tokenPassword

            $tokenPreview = $script:SERVER_API_TOKEN.Substring(0, [Math]::Min(16, $script:SERVER_API_TOKEN.Length))
            Write-Info "Generated API Token: ${tokenPreview}..."
            Write-Host ""
            Write-Host "  IMPORTANT: Save this token for n8n configuration:" -ForegroundColor Yellow
            Write-Host "  $($script:SERVER_API_TOKEN)" -ForegroundColor Cyan
            Write-Host ""

            # Public Server URL
            Write-Host "  Public Server URL: Used by the platform to send commands back to agents." -ForegroundColor Blue
            Write-Host "  This must be the publicly accessible URL (IP or domain) where this server listens." -ForegroundColor Blue
            $primaryIP = try {
                (Get-NetIPAddress -AddressFamily IPv4 |
                    Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
                    Select-Object -First 1).IPAddress
            } catch { "IP" }
            Write-Host "  Example: https://${primaryIP}:8443" -ForegroundColor Yellow
            Write-Host ""
            $script:PUBLIC_SERVER_URL = Read-Prompt "Public Server URL" "https://${primaryIP}:8443"
            Write-Host ""

        } else {
            $script:SERVER_URL = Read-Prompt "Command Server WebSocket URL" $DEFAULT_SERVER_URL

            Write-Host ""
            Write-Host "  To enable SOAR commands from the platform, the CS API token and public URL are needed." -ForegroundColor Blue
            Write-Host "  These are used during registration so the platform can reach the Command Server." -ForegroundColor Blue
            Write-Host ""

            $script:SERVER_API_TOKEN = Read-Prompt "Command Server API Token (Bearer token used by n8n)"
            if ($script:SERVER_API_TOKEN) {
                $primaryIP = try {
                    (Get-NetIPAddress -AddressFamily IPv4 |
                        Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
                        Select-Object -First 1).IPAddress
                } catch { "IP" }
                $script:PUBLIC_SERVER_URL = Read-Prompt "Public Command Server URL" "https://${primaryIP}:8443"
            }
        }

        # Certificates
        Write-Host ""
        Write-Host "  mTLS certificates are required for secure communication." -ForegroundColor Blue

        if ((Test-Path "$CERT_DIR\agent.crt") -and (Test-Path "$CERT_DIR\ca.crt")) {
            Write-Ok "Existing certificates found in $CERT_DIR"
            if (Read-YesNo "Use existing certificates?" "y") {
                $script:GENERATE_CERTS = $false
            } else {
                $script:GENERATE_CERTS = $true
            }
        } else {
            if (Get-Command openssl.exe -ErrorAction SilentlyContinue) {
                if (Read-YesNo "Generate mTLS certificates automatically?" "y") {
                    $script:GENERATE_CERTS = $true
                } else {
                    Write-Warn "You'll need to manually copy certificates to $CERT_DIR"
                    Write-Info "Required files: ca.crt, agent.crt, agent.key"
                }
            } else {
                Write-Warn "OpenSSL not found. You'll need to manually copy certificates to $CERT_DIR"
            }
        }

        if ($script:GENERATE_CERTS) {
            $script:SERVER_HOSTNAME = $script:SERVER_URL -replace '^wss?://([^:/]+).*', '$1'
            if (Read-YesNo "Also generate server certificates for '$($script:SERVER_HOSTNAME)'?" "y") {
                $script:GENERATE_SERVER_CERTS = $true
            }
        }

        $script:TLS_ENABLED = $true

    } else {
        $script:SOAR_ENABLED = $false
        $script:TLS_ENABLED = $false
    }

    # ── Registration ──
    Write-Host ""
    Write-Host "  --- Agent Registration ---" -ForegroundColor Yellow
    Write-Host ""

    # Registration URL (allow override for staging)
    $registerUrl = if ($env:AISAC_REGISTER_URL) { $env:AISAC_REGISTER_URL } else { $DEFAULT_REGISTER_URL }

    if (($script:API_KEY -ne "aisac_your_api_key_here") -and ($script:ASSET_ID -ne "your-asset-uuid-here")) {
        if ($script:SERVER_API_TOKEN -and $script:PUBLIC_SERVER_URL) {
            Write-Info "Registering WITH command_server data"
            Register-Agent -AgentId $script:AGENT_ID -ApiKey $script:API_KEY -AssetId $script:ASSET_ID `
                -RegisterUrl $registerUrl `
                -CsApiToken $script:SERVER_API_TOKEN -CsUrl $script:PUBLIC_SERVER_URL
        } else {
            Write-Info "Registering WITHOUT command_server data"
            Register-Agent -AgentId $script:AGENT_ID -ApiKey $script:API_KEY -AssetId $script:ASSET_ID `
                -RegisterUrl $registerUrl
        }
    } else {
        Write-Warn "Skipping registration (missing credentials). Configure manually later."
    }

    # ── Step 4: Log Collector ──
    Write-Host ""
    Write-Host "  --- Step 4: Log Collector Configuration (SIEM) ---" -ForegroundColor Yellow
    Write-Host "  Collector sends security logs to the AISAC platform for analysis." -ForegroundColor Blue
    Write-Host ""

    $script:COLLECTOR_ENABLED = $false
    $script:INGEST_URL = $DEFAULT_INGEST_URL
    $script:ENABLE_WINEVT = $false
    $script:ENABLE_SYSMON = $false
    $script:ENABLE_SURICATA = $false
    $script:ENABLE_WAZUH = $false
    $script:SURICATA_PATH = ""
    $script:WAZUH_PATH = ""

    if (Read-YesNo "Enable Log Collector?" "y") {
        $script:COLLECTOR_ENABLED = $true
        $script:INGEST_URL = Read-Prompt "Log Ingest URL" $DEFAULT_INGEST_URL

        Write-Host ""
        Write-Host "  --- Detected Log Sources ---" -ForegroundColor Yellow

        # Windows Event Log (Security) - always available
        Write-Ok "Windows Security Event Log available"
        if (Read-YesNo "Enable Windows Security Event Log collection?" "y") {
            $script:ENABLE_WINEVT = $true
        }

        # Sysmon detection
        $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        if ($sysmonService) {
            Write-Ok "Sysmon detected (Service: $($sysmonService.Status))"
            if (Read-YesNo "Enable Sysmon Event Log collection?" "y") {
                $script:ENABLE_SYSMON = $true
            }
        } else {
            if (Read-YesNo "Enable Sysmon Event Log collection (not detected)?" "n") {
                $script:ENABLE_SYSMON = $true
            }
        }

        # Suricata on Windows (less common but possible)
        $suricataDefault = "C:\Program Files\Suricata\log\eve.json"
        if (Test-Path $suricataDefault) {
            Write-Ok "Suricata EVE logs detected at $suricataDefault"
            if (Read-YesNo "Enable Suricata collection?" "y") {
                $script:ENABLE_SURICATA = $true
                $script:SURICATA_PATH = $suricataDefault
            }
        } else {
            if (Read-YesNo "Enable Suricata EVE log collection (not detected)?" "n") {
                $script:ENABLE_SURICATA = $true
                $script:SURICATA_PATH = Read-Prompt "Suricata EVE log path" $suricataDefault
            }
        }

        # Wazuh on Windows
        $wazuhDefault = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
        $wazuhAlerts  = "C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json"
        if (Test-Path $wazuhAlerts) {
            Write-Ok "Wazuh alerts detected at $wazuhAlerts"
            if (Read-YesNo "Enable Wazuh alerts collection?" "y") {
                $script:ENABLE_WAZUH = $true
                $script:WAZUH_PATH = $wazuhAlerts
            }
        } else {
            if (Read-YesNo "Enable Wazuh alerts collection (not detected)?" "n") {
                $script:ENABLE_WAZUH = $true
                $script:WAZUH_PATH = Read-Prompt "Wazuh alerts path" $wazuhAlerts
            }
        }
    }

    # ── Step 5: Heartbeat ──
    Write-Host ""
    Write-Host "  --- Step 5: Heartbeat Configuration ---" -ForegroundColor Yellow
    Write-Host "  Heartbeat reports agent status and health to the platform." -ForegroundColor Blue
    Write-Host ""

    $script:HEARTBEAT_ENABLED = $false
    $script:HEARTBEAT_URL = $DEFAULT_HEARTBEAT_URL

    if (Read-YesNo "Enable Heartbeat (recommended)?" "y") {
        $script:HEARTBEAT_ENABLED = $true
        $script:HEARTBEAT_URL = Read-Prompt "Heartbeat URL" $DEFAULT_HEARTBEAT_URL
    }

    # ── Step 6: Safety ──
    $script:ADDITIONAL_CONTROL_PLANE_IPS = @()

    if ($script:SOAR_ENABLED) {
        Write-Host ""
        Write-Host "  --- Step 6: Safety Configuration ---" -ForegroundColor Yellow
        Write-Host "  Safety features protect against accidental lockout:" -ForegroundColor Blue
        Write-Host "    - Control Plane Whitelist: IPs that can never be blocked" -ForegroundColor Blue
        Write-Host "    - Auto-Revert: Actions automatically undo after TTL expires" -ForegroundColor Blue
        Write-Host "    - Heartbeat Recovery: Auto-recovery if agent loses connectivity" -ForegroundColor Blue
        Write-Host ""
        Write-Host "  Detected control plane endpoints (auto-protected):" -ForegroundColor Green
        if ($script:SERVER_URL)        { Write-Host "    - Command Server: $($script:SERVER_URL)" }
        if ($script:HEARTBEAT_URL)     { Write-Host "    - Heartbeat: $($script:HEARTBEAT_URL)" }
        if ($script:COLLECTOR_ENABLED) { Write-Host "    - Log Ingest: $($script:INGEST_URL)" }
        Write-Host ""

        if (Read-YesNo "Add additional control plane IPs? (SSH bastion, VPN, RDP, etc.)" "n") {
            Write-Host "  Enter additional IPs to whitelist (comma-separated):" -ForegroundColor Blue
            Write-Host "  Example: 10.0.0.1, 192.168.1.100" -ForegroundColor Blue
            $extraIps = Read-Prompt "Additional IPs"
            if ($extraIps) {
                $script:ADDITIONAL_CONTROL_PLANE_IPS = $extraIps -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
        }
        Write-Ok "Safety features configured"
    }

    # ── Summary ──
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                      Configuration Summary                      " -ForegroundColor Cyan
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Agent ID:       $($script:AGENT_ID)" -ForegroundColor Cyan
    Write-Host "    Asset ID:       $($script:ASSET_ID)" -ForegroundColor Cyan
    Write-Host "    SOAR Enabled:   $($script:SOAR_ENABLED)" -ForegroundColor Cyan
    Write-Host "    Collector:      $($script:COLLECTOR_ENABLED)" -ForegroundColor Cyan
    if ($script:COLLECTOR_ENABLED) {
        if ($script:ENABLE_WINEVT)   { Write-Host "      - Windows Security Event Log" }
        if ($script:ENABLE_SYSMON)   { Write-Host "      - Sysmon Event Log" }
        if ($script:ENABLE_SURICATA) { Write-Host "      - Suricata: $($script:SURICATA_PATH)" }
        if ($script:ENABLE_WAZUH)    { Write-Host "      - Wazuh: $($script:WAZUH_PATH)" }
    }
    Write-Host "    Heartbeat:      $($script:HEARTBEAT_ENABLED)" -ForegroundColor Cyan
    if ($script:SOAR_ENABLED) {
        Write-Host "    Safety:         Enabled (Whitelist + Auto-Revert + Recovery)" -ForegroundColor Cyan
    }
    if ($script:REGISTRATION_SUCCESS) {
        Write-Host "    Registration:   Registered with platform" -ForegroundColor Green
    } else {
        Write-Host "    Registration:   Offline mode" -ForegroundColor Yellow
    }
    Write-Host ""

    if (-not (Read-YesNo "Proceed with this configuration?" "y")) {
        Write-Err "Installation cancelled by user"
        exit 1
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Non-interactive configuration
# ─────────────────────────────────────────────────────────────────────────────

function Set-NonInteractiveConfiguration {
    Write-Info "Running in non-interactive mode..."

    $script:API_KEY  = if ($env:AISAC_API_KEY)  { $env:AISAC_API_KEY }  else { "aisac_your_api_key_here" }
    $script:ASSET_ID = if ($env:AISAC_ASSET_ID) { $env:AISAC_ASSET_ID } else { "your-asset-uuid-here" }

    $script:AGENT_ID = New-AgentId
    Write-Info "Generated Agent ID: $($script:AGENT_ID)"

    $script:SOAR_ENABLED      = if ($env:AISAC_SOAR -eq "true") { $true } else { $false }
    $script:COLLECTOR_ENABLED  = if ($env:AISAC_COLLECTOR -eq "false") { $false } else { $true }
    $script:HEARTBEAT_ENABLED  = if ($env:AISAC_HEARTBEAT -eq "false") { $false } else { $true }
    $script:TLS_ENABLED        = $script:SOAR_ENABLED
    $script:SERVER_URL         = $DEFAULT_SERVER_URL
    $script:SERVER_API_TOKEN   = if ($env:AISAC_CS_TOKEN) { $env:AISAC_CS_TOKEN } else { "" }
    $script:PUBLIC_SERVER_URL  = if ($env:AISAC_CS_URL) { $env:AISAC_CS_URL } else { "" }
    $script:INSTALL_COMMAND_SERVER = $false
    $script:GENERATE_CERTS     = $false
    $script:INGEST_URL         = $DEFAULT_INGEST_URL
    $script:HEARTBEAT_URL      = $DEFAULT_HEARTBEAT_URL

    # Registration URL (allow override for staging)
    $registerUrl = if ($env:AISAC_REGISTER_URL) { $env:AISAC_REGISTER_URL } else { $DEFAULT_REGISTER_URL }

    # Registration
    if (($script:API_KEY -ne "aisac_your_api_key_here") -and ($script:ASSET_ID -ne "your-asset-uuid-here")) {
        if ($script:SERVER_API_TOKEN -and $script:PUBLIC_SERVER_URL) {
            Register-Agent -AgentId $script:AGENT_ID -ApiKey $script:API_KEY -AssetId $script:ASSET_ID `
                -RegisterUrl $registerUrl `
                -CsApiToken $script:SERVER_API_TOKEN -CsUrl $script:PUBLIC_SERVER_URL
        } else {
            Register-Agent -AgentId $script:AGENT_ID -ApiKey $script:API_KEY -AssetId $script:ASSET_ID `
                -RegisterUrl $registerUrl
        }
    } else {
        Write-Warn "Missing credentials. Set AISAC_API_KEY and AISAC_ASSET_ID environment variables."
    }

    # Auto-detect Windows log sources
    $script:ENABLE_WINEVT   = $true  # Always available on Windows
    $script:ENABLE_SYSMON   = [bool](Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue)
    $script:ENABLE_SURICATA = $false
    $script:ENABLE_WAZUH    = $false
    $script:SURICATA_PATH   = ""
    $script:WAZUH_PATH      = ""
    $script:ADDITIONAL_CONTROL_PLANE_IPS = @()

    $suricataDefault = "C:\Program Files\Suricata\log\eve.json"
    if (Test-Path $suricataDefault) {
        $script:ENABLE_SURICATA = $true
        $script:SURICATA_PATH = $suricataDefault
        Write-Ok "Auto-detected: Suricata EVE logs"
    }

    $wazuhAlerts = "C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json"
    if (Test-Path $wazuhAlerts) {
        $script:ENABLE_WAZUH = $true
        $script:WAZUH_PATH = $wazuhAlerts
        Write-Ok "Auto-detected: Wazuh alerts"
    }

    if ($script:ENABLE_SYSMON) { Write-Ok "Auto-detected: Sysmon" }
    Write-Ok "Auto-detected: Windows Security Event Log"

    Write-Host ""
    Write-Host "  Configuration Summary:" -ForegroundColor Cyan
    Write-Host "    Agent ID:    $($script:AGENT_ID)"
    Write-Host "    SOAR:        $($script:SOAR_ENABLED)"
    Write-Host "    Collector:   $($script:COLLECTOR_ENABLED)"
    Write-Host "    Heartbeat:   $($script:HEARTBEAT_ENABLED)"
    Write-Host "    WinEvt:      $($script:ENABLE_WINEVT)"
    Write-Host "    Sysmon:      $($script:ENABLE_SYSMON)"
    Write-Host "    Suricata:    $($script:ENABLE_SURICATA)"
    Write-Host "    Wazuh:       $($script:ENABLE_WAZUH)"
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Config file generation
# ─────────────────────────────────────────────────────────────────────────────

function New-ConfigFile {
    Write-Info "Generating configuration file..."

    $configFile = "$CONFIG_DIR\agent.yaml"

    $config = @"
# AISAC Agent Configuration (Windows)
# Generated by installer on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

agent:
  id: "$($script:AGENT_ID)"
  labels:
    - production
    - windows
  heartbeat_interval: 30s
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  enabled: $($script:SOAR_ENABLED.ToString().ToLower())
  url: "$($script:SERVER_URL)"
  connect_timeout: 30s
  write_timeout: 10s
  read_timeout: 60s

tls:
  enabled: $($script:TLS_ENABLED.ToString().ToLower())
  cert_file: "$($CERT_DIR -replace '\\', '/')/agent.crt"
  key_file: "$($CERT_DIR -replace '\\', '/')/agent.key"
  ca_file: "$($CERT_DIR -replace '\\', '/')/ca.crt"
  skip_verify: false

actions:
  enabled:
    - block_ip
    - unblock_ip
    - isolate_host
    - unisolate_host
    - disable_user
    - enable_user
    - kill_process
  rate_limits:
    block_ip:
      max_per_minute: 10
      max_per_hour: 100
    isolate_host:
      max_per_minute: 1
      max_per_hour: 5
  default_timeout: 5m

callback:
  enabled: false
  url: ""
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s

heartbeat:
  enabled: $($script:HEARTBEAT_ENABLED.ToString().ToLower())
  url: "$($script:HEARTBEAT_URL)"
  api_key: "$($script:API_KEY)"
  asset_id: "$($script:ASSET_ID)"
  interval: 120s
  timeout: 10s
  skip_tls_verify: false

collector:
  enabled: $($script:COLLECTOR_ENABLED.ToString().ToLower())
"@

    if ($script:COLLECTOR_ENABLED) {
        $config += "`n`n  sources:"

        if ($script:ENABLE_WINEVT) {
            $config += @"

    - name: windows_security
      type: winevtlog
      channel: Security
      parser: json
      tags:
        - security
        - windows
"@
        }

        if ($script:ENABLE_SYSMON) {
            $config += @"

    - name: sysmon
      type: winevtlog
      channel: Microsoft-Windows-Sysmon/Operational
      parser: json
      tags:
        - security
        - sysmon
        - edr
"@
        }

        if ($script:ENABLE_SURICATA) {
            $config += @"

    - name: suricata
      type: file
      path: $($script:SURICATA_PATH -replace '\\', '/')
      parser: suricata_eve
      tags:
        - security
        - ids
"@
        }

        if ($script:ENABLE_WAZUH) {
            $config += @"

    - name: wazuh
      type: file
      path: $($script:WAZUH_PATH -replace '\\', '/')
      parser: wazuh_alerts
      tags:
        - security
        - hids
        - wazuh
"@
        }

        $config += @"


  output:
    type: http
    url: "$($script:INGEST_URL)"
    api_key: "$($script:API_KEY)"
    asset_id: "$($script:ASSET_ID)"
    timeout: 30s
    retry_attempts: 3
    retry_delay: 5s
    skip_tls_verify: false

  batch:
    size: 100
    interval: 5s

  file:
    start_position: end
    sincedb_path: $($DATA_DIR -replace '\\', '/')/sincedb.json
"@
    }

    # Control plane protection
    $cpIps = @()
    $cpDomains = @()

    # Extract from URLs
    if ($script:SOAR_ENABLED -and $script:SERVER_URL) {
        $serverHost = $script:SERVER_URL -replace '^wss?://([^:/]+).*', '$1'
        if ($serverHost -match '^\d+\.\d+\.\d+\.\d+$') {
            $cpIps += "    - `"$serverHost`"      # SOAR Command Server"
        } else {
            $cpDomains += "    - `"$serverHost`""
        }
    }

    $hbUrl = $script:HEARTBEAT_URL
    if ($hbUrl) {
        $hbHost = $hbUrl -replace '^https?://([^:/]+).*', '$1'
        if ($cpDomains -notcontains "    - `"$hbHost`"") {
            $cpDomains += "    - `"$hbHost`""
        }
    }

    if ($script:COLLECTOR_ENABLED -and $script:INGEST_URL) {
        $ingestHost = $script:INGEST_URL -replace '^https?://([^:/]+).*', '$1'
        if ($cpDomains -notcontains "    - `"$ingestHost`"") {
            $cpDomains += "    - `"$ingestHost`""
        }
    }

    # Additional IPs from user
    foreach ($ip in $script:ADDITIONAL_CONTROL_PLANE_IPS) {
        $cpIps += "    - `"$ip`""
    }

    if ($cpIps.Count -eq 0) {
        $cpIps = @("    # Add your control plane IPs here (SOAR server, RDP bastion, etc.)",
                   "    # - `"10.0.0.1`"")
    }
    if ($cpDomains.Count -eq 0) {
        $cpDomains = @("    - `"api.aisac.cisec.es`"")
    }

    $config += @"


# Control plane protection (IPs/domains that should NEVER be blocked)
# These are auto-detected from your configured URLs
control_plane:
  ips:
$($cpIps -join "`n")
  domains:
$($cpDomains -join "`n")
  always_allowed: true

# Safety mechanisms for destructive SOAR actions
safety:
  # Persist active actions to survive agent restarts
  state_file: "$($DATA_DIR -replace '\\', '/')/safety_state.json"

  # Auto-revert: automatically undo destructive actions after TTL expires
  auto_revert_enabled: true

  # Default TTL for reversible actions
  default_ttl: 1h

  # Per-action TTL overrides
  action_ttls:
    isolate_host: 30m   # Critical: short TTL - most disruptive action
    block_ip: 4h        # IP blocks revert after 4 hours
    disable_user: 2h    # User disables revert after 2 hours

  # Heartbeat Auto-Recovery: if agent loses connectivity, trigger recovery
  # Prevents lockout if an action accidentally blocks the agent
  heartbeat_failure_threshold: 5   # 5 failures x 2min = ~10 min before recovery
  recovery_actions:
    - unisolate_host    # Restore network connectivity
    - unblock_all_ips   # Remove all IP blocks

logging:
  level: "info"
  format: "json"
  output: "file"
  file: "$($LOG_DIR -replace '\\', '/')/agent.log"
"@

    $config | Set-Content $configFile -Encoding UTF8
    Write-Ok "Configuration saved to $configFile"
    Write-Info "Safety features enabled: Control Plane Whitelist, TTL Auto-Revert, Heartbeat Recovery"
}

# ─────────────────────────────────────────────────────────────────────────────
# Windows Service installation
# ─────────────────────────────────────────────────────────────────────────────

function Install-AgentService {
    Write-Info "Installing Windows Service..."

    # Remove existing service if present
    $existing = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Removing existing agent service..."
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        & sc.exe delete $SERVICE_NAME | Out-Null
        Start-Sleep -Seconds 2
    }

    $agentExe = "$INSTALL_DIR\$BINARY_NAME"
    $configPath = "$CONFIG_DIR\agent.yaml"

    # Create service
    & sc.exe create $SERVICE_NAME binPath= "`"$agentExe`" -c `"$configPath`"" start= auto DisplayName= "$SERVICE_DISPLAY" | Out-Null
    & sc.exe description $SERVICE_NAME "AISAC Security Agent - SIEM collection, SOAR response, and asset monitoring" | Out-Null

    # Configure failure recovery: restart after 5s, 10s, 30s
    & sc.exe failure $SERVICE_NAME reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    # Set delayed auto-start (waits for network)
    & sc.exe config $SERVICE_NAME start= delayed-auto | Out-Null

    Write-Ok "Windows Service '$SERVICE_NAME' installed and set to auto-start"
}

function Start-AgentService {
    param([bool]$AskFirst = $true)

    if ($AskFirst) {
        Write-Host ""
        if (-not (Read-YesNo "Start AISAC Agent now?" "y")) { return }
    }

    Write-Info "Starting AISAC Agent..."
    Start-Service -Name $SERVICE_NAME
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "AISAC Agent is running"
    } else {
        Write-Err "Failed to start AISAC Agent"
        Write-Host "  Check Event Viewer > Windows Logs > Application for errors" -ForegroundColor Yellow
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

function Write-Summary {
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "                   Installation Complete!                         " -ForegroundColor Green
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "    Agent ID:               $($script:AGENT_ID)" -ForegroundColor Cyan
    Write-Host "    Installation Directory: $INSTALL_DIR" -ForegroundColor Cyan
    Write-Host "    Configuration:          $CONFIG_DIR\agent.yaml" -ForegroundColor Cyan
    Write-Host "    Data Directory:         $DATA_DIR" -ForegroundColor Cyan
    Write-Host "    Log File:               $LOG_DIR\agent.log" -ForegroundColor Cyan
    Write-Host ""

    if ($script:REGISTRATION_SUCCESS) {
        Write-Host "    [OK] Agent registered with AISAC platform" -ForegroundColor Green
    } else {
        Write-Host "    [--] Agent running in offline mode" -ForegroundColor Yellow
    }

    if ($script:SOAR_ENABLED) {
        Write-Host ""
        Write-Host "    Safety Features:" -ForegroundColor Cyan
        Write-Host "      [OK] Control Plane Whitelist (protected IPs/domains)" -ForegroundColor Green
        Write-Host "      [OK] Auto-Revert (isolate_host: 30m, block_ip: 4h)" -ForegroundColor Green
        Write-Host "      [OK] Heartbeat Recovery (after 5 consecutive failures)" -ForegroundColor Green
    }

    if ($script:INSTALL_COMMAND_SERVER) {
        Write-Host ""
        Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "                   Command Server (SOAR)                     " -ForegroundColor Green
        Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "    Service:     $SERVER_SERVICE" -ForegroundColor Cyan
        Write-Host "    Listen:      :8443 (WebSocket + REST API)" -ForegroundColor Cyan
        Write-Host "    API Token:   $CONFIG_DIR\server-api-token" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    n8n Configuration:" -ForegroundColor Yellow
        Write-Host "      REST API URL:  https://localhost:8443/api/v1" -ForegroundColor Cyan
        Write-Host "      API Token:     $($script:SERVER_API_TOKEN)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    Server Commands:" -ForegroundColor Yellow
        Write-Host "      Start:   Start-Service $SERVER_SERVICE" -ForegroundColor Cyan
        Write-Host "      Stop:    Stop-Service $SERVER_SERVICE" -ForegroundColor Cyan
        Write-Host "      Status:  Get-Service $SERVER_SERVICE" -ForegroundColor Cyan
        Write-Host "      Logs:    Get-EventLog -LogName Application -Source $SERVER_SERVICE" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "    Agent Commands:" -ForegroundColor Yellow
    Write-Host "      Start:   Start-Service $SERVICE_NAME" -ForegroundColor Cyan
    Write-Host "      Stop:    Stop-Service $SERVICE_NAME" -ForegroundColor Cyan
    Write-Host "      Status:  Get-Service $SERVICE_NAME" -ForegroundColor Cyan
    Write-Host "      Logs:    Get-Content '$LOG_DIR\agent.log' -Tail 50 -Wait" -ForegroundColor Cyan
    Write-Host "      Config:  notepad '$CONFIG_DIR\agent.yaml'" -ForegroundColor Cyan
    Write-Host ""

    # Pending warnings
    $hasWarnings = $false
    if ($script:API_KEY -eq "aisac_your_api_key_here") {
        $hasWarnings = $true
        Write-Host "    [!] PENDING: Add your API Key to the config file" -ForegroundColor Yellow
    }
    if ($script:ASSET_ID -eq "your-asset-uuid-here") {
        $hasWarnings = $true
        Write-Host "    [!] PENDING: Add your Asset ID to the config file" -ForegroundColor Yellow
    }
    if ($script:TLS_ENABLED -and (-not $script:GENERATE_CERTS)) {
        if (-not (Test-Path "$CERT_DIR\agent.crt")) {
            $hasWarnings = $true
            Write-Host "    [!] PENDING: Copy certificates to $CERT_DIR" -ForegroundColor Yellow
            Write-Host "                 (agent.crt, agent.key, ca.crt)" -ForegroundColor Yellow
        }
    }
    if ($hasWarnings) { Write-Host "" }

    Write-Host "    Quick Start:" -ForegroundColor Cyan
    Write-Host "      1. Verify config:  Get-Content '$CONFIG_DIR\agent.yaml'" -ForegroundColor Cyan
    Write-Host "      2. Check status:   Get-Service $SERVICE_NAME" -ForegroundColor Cyan
    Write-Host "      3. Watch logs:     Get-Content '$LOG_DIR\agent.log' -Tail 50 -Wait" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Documentation: https://github.com/aisacAdmin/aisac-agent" -ForegroundColor Blue
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup and uninstall
# ─────────────────────────────────────────────────────────────────────────────

function Stop-AllServices {
    Write-Info "Cleaning up existing AISAC services..."

    foreach ($svcName in @($SERVICE_NAME, $SERVER_SERVICE)) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq "Running") {
                Write-Info "Stopping $svcName..."
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            & sc.exe delete $svcName 2>$null | Out-Null
        }
    }

    # Kill any lingering processes
    Get-Process -Name "aisac-agent", "aisac-server" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    Write-Ok "Services cleaned up"
}

function Invoke-Uninstall {
    Write-Host ""
    Write-Warn "This will remove AISAC Agent and Command Server from your system"

    if (-not (Read-YesNo "Are you sure you want to uninstall?" "n")) {
        Write-Host "  Uninstall cancelled"
        exit 0
    }

    Stop-AllServices

    Write-Info "Removing binaries..."
    Remove-Item $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue

    if (Read-YesNo "Remove configuration, data, and certificates?" "n") {
        Remove-Item $CONFIG_DIR -Recurse -Force -ErrorAction SilentlyContinue
        # DATA_DIR and LOG_DIR are under CONFIG_DIR (ProgramData\AISAC)
        Write-Ok "Configuration, data, and certificates removed"
    } else {
        Write-Info "Configuration preserved in $CONFIG_DIR"
    }

    # Remove firewall rules created by the agent
    Write-Info "Cleaning up Windows Firewall rules..."
    $rules = Get-NetFirewallRule -DisplayName "AISAC_*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Ok "Firewall rules removed"
    }

    Write-Ok "AISAC Agent and Command Server uninstalled"
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

function Main {
    Write-Banner

    if ($Help) {
        Write-Host "Usage: .\install.ps1 [OPTIONS]"
        Write-Host ""
        Write-Host "Options:"
        Write-Host "  -Uninstall        Remove AISAC Agent"
        Write-Host "  -NonInteractive   Run in non-interactive mode (use env vars)"
        Write-Host "  -Help             Show this help message"
        Write-Host ""
        Write-Host "Non-interactive mode (for automation):"
        Write-Host "  Set environment variables before running:"
        Write-Host ""
        Write-Host "  Required:"
        Write-Host "    AISAC_API_KEY      API Key from AISAC Platform"
        Write-Host "    AISAC_ASSET_ID     Asset ID (UUID) from AISAC Platform"
        Write-Host ""
        Write-Host "  Optional:"
        Write-Host "    AISAC_SOAR         Enable SOAR (true/false, default: false)"
        Write-Host "    AISAC_COLLECTOR    Enable Collector (true/false, default: true)"
        Write-Host "    AISAC_HEARTBEAT    Enable Heartbeat (true/false, default: true)"
        Write-Host "    AISAC_CS_TOKEN     Command Server API token (for SOAR)"
        Write-Host "    AISAC_CS_URL       Command Server public URL (for SOAR)"
        Write-Host "    AISAC_REGISTER_URL Override registration endpoint (for staging)"
        Write-Host ""
        Write-Host "Example:"
        Write-Host '  $env:AISAC_API_KEY = "aisac_xxx"'
        Write-Host '  $env:AISAC_ASSET_ID = "uuid-here"'
        Write-Host "  .\install.ps1 -NonInteractive"
        Write-Host ""
        exit 0
    }

    if ($Uninstall) {
        Test-Prerequisites
        Invoke-Uninstall
        exit 0
    }

    # Pre-flight
    Test-Prerequisites
    Write-Host ""

    # Clean up existing installation
    Stop-AllServices
    Write-Host ""

    # Installation
    New-Directories
    Install-Binary

    # Configuration
    if ($NonInteractive -or $env:AISAC_NONINTERACTIVE -eq "true") {
        Set-NonInteractiveConfiguration
    } else {
        Set-AgentConfiguration
    }

    # Generate certificates if SOAR mode and requested
    if ($script:GENERATE_CERTS) {
        Write-Host ""
        Write-Info "Generating mTLS certificates..."
        $serverHost = if ($script:GENERATE_SERVER_CERTS) { $script:SERVER_HOSTNAME } else { "" }
        New-Certificates -CertDir $CERT_DIR -ServerHostname $serverHost
    }

    # Install Command Server if requested
    if ($script:INSTALL_COMMAND_SERVER) {
        Write-Host ""
        Install-CommandServer -ApiToken $script:SERVER_API_TOKEN
    }

    # Generate config and install service
    New-ConfigFile
    Install-AgentService

    # Verify certificates if SOAR mode
    if ($script:TLS_ENABLED -and (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-Host ""
        Write-Info "Verifying certificates..."
        if (-not (Test-Certificates -CertDir $CERT_DIR)) {
            Write-Err "Certificate verification failed. Services will not start correctly."
            Write-Info "Please regenerate certificates or fix the issue before starting services."
            exit 1
        }
    }

    # Start services
    if ($NonInteractive -or $env:AISAC_NONINTERACTIVE -eq "true") {
        if ($script:INSTALL_COMMAND_SERVER) {
            Start-CommandServer
            Write-Info "Waiting for command server to be fully ready..."
            Start-Sleep -Seconds 3
        }
        Start-AgentService -AskFirst $false
    } else {
        if ($script:INSTALL_COMMAND_SERVER) {
            if (Read-YesNo "Start Command Server now?" "y") {
                Start-CommandServer
                Write-Info "Waiting for command server to be fully ready..."
                Start-Sleep -Seconds 3
            }
        }
        Start-AgentService -AskFirst $true
    }

    Write-Summary
}

# Run
Main
