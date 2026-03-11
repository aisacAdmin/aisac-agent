<#
.SYNOPSIS
    AISAC Agent Installer for Windows

.DESCRIPTION
    Reads tenant config from C:\Windows\Temp\aisac-register.json
    (written by install-wazuh-agent.ps1) and installs the AISAC Agent
    with optional SOAR support.

.PARAMETER Soar
    Enable SOAR mode (Command Server + mTLS certificates)

.EXAMPLE
    .\install-aisac-agent.ps1

.EXAMPLE
    .\install-aisac-agent.ps1 -Soar
#>

param(
    [switch]$Soar
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallDir      = "C:\Program Files\AISAC"
$ConfigDir       = "C:\ProgramData\AISAC"
$CertDir         = "C:\ProgramData\AISAC\certs"
$LogDir          = "C:\ProgramData\AISAC\logs"
$DataDir         = "C:\ProgramData\AISAC\data"
$BinaryName      = "aisac-agent.exe"
$ServiceName     = "AISACAgent"
$ServerService   = "AISACServer"
$ServerBinary    = "aisac-server.exe"
$RegisterOutput  = "C:\Windows\Temp\aisac-register.json"

$DefaultServerUrl = "wss://localhost:8443/ws"

function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok      { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

#------------------------------------------------------------------------------
# Load config from agent-register response
#------------------------------------------------------------------------------

function Get-RegisterConfig {
    if (-not (Test-Path $RegisterOutput)) {
        Write-Fail "Register output not found: $RegisterOutput"
        Write-Fail "Run install-wazuh-agent.ps1 first"
        exit 1
    }

    $data = Get-Content $RegisterOutput -Raw | ConvertFrom-Json

    $script:ApiKey       = $data.aisac.api_key
    $script:AuthToken    = if ($data.aisac.PSObject.Properties["auth_token"]) { $data.aisac.auth_token } else { "" }
    $script:AssetId      = $data.asset_id
    $script:HeartbeatUrl = $data.aisac.heartbeat_url
    $script:IngestUrl    = $data.aisac.ingest_url
    $script:TenantId     = $data.tenant_id
    $script:WazuhAgentName = if ($data.wazuh -and $data.wazuh.PSObject.Properties["agent_name"]) { $data.wazuh.agent_name } else { "" }
    $script:WazuhAgentId   = if ($data.wazuh -and $data.wazuh.PSObject.Properties["agent_id"]) { $data.wazuh.agent_id } else { "" }

    if (-not $script:ApiKey -or -not $script:AssetId) {
        Write-Fail "Missing api_key or asset_id in $RegisterOutput"
        exit 1
    }

    # ── Validate and fix URLs ──
    # The install-config edge function sometimes returns incorrect endpoints.
    # Ensure heartbeat -> agent-heartbeat and ingest -> syslog-ingest.

    if ($script:HeartbeatUrl -and $script:HeartbeatUrl -notmatch "agent-heartbeat") {
        $baseUrl = $script:HeartbeatUrl -replace '/functions/v1/.*', '/functions/v1'
        $script:HeartbeatUrl = "$baseUrl/agent-heartbeat"
        Write-Warn "Corrected heartbeat URL to: $($script:HeartbeatUrl)"
    }

    if ($script:IngestUrl -and $script:IngestUrl -notmatch "syslog-ingest") {
        $baseUrl = $script:IngestUrl -replace '/functions/v1/.*', '/functions/v1'
        $script:IngestUrl = "$baseUrl/syslog-ingest"
        Write-Warn "Corrected ingest URL to: $($script:IngestUrl)"
    }

    if (-not $script:IngestUrl) {
        $baseUrl = $script:HeartbeatUrl -replace '/functions/v1/.*', '/functions/v1'
        $script:IngestUrl = "$baseUrl/syslog-ingest"
        Write-Warn "Ingest URL was empty, derived: $($script:IngestUrl)"
    }

    Write-Ok "Config loaded from $RegisterOutput"
    Write-Info "  Asset ID:      $($script:AssetId)"
    Write-Info "  Tenant ID:     $($script:TenantId)"
    Write-Info "  Heartbeat URL: $($script:HeartbeatUrl)"
    Write-Info "  Ingest URL:    $($script:IngestUrl)"
}

#------------------------------------------------------------------------------
# Agent ID management
#------------------------------------------------------------------------------

function Get-OrCreateAgentId {
    $idFile = Join-Path $DataDir "agent-id"

    # Override via env var
    if ($env:AISAC_AGENT_ID) {
        Write-Info "Using Agent ID from AISAC_AGENT_ID env var"
        $env:AISAC_AGENT_ID | Set-Content -Path $idFile -Encoding UTF8
        return $env:AISAC_AGENT_ID
    }

    # Reuse persisted ID
    if (Test-Path $idFile) {
        $existingId = (Get-Content $idFile -Raw).Trim()
        if ($existingId) {
            Write-Info "Reusing existing Agent ID from $idFile"
            return $existingId
        }
    }

    # Generate new
    $hostname = $env:COMPUTERNAME.ToLower() -replace '[^a-z0-9-]', '-'
    if ($hostname.Length -gt 20) { $hostname = $hostname.Substring(0, 20) }
    $random = -join ((97..122) + (48..57) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $newId = "agent-$hostname-$random"
    $newId | Set-Content -Path $idFile -Encoding UTF8
    Write-Info "Generated new Agent ID: $newId"
    return $newId
}

#------------------------------------------------------------------------------
# Create directories
#------------------------------------------------------------------------------

function New-Directories {
    Write-Info "Creating directories..."
    @($InstallDir, $ConfigDir, $CertDir, $LogDir, $DataDir) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
    Write-Ok "Directories created"
}

#------------------------------------------------------------------------------
# Install binary
#------------------------------------------------------------------------------

function Install-Binary {
    Write-Info "Installing AISAC Agent binary..."

    $binaryPath = Join-Path $InstallDir $BinaryName

    # Stop service if running
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }

    # Option 1: Local binary
    $localBinary = Join-Path $PSScriptRoot "aisac-agent-windows-amd64.exe"
    if (Test-Path $localBinary) {
        Copy-Item $localBinary $binaryPath -Force
        Write-Ok "Binary copied from local path"
        return
    }

    # Option 2: Download from GitHub Releases
    $downloadUrl = "https://github.com/CISECSL/aisac-agent/releases/latest/download/aisac-agent-windows-amd64.exe"
    Write-Info "Downloading from: $downloadUrl"
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath -UseBasicParsing
        Write-Ok "Binary downloaded"
    } catch {
        Write-Fail "Failed to download binary: $_"
        exit 1
    }
}

#------------------------------------------------------------------------------
# SOAR: Certificate Generation (mTLS)
#------------------------------------------------------------------------------

function New-Certificates {
    param([string]$CertPath, [string]$ServerHostname)

    Write-Info "Generating mTLS certificates for SOAR mode..."

    if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
        Write-Fail "OpenSSL is required but not found in PATH"
        Write-Fail "Install OpenSSL or add it to PATH"
        exit 1
    }

    $days = 365
    $caSubject  = "/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=AISAC CA"
    $agentSubject = "/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=$($script:AgentId)"

    if (-not (Test-Path $CertPath)) {
        New-Item -ItemType Directory -Path $CertPath -Force | Out-Null
    }

    # Remove old certs for clean state
    foreach ($f in @("ca.crt","ca.key","ca.srl","agent.crt","agent.key","server.crt","server.key")) {
        $fp = Join-Path $CertPath $f
        if (Test-Path $fp) { Remove-Item $fp -Force }
    }

    # Generate CA
    Write-Info "Generating CA key..."
    & openssl genrsa -out (Join-Path $CertPath "ca.key") 4096 2>$null

    Write-Info "Generating CA certificate..."
    & openssl req -new -x509 -days $days -key (Join-Path $CertPath "ca.key") `
        -out (Join-Path $CertPath "ca.crt") -subj $caSubject 2>$null

    # Generate agent certificate
    Write-Info "Generating agent key..."
    & openssl genrsa -out (Join-Path $CertPath "agent.key") 2048 2>$null

    & openssl req -new -key (Join-Path $CertPath "agent.key") `
        -out (Join-Path $CertPath "agent.csr") -subj $agentSubject 2>$null

    $agentExt = Join-Path $CertPath "agent.ext"
    @"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"@ | Set-Content -Path $agentExt -Encoding ASCII

    Write-Info "Generating agent certificate..."
    & openssl x509 -req -in (Join-Path $CertPath "agent.csr") `
        -CA (Join-Path $CertPath "ca.crt") -CAkey (Join-Path $CertPath "ca.key") -CAcreateserial `
        -out (Join-Path $CertPath "agent.crt") -days $days `
        -extfile $agentExt 2>$null

    # Generate server certificates if hostname provided
    if ($ServerHostname) {
        $serverSubject = "/C=ES/ST=Madrid/L=Madrid/O=AISAC/OU=Security/CN=$ServerHostname"

        Write-Info "Generating server key..."
        & openssl genrsa -out (Join-Path $CertPath "server.key") 2048 2>$null

        & openssl req -new -key (Join-Path $CertPath "server.key") `
            -out (Join-Path $CertPath "server.csr") -subj $serverSubject 2>$null

        $serverExt = Join-Path $CertPath "server.ext"
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
"@ | Set-Content -Path $serverExt -Encoding ASCII

        & openssl x509 -req -in (Join-Path $CertPath "server.csr") `
            -CA (Join-Path $CertPath "ca.crt") -CAkey (Join-Path $CertPath "ca.key") -CAcreateserial `
            -out (Join-Path $CertPath "server.crt") -days $days `
            -extfile $serverExt 2>$null

        Remove-Item (Join-Path $CertPath "server.csr"), $serverExt -Force -ErrorAction SilentlyContinue
    }

    # Clean up
    Remove-Item (Join-Path $CertPath "agent.csr"), $agentExt -Force -ErrorAction SilentlyContinue
    Get-ChildItem $CertPath -Filter "*.srl" | Remove-Item -Force -ErrorAction SilentlyContinue

    Write-Ok "Certificates generated in $CertPath"
}

function Test-Certificates {
    param([string]$CertPath)

    foreach ($f in @("ca.crt", "agent.crt", "agent.key")) {
        if (-not (Test-Path (Join-Path $CertPath $f))) {
            Write-Fail "Missing: $f"
            return $false
        }
    }

    $result = & openssl verify -CAfile (Join-Path $CertPath "ca.crt") (Join-Path $CertPath "agent.crt") 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Agent certificate verification failed"
        return $false
    }

    if (Test-Path (Join-Path $CertPath "server.crt")) {
        $result = & openssl verify -CAfile (Join-Path $CertPath "ca.crt") (Join-Path $CertPath "server.crt") 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Server certificate verification failed"
            return $false
        }
        Write-Ok "Server certificate verified"
    }

    Write-Ok "Agent certificate verified"
    return $true
}

#------------------------------------------------------------------------------
# SOAR: Command Server Installation
#------------------------------------------------------------------------------

function New-ApiToken {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes) -replace '[^a-zA-Z0-9]', '' | Select-Object -First 1
}

function Install-CommandServer {
    param([string]$ApiToken)

    Write-Info "Installing AISAC Command Server..."

    $serverPath = Join-Path $InstallDir $ServerBinary
    $nssmPath   = Join-Path $InstallDir "nssm.exe"

    # Download server binary if not present
    if (-not (Test-Path $serverPath)) {
        $downloadUrl = "https://github.com/CISECSL/aisac-agent/releases/latest/download/aisac-server-windows-amd64.exe"
        Write-Info "Downloading from: $downloadUrl"
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $serverPath -UseBasicParsing
            Write-Ok "Command server binary downloaded"
        } catch {
            Write-Fail "Failed to download command server: $_"
            return $false
        }
    }

    # Download NSSM if not present
    if (-not (Test-Path $nssmPath)) {
        Write-Info "Downloading NSSM (service wrapper)..."
        $nssmZip = "$env:TEMP\nssm.zip"
        $nssmUrls = @(
            "https://nssm.cc/release/nssm-2.24.zip",
            "https://github.com/nicehash/nssm/releases/download/v2.24/nssm-2.24.zip"
        )

        $downloaded = $false
        foreach ($nssmUrl in $nssmUrls) {
            try {
                Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 15
                $downloaded = $true
                break
            } catch {
                Write-Info "Failed, trying next source..."
            }
        }

        if (-not $downloaded) {
            Write-Fail "Failed to download NSSM"
            return $false
        }

        Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm" -Force
        $nssmExe = Get-ChildItem "$env:TEMP\nssm" -Filter "nssm.exe" -Recurse `
            | Where-Object { $_.FullName -like "*win64*" } | Select-Object -First 1
        Copy-Item $nssmExe.FullName $nssmPath -Force
        Remove-Item $nssmZip, "$env:TEMP\nssm" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "NSSM downloaded"
    }

    # Remove existing server service
    $existing = Get-Service -Name $ServerService -ErrorAction SilentlyContinue
    if ($existing) {
        if ($existing.Status -eq "Running") {
            Stop-Service -Name $ServerService -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        & $nssmPath remove $ServerService confirm 2>$null
        Start-Sleep -Seconds 2
    }

    # Install service
    $certDir_fwd = $CertDir.Replace('\', '/')
    $serverArgs = "--listen :8443 --cert `"$CertDir\server.crt`" --key `"$CertDir\server.key`" --ca `"$CertDir\ca.crt`" --api-token $ApiToken --api-mtls=false --log-level info"
    & $nssmPath install $ServerService $serverPath $serverArgs
    & $nssmPath set $ServerService DisplayName "AISAC Command Server (SOAR)"
    & $nssmPath set $ServerService Description "AISAC Command Server - receives SOAR commands from platform"
    & $nssmPath set $ServerService Start SERVICE_AUTO_START
    & $nssmPath set $ServerService AppStdout (Join-Path $LogDir "server-stdout.log")
    & $nssmPath set $ServerService AppStderr (Join-Path $LogDir "server-stderr.log")

    # Save API token
    $tokenFile = Join-Path $ConfigDir "server-api-token"
    $ApiToken | Set-Content -Path $tokenFile -Encoding UTF8
    Write-Info "API token saved to $tokenFile"

    Write-Ok "Command server service installed"
    return $true
}

function Start-CommandServer {
    Write-Info "Starting command server..."
    Start-Service -Name $ServerService
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name $ServerService -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Command server is running"
    } else {
        Write-Fail "Failed to start command server"
        Write-Info "Check logs at: $LogDir"
    }
}

#------------------------------------------------------------------------------
# SOAR: Agent registration with platform
#------------------------------------------------------------------------------

function Register-Agent {
    param(
        [string]$AgentId,
        [string]$ApiKeyVal,
        [string]$AssetIdVal,
        [string]$RegisterUrl,
        [string]$CsToken = "",
        [string]$CsUrl = "",
        [string]$AuthTokenVal = ""
    )

    Write-Info "Registering agent with AISAC platform..."

    $hostname = $env:COMPUTERNAME
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
    $osVersion = [System.Environment]::OSVersion.Version.ToString()
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress

    $capabilities = @("collector", "heartbeat")
    if ($CsToken) { $capabilities = @("collector", "soar", "heartbeat") }

    $body = @{
        event = "agent_registered"
        asset_id = $AssetIdVal
        agent_info = @{
            agent_id = $AgentId
            hostname = $hostname
            os = "windows"
            os_version = $osVersion
            arch = $arch
            kernel = ""
            ip_address = $ipAddress
            version = "1.0.5"
            capabilities = $capabilities
        }
    }

    if ($CsToken) {
        $body["command_server_token"] = $CsToken
        $body["command_server_url"] = $CsUrl
    }

    # Add Wazuh agent mapping (matches Linux behavior)
    if ($script:WazuhAgentName) {
        $body["integration_config"] = @{
            wazuh_agent_name = $script:WazuhAgentName
            wazuh_agent_id = if ($script:WazuhAgentId) { $script:WazuhAgentId } else { "" }
        }
    }

    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Key" = $ApiKeyVal
        }
        if ($AuthTokenVal) {
            $headers["Authorization"] = "Bearer $AuthTokenVal"
        }
        $jsonBody = $body | ConvertTo-Json -Depth 5
        $response = Invoke-RestMethod -Uri $RegisterUrl -Method POST -Headers $headers -Body $jsonBody
        Write-Ok "Agent registered successfully"
    } catch {
        Write-Warn "Registration returned error: $($_.Exception.Message). Continuing."
    }
}

#------------------------------------------------------------------------------
# Generate config (supports both standard and SOAR modes)
#------------------------------------------------------------------------------

function New-Config {
    Write-Info "Generating configuration..."

    $script:AgentId = Get-OrCreateAgentId
    Write-Info "Agent ID: $($script:AgentId)"

    $configPath = Join-Path $ConfigDir "agent.yaml"

    # Detect log sources (Windows paths)
    $enableSuricata = $false
    $suricataPath   = ""
    $enableWazuh    = $false
    $wazuhPath      = ""
    $enableSysmon   = $false
    $enableWinevt   = $false
    $collectorEnabled = $false

    # Suricata
    $suricataCheck = "C:\Program Files\Suricata\log\eve.json"
    if (Test-Path $suricataCheck) {
        $enableSuricata = $true
        $suricataPath = $suricataCheck.Replace('\', '/')
        $collectorEnabled = $true
        Write-Ok "Detected: Suricata EVE logs"
    }

    # Wazuh alerts (local agent alerts)
    $wazuhCheck = "C:\Program Files (x86)\ossec-agent\logs\alerts\alerts.json"
    if (Test-Path $wazuhCheck) {
        $enableWazuh = $true
        $wazuhPath = $wazuhCheck.Replace('\', '/')
        $collectorEnabled = $true
        Write-Ok "Detected: Wazuh alerts"
    }

    # SOAR variables
    $serverEnabled = "false"
    $serverUrl     = $DefaultServerUrl
    $tlsEnabled    = "false"

    if ($Soar) {
        $serverEnabled = "true"
        $tlsEnabled    = "true"
    }

    $certDir_fwd = $CertDir.Replace('\', '/')
    $dataDir_fwd = $DataDir.Replace('\', '/')
    $logDir_fwd  = $LogDir.Replace('\', '/')

    # Derive registration URL from heartbeat URL
    $registerUrl = ""
    if ($script:HeartbeatUrl) {
        $registerUrl = $script:HeartbeatUrl -replace '/functions/v1/.*', '/functions/v1/agent-webhook'
    }

    # ── Base config ──
    $config = @"
# AISAC Agent Configuration
# Generated by installer on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

agent:
  id: "$($script:AgentId)"
  labels:
    - production
  heartbeat_interval: 30s
  reconnect_delay: 5s
  max_reconnect_delay: 5m

server:
  enabled: $serverEnabled
  url: "$serverUrl"
  connect_timeout: 30s
  write_timeout: 10s
  read_timeout: 60s

tls:
  enabled: $tlsEnabled
  cert_file: "$certDir_fwd/agent.crt"
  key_file: "$certDir_fwd/agent.key"
  ca_file: "$certDir_fwd/ca.crt"
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
"@

    # Rate limits only in SOAR mode
    if ($Soar) {
        $config += @"

  rate_limits:
    block_ip:
      max_per_minute: 10
      max_per_hour: 100
    isolate_host:
      max_per_minute: 1
      max_per_hour: 5
"@
    }

    $config += @"

  default_timeout: 5m

callback:
  enabled: false
  url: ""
  auth_token: ""
  timeout: 30s
  retry_attempts: 3
  retry_delay: 5s

heartbeat:
  enabled: true
  url: "$($script:HeartbeatUrl)"
  api_key: "$($script:ApiKey)"
  auth_token: "$($script:AuthToken)"
  asset_id: "$($script:AssetId)"
  interval: 120s
  timeout: 10s
  skip_tls_verify: false

registration:
  enabled: true
  url: "$registerUrl"
  api_key: "$($script:ApiKey)"
  asset_id: "$($script:AssetId)"
  command_server_url: "$($script:PublicServerUrl)"
  command_server_token: "$($script:ServerApiToken)"

collector:
  enabled: $($collectorEnabled.ToString().ToLower())
"@

    # ── Collector sources ──
    if ($collectorEnabled) {
        $config += @"

  sources:
"@

        if ($enableSuricata) {
            $config += @"

    - name: suricata
      type: file
      path: $suricataPath
      parser: suricata_eve
      tags:
        - security
        - ids
"@
        }

        if ($enableWazuh) {
            $config += @"

    - name: wazuh
      type: file
      path: $wazuhPath
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
    url: "$($script:IngestUrl)"
    api_key: "$($script:ApiKey)"
    auth_token: "$($script:AuthToken)"
    asset_id: "$($script:AssetId)"
    timeout: 30s
    retry_attempts: 3
    retry_delay: 5s
    skip_tls_verify: false

  batch:
    size: 100
    interval: 5s

  file:
    start_position: end
    sincedb_path: $dataDir_fwd/sincedb.json
"@
    }

    # ── Control plane ──
    $heartbeatDomain = ""
    try { $heartbeatDomain = ([System.Uri]$script:HeartbeatUrl).Host } catch {}
    if (-not $heartbeatDomain) { $heartbeatDomain = "api.aisac.cisec.es" }

    $controlPlaneIps = "    # Add your control plane IPs here`n    # - `"10.0.0.1`""

    $config += @"

control_plane:
  ips:
$controlPlaneIps
  domains:
    - "$heartbeatDomain"
  always_allowed: true

safety:
  state_file: "$dataDir_fwd/safety_state.json"
  auto_revert_enabled: true
  default_ttl: 1h
  action_ttls:
    isolate_host: 30m
    block_ip: 4h
    disable_user: 2h
  heartbeat_failure_threshold: 5
  recovery_actions:
    - unisolate_host
    - unblock_all_ips

logging:
  level: "info"
  format: "json"
  output: "file"
  file: "$logDir_fwd/agent.log"
"@

    $config | Set-Content -Path $configPath -Encoding UTF8
    Write-Ok "Configuration saved to $configPath"
}

#------------------------------------------------------------------------------
# Install Windows Service using NSSM
#------------------------------------------------------------------------------

function Install-AgentService {
    Write-Info "Installing AISAC Agent as Windows Service..."

    $binaryPath = Join-Path $InstallDir $BinaryName
    $configPath = Join-Path $ConfigDir "agent.yaml"
    $nssmPath   = Join-Path $InstallDir "nssm.exe"

    # Download NSSM if not present
    if (-not (Test-Path $nssmPath)) {
        Write-Info "Downloading NSSM (service wrapper)..."
        $nssmZip = "$env:TEMP\nssm.zip"
        $nssmUrls = @(
            "https://nssm.cc/release/nssm-2.24.zip",
            "https://github.com/nicehash/nssm/releases/download/v2.24/nssm-2.24.zip"
        )

        $downloaded = $false
        foreach ($nssmUrl in $nssmUrls) {
            try {
                Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing -TimeoutSec 15
                $downloaded = $true
                break
            } catch {
                Write-Info "Failed, trying next source..."
            }
        }

        if (-not $downloaded) {
            Write-Fail "Failed to download NSSM"
            exit 1
        }

        Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm" -Force
        $nssmExe = Get-ChildItem "$env:TEMP\nssm" -Filter "nssm.exe" -Recurse `
            | Where-Object { $_.FullName -like "*win64*" } | Select-Object -First 1
        Copy-Item $nssmExe.FullName $nssmPath -Force
        Remove-Item $nssmZip, "$env:TEMP\nssm" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "NSSM downloaded"
    }

    # Remove existing service
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Info "Removing existing service..."
        if ($existing.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        & $nssmPath remove $ServiceName confirm 2>$null
        Start-Sleep -Seconds 2
    }

    # Install service
    & $nssmPath install $ServiceName $binaryPath "-c `"$configPath`""
    & $nssmPath set $ServiceName DisplayName "AISAC Security Agent"
    & $nssmPath set $ServiceName Description "AISAC SIEM/SOAR Agent - Heartbeat and incident response"
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START
    & $nssmPath set $ServiceName AppStdout (Join-Path $LogDir "service-stdout.log")
    & $nssmPath set $ServiceName AppStderr (Join-Path $LogDir "service-stderr.log")

    Write-Ok "Service installed"
}

#------------------------------------------------------------------------------
# Start service
#------------------------------------------------------------------------------

function Start-AgentService {
    Write-Info "Starting AISAC Agent service..."
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "AISAC Agent is running"
    } else {
        Write-Fail "Failed to start AISAC Agent"
        Write-Info "Check logs at: $LogDir"
        exit 1
    }
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

# Check admin
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Must be run as Administrator"
    exit 1
}

# Load config from install-wazuh-agent.ps1 output
Get-RegisterConfig
New-Directories
Install-Binary

# SOAR setup variables
$script:ServerApiToken  = ""
$script:PublicServerUrl  = ""

if ($Soar) {
    Write-Info "SOAR mode enabled"

    # Get or reuse API token
    $tokenFile = Join-Path $ConfigDir "server-api-token"
    if (Test-Path $tokenFile) {
        $script:ServerApiToken = (Get-Content $tokenFile -Raw).Trim()
        Write-Info "Reusing existing Command Server API token"
    }
    if (-not $script:ServerApiToken) {
        $script:ServerApiToken = New-ApiToken
        Write-Info "Generated new Command Server API token"
    }

    # Auto-detect public URL
    $detectedIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
    if ($detectedIp) {
        $script:PublicServerUrl = "https://${detectedIp}:8443"
        Write-Info "Public CS URL: $($script:PublicServerUrl)"
    }
}

# Generate YAML config
New-Config

if ($Soar) {
    # Generate certificates if not present
    if (-not (Test-Path (Join-Path $CertDir "agent.crt")) -or -not (Test-Path (Join-Path $CertDir "ca.crt"))) {
        New-Certificates -CertPath $CertDir -ServerHostname "localhost"
    } else {
        Write-Info "Existing certificates found in $CertDir"
    }

    # Verify certificates
    if (-not (Test-Certificates -CertPath $CertDir)) {
        Write-Fail "Certificate verification failed"
        exit 1
    }

    # Install and start command server
    Install-CommandServer -ApiToken $script:ServerApiToken
    Start-CommandServer

    # Wait for server to be ready
    Write-Info "Waiting for command server to be ready..."
    Start-Sleep -Seconds 3
}

Install-AgentService
Start-AgentService

# Register agent with platform
$registerUrl = ""
if ($script:HeartbeatUrl) {
    $registerUrl = $script:HeartbeatUrl -replace '/functions/v1/.*', '/functions/v1/agent-webhook'
}
if ($registerUrl) {
    if ($script:ServerApiToken -and $script:PublicServerUrl) {
        Register-Agent -AgentId $script:AgentId -ApiKeyVal $script:ApiKey -AssetIdVal $script:AssetId `
            -RegisterUrl $registerUrl -CsToken $script:ServerApiToken -CsUrl $script:PublicServerUrl `
            -AuthTokenVal $script:AuthToken
    } else {
        Register-Agent -AgentId $script:AgentId -ApiKeyVal $script:ApiKey -AssetIdVal $script:AssetId `
            -RegisterUrl $registerUrl -AuthTokenVal $script:AuthToken
    }
}

# Cleanup temp file
Remove-Item $RegisterOutput -Force -ErrorAction SilentlyContinue

# Summary
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "         AISAC Agent installed successfully!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Config:  $ConfigDir\agent.yaml"
Write-Host "  Logs:    $LogDir\agent.log"
Write-Host "  Status:  Get-Service $ServiceName"

if ($Soar) {
    Write-Host ""
    Write-Host "  SOAR:" -ForegroundColor Cyan
    Write-Host "    Command Server:  Get-Service $ServerService"
    Write-Host "    API Token:       $ConfigDir\server-api-token"
    Write-Host "    Certificates:    $CertDir"
}

Write-Host ""
