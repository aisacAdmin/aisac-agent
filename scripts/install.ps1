<#
.SYNOPSIS
    AISAC Installer — Orchestrator for Windows

.DESCRIPTION
    Installs Wazuh Agent + AISAC Agent by delegating to sub-scripts.

.PARAMETER ApiKey
    API Key from AISAC Platform (format: aisac_xxxx)

.PARAMETER AuthToken
    Supabase JWT anon key (for API gateway auth)

.PARAMETER ManagerIp
    Wazuh Manager IP address

.PARAMETER ConfigUrl
    install-config edge function URL (optional)

.PARAMETER Soar
    Enable SOAR mode (Command Server + mTLS certs)

.PARAMETER Uninstall
    Uninstall AISAC Agent, Command Server, and Wazuh Agent

.EXAMPLE
    .\install.ps1 -ApiKey aisac_xxxx -AuthToken eyJhbG... -ManagerIp 13.49.226.17

.EXAMPLE
    .\install.ps1 -ApiKey aisac_xxxx -AuthToken eyJhbG... -ManagerIp 13.49.226.17 -Soar

.EXAMPLE
    .\install.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [string]$ApiKey,
    [string]$AuthToken,
    [string]$ManagerIp,
    [string]$ConfigUrl = "https://api.aisac.cisec.es/functions/v1/install-config",
    [switch]$Soar,
    [switch]$Uninstall,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Constants ───
$INSTALL_DIR    = "$env:ProgramFiles\AISAC"
$CONFIG_DIR     = "$env:ProgramData\AISAC"
$DATA_DIR       = "$env:ProgramData\AISAC\data"
$LOG_DIR        = "$env:ProgramData\AISAC\logs"
$SERVICE_NAME   = "AISACAgent"
$SERVER_SERVICE = "AISACServer"

function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok      { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Show-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "              AISAC Installer v2.0                              " -ForegroundColor Cyan
    Write-Host "              Installs: Wazuh Agent + AISAC Agent               " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Usage {
    Write-Host "Usage: .\install.ps1 -ApiKey <KEY> -AuthToken <TOKEN> -ManagerIp <IP> [OPTIONS]"
    Write-Host ""
    Write-Host "Required:"
    Write-Host "  -ApiKey <key>        API Key from AISAC Platform (format: aisac_xxxx)"
    Write-Host "  -AuthToken <token>   Supabase JWT anon key (for API gateway auth)"
    Write-Host "  -ManagerIp <ip>      Wazuh Manager IP address"
    Write-Host ""
    Write-Host "Optional:"
    Write-Host "  -ConfigUrl <url>     install-config edge function URL"
    Write-Host "                       (default: https://api.aisac.cisec.es/functions/v1/install-config)"
    Write-Host "  -Soar                Enable SOAR mode (Command Server + mTLS certs)"
    Write-Host "  -Uninstall           Uninstall AISAC Agent, Command Server, and Wazuh Agent"
    Write-Host "  -Help                Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\install.ps1 -ApiKey aisac_xxxx -AuthToken eyJ... -ManagerIp 13.49.226.17"
    Write-Host "  .\install.ps1 -ApiKey aisac_xxxx -AuthToken eyJ... -ManagerIp 13.49.226.17 -Soar"
    Write-Host "  .\install.ps1 -Uninstall"
    Write-Host ""
}

# ─── Uninstall ───

function Stop-AllServices {
    Write-Info "Cleaning up existing AISAC services..."

    foreach ($svcName in @($SERVICE_NAME, $SERVER_SERVICE)) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq "Running") {
                Write-Info "Stopping $svcName..."
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            # Remove via sc.exe
            & sc.exe delete $svcName 2>$null | Out-Null
        }
    }

    # Kill lingering processes
    Get-Process -Name "aisac-agent", "aisac-server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    Write-Ok "AISAC services cleaned up"
}

function Invoke-Uninstall {
    Write-Host ""
    Write-Warn "This will remove AISAC Agent, Command Server, and Wazuh Agent from your system"
    $confirm = Read-Host "Are you sure? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Host "Uninstall cancelled"
        exit 0
    }

    # Clean up AISAC services
    Stop-AllServices

    # Remove AISAC binaries
    Write-Info "Removing AISAC binaries..."
    if (Test-Path $INSTALL_DIR) {
        Remove-Item $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Remove Wazuh Agent
    $wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhSvc) {
        Write-Info "Removing Wazuh Agent..."
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        $wazuhMsi = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "Wazuh Agent*" }
        if ($wazuhMsi) {
            $wazuhMsi.Uninstall() | Out-Null
        } else {
            & sc.exe delete WazuhSvc 2>$null | Out-Null
        }
    }

    # Remove firewall rules
    Get-NetFirewallRule -DisplayName "AISAC_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    $removeConfig = Read-Host "Remove configuration, data, and certificates? (y/N)"
    if ($removeConfig -eq "y" -or $removeConfig -eq "Y") {
        if (Test-Path $CONFIG_DIR) {
            Remove-Item $CONFIG_DIR -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "Configuration, data, and certificates removed"
    } else {
        Write-Info "Configuration preserved in $CONFIG_DIR"
    }

    Write-Ok "AISAC Agent, Command Server, and Wazuh Agent uninstalled"
}

# ─── Main ───

# Check admin
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Must be run as Administrator"
    exit 1
}

if ($Help) {
    Show-Usage
    exit 0
}

if ($Uninstall) {
    Invoke-Uninstall
    exit 0
}

# Validate required params
$missing = $false
if (-not $ApiKey) {
    Write-Fail "API Key is required (-ApiKey)"
    $missing = $true
}
if (-not $AuthToken) {
    Write-Fail "Auth token is required (-AuthToken)"
    $missing = $true
}
if (-not $ManagerIp) {
    Write-Fail "Manager IP is required (-ManagerIp)"
    $missing = $true
}
if ($missing) {
    Write-Host ""
    Show-Usage
    exit 1
}

Show-Banner

# ── Step 1: Install Wazuh Agent ──
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Step 1/2: Installing Wazuh Agent                             " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$wazuhScript = Join-Path $PSScriptRoot "install-wazuh-agent.ps1"
& $wazuhScript -ApiKey $ApiKey -RegisterUrl $ConfigUrl -AuthToken $AuthToken -ManagerIp $ManagerIp

if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    Write-Fail "Wazuh Agent installation failed"
    exit 1
}

# ── Step 2: Install AISAC Agent ──
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Step 2/2: Installing AISAC Agent                             " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$aisacScript = Join-Path $PSScriptRoot "install-aisac-agent.ps1"
if ($Soar) {
    & $aisacScript -Soar
} else {
    & $aisacScript
}

if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
    Write-Fail "AISAC Agent installation failed"
    exit 1
}

# ── Done ──
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "              Installation Complete!                            " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  AISAC Agent:  Get-Service $SERVICE_NAME"
Write-Host "  Wazuh Agent:  Get-Service WazuhSvc"
if ($Soar) {
    Write-Host "  SOAR Server:  Get-Service $SERVER_SERVICE"
}
Write-Host "  Agent Config: $CONFIG_DIR\agent.yaml"
Write-Host "  Agent Logs:   $LOG_DIR\agent.log"
Write-Host ""
