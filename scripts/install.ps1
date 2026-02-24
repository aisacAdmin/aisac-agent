# AISAC Agent - Main Installer for Windows
#
# Orchestrates the installation of:
#   1. Wazuh Agent   (via install-wazuh-agent.ps1)
#   2. AISAC Agent   (via install-aisac-agent.ps1)
#
# Usage:
#   .\install.ps1
#   .\install.ps1 -RegisterUrl https://custom-url/functions/v1/agent-register
#
# Non-interactive:
#   $env:AISAC_API_KEY="aisac_xxx"; .\install.ps1
#

param(
    [string]$RegisterUrl = "https://api.aisac.cisec.es/functions/v1/agent-register"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$GitHubRawUrl = "https://raw.githubusercontent.com/aisacAdmin/aisac-agent/main/scripts"

function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok      { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Fail    { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Print-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "            AISAC Agent Installer v2.0 (Windows)               " -ForegroundColor Cyan
    Write-Host "                                                                " -ForegroundColor Cyan
    Write-Host "   Installs: Wazuh Agent + AISAC Agent                         " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Check-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fail "Must be run as Administrator"
        Write-Info "Right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
}

function Get-Scripts {
    @("install-wazuh-agent.ps1", "install-aisac-agent.ps1") | ForEach-Object {
        $path = Join-Path $ScriptDir $_
        if (-not (Test-Path $path)) {
            Write-Info "Downloading $_..."
            try {
                Invoke-WebRequest -Uri "$GitHubRawUrl/$_" -OutFile $path -UseBasicParsing
                Write-Ok "Downloaded $_"
            } catch {
                Write-Fail "Failed to download $_`: $($_.Exception.Message)"
                exit 1
            }
        }
    }
    Write-Ok "Scripts ready"
}

function Get-ApiKey {
    # Use environment variable if set (non-interactive)
    if ($env:AISAC_API_KEY) {
        Write-Info "Using API Key from environment"
        return $env:AISAC_API_KEY
    }

    Write-Host ""
    Write-Host "--- AISAC Platform Credentials ---" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "You need the API Key from the AISAC Platform:" -ForegroundColor Cyan
    Write-Host "  Platform > Assets > [Your Asset] > API Key" -ForegroundColor Cyan
    Write-Host ""
    $apiKey = Read-Host "API Key"

    if (-not $apiKey) {
        Write-Fail "API Key is required"
        exit 1
    }

    return $apiKey
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

# Allow running scripts in this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Print-Banner
Check-Admin
Get-Scripts

Write-Info "Register URL: $RegisterUrl"

$ApiKey = Get-ApiKey

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Step 1/2: Installing Wazuh Agent                              " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

try {
    & (Join-Path $ScriptDir "install-wazuh-agent.ps1") -ApiKey $ApiKey -RegisterUrl $RegisterUrl
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Exit code: $LASTEXITCODE" }
} catch {
    Write-Fail "Wazuh Agent installation failed: $($_.Exception.Message)"
    Write-Fail "Common issues:"
    Write-Fail "  - Invalid API Key"
    Write-Fail "  - Register URL unreachable: $RegisterUrl"
    Write-Fail "  - Wazuh Manager ports (1514/1515) not open"
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Step 2/2: Installing AISAC Agent                              " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

try {
    & (Join-Path $ScriptDir "install-aisac-agent.ps1")
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Exit code: $LASTEXITCODE" }
} catch {
    Write-Fail "AISAC Agent installation failed: $($_.Exception.Message)"
    Write-Fail "Check the error above."
    exit 1
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "               Installation complete!                           " -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Wazuh Agent:   Get-Service WazuhSvc"
Write-Host "  AISAC Agent:   Get-Service AISACAgent"
Write-Host "  AISAC Logs:    C:\ProgramData\AISAC\logs\agent.log"
Write-Host ""
