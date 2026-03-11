# AISAC - Wazuh Agent Installer for Windows
#
# Calls the agent-register Edge Function to get tenant config,
# then installs the Wazuh Agent pointing to the centralized Wazuh Manager.
#
# Usage:
#   .\install-wazuh-agent.ps1 -ApiKey <api_key> -RegisterUrl <url> -ManagerIp <ip>
#
# Outputs:
#   C:\Windows\Temp\aisac-register.json  - Used by install-aisac-agent.ps1
#

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [Parameter(Mandatory=$true)]
    [string]$RegisterUrl,

    [Parameter(Mandatory=$true)]
    [string]$ManagerIp,

    [string]$AuthToken = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$WazuhVersion   = "4.14.3"
$RegisterOutput = "C:\Windows\Temp\aisac-register.json"

function Write-Info    { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Ok      { param($msg) Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Fail    { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

#------------------------------------------------------------------------------
# Call agent-register Edge Function
#------------------------------------------------------------------------------

function Invoke-Register {
    Write-Info "Calling agent-register: $RegisterUrl"

    try {
        $headers = @{ "X-API-Key" = $ApiKey }
        if ($AuthToken) {
            $headers["Authorization"] = "Bearer $AuthToken"
        }
        $response = Invoke-RestMethod `
            -Uri $RegisterUrl `
            -Method GET `
            -Headers $headers
    } catch {
        Write-Fail "agent-register failed: $($_.Exception.Message)"
        exit 1
    }

    $response | ConvertTo-Json -Depth 10 | Set-Content -Path $RegisterOutput -Encoding UTF8
    Write-Ok "Registration data received and saved to $RegisterOutput"
    return $response
}

#------------------------------------------------------------------------------
# Install Wazuh Agent
#------------------------------------------------------------------------------

function Install-WazuhAgent {
    param($ManagerIp, $ManagerPort, $AgentGroup, $AgentName)

    Write-Info "Installing Wazuh Agent $WazuhVersion..."
    Write-Info "  Manager:    ${ManagerIp}:${ManagerPort}"
    Write-Info "  Group:      $AgentGroup"
    Write-Info "  Agent name: $AgentName"

    $msiUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${WazuhVersion}-1.msi"
    $msiPath = "$env:TEMP\wazuh-agent.msi"

    Write-Info "Downloading Wazuh Agent MSI..."
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

    Write-Info "Installing Wazuh Agent..."
    $msiArgs = @(
        "/i", $msiPath,
        "/q",
        "WAZUH_MANAGER=`"$ManagerIp`"",
        "WAZUH_MANAGER_PORT=`"$ManagerPort`"",
        "WAZUH_AGENT_NAME=`"$AgentName`"",
        "WAZUH_AGENT_GROUP=`"$AgentGroup`""
    )
    $result = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($result.ExitCode -ne 0) {
        Write-Fail "Wazuh Agent installation failed (exit code: $($result.ExitCode))"
        exit 1
    }

    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue

    Write-Info "Starting Wazuh Agent service..."
    Start-Service -Name "WazuhSvc"
    Start-Sleep -Seconds 3

    $svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Ok "Wazuh Agent is running"
    } else {
        Write-Fail "Wazuh Agent failed to start"
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

# 1. Call agent-register
$data = Invoke-Register

# 2. Parse config (Manager IP comes from CLI parameter)
$managerPort = $data.wazuh.manager_port
$agentGroup  = $data.wazuh.agent_group
$assetName   = if ($data.PSObject.Properties["asset_name"] -and $data.asset_name) { $data.asset_name } else { $env:COMPUTERNAME }
$managerIp   = $ManagerIp

if (-not $agentGroup) {
    Write-Fail "Missing wazuh.agent_group in agent-register response"
    Write-Fail "Response: $($data | ConvertTo-Json -Depth 5 -Compress)"
    exit 1
}

if (-not $managerPort) { $managerPort = 1514 }

Write-Info "Manager:    ${managerIp}:${managerPort}"
Write-Info "Group:      $agentGroup"
Write-Info "Asset name: $assetName"

# 3. Install Wazuh Agent
Install-WazuhAgent -ManagerIp $managerIp -ManagerPort $managerPort `
    -AgentGroup $agentGroup -AgentName $assetName

# 4. Extract Wazuh agent ID and inject metadata into register JSON
$wazuhAgentId = ""
$clientKeysPath = "C:\Program Files (x86)\ossec-agent\client.keys"
if (Test-Path $clientKeysPath) {
    $firstLine = Get-Content $clientKeysPath -TotalCount 1
    if ($firstLine) {
        $firstLine = $firstLine.Trim()
        $wazuhAgentId = ($firstLine -split '\s+')[0]
    }
}

# Inject wazuh.agent_name and wazuh.agent_id into register JSON (matches Linux behavior)
$regData = Get-Content $RegisterOutput -Raw | ConvertFrom-Json
if (-not $regData.wazuh) { $regData | Add-Member -NotePropertyName "wazuh" -NotePropertyValue ([PSCustomObject]@{}) -Force }
$regData.wazuh | Add-Member -NotePropertyName "agent_name" -NotePropertyValue $assetName -Force
$regData.wazuh | Add-Member -NotePropertyName "agent_id" -NotePropertyValue $wazuhAgentId -Force
$regData | ConvertTo-Json -Depth 10 | Set-Content -Path $RegisterOutput -Encoding UTF8

Write-Info "  Wazuh Agent Name: $assetName"
Write-Info "  Wazuh Agent ID:   $(if ($wazuhAgentId) { $wazuhAgentId } else { 'unknown' })"
Write-Ok "Wazuh Agent installed -> Manager: $managerIp | Group: $agentGroup"

# Reset LASTEXITCODE so the caller doesn't see a stale non-zero from msiexec or other native commands
$global:LASTEXITCODE = 0
