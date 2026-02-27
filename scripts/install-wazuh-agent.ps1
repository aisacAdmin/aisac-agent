# AISAC - Wazuh Agent Installer for Windows
#
# Calls the agent-register Edge Function to get tenant config,
# then installs the Wazuh Agent pointing to the centralized Wazuh Manager.
#
# Usage:
#   .\install-wazuh-agent.ps1 -ApiKey <api_key> -RegisterUrl <url>
#
# Outputs:
#   C:\Windows\Temp\aisac-register.json  - Used by install-aisac-agent.ps1
#

param(
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [Parameter(Mandatory=$true)]
    [string]$RegisterUrl
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
        $response = Invoke-RestMethod `
            -Uri $RegisterUrl `
            -Method GET `
            -Headers @{ "X-API-Key" = $ApiKey }
    } catch {
        Write-Fail "agent-register failed: $($_.Exception.Message)"
        exit 1
    }

    $response | ConvertTo-Json -Depth 10 | Set-Content -Path $RegisterOutput -Encoding UTF8
    Write-Ok "Registration data received and saved to $RegisterOutput"
    return $response
}

#------------------------------------------------------------------------------
# Update integration_config in platform (PATCH install-config)
#------------------------------------------------------------------------------

function Update-IntegrationConfig {
    param($AgentName, $AgentId)

    Write-Info "Updating integration_config in platform..."

    $body = @{
        integration_type = "wazuh"
        integration_config = @{
            wazuh_agent_name = $AgentName
            wazuh_agent_id = $AgentId
        }
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod `
            -Uri $RegisterUrl `
            -Method PATCH `
            -Headers @{ "X-API-Key" = $ApiKey; "Content-Type" = "application/json" } `
            -Body $body
        Write-Ok "integration_config updated (agent_name=$AgentName, agent_id=$AgentId)"
    } catch {
        Write-Fail "Failed to update integration_config: $($_.Exception.Message)"
        Write-Info "This is non-fatal. The agent is installed but asset routing may not work."
    }
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

# 2. Parse config
$managerIp   = $data.wazuh.manager_ip
$managerPort = $data.wazuh.manager_port
$agentGroup  = $data.wazuh.agent_group
$assetName   = if ($data.PSObject.Properties["asset_name"] -and $data.asset_name) { $data.asset_name } else { $env:COMPUTERNAME }

if (-not $managerIp -or -not $agentGroup) {
    Write-Fail "Missing wazuh config in agent-register response"
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

# 4. Get Wazuh agent ID assigned by the Manager (retry up to 15s)
$wazuhAgentId = ""
$clientKeysPath = "C:\Program Files (x86)\ossec-agent\client.keys"
for ($attempt = 1; $attempt -le 5; $attempt++) {
    if (Test-Path $clientKeysPath) {
        $firstLine = Get-Content $clientKeysPath -TotalCount 1 -ErrorAction SilentlyContinue
        if ($firstLine -and $firstLine -match "^(\d+)\s") {
            $wazuhAgentId = $Matches[1]
            Write-Info "Wazuh agent ID: $wazuhAgentId"
            break
        }
    }
    if ($attempt -lt 5) {
        Write-Info "Waiting for agent registration... ($attempt/5)"
        Start-Sleep -Seconds 3
    }
}

# 5. Update integration_config in platform so syslog-ingest can route by agent name
Update-IntegrationConfig -AgentName $assetName -AgentId $wazuhAgentId

Write-Ok "Wazuh Agent installed -> Manager: $managerIp | Group: $agentGroup"
