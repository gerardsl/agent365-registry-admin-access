#Requires -Version 7.2
<#
.SYNOPSIS
    Checks, without changing any data, whether the identity you sign in with can read and update Microsoft Agent 365
    agent registrations.

.DESCRIPTION
    For each registration ID:
      1. Read: GET /beta/copilot/agentRegistrations/{id}.
      2. Write: PATCH /beta/copilot/agentRegistrations/{id} with an empty body ({}). The API applies the same
         authorization as for a real change (403 "Access is denied to update the agent registration" when you don't
         have access), but an empty PATCH doesn't change any property. It works even if you can't read the registration.

    Shows a table with the results and saves the evidence as JSON (identity, permissions and roles in the token, and
    for each call the HTTP status, error message, request-id and date), which is useful for a support case.

    Sign-in: the same parameters as Connect-AgentRegistryGraph (browser, certificate or token). Without sign-in
    parameters, it reuses the session already open in this PowerShell window or opens the browser.

.PARAMETER Id
    Registration IDs. A registration's ID is its sourceAgentId (see the README).

.PARAMETER ReadOnly
    Only checks read access (doesn't send the empty PATCH).

.PARAMETER OutputPath
    Evidence JSON file. Default: .\output\write-access-<date>.json

.PARAMETER PassThru
    Also returns the results as objects.

.EXAMPLE
    .\Test-AgentRegistrationWriteAccess.ps1 -Id 'my-agent-1','my-agent-2' -TenantId contoso.onmicrosoft.com
    Delegated: sign in in the browser with the account you want to test (for example, one with the AI Administrator role).

.EXAMPLE
    .\Test-AgentRegistrationWriteAccess.ps1 -Id 'my-agent-1' -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
    App-only, with the certificate of the application created with New-AgentRegistryAdminApp.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('RegistrationId')]
    [string[]]$Id,

    [switch]$ReadOnly,

    [string]$OutputPath,

    [switch]$PassThru,

    [string]$TenantId,
    [string]$ClientId,
    [string[]]$Scopes,
    [string]$LoginHint,
    [switch]$PrivateBrowser,
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [object]$CertificatePassword,
    [object]$AccessToken
)

begin {
    $ErrorActionPreference = 'Stop'
    Import-Module (Join-Path $PSScriptRoot 'AgentRegistry.psm1')
    $ids = [System.Collections.Generic.List[string]]::new()
}

process {
    foreach ($item in $Id) { if (-not [string]::IsNullOrWhiteSpace($item)) { $ids.Add($item.Trim()) } }
}

end {
    $context = Initialize-AgentRegistryConnection -BoundParameters $PSBoundParameters

    function New-CallResult([int]$Status, [object]$Detail) {
        [ordered]@{
            status       = $Status
            errorCode    = $Detail.ErrorCode
            errorMessage = $Detail.ErrorMessage
            requestId    = $Detail.RequestId
            date         = $Detail.Date
        }
    }

    # The Agent Registration API wraps service errors as JSON text inside error.message.
    function Get-ShortMessage([string]$Message) {
        if (-not $Message) { return $null }
        try { $inner = $Message | ConvertFrom-Json -ErrorAction Stop; if ($inner.message) { return $inner.message }; if ($inner.title) { return $inner.title } } catch { $null = $_ }
        return $Message
    }

    $results = foreach ($registrationId in ($ids | Select-Object -Unique)) {
        $row = [ordered]@{
            id = $registrationId; displayName = $null; ownerIds = @(); createdBy = $null; managedByAppId = $null
            callerIsOwner = $null; read = $null; write = $null; result = $null
        }

        try {
            $registration = Get-AgentRegistration -Id $registrationId
            $row.read = New-CallResult 200 $null
            $row.displayName = $registration.displayName
            $row.ownerIds = @($registration.ownerIds)
            $row.createdBy = $registration.createdBy
            $row.managedByAppId = $registration.managedByAppId
            $row.callerIsOwner = ($row.ownerIds -contains $context.CallerObjectId) -or
                ([bool]$registration.managedByAppId -and $registration.managedByAppId -eq $context.ClientId)
        }
        catch {
            $detail = Get-AgentRegistryErrorDetail $_
            $row.read = New-CallResult $detail.StatusCode $detail
        }

        if (-not $ReadOnly) {
            try {
                $null = Invoke-AgentRegistryGraph -Method PATCH -Uri "/beta/copilot/agentRegistrations/$([uri]::EscapeDataString($registrationId))" -Body @{}
                $row.write = New-CallResult 200 $null
            }
            catch {
                $detail = Get-AgentRegistryErrorDetail $_
                $row.write = New-CallResult $detail.StatusCode $detail
            }
        }

        $row.result = if ($row.read.status -eq 404 -or $row.write.status -eq 404) { 'Not found' }
        elseif ($ReadOnly) { if ($row.read.status -eq 200) { 'Can read' } elseif ($row.read.status -eq 403) { 'Read denied' } else { 'Error' } }
        elseif ($row.write.status -eq 200) { 'Can update' }
        elseif ($row.write.status -eq 403) { 'Update denied' }
        else { 'Error' }
        [pscustomobject]$row
    }

    Write-Host ''
    $knownRoles = @($context.DirectoryRoles | Where-Object { $_ -notmatch '^[0-9a-f]{8}-' })
    $otherRoles = @($context.DirectoryRoles).Count - $knownRoles.Count
    $rolesText = if ($context.TokenType -eq 'Application') { 'n/a (application token)' } elseif ($knownRoles) { $knownRoles -join ', ' } else { '(none)' }
    if ($otherRoles -gt 0 -and $context.TokenType -ne 'Application') { $rolesText += " (+$otherRoles)" }
    Write-Host ("Identity: {0} | Token: {1} | Roles: {2}" -f $context.Caller, $context.TokenType, $rolesText) -ForegroundColor Cyan
    $results | Format-Table -Wrap -Property `
    @{ Name = 'Registration'; Width = 38; Expression = { if ($_.displayName) { $_.displayName } else { $_.id } } },
    @{ Name = 'Owner'; Width = 5; Expression = { if ($null -eq $_.callerIsOwner) { '?' } elseif ($_.callerIsOwner) { 'Yes' } else { 'No' } } },
    @{ Name = 'GET'; Width = 4; Expression = { $_.read.status } },
    @{ Name = 'PATCH'; Width = 5; Expression = { if ($_.write) { $_.write.status } else { '-' } } },
    @{ Name = 'Result'; Width = 16; Expression = { $_.result } },
    @{ Name = 'Error'; Width = 50; Expression = { Get-ShortMessage $(if ($_.write -and $_.write.status -ne 200) { $_.write.errorMessage } elseif ($_.read.status -ne 200) { $_.read.errorMessage }) } } |
        Out-Host

    if (-not $OutputPath) { $OutputPath = Join-Path (Join-Path (Get-Location) 'output') "write-access-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" }
    $fullOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $fullOutput)
    [ordered]@{
        tool        = 'Test-AgentRegistrationWriteAccess.ps1'
        generatedAt = (Get-Date).ToUniversalTime().ToString('o')
        writeProbe  = if ($ReadOnly) { 'none' } else { 'PATCH {} (empty body, no data change)' }
        identity    = [ordered]@{
            tenantId = $context.TenantId; caller = $context.Caller; callerObjectId = $context.CallerObjectId
            tokenType = $context.TokenType; clientId = $context.ClientId; clientName = $context.ClientName
            permissions = $context.Permissions; directoryRoles = $context.DirectoryRoles
        }
        results     = @($results)
    } | ConvertTo-Json -Depth 10 | Set-Content -Path $fullOutput -Encoding utf8
    Write-Host "Evidence: $fullOutput"

    if ($PassThru) { $results }
}
