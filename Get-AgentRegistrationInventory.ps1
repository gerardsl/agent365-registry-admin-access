#Requires -Version 7.2
<#
.SYNOPSIS
    Lists the agents in the Microsoft Agent 365 registry with their agent registration ID, their platform and the
    application that manages them, so you know who can update each one.

.DESCRIPTION
    The Agent Registration API has no operation to list registrations. This script uses the Agent 365 Package
    Management API instead:
      GET /beta/copilot/admin/catalog/packages?$filter=elementTypes/any(e:e eq 'AgentMetadatas')
      GET /beta/copilot/admin/catalog/packages/{id}
    and reads, from each package, the registration ID (SourceAgentId) and the managing application (ManagedBy).

    EditableBy column (who can update the registration with the Agent Registration API):
      * No managing application: the registration's owners, or an app-only application with
        AgentRegistration.ReadWrite.All.
      * Managing application (managedByAppId): only that application. Not the owners, not administrators (not even
        Global Administrator) and not other applications.

    Permissions: CopilotPackages.Read.All, delegated (with the AI Administrator or Global Administrator role) or
    application. The Package Management API requires Microsoft Agent 365 licenses in the tenant.

    Returns one object per registration (it can be piped to Test-AgentRegistrationWriteAccess.ps1) and saves a CSV.

.PARAMETER OutputPath
    Output CSV. Default: .\output\agent-registrations-<date>.csv

.PARAMETER CsvDelimiter
    CSV delimiter. Default: ','. Use ';' to open it in Excel with regional settings that use the comma as the
    decimal separator.

.PARAMETER DelayMilliseconds
    Pause between detail calls, to avoid throttling (429). Default: 500 ms.

.EXAMPLE
    .\Get-AgentRegistrationInventory.ps1 -TenantId contoso.onmicrosoft.com
    Delegated, with an account that has the AI Administrator role.

.EXAMPLE
    $app = @{ TenantId = '<tenantId>'; ClientId = '<appId>'; CertificateThumbprint = '<thumbprint>' }
    .\Get-AgentRegistrationInventory.ps1 @app | Where-Object { -not $_.ManagedByAppId } | .\Test-AgentRegistrationWriteAccess.ps1 @app
    App-only: lists the registrations without a managing application and checks that the application can update them.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [ValidateLength(1, 1)]
    [string]$CsvDelimiter = ',',

    [ValidateRange(0, 10000)]
    [int]$DelayMilliseconds = 500,

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

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AgentRegistry.psm1')

# Microsoft first-party apps (global appIds) seen as managing apps of agent registrations.
$KnownManagers = @{
    '0517ffae-825d-4aff-999e-3f2336b8a20a' = 'M365 App Management Service'    # Agent 365 connectors: Amazon Bedrock, Google Vertex AI, Salesforce
    '0736f41a-0425-4b46-bdb5-1563eff02385' = 'Azure Machine Learning'         # Microsoft Foundry
    '59eca866-2f46-40b8-96ff-63f663121ef9' = 'Agent 365'                      # Agent 365 SDK / CLI
    '9d8f559b-5984-46a4-902a-ad4271e83efa' = 'Power Virtual Agents Service'   # Copilot Studio, Microsoft 365 Copilot Agent Builder
}

#region Sign-in (an interactive sign-in also asks for the scopes Test-AgentRegistrationWriteAccess.ps1 needs)
$connect = @{}
foreach ($key in $PSBoundParameters.Keys) { $connect[$key] = $PSBoundParameters[$key] }
$appOrToken = @($connect.Keys | Where-Object { $_ -in 'CertificateThumbprint', 'CertificatePath', 'AccessToken' }).Count -gt 0
$hasSession = $true
try { $null = Get-AgentRegistryContext } catch { $hasSession = $false }
if (-not $appOrToken -and -not $connect.ContainsKey('Scopes') -and ($connect.Count -gt 0 -or -not $hasSession)) {
    $connect.Scopes = @('CopilotPackages.Read.All', 'AgentRegistration.ReadWrite.All')
}
foreach ($key in 'OutputPath', 'CsvDelimiter', 'DelayMilliseconds') { $connect.Remove($key) }
$context = Initialize-AgentRegistryConnection -BoundParameters $connect
if ($context.Permissions -notcontains 'CopilotPackages.Read.All' -and $context.Permissions -notcontains 'CopilotPackages.ReadWrite.All') {
    Write-Warning "The token doesn't include CopilotPackages.Read.All: the Package Management API will return 403."
}
#endregion

#region Packages that come from the agent registry
function Get-AllPage([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-AgentRegistryGraph -Uri $next
        foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
        $next = $page.'@odata.nextLink'
    }
    return , $items.ToArray()
}

try { $packages = Get-AllPage "/beta/copilot/admin/catalog/packages?`$filter=elementTypes/any(e:e eq 'AgentMetadatas')" }
catch {
    $detail = Get-AgentRegistryErrorDetail $_
    if ($detail.StatusCode -ne 400) { throw }
    Write-Verbose 'The elementTypes filter is not supported; filtering locally.'
    $packages = @(Get-AllPage '/beta/copilot/admin/catalog/packages' | Where-Object { $_.elementTypes -contains 'AgentMetadatas' })
}
Write-Host "Packages with agent registry metadata: $($packages.Count)" -ForegroundColor Cyan

$managerNames = @{}
$canResolveApps = $true
function Get-ManagerName([string]$AppId) {
    if (-not $AppId) { return $null }
    if ($KnownManagers.ContainsKey($AppId)) { return $KnownManagers[$AppId] }
    if ($managerNames.ContainsKey($AppId)) { return $managerNames[$AppId] }
    $name = $null
    if ($script:canResolveApps) {
        try { $name = @((Invoke-AgentRegistryGraph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=displayName").value)[0].displayName }
        catch { $script:canResolveApps = $false; Write-Verbose "Can't resolve application names (Application.Read.All is missing)." }
    }
    $managerNames[$AppId] = $name
    return $name
}

$displaySet = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet', [string[]]@('DisplayName', 'Platform', 'RegistrationId', 'EditableBy'))
$standardMembers = [System.Management.Automation.PSMemberInfo[]]@($displaySet)

$index = 0
$inventory = foreach ($package in $packages) {
    $index++
    Write-Progress -Activity 'Reading package details' -Status $package.displayName -PercentComplete (100 * $index / [Math]::Max(1, $packages.Count))
    if ($DelayMilliseconds -gt 0) { Start-Sleep -Milliseconds $DelayMilliseconds }
    try { $detail = Invoke-AgentRegistryGraph -Uri "/beta/copilot/admin/catalog/packages/$([uri]::EscapeDataString($package.id))" }
    catch {
        Write-Warning "Can't read package $($package.id) ($($package.displayName)): $((Get-AgentRegistryErrorDetail $_).ErrorMessage)"
        continue
    }
    $elements = @(@($detail.elementDetails | Where-Object { $_.elementType -eq 'AgentMetadatas' }).elements | Where-Object { $_ })
    foreach ($element in $elements) {
        $definition = $null
        try { $definition = $element.definition | ConvertFrom-Json -Depth 50 } catch { Write-Verbose "Invalid definition in $($package.id)" }
        $managedBy = $definition.ManagedBy
        $managerName = Get-ManagerName $managedBy
        $owners = @($detail.owners | Where-Object { $_.resourceId } | ForEach-Object { $_.resourceId })
        if (-not $owners -and $package.ownerId) { $owners = @($package.ownerId) }
        $row = [pscustomobject]@{
            DisplayName              = $package.displayName
            Platform                 = $package.platform
            RegistrationId           = $definition.SourceAgentId
            ManagedByAppId           = $managedBy
            ManagedBy                = $managerName
            EditableBy               = if ($managedBy) { "Managing app only: $(if ($managerName) { $managerName } else { $managedBy })" } else { 'Owners, or app-only with AgentRegistration.ReadWrite.All' }
            OwnerIds                 = $owners -join ' '
            PackageId                = $package.id
            PackageType              = $package.type
            AgentIdentityId          = $definition.AgentIdentityId
            AgentIdentityBlueprintId = $definition.AgentIdentityBlueprintId
            IsBlocked                = $package.isBlocked
            LastModifiedDateTime     = $package.lastModifiedDateTime
        }
        $row | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $standardMembers
        $row
    }
}
Write-Progress -Activity 'Reading package details' -Completed
#endregion

$inventory = @($inventory)
if (-not $OutputPath) { $OutputPath = Join-Path (Join-Path (Get-Location) 'output') "agent-registrations-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv" }
$fullOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $fullOutput)
$inventory | Export-Csv -Path $fullOutput -Delimiter $CsvDelimiter -Encoding utf8BOM

$managed = @($inventory | Where-Object ManagedByAppId).Count
Write-Host ("Registrations: {0} | without a managing app: {1} | with a managing app: {2}" -f $inventory.Count, ($inventory.Count - $managed), $managed) -ForegroundColor Cyan
$inventory | Group-Object Platform | Sort-Object Count -Descending | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Name, $_.Count) }
Write-Host "CSV: $fullOutput"
$inventory
