#Requires -Version 7.2
<#
.SYNOPSIS
    Updates properties of one or more Microsoft Agent 365 agent registrations and saves a copy of the previous
    values so the change can be undone.

.DESCRIPTION
    For each registration:
      1. Reads the current values (GET).
      2. Works out which properties change. Properties that already have the requested value aren't sent.
      3. Applies the change (PATCH). Supports -WhatIf (simulation) and -Confirm.
      4. Reads the registration again to verify the change.
      5. Saves a JSON snapshot with the previous and new values in the -SnapshotPath folder.
    With -RestoreFrom, it puts back the previous values saved in a snapshot.

    The identity that runs it needs permission to update the registration: an app-only application with the
    AgentRegistration.ReadWrite.All application permission (all registrations without a managing app) or a user who
    owns the registration.

    The "platform" that the Microsoft 365 admin center shows is the registration's originatingStore property.

.PARAMETER Id
    Registration ID. It's the registration's sourceAgentId (see the README).

.PARAMETER DisplayName
    New display name.

.PARAMETER Description
    New description.

.PARAMETER OriginatingStore
    New platform or source system (originatingStore). Examples used by Microsoft: 'Copilot Studio', 'Foundry',
    'GoogleVertexAI', 'AmazonBedrock', 'Salesforce'.

.PARAMETER OwnerIds
    Replaces the whole list of owners (Microsoft Entra object IDs).

.PARAMETER AddOwnerId
    Adds owners without removing the current ones.

.PARAMETER RemoveOwnerId
    Removes owners without changing the rest.

.PARAMETER Property
    Other properties, as a hashtable. Example: @{ managedByAppId = '<appId>' }

.PARAMETER CsvPath
    CSV with one row per registration. Required column: id. Optional columns: displayName, description,
    originatingStore, ownerIds, addOwnerIds, removeOwnerIds, managedByAppId, agentIdentityId,
    agentIdentityBlueprintId, lastPublishedBy. An empty cell doesn't change that property. In the owner columns,
    separate several IDs with spaces or '|'.

.PARAMETER CsvDelimiter
    CSV delimiter. Default: ','. Use ';' for a CSV saved by Excel with regional settings that use the comma as the
    decimal separator.

.PARAMETER RestoreFrom
    JSON snapshot created by this script. Puts back the previous values of the properties that were changed.

.PARAMETER Reason
    Reason for the change (for example, the ticket number). It's saved in the snapshot.

.PARAMETER SnapshotPath
    Snapshot folder. Default: .\snapshots

.PARAMETER PassThru
    Also returns the results as objects.

.EXAMPLE
    .\Set-AgentRegistration.ps1 -Id 'my-agent-1' -Description 'Reviewed by IAM' -Reason 'CHG0001234' -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
    Updates a registration with the app-only application.

.EXAMPLE
    .\Set-AgentRegistration.ps1 -CsvPath .\samples\changes-example.csv -WhatIf -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
    Shows the changes in the CSV without applying them. Remove -WhatIf to apply them.

.EXAMPLE
    .\Set-AgentRegistration.ps1 -Id 'my-agent-1' -AddOwnerId <new-owner-objectId> -RemoveOwnerId <old-owner-objectId> -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
    Reassigns the ownership of a registration.

.EXAMPLE
    .\Set-AgentRegistration.ps1 -RestoreFrom .\snapshots\agentregistration-changes-20261123-101500.json -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
    Undoes the changes of a previous run.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Single')]
param(
    [Parameter(ParameterSetName = 'Single', Mandatory, Position = 0)]
    [string]$Id,

    [Parameter(ParameterSetName = 'Single')]
    [string]$DisplayName,

    [Parameter(ParameterSetName = 'Single')]
    [string]$Description,

    [Parameter(ParameterSetName = 'Single')]
    [string]$OriginatingStore,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$OwnerIds,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$AddOwnerId,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$RemoveOwnerId,

    [Parameter(ParameterSetName = 'Single')]
    [hashtable]$Property,

    [Parameter(ParameterSetName = 'Csv', Mandatory)]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Csv')]
    [ValidateLength(1, 1)]
    [string]$CsvDelimiter = ',',

    [Parameter(ParameterSetName = 'Restore', Mandatory)]
    [string]$RestoreFrom,

    [string]$Reason,

    [string]$SnapshotPath = '.\snapshots',

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

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AgentRegistry.psm1')

# sourceAgentId is not editable here on purpose: it is also the registration ID.
$UpdatableProperties = @('displayName', 'description', 'originatingStore', 'ownerIds', 'managedByAppId', 'agentIdentityId',
    'agentIdentityBlueprintId', 'lastPublishedBy', 'agentCard', 'a2aAuthorization')
$JsonReadParams = @{ Depth = 100 }
if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $JsonReadParams.DateKind = 'String' }

function Resolve-PropertyName([string]$Name) {
    $match = $UpdatableProperties | Where-Object { $_ -eq $Name.Trim() } | Select-Object -First 1
    if (-not $match) { throw "Property '$Name' can't be changed with this script. Supported properties: $($UpdatableProperties -join ', ')." }
    return $match
}

function Split-IdList([object[]]$Value) {
    @($Value | ForEach-Object { "$_" -split '[\s|;,]+' } | Where-Object { $_ })
}

function Test-SameValue([object]$Current, [object]$Desired, [string]$Name) {
    if ($Name -eq 'ownerIds') {
        $a = @($Current | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique) -join '|'
        $b = @($Desired | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique) -join '|'
        return $a -eq $b
    }
    if ($null -eq $Current -and $null -eq $Desired) { return $true }
    if ($Current -is [string] -or $Desired -is [string] -or $null -eq $Current -or $null -eq $Desired) { return "$Current" -ceq "$Desired" }
    return (ConvertTo-Json -InputObject $Current -Depth 20 -Compress) -ceq (ConvertTo-Json -InputObject $Desired -Depth 20 -Compress)
}

function Format-Value([object]$Value) {
    if ($null -eq $Value) { return '(empty)' }
    if ($Value -is [string]) { return "'$Value'" }
    return ConvertTo-Json -InputObject $Value -Depth 5 -Compress
}

function Get-ShortMessage([string]$Message) {
    if (-not $Message) { return $null }
    try { $inner = $Message | ConvertFrom-Json -ErrorAction Stop; if ($inner.message) { return $inner.message }; if ($inner.title) { return $inner.title } } catch { $null = $_ }
    return $Message
}

#region Requested changes
$requests = [System.Collections.Generic.List[object]]::new()
switch ($PSCmdlet.ParameterSetName) {
    'Single' {
        $set = [ordered]@{}
        if ($PSBoundParameters.ContainsKey('DisplayName')) { $set.displayName = $DisplayName }
        if ($PSBoundParameters.ContainsKey('Description')) { $set.description = $Description }
        if ($PSBoundParameters.ContainsKey('OriginatingStore')) { $set.originatingStore = $OriginatingStore }
        if ($PSBoundParameters.ContainsKey('OwnerIds')) { $set.ownerIds = [string[]](Split-IdList $OwnerIds) }
        if ($Property) { foreach ($key in $Property.Keys) { $set[(Resolve-PropertyName $key)] = $Property[$key] } }
        $requests.Add([pscustomobject]@{ Id = $Id.Trim(); Set = $set; AddOwners = @(Split-IdList $AddOwnerId); RemoveOwners = @(Split-IdList $RemoveOwnerId) })
    }
    'Csv' {
        $line = 1
        foreach ($row in (Import-Csv -LiteralPath $CsvPath -Delimiter $CsvDelimiter)) {
            $line++
            $set = [ordered]@{}; $add = @(); $remove = @(); $rowId = $null
            foreach ($column in $row.PSObject.Properties) {
                $name = $column.Name.Trim(); $value = "$($column.Value)".Trim()
                if ($name -eq 'id') { $rowId = $value; continue }
                if ($value -eq '') { continue }
                switch ($name) {
                    'addOwnerIds' { $add = Split-IdList $value }
                    'removeOwnerIds' { $remove = Split-IdList $value }
                    'ownerIds' { $set.ownerIds = [string[]](Split-IdList $value) }
                    default {
                        $canonical = Resolve-PropertyName $name
                        if ($canonical -in 'agentCard', 'a2aAuthorization') { throw "Line ${line}: $canonical can't be changed from a CSV. Use -Property." }
                        $set[$canonical] = $value
                    }
                }
            }
            if (-not $rowId) { throw "Line ${line}: the registration id is missing." }
            $requests.Add([pscustomobject]@{ Id = $rowId; Set = $set; AddOwners = @($add); RemoveOwners = @($remove) })
        }
    }
    'Restore' {
        $snapshot = Get-Content -Raw -LiteralPath $RestoreFrom | ConvertFrom-Json @JsonReadParams
        foreach ($change in @($snapshot.changes)) {
            $set = [ordered]@{}
            foreach ($name in @($change.changed)) {
                # Assign inside the branches: an if-expression would unroll a one-element array into a string.
                if ($name -eq 'ownerIds') { $set[$name] = [string[]]@($change.before.$name) }
                else { $set[$name] = $change.before.$name }
            }
            $requests.Add([pscustomobject]@{ Id = $change.id; Set = $set; AddOwners = @(); RemoveOwners = @() })
        }
        if (-not $Reason) { $Reason = "Restore from $(Split-Path -Leaf $RestoreFrom)" }
    }
}
if ($requests.Count -eq 0) { throw 'There are no changes to apply.' }
foreach ($request in $requests) {
    if ($request.Set.Count -eq 0 -and $request.AddOwners.Count -eq 0 -and $request.RemoveOwners.Count -eq 0) {
        throw "No change was specified for registration '$($request.Id)'."
    }
}
#endregion

$context = Initialize-AgentRegistryConnection -BoundParameters $PSBoundParameters

$results = [System.Collections.Generic.List[object]]::new()
$changeLog = [System.Collections.Generic.List[object]]::new()
foreach ($request in $requests) {
    $result = [ordered]@{ Id = $request.Id; DisplayName = $null; Changes = $null; Result = $null; Status = $null; Error = $null; RequestId = $null }

    try { $before = Get-AgentRegistration -Id $request.Id }
    catch {
        $detail = Get-AgentRegistryErrorDetail $_
        $result.Status = $detail.StatusCode; $result.RequestId = $detail.RequestId; $result.Error = Get-ShortMessage $detail.ErrorMessage
        $result.Result = switch ($detail.StatusCode) { 403 { 'Read denied' } 404 { 'Not found' } default { 'Error' } }
        $results.Add([pscustomobject]$result); continue
    }
    $result.DisplayName = $before.displayName

    $set = [ordered]@{}
    foreach ($key in $request.Set.Keys) { $set[$key] = $request.Set[$key] }
    if ($request.AddOwners.Count -gt 0 -or $request.RemoveOwners.Count -gt 0) {
        $base = if ($set.Contains('ownerIds')) { @($set.ownerIds) } else { @($before.ownerIds) }
        $owners = [System.Collections.Generic.List[string]]::new()
        foreach ($owner in @($base) + @($request.AddOwners)) { if ($owner -and -not ($owners -contains $owner)) { $owners.Add($owner) } }
        $set.ownerIds = [string[]]@($owners | Where-Object { $_ -notin $request.RemoveOwners })
    }
    if ($set.Contains('ownerIds') -and @($set.ownerIds).Count -eq 0) {
        $managedBy = if ($set.Contains('managedByAppId')) { $set.managedByAppId } else { $before.managedByAppId }
        if (-not $managedBy) {
            $result.Result = 'Rejected'; $result.Error = 'The registration would be left without owners and without managedByAppId.'
            $results.Add([pscustomobject]$result); continue
        }
    }

    $changes = [ordered]@{}
    foreach ($key in $set.Keys) { if (-not (Test-SameValue $before.$key $set[$key] $key)) { $changes[$key] = $set[$key] } }
    $result.Changes = (@($changes.Keys) | ForEach-Object { '{0}: {1} -> {2}' -f $_, (Format-Value $before.$_), (Format-Value $changes[$_]) }) -join '; '
    if ($changes.Count -eq 0) { $result.Result = 'No changes'; $results.Add([pscustomobject]$result); continue }

    if (-not $PSCmdlet.ShouldProcess("$($before.displayName) [$($request.Id)]", "Change $($result.Changes)")) {
        $result.Result = if ($WhatIfPreference) { 'Simulated (-WhatIf)' } else { 'Canceled' }
        $results.Add([pscustomobject]$result); continue
    }

    try {
        Update-AgentRegistration -Id $request.Id -Property $changes -Confirm:$false -WhatIf:$false
        $result.Status = 200
    }
    catch {
        $detail = Get-AgentRegistryErrorDetail $_
        $result.Status = $detail.StatusCode; $result.RequestId = $detail.RequestId; $result.Error = Get-ShortMessage $detail.ErrorMessage
        $result.Result = if ($detail.StatusCode -eq 403) { 'Update denied' } else { 'Error' }
        $results.Add([pscustomobject]$result); continue
    }

    $after = $null
    $mismatch = @($changes.Keys)
    foreach ($attempt in 1..3) {
        Start-Sleep -Seconds $attempt
        try { $after = Get-AgentRegistration -Id $request.Id } catch { $after = $null }
        if ($after) { $mismatch = @($changes.Keys | Where-Object { -not (Test-SameValue $after.$_ $changes[$_] $_) }) }
        if ($after -and $mismatch.Count -eq 0) { break }
    }
    $result.Result = if ($mismatch.Count -eq 0) { 'Updated' } else { "Updated; not verified: $($mismatch -join ', ')" }

    $beforeValues = [ordered]@{}; $afterValues = [ordered]@{}
    foreach ($key in $changes.Keys) {
        $beforeValues[$key] = $before.$key
        if ($after) { $afterValues[$key] = $after.$key } else { $afterValues[$key] = $null }
    }
    $changeLog.Add([ordered]@{
            id = $request.Id; displayName = $before.displayName; changedAt = (Get-Date).ToUniversalTime().ToString('o')
            changed = @($changes.Keys); before = $beforeValues; after = $afterValues; registrationBefore = $before
        })
    $results.Add([pscustomobject]$result)
}

$results | Format-Table -Wrap -Property `
@{ Name = 'Registration'; Width = 30; Expression = { if ($_.DisplayName) { $_.DisplayName } else { $_.Id } } },
@{ Name = 'Changes'; Width = 50; Expression = { $_.Changes } },
@{ Name = 'Result'; Width = 18; Expression = { $_.Result } },
@{ Name = 'HTTP'; Width = 4; Expression = { $_.Status } },
@{ Name = 'Error'; Width = 40; Expression = { $_.Error } } |
    Out-Host

if ($changeLog.Count -gt 0) {
    $folder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SnapshotPath)
    $null = New-Item -ItemType Directory -Force -Path $folder
    $file = Join-Path $folder "agentregistration-changes-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    [ordered]@{
        tool      = 'Set-AgentRegistration.ps1'
        createdAt = (Get-Date).ToUniversalTime().ToString('o')
        reason    = $Reason
        identity  = [ordered]@{
            tenantId = $context.TenantId; caller = $context.Caller; callerObjectId = $context.CallerObjectId
            tokenType = $context.TokenType; clientId = $context.ClientId
        }
        changes   = @($changeLog)
    } | ConvertTo-Json -Depth 20 | Set-Content -Path $file -Encoding utf8
    Write-Host "Snapshot to undo the changes (-RestoreFrom): $file"
}

if ($PassThru) { $results }
