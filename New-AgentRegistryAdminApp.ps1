#Requires -Version 7.2
<#
.SYNOPSIS
    Creates a dedicated app-only application (certificate authentication) to manage Microsoft Agent 365 agent
    registrations: AgentRegistration.ReadWrite.All application permission (read and update registrations) and, for
    the inventory, CopilotPackages.Read.All (read-only).

.DESCRIPTION
    Steps:
      1. Certificate: creates a self-signed certificate in Cert:\CurrentUser\My (non-exportable RSA 2048 key), or
         uses the one you pass with -CertificateThumbprint (certificate store) or -CertificatePath (.cer public key).
      2. Creates the app registration (single tenant) with the certificate's public key and the Microsoft Graph
         application permissions.
      3. Creates the service principal and grants admin consent (app role assignments).

    What the application can do (tested): read and update registrations that have no managing application
    (managedByAppId is empty), whoever their owners are, and the registrations it manages itself. It can't read or
    update registrations managed by another application (for example, a Microsoft service).

    Who must run it: a Global Administrator or a Privileged Role Administrator, because granting Microsoft Graph
    application permissions requires one of these roles. The sign-in is delegated and requests
    Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All.

    The certificate's private key stays on the computer where it's created. Run the scripts that update registrations
    on that computer (with the same Windows account), or use your own certificate, for example one issued from
    Azure Key Vault.

.PARAMETER DisplayName
    Application name. If an application with this name already exists, the script stops.

.PARAMETER SkipInventoryPermission
    Doesn't add CopilotPackages.Read.All. Without it, the application can't run Get-AgentRegistrationInventory.ps1.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate already in Cert:\CurrentUser\My or Cert:\LocalMachine\My. No new certificate is created.

.PARAMETER CertificatePath
    .cer (or .pem/.crt) file with the public key of a certificate you already have. No new certificate is created.

.PARAMETER CertificateValidityMonths
    Validity of the self-signed certificate that's created. Default: 12 months.

.PARAMETER ExportCertificatePath
    If set, saves the public key (.cer) of the new certificate to this path.

.PARAMETER TenantId
    Tenant (ID or domain) for the administrator sign-in.

.PARAMETER LoginHint
    Account to sign in with (pre-fills the user name on the sign-in page).

.PARAMETER AccessToken
    A delegated Microsoft Graph token of an administrator that you already have, instead of signing in in the browser.

.EXAMPLE
    .\New-AgentRegistryAdminApp.ps1 -TenantId contoso.onmicrosoft.com
    Creates the application "Agent 365 Registry Admin (app-only)" with a new certificate.

.EXAMPLE
    .\New-AgentRegistryAdminApp.ps1 -TenantId contoso.onmicrosoft.com -WhatIf
    Shows what it would do, without creating anything.

.EXAMPLE
    .\New-AgentRegistryAdminApp.ps1 -TenantId contoso.onmicrosoft.com -DisplayName 'IAM - Agent 365 Registry' -CertificatePath .\iam-agent365.cer
    Uses the public key of a certificate you already have (for example, from Azure Key Vault).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName = 'Agent 365 Registry Admin (app-only)',

    [switch]$SkipInventoryPermission,

    [string]$CertificateThumbprint,

    [string]$CertificatePath,

    [ValidateRange(1, 24)]
    [int]$CertificateValidityMonths = 12,

    [string]$ExportCertificatePath,

    [string]$TenantId,

    [string]$LoginHint,

    [object]$AccessToken
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AgentRegistry.psm1')

$GraphAppId = '00000003-0000-0000-c000-000000000000'
$PermissionNames = @('AgentRegistration.ReadWrite.All')
if (-not $SkipInventoryPermission) { $PermissionNames += 'CopilotPackages.Read.All' }
$AdminScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')

if ($CertificateThumbprint -and $CertificatePath) { throw 'Use -CertificateThumbprint or -CertificatePath, not both.' }

#region Sign-in (delegated, administrator)
$connect = @{ Scopes = $AdminScopes }
if ($AccessToken) { $connect = @{ AccessToken = $AccessToken } }
else {
    if ($TenantId) { $connect.TenantId = $TenantId }
    if ($LoginHint) { $connect.LoginHint = $LoginHint }
}
$context = Connect-AgentRegistryGraph @connect
if ($context.TokenType -ne 'Delegated') { throw 'This script needs a delegated sign-in of an administrator, not an application token.' }
foreach ($scope in $AdminScopes) {
    if ($context.Permissions -notcontains $scope -and $context.Permissions -notcontains 'Directory.AccessAsUser.All') {
        Write-Warning "The token doesn't include $scope. Creating the application or granting consent might fail."
    }
}
if (-not ($context.DirectoryRoles | Where-Object { $_ -in 'Global Administrator', 'Privileged Role Administrator' })) {
    Write-Warning "The token doesn't have the Global Administrator or Privileged Role Administrator role. Without one of them, granting the application permissions fails (403)."
}
#endregion

#region Checks
$escapedName = $DisplayName.Replace("'", "''")
$existing = @((Invoke-AgentRegistryGraph -Uri "/v1.0/applications?`$filter=displayName eq '$([uri]::EscapeDataString($escapedName))'&`$select=id,appId,displayName").value)
if ($existing.Count -gt 0) {
    throw "An application named '$DisplayName' already exists (appId $($existing[0].appId)). Use another -DisplayName or delete the existing one."
}

$graphSp = @((Invoke-AgentRegistryGraph -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appRoles").value)[0]
if (-not $graphSp) { throw 'The Microsoft Graph service principal was not found in the tenant.' }
$appRoles = foreach ($name in $PermissionNames) {
    $role = $graphSp.appRoles | Where-Object { $_.value -eq $name -and $_.allowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Microsoft Graph doesn't publish the $name application permission in this tenant." }
    $role
}
#endregion

#region Certificate
$certificate = $null
if ($CertificateThumbprint) {
    $tp = ($CertificateThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $certificate = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') | ForEach-Object { Get-Item -Path "$_\$tp" -ErrorAction SilentlyContinue } | Select-Object -First 1
    if (-not $certificate) { throw "Certificate $tp not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My." }
}
elseif ($CertificatePath) {
    $fullPath = (Resolve-Path -LiteralPath $CertificatePath).Path
    $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]
    $certificate = if ($loader) { $loader::LoadCertificateFromFile($fullPath) }
    else { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($fullPath) }
}
elseif ($PSCmdlet.ShouldProcess('Cert:\CurrentUser\My', "Create a self-signed certificate 'CN=$DisplayName' valid for $CertificateValidityMonths months")) {
    if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw 'New-SelfSignedCertificate is only available on Windows. Use -CertificatePath with the public key of your certificate.'
    }
    $certificate = New-SelfSignedCertificate -Subject "CN=$DisplayName" -FriendlyName $DisplayName -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature `
        -Provider 'Microsoft Software Key Storage Provider' -Type Custom -NotAfter (Get-Date).AddMonths($CertificateValidityMonths)
    Write-Host "Certificate created in Cert:\CurrentUser\My: $($certificate.Thumbprint) (expires $($certificate.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green
    if ($ExportCertificatePath) {
        [System.IO.File]::WriteAllBytes($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportCertificatePath), $certificate.RawData)
        Write-Host "Public key saved to $ExportCertificatePath"
    }
}
#endregion

#region Application, service principal and admin consent
$permissionText = $PermissionNames -join ', '
$target = "Application '$DisplayName' with the Microsoft Graph application permissions $permissionText and admin consent"
if (-not $PSCmdlet.ShouldProcess($target, 'Create')) { return }

$application = Invoke-AgentRegistryGraph -Method POST -Uri '/v1.0/applications' -Body @{
    displayName            = $DisplayName
    signInAudience         = 'AzureADMyOrg'
    notes                  = "App-only application to manage Microsoft Agent 365 agent registrations (Graph: $permissionText). Created with New-AgentRegistryAdminApp.ps1."
    requiredResourceAccess = @(@{ resourceAppId = $GraphAppId; resourceAccess = @($appRoles | ForEach-Object { @{ id = $_.id; type = 'Role' } }) })
    keyCredentials         = @(@{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = [Convert]::ToBase64String($certificate.RawData); displayName = $certificate.Subject })
}
Write-Host "Application created: appId $($application.appId)" -ForegroundColor Green

$servicePrincipal = Invoke-AgentRegistryGraph -Method POST -Uri '/v1.0/servicePrincipals' -Body @{ appId = $application.appId }
Write-Host "Service principal created: $($servicePrincipal.id)" -ForegroundColor Green

$assignments = foreach ($appRole in $appRoles) {
    # A new service principal can take a few seconds to replicate before it accepts app role assignments.
    foreach ($attempt in 1..6) {
        try {
            Invoke-AgentRegistryGraph -Method POST -Uri "/v1.0/servicePrincipals/$($graphSp.id)/appRoleAssignedTo" -Body @{
                principalId = $servicePrincipal.id; resourceId = $graphSp.id; appRoleId = $appRole.id
            }
            Write-Host "Admin consent granted: $($appRole.value)" -ForegroundColor Green
            break
        }
        catch {
            $detail = Get-AgentRegistryErrorDetail $_
            if ($detail.StatusCode -notin 400, 404 -or $attempt -eq 6) {
                Write-Warning "The application was created, but granting $($appRole.value) failed: HTTP $($detail.StatusCode) $($detail.ErrorCode) $($detail.ErrorMessage)"
                Write-Warning "Grant admin consent in Microsoft Entra ID > App registrations > $DisplayName > API permissions, or run the script again as a Global Administrator."
                throw
            }
            Start-Sleep -Seconds (5 * $attempt)
        }
    }
}
#endregion

$result = [pscustomobject]@{
    DisplayName           = $DisplayName
    TenantId              = $context.TenantId
    ClientId              = $application.appId
    ApplicationObjectId   = $application.id
    ServicePrincipalId    = $servicePrincipal.id
    Permissions           = $PermissionNames
    AppRoleAssignmentIds  = @($assignments | ForEach-Object { $_.id })
    CertificateThumbprint = $certificate.Thumbprint
    CertificateNotAfter   = $certificate.NotAfter
}
Write-Host ''
Write-Host 'Next step (the permissions can take a few minutes to appear in the token):' -ForegroundColor Cyan
Write-Host "  .\Test-AgentRegistrationWriteAccess.ps1 -Id <registration-id> -TenantId $($context.TenantId) -ClientId $($application.appId) -CertificateThumbprint $($certificate.Thumbprint)"
$result
