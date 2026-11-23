# Agent 365: update agent registrations you don't own

PowerShell scripts that let an identity and security team read and update **Microsoft Agent 365** agent registrations (Microsoft Graph Agent Registration API, beta), even when the team doesn't own those registrations.

> Sample code, provided as is and without official support. The Agent Registration API is in beta: it can change, and Microsoft doesn't support its use in production applications. Try it in a test environment first.

## Summary

**Symptom:** an account with the **AI Administrator** role can run `PATCH https://graph.microsoft.com/beta/copilot/agentRegistrations/{id}` on registrations it owns. On any other registration, the call returns `403 Access is denied to update the agent registration`.

**What we verified** in a lab tenant (November 2026; details in [docs/test-results.md](docs/test-results.md)):

| Caller | Registration without a managing application | Registration with a managing application (`managedByAppId`) |
|---|---|---|
| User who owns the registration (delegated) | ✅ Read and update | ❌ 403, even as owner |
| User who isn't an owner (delegated), with **AI Administrator**, **Agent Registry Administrator** or **Global Administrator** | ❌ 403 (read and update) | ❌ 403 |
| **App-only application** with the `AgentRegistration.ReadWrite.All` application permission | ✅ **Read and update, whoever the owner is** | ❌ 403, unless it's the managing application |
| The registration's managing application (app-only) | n/a | ✅ Read and update |

Conclusions:

1. **With delegated access, the API only lets owners read and update a registration.** No Microsoft Entra role changes this: AI Administrator, Agent Registry Administrator and Global Administrator all get the same 403. Having the role isn't enough, because the API checks that the user is in `ownerIds`.
2. **The solution is an app-only application** with the `AgentRegistration.ReadWrite.All` application permission. It can read and update registrations of any owner, as long as the registration has no managing application.
3. **Registrations with a managing application (`managedByAppId`) can only be read and updated by that application.** Not by their owners, not by administrators and not by other applications. This applies, for example, to agents registered by Microsoft services (Agent 365 connectors for Amazon Bedrock, Google Vertex AI or Salesforce) and to registrations that your own application creates with `managedByAppId`. Change those registrations at their source or with the application that manages them.

## How the solution works

1. A Global Administrator (or a Privileged Role Administrator) creates a **dedicated application** with **certificate** authentication and grants it these Microsoft Graph application permissions:
   - `AgentRegistration.ReadWrite.All`: read and update agent registrations.
   - `CopilotPackages.Read.All` (optional, read-only): inventory, to find the registration IDs.
2. The identity team uses that application with these scripts:
   - `Get-AgentRegistrationInventory.ps1`: lists the registrations with their ID, platform and managing application.
   - `Test-AgentRegistrationWriteAccess.ps1`: checks, without changing data, which registrations it can update.
   - `Set-AgentRegistration.ps1`: applies changes, with simulation (`-WhatIf`) and a copy of the previous values to undo them.

## Requirements

- PowerShell 7.2 or later (Windows, macOS or Linux). No modules are needed: the scripts call Microsoft Graph with `Invoke-WebRequest`.
- `New-SelfSignedCertificate` (to create the certificate) and the `Cert:\` stores only exist on Windows. On macOS or Linux, use `-CertificatePath` with a .pfx file (or a .cer file to create the application).
- To create the application and grant consent: **Global Administrator** or **Privileged Role Administrator**.
- For the inventory: Microsoft Agent 365 licenses in the tenant (required by the Package Management API).
- If you download the repository as a ZIP file on Windows, unblock the files before you run them (`Get-ChildItem -Recurse | Unblock-File`). Otherwise the `RemoteSigned` execution policy blocks them.

## Step 1: create the application

### With the script

```powershell
# Simulation: shows what it would do, without creating anything
.\New-AgentRegistryAdminApp.ps1 -TenantId contoso.onmicrosoft.com -DisplayName 'IAM - Agent 365 Registry Admin' -WhatIf

# Creation: opens the browser so a Global Administrator can sign in
.\New-AgentRegistryAdminApp.ps1 -TenantId contoso.onmicrosoft.com -DisplayName 'IAM - Agent 365 Registry Admin'
```

The script:

1. Creates a self-signed certificate in `Cert:\CurrentUser\My`, with a **non-exportable** RSA 2048 key, valid for 12 months (`-CertificateValidityMonths`). To use a certificate you already have, for example from Azure Key Vault, pass its public key with `-CertificatePath .\certificate.cer` or its thumbprint with `-CertificateThumbprint`.
2. Creates the app registration (single tenant) with the certificate's public key and both application permissions. With `-SkipInventoryPermission`, it only adds `AgentRegistration.ReadWrite.All`.
3. Creates the service principal and grants admin consent.
4. Shows the `ClientId`, the `TenantId` and the certificate thumbprint. The other scripts need these values.

The permissions can take a minute or two to appear in the application's token.

### Manually, in the Microsoft Entra admin center

1. **App registrations** > **New registration** > *Accounts in this organizational directory only*.
2. **Certificates & secrets** > **Certificates** > **Upload certificate**: upload the public key (.cer). Avoid client secrets.
3. **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**: `AgentRegistration.ReadWrite.All` and, for the inventory, `CopilotPackages.Read.All`.
4. **Grant admin consent** (Global Administrator or Privileged Role Administrator).

## Step 2: find the registrations and their IDs

The Agent Registration API has no operation to list registrations (`GET /copilot/agentRegistrations` returns 404). Also, in our tests **a registration's ID is the same as its `sourceAgentId`**, although the documentation examples show a GUID.

`Get-AgentRegistrationInventory.ps1` gets the list from the Agent 365 **Package Management API** (`GET /beta/copilot/admin/catalog/packages`, filtered to packages with `AgentMetadatas`). From each package's details it reads the registration ID (`SourceAgentId`) and the managing application (`ManagedBy`):

```powershell
$app = @{ TenantId = '<tenantId>'; ClientId = '<clientId>'; CertificateThumbprint = '<thumbprint>' }

# Full inventory (CSV in .\output)
.\Get-AgentRegistrationInventory.ps1 @app
```

Main CSV columns: `DisplayName`, `Platform` (the "platform" in the Microsoft 365 admin center), `RegistrationId`, `ManagedByAppId`, `ManagedBy`, `EditableBy` and `OwnerIds`.

The inventory also includes agents that **can't** be managed with the Agent Registration API through their `SourceAgentId`. In our tests this was the case for:
- Copilot Studio agents and agents created with the Agent 365 SDK or CLI (404);
- Microsoft Foundry agents, whose ID contains `/`, which Graph doesn't accept in the URL (400).

Manage those agents in their source platform.

## Step 3: check access without changing data

```powershell
# Specific registrations
.\Test-AgentRegistrationWriteAccess.ps1 -Id 'my-agent-1', 'my-agent-2' @app

# All registrations without a managing application, piped from the inventory
.\Get-AgentRegistrationInventory.ps1 @app | Where-Object { -not $_.ManagedByAppId } |
    .\Test-AgentRegistrationWriteAccess.ps1 @app
```

For each registration it sends a `GET` and a `PATCH` with an empty body (`{}`). The API applies the same authorization as for a real change (`403 Access is denied to update the agent registration` when you don't have access), but the empty PATCH doesn't change any property. It shows a table with the results and saves the evidence to `.\output\write-access-<date>.json`: the identity, permissions and roles in the token, and for each call the HTTP status, message, `request-id` and date. You can use it to open a support case.

It also checks a user's access (delegated):

```powershell
.\Test-AgentRegistrationWriteAccess.ps1 -Id 'my-agent-1' -TenantId contoso.onmicrosoft.com
```

## Step 4: apply changes

```powershell
# Simulation
.\Set-AgentRegistration.ps1 -Id 'my-agent-1' -DisplayName 'Sales assistant' -Description 'Reviewed by IAM' -WhatIf @app

# Real change, with a reason (saved in the snapshot)
.\Set-AgentRegistration.ps1 -Id 'my-agent-1' -DisplayName 'Sales assistant' -Reason 'CHG0012345' @app

# Reassign owners without changing the rest (for example, when the owner leaves the organization)
.\Set-AgentRegistration.ps1 -Id 'my-agent-1' -AddOwnerId '<new-owner-objectId>' -RemoveOwnerId '<old-owner-objectId>' -Reason 'Employee leaver' @app

# Several registrations from a CSV (see samples\changes-example.csv)
.\Set-AgentRegistration.ps1 -CsvPath .\samples\changes-example.csv -WhatIf @app

# Undo the changes of a run
.\Set-AgentRegistration.ps1 -RestoreFrom .\snapshots\agentregistration-changes-20261123-101500.json @app
```

For each registration, the script:
1. Reads the current values.
2. Sends only the properties that change.
3. Reads the registration again to verify the change.
4. Saves a JSON snapshot with the previous and new values in `.\snapshots`.

It also refuses to leave a registration without owners and without a managing application. Supported properties: `displayName`, `description`, `originatingStore`, `ownerIds`, `managedByAppId`, `agentIdentityId`, `agentIdentityBlueprintId`, `lastPublishedBy` and, with `-Property`, `agentCard` and `a2aAuthorization`. `sourceAgentId` can't be changed on purpose, because it's also the registration ID.

## Sign-in (all scripts)

| Mode | Parameters |
|---|---|
| App-only with a certificate from the store (recommended) | `-TenantId <id> -ClientId <appId> -CertificateThumbprint <thumbprint>` |
| App-only with a .pfx file | `-TenantId <id> -ClientId <appId> -CertificatePath .\app.pfx -CertificatePassword (Read-Host -AsSecureString)` |
| Delegated, in the browser | `-TenantId <id>`. Optional: `-LoginHint user@contoso.com` and `-PrivateBrowser` (Edge InPrivate window). |
| A token you already have | `-AccessToken $token` |

Notes about delegated sign-in:
- By default it uses the *Microsoft Graph Command Line Tools* public client and requests `AgentRegistration.ReadWrite.All`, which requires admin consent.
- To use your own app registration, pass `-ClientId` and add the `http://localhost` redirect URI (Mobile and desktop applications).
- If the browser window doesn't appear, copy the address that the console shows.

Without sign-in parameters, the scripts reuse the session already open in that PowerShell window. All of them use the `AgentRegistry.psm1` module, which you can also import directly:

```powershell
Import-Module .\AgentRegistry.psm1
Connect-AgentRegistryGraph -TenantId <id> -ClientId <appId> -CertificateThumbprint <thumbprint>
Get-AgentRegistration -Id 'my-agent-1'
Update-AgentRegistration -Id 'my-agent-1' -Property @{ description = 'Reviewed by IAM' }
```

## Security

The `AgentRegistration.ReadWrite.All` application permission applies to the whole tenant: whoever holds the certificate's private key can update any registration without a managing application. Recommendations:

- **Certificates, not secrets.** Keep the private key non-exportable on a dedicated admin workstation, or in Azure Key Vault or an HSM. Use short validity periods and rotate the certificate before it expires.
- **Least privilege.** Only `AgentRegistration.ReadWrite.All` and, if you use the inventory, `CopilotPackages.Read.All` (read-only). Don't add other permissions to this application.
- **Control who can use or change it.** Limit the application's owners and who can manage its credentials (for example, Application Administrator or Cloud Application Administrator).
- **Monitoring.** Review the service principal sign-in logs and the Microsoft Entra audit logs. With Workload Identities licenses, use **Conditional Access for workload identities**, for example to allow only the admin network's IP addresses.
- **Change control.** Use `-WhatIf` and `-Reason`, and keep the snapshots in `.\snapshots` with the change ticket.

## Known limitations

- **Beta API.** It can change without notice.
- **No list operation.** IDs come from the inventory (Package Management API, which requires Agent 365 licenses) or from the system that created the registration.
- **Changing `originatingStore` (the platform) returned `500 Agent registration not found`** for every identity, including the owner and the managing application. The other properties changed without problems. If this happens to you, open a support case with the evidence from `Set-AgentRegistration.ps1`.
- **Throttling.** With many calls in a row, the API returns `429 The request was throttled by a downstream service`. The module retries and honors `Retry-After`, and the inventory waits 500 ms between calls (`-DelayMilliseconds`).
- **`managedByAppId`.** A user can't create registrations with a managing application, and an application can only set itself as the managing application (403 `Access is denied to create the agent registration`).

## Files

| File | Purpose |
|---|---|
| `AgentRegistry.psm1` | Shared module: sign-in (browser, certificate or token), Graph calls with retries, `Get-AgentRegistration`, `Update-AgentRegistration` |
| `New-AgentRegistryAdminApp.ps1` | Creates the app-only application with a certificate, permissions and admin consent |
| `Get-AgentRegistrationInventory.ps1` | Inventory: registration ID, platform, managing application and who can update it |
| `Test-AgentRegistrationWriteAccess.ps1` | Checks read and update access without changing data, and saves evidence |
| `Set-AgentRegistration.ps1` | Applies changes (one registration, several or a CSV), with `-WhatIf`, verification, snapshot and restore |
| `samples/changes-example.csv` | Sample CSV for `Set-AgentRegistration.ps1` |
| `docs/test-results.md` | Test details |

The `output/` and `snapshots/` folders and certificate files are excluded from Git (`.gitignore`), because they contain tenant data.

## References

- [Agent Registration API overview (preview)](https://learn.microsoft.com/microsoft-365/copilot/extensibility/api/admin-settings/agent-registration/overview)
- [Update agentRegistration](https://learn.microsoft.com/microsoft-365/copilot/extensibility/api/admin-settings/agent-registration/agentregistration-update)
- [agentRegistration resource type](https://learn.microsoft.com/microsoft-365/copilot/extensibility/api/admin-settings/agent-registration/resources/agentregistration)
- [Agent 365 Package Management API overview](https://learn.microsoft.com/microsoft-365/copilot/extensibility/api/admin-settings/package/overview)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference)
- [Microsoft Entra built-in roles: AI Administrator, Agent Registry Administrator](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference)
- [Agent Registry convergence with Microsoft Agent 365](https://learn.microsoft.com/entra/agent-id/agent-registry-convergence)
- [Conditional Access for workload identities](https://learn.microsoft.com/entra/identity/conditional-access/workload-identity)
