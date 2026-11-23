#Requires -Version 7.2
<#
.SYNOPSIS
    Functions for the Microsoft Graph Agent Registration API (beta): sign-in and reading/updating Microsoft Agent 365
    agent registrations (agentRegistration).

.DESCRIPTION
    Module used by the scripts in this folder. It only uses Invoke-WebRequest, so it doesn't need the Microsoft Graph
    SDK modules.

    Sign-in options (Connect-AgentRegistryGraph):
      * Delegated, in the browser (authorization code + PKCE, redirect to http://localhost).
      * App-only, with a certificate (client credentials with a signed client assertion).
      * An access token you already have.

    Functions:
      Connect-AgentRegistryGraph          Signs in and returns the identity, permissions and roles in the token.
      Disconnect-AgentRegistryGraph       Clears the token from memory.
      Get-AgentRegistryContext            Identity, permissions and Microsoft Entra roles in the current token.
      Get-AgentRegistration               GET   /beta/copilot/agentRegistrations/{id}
      Update-AgentRegistration            PATCH /beta/copilot/agentRegistrations/{id}
      Invoke-AgentRegistryGraph           Generic Microsoft Graph call with retries (429/5xx).
      Get-AgentRegistryErrorDetail        HTTP status, error code and message, request-id and date of an error.
      Initialize-AgentRegistryConnection  Used by the scripts: signs in or reuses the current session.
#>

$script:LoginHost = 'https://login.microsoftonline.com'
$script:GraphHost = 'https://graph.microsoft.com'
$script:GraphCliClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
$script:RegistrationsUri = "$script:GraphHost/beta/copilot/agentRegistrations"
$script:Session = $null

# Built-in Microsoft Entra roles (template IDs) shown by Get-AgentRegistryContext from the token's wids claim.
$script:KnownRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    'd2562ede-74db-457e-a7b6-544e236ebb61' = 'AI Administrator'
    '1fe13547-53f6-408d-ac04-7f8eed167b38' = 'AI Reader'
    '6b942400-691f-4bf0-9d12-d8a254a2baf5' = 'Agent Registry Administrator'
    'db506228-d27e-4b7d-95e5-295956d6615f' = 'Agent ID Administrator'
    'adb2368d-a9be-41b5-8667-d96778e081b0' = 'Agent ID Developer'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = 'Global Reader'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f' = 'Security Operator'
    '5d6b6bb7-de71-4623-b4af-96380a352509' = 'Security Reader'
}

class AgentRegistryGraphException : System.Exception {
    [int]$StatusCode
    [string]$ErrorCode
    [string]$ErrorMessage
    [string]$RequestId
    [string]$Date
    [string]$Method
    [string]$Uri

    AgentRegistryGraphException([string]$method, [string]$uri, [int]$statusCode, [string]$errorCode, [string]$errorMessage, [string]$requestId, [string]$date) :
    base("$method $uri -> HTTP $statusCode $($errorCode): $errorMessage") {
        $this.Method = $method
        $this.Uri = $uri
        $this.StatusCode = $statusCode
        $this.ErrorCode = $errorCode
        $this.ErrorMessage = $errorMessage
        $this.RequestId = $requestId
        $this.Date = $date
    }
}

#region Generic helpers
function ConvertTo-PlainText([object]$Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [securestring]) { return [System.Net.NetworkCredential]::new('', $Value).Password }
    return [string]$Value
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string]$Text) {
    $t = $Text.Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return , [Convert]::FromBase64String($t)
}

function Get-JwtClaim([string]$Jwt) {
    $parts = "$Jwt".Split('.')
    if ($parts.Count -lt 2) { return $null }
    try { return [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json } catch { return $null }
}

# Keep dates as strings (PowerShell 7.5+) so values are compared and saved exactly as Graph returns them.
$script:JsonReadParams = @{ Depth = 100 }
if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $script:JsonReadParams.DateKind = 'String' }

function ConvertFrom-GraphJson([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $Text | ConvertFrom-Json @script:JsonReadParams
}

function ConvertFrom-QueryString([string]$Query) {
    $result = @{}
    foreach ($pair in $Query.TrimStart('?').Split('&', [StringSplitOptions]::RemoveEmptyEntries)) {
        $kv = $pair.Split('=', 2)
        $value = if ($kv.Count -gt 1) { [uri]::UnescapeDataString($kv[1].Replace('+', ' ')) } else { '' }
        $result[[uri]::UnescapeDataString($kv[0])] = $value
    }
    return $result
}

function Get-RetryDelay([object]$RetryAfter, [int]$Attempt) {
    $seconds = 0
    $value = @($RetryAfter)[0]
    if ($null -ne $value -and [int]::TryParse("$value", [ref]$seconds) -and $seconds -gt 0) { return [Math]::Min($seconds, 120) }
    return [Math]::Min(60, [Math]::Pow(2, $Attempt))
}
#endregion

#region Authentication
function Invoke-TokenRequest([hashtable]$Form, [string]$Tenant) {
    $resp = Invoke-WebRequest -Method Post -Uri "$script:LoginHost/$Tenant/oauth2/v2.0/token" -Body $Form `
        -ContentType 'application/x-www-form-urlencoded' -SkipHttpErrorCheck -UseBasicParsing
    [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Json = (ConvertFrom-GraphJson $resp.Content) }
}

function Set-SessionToken([object]$Response, [string]$What) {
    if ($Response.StatusCode -ne 200 -or -not $Response.Json.access_token) {
        throw "$What failed (HTTP $($Response.StatusCode)): $($Response.Json.error) - $($Response.Json.error_description)"
    }
    $script:Session.AccessToken = $Response.Json.access_token
    $script:Session.ExpiresOn = [datetimeoffset]::UtcNow.AddSeconds([int]$Response.Json.expires_in)
    if ($Response.Json.refresh_token) { $script:Session.RefreshToken = $Response.Json.refresh_token }
    $claims = Get-JwtClaim $Response.Json.access_token
    if ($claims.tid) { $script:Session.TenantId = $claims.tid }
}

function Get-DelegatedScopeString([string[]]$Scopes) {
    $list = foreach ($s in $Scopes) {
        if ($s -match '^(https?|api)://' -or $s -in 'openid', 'profile', 'offline_access', 'email') { $s } else { "$script:GraphHost/$s" }
    }
    return (@($list) + 'offline_access', 'openid', 'profile' | Select-Object -Unique) -join ' '
}

function Get-CertificateFromStore([string]$Thumbprint) {
    $tp = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        $cert = Get-Item -Path "$store\$tp" -ErrorAction SilentlyContinue
        if ($cert) { return $cert }
    }
    throw "Certificate $tp not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
}

function Import-PfxCertificateFile([string]$Path, [object]$Password) {
    $fullPath = (Resolve-Path -LiteralPath $Path).Path
    $plainPassword = ConvertTo-PlainText $Password
    $flags = if ($IsMacOS) { [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet }
    else { [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet }
    $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]
    if ($loader) { return $loader::LoadPkcs12FromFile($fullPath, $plainPassword, $flags) }
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($fullPath, $plainPassword, $flags)
}

function New-ClientAssertion {
    $s = $script:Session
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($s.Certificate)
    if (-not $rsa) { throw 'Only RSA certificates are supported for certificate authentication.' }
    $now = [datetimeoffset]::UtcNow.ToUnixTimeSeconds()
    $payload = [ordered]@{
        aud = "$script:LoginHost/$($s.TenantId)/oauth2/v2.0/token"; iss = $s.ClientId; sub = $s.ClientId
        jti = [guid]::NewGuid().ToString(); nbf = $now; iat = $now; exp = $now + 600
    } | ConvertTo-Json -Compress
    $encodedPayload = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload))
    $x5t = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::HashData($s.Certificate.RawData))

    # PS256 is recommended; RS256 is the fallback for keys in legacy CryptoAPI providers that can't sign with PSS.
    foreach ($alg in 'PS256', 'RS256') {
        $header = [ordered]@{ alg = $alg; typ = 'JWT'; 'x5t#S256' = $x5t } | ConvertTo-Json -Compress
        $signingInput = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + $encodedPayload
        $padding = if ($alg -eq 'PS256') { [System.Security.Cryptography.RSASignaturePadding]::Pss } else { [System.Security.Cryptography.RSASignaturePadding]::Pkcs1 }
        try {
            $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signingInput), [System.Security.Cryptography.HashAlgorithmName]::SHA256, $padding)
            return "$signingInput.$(ConvertTo-Base64Url $signature)"
        }
        catch { if ($alg -eq 'RS256') { throw } }
    }
}

function Open-SignInPage([string]$Url, [bool]$PrivateBrowser) {
    if ($PrivateBrowser) {
        $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
        if ($edge) { Start-Process -FilePath $edge -ArgumentList '--inprivate', '--new-window', $Url; return }
        Write-Warning 'Microsoft Edge not found: opening the default browser instead of an InPrivate window.'
    }
    Start-Process $Url
}

function Get-TokenInteractive {
    $s = $script:Session
    $verifierBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
    $verifier = ConvertTo-Base64Url $verifierBytes
    $challenge = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = [guid]::NewGuid().ToString('N')

    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
    $redirectUri = "http://localhost:$port"
    $scope = Get-DelegatedScopeString $s.Scopes

    $query = [ordered]@{
        client_id = $s.ClientId; response_type = 'code'; redirect_uri = $redirectUri; response_mode = 'query'
        scope = $scope; state = $state; code_challenge = $challenge; code_challenge_method = 'S256'; prompt = 'select_account'
    }
    if ($s.LoginHint) { $query.login_hint = $s.LoginHint }
    $qs = ($query.GetEnumerator() | ForEach-Object { "$($_.Key)=$([uri]::EscapeDataString($_.Value))" }) -join '&'
    $authorizeUrl = "$script:LoginHost/$($s.TenantId)/oauth2/v2.0/authorize?$qs"

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("$redirectUri/")
    $listener.Start()
    try {
        Write-Host 'Opening the browser to sign in. If it does not open, copy this address into a browser:' -ForegroundColor Yellow
        Write-Host $authorizeUrl
        try { Open-SignInPage -Url $authorizeUrl -PrivateBrowser $s.PrivateBrowser } catch { Write-Verbose "Could not open the browser: $_" }

        $contextTask = $listener.GetContextAsync()
        $deadline = [datetime]::UtcNow.AddMinutes($s.TimeoutMinutes)
        while (-not $contextTask.AsyncWaitHandle.WaitOne(500)) {
            if ([datetime]::UtcNow -gt $deadline) { throw "Timed out waiting for the browser sign-in ($($s.TimeoutMinutes) minutes)." }
        }
        $context = $contextTask.GetAwaiter().GetResult()
        $params = ConvertFrom-QueryString $context.Request.Url.Query
        $ok = -not $params['error'] -and $params['code'] -and $params['state'] -eq $state
        $html = if ($ok) { '<html><body style="font-family:sans-serif"><h3>Signed in. You can close this window.</h3></body></html>' }
        else { '<html><body style="font-family:sans-serif"><h3>Sign-in failed. Check the PowerShell window.</h3></body></html>' }
        $buffer = [Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.ContentType = 'text/html; charset=utf-8'
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.Close()
    }
    finally { $listener.Stop(); $listener.Close() }

    if ($params['error']) { throw "Sign-in failed: $($params['error']) - $($params['error_description'])" }
    if ($params['state'] -ne $state) { throw 'Sign-in failed: the state parameter does not match.' }

    $resp = Invoke-TokenRequest -Tenant $s.TenantId -Form @{
        client_id = $s.ClientId; grant_type = 'authorization_code'; code = $params['code']
        redirect_uri = $redirectUri; code_verifier = $verifier; scope = $scope
    }
    Set-SessionToken $resp 'Authorization code redemption'
}

function Get-SessionAccessToken([switch]$ForceRefresh) {
    $s = $script:Session
    if (-not $s) { throw 'Not signed in. Run Connect-AgentRegistryGraph first.' }
    if (-not $ForceRefresh -and $s.AccessToken -and $s.ExpiresOn -gt [datetimeoffset]::UtcNow.AddMinutes(5)) { return $s.AccessToken }
    switch ($s.Mode) {
        'Certificate' {
            $r = Invoke-TokenRequest -Tenant $s.TenantId -Form @{
                client_id = $s.ClientId; grant_type = 'client_credentials'; scope = "$script:GraphHost/.default"
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion = (New-ClientAssertion)
            }
            Set-SessionToken $r 'Certificate token request'
        }
        'Interactive' {
            $refreshed = $false
            if ($s.RefreshToken) {
                $r = Invoke-TokenRequest -Tenant $s.TenantId -Form @{
                    client_id = $s.ClientId; grant_type = 'refresh_token'; refresh_token = $s.RefreshToken
                    scope = (Get-DelegatedScopeString $s.Scopes)
                }
                if ($r.StatusCode -eq 200) { Set-SessionToken $r 'Token refresh'; $refreshed = $true }
            }
            if (-not $refreshed) { Get-TokenInteractive }
        }
        'AccessToken' {
            if ($s.ExpiresOn -le [datetimeoffset]::UtcNow) { throw 'The access token has expired. Get a new one and run the command again.' }
        }
    }
    return $script:Session.AccessToken
}

function Connect-AgentRegistryGraph {
    <#
    .SYNOPSIS
        Signs in to Microsoft Graph to use the Agent Registration API.
    .DESCRIPTION
        Delegated (default): opens the browser. The token has the delegated permissions consented for the client
        (by default, Microsoft Graph Command Line Tools), and the API also applies the user's own access.
        App-only: -TenantId, -ClientId and the application's certificate (-CertificateThumbprint or -CertificatePath).
        Token: -AccessToken with a Microsoft Graph token obtained some other way.
    .EXAMPLE
        Connect-AgentRegistryGraph -TenantId contoso.onmicrosoft.com
    .EXAMPLE
        Connect-AgentRegistryGraph -TenantId <tenantId> -ClientId <appId> -CertificateThumbprint <thumbprint>
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory)]
        [Parameter(ParameterSetName = 'CertificateFile', Mandatory)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Interactive')]
        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory)]
        [Parameter(ParameterSetName = 'CertificateFile', Mandatory)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Interactive')]
        [string[]]$Scopes = @('AgentRegistration.ReadWrite.All'),

        [Parameter(ParameterSetName = 'Interactive')]
        [string]$LoginHint,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$PrivateBrowser,

        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateRange(1, 30)]
        [int]$TimeoutMinutes = 5,

        [Parameter(ParameterSetName = 'CertificateThumbprint', Mandatory)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'CertificateFile', Mandatory)]
        [string]$CertificatePath,

        [Parameter(ParameterSetName = 'CertificateFile')]
        [object]$CertificatePassword,

        [Parameter(ParameterSetName = 'AccessToken', Mandatory)]
        [object]$AccessToken,

        [ValidateRange(0, 10)]
        [int]$MaxRetries = 6
    )
    $mode = switch ($PSCmdlet.ParameterSetName) { 'Interactive' { 'Interactive' } 'AccessToken' { 'AccessToken' } default { 'Certificate' } }
    $script:Session = [pscustomobject]@{
        Mode           = $mode
        TenantId       = if ($TenantId) { $TenantId } else { 'organizations' }
        ClientId       = if ($ClientId) { $ClientId } elseif ($mode -eq 'Interactive') { $script:GraphCliClientId } else { $null }
        Scopes         = $Scopes
        LoginHint      = $LoginHint
        PrivateBrowser = [bool]$PrivateBrowser
        TimeoutMinutes = $TimeoutMinutes
        Certificate    = $null
        AccessToken    = $null
        RefreshToken   = $null
        ExpiresOn      = [datetimeoffset]::MinValue
        MaxRetries     = $MaxRetries
    }
    try {
        switch ($PSCmdlet.ParameterSetName) {
            'CertificateThumbprint' { $script:Session.Certificate = Get-CertificateFromStore $CertificateThumbprint }
            'CertificateFile' { $script:Session.Certificate = Import-PfxCertificateFile $CertificatePath $CertificatePassword }
            'AccessToken' {
                $token = (ConvertTo-PlainText $AccessToken) -replace '^\s*Bearer\s+', ''
                $claims = Get-JwtClaim $token
                if (-not $claims) { throw 'The -AccessToken value is not a valid JWT.' }
                if ($claims.aud -notin 'https://graph.microsoft.com', 'https://graph.microsoft.com/', '00000003-0000-0000-c000-000000000000') {
                    Write-Warning "The token isn't for Microsoft Graph (aud = $($claims.aud))."
                }
                $script:Session.AccessToken = $token
                $script:Session.ExpiresOn = if ($claims.exp) { [datetimeoffset]::FromUnixTimeSeconds([long]$claims.exp) } else { [datetimeoffset]::MaxValue }
                $script:Session.TenantId = $claims.tid
            }
        }
        if ($script:Session.Certificate -and -not $script:Session.Certificate.HasPrivateKey) {
            throw "Certificate $($script:Session.Certificate.Thumbprint) has no accessible private key."
        }
        $null = Get-SessionAccessToken
    }
    catch { $script:Session = $null; throw }

    $context = Get-AgentRegistryContext
    Write-Host ('Connected: {0} | Token: {1} | Tenant: {2}' -f $context.Caller, $context.TokenType, $context.TenantId) -ForegroundColor Cyan
    if (-not $context.CanWriteRegistrations) {
        Write-Warning "The token doesn't include AgentRegistration.ReadWrite.All. Token permissions: $($context.Permissions -join ', ')"
    }
    return $context
}

function Disconnect-AgentRegistryGraph {
    <#
    .SYNOPSIS
        Clears the token and certificate of the current session from memory.
    #>
    [CmdletBinding()]
    param()
    $script:Session = $null
}

function Get-AgentRegistryContext {
    <#
    .SYNOPSIS
        Returns the identity, token type, permissions and Microsoft Entra roles of the current token.
    #>
    [CmdletBinding()]
    param()
    if (-not $script:Session -or -not $script:Session.AccessToken) { throw 'Not signed in. Run Connect-AgentRegistryGraph first.' }
    $c = Get-JwtClaim $script:Session.AccessToken
    $delegated = [bool]$c.scp
    $permissions = @(@($c.scp -split ' ') + @($c.roles) | Where-Object { $_ } | Sort-Object -Unique)
    $caller = if ($delegated) { @($c.upn, $c.preferred_username, $c.unique_name, $c.oid) | Where-Object { $_ } | Select-Object -First 1 }
    else { @($c.app_displayname, $c.appid) | Where-Object { $_ } | Select-Object -First 1 }
    [pscustomobject]@{
        TenantId              = $c.tid
        TokenType             = if ($delegated) { 'Delegated' } else { 'Application' }
        Caller                = $caller
        CallerObjectId        = $c.oid
        ClientId              = if ($c.appid) { $c.appid } else { $c.azp }
        ClientName            = $c.app_displayname
        Permissions           = $permissions
        # b79fbf4d-... is sent for every non-guest user and isn't an administrator role.
        DirectoryRoles        = @($c.wids | Where-Object { $_ -and $_ -ne 'b79fbf4d-3ef9-4689-8143-76b194e85509' } | ForEach-Object { if ($script:KnownRoles.ContainsKey($_)) { $script:KnownRoles[$_] } else { $_ } })
        CanWriteRegistrations = $permissions -contains 'AgentRegistration.ReadWrite.All'
        ExpiresOn             = $script:Session.ExpiresOn
        AuthMode              = $script:Session.Mode
    }
}

function Initialize-AgentRegistryConnection {
    <#
    .SYNOPSIS
        Used by the scripts: signs in with the authentication parameters the script received or, if it received
        none and this PowerShell session is already signed in, reuses that session.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters)
    $auth = @{}
    $boundNames = @($BoundParameters.Keys)
    foreach ($name in 'TenantId', 'ClientId', 'Scopes', 'LoginHint', 'PrivateBrowser', 'CertificateThumbprint', 'CertificatePath', 'CertificatePassword', 'AccessToken') {
        if ($boundNames -contains $name) { $auth[$name] = $BoundParameters[$name] }
    }
    if ($auth.Count -eq 0 -and $script:Session -and $script:Session.AccessToken) {
        $context = Get-AgentRegistryContext
        Write-Host ('Current session: {0} | Token: {1} | Tenant: {2}' -f $context.Caller, $context.TokenType, $context.TenantId) -ForegroundColor Cyan
        return $context
    }
    return Connect-AgentRegistryGraph @auth
}
#endregion

#region Microsoft Graph requests
function Invoke-AgentRegistryGraph {
    <#
    .SYNOPSIS
        Calls Microsoft Graph with the session token and retries 429 and 5xx responses.
        On an error response, it throws an exception with the HTTP status, the error code and message, the
        request-id and the date (useful for a support case).
    .EXAMPLE
        Invoke-AgentRegistryGraph -Uri '/beta/copilot/agentRegistrations/<id>'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method = 'GET',
        [object]$Body
    )
    if ($Uri -notmatch '^https://') { $Uri = "$script:GraphHost/$($Uri.TrimStart('/'))" }
    $ProgressPreference = 'SilentlyContinue'
    $maxRetries = if ($script:Session) { $script:Session.MaxRetries } else { 6 }
    $attempt = 0
    while ($true) {
        $attempt++
        $request = @{
            Method = $Method; Uri = $Uri; SkipHttpErrorCheck = $true; UseBasicParsing = $true
            Headers = @{ Authorization = "Bearer $(Get-SessionAccessToken)"; 'client-request-id' = [guid]::NewGuid().ToString() }
        }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 20 -Compress }
            $request.Body = [Text.Encoding]::UTF8.GetBytes($json)
            $request.ContentType = 'application/json; charset=utf-8'
        }
        try { $resp = Invoke-WebRequest @request }
        catch {
            if ($attempt -le $maxRetries) {
                Write-Verbose "Network error on $Method $Uri ($($_.Exception.Message)); retry $attempt"
                Start-Sleep -Seconds (Get-RetryDelay $null $attempt); continue
            }
            throw
        }
        $status = [int]$resp.StatusCode
        if ($status -ge 200 -and $status -lt 300) { return ConvertFrom-GraphJson $resp.Content }
        if ($status -eq 401 -and $attempt -eq 1 -and $script:Session.Mode -ne 'AccessToken') {
            $null = Get-SessionAccessToken -ForceRefresh; continue
        }
        if (($status -eq 429 -or $status -ge 500) -and $attempt -le $maxRetries) {
            $delay = Get-RetryDelay $resp.Headers['Retry-After'] $attempt
            Write-Verbose "HTTP $status on $Method $Uri; waiting $delay s (retry $attempt)"
            Start-Sleep -Seconds $delay; continue
        }
        $graphError = $null
        try { $graphError = (ConvertFrom-GraphJson $resp.Content).error } catch { Write-Verbose 'The error response is not JSON.' }
        $requestId = @($resp.Headers['request-id'])[0]
        if (-not $requestId) { $requestId = $graphError.innerError.'request-id' }
        $date = if ($graphError.innerError.date) { [string]$graphError.innerError.date } else { [string]@($resp.Headers['Date'])[0] }
        throw [AgentRegistryGraphException]::new($Method, $Uri, $status, $graphError.code, $graphError.message, $requestId, $date)
    }
}

function Get-AgentRegistryErrorDetail {
    <#
    .SYNOPSIS
        Returns the HTTP status, error code and message, request-id and date of an Invoke-AgentRegistryGraph error
        (or the type and message of any other error).
    .EXAMPLE
        try { Get-AgentRegistration -Id $id } catch { Get-AgentRegistryErrorDetail $_ }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e -and $e -isnot [AgentRegistryGraphException] -and $e.InnerException) { $e = $e.InnerException }
    if ($e -is [AgentRegistryGraphException]) {
        return [pscustomobject]@{ StatusCode = $e.StatusCode; ErrorCode = $e.ErrorCode; ErrorMessage = $e.ErrorMessage; RequestId = $e.RequestId; Date = $e.Date }
    }
    [pscustomobject]@{
        StatusCode = 0; ErrorCode = $ErrorRecord.Exception.GetType().Name; ErrorMessage = $ErrorRecord.Exception.Message
        RequestId = $null; Date = $null
    }
}

function Get-AgentRegistration {
    <#
    .SYNOPSIS
        Reads an agent registration: GET /beta/copilot/agentRegistrations/{id}.
    .EXAMPLE
        Get-AgentRegistration -Id <id>
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('RegistrationId')]
        [string[]]$Id,

        [string[]]$Property
    )
    process {
        foreach ($item in $Id) {
            $uri = "$script:RegistrationsUri/$([uri]::EscapeDataString($item.Trim()))"
            if ($Property) { $uri += '?$select=' + ($Property -join ',') }
            Invoke-AgentRegistryGraph -Uri $uri
        }
    }
}

function Update-AgentRegistration {
    <#
    .SYNOPSIS
        Updates properties of an agent registration: PATCH /beta/copilot/agentRegistrations/{id}.
        Properties you don't send keep their values.
    .EXAMPLE
        Update-AgentRegistration -Id <id> -Property @{ description = 'Reviewed by IAM' }
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Property
    )
    if ($PSCmdlet.ShouldProcess($Id, "PATCH agentRegistration ($(@($Property.Keys) -join ', '))")) {
        $null = Invoke-AgentRegistryGraph -Method PATCH -Uri "$script:RegistrationsUri/$([uri]::EscapeDataString($Id.Trim()))" -Body $Property
    }
}
#endregion

Export-ModuleMember -Function Connect-AgentRegistryGraph, Disconnect-AgentRegistryGraph, Get-AgentRegistryContext,
Initialize-AgentRegistryConnection, Invoke-AgentRegistryGraph, Get-AgentRegistryErrorDetail, Get-AgentRegistration,
Update-AgentRegistration
