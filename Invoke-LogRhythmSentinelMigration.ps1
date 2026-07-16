<#
.SYNOPSIS
    Assesses and stages a LogRhythm-to-Microsoft-Sentinel migration.

.DESCRIPTION
    This standalone helper covers the repeatable parts of a migration:

    - checks and installs prerequisites;
    - exports LogRhythm EMDB inventories without requiring the SqlServer module;
    - safely inventories a target Microsoft Sentinel workspace using the Azure CLI sign-in;
    - maps log-source types to likely Sentinel connectors, tables, and collection paths;
    - creates a use-case translation queue and an editable analytics-rule package;
    - validates translated KQL and deploys scheduled rules, disabled by default;
    - checks expected Sentinel tables for recent ingestion; and
    - updates itself from the project's GitHub repository.

    LogRhythm AIE logic is proprietary and does not have a reliable one-to-one KQL
    conversion. The helper inventories exported AIE XML, creates the translation
    package, and refuses to deploy a rule until that rule is explicitly marked Ready
    and contains valid KQL.

.PARAMETER Action
    Menu, Status, InstallPrerequisites, Export, Inventory, Assess, ValidateRules,
    DeployRules, ValidateIngestion, Migrate, Update, or SelfTest.

.PARAMETER OutputPath
    Working directory for migration evidence and generated artifacts. It defaults
    outside the repository to Documents\LogRhythm-Sentinel-Migration.

.PARAMETER SqlServer
    LogRhythm EMDB SQL Server or named instance.

.PARAMETER Database
    LogRhythm EMDB database name.

.PARAMETER UseSqlAuthentication
    Uses the supplied SqlCredential instead of Windows integrated authentication.

.PARAMETER SqlCredential
    SQL credential. Credentials are never written to disk or placed in a connection
    string.

.PARAMETER EncryptSqlConnection
    Enables TLS for the SQL connection. This defaults to true.

.PARAMETER TrustServerCertificate
    Trusts the SQL Server certificate without validating its chain. Use only when
    the LogRhythm SQL Server does not have a certificate trusted by this host.

.PARAMETER AieXmlPath
    Optional file or directory containing AIE rule XML exported from the LogRhythm
    Console. Directory input is searched recursively.

.PARAMETER SubscriptionId
    Azure subscription containing the target Sentinel workspace.

.PARAMETER ResourceGroupName
    Resource group containing the target Log Analytics workspace.

.PARAMETER WorkspaceName
    Target Log Analytics workspace with Microsoft Sentinel enabled.

.PARAMETER MappingOverridesPath
    Optional CSV that prepends custom source mappings. Expected columns are Pattern,
    Connector, ConnectorMatch, TargetTables, CollectionMethod, MigrationApproach,
    and Documentation.

.PARAMETER RulePackagePath
    Analytics-rule JSON package. Defaults to
    <OutputPath>\Assessment\AnalyticsRules.json.

.PARAMETER EnableRules
    Allows rules whose package property enabled is true to be deployed enabled.
    Without this switch every deployed rule is forced disabled.

.PARAMETER SkipQueryValidation
    Skips online KQL validation before deployment. Offline package validation still
    runs. Use only when Log Analytics query access is intentionally unavailable.

.PARAMETER OnlineValidation
    Runs live KQL compilation against the target workspace during ValidateRules.

.PARAMETER LookbackDays
    Number of days checked by ingestion validation.

.EXAMPLE
    .\Invoke-LogRhythmSentinelMigration.ps1

.EXAMPLE
    .\Invoke-LogRhythmSentinelMigration.ps1 -Action Migrate `
        -SqlServer LRPM01 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroupName rg-soc -WorkspaceName law-sentinel

.EXAMPLE
    $credential = Get-Credential
    .\Invoke-LogRhythmSentinelMigration.ps1 -Action Export `
        -SqlServer 'LRPM01\LOGRHYTHM' -UseSqlAuthentication `
        -SqlCredential $credential -TrustServerCertificate

.EXAMPLE
    .\Invoke-LogRhythmSentinelMigration.ps1 -Action DeployRules `
        -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroupName rg-soc -WorkspaceName law-sentinel -WhatIf

.NOTES
    The script supports Windows PowerShell 5.1 and PowerShell 7+.
#>

#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet(
        'Menu',
        'Status',
        'InstallPrerequisites',
        'Export',
        'Inventory',
        'Assess',
        'ValidateRules',
        'DeployRules',
        'ValidateIngestion',
        'Migrate',
        'Update',
        'SelfTest'
    )]
    [string]$Action = 'Menu',

    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'LogRhythm-Sentinel-Migration'),

    [string]$SqlServer = 'localhost',
    [string]$Database = 'LogRhythmEMDB',
    [Alias('SqlAuth')]
    [switch]$UseSqlAuthentication,
    [System.Management.Automation.PSCredential]$SqlCredential,
    [bool]$EncryptSqlConnection = $true,
    [switch]$TrustServerCertificate,
    [string]$AieXmlPath,

    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$WorkspaceName,

    [string]$MappingOverridesPath,
    [string]$RulePackagePath,
    [switch]$EnableRules,
    [switch]$SkipQueryValidation,
    [switch]$OnlineValidation,

    [ValidateRange(1, 90)]
    [int]$LookbackDays = 7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptVersion = [version]'1.0.1'
$script:Repository = 'oguzhanf/logrhythm-to-sentinel-migration-helper'
$script:SentinelApiVersion = '2025-09-01'
$script:LogAnalyticsTablesApiVersion = '2023-09-01'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:AzureTokenSubscriptionId = ''
$script:AzureAccessTokenCache = @{}

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ("`n==> {0}" -f $Message) -ForegroundColor Cyan
}

function Write-Success {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ("[OK] {0}" -f $Message) -ForegroundColor Green
}

function Write-Notice {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host ("[!]  {0}" -f $Message) -ForegroundColor Yellow
}

function Get-MigrationPaths {
    param([Parameter(Mandatory = $true)][string]$Root)

    $resolvedRoot = [System.IO.Path]::GetFullPath($Root)
    [pscustomobject]@{
        Root       = $resolvedRoot
        LogRhythm  = Join-Path $resolvedRoot 'LogRhythm'
        Sentinel   = Join-Path $resolvedRoot 'Sentinel'
        Assessment = Join-Path $resolvedRoot 'Assessment'
        Deployment = Join-Path $resolvedRoot 'Deployment'
    }
}

function Initialize-MigrationPaths {
    param([Parameter(Mandatory = $true)][string]$Root)

    $paths = Get-MigrationPaths -Root $Root
    foreach ($path in @($paths.Root, $paths.LogRhythm, $paths.Sentinel, $paths.Assessment, $paths.Deployment)) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $path -Force)
        }
    }
    return $paths
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = ConvertTo-Json -InputObject $InputObject -Depth 100
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $script:Utf8NoBom)
}

function Export-CsvFile {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($InputObject.Count -eq 0) {
        [System.IO.File]::WriteAllText($Path, [string]::Empty, $script:Utf8NoBom)
        return
    }

    $InputObject | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ieq $name } |
            Select-Object -First 1
        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }
    return $Default
}

function ConvertTo-CompactJson {
    param($InputObject)

    if ($null -eq $InputObject) {
        return ''
    }
    return (ConvertTo-Json -InputObject $InputObject -Depth 50 -Compress)
}

function Invoke-NativeText {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Arguments
    )

    $output = & $Command @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        if ([string]::IsNullOrWhiteSpace($text)) {
            $text = 'No error text was returned.'
        }
        throw "'$Command' exited with code $exitCode. $text"
    }
    return $text
}

function Invoke-AzJson {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowEmpty
    )

    $allArguments = @($Arguments) + @('--only-show-errors', '--output', 'json')
    $errorPath = Join-Path ([System.IO.Path]::GetTempPath()) (
        'lr-sentinel-az-error-{0}.txt' -f ([guid]::NewGuid().ToString('N'))
    )
    try {
        $output = & az @allArguments 2> $errorPath
        $exitCode = $LASTEXITCODE
        $text = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $errorText = if (Test-Path -LiteralPath $errorPath) {
            [System.IO.File]::ReadAllText($errorPath)
        }
        else {
            ''
        }
        if ($exitCode -ne 0) {
            $detail = @($errorText.Trim(), $text.Trim()) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            throw "Azure CLI exited with code $exitCode. $($detail -join ' ')"
        }
        if (-not [string]::IsNullOrWhiteSpace($errorText)) {
            Write-Verbose $errorText.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($text)) {
            if ($AllowEmpty) {
                return $null
            }
            throw "Azure CLI returned no JSON for: az $($Arguments -join ' ')"
        }

        try {
            return ($text | ConvertFrom-Json)
        }
        catch {
            throw "Azure CLI returned invalid JSON for: az $($Arguments -join ' '). $($_.Exception.Message)"
        }
    }
    finally {
        if (Test-Path -LiteralPath $errorPath) {
            Remove-Item -LiteralPath $errorPath -Force
        }
    }
}

function Get-AzureAccessToken {
    param(
        [Parameter(Mandatory = $true)][string]$Resource,
        [switch]$ForceRefresh
    )

    $cacheKey = '{0}|{1}' -f $Resource.TrimEnd('/'), $script:AzureTokenSubscriptionId
    if (-not $ForceRefresh -and $script:AzureAccessTokenCache.ContainsKey($cacheKey)) {
        $cached = $script:AzureAccessTokenCache[$cacheKey]
        if ($cached.ExpiresAtUtc -gt [datetime]::UtcNow.AddMinutes(5)) {
            return [string]$cached.AccessToken
        }
    }

    $arguments = @('account', 'get-access-token', '--resource', $Resource)
    if (-not [string]::IsNullOrWhiteSpace($script:AzureTokenSubscriptionId)) {
        $arguments += @('--subscription', $script:AzureTokenSubscriptionId)
    }
    $tokenResponse = Invoke-AzJson -Arguments $arguments
    $accessToken = [string](Get-PropertyValue -InputObject $tokenResponse -Names @('accessToken'))
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        throw "Azure CLI did not return an access token for '$Resource'."
    }

    $expiresAtUtc = [datetime]::UtcNow.AddMinutes(30)
    $epochText = [string](Get-PropertyValue -InputObject $tokenResponse -Names @('expires_on') -Default '')
    $epoch = 0L
    if ([long]::TryParse($epochText, [ref]$epoch)) {
        $expiresAtUtc = [datetimeoffset]::FromUnixTimeSeconds($epoch).UtcDateTime
    }
    else {
        $expiresText = [string](Get-PropertyValue -InputObject $tokenResponse -Names @('expiresOn') -Default '')
        $parsedExpiry = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse($expiresText, [ref]$parsedExpiry)) {
            $expiresAtUtc = $parsedExpiry.UtcDateTime
        }
    }

    $script:AzureAccessTokenCache[$cacheKey] = [pscustomobject]@{
        AccessToken = $accessToken
        ExpiresAtUtc = $expiresAtUtc
    }
    return $accessToken
}

function Get-RestErrorDetail {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    if ($null -ne $ErrorRecord.ErrorDetails -and
        -not [string]::IsNullOrWhiteSpace([string]$ErrorRecord.ErrorDetails.Message)) {
        return [string]$ErrorRecord.ErrorDetails.Message
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ErrorRecord.Exception.Message)) {
        return [string]$ErrorRecord.Exception.Message
    }
    return 'No HTTP error detail was returned.'
}

function Invoke-AuthenticatedJsonRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'PUT', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$TokenResource,
        $Body,
        [switch]$AllowEmpty
    )

    [System.Net.ServicePointManager]::SecurityProtocol = (
        [System.Net.ServicePointManager]::SecurityProtocol -bor
        [System.Net.SecurityProtocolType]::Tls12
    )

    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $token = Get-AzureAccessToken -Resource $TokenResource -ForceRefresh:($attempt -gt 0)
        $request = @{
            Uri         = $Url
            Method      = $Method
            Headers     = @{ Authorization = "Bearer $token" }
            ErrorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $request.ContentType = 'application/json'
            $request.Body = ConvertTo-Json -InputObject $Body -Depth 100 -Compress
        }
        try {
            $response = Invoke-RestMethod @request
            if ($null -eq $response -and -not $AllowEmpty) {
                throw "HTTP $Method '$Url' returned an empty response."
            }
            return $response
        }
        catch {
            $statusCode = 0
            $responseProperty = $_.Exception.PSObject.Properties |
                Where-Object { $_.Name -eq 'Response' } |
                Select-Object -First 1
            if ($responseProperty -and $responseProperty.Value) {
                $statusProperty = $responseProperty.Value.PSObject.Properties |
                    Where-Object { $_.Name -eq 'StatusCode' } |
                    Select-Object -First 1
                if ($statusProperty -and $null -ne $statusProperty.Value) {
                    $statusCode = [int]$statusProperty.Value
                }
            }
            if ($statusCode -eq 401 -and $attempt -eq 0) {
                $cacheKey = '{0}|{1}' -f $TokenResource.TrimEnd('/'), $script:AzureTokenSubscriptionId
                [void]$script:AzureAccessTokenCache.Remove($cacheKey)
                continue
            }
            $detail = Get-RestErrorDetail -ErrorRecord $_
            throw "HTTP $Method '$Url' failed. $detail"
        }
    }
    throw "HTTP $Method '$Url' failed after refreshing the Azure access token."
}

function Invoke-ArmRestJson {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'PUT', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        $Body,
        [switch]$AllowEmpty
    )

    $parameters = @{
        Method        = $Method
        Url           = $Url
        TokenResource = 'https://management.azure.com/'
        AllowEmpty    = $AllowEmpty
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.Body = $Body
    }
    return Invoke-AuthenticatedJsonRequest @parameters
}

function Invoke-ArmRestPaged {
    param([Parameter(Mandatory = $true)][string]$Url)

    $items = New-Object System.Collections.Generic.List[object]
    $nextUrl = $Url
    while (-not [string]::IsNullOrWhiteSpace($nextUrl)) {
        $response = Invoke-ArmRestJson -Method GET -Url $nextUrl
        $valueProperty = $response.PSObject.Properties |
            Where-Object { $_.Name -ieq 'value' } |
            Select-Object -First 1
        if ($null -eq $valueProperty) {
            throw "Paged Azure response from '$nextUrl' did not contain a value array."
        }
        foreach ($item in @($valueProperty.Value)) {
            $items.Add($item)
        }
        $nextLink = Get-PropertyValue -InputObject $response -Names @('nextLink') -Default ''
        $nextUrl = [string]$nextLink
    }
    return $items.ToArray()
}

function Assert-AzureCli {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI is required for this action. Run this script with -Action InstallPrerequisites."
    }

    try {
        return Invoke-AzJson -Arguments @('account', 'show')
    }
    catch {
        throw "Azure CLI is not authenticated. Run 'az login', then retry. $($_.Exception.Message)"
    }
}

function Set-AzureSubscription {
    param([string]$RequestedSubscriptionId)

    $account = Assert-AzureCli
    if (-not [string]::IsNullOrWhiteSpace($RequestedSubscriptionId)) {
        $account = Invoke-AzJson -Arguments @(
            'account', 'show', '--subscription', $RequestedSubscriptionId
        )
    }
    $script:AzureTokenSubscriptionId = [string]$account.id
    return $account
}

function Resolve-AzureTarget {
    param(
        [string]$RequestedSubscriptionId,
        [Parameter(Mandatory = $true)][string]$RequestedResourceGroupName,
        [Parameter(Mandatory = $true)][string]$RequestedWorkspaceName
    )

    if ([string]::IsNullOrWhiteSpace($RequestedResourceGroupName)) {
        throw 'ResourceGroupName is required for this action.'
    }
    if ([string]::IsNullOrWhiteSpace($RequestedWorkspaceName)) {
        throw 'WorkspaceName is required for this action.'
    }

    $account = Set-AzureSubscription -RequestedSubscriptionId $RequestedSubscriptionId
    $subscription = [string](Get-PropertyValue -InputObject $account -Names @('id'))

    $escapedResourceGroup = [uri]::EscapeDataString($RequestedResourceGroupName)
    $escapedWorkspace = [uri]::EscapeDataString($RequestedWorkspaceName)
    $workspaceResourceId = (
        '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}' -f
        $subscription,
        $escapedResourceGroup,
        $escapedWorkspace
    )

    [pscustomobject]@{
        SubscriptionId    = $subscription
        ResourceGroupName = $RequestedResourceGroupName
        WorkspaceName     = $RequestedWorkspaceName
        WorkspaceId       = $workspaceResourceId
        SentinelBaseUrl   = "https://management.azure.com$workspaceResourceId/providers/Microsoft.SecurityInsights"
    }
}

function Get-PrerequisiteStatus {
    $azureCli = Get-Command az -ErrorAction SilentlyContinue
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    $gitHubCli = Get-Command gh -ErrorAction SilentlyContinue
    $azureAccount = $null

    if ($azureCli) {
        try {
            $azureAccount = Invoke-AzJson -Arguments @('account', 'show')
        }
        catch {
            $azureAccount = $null
        }
    }

    $status = @(
        [pscustomobject]@{
            Component = 'PowerShell'
            Required  = $true
            Status    = if ($PSVersionTable.PSVersion.Major -ge 5) { 'Ready' } else { 'Upgrade required' }
            Detail    = $PSVersionTable.PSVersion.ToString()
        },
        [pscustomobject]@{
            Component = '.NET SqlClient'
            Required  = $true
            Status    = if ('System.Data.SqlClient.SqlConnection' -as [type]) { 'Ready' } else { 'Missing' }
            Detail    = 'Built into supported PowerShell versions'
        },
        [pscustomobject]@{
            Component = 'Azure CLI'
            Required  = 'Sentinel actions'
            Status    = if ($azureCli) { 'Ready' } else { 'Missing' }
            Detail    = if ($azureCli) { $azureCli.Source } else { 'Install with menu option 2' }
        },
        [pscustomobject]@{
            Component = 'Azure sign-in'
            Required  = 'Sentinel actions'
            Status    = if ($azureAccount) { 'Ready' } else { 'Not signed in' }
            Detail    = if ($azureAccount) {
                '{0} / {1}' -f $azureAccount.user.name, $azureAccount.name
            }
            else {
                'Run az login'
            }
        },
        [pscustomobject]@{
            Component = 'Windows Package Manager'
            Required  = 'Prerequisite install'
            Status    = if ($winget) { 'Ready' } else { 'Missing' }
            Detail    = if ($winget) { $winget.Source } else { 'Install App Installer from Microsoft Store' }
        },
        [pscustomobject]@{
            Component = 'GitHub CLI'
            Required  = $false
            Status    = if ($gitHubCli) { 'Ready' } else { 'Not installed' }
            Detail    = 'Not required by the migration workflow'
        }
    )
    return $status
}

function Show-PrerequisiteStatus {
    Write-Step "Migration helper $script:ScriptVersion prerequisite status"
    $status = Get-PrerequisiteStatus
    $status | Format-Table -AutoSize | Out-Host
    return $status
}

function Install-MigrationPrerequisites {
    Write-Step 'Installing migration prerequisites'

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw 'Azure CLI is missing and winget is unavailable. Install Microsoft App Installer, then rerun this action.'
        }
        [void](Invoke-NativeText -Command 'winget' -Arguments @(
            'install',
            '--id', 'Microsoft.AzureCLI',
            '--exact',
            '--accept-package-agreements',
            '--accept-source-agreements',
            '--silent'
        ))
        Write-Success 'Azure CLI installation completed. Reopen PowerShell if az is not yet on PATH.'
    }
    else {
        Write-Success 'Azure CLI is already installed.'
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        try {
            $account = Set-AzureSubscription -RequestedSubscriptionId $SubscriptionId
            foreach ($provider in @('Microsoft.OperationalInsights', 'Microsoft.SecurityInsights')) {
                $state = Invoke-AzJson -Arguments @(
                    'provider', 'show',
                    '--namespace', $provider,
                    '--subscription', $account.id,
                    '--query', '{registrationState:registrationState}'
                )
                if ($state.registrationState -ne 'Registered') {
                    [void](Invoke-NativeText -Command 'az' -Arguments @(
                        'provider', 'register',
                        '--namespace', $provider,
                        '--subscription', $account.id,
                        '--wait',
                        '--only-show-errors'
                    ))
                }
                Write-Success "$provider is registered in subscription $($account.id)."
            }
        }
        catch {
            Write-Notice "Azure provider registration was not completed: $($_.Exception.Message)"
            Write-Notice "Sign in with 'az login' and rerun InstallPrerequisites."
        }
    }
}

function New-SqlConnection {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [switch]$SqlAuthentication,
        [System.Management.Automation.PSCredential]$Credential,
        [bool]$Encrypt = $true,
        [switch]$TrustCertificate
    )

    $builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder['Data Source'] = $Server
    $builder['Initial Catalog'] = $DatabaseName
    $builder['Application Name'] = 'LogRhythm Sentinel Migration Helper'
    $builder['Connect Timeout'] = 30
    $builder['Encrypt'] = $Encrypt
    $builder['TrustServerCertificate'] = [bool]$TrustCertificate

    if ($SqlAuthentication) {
        if ($null -eq $Credential) {
            $Credential = Get-Credential -Message "SQL login for $DatabaseName on $Server"
        }
        if ($null -eq $Credential) {
            throw 'SQL authentication was selected, but no credential was supplied.'
        }
        $builder['Integrated Security'] = $false
        $connection = New-Object `
            -TypeName System.Data.SqlClient.SqlConnection `
            -ArgumentList $builder.ConnectionString
        $securePassword = $Credential.Password.Copy()
        $securePassword.MakeReadOnly()
        $connection.Credential = New-Object `
            -TypeName System.Data.SqlClient.SqlCredential `
            -ArgumentList $Credential.UserName, $securePassword
        return $connection
    }

    $builder['Integrated Security'] = $true
    return (New-Object `
        -TypeName System.Data.SqlClient.SqlConnection `
        -ArgumentList $builder.ConnectionString)
}

function Invoke-SqlDataTable {
    param(
        [Parameter(Mandatory = $true)][System.Data.SqlClient.SqlConnection]$Connection,
        [Parameter(Mandatory = $true)][string]$Query,
        [int]$CommandTimeoutSeconds = 300
    )

    $command = $Connection.CreateCommand()
    $adapter = $null
    try {
        $command.CommandText = $Query
        $command.CommandTimeout = $CommandTimeoutSeconds
        $adapter = New-Object `
            -TypeName System.Data.SqlClient.SqlDataAdapter `
            -ArgumentList $command
        $table = New-Object System.Data.DataTable
        [void]$adapter.Fill($table)
        return ,$table
    }
    finally {
        if ($adapter) {
            $adapter.Dispose()
        }
        $command.Dispose()
    }
}

function Export-DataTable {
    param(
        [Parameter(Mandatory = $true)][System.Data.DataTable]$Table,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($Table.Rows.Count -eq 0) {
        $headers = @($Table.Columns | ForEach-Object { $_.ColumnName })
        if ($headers.Count -gt 0) {
            $quotedHeaders = $headers | ForEach-Object {
                '"' + ([string]$_).Replace('"', '""') + '"'
            }
            [System.IO.File]::WriteAllText(
                $Path,
                ($quotedHeaders -join ',') + [Environment]::NewLine,
                $script:Utf8NoBom
            )
        }
        else {
            [System.IO.File]::WriteAllText($Path, [string]::Empty, $script:Utf8NoBom)
        }
        return
    }

    $Table | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Test-SchemaObject {
    param(
        [Parameter(Mandatory = $true)][System.Data.DataTable]$Schema,
        [Parameter(Mandatory = $true)][string]$TableName,
        [string]$ColumnName,
        [string]$SchemaName
    )

    foreach ($row in $Schema.Rows) {
        if ([string]$row.TableName -ieq $TableName -and
            ([string]::IsNullOrWhiteSpace($SchemaName) -or
             [string]$row.SchemaName -ieq $SchemaName)) {
            if ([string]::IsNullOrWhiteSpace($ColumnName) -or
                [string]$row.ColumnName -ieq $ColumnName) {
                return $true
            }
        }
    }
    return $false
}

function Resolve-SchemaTable {
    param(
        [Parameter(Mandatory = $true)][System.Data.DataTable]$Schema,
        [Parameter(Mandatory = $true)][string[]]$TableNames
    )

    foreach ($tableName in $TableNames) {
        $match = $null
        foreach ($row in $Schema.Rows) {
            if ([string]$row.TableName -ine $tableName) {
                continue
            }
            if ($null -eq $match -or [string]$row.SchemaName -ieq 'dbo') {
                $match = $row
            }
            if ([string]$row.SchemaName -ieq 'dbo') {
                break
            }
        }
        if ($null -ne $match) {
            return [pscustomobject]@{
                SchemaName = [string]$match.SchemaName
                TableName  = [string]$match.TableName
            }
        }
    }
    return $null
}

function Get-QualifiedSqlName {
    param(
        [Parameter(Mandatory = $true)][string]$SchemaName,
        [Parameter(Mandatory = $true)][string]$TableName
    )

    return '[{0}].[{1}]' -f $SchemaName.Replace(']', ']]'), $TableName.Replace(']', ']]')
}

function Get-XmlNodeValue {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Node.Attributes) {
            foreach ($attribute in $Node.Attributes) {
                if ($attribute.LocalName -ieq $name -and
                    -not [string]::IsNullOrWhiteSpace($attribute.Value)) {
                    return $attribute.Value
                }
            }
        }

        $child = $Node.SelectSingleNode((
            ".//*[translate(local-name(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='{0}']" -f
            $name.ToLowerInvariant()
        ))
        if ($child -and -not [string]::IsNullOrWhiteSpace($child.InnerText)) {
            return $child.InnerText.Trim()
        }
    }
    return ''
}

function Convert-LogRhythmAieXml {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "AIE XML path '$Path' does not exist."
    }

    $item = Get-Item -LiteralPath $Path
    $files = @(if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $item.FullName -Filter '*.xml' -File -Recurse
    }
    else {
        if ($item.Extension -ine '.xml') {
            throw "AIE rule input '$Path' is not an XML file."
        }
        $item
    })

    if ($files.Count -eq 0) {
        throw "No XML files were found under '$Path'."
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($file in $files) {
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = $null
        try {
            $reader = [System.Xml.XmlReader]::Create($file.FullName, $settings)
            $document = New-Object System.Xml.XmlDocument
            $document.XmlResolver = $null
            $document.Load($reader)
        }
        finally {
            if ($reader) {
                $reader.Dispose()
            }
        }

        $candidateNodes = @($document.SelectNodes(
            "//*[local-name()='AIERule' or local-name()='AieRule' or local-name()='AlarmRule' or local-name()='Rule']"
        ))
        if ($candidateNodes.Count -eq 0) {
            $candidateNodes = @($document.DocumentElement)
        }

        foreach ($node in $candidateNodes) {
            $rows.Add([pscustomobject]@{
                SourceFile  = $file.Name
                XmlSha256   = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                RootElement = $document.DocumentElement.LocalName
                Element     = $node.LocalName
                RuleId      = Get-XmlNodeValue -Node $node -Names @('RuleID', 'RuleId', 'ID', 'Guid')
                RuleName    = Get-XmlNodeValue -Node $node -Names @('RuleName', 'Name', 'DisplayName')
                Description = Get-XmlNodeValue -Node $node -Names @('Description', 'LongDescription')
                Enabled     = Get-XmlNodeValue -Node $node -Names @('Enabled', 'IsEnabled', 'Active')
                RiskRating  = Get-XmlNodeValue -Node $node -Names @('RiskRating', 'Risk', 'Severity')
            })
        }
    }
    return $rows.ToArray()
}

function Export-LogRhythmInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$DatabaseName,
        [switch]$SqlAuthentication,
        [System.Management.Automation.PSCredential]$Credential,
        [bool]$Encrypt = $true,
        [switch]$TrustCertificate,
        [string]$RuleXmlPath
    )

    $paths = Initialize-MigrationPaths -Root $Root
    Write-Step "Exporting LogRhythm inventory from $Server / $DatabaseName"

    $connection = New-SqlConnection `
        -Server $Server `
        -DatabaseName $DatabaseName `
        -SqlAuthentication:$SqlAuthentication `
        -Credential $Credential `
        -Encrypt:$Encrypt `
        -TrustCertificate:$TrustCertificate

    $exportResults = New-Object System.Collections.Generic.List[object]
    $missingOptional = New-Object System.Collections.Generic.List[string]
    try {
        $connection.Open()
        Write-Success 'SQL connection established.'

        $schemaQuery = @'
SELECT
    s.name AS SchemaName,
    t.name AS TableName,
    c.column_id AS ColumnOrdinal,
    c.name AS ColumnName,
    ty.name AS DataType,
    c.max_length AS MaxLength,
    c.is_nullable AS IsNullable
FROM sys.tables AS t
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.columns AS c ON c.object_id = t.object_id
JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
WHERE t.name LIKE '%LogSource%'
   OR t.name LIKE '%MsgSource%'
   OR t.name LIKE '%AIE%'
   OR t.name LIKE '%Alarm%'
   OR t.name LIKE '%Host%'
   OR t.name LIKE '%Entity%'
ORDER BY s.name, t.name, c.column_id;
'@
        $schema = Invoke-SqlDataTable -Connection $connection -Query $schemaQuery
        $schemaPath = Join-Path $paths.LogRhythm 'RelevantSchema.csv'
        Export-DataTable -Table $schema -Path $schemaPath
        $exportResults.Add([pscustomobject]@{
            Name = 'RelevantSchema'; Rows = $schema.Rows.Count; File = $schemaPath
        })

        $logSourceTable = Resolve-SchemaTable -Schema $schema -TableNames @('MsgSource', 'LogSource')
        if ($null -eq $logSourceTable) {
            throw "Neither MsgSource nor LogSource was found. Review '$schemaPath' and the companion LogRhythm-Export.sql for this LogRhythm build."
        }
        $logSourceSqlName = Get-QualifiedSqlName `
            -SchemaName $logSourceTable.SchemaName `
            -TableName $logSourceTable.TableName
        Write-Success (
            "Using {0}.{1} for the log-source inventory." -f
            $logSourceTable.SchemaName, $logSourceTable.TableName
        )

        $hostTable = Resolve-SchemaTable -Schema $schema -TableNames @('Host')
        $entityTable = Resolve-SchemaTable -Schema $schema -TableNames @('Entity')
        $typeTable = Resolve-SchemaTable -Schema $schema -TableNames @('MsgSourceType', 'LogSourceType')

        $hasHostJoin = (
            $null -ne $hostTable -and
            (Test-SchemaObject -Schema $schema `
                -SchemaName $logSourceTable.SchemaName `
                -TableName $logSourceTable.TableName `
                -ColumnName 'HostID') -and
            (Test-SchemaObject -Schema $schema `
                -SchemaName $hostTable.SchemaName `
                -TableName $hostTable.TableName `
                -ColumnName 'HostID')
        )
        $hasEntityJoin = (
            $hasHostJoin -and
            $null -ne $entityTable -and
            (Test-SchemaObject -Schema $schema `
                -SchemaName $hostTable.SchemaName `
                -TableName $hostTable.TableName `
                -ColumnName 'EntityID') -and
            (Test-SchemaObject -Schema $schema `
                -SchemaName $entityTable.SchemaName `
                -TableName $entityTable.TableName `
                -ColumnName 'EntityID')
        )
        $hasTypeJoin = (
            $null -ne $typeTable -and
            (Test-SchemaObject -Schema $schema `
                -SchemaName $logSourceTable.SchemaName `
                -TableName $logSourceTable.TableName `
                -ColumnName 'MsgSourceTypeID') -and
            (Test-SchemaObject -Schema $schema `
                -SchemaName $typeTable.SchemaName `
                -TableName $typeTable.TableName `
                -ColumnName 'MsgSourceTypeID')
        )

        $selectColumns = @()
        $joins = @()
        if ($hasEntityJoin) {
            $selectColumns += 'e.Name AS Entity'
        }
        else {
            $selectColumns += 'CAST(NULL AS nvarchar(256)) AS Entity'
        }
        if ($hasHostJoin) {
            $selectColumns += 'h.Name AS HostName'
            $hostSqlName = Get-QualifiedSqlName `
                -SchemaName $hostTable.SchemaName `
                -TableName $hostTable.TableName
            $joins += "LEFT JOIN $hostSqlName AS h ON ls.HostID = h.HostID"
        }
        else {
            $selectColumns += 'CAST(NULL AS nvarchar(256)) AS HostName'
        }
        if ($hasEntityJoin) {
            $entitySqlName = Get-QualifiedSqlName `
                -SchemaName $entityTable.SchemaName `
                -TableName $entityTable.TableName
            $joins += "LEFT JOIN $entitySqlName AS e ON h.EntityID = e.EntityID"
        }
        if ($hasTypeJoin) {
            $selectColumns += 'mst.Name AS LogSourceType'
            $typeSqlName = Get-QualifiedSqlName `
                -SchemaName $typeTable.SchemaName `
                -TableName $typeTable.TableName
            $joins += "LEFT JOIN $typeSqlName AS mst ON ls.MsgSourceTypeID = mst.MsgSourceTypeID"
        }
        elseif (Test-SchemaObject -Schema $schema `
                -SchemaName $logSourceTable.SchemaName `
                -TableName $logSourceTable.TableName `
                -ColumnName 'MsgSourceTypeID') {
            $selectColumns += 'CONVERT(nvarchar(64), ls.MsgSourceTypeID) AS LogSourceType'
        }
        else {
            $selectColumns += "CAST('(Unknown)' AS nvarchar(64)) AS LogSourceType"
        }
        $selectColumns += 'ls.*'

        $logSourceQuery = "SELECT`n    $($selectColumns -join ",`n    ")`nFROM $logSourceSqlName AS ls`n$($joins -join "`n");"
        $logSources = Invoke-SqlDataTable -Connection $connection -Query $logSourceQuery
        $logSourcesPath = Join-Path $paths.LogRhythm 'LogSources.csv'
        Export-DataTable -Table $logSources -Path $logSourcesPath
        $exportResults.Add([pscustomobject]@{
            Name = 'LogSources'; Rows = $logSources.Rows.Count; File = $logSourcesPath
        })

        if ($hasTypeJoin) {
            $typeQuery = @"
SELECT
    COALESCE(mst.Name, '(Unknown)') AS LogSourceType,
    COUNT_BIG(*) AS LogSourceCount
FROM $logSourceSqlName AS ls
LEFT JOIN $typeSqlName AS mst ON ls.MsgSourceTypeID = mst.MsgSourceTypeID
GROUP BY COALESCE(mst.Name, '(Unknown)')
ORDER BY COUNT_BIG(*) DESC, COALESCE(mst.Name, '(Unknown)');
"@
        }
        elseif (Test-SchemaObject -Schema $schema `
                -SchemaName $logSourceTable.SchemaName `
                -TableName $logSourceTable.TableName `
                -ColumnName 'MsgSourceTypeID') {
            $typeQuery = @"
SELECT
    CONVERT(nvarchar(64), MsgSourceTypeID) AS LogSourceType,
    COUNT_BIG(*) AS LogSourceCount
FROM $logSourceSqlName
GROUP BY MsgSourceTypeID
ORDER BY COUNT_BIG(*) DESC, MsgSourceTypeID;
"@
        }
        else {
            $typeQuery = "SELECT CAST('(Unknown)' AS nvarchar(64)) AS LogSourceType, COUNT_BIG(*) AS LogSourceCount FROM $logSourceSqlName;"
        }
        $sourceTypes = Invoke-SqlDataTable -Connection $connection -Query $typeQuery
        $sourceTypesPath = Join-Path $paths.LogRhythm 'LogSourceTypes.csv'
        Export-DataTable -Table $sourceTypes -Path $sourceTypesPath
        $exportResults.Add([pscustomobject]@{
            Name = 'LogSourceTypes'; Rows = $sourceTypes.Rows.Count; File = $sourceTypesPath
        })

        foreach ($optionalExport in @(
            [pscustomobject]@{ Name = 'Entities'; Table = 'Entity' },
            [pscustomobject]@{ Name = 'Hosts'; Table = 'Host' },
            [pscustomobject]@{ Name = 'MessageSourceTypes'; Table = 'MsgSourceType' },
            [pscustomobject]@{ Name = 'AIERules'; Table = 'AIERule' },
            [pscustomobject]@{ Name = 'AlarmRules'; Table = 'AlarmRule' }
        )) {
            $optionalTable = Resolve-SchemaTable `
                -Schema $schema `
                -TableNames @($optionalExport.Table)
            if ($null -ne $optionalTable) {
                $optionalSqlName = Get-QualifiedSqlName `
                    -SchemaName $optionalTable.SchemaName `
                    -TableName $optionalTable.TableName
                $table = Invoke-SqlDataTable `
                    -Connection $connection `
                    -Query "SELECT * FROM $optionalSqlName;"
                $file = Join-Path $paths.LogRhythm ($optionalExport.Name + '.csv')
                Export-DataTable -Table $table -Path $file
                $exportResults.Add([pscustomobject]@{
                    Name = $optionalExport.Name; Rows = $table.Rows.Count; File = $file
                })
            }
            else {
                $missingOptional.Add($optionalExport.Table)
                Write-Notice "Optional table $($optionalExport.Table) was not found."
            }
        }
    }
    finally {
        if ($connection.State -ne [System.Data.ConnectionState]::Closed) {
            $connection.Close()
        }
        $connection.Dispose()
    }

    if (-not [string]::IsNullOrWhiteSpace($RuleXmlPath)) {
        $xmlRows = @(Convert-LogRhythmAieXml -Path $RuleXmlPath)
        $xmlPath = Join-Path $paths.LogRhythm 'AieXmlRules.csv'
        Export-CsvFile -InputObject $xmlRows -Path $xmlPath
        $exportResults.Add([pscustomobject]@{
            Name = 'AieXmlRules'; Rows = $xmlRows.Count; File = $xmlPath
        })
    }
    else {
        Write-Notice 'No AIE XML path was supplied. Export AIE rules from the LogRhythm Console for full detection logic.'
    }

    $files = @()
    foreach ($result in $exportResults) {
        $files += [pscustomobject]@{
            Name   = $result.Name
            Rows   = $result.Rows
            File   = [System.IO.Path]::GetFileName($result.File)
            Sha256 = (Get-FileHash -LiteralPath $result.File -Algorithm SHA256).Hash
        }
        Write-Success ("{0}: {1} rows" -f $result.Name, $result.Rows)
    }

    $manifest = [pscustomobject]@{
        SchemaVersion      = '1.0'
        ToolVersion        = $script:ScriptVersion.ToString()
        ExportedAtUtc      = [datetime]::UtcNow.ToString('o')
        SqlServer          = $Server
        Database           = $DatabaseName
        Authentication     = if ($SqlAuthentication) { 'SQL credential' } else { 'Windows integrated' }
        Encrypted          = $Encrypt
        TrustedCertificate = [bool]$TrustCertificate
        LogSourceObject    = "$($logSourceTable.SchemaName).$($logSourceTable.TableName)"
        OptionalTablesNotFound = $missingOptional.ToArray()
        Files              = $files
    }
    Write-JsonFile -InputObject $manifest -Path (Join-Path $paths.LogRhythm 'ExportManifest.json')
    Write-Success "LogRhythm inventory written to $($paths.LogRhythm)."
    return $manifest
}

function Get-ConnectorDisplayName {
    param([Parameter(Mandatory = $true)]$Connector)

    $properties = Get-PropertyValue -InputObject $Connector -Names @('properties')
    if ($null -ne $properties) {
        $display = Get-PropertyValue -InputObject $properties -Names @('displayName', 'title')
        if (-not [string]::IsNullOrWhiteSpace([string]$display)) {
            return [string]$display
        }
        $uiConfig = Get-PropertyValue -InputObject $properties -Names @('connectorUiConfig')
        if ($null -ne $uiConfig) {
            $title = Get-PropertyValue -InputObject $uiConfig -Names @('title')
            if (-not [string]::IsNullOrWhiteSpace([string]$title)) {
                return [string]$title
            }
        }
    }
    return [string](Get-PropertyValue -InputObject $Connector -Names @('kind', 'name') -Default '')
}

function Export-SentinelInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$RequestedSubscriptionId,
        [Parameter(Mandatory = $true)][string]$RequestedResourceGroupName,
        [Parameter(Mandatory = $true)][string]$RequestedWorkspaceName
    )

    $paths = Initialize-MigrationPaths -Root $Root
    $target = Resolve-AzureTarget `
        -RequestedSubscriptionId $RequestedSubscriptionId `
        -RequestedResourceGroupName $RequestedResourceGroupName `
        -RequestedWorkspaceName $RequestedWorkspaceName

    Write-Step "Inventorying Sentinel workspace $($target.WorkspaceName)"
    $workspaceUrl = "https://management.azure.com$($target.WorkspaceId)?api-version=2023-09-01"
    $workspace = Invoke-ArmRestJson -Method GET -Url $workspaceUrl

    $sentinelApi = $script:SentinelApiVersion
    $connectors = @(Invoke-ArmRestPaged -Url (
        "$($target.SentinelBaseUrl)/dataConnectors?api-version=$sentinelApi"
    ))
    $alertRules = @(Invoke-ArmRestPaged -Url (
        "$($target.SentinelBaseUrl)/alertRules?api-version=$sentinelApi"
    ))
    $automationRules = @(Invoke-ArmRestPaged -Url (
        "$($target.SentinelBaseUrl)/automationRules?api-version=$sentinelApi"
    ))
    $watchlists = @(Invoke-ArmRestPaged -Url (
        "$($target.SentinelBaseUrl)/watchlists?api-version=$sentinelApi"
    ))
    $tables = @(Invoke-ArmRestPaged -Url (
        "https://management.azure.com$($target.WorkspaceId)/tables?api-version=$($script:LogAnalyticsTablesApiVersion)"
    ))

    Write-JsonFile -InputObject $workspace -Path (Join-Path $paths.Sentinel 'Workspace.json')
    Write-JsonFile -InputObject $connectors -Path (Join-Path $paths.Sentinel 'DataConnectors.json')
    Write-JsonFile -InputObject $alertRules -Path (Join-Path $paths.Sentinel 'AnalyticsRules.json')
    Write-JsonFile -InputObject $automationRules -Path (Join-Path $paths.Sentinel 'AutomationRules.json')
    Write-JsonFile -InputObject $watchlists -Path (Join-Path $paths.Sentinel 'Watchlists.json')
    Write-JsonFile -InputObject $tables -Path (Join-Path $paths.Sentinel 'Tables.json')

    $connectorRows = @($connectors | ForEach-Object {
        $properties = Get-PropertyValue -InputObject $_ -Names @('properties')
        $stateValue = Get-PropertyValue -InputObject $properties -Names @(
            'isEnabled', 'dataCollectionEndpoint', 'connectivityCriteria'
        ) -Default ''
        [pscustomobject]@{
            ResourceName = [string](Get-PropertyValue -InputObject $_ -Names @('name'))
            Kind         = [string](Get-PropertyValue -InputObject $_ -Names @('kind'))
            DisplayName  = Get-ConnectorDisplayName -Connector $_
            State        = if ($stateValue -is [string] -or $stateValue -is [System.ValueType]) {
                [string]$stateValue
            }
            else {
                ConvertTo-CompactJson $stateValue
            }
            DataTypes    = ConvertTo-CompactJson (
                Get-PropertyValue -InputObject $properties -Names @('dataTypes')
            )
        }
    })
    Export-CsvFile -InputObject $connectorRows -Path (Join-Path $paths.Sentinel 'DataConnectors.csv')

    $ruleRows = @($alertRules | ForEach-Object {
        $properties = Get-PropertyValue -InputObject $_ -Names @('properties')
        [pscustomobject]@{
            ResourceName  = [string](Get-PropertyValue -InputObject $_ -Names @('name'))
            Kind          = [string](Get-PropertyValue -InputObject $_ -Names @('kind'))
            DisplayName   = [string](Get-PropertyValue -InputObject $properties -Names @('displayName'))
            Enabled       = Get-PropertyValue -InputObject $properties -Names @('enabled')
            Severity      = [string](Get-PropertyValue -InputObject $properties -Names @('severity'))
            QueryFrequency = [string](Get-PropertyValue -InputObject $properties -Names @('queryFrequency'))
            QueryPeriod   = [string](Get-PropertyValue -InputObject $properties -Names @('queryPeriod'))
            Query         = [string](Get-PropertyValue -InputObject $properties -Names @('query'))
        }
    })
    Export-CsvFile -InputObject $ruleRows -Path (Join-Path $paths.Sentinel 'AnalyticsRules.csv')

    $automationRows = @($automationRules | ForEach-Object {
        $properties = Get-PropertyValue -InputObject $_ -Names @('properties')
        $triggeringLogic = Get-PropertyValue -InputObject $properties -Names @('triggeringLogic')
        [pscustomobject]@{
            ResourceName = [string](Get-PropertyValue -InputObject $_ -Names @('name'))
            DisplayName  = [string](Get-PropertyValue -InputObject $properties -Names @('displayName'))
            Order        = Get-PropertyValue -InputObject $properties -Names @('order')
            Enabled      = Get-PropertyValue -InputObject $triggeringLogic -Names @('isEnabled')
            TriggersOn   = [string](Get-PropertyValue -InputObject $triggeringLogic -Names @('triggersOn'))
            TriggersWhen = [string](Get-PropertyValue -InputObject $triggeringLogic -Names @('triggersWhen'))
        }
    })
    Export-CsvFile -InputObject $automationRows -Path (Join-Path $paths.Sentinel 'AutomationRules.csv')

    $watchlistRows = @($watchlists | ForEach-Object {
        $properties = Get-PropertyValue -InputObject $_ -Names @('properties')
        [pscustomobject]@{
            Alias       = [string](Get-PropertyValue -InputObject $_ -Names @('name'))
            DisplayName = [string](Get-PropertyValue -InputObject $properties -Names @('displayName'))
            Provider    = [string](Get-PropertyValue -InputObject $properties -Names @('provider'))
            Source      = [string](Get-PropertyValue -InputObject $properties -Names @('source'))
            ItemsSearchKey = [string](Get-PropertyValue -InputObject $properties -Names @('itemsSearchKey'))
        }
    })
    Export-CsvFile -InputObject $watchlistRows -Path (Join-Path $paths.Sentinel 'Watchlists.csv')

    $tableRows = @($tables | ForEach-Object {
        $properties = Get-PropertyValue -InputObject $_ -Names @('properties')
        [pscustomobject]@{
            Name                 = [string](Get-PropertyValue -InputObject $_ -Names @('name'))
            Plan                 = [string](Get-PropertyValue -InputObject $properties -Names @('plan'))
            RetentionInDays      = Get-PropertyValue -InputObject $properties -Names @('retentionInDays')
            TotalRetentionInDays = Get-PropertyValue -InputObject $properties -Names @('totalRetentionInDays')
            ArchiveRetentionInDays = Get-PropertyValue -InputObject $properties -Names @('archiveRetentionInDays')
        }
    })
    Export-CsvFile -InputObject $tableRows -Path (Join-Path $paths.Sentinel 'Tables.csv')

    $manifest = [pscustomobject]@{
        SchemaVersion       = '1.0'
        ToolVersion         = $script:ScriptVersion.ToString()
        InventoriedAtUtc    = [datetime]::UtcNow.ToString('o')
        SubscriptionId      = $target.SubscriptionId
        ResourceGroupName   = $target.ResourceGroupName
        WorkspaceName       = $target.WorkspaceName
        WorkspaceResourceId = $target.WorkspaceId
        WorkspaceCustomerId = [string](Get-PropertyValue `
            -InputObject (Get-PropertyValue -InputObject $workspace -Names @('properties')) `
            -Names @('customerId'))
        Counts = [pscustomobject]@{
            DataConnectors  = $connectors.Count
            AnalyticsRules  = $alertRules.Count
            AutomationRules = $automationRules.Count
            Watchlists      = $watchlists.Count
            Tables          = $tables.Count
        }
    }
    Write-JsonFile -InputObject $manifest -Path (Join-Path $paths.Sentinel 'InventoryManifest.json')
    Write-Success (
        'Sentinel inventory: {0} connectors, {1} rules, {2} tables.' -f
        $connectors.Count,
        $alertRules.Count,
        $tables.Count
    )
    return $manifest
}

function New-MappingEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Connector,
        [Parameter(Mandatory = $true)][string]$ConnectorMatch,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$TargetTables,
        [Parameter(Mandatory = $true)][string]$CollectionMethod,
        [Parameter(Mandatory = $true)][string]$MigrationApproach,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Documentation
    )

    [pscustomobject]@{
        Pattern            = $Pattern
        Connector          = $Connector
        ConnectorMatch     = $ConnectorMatch
        TargetTables       = $TargetTables
        CollectionMethod   = $CollectionMethod
        MigrationApproach  = $MigrationApproach
        Documentation      = $Documentation
    }
}

function Get-BuiltInMappings {
    $connectorReference = 'https://learn.microsoft.com/azure/sentinel/data-connectors-reference'
    return @(
        (New-MappingEntry '(?i)(Microsoft.*Windows.*(Security|Event)|Windows Event Log|Windows Security Audit)' 'Windows Security Events via AMA' '(?i)Windows Security' 'SecurityEvent;WindowsEvent' 'Azure Monitor Agent and data collection rule' 'Replace the LogRhythm collection policy with an AMA DCR; select only required channels and event IDs.' $connectorReference),
        (New-MappingEntry '(?i)(Sysmon)' 'Windows Security Events via AMA' '(?i)Windows Security|Sysmon' 'WindowsEvent' 'Azure Monitor Agent and data collection rule' 'Collect Microsoft-Windows-Sysmon/Operational through an AMA DCR and normalize detections to ASIM where practical.' $connectorReference),
        (New-MappingEntry '(?i)(Linux|Unix|AIX|Solaris).*Syslog|^Syslog$' 'Syslog via AMA' '(?i)Syslog' 'Syslog' 'Azure Monitor Agent and data collection rule' 'Forward RFC-compliant Syslog to an AMA Linux collector and scope facilities/severities in the DCR.' $connectorReference),
        (New-MappingEntry '(?i)(Palo Alto|PAN-OS|Cisco ASA|Cisco FTD|FortiGate|Fortinet|Check Point|SonicWall|Juniper.*(SRX|Firewall)|WatchGuard)' 'Common Event Format via AMA' '(?i)CEF|Common Event Format|Palo Alto|Fortinet|Cisco' 'CommonSecurityLog' 'CEF over Syslog to an AMA collector' 'Configure vendor CEF output, preserve source identifiers, and validate ASIM Network Session normalization.' $connectorReference),
        (New-MappingEntry '(?i)(Zscaler|Blue Coat|ProxySG|Websense|Forcepoint.*Web|Squid|Web Proxy)' 'Common Event Format via AMA or vendor solution' '(?i)CEF|Zscaler|Forcepoint|Proxy' 'CommonSecurityLog' 'Vendor connector or CEF over Syslog' 'Prefer the supported vendor solution; otherwise normalize proxy events sent as CEF.' $connectorReference),
        (New-MappingEntry '(?i)(Azure Active Directory|Microsoft Entra|Entra ID|AAD)' 'Microsoft Entra ID' '(?i)Entra|Azure Active Directory|AAD' 'SigninLogs;AuditLogs;AADNonInteractiveUserSignInLogs;AADServicePrincipalSignInLogs;AADManagedIdentitySignInLogs' 'Native diagnostic connector' 'Enable required Entra log categories and preserve an overlap window before retiring LogRhythm collection.' $connectorReference),
        (New-MappingEntry '(?i)(Office 365|Microsoft 365|O365|Exchange Online|SharePoint Online|Teams)' 'Microsoft 365' '(?i)Microsoft 365|Office 365' 'OfficeActivity' 'Native Microsoft 365 connector' 'Enable required workloads and compare event counts by workload during parallel collection.' $connectorReference),
        (New-MappingEntry '(?i)(Defender for Endpoint|Microsoft Defender|MDE|Microsoft 365 Defender|Defender XDR)' 'Microsoft Defender XDR' '(?i)Defender|XDR' 'DeviceEvents;DeviceProcessEvents;DeviceNetworkEvents;DeviceFileEvents;AlertInfo;AlertEvidence' 'Native Defender XDR connector' 'Connect the tenant natively and migrate detections to the Defender or Sentinel layer based on data residency and response ownership.' $connectorReference),
        (New-MappingEntry '(?i)(Azure Activity|Azure Monitor Activity)' 'Azure Activity' '(?i)Azure Activity' 'AzureActivity' 'Azure Policy diagnostic setting' 'Configure the subscription policy connector and validate all in-scope subscriptions.' $connectorReference),
        (New-MappingEntry '(?i)(AWS.*CloudTrail|CloudTrail)' 'Amazon Web Services S3' '(?i)AWS|Amazon' 'AWSCloudTrail' 'AWS S3/SQS connector' 'Use the supported AWS connector, scope accounts and regions, and validate event selectors.' $connectorReference),
        (New-MappingEntry '(?i)(Amazon.*(VPC|Flow)|AWS.*VPC)' 'Amazon Web Services S3' '(?i)AWS|Amazon' 'AWSVPCFlow' 'AWS S3/SQS connector' 'Route VPC flow logs through the supported AWS connector and retune network detections.' $connectorReference),
        (New-MappingEntry '(?i)(Okta)' 'Okta Single Sign-On' '(?i)Okta' 'OktaSystemLog' 'Supported API connector' 'Configure the supported Okta connector and verify system-log polling continuity.' $connectorReference),
        (New-MappingEntry '(?i)(Proofpoint|Mimecast|IronPort|Cisco Email Security)' 'Vendor solution or Common Event Format via AMA' '(?i)Proofpoint|Mimecast|Email|CEF' 'CommonSecurityLog' 'Supported API connector or CEF' 'Prefer the supported vendor solution; document any event classes that require a custom connector.' $connectorReference),
        (New-MappingEntry '(?i)(VMware|vCenter|ESXi)' 'Syslog via AMA' '(?i)Syslog|VMware' 'Syslog' 'Syslog to an AMA collector' 'Forward vCenter and ESXi logs to redundant AMA collectors and preserve host identity.' $connectorReference),
        (New-MappingEntry '(?i)(DNS|Domain Name)' 'DNS solution, AMA, or supported vendor connector' '(?i)DNS' 'DnsEvents;ASimDnsActivityLogs;WindowsEvent' 'Source-specific connector or AMA DCR' 'Select the target table from the authoritative DNS platform and normalize detections to ASIM DNS.' $connectorReference),
        (New-MappingEntry '(?i)(DHCP)' 'Azure Monitor Agent or custom Logs Ingestion API connector' '(?i)DHCP|Windows' 'WindowsEvent;DHCP_CL' 'AMA DCR or Logs Ingestion API' 'Define the required DHCP schema and retention before building a DCR transformation.' $connectorReference),
        (New-MappingEntry '(?i)(CrowdStrike|Falcon)' 'CrowdStrike Falcon solution' '(?i)CrowdStrike|Falcon' 'CommonSecurityLog' 'Supported solution, API, or CEF connector' 'Use the current Content Hub solution and confirm its table schema before translating rules.' $connectorReference),
        (New-MappingEntry '(?i)(SQL Server|Oracle|MySQL|PostgreSQL|Database Audit)' 'Azure Monitor Agent or custom Logs Ingestion API connector' '(?i)SQL|Database' 'WindowsEvent;Syslog;DatabaseAudit_CL' 'Platform audit stream through AMA or Logs Ingestion API' 'Inventory audit categories and define a source-specific DCR and transformation.' $connectorReference)
    )
}

function Get-MappingCatalog {
    param([string]$OverridesPath)

    $catalog = New-Object System.Collections.Generic.List[object]
    if (-not [string]::IsNullOrWhiteSpace($OverridesPath)) {
        if (-not (Test-Path -LiteralPath $OverridesPath -PathType Leaf)) {
            throw "Mapping override CSV '$OverridesPath' does not exist."
        }
        foreach ($row in @(Import-Csv -LiteralPath $OverridesPath)) {
            $pattern = [string](Get-PropertyValue -InputObject $row -Names @('Pattern'))
            if ([string]::IsNullOrWhiteSpace($pattern)) {
                throw "A mapping override in '$OverridesPath' has an empty Pattern."
            }
            try {
                [void][regex]::new($pattern)
            }
            catch {
                throw "Mapping override pattern '$pattern' is not a valid regular expression."
            }
            $catalog.Add((New-MappingEntry `
                -Pattern $pattern `
                -Connector ([string](Get-PropertyValue -InputObject $row -Names @('Connector') -Default 'Custom')) `
                -ConnectorMatch ([string](Get-PropertyValue -InputObject $row -Names @('ConnectorMatch') -Default $pattern)) `
                -TargetTables ([string](Get-PropertyValue -InputObject $row -Names @('TargetTables') -Default '')) `
                -CollectionMethod ([string](Get-PropertyValue -InputObject $row -Names @('CollectionMethod') -Default 'Custom')) `
                -MigrationApproach ([string](Get-PropertyValue -InputObject $row -Names @('MigrationApproach') -Default 'Review and design')) `
                -Documentation ([string](Get-PropertyValue -InputObject $row -Names @('Documentation') -Default ''))
            ))
        }
    }
    foreach ($entry in Get-BuiltInMappings) {
        $catalog.Add($entry)
    }
    return $catalog.ToArray()
}

function Resolve-SourceMapping {
    param(
        [Parameter(Mandatory = $true)][string]$LogSourceType,
        [Parameter(Mandatory = $true)][object[]]$Catalog
    )

    foreach ($mapping in $Catalog) {
        if ($LogSourceType -match $mapping.Pattern) {
            return $mapping
        }
    }

    return (New-MappingEntry `
        -Pattern '.*' `
        -Connector 'Architecture decision required' `
        -ConnectorMatch '(?!)' `
        -TargetTables '' `
        -CollectionMethod 'Evaluate Content Hub, CEF/Syslog via AMA, or Logs Ingestion API' `
        -MigrationApproach 'Confirm vendor support, required event classes, parsing, normalization, volume, and retention before onboarding.' `
        -Documentation 'https://learn.microsoft.com/azure/sentinel/connect-data-sources')
}

function ConvertTo-LongCount {
    param($Value)

    $result = 0L
    if ([long]::TryParse([string]$Value, [ref]$result)) {
        return $result
    }
    return 0L
}

function Get-LogSourceTypeInventory {
    param([Parameter(Mandatory = $true)]$Paths)

    $typesPath = Join-Path $Paths.LogRhythm 'LogSourceTypes.csv'
    if (Test-Path -LiteralPath $typesPath -PathType Leaf) {
        $rows = @(Import-Csv -LiteralPath $typesPath)
        return @($rows | ForEach-Object {
            [pscustomobject]@{
                LogSourceType = [string](Get-PropertyValue -InputObject $_ -Names @(
                    'LogSourceType', 'MsgSourceType', 'Name'
                ) -Default '(Unknown)')
                LogSourceCount = ConvertTo-LongCount (
                    Get-PropertyValue -InputObject $_ -Names @('LogSourceCount', 'Count') -Default 0
                )
            }
        })
    }

    $sourcesPath = Join-Path $Paths.LogRhythm 'LogSources.csv'
    if (-not (Test-Path -LiteralPath $sourcesPath -PathType Leaf)) {
        throw "Neither '$typesPath' nor '$sourcesPath' exists. Run the Export action first."
    }
    $sources = @(Import-Csv -LiteralPath $sourcesPath)
    return @($sources |
        Group-Object -Property {
            [string](Get-PropertyValue -InputObject $_ -Names @('LogSourceType', 'MsgSourceType') -Default '(Unknown)')
        } |
        ForEach-Object {
            [pscustomobject]@{
                LogSourceType  = $_.Name
                LogSourceCount = [long]$_.Count
            }
        })
}

function Get-UseCaseRows {
    param([Parameter(Mandatory = $true)]$Paths)

    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $inputs = @(
        [pscustomobject]@{
            Path = Join-Path $Paths.LogRhythm 'AieXmlRules.csv'
            Type = 'AI Engine XML'
            Names = @('RuleName', 'Name', 'DisplayName')
        },
        [pscustomobject]@{
            Path = Join-Path $Paths.LogRhythm 'AIERules.csv'
            Type = 'AI Engine database'
            Names = @('Name', 'RuleName', 'DisplayName')
        },
        [pscustomobject]@{
            Path = Join-Path $Paths.LogRhythm 'AlarmRules.csv'
            Type = 'Alarm rule'
            Names = @('Name', 'RuleName', 'AlarmName', 'DisplayName')
        }
    )

    foreach ($input in $inputs) {
        if (-not (Test-Path -LiteralPath $input.Path -PathType Leaf)) {
            continue
        }
        $index = 0
        foreach ($row in @(Import-Csv -LiteralPath $input.Path)) {
            $index++
            $name = [string](Get-PropertyValue -InputObject $row -Names $input.Names)
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = '{0} {1}' -f $input.Type, $index
            }
            $deduplicationKey = if ($input.Type -like 'AI Engine*') {
                'aie|' + $name.Trim().ToLowerInvariant()
            }
            else {
                'alarm|' + $name.Trim().ToLowerInvariant()
            }
            if ($seen.ContainsKey($deduplicationKey)) {
                continue
            }
            $seen[$deduplicationKey] = $true

            $rows.Add([pscustomobject]@{
                SourceType     = $input.Type
                SourceId       = [string](Get-PropertyValue -InputObject $row -Names @(
                    'RuleId', 'RuleID', 'AIERuleID', 'AlarmRuleID', 'Guid', 'ID'
                ))
                Name           = $name
                Enabled        = [string](Get-PropertyValue -InputObject $row -Names @(
                    'Enabled', 'IsEnabled', 'Active'
                ))
                RiskRating     = [string](Get-PropertyValue -InputObject $row -Names @(
                    'RiskRating', 'Risk', 'Severity'
                ))
                Description    = [string](Get-PropertyValue -InputObject $row -Names @(
                    'Description', 'LongDescription'
                ))
                MigrationStatus = 'NeedsTranslation'
                KqlOwner       = ''
                ValidationOwner = ''
                Notes          = if ($input.Type -eq 'AI Engine database') {
                    'Export the matching AIE rule as XML before translating its full logic.'
                }
                else {
                    ''
                }
            })
        }
    }
    return $rows.ToArray()
}

function New-StableGuid {
    param([Parameter(Mandatory = $true)][string]$Value)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    }
    finally {
        $sha256.Dispose()
    }
    $bytes = New-Object byte[] 16
    [array]::Copy($hash, $bytes, 16)
    $bytes[7] = ($bytes[7] -band 0x0F) -bor 0x50
    $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80
    return (New-Object guid (,$bytes)).ToString()
}

function New-AnalyticsRulePackage {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$UseCases,
        [string]$WorkspaceResourceId
    )

    $rules = @($UseCases | ForEach-Object {
        $sourceIdentity = '{0}|{1}|{2}' -f $_.SourceType, $_.SourceId, $_.Name
        [pscustomobject]@{
            ruleId             = New-StableGuid -Value $sourceIdentity
            migrationStatus    = 'NeedsTranslation'
            enabled            = $false
            name               = $_.Name
            description        = if ([string]::IsNullOrWhiteSpace($_.Description)) {
                "Migrated from LogRhythm $($_.SourceType)."
            }
            else {
                $_.Description
            }
            severity           = 'Medium'
            query              = ''
            queryFrequency     = 'PT1H'
            queryPeriod        = 'PT1H'
            triggerOperator    = 'GreaterThan'
            triggerThreshold   = 0
            suppressionEnabled = $false
            suppressionDuration = 'PT1H'
            tactics            = @()
            techniques         = @()
            entityMappings     = @()
            customDetails      = [pscustomobject]@{}
            source             = [pscustomobject]@{
                product = 'LogRhythm'
                type    = $_.SourceType
                id      = $_.SourceId
                name    = $_.Name
            }
        }
    })

    [pscustomobject]@{
        schemaVersion       = '1.0'
        generatedAtUtc      = [datetime]::UtcNow.ToString('o')
        generatedByVersion  = $script:ScriptVersion.ToString()
        workspaceResourceId = $WorkspaceResourceId
        instructions        = 'Translate query, review metadata, set migrationStatus to Ready, and set enabled intentionally. Deployment is disabled unless -EnableRules is also supplied.'
        rules               = $rules
    }
}

function New-MigrationAssessment {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$OverridesPath
    )

    $paths = Initialize-MigrationPaths -Root $Root
    Write-Step 'Building migration assessment and work queues'

    $sourceTypes = @(Get-LogSourceTypeInventory -Paths $paths)
    $catalog = @(Get-MappingCatalog -OverridesPath $OverridesPath)

    $sentinelTablesPath = Join-Path $paths.Sentinel 'Tables.csv'
    $sentinelConnectorsPath = Join-Path $paths.Sentinel 'DataConnectors.csv'
    $sentinelTables = if (Test-Path -LiteralPath $sentinelTablesPath -PathType Leaf) {
        @(Import-Csv -LiteralPath $sentinelTablesPath | ForEach-Object { [string]$_.Name })
    }
    else {
        @()
    }
    $sentinelConnectorText = if (Test-Path -LiteralPath $sentinelConnectorsPath -PathType Leaf) {
        (@(Import-Csv -LiteralPath $sentinelConnectorsPath | ForEach-Object {
            '{0} {1}' -f $_.DisplayName, $_.Kind
        }) -join [Environment]::NewLine)
    }
    else {
        ''
    }

    $plan = @($sourceTypes | Sort-Object LogSourceCount -Descending | ForEach-Object {
        $mapping = Resolve-SourceMapping -LogSourceType $_.LogSourceType -Catalog $catalog
        $expectedTables = @($mapping.TargetTables -split ';' | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        })
        $presentTables = @($expectedTables | Where-Object {
            $expected = $_
            @($sentinelTables | Where-Object { $_ -ieq $expected }).Count -gt 0
        })
        $connectorPresent = (
            -not [string]::IsNullOrWhiteSpace($sentinelConnectorText) -and
            $sentinelConnectorText -match $mapping.ConnectorMatch
        )

        if ($presentTables.Count -gt 0) {
            $coverageStatus = 'Table present - validate ingestion'
            $nextAction = 'Run ValidateIngestion, compare volume and fields, then migrate dependent detections.'
        }
        elseif ($connectorPresent) {
            $coverageStatus = 'Connector configured - table not observed'
            $nextAction = 'Confirm connector configuration, DCR scope, and source-side forwarding.'
        }
        elseif ($mapping.Connector -eq 'Architecture decision required') {
            $coverageStatus = 'Design required'
            $nextAction = $mapping.MigrationApproach
        }
        else {
            $coverageStatus = 'Onboarding required'
            $nextAction = $mapping.MigrationApproach
        }

        $priority = if ($_.LogSourceCount -ge 100) {
            'High'
        }
        elseif ($_.LogSourceCount -ge 10) {
            'Medium'
        }
        else {
            'Low'
        }

        [pscustomobject]@{
            Priority           = $priority
            LogSourceType      = $_.LogSourceType
            LogSourceCount     = $_.LogSourceCount
            RecommendedConnector = $mapping.Connector
            TargetTables       = $mapping.TargetTables
            CollectionMethod   = $mapping.CollectionMethod
            CoverageStatus     = $coverageStatus
            TablesPresent      = $presentTables -join ';'
            NextAction         = $nextAction
            Documentation      = $mapping.Documentation
            Owner              = ''
            PlannedWave        = ''
            Disposition        = 'Migrate'
            Notes              = ''
        }
    })
    Export-CsvFile -InputObject $plan -Path (Join-Path $paths.Assessment 'DataSourceMigrationPlan.csv')

    $useCases = @(Get-UseCaseRows -Paths $paths)
    Export-CsvFile -InputObject $useCases -Path (Join-Path $paths.Assessment 'UseCaseMigrationPlan.csv')

    $inventoryManifestPath = Join-Path $paths.Sentinel 'InventoryManifest.json'
    $workspaceResourceId = ''
    if (Test-Path -LiteralPath $inventoryManifestPath -PathType Leaf) {
        $inventoryManifest = Get-Content -LiteralPath $inventoryManifestPath -Raw | ConvertFrom-Json
        $workspaceResourceId = [string](Get-PropertyValue `
            -InputObject $inventoryManifest `
            -Names @('WorkspaceResourceId'))
    }

    $generatedPackage = New-AnalyticsRulePackage `
        -UseCases $useCases `
        -WorkspaceResourceId $workspaceResourceId
    $generatedPackagePath = Join-Path $paths.Assessment 'AnalyticsRules.generated.json'
    $editablePackagePath = Join-Path $paths.Assessment 'AnalyticsRules.json'
    Write-JsonFile -InputObject $generatedPackage -Path $generatedPackagePath
    if (-not (Test-Path -LiteralPath $editablePackagePath -PathType Leaf)) {
        Copy-Item -LiteralPath $generatedPackagePath -Destination $editablePackagePath
    }
    else {
        Write-Notice "Existing editable rule package was preserved: $editablePackagePath"
    }

    $overrideTemplate = @(
        [pscustomobject]@{
            Pattern = '^Vendor Product$'
            Connector = 'Supported connector or custom Logs Ingestion API connector'
            ConnectorMatch = '(?i)Vendor Product'
            TargetTables = 'VendorProduct_CL'
            CollectionMethod = 'Document the supported collection path'
            MigrationApproach = 'Define parsing, normalization, volume, retention, and validation.'
            Documentation = 'https://learn.microsoft.com/azure/sentinel/connect-data-sources'
        }
    )
    Export-CsvFile `
        -InputObject $overrideTemplate `
        -Path (Join-Path $paths.Assessment 'MappingOverrides.template.csv')

    $totalSources = [long](($sourceTypes | Measure-Object -Property LogSourceCount -Sum).Sum)
    $summary = [pscustomobject]@{
        SchemaVersion       = '1.0'
        ToolVersion         = $script:ScriptVersion.ToString()
        GeneratedAtUtc      = [datetime]::UtcNow.ToString('o')
        TotalLogSources     = $totalSources
        LogSourceTypes      = $sourceTypes.Count
        UseCases            = $useCases.Count
        Coverage = @($plan | Group-Object CoverageStatus | ForEach-Object {
            [pscustomobject]@{
                Status         = $_.Name
                LogSourceTypes = $_.Count
                LogSources     = [long](($_.Group | Measure-Object LogSourceCount -Sum).Sum)
            }
        })
        Files = [pscustomobject]@{
            DataSourcePlan      = 'DataSourceMigrationPlan.csv'
            UseCasePlan         = 'UseCaseMigrationPlan.csv'
            GeneratedRulePackage = 'AnalyticsRules.generated.json'
            EditableRulePackage = 'AnalyticsRules.json'
        }
    }
    Write-JsonFile -InputObject $summary -Path (Join-Path $paths.Assessment 'MigrationSummary.json')
    Write-Success (
        'Assessment created for {0} log sources across {1} types and {2} use cases.' -f
        $totalSources,
        $sourceTypes.Count,
        $useCases.Count
    )
    return $summary
}

function Test-IsoDuration {
    param(
        [string]$Value,
        [string]$Field,
        [System.Collections.Generic.List[string]]$Errors
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Errors.Add("$Field is required.")
        return $null
    }
    try {
        $duration = [System.Xml.XmlConvert]::ToTimeSpan($Value)
        if ($duration -le [timespan]::Zero) {
            $Errors.Add("$Field must be greater than zero.")
            return $null
        }
        return $duration
    }
    catch {
        $Errors.Add("$Field '$Value' is not an ISO 8601 duration.")
        return $null
    }
}

function Read-RulePackage {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Rule package '$Path' does not exist. Run Assess first or supply RulePackagePath."
    }
    try {
        $package = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Rule package '$Path' is not valid JSON. $($_.Exception.Message)"
    }
    $schemaVersion = [string](Get-PropertyValue -InputObject $package -Names @('schemaVersion'))
    if ($schemaVersion -ne '1.0') {
        throw "Rule package '$Path' has unsupported schemaVersion '$schemaVersion'."
    }
    $rulesProperty = $package.PSObject.Properties |
        Where-Object { $_.Name -eq 'rules' } |
        Select-Object -First 1
    if ($null -eq $rulesProperty) {
        throw "Rule package '$Path' does not contain a rules array."
    }
    return $package
}

function Test-AnalyticsRulePackage {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$WorkspaceCustomerId,
        [switch]$Online,
        [switch]$ReadyOnly
    )

    $package = Read-RulePackage -Path $Path
    $results = New-Object System.Collections.Generic.List[object]
    $names = @{}
    $ids = @{}
    $index = 0

    foreach ($rule in @($package.rules)) {
        $index++
        $errors = New-Object System.Collections.Generic.List[string]
        $name = [string](Get-PropertyValue -InputObject $rule -Names @('name'))
        $ruleId = [string](Get-PropertyValue -InputObject $rule -Names @('ruleId'))
        $query = [string](Get-PropertyValue -InputObject $rule -Names @('query'))
        $status = [string](Get-PropertyValue -InputObject $rule -Names @('migrationStatus'))
        $severity = [string](Get-PropertyValue -InputObject $rule -Names @('severity'))
        $operator = [string](Get-PropertyValue -InputObject $rule -Names @('triggerOperator'))

        if ($ReadyOnly -and $status -ne 'Ready') {
            $results.Add([pscustomobject]@{
                RuleId = $ruleId
                Name    = if ([string]::IsNullOrWhiteSpace($name)) { "Rule $index" } else { $name }
                Valid   = $true
                Mode    = 'Skipped - not Ready'
                Errors  = ''
            })
            continue
        }

        if ([string]::IsNullOrWhiteSpace($name)) {
            $errors.Add('name is required.')
            $name = "Rule $index"
        }
        elseif ($name.Length -gt 256) {
            $errors.Add('name exceeds 256 characters.')
        }
        elseif ($names.ContainsKey($name.ToLowerInvariant())) {
            $errors.Add("name duplicates rule '$($names[$name.ToLowerInvariant()])'.")
        }
        else {
            $names[$name.ToLowerInvariant()] = $name
        }

        $parsedGuid = [guid]::Empty
        if (-not [guid]::TryParse($ruleId, [ref]$parsedGuid)) {
            $errors.Add("ruleId '$ruleId' is not a GUID.")
        }
        elseif ($ids.ContainsKey($ruleId.ToLowerInvariant())) {
            $errors.Add('ruleId is duplicated in the package.')
        }
        else {
            $ids[$ruleId.ToLowerInvariant()] = $true
        }

        if ($status -ne 'Ready') {
            $errors.Add("migrationStatus must be 'Ready'.")
        }
        if ([string]::IsNullOrWhiteSpace($query)) {
            $errors.Add('query is empty.')
        }
        elseif ($query -match '(?i)\b(TODO|REPLACE_WITH_KQL)\b') {
            $errors.Add('query still contains a migration placeholder.')
        }
        if ($severity -notin @('Informational', 'Low', 'Medium', 'High')) {
            $errors.Add("severity '$severity' is unsupported.")
        }
        if ($operator -notin @('GreaterThan', 'LessThan', 'Equal', 'NotEqual')) {
            $errors.Add("triggerOperator '$operator' is unsupported.")
        }
        $enabledValue = Get-PropertyValue -InputObject $rule -Names @('enabled')
        if ($enabledValue -isnot [bool]) {
            $errors.Add('enabled must be a JSON boolean.')
        }
        $suppressionEnabledValue = Get-PropertyValue -InputObject $rule -Names @('suppressionEnabled')
        if ($suppressionEnabledValue -isnot [bool]) {
            $errors.Add('suppressionEnabled must be a JSON boolean.')
        }

        $threshold = 0
        if (-not [int]::TryParse(
            [string](Get-PropertyValue -InputObject $rule -Names @('triggerThreshold')),
            [ref]$threshold
        )) {
            $errors.Add('triggerThreshold must be an integer.')
        }

        $frequency = Test-IsoDuration `
            -Value ([string](Get-PropertyValue -InputObject $rule -Names @('queryFrequency'))) `
            -Field 'queryFrequency' `
            -Errors $errors
        $period = Test-IsoDuration `
            -Value ([string](Get-PropertyValue -InputObject $rule -Names @('queryPeriod'))) `
            -Field 'queryPeriod' `
            -Errors $errors
        if ($null -ne $frequency -and $null -ne $period -and $frequency -gt $period) {
            $errors.Add('queryFrequency cannot be greater than queryPeriod.')
        }
        if ($null -ne $frequency -and (
            $frequency -lt [timespan]::FromMinutes(5) -or
            $frequency -gt [timespan]::FromDays(14)
        )) {
            $errors.Add('queryFrequency must be between five minutes and 14 days.')
        }
        if ($null -ne $period -and (
            $period -lt [timespan]::FromMinutes(5) -or
            $period -gt [timespan]::FromDays(14)
        )) {
            $errors.Add('queryPeriod must be between five minutes and 14 days.')
        }

        $suppression = Test-IsoDuration `
            -Value ([string](Get-PropertyValue -InputObject $rule -Names @('suppressionDuration'))) `
            -Field 'suppressionDuration' `
            -Errors $errors
        if ($null -ne $suppression -and $suppression -gt [timespan]::FromDays(1)) {
            $errors.Add('suppressionDuration cannot exceed one day.')
        }
        if ($null -ne $suppression -and $suppression -lt [timespan]::FromMinutes(5)) {
            $errors.Add('suppressionDuration cannot be less than five minutes.')
        }

        if ($Online -and $errors.Count -eq 0) {
            if ([string]::IsNullOrWhiteSpace($WorkspaceCustomerId)) {
                $errors.Add('Workspace customer ID is required for online query validation.')
            }
            else {
                $validationQuery = $query.Trim().TrimEnd(';') + [Environment]::NewLine + '| take 0'
                try {
                    [void]@(Invoke-LogAnalyticsQuery `
                        -WorkspaceCustomerId $WorkspaceCustomerId `
                        -Query $validationQuery `
                        -Timespan ([string](Get-PropertyValue -InputObject $rule -Names @('queryPeriod'))))
                }
                catch {
                    $errors.Add("KQL validation failed: $($_.Exception.Message)")
                }
            }
        }

        $results.Add([pscustomobject]@{
            RuleId = $ruleId
            Name    = $name
            Valid   = ($errors.Count -eq 0)
            Mode    = if ($Online) { 'Offline and online' } else { 'Offline' }
            Errors  = $errors -join ' | '
        })
    }
    return $results.ToArray()
}

function Resolve-RulePackagePath {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [string]$RequestedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return [System.IO.Path]::GetFullPath($RequestedPath)
    }
    return (Join-Path $Paths.Assessment 'AnalyticsRules.json')
}

function Get-WorkspaceCustomerId {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [string]$RequestedSubscriptionId,
        [string]$RequestedResourceGroupName,
        [string]$RequestedWorkspaceName
    )

    $account = Set-AzureSubscription -RequestedSubscriptionId $RequestedSubscriptionId
    $effectiveSubscriptionId = [string](Get-PropertyValue -InputObject $account -Names @('id'))
    $manifestPath = Join-Path $Paths.Sentinel 'InventoryManifest.json'
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifestSubscriptionId = [string](Get-PropertyValue -InputObject $manifest -Names @('SubscriptionId'))
        $manifestResourceGroup = [string](Get-PropertyValue -InputObject $manifest -Names @('ResourceGroupName'))
        $manifestWorkspace = [string](Get-PropertyValue -InputObject $manifest -Names @('WorkspaceName'))
        $manifestCustomerId = [string](Get-PropertyValue -InputObject $manifest -Names @('WorkspaceCustomerId'))
        $targetMatchesManifest = (
            $manifestSubscriptionId -ieq $effectiveSubscriptionId -and
            $manifestResourceGroup -ieq $RequestedResourceGroupName -and
            $manifestWorkspace -ieq $RequestedWorkspaceName
        )
        if ($targetMatchesManifest -and -not [string]::IsNullOrWhiteSpace($manifestCustomerId)) {
            return $manifestCustomerId
        }
    }

    $target = Resolve-AzureTarget `
        -RequestedSubscriptionId $effectiveSubscriptionId `
        -RequestedResourceGroupName $RequestedResourceGroupName `
        -RequestedWorkspaceName $RequestedWorkspaceName
    $workspace = Invoke-ArmRestJson `
        -Method GET `
        -Url "https://management.azure.com$($target.WorkspaceId)?api-version=2023-09-01"
    $workspaceProperties = Get-PropertyValue -InputObject $workspace -Names @('properties')
    $customerId = [string](Get-PropertyValue -InputObject $workspaceProperties -Names @('customerId'))
    if ([string]::IsNullOrWhiteSpace($customerId)) {
        throw "Workspace '$RequestedWorkspaceName' did not return a customer ID."
    }
    return $customerId
}

function Invoke-RulePackageValidation {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$RequestedPath,
        [string]$RequestedSubscriptionId,
        [string]$RequestedResourceGroupName,
        [string]$RequestedWorkspaceName,
        [switch]$Online,
        [switch]$ReadyOnly
    )

    $paths = Initialize-MigrationPaths -Root $Root
    $packagePath = Resolve-RulePackagePath -Paths $paths -RequestedPath $RequestedPath
    $workspaceCustomerId = ''
    if ($Online) {
        $workspaceCustomerId = Get-WorkspaceCustomerId `
            -Paths $paths `
            -RequestedSubscriptionId $RequestedSubscriptionId `
            -RequestedResourceGroupName $RequestedResourceGroupName `
            -RequestedWorkspaceName $RequestedWorkspaceName
    }

    Write-Step "Validating analytics-rule package $packagePath"
    $results = @(Test-AnalyticsRulePackage `
        -Path $packagePath `
        -WorkspaceCustomerId $workspaceCustomerId `
        -Online:$Online `
        -ReadyOnly:$ReadyOnly)
    $reportPath = Join-Path $paths.Deployment 'RuleValidation.csv'
    Export-CsvFile -InputObject $results -Path $reportPath
    $failures = @($results | Where-Object { -not $_.Valid })
    if ($failures.Count -gt 0) {
        throw "$($failures.Count) of $($results.Count) analytics rules failed validation. Review '$reportPath'."
    }
    $skipped = @($results | Where-Object Mode -eq 'Skipped - not Ready')
    $validated = $results.Count - $skipped.Count
    Write-Success "$validated analytics rules passed validation; $($skipped.Count) not-ready rules skipped."
    return $results
}

function New-SentinelRulePayload {
    param(
        [Parameter(Mandatory = $true)]$Rule,
        [switch]$AllowEnabled
    )

    $properties = [ordered]@{
        displayName          = [string](Get-PropertyValue -InputObject $Rule -Names @('name'))
        description          = [string](Get-PropertyValue -InputObject $Rule -Names @('description') -Default '')
        severity             = [string](Get-PropertyValue -InputObject $Rule -Names @('severity'))
        enabled              = if ($AllowEnabled) {
            [bool](Get-PropertyValue -InputObject $Rule -Names @('enabled') -Default $false)
        }
        else {
            $false
        }
        query                = [string](Get-PropertyValue -InputObject $Rule -Names @('query'))
        queryFrequency       = [string](Get-PropertyValue -InputObject $Rule -Names @('queryFrequency'))
        queryPeriod          = [string](Get-PropertyValue -InputObject $Rule -Names @('queryPeriod'))
        triggerOperator      = [string](Get-PropertyValue -InputObject $Rule -Names @('triggerOperator'))
        triggerThreshold     = [int](Get-PropertyValue -InputObject $Rule -Names @('triggerThreshold'))
        suppressionEnabled   = [bool](Get-PropertyValue -InputObject $Rule -Names @('suppressionEnabled'))
        suppressionDuration  = [string](Get-PropertyValue -InputObject $Rule -Names @('suppressionDuration'))
        eventGroupingSettings = [ordered]@{
            aggregationKind = 'SingleAlert'
        }
        incidentConfiguration = [ordered]@{
            createIncident = $true
            groupingConfiguration = [ordered]@{
                enabled = $false
                reopenClosedIncident = $false
                lookbackDuration = 'PT5H'
                matchingMethod = 'AllEntities'
                groupByEntities = @()
                groupByAlertDetails = @()
                groupByCustomDetails = @()
            }
        }
    }

    foreach ($optionalProperty in @('tactics', 'techniques', 'entityMappings', 'customDetails')) {
        $value = Get-PropertyValue -InputObject $Rule -Names @($optionalProperty)
        if ($null -ne $value) {
            $properties[$optionalProperty] = $value
        }
    }

    return [ordered]@{
        kind       = 'Scheduled'
        properties = $properties
    }
}

function Deploy-AnalyticsRulePackage {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$RequestedPath,
        [string]$RequestedSubscriptionId,
        [Parameter(Mandatory = $true)][string]$RequestedResourceGroupName,
        [Parameter(Mandatory = $true)][string]$RequestedWorkspaceName,
        [switch]$AllowEnabled,
        [switch]$SkipOnlineValidation
    )

    $paths = Initialize-MigrationPaths -Root $Root
    $target = Resolve-AzureTarget `
        -RequestedSubscriptionId $RequestedSubscriptionId `
        -RequestedResourceGroupName $RequestedResourceGroupName `
        -RequestedWorkspaceName $RequestedWorkspaceName
    $packagePath = Resolve-RulePackagePath -Paths $paths -RequestedPath $RequestedPath

    [void](Invoke-RulePackageValidation `
        -Root $Root `
        -RequestedPath $packagePath `
        -RequestedSubscriptionId $target.SubscriptionId `
        -RequestedResourceGroupName $target.ResourceGroupName `
        -RequestedWorkspaceName $target.WorkspaceName `
        -Online:(-not $SkipOnlineValidation) `
        -ReadyOnly)

    $package = Read-RulePackage -Path $packagePath
    $existingRules = @(Invoke-ArmRestPaged -Url (
        "$($target.SentinelBaseUrl)/alertRules?api-version=$($script:SentinelApiVersion)"
    ))
    $existingByDisplayName = @{}
    foreach ($existingRule in $existingRules) {
        $existingProperties = Get-PropertyValue -InputObject $existingRule -Names @('properties')
        $displayName = [string](Get-PropertyValue -InputObject $existingProperties -Names @('displayName'))
        if (-not [string]::IsNullOrWhiteSpace($displayName)) {
            $existingByDisplayName[$displayName.ToLowerInvariant()] = [string](
                Get-PropertyValue -InputObject $existingRule -Names @('name')
            )
        }
    }

    Write-Step "Deploying analytics rules to $($target.WorkspaceName)"
    $results = New-Object System.Collections.Generic.List[object]
    $readyRules = New-Object System.Collections.Generic.List[object]
    foreach ($rule in @($package.rules)) {
        $ruleStatus = [string](Get-PropertyValue -InputObject $rule -Names @('migrationStatus'))
        if ($ruleStatus -eq 'Ready') {
            $readyRules.Add($rule)
            continue
        }
        $results.Add([pscustomobject]@{
            RuleId = [string](Get-PropertyValue -InputObject $rule -Names @('ruleId'))
            Name = [string](Get-PropertyValue -InputObject $rule -Names @('name') -Default '(Unnamed rule)')
            Status = 'Skipped'
            Enabled = $false
            Detail = "migrationStatus is '$ruleStatus', not 'Ready'."
        })
    }

    foreach ($rule in $readyRules) {
        $ruleId = [string](Get-PropertyValue -InputObject $rule -Names @('ruleId'))
        $name = [string](Get-PropertyValue -InputObject $rule -Names @('name'))
        $existingId = $null
        if ($existingByDisplayName.ContainsKey($name.ToLowerInvariant())) {
            $existingId = $existingByDisplayName[$name.ToLowerInvariant()]
        }
        if ($existingId -and $existingId -ine $ruleId) {
            $results.Add([pscustomobject]@{
                RuleId = $ruleId
                Name = $name
                Status = 'Conflict'
                Enabled = $false
                Detail = "An existing rule with this display name uses resource ID '$existingId'."
            })
            continue
        }

        $enabled = if ($AllowEnabled) {
            [bool](Get-PropertyValue -InputObject $rule -Names @('enabled') -Default $false)
        }
        else {
            $false
        }
        if ($PSCmdlet.ShouldProcess(
            "$($target.WorkspaceName)/$name",
            "Deploy scheduled analytics rule (enabled=$enabled)"
        )) {
            try {
                $payload = New-SentinelRulePayload -Rule $rule -AllowEnabled:$AllowEnabled
                $url = (
                    "$($target.SentinelBaseUrl)/alertRules/{0}?api-version={1}" -f
                    [uri]::EscapeDataString($ruleId),
                    $script:SentinelApiVersion
                )
                $response = Invoke-ArmRestJson -Method PUT -Url $url -Body $payload
                $responseProperties = Get-PropertyValue -InputObject $response -Names @('properties')
                $results.Add([pscustomobject]@{
                    RuleId = $ruleId
                    Name = $name
                    Status = 'Deployed'
                    Enabled = [bool](Get-PropertyValue -InputObject $responseProperties -Names @('enabled'))
                    Detail = [string](Get-PropertyValue -InputObject $response -Names @('id'))
                })
            }
            catch {
                $results.Add([pscustomobject]@{
                    RuleId = $ruleId
                    Name = $name
                    Status = 'Failed'
                    Enabled = $false
                    Detail = $_.Exception.Message
                })
            }
        }
        else {
            $results.Add([pscustomobject]@{
                RuleId = $ruleId
                Name = $name
                Status = 'WhatIf'
                Enabled = $enabled
                Detail = 'No Azure change was made.'
            })
        }
    }

    $reportPath = Join-Path $paths.Deployment 'RuleDeployment.csv'
    Export-CsvFile -InputObject $results.ToArray() -Path $reportPath
    $failures = @($results | Where-Object { $_.Status -in @('Conflict', 'Failed') })
    if ($failures.Count -gt 0) {
        throw "$($failures.Count) analytics rules were not deployed. Review '$reportPath'."
    }
    Write-Success "$(@($results | Where-Object Status -eq 'Deployed').Count) analytics rules deployed."
    return $results.ToArray()
}

function Invoke-LogAnalyticsQuery {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceCustomerId,
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string]$Timespan
    )

    $url = 'https://api.loganalytics.azure.com/v1/workspaces/{0}/query' -f (
        [uri]::EscapeDataString($WorkspaceCustomerId)
    )
    $response = Invoke-AuthenticatedJsonRequest `
        -Method POST `
        -Url $url `
        -TokenResource 'https://api.loganalytics.io' `
        -Body ([ordered]@{
            query = $Query
            timespan = $Timespan
        })

    $tables = @(Get-PropertyValue -InputObject $response -Names @('tables') -Default @())
    if ($tables.Count -eq 0) {
        return @()
    }
    $primary = $tables | Where-Object {
        [string](Get-PropertyValue -InputObject $_ -Names @('name')) -eq 'PrimaryResult'
    } | Select-Object -First 1
    if ($null -eq $primary) {
        $primary = $tables[0]
    }

    $columns = @(Get-PropertyValue -InputObject $primary -Names @('columns') -Default @())
    $rows = @(Get-PropertyValue -InputObject $primary -Names @('rows') -Default @())
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $rowValues = @($row)
        $record = [ordered]@{}
        for ($columnIndex = 0; $columnIndex -lt $columns.Count; $columnIndex++) {
            $columnName = [string](Get-PropertyValue -InputObject $columns[$columnIndex] -Names @('name'))
            $record[$columnName] = if ($columnIndex -lt $rowValues.Count) {
                $rowValues[$columnIndex]
            }
            else {
                $null
            }
        }
        $results.Add([pscustomobject]$record)
    }
    return $results.ToArray()
}

function Test-SentinelIngestion {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$RequestedSubscriptionId,
        [Parameter(Mandatory = $true)][string]$RequestedResourceGroupName,
        [Parameter(Mandatory = $true)][string]$RequestedWorkspaceName,
        [Parameter(Mandatory = $true)][int]$Days
    )

    $paths = Initialize-MigrationPaths -Root $Root
    $workspaceCustomerId = Get-WorkspaceCustomerId `
        -Paths $paths `
        -RequestedSubscriptionId $RequestedSubscriptionId `
        -RequestedResourceGroupName $RequestedResourceGroupName `
        -RequestedWorkspaceName $RequestedWorkspaceName

    $planPath = Join-Path $paths.Assessment 'DataSourceMigrationPlan.csv'
    $tablePath = Join-Path $paths.Sentinel 'Tables.csv'
    if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
        throw "Migration plan '$planPath' does not exist. Run Assess first."
    }
    if (-not (Test-Path -LiteralPath $tablePath -PathType Leaf)) {
        throw "Sentinel table inventory '$tablePath' does not exist. Run Inventory first."
    }

    $plan = @(Import-Csv -LiteralPath $planPath)
    $workspaceTables = @(Import-Csv -LiteralPath $tablePath | ForEach-Object { [string]$_.Name })
    $expectedTables = @($plan | ForEach-Object {
        @([string]$_.TargetTables -split ';')
    } | Where-Object {
        $_ -match '^[A-Za-z][A-Za-z0-9_]*$'
    } | Sort-Object -Unique)

    if ($expectedTables.Count -eq 0) {
        throw "The migration plan contains no concrete target table names to validate."
    }

    $presentExpectedTables = @($expectedTables | Where-Object {
        $expected = $_
        @($workspaceTables | Where-Object { $_ -ieq $expected }).Count -gt 0
    })
    $observations = @{}
    Write-Step "Checking Sentinel ingestion over the last $Days days"

    for ($offset = 0; $offset -lt $presentExpectedTables.Count; $offset += 20) {
        $lastIndex = [math]::Min($offset + 19, $presentExpectedTables.Count - 1)
        $batch = @($presentExpectedTables[$offset..$lastIndex])
        $query = @"
union isfuzzy=true withsource=SourceTable $($batch -join ', ')
| summarize EventCount=count(), LastEventUtc=max(TimeGenerated) by SourceTable
"@
        foreach ($row in @(Invoke-LogAnalyticsQuery `
            -WorkspaceCustomerId $workspaceCustomerId `
            -Query $query `
            -Timespan ('P{0}D' -f $Days))) {
            $tableName = [string](Get-PropertyValue -InputObject $row -Names @('SourceTable'))
            if ($tableName.Contains('.')) {
                $tableName = $tableName.Split('.')[-1]
            }
            $observations[$tableName.ToLowerInvariant()] = $row
        }
    }

    $results = @($expectedTables | ForEach-Object {
        $tableName = $_
        $isPresent = @($workspaceTables | Where-Object { $_ -ieq $tableName }).Count -gt 0
        $observation = $null
        if ($observations.ContainsKey($tableName.ToLowerInvariant())) {
            $observation = $observations[$tableName.ToLowerInvariant()]
        }
        $eventCount = if ($observation) {
            ConvertTo-LongCount (Get-PropertyValue -InputObject $observation -Names @('EventCount'))
        }
        else {
            0L
        }
        [pscustomobject]@{
            Table          = $tableName
            Exists         = $isPresent
            EventCount     = $eventCount
            LastEventUtc   = if ($observation) {
                [string](Get-PropertyValue -InputObject $observation -Names @('LastEventUtc'))
            }
            else {
                ''
            }
            LookbackDays   = $Days
            Status         = if (-not $isPresent) {
                'Table not present'
            }
            elseif ($eventCount -gt 0) {
                'Receiving data'
            }
            else {
                'No events in lookback'
            }
        }
    })

    $reportPath = Join-Path $paths.Assessment 'IngestionValidation.csv'
    Export-CsvFile -InputObject $results -Path $reportPath
    Write-Success (
        '{0} of {1} expected tables received events in the lookback window.' -f
        @($results | Where-Object Status -eq 'Receiving data').Count,
        $results.Count
    )
    return $results
}

function Update-MigrationHelper {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Self-update is unavailable when the script is not running from a file.'
    }

    Write-Step "Checking $script:Repository for updates"
    $url = "https://raw.githubusercontent.com/$($script:Repository)/main/Invoke-LogRhythmSentinelMigration.ps1"
    $previousProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = (
            $previousProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        )
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        $content = [string]$response.Content
    }
    finally {
        [System.Net.ServicePointManager]::SecurityProtocol = $previousProtocol
    }

    $versionMatch = [regex]::Match(
        $content,
        "\`$script:ScriptVersion\s*=\s*\[version\]'(?<Version>[0-9]+\.[0-9]+\.[0-9]+)'"
    )
    if (-not $versionMatch.Success) {
        throw 'The remote script does not contain a recognizable version marker.'
    }
    $remoteVersion = [version]$versionMatch.Groups['Version'].Value
    if ($remoteVersion -le $script:ScriptVersion) {
        Write-Success "Already current at version $script:ScriptVersion."
        return
    }

    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput(
        $content,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        throw "The remote version failed PowerShell parsing: $($parseErrors[0].Message)"
    }

    if ($PSCmdlet.ShouldProcess($PSCommandPath, "Update to version $remoteVersion")) {
        $temporaryPath = Join-Path ([System.IO.Path]::GetTempPath()) (
            'Invoke-LogRhythmSentinelMigration-{0}.ps1' -f ([guid]::NewGuid().ToString('N'))
        )
        try {
            [System.IO.File]::WriteAllText($temporaryPath, $content, $script:Utf8NoBom)
            Copy-Item -LiteralPath $temporaryPath -Destination $PSCommandPath -Force
        }
        finally {
            if (Test-Path -LiteralPath $temporaryPath) {
                Remove-Item -LiteralPath $temporaryPath -Force
            }
        }
        Write-Success "Updated to version $remoteVersion. Restart the script."
    }
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "Self-test failed: $Message"
    }
}

function Invoke-MigrationSelfTest {
    Write-Step 'Running offline migration-helper self-test'
    $testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'lr-sentinel-selftest-{0}' -f ([guid]::NewGuid().ToString('N'))
    )
    try {
        $integratedConnection = New-SqlConnection `
            -Server 'localhost' `
            -DatabaseName 'LogRhythmEMDB' `
            -Encrypt:$false
        try {
            Assert-Condition (
                $integratedConnection -is [System.Data.SqlClient.SqlConnection] -and
                $integratedConnection.ConnectionString -match 'Integrated Security=True'
            ) 'Windows-authentication SQL connection construction failed.'
        }
        finally {
            $integratedConnection.Dispose()
        }

        $testPassword = ConvertTo-SecureString 'not-a-real-password' -AsPlainText -Force
        $testCredential = New-Object `
            -TypeName System.Management.Automation.PSCredential `
            -ArgumentList 'test-user', $testPassword
        $credentialConnection = New-SqlConnection `
            -Server 'localhost' `
            -DatabaseName 'LogRhythmEMDB' `
            -SqlAuthentication `
            -Credential $testCredential `
            -Encrypt:$false
        try {
            Assert-Condition (
                $credentialConnection.Credential.UserId -eq 'test-user'
            ) 'SQL-credential connection construction failed.'
        }
        finally {
            $credentialConnection.Dispose()
        }

        $testSchema = New-Object System.Data.DataTable
        [void]$testSchema.Columns.Add('SchemaName', [string])
        [void]$testSchema.Columns.Add('TableName', [string])
        [void]$testSchema.Columns.Add('ColumnName', [string])
        foreach ($schemaRow in @(
            [pscustomobject]@{ SchemaName = 'archive'; TableName = 'MsgSource'; ColumnName = 'HostID' },
            [pscustomobject]@{ SchemaName = 'dbo'; TableName = 'MsgSource'; ColumnName = 'HostID' },
            [pscustomobject]@{ SchemaName = 'dbo'; TableName = 'MsgSource'; ColumnName = 'MsgSourceTypeID' },
            [pscustomobject]@{ SchemaName = 'dbo'; TableName = 'LogSource'; ColumnName = 'HostID' }
        )) {
            $row = $testSchema.NewRow()
            $row.SchemaName = $schemaRow.SchemaName
            $row.TableName = $schemaRow.TableName
            $row.ColumnName = $schemaRow.ColumnName
            [void]$testSchema.Rows.Add($row)
        }
        $resolvedSource = Resolve-SchemaTable `
            -Schema $testSchema `
            -TableNames @('MsgSource', 'LogSource')
        Assert-Condition (
            $resolvedSource.SchemaName -eq 'dbo' -and
            $resolvedSource.TableName -eq 'MsgSource'
        ) 'MsgSource schema discovery failed.'
        Assert-Condition (
            (Get-QualifiedSqlName `
                -SchemaName $resolvedSource.SchemaName `
                -TableName $resolvedSource.TableName) -eq '[dbo].[MsgSource]'
        ) 'qualified SQL object construction failed.'
        Assert-Condition (
            (Test-SchemaObject `
                -Schema $testSchema `
                -SchemaName 'dbo' `
                -TableName 'MsgSource' `
                -ColumnName 'MsgSourceTypeID')
        ) 'schema-specific column discovery failed.'

        $paths = Initialize-MigrationPaths -Root $testRoot
        Export-CsvFile -InputObject @(
            [pscustomobject]@{ LogSourceType = 'Microsoft Windows Event Log'; LogSourceCount = 25 },
            [pscustomobject]@{ LogSourceType = 'Unmapped Test Appliance'; LogSourceCount = 2 }
        ) -Path (Join-Path $paths.LogRhythm 'LogSourceTypes.csv')
        Export-CsvFile -InputObject @(
            [pscustomobject]@{
                RuleID = 'LR-1'
                Name = 'Repeated failed logons'
                Enabled = 'True'
                Description = 'Detects repeated failures.'
            }
        ) -Path (Join-Path $paths.LogRhythm 'AIERules.csv')
        Export-CsvFile -InputObject @(
            [pscustomobject]@{
                Name = 'SecurityEvent'
                Plan = 'Analytics'
                RetentionInDays = 90
                TotalRetentionInDays = 90
                ArchiveRetentionInDays = 0
            }
        ) -Path (Join-Path $paths.Sentinel 'Tables.csv')
        Export-CsvFile -InputObject @(
            [pscustomobject]@{
                ResourceName = 'test'
                Kind = 'GenericUI'
                DisplayName = 'Windows Security Events via AMA'
                State = ''
                DataTypes = ''
            }
        ) -Path (Join-Path $paths.Sentinel 'DataConnectors.csv')

        [void](New-MigrationAssessment -Root $testRoot)
        $plan = @(Import-Csv -LiteralPath (Join-Path $paths.Assessment 'DataSourceMigrationPlan.csv'))
        Assert-Condition ($plan.Count -eq 2) 'assessment did not retain both source types.'
        $windows = $plan | Where-Object LogSourceType -eq 'Microsoft Windows Event Log'
        Assert-Condition ($windows.TargetTables -match 'SecurityEvent') 'Windows mapping did not select SecurityEvent.'
        Assert-Condition ($windows.CoverageStatus -eq 'Table present - validate ingestion') 'existing table was not detected.'
        $unknown = $plan | Where-Object LogSourceType -eq 'Unmapped Test Appliance'
        Assert-Condition ($unknown.CoverageStatus -eq 'Design required') 'unknown source was not gated for design.'

        $packagePath = Join-Path $paths.Assessment 'AnalyticsRules.json'
        $package = Read-RulePackage -Path $packagePath
        Assert-Condition (@($package.rules).Count -eq 1) 'use case did not create one rule package entry.'
        $package.rules[0].migrationStatus = 'Ready'
        $package.rules[0].query = 'SecurityEvent | where EventID == 4625'
        Write-JsonFile -InputObject $package -Path $packagePath
        $validation = @(Test-AnalyticsRulePackage -Path $packagePath)
        Assert-Condition ($validation.Count -eq 1 -and $validation[0].Valid) 'valid translated rule was rejected.'
        $pendingRule = $package.rules[0].PSObject.Copy()
        $pendingRule.ruleId = New-StableGuid -Value 'pending-rule'
        $pendingRule.name = 'Pending translation'
        $pendingRule.migrationStatus = 'NeedsTranslation'
        $pendingRule.query = ''
        $package.rules = @($package.rules[0], $pendingRule)
        Write-JsonFile -InputObject $package -Path $packagePath
        $waveValidation = @(Test-AnalyticsRulePackage -Path $packagePath -ReadyOnly)
        Assert-Condition (
            $waveValidation.Count -eq 2 -and
            @($waveValidation | Where-Object Mode -eq 'Skipped - not Ready').Count -eq 1 -and
            @($waveValidation | Where-Object { -not $_.Valid }).Count -eq 0
        ) 'wave validation did not skip an untranslated rule safely.'

        $guidOne = New-StableGuid -Value 'stable-test'
        $guidTwo = New-StableGuid -Value 'stable-test'
        Assert-Condition ($guidOne -eq $guidTwo) 'rule IDs are not deterministic.'
        $emptyPackage = New-AnalyticsRulePackage -UseCases @()
        Assert-Condition (@($emptyPackage.rules).Count -eq 0) 'empty use-case inventory did not create an empty rule package.'

        $xmlPath = Join-Path $testRoot 'rule.xml'
        [System.IO.File]::WriteAllText(
            $xmlPath,
            '<Export><AIERule><RuleID>1</RuleID><RuleName>XML test</RuleName></AIERule></Export>',
            $script:Utf8NoBom
        )
        $xmlRows = @(Convert-LogRhythmAieXml -Path $xmlPath)
        Assert-Condition ($xmlRows.Count -eq 1 -and $xmlRows[0].RuleName -eq 'XML test') 'AIE XML inventory failed.'

        Write-Success 'Offline self-test passed.'
    }
    finally {
        if (Test-Path -LiteralPath $testRoot) {
            Remove-Item -LiteralPath $testRoot -Recurse -Force
        }
    }
}

function Read-RequiredValue {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [string]$CurrentValue
    )

    if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        return $CurrentValue
    }
    $value = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Prompt is required."
    }
    return $value
}

function Read-ValueWithDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter(Mandatory = $true)][string]$DefaultValue
    )

    $value = Read-Host ("{0} [{1}]" -f $Prompt, $DefaultValue)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }
    return $value
}

function Start-MigrationMenu {
    do {
        Write-Host ''
        Write-Host "LogRhythm to Sentinel Migration Helper $script:ScriptVersion" -ForegroundColor Cyan
        Write-Host '  1  Check prerequisite and sign-in status'
        Write-Host '  2  Install prerequisites and register Azure providers'
        Write-Host '  3  Export LogRhythm inventory'
        Write-Host '  4  Inventory target Sentinel workspace'
        Write-Host '  5  Build migration plans and analytics-rule package'
        Write-Host '  6  Validate translated analytics rules'
        Write-Host '  7  Deploy analytics rules (disabled by default)'
        Write-Host '  8  Validate Sentinel ingestion'
        Write-Host '  9  Run export, inventory, assessment, and ingestion validation'
        Write-Host '  T  Run offline self-test'
        Write-Host '  U  Update this helper'
        Write-Host '  Q  Exit'
        $selection = (Read-Host 'Select an action').Trim().ToUpperInvariant()

        try {
            switch ($selection) {
                '1' {
                    [void](Show-PrerequisiteStatus)
                }
                '2' {
                    Install-MigrationPrerequisites
                }
                '3' {
                    $menuSqlServer = Read-ValueWithDefault -Prompt 'SQL Server or instance' -DefaultValue $SqlServer
                    $useSql = (Read-Host 'Use SQL authentication instead of Windows authentication? [y/N]') -match '^[Yy]'
                    $credential = if ($useSql) {
                        Get-Credential -Message "SQL login for $Database on $menuSqlServer"
                    }
                    else {
                        $null
                    }
                    Export-LogRhythmInventory `
                        -Root $OutputPath `
                        -Server $menuSqlServer `
                        -DatabaseName $Database `
                        -SqlAuthentication:$useSql `
                        -Credential $credential `
                        -Encrypt:$EncryptSqlConnection `
                        -TrustCertificate:$TrustServerCertificate `
                        -RuleXmlPath $AieXmlPath | Out-Null
                }
                '4' {
                    $menuResourceGroup = Read-RequiredValue -Prompt 'Target resource group' -CurrentValue $ResourceGroupName
                    $menuWorkspace = Read-RequiredValue -Prompt 'Target Sentinel workspace' -CurrentValue $WorkspaceName
                    Export-SentinelInventory `
                        -Root $OutputPath `
                        -RequestedSubscriptionId $SubscriptionId `
                        -RequestedResourceGroupName $menuResourceGroup `
                        -RequestedWorkspaceName $menuWorkspace | Out-Null
                }
                '5' {
                    New-MigrationAssessment -Root $OutputPath -OverridesPath $MappingOverridesPath | Out-Null
                }
                '6' {
                    $online = (Read-Host 'Run live KQL validation against Sentinel? [y/N]') -match '^[Yy]'
                    $menuResourceGroup = $ResourceGroupName
                    $menuWorkspace = $WorkspaceName
                    if ($online) {
                        $menuResourceGroup = Read-RequiredValue -Prompt 'Target resource group' -CurrentValue $ResourceGroupName
                        $menuWorkspace = Read-RequiredValue -Prompt 'Target Sentinel workspace' -CurrentValue $WorkspaceName
                    }
                    Invoke-RulePackageValidation `
                        -Root $OutputPath `
                        -RequestedPath $RulePackagePath `
                        -RequestedSubscriptionId $SubscriptionId `
                        -RequestedResourceGroupName $menuResourceGroup `
                        -RequestedWorkspaceName $menuWorkspace `
                        -Online:$online | Out-Null
                }
                '7' {
                    $menuResourceGroup = Read-RequiredValue -Prompt 'Target resource group' -CurrentValue $ResourceGroupName
                    $menuWorkspace = Read-RequiredValue -Prompt 'Target Sentinel workspace' -CurrentValue $WorkspaceName
                    $enableText = Read-Host 'Type ENABLE to permit package-enabled rules to be enabled; press Enter to force all disabled'
                    Deploy-AnalyticsRulePackage `
                        -Root $OutputPath `
                        -RequestedPath $RulePackagePath `
                        -RequestedSubscriptionId $SubscriptionId `
                        -RequestedResourceGroupName $menuResourceGroup `
                        -RequestedWorkspaceName $menuWorkspace `
                        -AllowEnabled:($enableText -ceq 'ENABLE') `
                        -SkipOnlineValidation:$SkipQueryValidation | Out-Null
                }
                '8' {
                    $menuResourceGroup = Read-RequiredValue -Prompt 'Target resource group' -CurrentValue $ResourceGroupName
                    $menuWorkspace = Read-RequiredValue -Prompt 'Target Sentinel workspace' -CurrentValue $WorkspaceName
                    Test-SentinelIngestion `
                        -Root $OutputPath `
                        -RequestedSubscriptionId $SubscriptionId `
                        -RequestedResourceGroupName $menuResourceGroup `
                        -RequestedWorkspaceName $menuWorkspace `
                        -Days $LookbackDays | Out-Null
                }
                '9' {
                    $menuSqlServer = Read-ValueWithDefault -Prompt 'SQL Server or instance' -DefaultValue $SqlServer
                    $menuResourceGroup = Read-RequiredValue -Prompt 'Target resource group' -CurrentValue $ResourceGroupName
                    $menuWorkspace = Read-RequiredValue -Prompt 'Target Sentinel workspace' -CurrentValue $WorkspaceName
                    Export-LogRhythmInventory `
                        -Root $OutputPath `
                        -Server $menuSqlServer `
                        -DatabaseName $Database `
                        -SqlAuthentication:$UseSqlAuthentication `
                        -Credential $SqlCredential `
                        -Encrypt:$EncryptSqlConnection `
                        -TrustCertificate:$TrustServerCertificate `
                        -RuleXmlPath $AieXmlPath | Out-Null
                    Export-SentinelInventory `
                        -Root $OutputPath `
                        -RequestedSubscriptionId $SubscriptionId `
                        -RequestedResourceGroupName $menuResourceGroup `
                        -RequestedWorkspaceName $menuWorkspace | Out-Null
                    New-MigrationAssessment -Root $OutputPath -OverridesPath $MappingOverridesPath | Out-Null
                    Test-SentinelIngestion `
                        -Root $OutputPath `
                        -RequestedSubscriptionId $SubscriptionId `
                        -RequestedResourceGroupName $menuResourceGroup `
                        -RequestedWorkspaceName $menuWorkspace `
                        -Days $LookbackDays | Out-Null
                }
                'T' {
                    Invoke-MigrationSelfTest
                }
                'U' {
                    Update-MigrationHelper
                }
                'Q' {
                    return
                }
                default {
                    Write-Notice "Unknown menu selection '$selection'."
                }
            }
        }
        catch {
            Write-Host ("[ERROR] {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    } while ($true)
}

$migrationPaths = Get-MigrationPaths -Root $OutputPath
if ([string]::IsNullOrWhiteSpace($RulePackagePath)) {
    $RulePackagePath = Join-Path $migrationPaths.Assessment 'AnalyticsRules.json'
}

switch ($Action) {
    'Menu' {
        Start-MigrationMenu
    }
    'Status' {
        [void](Show-PrerequisiteStatus)
    }
    'InstallPrerequisites' {
        Install-MigrationPrerequisites
    }
    'Export' {
        Export-LogRhythmInventory `
            -Root $OutputPath `
            -Server $SqlServer `
            -DatabaseName $Database `
            -SqlAuthentication:$UseSqlAuthentication `
            -Credential $SqlCredential `
            -Encrypt:$EncryptSqlConnection `
            -TrustCertificate:$TrustServerCertificate `
            -RuleXmlPath $AieXmlPath | Out-Null
    }
    'Inventory' {
        Export-SentinelInventory `
            -Root $OutputPath `
            -RequestedSubscriptionId $SubscriptionId `
            -RequestedResourceGroupName $ResourceGroupName `
            -RequestedWorkspaceName $WorkspaceName | Out-Null
    }
    'Assess' {
        New-MigrationAssessment `
            -Root $OutputPath `
            -OverridesPath $MappingOverridesPath | Out-Null
    }
    'ValidateRules' {
        Invoke-RulePackageValidation `
            -Root $OutputPath `
            -RequestedPath $RulePackagePath `
            -RequestedSubscriptionId $SubscriptionId `
            -RequestedResourceGroupName $ResourceGroupName `
            -RequestedWorkspaceName $WorkspaceName `
            -Online:$OnlineValidation | Out-Null
    }
    'DeployRules' {
        Deploy-AnalyticsRulePackage `
            -Root $OutputPath `
            -RequestedPath $RulePackagePath `
            -RequestedSubscriptionId $SubscriptionId `
            -RequestedResourceGroupName $ResourceGroupName `
            -RequestedWorkspaceName $WorkspaceName `
            -AllowEnabled:$EnableRules `
            -SkipOnlineValidation:$SkipQueryValidation | Out-Null
    }
    'ValidateIngestion' {
        Test-SentinelIngestion `
            -Root $OutputPath `
            -RequestedSubscriptionId $SubscriptionId `
            -RequestedResourceGroupName $ResourceGroupName `
            -RequestedWorkspaceName $WorkspaceName `
            -Days $LookbackDays | Out-Null
    }
    'Migrate' {
        [void](Show-PrerequisiteStatus)
        Export-LogRhythmInventory `
            -Root $OutputPath `
            -Server $SqlServer `
            -DatabaseName $Database `
            -SqlAuthentication:$UseSqlAuthentication `
            -Credential $SqlCredential `
            -Encrypt:$EncryptSqlConnection `
            -TrustCertificate:$TrustServerCertificate `
            -RuleXmlPath $AieXmlPath | Out-Null
        Export-SentinelInventory `
            -Root $OutputPath `
            -RequestedSubscriptionId $SubscriptionId `
            -RequestedResourceGroupName $ResourceGroupName `
            -RequestedWorkspaceName $WorkspaceName | Out-Null
        New-MigrationAssessment `
            -Root $OutputPath `
            -OverridesPath $MappingOverridesPath | Out-Null
        Test-SentinelIngestion `
            -Root $OutputPath `
            -RequestedSubscriptionId $SubscriptionId `
            -RequestedResourceGroupName $ResourceGroupName `
            -RequestedWorkspaceName $WorkspaceName `
            -Days $LookbackDays | Out-Null
    }
    'Update' {
        Update-MigrationHelper
    }
    'SelfTest' {
        Invoke-MigrationSelfTest
    }
}
