This PowerShell helper exports a LogRhythm EMDB inventory, inventories Microsoft Sentinel, builds data-source and use-case migration plans, stages analytics rules, validates ingestion, and deploys translated rules safely. AIE logic is not converted automatically; export the AIE rules as XML from the LogRhythm Console and pass that folder with `-AieXmlPath`.

Run it from a Windows host with PowerShell 5.1 or later, network access to the LogRhythm SQL Server, and an Azure account that can read the target Sentinel workspace. If Azure CLI is missing, run the script with `-Action InstallPrerequisites` and reopen PowerShell; after signing in, run that action again to register the required Azure resource providers.

```powershell
git clone https://github.com/oguzhanf/logrhythm-to-sentinel-migration-helper.git
Set-Location .\logrhythm-to-sentinel-migration-helper
az login
.\Invoke-LogRhythmSentinelMigration.ps1 -Action InstallPrerequisites
.\Invoke-LogRhythmSentinelMigration.ps1
```

The menu is the simplest execution path: export LogRhythm, inventory Sentinel, then build the assessment. To perform the collection and assessment in one command with Windows integrated SQL authentication:

```powershell
.\Invoke-LogRhythmSentinelMigration.ps1 -Action Migrate `
  -SqlServer 'LRPM01' `
  -SubscriptionId '00000000-0000-0000-0000-000000000000' `
  -ResourceGroupName 'rg-soc' `
  -WorkspaceName 'law-sentinel' `
  -AieXmlPath 'C:\Exports\LogRhythm-AIE'
```

For SQL authentication, pass a credential rather than a plaintext password:

```powershell
$credential = Get-Credential
.\Invoke-LogRhythmSentinelMigration.ps1 -Action Export `
  -SqlServer 'LRPM01\LOGRHYTHM' `
  -UseSqlAuthentication `
  -SqlCredential $credential `
  -TrustServerCertificate
```

Outputs are written to `Documents\LogRhythm-Sentinel-Migration` by default. Translate detections in `Assessment\AnalyticsRules.json`, set each completed rule's `migrationStatus` to `Ready`, validate it, and preview deployment:

```powershell
.\Invoke-LogRhythmSentinelMigration.ps1 -Action ValidateRules -OnlineValidation `
  -SubscriptionId '00000000-0000-0000-0000-000000000000' `
  -ResourceGroupName 'rg-soc' -WorkspaceName 'law-sentinel'

.\Invoke-LogRhythmSentinelMigration.ps1 -Action DeployRules -WhatIf `
  -SubscriptionId '00000000-0000-0000-0000-000000000000' `
  -ResourceGroupName 'rg-soc' -WorkspaceName 'law-sentinel'
```

Remove `-WhatIf` to deploy. Rules are forced disabled unless the package has `enabled: true` and `-EnableRules` is also supplied. Run `.\Invoke-LogRhythmSentinelMigration.ps1 -Action Update` to update the helper, or `Get-Help .\Invoke-LogRhythmSentinelMigration.ps1 -Full` for every action and parameter.
