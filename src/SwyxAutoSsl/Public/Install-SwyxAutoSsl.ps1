function Install-SwyxAutoSsl {
    <#
    .SYNOPSIS
        Configures SwyxAutoSsl on this SwyxWare server.
    .DESCRIPTION
        - Checks that the Swyx Connectivity Setup Tool CLI is present.
        - Creates the data directory (%ProgramData%\SwyxAutoSsl, SYSTEM + Administrators only).
        - Installs Posh-ACME from the PowerShell Gallery if needed and copies this module to
          %ProgramFiles%\WindowsPowerShell\Modules so it can be imported by name.
        - Saves the configuration and the Cloudflare API token (prompted for if none is stored yet).
        - Registers the 'SwyxAutoSsl' event log source.
        - Registers the daily scheduled task '\SwyxAutoSsl\Renew certificate', running Invoke-SwyxAutoSsl as SYSTEM.
        Safe to re-run to change settings; the stored token and task time are kept unless given again.
    .PARAMETER Fqdn
        Public name of this SwyxWare server, e.g. swyx01.example.com. Must be in a Cloudflare zone.
    .PARAMETER ContactEmail
        Contact address for the Let's Encrypt account.
    .PARAMETER CloudflareToken
        Cloudflare API token (Zone:Read + DNS:Edit on the zone). Prompted for when none is stored.
    .PARAMETER Staging
        Use the Let's Encrypt staging environment. Staging certificates are never installed into SwyxWare.
    .PARAMETER CertKeyLength
        Certificate key type. RSA 2048 is the most compatible with desk phones.
    .PARAMETER DailyAt
        Time (HH:mm) of the daily run. Defaults to the existing task's time, or a random time between 01:00 and 05:59.
    .PARAMETER SkipScheduledTask
        Configure everything but do not register the scheduled task (runs only happen via Invoke-SwyxAutoSsl).
    .PARAMETER RunNow
        Start the scheduled task immediately instead of waiting for the next daily run.
    .PARAMETER SkipDependencyInstall
        Do not install Posh-ACME (it must already be installed).
    .EXAMPLE
        Install-SwyxAutoSsl -Fqdn swyx01.example.com -ContactEmail it@example.com -Staging
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateScript({ Test-Fqdn $_ })][string]$Fqdn,
        [Parameter(Mandatory)][ValidateScript({ Test-EmailAddress $_ })][string]$ContactEmail,
        [securestring]$CloudflareToken,
        [switch]$Staging,
        [ValidateSet('2048', '3072', '4096', 'ec-256', 'ec-384')][string]$CertKeyLength = '2048',
        [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')][string]$DailyAt,
        [switch]$SkipScheduledTask,
        [switch]$RunNow,
        [switch]$SkipDependencyInstall
    )

    Assert-Administrator
    if (-not $PSCmdlet.ShouldProcess($Fqdn, 'Configure SwyxAutoSsl')) { return }

    $existing = $null
    if (Test-Path -LiteralPath (Get-DataPath Config)) { $existing = Get-Config }
    $cliPath = Get-ScstCliPath -Config $existing

    Initialize-DataDirectory
    Register-EventSource
    if (-not $SkipDependencyInstall) { Install-PoshAcmeDependency }
    Install-ModuleFile

    $config = [pscustomobject][ordered]@{
        Fqdn             = $Fqdn.ToLowerInvariant()
        ContactEmail     = $ContactEmail
        AcmeServer       = $(if ($Staging) { 'LE_STAGE' } else { 'LE_PROD' })
        CertKeyLength    = $CertKeyLength
        LogRetentionDays = $(if ($existing -and $existing.LogRetentionDays) { $existing.LogRetentionDays } else { 90 })
        ScstCliPath      = $(if ($existing -and $existing.ScstCliPath) { $existing.ScstCliPath } else { $null })
    }
    Save-Config -Config $config
    Write-RunLog "Configured for $($config.Fqdn) using $($config.AcmeServer); SCST CLI: $cliPath."

    $scstFqdn = Get-ScstFqdn
    if ($scstFqdn -and $scstFqdn -ne $config.Fqdn) {
        Write-RunLog "SCST currently uses server name '$scstFqdn'. The first production run will switch SwyxWare to '$($config.Fqdn)'." -Level Warning
    }

    if ($CloudflareToken) {
        Set-SwyxAutoSslCloudflareToken -Token $CloudflareToken -Confirm:$false
    }
    elseif (-not (Test-Path -LiteralPath (Get-DataPath Token))) {
        Set-SwyxAutoSslCloudflareToken -Confirm:$false
    }

    if (-not $SkipScheduledTask) {
        Register-RenewalTask -Fqdn $config.Fqdn -DailyAt $DailyAt
        $start = "Start-ScheduledTask -TaskPath '$($script:TaskPath)' -TaskName '$($script:TaskName)'"
        if ($RunNow) {
            Start-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:TaskName
            Write-RunLog 'First run started in the background; it takes a few minutes. Check Get-SwyxAutoSslStatus.'
        }
        elseif (-not (Get-State).LastRun) {
            Write-RunLog "No certificate has been requested yet; that happens at the next daily run. To run now: $start" -Level Warning
        }
    }
    elseif (-not (Get-State).LastRun) {
        Write-RunLog 'No certificate has been requested yet. Run Invoke-SwyxAutoSsl.' -Level Warning
    }

    Get-SwyxAutoSslStatus
}
