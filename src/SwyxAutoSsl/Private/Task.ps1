# The unattended run is a daily scheduled task, by default running as SYSTEM (which Install-SwyxAutoSsl registers as
# a SwyxWare administrator), or as an account given with -TaskCredential. That account must be a local Administrator
# and a SwyxWare administrator; its password is stored by Task Scheduler, not by SwyxAutoSsl.

$script:TaskPath = '\SwyxAutoSsl\'
$script:TaskName = 'Renew certificate'

function Get-RenewalTask {
    Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:TaskName -ErrorAction SilentlyContinue
}

function Register-RenewalTask {
    param(
        [Parameter(Mandatory)][string]$Fqdn,
        # HH:mm. Defaults to the existing task's time, or a random time between 01:00 and 05:59 so that
        # many servers do not all hit Let's Encrypt at once.
        [string]$DailyAt,
        # Run as this account instead of SYSTEM.
        [pscredential]$Credential
    )
    if (-not $DailyAt) {
        $existing = Get-RenewalTask
        if ($existing -and $existing.Triggers -and $existing.Triggers[0].StartBoundary) {
            $DailyAt = ([datetime]$existing.Triggers[0].StartBoundary).ToString('HH:mm')
        }
        else {
            $DailyAt = '{0:00}:{1:00}' -f (Get-Random -Minimum 1 -Maximum 6), (Get-Random -Minimum 0 -Maximum 60)
        }
    }
    $at = [datetime]::ParseExact($DailyAt, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture)

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $command = 'Import-Module SwyxAutoSsl -ErrorAction Stop; Invoke-SwyxAutoSsl'
    $taskParams = @{
        TaskPath    = $script:TaskPath
        TaskName    = $script:TaskName
        Description = "Renews the Let's Encrypt certificate for $Fqdn and installs it into SwyxWare. Managed by the SwyxAutoSsl PowerShell module."
        Action      = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$command`""
        Trigger     = New-ScheduledTaskTrigger -Daily -At $at
        Settings    = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 30)
        Force       = $true
    }
    if ($Credential) {
        # Task Scheduler stores the password itself; it runs whether or not the account is logged on.
        $taskParams.User = $Credential.UserName
        $taskParams.Password = $Credential.GetNetworkCredential().Password
        $taskParams.RunLevel = 'Highest'
        $account = $Credential.UserName
    }
    else {
        $taskParams.Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $account = 'SYSTEM'
    }
    Register-ScheduledTask @taskParams | Out-Null
    Write-RunLog "Scheduled task '$($script:TaskPath)$($script:TaskName)' runs daily at $DailyAt as $account."
}

function Unregister-RenewalTask {
    if (Get-RenewalTask) {
        Unregister-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:TaskName -Confirm:$false
        Write-RunLog "Scheduled task '$($script:TaskPath)$($script:TaskName)' removed."
    }
}
