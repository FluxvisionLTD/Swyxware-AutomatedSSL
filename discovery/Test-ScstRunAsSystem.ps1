#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Checks whether Scst.Cli.exe accepts SYSTEM as a Windows + SwyxWare administrator, and lists the SwyxWare Windows groups.

.DESCRIPTION
    Registers a temporary scheduled task running as SYSTEM that executes the read-only commands
    'Scst.Cli.exe show configuration' and 'Scst.Cli.exe show certificate', prints their output,
    then removes the task again. Nothing else is changed.

    'show certificate' performs the same "Windows and SwyxWare administrator rights" check as
    'install certificate', so if it succeeds here, an unattended SYSTEM task can install certificates.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ScstRunAsSystem.ps1
#>
[CmdletBinding()]
param(
    [string]$ScstCli = (Join-Path $env:ProgramFiles 'Swyx\SwyxWare\SCST\Scst.Cli.exe'),
    [int]$TimeoutSeconds = 120
)

if (-not (Test-Path -LiteralPath $ScstCli)) { throw "Scst.Cli.exe not found at $ScstCli" }

$taskName = 'SwyxAutoSsl-SystemProbe'
$out = Join-Path $env:ProgramData 'SwyxAutoSsl-SystemProbe.txt'
Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue

# Script executed by the task as SYSTEM: records the identity, both command outputs and their exit codes.
$probe = @'
$cli = '{0}'
$out = '{1}'
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('Running as: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
foreach ($command in 'configuration', 'certificate') {{
    $lines.Add('=== Scst.Cli.exe show ' + $command)
    $lines.Add((& $cli show $command --noTraceFile 2>&1 | Out-String))
    $lines.Add('EXITCODE ' + $command + '=' + $LASTEXITCODE)
}}
Set-Content -LiteralPath $out -Value $lines -Encoding UTF8
'@ -f $ScstCli.Replace("'", "''"), $out.Replace("'", "''")
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds)

$probeOutput = ''
$info = $null
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
try {
    $started = Get-Date
    Start-ScheduledTask -TaskName $taskName
    $deadline = $started.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $taskName
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $finished = $task.State -eq 'Ready' -and $info.LastRunTime -ge $started.AddSeconds(-5)
    } until ($finished -or (Get-Date) -gt $deadline)

    if (-not $finished) { Write-Warning "Task did not finish within $TimeoutSeconds seconds (state: $($task.State))." }
    if (Test-Path -LiteralPath $out) { $probeOutput = Get-Content -LiteralPath $out -Raw }
}
finally {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
}

'=== Scst.Cli.exe run as SYSTEM (task result 0x{0:X})' -f $(if ($info) { $info.LastTaskResult } else { 0 })
if ($probeOutput) { $probeOutput } else { '(the task wrote no output)' }

"`n=== Verdict"
if ($probeOutput -match 'administrator rights are required') {
    'SYSTEM is NOT accepted by Scst.Cli.exe: the scheduled task needs a dedicated account or a supplied credential.'
}
elseif ($probeOutput -match 'EXITCODE certificate=0' -and $probeOutput -match 'Thumbprint:') {
    'SYSTEM works: an unattended SYSTEM task can run Scst.Cli.exe certificate commands.'
}
else {
    'Inconclusive: check the output above.'
}

"`n=== HKLM\SOFTWARE\Swyx\General\CurrentVersion\Options (secrets and binary values hidden)"
$key = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Swyx\General\CurrentVersion\Options' -ErrorAction SilentlyContinue
if ($key) {
    foreach ($name in $key.GetValueNames()) {
        $value = $key.GetValue($name)
        if ($name -match '(?i)pass|pwd|secret|token|key') { $value = '***' }
        elseif ($value -is [byte[]]) { $value = "<binary, $($value.Length) bytes>" }
        '{0} = {1}' -f $name, $value
    }
}
else { 'key not found' }

"`n=== Local groups mentioning Swyx / IpPbx, and their members"
Get-LocalGroup | Where-Object { $_.Name -match 'Swyx|IpPbx' -or $_.Description -match 'Swyx|IpPbx' } | ForEach-Object {
    "--- $($_.Name)  [$($_.SID)]  $($_.Description)"
    try { Get-LocalGroupMember -Group $_ -ErrorAction Stop | ForEach-Object { "    $($_.ObjectClass) $($_.Name) [$($_.PrincipalSource)]" } }
    catch { "    (could not list members: $($_.Exception.Message))" }
}
