# Event IDs written to the Windows Application log (source 'SwyxAutoSsl'), for monitoring:
#   1000  Run finished, installed certificate still current
#   1001  New certificate installed into SwyxWare
#   1002  Certificate obtained but not installed (staging or -SkipScstInstall)
#   1100  Run failed
#   1200  Cloudflare API token changed

function Write-RunLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')][string]$Level = 'Information',
        # Non-zero also writes the message to the Windows Application event log.
        [int]$EventId = 0
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level.ToUpperInvariant(), $Message
    $logDir = Get-DataPath Logs
    if (Test-Path -LiteralPath $logDir) {
        Add-Content -LiteralPath (Join-Path $logDir ('SwyxAutoSsl-{0:yyyy-MM}.log' -f (Get-Date))) -Value $line -Encoding UTF8
    }

    if ($Level -eq 'Warning') { Write-Warning $Message }
    else { Write-Information $line -InformationAction Continue }

    if ($EventId) {
        try {
            if ([System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
                [System.Diagnostics.EventLog]::WriteEntry($script:EventSource, $Message, [System.Diagnostics.EventLogEntryType]$Level, $EventId)
            }
        }
        catch {
            Write-Verbose "Could not write to the event log: $($_.Exception.Message)"
        }
    }
}

function Register-EventSource {
    if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
        [System.Diagnostics.EventLog]::CreateEventSource($script:EventSource, 'Application')
    }
}

function Remove-OldLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal log retention during unattended runs.')]
    param([Parameter(Mandatory)][int]$RetentionDays)
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -LiteralPath (Get-DataPath Logs) -File -Filter '*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
