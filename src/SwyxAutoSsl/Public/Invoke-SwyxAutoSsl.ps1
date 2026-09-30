function Invoke-SwyxAutoSsl {
    <#
    .SYNOPSIS
        Obtains or renews the Let's Encrypt certificate and installs it into SwyxWare when it changed.
    .DESCRIPTION
        One unattended run:
          1. Request/renew the certificate for the configured FQDN with Posh-ACME (Cloudflare DNS-01). Renewal only
             happens inside the ACME renewal window unless -ForceRenew is used.
          2. If the certificate differs from the one SCST reports as installed, install it with Scst.Cli.exe.
        Staging certificates are never installed. Failures are logged (file + event 1100) and rethrown.
    .PARAMETER ForceRenew
        Request a new certificate even if the current one is not due for renewal.
    .PARAMETER ForceInstall
        Re-install the current certificate into SCST even if SCST already reports it.
    .PARAMETER SkipScstInstall
        Obtain/renew the certificate but do not touch SwyxWare.
    .EXAMPLE
        Invoke-SwyxAutoSsl -Verbose
    #>
    [CmdletBinding()]
    param(
        [switch]$ForceRenew,
        [switch]$ForceInstall,
        [switch]$SkipScstInstall
    )

    Assert-Administrator
    $config = Get-Config
    $state = Get-State

    $transcribing = $false
    try {
        Start-Transcript -LiteralPath (Join-Path (Get-DataPath Logs) ('run-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))) -ErrorAction Stop | Out-Null
        $transcribing = $true
    }
    catch {
        Write-Verbose "Transcript not started: $($_.Exception.Message)"
    }

    try {
        Write-RunLog "Run started for $($config.Fqdn) using $($config.AcmeServer)."
        Remove-OldLog -RetentionDays $config.LogRetentionDays

        $token = Read-Secret -Path (Get-DataPath Token)
        $certificate = Update-AcmeCertificate -Config $config -CloudflareToken $token -ForceRenew:$ForceRenew
        $state.CertificateThumbprint = $certificate.Thumbprint
        $state.CertificateExpires = $certificate.NotAfter.ToString('o')

        if ($config.AcmeServer -ne 'LE_PROD') {
            Write-RunLog ("Staging certificate {0} (expires {1:yyyy-MM-dd}) obtained. Staging certificates are not trusted, so it is not installed into SwyxWare." -f
                $certificate.Thumbprint, $certificate.NotAfter) -Level Warning -EventId 1002
        }
        elseif ($SkipScstInstall) {
            Write-RunLog "Certificate $($certificate.Thumbprint) is ready at $($certificate.PfxFullChain); SCST installation skipped." -Level Warning -EventId 1002
        }
        elseif (-not $ForceInstall -and $certificate.Thumbprint -eq (Get-ScstInstalledThumbprint)) {
            Write-RunLog ("Certificate {0} is installed and valid until {1:yyyy-MM-dd}; nothing to do." -f $certificate.Thumbprint, $certificate.NotAfter) -EventId 1000
        }
        else {
            Install-ScstCertificate -Config $config -Certificate $certificate | Out-Null
            $state.InstalledThumbprint = $certificate.Thumbprint
            $state.InstalledAt = (Get-Date).ToString('o')
            Write-RunLog ("Certificate {0} for {1} (valid until {2:yyyy-MM-dd}) installed into SwyxWare." -f
                $certificate.Thumbprint, $config.Fqdn, $certificate.NotAfter) -EventId 1001
        }
        $state.LastResult = 'Success'
        $state.LastError = $null
    }
    catch {
        $state.LastResult = 'Failed'
        $state.LastError = $_.Exception.Message
        Write-RunLog "Run failed: $($_.Exception.Message)" -Level Error -EventId 1100
        throw
    }
    finally {
        $state.LastRun = (Get-Date).ToString('o')
        Save-State -State $state
        if ($transcribing) { Stop-Transcript | Out-Null }
    }
}
