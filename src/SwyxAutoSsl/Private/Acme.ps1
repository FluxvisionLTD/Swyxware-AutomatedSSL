function Install-PoshAcmeDependency {
    # Only a machine-wide copy counts: the scheduled task runs as SYSTEM and cannot see modules installed in a user profile.
    $allUsers = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $usable = Get-Module -ListAvailable -Name Posh-ACME | Where-Object {
        $_.Version -ge $script:PoshAcmeMinimumVersion -and $_.ModuleBase -like "$allUsers\*"
    }
    if ($usable) { return }
    Enable-Tls12
    Write-RunLog "Installing Posh-ACME $($script:PoshAcmeMinimumVersion) or later for all users from the PowerShell Gallery."
    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope AllUsers -Force | Out-Null
    }
    Install-Module -Name Posh-ACME -MinimumVersion $script:PoshAcmeMinimumVersion -Scope AllUsers -Repository PSGallery -Force
}

function Import-PoshAcme {
    # POSHACME_HOME must be set before Posh-ACME loads so that its account and order data (including private keys)
    # lives in our ACL-protected data directory rather than in the profile of whoever runs it.
    $env:POSHACME_HOME = Get-DataPath PoshAcme
    Import-Module -Name Posh-ACME -MinimumVersion $script:PoshAcmeMinimumVersion -Force -ErrorAction Stop -Verbose:$false
}

function Initialize-AcmeAccount {
    param([Parameter(Mandatory)]$Config)
    Set-PAServer -DirectoryUrl $Config.AcmeServer -DisableTelemetry
    $account = Get-PAAccount
    if (-not $account) {
        Write-RunLog "Creating ACME account on $($Config.AcmeServer) for $($Config.ContactEmail)."
        # Alternate plugin encryption keeps the stored Cloudflare token decryptable by any administrator and by the
        # unattended run, instead of binding it to the Windows user that happened to create the account.
        New-PAAccount -Contact $Config.ContactEmail -AcceptTOS -UseAltPluginEncryption | Out-Null
        return
    }
    if ($account.contact -notcontains "mailto:$($Config.ContactEmail)") {
        Set-PAAccount -Contact $Config.ContactEmail | Out-Null
    }
    if (-not $account.sskey) {
        Set-PAAccount -UseAltPluginEncryption | Out-Null
    }
}

function Update-AcmeCertificate {
    # Requests or renews the certificate for $Config.Fqdn and returns Posh-ACME's certificate object
    # (Thumbprint, NotAfter, PfxFullChain, PfxPass, ...). Renewal only happens inside the ACME (ARI) renewal window
    # unless -ForceRenew is used.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal step of the unattended run.')]
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][securestring]$CloudflareToken,
        [switch]$ForceRenew
    )
    Import-PoshAcme
    Initialize-AcmeAccount -Config $Config

    # The current token is passed on every run, so a changed token takes effect immediately.
    $pluginArgs = @{ CFToken = $CloudflareToken }
    $acmeWarnings = @()
    try {
        $order = Get-PAOrder -MainDomain $Config.Fqdn
        if (-not $order -or $order.status -in 'invalid', 'deactivated') {
            Write-RunLog "Requesting a new certificate for $($Config.Fqdn)."
            $certParams = @{
                Domain          = $Config.Fqdn
                Plugin          = 'Cloudflare'
                PluginArgs      = $pluginArgs
                CertKeyLength   = $Config.CertKeyLength
                PfxPassSecure   = New-RandomPassword
                AcceptTOS       = $true
                Force           = $ForceRenew.IsPresent
                WarningVariable = 'acmeWarnings'
                WarningAction   = 'SilentlyContinue'
            }
            New-PACertificate @certParams | Out-Null
        }
        else {
            Submit-Renewal -MainDomain $Config.Fqdn -PluginArgs $pluginArgs -Force:$ForceRenew -WarningVariable acmeWarnings -WarningAction SilentlyContinue | Out-Null
        }
    }
    finally {
        Remove-PoshAcmeTokenCopy -Fqdn $Config.Fqdn
    }
    foreach ($warning in $acmeWarnings) { Write-RunLog "Posh-ACME: $warning" }

    $certificate = Get-PACertificate -MainDomain $Config.Fqdn
    if (-not $certificate) { throw "Posh-ACME did not return a certificate for $($Config.Fqdn)." }
    $certificate
}

function Remove-PoshAcmeTokenCopy {
    # Posh-ACME saves plugin arguments (the Cloudflare token) to pluginargs.json in the order folder, encrypted with a
    # key stored in the same directory, so a file-level backup of that directory would expose the token. We pass the
    # token on every run anyway, so drop that copy: the only token at rest is the machine-bound DPAPI file.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal cleanup during the unattended run.')]
    param([Parameter(Mandatory)][string]$Fqdn)
    $order = Get-PAOrder -MainDomain $Fqdn
    if ($order -and $order.Folder) {
        Remove-Item -LiteralPath (Join-Path $order.Folder 'pluginargs.json') -Force -ErrorAction SilentlyContinue
    }
}
