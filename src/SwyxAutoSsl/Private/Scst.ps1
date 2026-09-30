# Wrapper around the Swyx Connectivity Setup Tool command line (SwyxWare 14 and later):
#   Scst.Cli.exe configure manual --name <fqdn> --file <pfx>
#   Scst.Cli.exe install certificate --certificate-file <pfx>
#   Scst.Cli.exe show configuration | show certificate
# 'install certificate' is what SCST itself runs after win-acme renews a certificate in automatic mode.
# SCST then binds the certificate to all SwyxWare services (HTTP.sys ports, e-mail service, phonebook, phones).
#
# No password is ever passed: '--password -' is an interactive Console.ReadKey prompt that cannot work unattended,
# and a password argument would be visible in process-auditing logs. Instead SCST imports a password-less PFX copy
# written inside the ACL-protected data directory (SYSTEM + Administrators only) and deleted right after installation.

$script:ScstRegistryKey = 'HKLM:\SOFTWARE\Swyx\SCST'

function Get-ScstCliPath {
    param($Config)
    $candidates = @()
    if ($Config -and $Config.PSObject.Properties['ScstCliPath'] -and $Config.ScstCliPath) { $candidates += $Config.ScstCliPath }
    $candidates += Join-Path $env:ProgramFiles 'Swyx\SwyxWare\SCST\Scst.Cli.exe'
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw 'Scst.Cli.exe was not found. The Swyx Connectivity Setup Tool (SwyxWare 14 or later) is required; set ScstCliPath in config.json if it is installed elsewhere.'
}

function Invoke-ScstCli {
    # stdin is closed immediately, so an unexpected prompt fails fast instead of hanging the unattended run.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments,
        [int]$TimeoutSeconds = 900
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = ($Arguments | ForEach-Object { ConvertTo-CommandLineArgument -Value $_ }) -join ' '
    $psi.WorkingDirectory = Split-Path -Parent $Path
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Close()

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { Write-Verbose "Kill failed: $($_.Exception.Message)" }
            throw "Scst.Cli.exe $($Arguments[0]) $($Arguments[1]) did not finish within $TimeoutSeconds seconds."
        }
        $process.WaitForExit()
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output   = $stdout.Result
            Error    = $stderr.Result
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-ScstField {
    # Scst.Cli prints 'Label:   value' lines; string values are quoted by its logger.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Label)
    $match = [regex]::Match($Text, '(?m)^\s*' + [regex]::Escape($Label) + ':[ \t]*"?(?<value>[^"\r\n]*?)"?[ \t]*\r?$')
    if ($match.Success) { $match.Groups['value'].Value }
}

function ConvertFrom-ScstConfigurationOutput {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    [pscustomobject]@{
        ServernameMode     = Get-ScstField -Text $Text -Label 'Servername Mode'
        Servername         = Get-ScstField -Text $Text -Label 'Servername'
        TlsCertificateMode = Get-ScstField -Text $Text -Label 'TLS Certificate Mode'
    }
}

function ConvertFrom-ScstCertificateOutput {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $states = [ordered]@{}
    foreach ($match in [regex]::Matches($Text, '(?m)^\s*(?<service>\w+):[ \t]*(?<state>Installed|NotInstalled|InstallationFailed)[ \t]*\r?$')) {
        $states[$match.Groups['service'].Value] = $match.Groups['state'].Value
    }
    [pscustomobject]@{
        Name               = Get-ScstField -Text $Text -Label 'Name'
        Issuer             = Get-ScstField -Text $Text -Label 'Issuer'
        Thumbprint         = Get-ScstField -Text $Text -Label 'Thumbprint'
        ValidUntil         = Get-ScstField -Text $Text -Label 'Valid until'
        InstallationStates = $states
    }
}

function Assert-ScstRight {
    # Scst.Cli.exe refuses to work unless the calling account is a Windows and SwyxWare administrator.
    param([Parameter(Mandatory)]$Result)
    if ("$($Result.Output) $($Result.Error)" -match 'administrator rights are required') {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        throw ("Scst.Cli.exe refused '{0}': it needs Windows and SwyxWare administrator rights. Re-run Install-SwyxAutoSsl " +
            'to register SYSTEM as a SwyxWare administrator, or install with -TaskCredential for an account that is one.') -f $identity
    }
}

function Get-ScstConfiguration {
    param([Parameter(Mandatory)][string]$CliPath)
    $result = Invoke-ScstCli -Path $CliPath -Arguments 'show', 'configuration', '--noTraceFile' -TimeoutSeconds 120
    Assert-ScstRight -Result $result
    if ($result.ExitCode -ne 0) { throw "Scst.Cli.exe show configuration failed ($($result.ExitCode)): $($result.Output) $($result.Error)" }
    ConvertFrom-ScstConfigurationOutput -Text $result.Output
}

function Get-ScstCertificate {
    param([Parameter(Mandatory)][string]$CliPath)
    $result = Invoke-ScstCli -Path $CliPath -Arguments 'show', 'certificate', '--noTraceFile' -TimeoutSeconds 120
    Assert-ScstRight -Result $result
    if ($result.ExitCode -ne 0) { throw "Scst.Cli.exe show certificate failed ($($result.ExitCode)): $($result.Output) $($result.Error)" }
    ConvertFrom-ScstCertificateOutput -Text $result.Output
}

function Get-ScstInstalledThumbprint {
    # SCST records the certificate it installed here; cheap to read, no CDS connection needed.
    (Get-ItemProperty -LiteralPath $script:ScstRegistryKey -Name CertThumbprint -ErrorAction SilentlyContinue).CertThumbprint
}

function Get-ScstFqdn {
    (Get-ItemProperty -LiteralPath $script:ScstRegistryKey -Name FQDN -ErrorAction SilentlyContinue).FQDN
}

function Export-TransientPfx {
    # Writes the certificate, its chain and private key as a PFX without a password, for Scst.Cli.exe to import.
    # The destination must be inside the ACL-protected data directory and deleted right after use. EphemeralKeySet
    # keeps the private key in memory only while converting.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][securestring]$Password,
        [Parameter(Mandatory)][string]$Destination
    )
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'Exportable, EphemeralKeySet'
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $collection.Import([System.IO.File]::ReadAllBytes($Path), (ConvertFrom-SecureStringToPlain -Value $Password), $flags)
    try {
        [System.IO.File]::WriteAllBytes($Destination, $collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12))
    }
    finally {
        foreach ($certificate in $collection) { $certificate.Reset() }
    }
}

function Install-ScstCertificate {
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)]$Certificate)

    $cli = Get-ScstCliPath -Config $Config
    $current = Get-ScstConfiguration -CliPath $cli

    $pfx = Join-Path (Get-DataRoot) ('scst-install-{0}.pfx' -f [guid]::NewGuid().ToString('N'))
    try {
        Export-TransientPfx -Path $Certificate.PfxFullChain -Password $Certificate.PfxPass -Destination $pfx
        if ($current.TlsCertificateMode -eq 'Manual' -and $current.Servername -eq $Config.Fqdn) {
            Write-RunLog "Installing certificate $($Certificate.Thumbprint) with 'Scst.Cli.exe install certificate'."
            $cliArgs = 'install', 'certificate', '--certificate-file', $pfx
        }
        else {
            Write-RunLog ("SCST is in '{0}' certificate mode with server name '{1}'; configuring manual mode for {2} with 'Scst.Cli.exe configure manual'." -f
                $current.TlsCertificateMode, $current.Servername, $Config.Fqdn) -Level Warning
            $cliArgs = 'configure', 'manual', '--name', $Config.Fqdn, '--file', $pfx
        }
        $result = Invoke-ScstCli -Path $cli -Arguments $cliArgs
    }
    finally {
        Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
    }

    foreach ($line in ($result.Output + "`n" + $result.Error) -split '\r?\n') {
        if ($line.Trim()) { Write-RunLog "Scst.Cli: $line" }
    }
    Assert-ScstRight -Result $result
    if ($result.ExitCode -ne 0) {
        throw "Scst.Cli.exe $($cliArgs[0]) $($cliArgs[1]) failed with exit code $($result.ExitCode). SCST traces: $env:ProgramData\Swyx\Traces"
    }

    $installed = Get-ScstCertificate -CliPath $cli
    if ($installed.Thumbprint -ne $Certificate.Thumbprint) {
        throw "SCST reports certificate '$($installed.Thumbprint)' after installation, expected '$($Certificate.Thumbprint)'."
    }
    $failed = @($installed.InstallationStates.GetEnumerator() | Where-Object { $_.Value -ne 'Installed' })
    if ($failed) {
        throw 'SCST did not install the certificate for every service: ' + (($failed | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')
    }
    $installed
}
