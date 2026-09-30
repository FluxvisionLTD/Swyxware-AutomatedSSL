#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\SwyxAutoSsl\SwyxAutoSsl.psd1') -Force
    $script:Module = Get-Module SwyxAutoSsl

    # Stand-ins for Posh-ACME so its commands can be mocked without the module installed.
    function global:Get-PAOrder { param([string]$MainDomain) }
    function global:Get-PACertificate { param([string]$MainDomain) }
    function global:New-PACertificate {
        [CmdletBinding()]
        param($Domain, $Plugin, $PluginArgs, $CertKeyLength, $PfxPassSecure, [switch]$AcceptTOS, [switch]$Force)
    }
    function global:Submit-Renewal {
        [CmdletBinding()]
        param($MainDomain, $PluginArgs, [switch]$Force)
    }
    # Stand-ins for the SwyxWare IpPbx module.
    function global:Connect-IpPbx { }
    function global:Disconnect-IpPbx { }

    function Invoke-InModule {
        # Runs a script block inside the module scope, passing arguments positionally.
        param([scriptblock]$ScriptBlock, [object[]]$ArgumentList = @())
        & $script:Module $ScriptBlock @ArgumentList
    }

    function New-TestHome {
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $path 'logs') -Force | Out-Null
        $env:SWYXAUTOSSL_HOME = $path
        $path
    }

    function New-TestSecureString {
        param([string]$Value)
        $secure = New-Object System.Security.SecureString
        foreach ($c in $Value.ToCharArray()) { $secure.AppendChar($c) }
        $secure
    }

    function New-TestConfig {
        param([string]$AcmeServer = 'LE_PROD')
        [pscustomobject]@{
            Fqdn             = 'swyx01.example.com'
            ContactEmail     = 'it@example.com'
            AcmeServer       = $AcmeServer
            CertKeyLength    = '2048'
            LogRetentionDays = 90
            ScstCliPath      = $null
        }
    }

    function New-TestCertificate {
        param([string]$Thumbprint = 'NEWTHUMBPRINT')
        [pscustomobject]@{
            Thumbprint   = $Thumbprint
            NotAfter     = (Get-Date).AddDays(90)
            PfxFullChain = 'C:\ProgramData\SwyxAutoSsl\posh-acme\example\fullchain.pfx'
            PfxPass      = New-TestSecureString 'pfx-password'
        }
    }
}

AfterAll {
    Remove-Module SwyxAutoSsl -Force -ErrorAction SilentlyContinue
    foreach ($name in 'Get-PAOrder', 'Get-PACertificate', 'New-PACertificate', 'Submit-Renewal', 'Connect-IpPbx', 'Disconnect-IpPbx') {
        Remove-Item -Path "function:global:$name" -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name AdminFacade -Scope Global -ErrorAction SilentlyContinue
    Remove-Item Env:\SWYXAUTOSSL_HOME -ErrorAction SilentlyContinue
}

Describe 'Test-Fqdn' {
    It 'accepts <Name>' -ForEach @(
        @{ Name = 'swyx01.example.com' }
        @{ Name = 'pbx.dept.example.co.uk' }
        @{ Name = 'a1-b2.example.net' }
    ) {
        Invoke-InModule { Test-Fqdn $args[0] } $Name | Should -BeTrue
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'localhost' }
        @{ Name = '*.example.com' }
        @{ Name = '-bad.example.com' }
        @{ Name = 'bad-.example.com' }
        @{ Name = 'has space.example.com' }
        @{ Name = '10.0.0.1' }
    ) {
        Invoke-InModule { Test-Fqdn $args[0] } $Name | Should -BeFalse
    }
}

Describe 'Get-ZoneCandidate' {
    It 'walks up the labels, stopping before the TLD' {
        Invoke-InModule { Get-ZoneCandidate -Fqdn 'swyx01.dept.example.com' } |
            Should -Be @('swyx01.dept.example.com', 'dept.example.com', 'example.com')
    }
}

Describe 'ConvertTo-CommandLineArgument' {
    It 'quotes <Value> as <Expected>' -ForEach @(
        @{ Value = 'plain'; Expected = 'plain' }
        @{ Value = ''; Expected = '""' }
        @{ Value = 'C:\Program Data\cert.pfx'; Expected = '"C:\Program Data\cert.pfx"' }
        @{ Value = 'say "hi"'; Expected = '"say \"hi\""' }
        @{ Value = 'C:\dir with space\'; Expected = '"C:\dir with space\\"' }
    ) {
        Invoke-InModule { ConvertTo-CommandLineArgument -Value $args[0] } $Value | Should -BeExactly $Expected
    }
}

Describe 'Secret storage' {
    BeforeEach { New-TestHome | Out-Null }

    It 'round-trips a secret and does not store it in clear text' {
        $path = Join-Path $env:SWYXAUTOSSL_HOME 'test.secret'
        Invoke-InModule {
            Save-Secret -Value $args[0] -Path $args[1]
        } (New-TestSecureString 'cf-token-123'), $path

        Get-Content -LiteralPath $path -Raw | Should -Not -Match 'cf-token-123'
        $read = Invoke-InModule { ConvertFrom-SecureStringToPlain -Value (Read-Secret -Path $args[0]) } $path
        $read | Should -BeExactly 'cf-token-123'
    }

    It 'generates alphanumeric random passwords' {
        $password = Invoke-InModule { ConvertFrom-SecureStringToPlain -Value (New-RandomPassword) }
        $password | Should -Match '^[A-Za-z0-9]{32}$'
    }
}

Describe 'Scst.Cli output parsing' {
    BeforeAll {
        $script:CertificateOutput = @'
30 11:01:32.169 INFO  1   LibManagerAccess                         Connect to CDS with username "EXAMPLE\\admin" and userId 0, result: Success
30 11:01:34.035 INFO  4   CommandlineEngine                        TLS Certificate:
Name:        "swyx01.example.com"
Issuer:      "CN=R11, O=Let's Encrypt, C=US"
Thumbprint:  "0123456789ABCDEF0123456789ABCDEF01234567"
Valid until: 12/28/2026 10:00:00 +00:00
Installation states:
ConfigDataStore: Installed
EmailService: Installed
GlobalPhonebook: InstallationFailed
ManagementApi: Installed
SwyxControlCenter: Installed
'@ -replace "`r?`n", "`r`n"

        # Shape of real SwyxWare 14.26 output, with example values.
        $script:ConfigurationOutput = @'
30 11:51:10.833 INFO  1   LibManagerAccess                         Connect to CDS with username "NT AUTHORITY\\SYSTEM" and userId 0, result: Success
30 11:51:11.530 INFO  4   CommandlineEngine                        SCST configuration:
Servername Mode:              Manual
Servername:                   "swyx01.example.com"
Public IP Address:            ""
TLS Certificate Mode:         Manual
30 11:51:11.679 INFO  7   CommandlineEngine                        RemoteConnector configuration:
Enable Remote Access:         True
Authentication Server:        "swyx01.example.com":9101
RemoteConnector Server:       "swyx01.example.com":{ConnPort}
'@
    }

    It 'parses show certificate' {
        $parsed = Invoke-InModule { ConvertFrom-ScstCertificateOutput -Text $args[0] } $script:CertificateOutput
        $parsed.Name | Should -Be 'swyx01.example.com'
        $parsed.Thumbprint | Should -Be '0123456789ABCDEF0123456789ABCDEF01234567'
        $parsed.Issuer | Should -Be "CN=R11, O=Let's Encrypt, C=US"
        $parsed.InstallationStates.Count | Should -Be 5
        $parsed.InstallationStates['GlobalPhonebook'] | Should -Be 'InstallationFailed'
    }

    It 'parses show configuration without confusing Servername and Servername Mode' {
        $parsed = Invoke-InModule { ConvertFrom-ScstConfigurationOutput -Text $args[0] } $script:ConfigurationOutput
        $parsed.Servername | Should -Be 'swyx01.example.com'
        $parsed.ServernameMode | Should -Be 'Manual'
        $parsed.TlsCertificateMode | Should -Be 'Manual'
    }
}

Describe 'Invoke-ScstCli' {
    It 'closes stdin so an interactive prompt fails fast instead of hanging' {
        # findstr reads stdin until EOF; with stdin closed it returns at once with nothing to print.
        $findstr = Join-Path $env:SystemRoot 'System32\findstr.exe'
        $elapsed = Measure-Command {
            $script:StdinResult = Invoke-InModule {
                Invoke-ScstCli -Path $args[0] -Arguments '/V', '/C:zz_no_match_zz' -TimeoutSeconds 30
            } $findstr
        }
        $elapsed.TotalSeconds | Should -BeLessThan 10
        "$($script:StdinResult.Output)".Trim() | Should -BeNullOrEmpty
    }
}

Describe 'Export-TransientPfx' {
    BeforeAll {
        function New-TestPfxFile {
            # CA + leaf chain, saved as a password-protected PFX like Posh-ACME's fullchain.pfx.
            param([string]$Kind, [string]$Path, [string]$Password)
            $sha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
            if ($Kind -eq 'RSA') {
                $caKey = [System.Security.Cryptography.RSA]::Create(2048)
                $leafKey = [System.Security.Cryptography.RSA]::Create(2048)
                $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
                $caReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=Test CA', $caKey, $sha, $padding)
                $leafReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=swyx01.example.com', $leafKey, $sha, $padding)
            }
            else {
                $curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
                $caKey = [System.Security.Cryptography.ECDsa]::Create($curve)
                $leafKey = [System.Security.Cryptography.ECDsa]::Create($curve)
                $caReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=Test CA', $caKey, $sha)
                $leafReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=swyx01.example.com', $leafKey, $sha)
            }
            $caReq.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($true, $false, 0, $true)))
            $ca = $caReq.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(30))
            $leafPublic = $leafReq.Create($ca, [DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(20), [byte[]](1, 2, 3, 4, 5, 6, 7, 8))
            if ($Kind -eq 'RSA') { $leaf = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leafPublic, $leafKey) }
            else { $leaf = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($leafPublic, $leafKey) }
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            [void]$chain.Add($leaf)
            [void]$chain.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $ca.RawData)))
            [System.IO.File]::WriteAllBytes($Path, $chain.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $Password))
            $leaf.Thumbprint
        }
    }

    It 'converts a <Kind> PFX with its chain into a password-less PFX that keeps the private key' -ForEach @(
        @{ Kind = 'RSA' }
        @{ Kind = 'EC' }
    ) {
        $source = Join-Path $TestDrive "source-$Kind.pfx"
        $target = Join-Path $TestDrive "target-$Kind.pfx"
        $thumbprint = New-TestPfxFile -Kind $Kind -Path $source -Password 'posh-acme-pass'

        Invoke-InModule { Export-TransientPfx -Path $args[0] -Password $args[1] -Destination $args[2] } $source, (New-TestSecureString 'posh-acme-pass'), $target

        $loaded = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $loaded.Import($target, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        $loaded.Count | Should -Be 2
        $leaf = @($loaded | Where-Object { $_.HasPrivateKey })
        $leaf.Count | Should -Be 1
        $leaf[0].Thumbprint | Should -Be $thumbprint
    }
}

Describe 'Install-ScstCertificate' {
    BeforeEach {
        New-TestHome | Out-Null
        Mock -ModuleName SwyxAutoSsl Write-RunLog { }
        Mock -ModuleName SwyxAutoSsl Get-ScstCliPath { 'C:\Swyx\Scst.Cli.exe' }
        Mock -ModuleName SwyxAutoSsl Export-TransientPfx { Set-Content -LiteralPath $Destination -Value 'pfx' }
        Mock -ModuleName SwyxAutoSsl Invoke-ScstCli {
            $script:PfxSeenByScst = $Arguments[[array]::IndexOf($Arguments, $(if ($Arguments[0] -eq 'install') { '--certificate-file' } else { '--file' })) + 1]
            $script:PfxExistedDuringCall = Test-Path -LiteralPath $script:PfxSeenByScst
            [pscustomobject]@{ ExitCode = 0; Output = 'ok'; Error = '' }
        }
        Mock -ModuleName SwyxAutoSsl Get-ScstConfiguration {
            [pscustomobject]@{ ServernameMode = 'Manual'; Servername = 'swyx01.example.com'; TlsCertificateMode = 'Manual' }
        }
        Mock -ModuleName SwyxAutoSsl Get-ScstCertificate {
            [pscustomobject]@{ Thumbprint = 'NEWTHUMBPRINT'; InstallationStates = [ordered]@{ ConfigDataStore = 'Installed'; EmailService = 'Installed' } }
        }
    }

    It 'uses install certificate when SCST is already in manual mode for this FQDN' {
        Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) | Out-Null
        Should -Invoke -ModuleName SwyxAutoSsl Invoke-ScstCli -Times 1 -Exactly -ParameterFilter {
            $Arguments[0] -eq 'install' -and $Arguments[1] -eq 'certificate' -and ($Arguments -join ' ') -match '--certificate-file \S+\.pfx$'
        }
    }

    It 'uses configure manual when SCST uses another server name or mode' {
        Mock -ModuleName SwyxAutoSsl Get-ScstConfiguration {
            [pscustomobject]@{ ServernameMode = 'Automatic'; Servername = 'abc.swyxon.example'; TlsCertificateMode = 'Automatic' }
        }
        Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) | Out-Null
        Should -Invoke -ModuleName SwyxAutoSsl Invoke-ScstCli -Times 1 -Exactly -ParameterFilter {
            $Arguments[0] -eq 'configure' -and $Arguments[1] -eq 'manual' -and ($Arguments -join ' ') -match '--name swyx01\.example\.com --file \S+\.pfx$'
        }
    }

    It 'never passes a password to Scst.Cli' {
        Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) | Out-Null
        Should -Invoke -ModuleName SwyxAutoSsl Invoke-ScstCli -Times 0 -ParameterFilter { $Arguments -contains '--password' }
    }

    It 'hands SCST a temporary PFX inside the data directory and deletes it afterwards' {
        Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) | Out-Null
        $script:PfxSeenByScst | Should -BeLike "$($env:SWYXAUTOSSL_HOME)\scst-install-*.pfx"
        $script:PfxExistedDuringCall | Should -BeTrue
        $script:PfxSeenByScst | Should -Not -Exist
    }

    It 'deletes the temporary PFX when Scst.Cli fails' {
        Mock -ModuleName SwyxAutoSsl Invoke-ScstCli {
            $script:PfxSeenByScst = $Arguments[[array]::IndexOf($Arguments, '--certificate-file') + 1]
            [pscustomobject]@{ ExitCode = 1; Output = 'boom'; Error = '' }
        }
        { Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) } |
            Should -Throw '*exit code 1*'
        $script:PfxSeenByScst | Should -Not -Exist
    }

    It 'fails when SCST reports a different certificate afterwards' {
        Mock -ModuleName SwyxAutoSsl Get-ScstCertificate { [pscustomobject]@{ Thumbprint = 'OTHER'; InstallationStates = [ordered]@{} } }
        { Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) } |
            Should -Throw '*expected ''NEWTHUMBPRINT''*'
    }

    It 'fails when a service was not provisioned' {
        Mock -ModuleName SwyxAutoSsl Get-ScstCertificate {
            [pscustomobject]@{ Thumbprint = 'NEWTHUMBPRINT'; InstallationStates = [ordered]@{ ConfigDataStore = 'Installed'; EmailService = 'InstallationFailed' } }
        }
        { Invoke-InModule { Install-ScstCertificate -Config $args[0] -Certificate $args[1] } (New-TestConfig), (New-TestCertificate) } |
            Should -Throw '*EmailService=InstallationFailed*'
    }
}

Describe 'Update-AcmeCertificate' {
    BeforeEach {
        Mock -ModuleName SwyxAutoSsl Write-RunLog { }
        Mock -ModuleName SwyxAutoSsl Import-PoshAcme { }
        Mock -ModuleName SwyxAutoSsl Initialize-AcmeAccount { }
        Mock -ModuleName SwyxAutoSsl New-PACertificate { }
        Mock -ModuleName SwyxAutoSsl Submit-Renewal { }
        Mock -ModuleName SwyxAutoSsl Get-PACertificate { New-TestCertificate }
    }

    It 'creates a new order with the Cloudflare plugin when none exists' {
        Mock -ModuleName SwyxAutoSsl Get-PAOrder { $null }
        Invoke-InModule { Update-AcmeCertificate -Config $args[0] -CloudflareToken $args[1] } (New-TestConfig), (New-TestSecureString 'tok') | Out-Null
        Should -Invoke -ModuleName SwyxAutoSsl New-PACertificate -Times 1 -Exactly -ParameterFilter {
            $Domain -eq 'swyx01.example.com' -and $Plugin -eq 'Cloudflare' -and $PluginArgs.CFToken -is [securestring] -and $PfxPassSecure -is [securestring]
        }
        Should -Invoke -ModuleName SwyxAutoSsl Submit-Renewal -Times 0 -Exactly
    }

    It 'renews an existing order and hands over the current token' {
        Mock -ModuleName SwyxAutoSsl Get-PAOrder { [pscustomobject]@{ status = 'valid' } }
        Invoke-InModule { Update-AcmeCertificate -Config $args[0] -CloudflareToken $args[1] } (New-TestConfig), (New-TestSecureString 'tok') | Out-Null
        Should -Invoke -ModuleName SwyxAutoSsl Submit-Renewal -Times 1 -Exactly -ParameterFilter {
            $MainDomain -eq 'swyx01.example.com' -and $PluginArgs.CFToken -is [securestring]
        }
        Should -Invoke -ModuleName SwyxAutoSsl New-PACertificate -Times 0 -Exactly
    }

    It 'fails when Posh-ACME returns no certificate' {
        Mock -ModuleName SwyxAutoSsl Get-PAOrder { [pscustomobject]@{ status = 'valid' } }
        Mock -ModuleName SwyxAutoSsl Get-PACertificate { $null }
        { Invoke-InModule { Update-AcmeCertificate -Config $args[0] -CloudflareToken $args[1] } (New-TestConfig), (New-TestSecureString 'tok') } |
            Should -Throw '*did not return a certificate*'
    }

    Context "Posh-ACME's copy of the token" {
        BeforeEach {
            $script:OrderFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $script:OrderFolder | Out-Null
            Set-Content -LiteralPath (Join-Path $script:OrderFolder 'pluginargs.json') -Value '{"CFToken":"encrypted"}'
            Mock -ModuleName SwyxAutoSsl Get-PAOrder { [pscustomobject]@{ status = 'valid'; Folder = $script:OrderFolder } }
        }

        It 'is removed after a successful run' {
            Invoke-InModule { Update-AcmeCertificate -Config $args[0] -CloudflareToken $args[1] } (New-TestConfig), (New-TestSecureString 'tok') | Out-Null
            Join-Path $script:OrderFolder 'pluginargs.json' | Should -Not -Exist
        }

        It 'is removed when the renewal fails' {
            Mock -ModuleName SwyxAutoSsl Submit-Renewal { throw 'DNS challenge failed' }
            { Invoke-InModule { Update-AcmeCertificate -Config $args[0] -CloudflareToken $args[1] } (New-TestConfig), (New-TestSecureString 'tok') } |
                Should -Throw '*DNS challenge failed*'
            Join-Path $script:OrderFolder 'pluginargs.json' | Should -Not -Exist
        }
    }
}

Describe 'Install-PoshAcmeDependency' {
    BeforeEach {
        Mock -ModuleName SwyxAutoSsl Write-RunLog { }
        Mock -ModuleName SwyxAutoSsl Enable-Tls12 { }
        Mock -ModuleName SwyxAutoSsl Get-PackageProvider { [pscustomobject]@{ Version = [version]'2.8.5.208' } }
        Mock -ModuleName SwyxAutoSsl Install-PackageProvider { }
        Mock -ModuleName SwyxAutoSsl Install-Module { }
    }

    It 'installs for all users when Posh-ACME only exists in a user profile (invisible to SYSTEM)' {
        Mock -ModuleName SwyxAutoSsl Get-Module {
            [pscustomobject]@{ Version = [version]'4.34.0'; ModuleBase = 'C:\Users\admin\Documents\WindowsPowerShell\Modules\Posh-ACME\4.34.0' }
        }
        Invoke-InModule { Install-PoshAcmeDependency }
        Should -Invoke -ModuleName SwyxAutoSsl Install-Module -Times 1 -Exactly -ParameterFilter { $Scope -eq 'AllUsers' }
    }

    It 'does nothing when a recent machine-wide copy exists' {
        Mock -ModuleName SwyxAutoSsl Get-Module {
            [pscustomobject]@{ Version = [version]'4.34.0'; ModuleBase = (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\Posh-ACME\4.34.0') }
        }
        Invoke-InModule { Install-PoshAcmeDependency }
        Should -Invoke -ModuleName SwyxAutoSsl Install-Module -Times 0 -Exactly
    }

    It 'upgrades a machine-wide copy that is too old' {
        Mock -ModuleName SwyxAutoSsl Get-Module {
            [pscustomobject]@{ Version = [version]'4.20.0'; ModuleBase = (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\Posh-ACME\4.20.0') }
        }
        Invoke-InModule { Install-PoshAcmeDependency }
        Should -Invoke -ModuleName SwyxAutoSsl Install-Module -Times 1 -Exactly
    }
}

Describe 'Register-RenewalTask' {
    BeforeAll {
        # New-ScheduledTaskTrigger stores StartBoundary in UTC ('...Z'); compare in local time.
        function Get-LocalTriggerTime {
            param($Trigger)
            ([datetime]@($Trigger)[0].StartBoundary).ToString('HH:mm')
        }
    }

    BeforeEach {
        Mock -ModuleName SwyxAutoSsl Write-RunLog { }
        Mock -ModuleName SwyxAutoSsl Register-ScheduledTask { }
        Mock -ModuleName SwyxAutoSsl Get-RenewalTask { $null }
    }

    It 'runs Invoke-SwyxAutoSsl daily as SYSTEM with highest privileges' {
        Invoke-InModule { Register-RenewalTask -Fqdn 'swyx01.example.com' -DailyAt '03:17' }
        Should -Invoke -ModuleName SwyxAutoSsl Register-ScheduledTask -Times 1 -Exactly -ParameterFilter {
            $TaskPath -eq '\SwyxAutoSsl\' -and
            $Principal.UserId -eq 'SYSTEM' -and "$($Principal.RunLevel)" -in 'Highest', '1' -and
            @($Action)[0].Execute -like '*\WindowsPowerShell\v1.0\powershell.exe' -and
            @($Action)[0].Arguments -match 'Import-Module SwyxAutoSsl -ErrorAction Stop; Invoke-SwyxAutoSsl' -and
            (Get-LocalTriggerTime $Trigger) -eq '03:17'
        }
    }

    It 'keeps the time of an existing task' {
        Mock -ModuleName SwyxAutoSsl Get-RenewalTask { [pscustomobject]@{ Triggers = @([pscustomobject]@{ StartBoundary = '2026-01-01T04:42:00' }) } }
        Invoke-InModule { Register-RenewalTask -Fqdn 'swyx01.example.com' }
        Should -Invoke -ModuleName SwyxAutoSsl Register-ScheduledTask -Times 1 -Exactly -ParameterFilter { (Get-LocalTriggerTime $Trigger) -eq '04:42' }
    }

    It 'picks a random time between 01:00 and 05:59 for a new task' {
        Invoke-InModule { Register-RenewalTask -Fqdn 'swyx01.example.com' }
        Should -Invoke -ModuleName SwyxAutoSsl Register-ScheduledTask -Times 1 -Exactly -ParameterFilter { (Get-LocalTriggerTime $Trigger) -match '^0[1-5]:[0-5]\d$' }
    }
}

Describe 'Invoke-SwyxAutoSsl' {
    BeforeEach {
        New-TestHome | Out-Null
        Invoke-InModule {
            Save-Config -Config $args[0]
            Save-Secret -Value $args[1] -Path (Get-DataPath Token)
        } (New-TestConfig), (New-TestSecureString 'tok')

        Mock -ModuleName SwyxAutoSsl Assert-Administrator { }
        Mock -ModuleName SwyxAutoSsl Start-Transcript { }
        Mock -ModuleName SwyxAutoSsl Stop-Transcript { }
        Mock -ModuleName SwyxAutoSsl Write-Information { }
        Mock -ModuleName SwyxAutoSsl Write-Warning { }
        Mock -ModuleName SwyxAutoSsl Update-AcmeCertificate { New-TestCertificate 'NEWTHUMBPRINT' }
        Mock -ModuleName SwyxAutoSsl Get-ScstInstalledThumbprint { 'OLDTHUMBPRINT' }
        Mock -ModuleName SwyxAutoSsl Install-ScstCertificate { }
    }

    It 'installs a certificate SCST does not have yet and records it' {
        Invoke-SwyxAutoSsl
        Should -Invoke -ModuleName SwyxAutoSsl Install-ScstCertificate -Times 1 -Exactly
        $state = Invoke-InModule { Get-State }
        $state.LastResult | Should -Be 'Success'
        $state.InstalledThumbprint | Should -Be 'NEWTHUMBPRINT'
    }

    It 'does nothing when SCST already has the certificate' {
        Mock -ModuleName SwyxAutoSsl Get-ScstInstalledThumbprint { 'NEWTHUMBPRINT' }
        Invoke-SwyxAutoSsl
        Should -Invoke -ModuleName SwyxAutoSsl Install-ScstCertificate -Times 0 -Exactly
        (Invoke-InModule { Get-State }).LastResult | Should -Be 'Success'
    }

    It 'reinstalls with -ForceInstall' {
        Mock -ModuleName SwyxAutoSsl Get-ScstInstalledThumbprint { 'NEWTHUMBPRINT' }
        Invoke-SwyxAutoSsl -ForceInstall
        Should -Invoke -ModuleName SwyxAutoSsl Install-ScstCertificate -Times 1 -Exactly
    }

    It 'never installs staging certificates' {
        Invoke-InModule { Save-Config -Config $args[0] } (New-TestConfig -AcmeServer 'LE_STAGE')
        Invoke-SwyxAutoSsl
        Should -Invoke -ModuleName SwyxAutoSsl Install-ScstCertificate -Times 0 -Exactly
    }

    It 'records the failure and rethrows' {
        Mock -ModuleName SwyxAutoSsl Install-ScstCertificate { throw 'SCST exploded' }
        { Invoke-SwyxAutoSsl } | Should -Throw '*SCST exploded*'
        $state = Invoke-InModule { Get-State }
        $state.LastResult | Should -Be 'Failed'
        $state.LastError | Should -Be 'SCST exploded'
        $state.InstalledThumbprint | Should -BeNullOrEmpty
    }
}

Describe 'Test-SwyxAutoSslCloudflareToken' {
    BeforeEach {
        Mock -ModuleName SwyxAutoSsl Invoke-CloudflareApi -ParameterFilter { $Path -eq '/user/tokens/verify' } {
            [pscustomobject]@{ result = [pscustomobject]@{ status = 'active' } }
        }
        Mock -ModuleName SwyxAutoSsl Invoke-CloudflareApi -ParameterFilter { $Path -eq '/zones' } {
            if ($Query.name -eq 'example.com') { [pscustomobject]@{ result = @([pscustomobject]@{ id = 'zone123' }) } }
            else { [pscustomobject]@{ result = @() } }
        }
    }

    It 'finds the zone above the FQDN' {
        $result = Test-SwyxAutoSslCloudflareToken -Token (New-TestSecureString 'tok') -Fqdn 'swyx01.example.com'
        $result.Valid | Should -BeTrue
        $result.Zone | Should -Be 'example.com'
        $result.ZoneId | Should -Be 'zone123'
    }

    It 'is invalid when no zone is visible' {
        $result = Test-SwyxAutoSslCloudflareToken -Token (New-TestSecureString 'tok') -Fqdn 'swyx01.other.org'
        $result.Valid | Should -BeFalse
        $result.Message | Should -Match 'No Cloudflare zone'
    }

    It 'still accepts account-owned tokens that cannot use the verify endpoint' {
        Mock -ModuleName SwyxAutoSsl Invoke-CloudflareApi -ParameterFilter { $Path -eq '/user/tokens/verify' } { throw 'HTTP 401' }
        $result = Test-SwyxAutoSslCloudflareToken -Token (New-TestSecureString 'tok') -Fqdn 'swyx01.example.com'
        $result.Valid | Should -BeTrue
        $result.TokenStatus | Should -Be 'unverified'
    }

    It 'is invalid when the zone lookup is rejected' {
        Mock -ModuleName SwyxAutoSsl Invoke-CloudflareApi -ParameterFilter { $Path -eq '/zones' } { throw 'HTTP 403 Forbidden' }
        $result = Test-SwyxAutoSslCloudflareToken -Token (New-TestSecureString 'tok') -Fqdn 'swyx01.example.com'
        $result.Valid | Should -BeFalse
        $result.Message | Should -Match '403'
    }
}

Describe 'SwyxWare administrator rights for SYSTEM' {
    BeforeEach {
        Mock -ModuleName SwyxAutoSsl Write-RunLog { }
        Mock -ModuleName SwyxAutoSsl Import-IpPbxModule { }
        Mock -ModuleName SwyxAutoSsl Connect-IpPbx { }
        Mock -ModuleName SwyxAutoSsl Disconnect-IpPbx { }

        # Fake IpPbx AdminFacade backed by an in-memory admin list.
        $script:AdminRows = New-Object System.Collections.ArrayList
        $script:AddedAdmins = New-Object System.Collections.ArrayList
        $script:AddTakesEffect = $true
        $global:AdminFacade = New-Object psobject
        $global:AdminFacade | Add-Member -MemberType ScriptMethod -Name GetAdminUsersView -Value { $script:AdminRows.ToArray() }
        $global:AdminFacade | Add-Member -MemberType ScriptMethod -Name AddAdminUser -Value {
            param($Identity, $ProfileName)
            [void]$script:AddedAdmins.Add("$Identity|$ProfileName")
            if ($script:AddTakesEffect) {
                [void]$script:AdminRows.Add([pscustomobject]@{ AdminUserID = 42; WindowsIdentitiy = $Identity; SID = 'S-1-5-18'; AdminProfileID = 1 })
            }
            0
        }
        $global:AdminFacade | Add-Member -MemberType ScriptMethod -Name DeleteAdminUser -Value {
            param($AdminUserID)
            $row = $script:AdminRows | Where-Object { $_.AdminUserID -eq $AdminUserID }
            if (-not $row) { return $false }
            $script:AdminRows.Remove($row)
            $true
        }
    }

    It 'adds SYSTEM with the IpPbxAdministrator profile when it is missing' {
        Invoke-InModule { Grant-SystemSwyxAdmin } | Should -BeTrue
        $script:AddedAdmins.Count | Should -Be 1
        $script:AddedAdmins[0] | Should -Match '\\SYSTEM\|IpPbxAdministrator$'
        Should -Invoke -ModuleName SwyxAutoSsl Disconnect-IpPbx -Times 1 -Exactly
    }

    It 'leaves an existing SYSTEM entry alone' {
        [void]$script:AdminRows.Add([pscustomobject]@{ AdminUserID = 7; WindowsIdentitiy = 'NT AUTHORITY\SYSTEM'; SID = 'S-1-5-18'; AdminProfileID = 1 })
        Invoke-InModule { Grant-SystemSwyxAdmin } | Should -BeFalse
        $script:AddedAdmins.Count | Should -Be 0
    }

    It 'fails, and still disconnects, when SwyxWare does not accept the entry' {
        $script:AddTakesEffect = $false
        { Invoke-InModule { Grant-SystemSwyxAdmin } } | Should -Throw '*did not accept*'
        Should -Invoke -ModuleName SwyxAutoSsl Disconnect-IpPbx -Times 1 -Exactly
    }

    It 'removes the SYSTEM entry again' {
        [void]$script:AdminRows.Add([pscustomobject]@{ AdminUserID = 42; WindowsIdentitiy = 'NT AUTHORITY\SYSTEM'; SID = 'S-1-5-18'; AdminProfileID = 1 })
        [void]$script:AdminRows.Add([pscustomobject]@{ AdminUserID = 3; WindowsIdentitiy = 'EXAMPLE\admin'; SID = 'S-1-5-21-1-2-3-500'; AdminProfileID = 1 })
        Invoke-InModule { Revoke-SystemSwyxAdmin }
        @($script:AdminRows | ForEach-Object { $_.SID }) | Should -Be @('S-1-5-21-1-2-3-500')
    }
}

Describe 'Register-RenewalTask with -Credential' {
    It 'runs as the given account with highest privileges' {
        Mock -ModuleName SwyxAutoSsl Write-RunLog { }
        Mock -ModuleName SwyxAutoSsl Register-ScheduledTask { }
        Mock -ModuleName SwyxAutoSsl Get-RenewalTask { $null }
        $credential = New-Object System.Management.Automation.PSCredential('EXAMPLE\svc-swyx', (New-TestSecureString 'not-a-real-password'))
        Invoke-InModule { Register-RenewalTask -Fqdn 'swyx01.example.com' -DailyAt '03:17' -Credential $args[0] } $credential
        Should -Invoke -ModuleName SwyxAutoSsl Register-ScheduledTask -Times 1 -Exactly -ParameterFilter {
            $User -eq 'EXAMPLE\svc-swyx' -and $Password -eq 'not-a-real-password' -and $RunLevel -eq 'Highest' -and -not $Principal
        }
    }
}

Describe 'Scst.Cli rights check' {
    It 'explains how to fix a missing SwyxWare administrator right' {
        Mock -ModuleName SwyxAutoSsl Invoke-ScstCli {
            [pscustomobject]@{ ExitCode = 1; Output = '"configuration": "Windows and SwyxWare administrator rights are required to use this command in an elevated command prompt!"'; Error = '' }
        }
        { Invoke-InModule { Get-ScstConfiguration -CliPath 'C:\Swyx\Scst.Cli.exe' } } | Should -Throw '*Re-run Install-SwyxAutoSsl*'
    }
}

Describe 'Install-SwyxAutoSsl task identity' {
    BeforeEach {
        New-TestHome | Out-Null
        foreach ($command in 'Write-RunLog', 'Assert-Administrator', 'Initialize-DataDirectory', 'Register-EventSource',
            'Install-PoshAcmeDependency', 'Install-ModuleFile', 'Set-SwyxAutoSslCloudflareToken', 'Revoke-SystemSwyxAdmin',
            'Register-RenewalTask', 'Start-ScheduledTask', 'Get-SwyxAutoSslStatus') {
            Mock -ModuleName SwyxAutoSsl $command { }
        }
        Mock -ModuleName SwyxAutoSsl Get-ScstCliPath { 'C:\Swyx\Scst.Cli.exe' }
        Mock -ModuleName SwyxAutoSsl Get-ScstFqdn { 'swyx01.example.com' }
        Mock -ModuleName SwyxAutoSsl Grant-SystemSwyxAdmin { $true }
        Mock -ModuleName SwyxAutoSsl Get-RenewalTask { [pscustomobject]@{ State = 'Ready' } }
        $script:InstallArgs = @{ Fqdn = 'swyx01.example.com'; ContactEmail = 'it@example.com' }
        $script:SvcCredential = New-Object System.Management.Automation.PSCredential('EXAMPLE\svc-swyx', (New-TestSecureString 'not-a-real-password'))
    }

    It 'makes SYSTEM a SwyxWare administrator and runs the task as SYSTEM by default' {
        Install-SwyxAutoSsl @script:InstallArgs
        Should -Invoke -ModuleName SwyxAutoSsl Grant-SystemSwyxAdmin -Times 1 -Exactly
        Should -Invoke -ModuleName SwyxAutoSsl Register-RenewalTask -Times 1 -Exactly -ParameterFilter { -not $Credential }
        $config = Invoke-InModule { Get-Config }
        $config.SystemSwyxAdminGranted | Should -BeTrue
        $config.TaskAccount | Should -BeNullOrEmpty
    }

    It 'leaves SwyxWare administrators alone with -TaskCredential' {
        Install-SwyxAutoSsl @script:InstallArgs -TaskCredential $script:SvcCredential
        Should -Invoke -ModuleName SwyxAutoSsl Grant-SystemSwyxAdmin -Times 0 -Exactly
        Should -Invoke -ModuleName SwyxAutoSsl Register-RenewalTask -Times 1 -Exactly -ParameterFilter { $Credential.UserName -eq 'EXAMPLE\svc-swyx' }
        (Invoke-InModule { Get-Config }).TaskAccount | Should -Be 'EXAMPLE\svc-swyx'
    }

    It 'removes the SYSTEM rights it added when switching to -TaskCredential' {
        Install-SwyxAutoSsl @script:InstallArgs
        Install-SwyxAutoSsl @script:InstallArgs -TaskCredential $script:SvcCredential
        Should -Invoke -ModuleName SwyxAutoSsl Revoke-SystemSwyxAdmin -Times 1 -Exactly
        (Invoke-InModule { Get-Config }).SystemSwyxAdminGranted | Should -BeFalse
    }

    It 'keeps a task that runs as another account when re-run without a credential' {
        Install-SwyxAutoSsl @script:InstallArgs -TaskCredential $script:SvcCredential
        Install-SwyxAutoSsl @script:InstallArgs
        Should -Invoke -ModuleName SwyxAutoSsl Register-RenewalTask -Times 1 -Exactly
        Should -Invoke -ModuleName SwyxAutoSsl Grant-SystemSwyxAdmin -Times 0 -Exactly
        (Invoke-InModule { Get-Config }).TaskAccount | Should -Be 'EXAMPLE\svc-swyx'
    }

    It 'switches back to SYSTEM with -RunAsSystem' {
        Install-SwyxAutoSsl @script:InstallArgs -TaskCredential $script:SvcCredential
        Install-SwyxAutoSsl @script:InstallArgs -RunAsSystem
        Should -Invoke -ModuleName SwyxAutoSsl Grant-SystemSwyxAdmin -Times 1 -Exactly
        Should -Invoke -ModuleName SwyxAutoSsl Register-RenewalTask -Times 1 -Exactly -ParameterFilter { -not $Credential }
        (Invoke-InModule { Get-Config }).TaskAccount | Should -BeNullOrEmpty
    }
}
