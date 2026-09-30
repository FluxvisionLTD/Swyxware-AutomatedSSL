#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Read-only discovery of how the Swyx Connectivity Setup Tool (SCST) installs TLS certificates.

.DESCRIPTION
    Collects what is needed to automate "Let's Encrypt -> PFX -> SCST" without user interaction.

    This script makes NO changes to the system and never exports private keys.
    The only Swyx binary it executes is 'scst.cli.exe --help' / '--version' (use -SkipCliHelp to avoid that).

    Collected:
      - Swyx products, services and listening TCP ports
      - SCST install folder, scst.cli.exe help text, CLI verbs/options (reflection + string scan)
      - Scheduled tasks created by SCST (Let's Encrypt renewal / SwyxON DNS)
      - Certificates in LocalMachine\My and WebHosting (public metadata only) and private key ACLs
      - HTTP.sys SSL bindings (netsh http show sslcert) and IIS HTTPS bindings
      - Swyx registry values related to certificates / TLS / FQDN (secrets masked)
      - SCST config files and recent SCST log files (secrets masked)
      - SCST configuration stored in the SwyxWare database (via the IpPbx PowerShell module)

    Review the output before sharing: it contains host names, FQDNs and IP addresses.

.PARAMETER OutputPath
    Folder to write results to. A .zip of the folder is created next to it.

.PARAMETER SkipCliHelp
    Do not execute scst.cli.exe at all; only inspect the binaries statically.

.PARAMETER ScstPath
    Folder containing scst.cli.exe, if it is not found automatically under Program Files\Swyx.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-SwyxScstDiscovery.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot ("output\SwyxScstDiscovery_{0}_{1:yyyyMMdd_HHmmss}" -f $env:COMPUTERNAME, (Get-Date))),
    [switch]$SkipCliHelp,
    [string]$ScstPath
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$Summary = New-Object System.Collections.Generic.List[string]

#region Helpers ---------------------------------------------------------------------------------

function Invoke-Section {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Name)
    $file = Join-Path $OutputPath ($Name + '.txt')
    try {
        $out = & $Body 2>&1 | Out-String -Width 4096
    }
    catch {
        $out = "SECTION FAILED: $($_.Exception.Message)`r`n$($_.ScriptStackTrace)"
    }
    Set-Content -LiteralPath $file -Value $out -Encoding UTF8
}

function Protect-Text {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $Text = [regex]::Replace($Text, '(?i)(key\s*=\s*"[^"]*(?:password|pwd|secret|token|apikey)[^"]*"\s+value\s*=\s*")[^"]*', '$1***MASKED***')
    $Text = [regex]::Replace($Text, '(?i)((?:password|passwd|pwd|secret|token|apikey|api_key)[\w\.-]{0,30}["'']?\s*[:=]\s*["'']?)[^"''\s<>;,]+', '$1***MASKED***')
    $Text
}

function Invoke-Exe {
    param([string]$Path, [string]$Arguments, [int]$TimeoutSeconds = 30)
    "> `"$Path`" $Arguments"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Split-Path -Parent $Path
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()   # any interactive prompt gets EOF instead of hanging
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        try { $p.Kill() } catch { }
        "TIMEOUT after $TimeoutSeconds s (process killed)"
    }
    else {
        "ExitCode: $($p.ExitCode)"
    }
    # A child process that inherited the pipes could keep them open; don't wait on that forever.
    "--- stdout"
    if ($stdout.Wait(5000)) { $stdout.Result } else { '<stdout still open>' }
    "--- stderr"
    if ($stderr.Wait(5000)) { $stderr.Result } else { '<stderr still open>' }
    ""
}

function Get-BinaryString {
    # Printable ASCII runs from the raw bytes and from UTF-16LE at both byte alignments
    # (.NET user strings such as CLI verbs/options live in the UTF-16 #US heap).
    param([string]$Path, [int]$MinLength = 4, [switch]$Utf16Only)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $texts = New-Object System.Collections.Generic.List[string]
    if (-not $Utf16Only) { $texts.Add([System.Text.Encoding]::GetEncoding(28591).GetString($bytes)) }
    $texts.Add([System.Text.Encoding]::Unicode.GetString($bytes))
    if ($bytes.Length -gt 1) { $texts.Add([System.Text.Encoding]::Unicode.GetString($bytes, 1, $bytes.Length - 1)) }
    $rx = New-Object System.Text.RegularExpressions.Regex ("[\x20-\x7E]{$MinLength,}")
    $seen = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in $texts) {
        foreach ($m in $rx.Matches($t)) {
            if ($seen.Add($m.Value)) { $m.Value }
        }
    }
}

function Get-PrivateKeyDetail {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    if (-not $Cert.HasPrivateKey) { return 'no private key' }
    try {
        $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        if (-not $key) { $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert) }
        if (-not $key) { return 'private key present but not RSA/ECDsa' }

        $file = $null
        $detail = $key.GetType().Name
        if ($key.PSObject.Properties['Key'] -and $key.Key -is [System.Security.Cryptography.CngKey]) {
            $cng = $key.Key
            $detail += " | provider=$($cng.Provider.Provider) | exportPolicy=$($cng.ExportPolicy) | machineKey=$($cng.IsMachineKey)"
            $file = Join-Path $env:ProgramData ("Microsoft\Crypto\Keys\" + $cng.UniqueName)
        }
        elseif ($key.PSObject.Properties['CspKeyContainerInfo']) {
            $ci = $key.CspKeyContainerInfo
            $detail += " | provider=$($ci.ProviderName) | exportable=$($ci.Exportable) | machineKey=$($ci.MachineKeyStore)"
            $file = Join-Path $env:ProgramData ("Microsoft\Crypto\RSA\MachineKeys\" + $ci.UniqueKeyContainerName)
        }
        if ($file -and (Test-Path -LiteralPath $file)) {
            $acl = (Get-Acl -LiteralPath $file).Access | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" }
            $detail += " | keyFile=$file | ACL: " + ($acl -join '; ')
        }
        elseif ($file) {
            $detail += " | keyFile not found at $file"
        }
        $detail
    }
    catch {
        "private key inspection failed: $($_.Exception.Message)"
    }
}

#endregion

#region Locate SCST ----------------------------------------------------------------------------

Write-Host "Locating Swyx / SCST installation..."
$SwyxRoots = @(
    (Join-Path $env:ProgramFiles 'Swyx'),
    (Join-Path ${env:ProgramFiles(x86)} 'Swyx'),
    (Join-Path $env:ProgramFiles 'Enreach'),
    (Join-Path ${env:ProgramFiles(x86)} 'Enreach')
) | Where-Object { Test-Path -LiteralPath $_ }

# Note: -Include is silently ignored together with -LiteralPath in Windows PowerShell 5.1, so filter explicitly.
$ScstExes = @()
if ($ScstPath) {
    $ScstExes += Get-ChildItem -LiteralPath $ScstPath -File -Filter '*.exe' | Where-Object { $_.Name -match '(?i)^scst|connectivity' }
}
elseif ($SwyxRoots) {
    $ScstExes += Get-ChildItem -LiteralPath $SwyxRoots -Recurse -File -Filter '*.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)^scst|connectivity' }
}

$SwyxTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
        $text = "$($_.TaskPath)$($_.TaskName) $actions"
        # Built-in \Microsoft\Windows\ tasks (e.g. CertificateServicesClient) are noise unless they reference Swyx.
        $text -match '(?i)swyx|scst|ippbx|enreach' -or
        ($text -match '(?i)letsencrypt|acme|certif' -and $_.TaskPath -notlike '\Microsoft\Windows\*')
    })
foreach ($t in $SwyxTasks) {
    foreach ($a in $t.Actions) {
        if (-not $a.Execute) { continue }
        $exe = [Environment]::ExpandEnvironmentVariables($a.Execute.Trim('"'))
        if ($exe -match '(?i)scst|connectivity' -and (Test-Path -LiteralPath $exe)) { $ScstExes += Get-Item -LiteralPath $exe }
    }
}

if (-not $ScstExes) {
    Write-Host "  not found under Swyx folders, searching Program Files (may take a minute)..."
    $ScstExes += Get-ChildItem -LiteralPath $env:ProgramFiles, ${env:ProgramFiles(x86)} -Recurse -Depth 6 -File -Filter 'scst*.exe' -ErrorAction SilentlyContinue
}

$ScstExes = @($ScstExes | Sort-Object FullName -Unique)
$ScstDirs = @($ScstExes | ForEach-Object { $_.DirectoryName } | Sort-Object -Unique)
$ScstCli = $ScstExes | Where-Object { $_.Name -ieq 'scst.cli.exe' } | Select-Object -First 1

$Summary.Add("SCST executables: " + $(if ($ScstExes) { ($ScstExes.FullName -join '; ') } else { 'NOT FOUND' }))
$Summary.Add("SCST-related scheduled tasks: " + $(if ($SwyxTasks) { (($SwyxTasks | ForEach-Object { $_.TaskPath + $_.TaskName }) -join '; ') } else { 'none' }))

#endregion

#region Sections -------------------------------------------------------------------------------

Invoke-Section '01-system' {
    "Computer : $env:COMPUTERNAME"
    try { "DNS name : " + [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { }
    Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture, OSLanguage, MUILanguages
    "Windows PowerShell : $($PSVersionTable.PSVersion)"
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    "PowerShell 7       : " + $(if ($pwsh) { $pwsh.Source } else { 'not installed' })
    ".NET Fx release    : " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
    $dotnet = Get-Command dotnet.exe -ErrorAction SilentlyContinue
    if ($dotnet) { "`n--- dotnet --list-runtimes"; & $dotnet.Source --list-runtimes }
    "`n--- PowerShell modules of interest"
    Get-Module -ListAvailable Posh-ACME, WebAdministration, IISAdministration, PKI, IpPbx -ErrorAction SilentlyContinue |
        Format-Table Name, Version, Path -AutoSize
    "`n--- Installed Swyx / Enreach products"
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Swyx|Enreach|IpPbx' -or $_.Publisher -match 'Swyx|Enreach' } |
        Sort-Object DisplayName |
        Format-Table DisplayName, DisplayVersion, Publisher, InstallLocation -AutoSize
}

Invoke-Section '02-services-ports' {
    "--- Swyx services"
    Get-CimInstance Win32_Service |
        Where-Object { $_.Name -match 'Swyx|IpPbx|Enreach|Scst' -or $_.DisplayName -match 'Swyx|IpPbx|Enreach' -or $_.PathName -match 'Swyx|Enreach' } |
        Sort-Object Name |
        Format-Table Name, DisplayName, State, StartMode, StartName, ProcessId, PathName -AutoSize -Wrap
    "`n--- Listening TCP ports"
    $procs = @{}
    Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Sort-Object LocalPort, LocalAddress |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } } |
        Format-Table -AutoSize
}

Invoke-Section '03-scst-files' {
    "SCST executables found:"
    $ScstExes | ForEach-Object { "  " + $_.FullName }
    foreach ($dir in $ScstDirs) {
        "`n===== $dir"
        Get-ChildItem -LiteralPath $dir -File | Sort-Object Name | Select-Object Name, Length, LastWriteTime,
            @{ n = 'FileVersion'; e = { $_.VersionInfo.FileVersion } },
            @{ n = 'Description'; e = { $_.VersionInfo.FileDescription } } |
            Format-Table -AutoSize
        "Subfolders:"
        Get-ChildItem -LiteralPath $dir -Directory | ForEach-Object { "  " + $_.Name }
    }
}

Invoke-Section '04-scst-cli-help' {
    if (-not $ScstCli) { 'scst.cli.exe not found'; return }
    if ($SkipCliHelp) { 'Skipped (-SkipCliHelp)'; return }
    Invoke-Exe -Path $ScstCli.FullName -Arguments '--help'
    Invoke-Exe -Path $ScstCli.FullName -Arguments 'help'
    Invoke-Exe -Path $ScstCli.FullName -Arguments '--version'
}

Invoke-Section '05-scst-reflection' {
    if (-not $ScstDirs) { 'No SCST folder found'; return }
    $reflect = @'
param([string]$Dir, [string]$Pattern)
$ErrorActionPreference = 'Continue'
# Compiled resolver: a scriptblock AssemblyResolve handler deadlocks in PowerShell 7.
Add-Type -TypeDefinition @"
using System; using System.IO; using System.Reflection;
public static class ScstDirResolver {
    static string _dir;
    public static void Register(string dir) {
        _dir = dir;
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
            string n = new AssemblyName(e.Name).Name;
            foreach (string ext in new[] { ".dll", ".exe" }) {
                string p = Path.Combine(_dir, n + ext);
                if (File.Exists(p)) { try { return Assembly.LoadFrom(p); } catch { } }
            }
            return null;
        };
    }
}
"@
[ScstDirResolver]::Register($Dir)
$flags = [System.Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'
$attrRx = 'Verb|Command|Option|Argument|Value|Usage|HelpText'
$typeRx = 'Command|Verb|Option|Install|Certif|Pfx|Renew|Reset|Register|Task|Binding|Netsh|SslCert|Port|Provision|Component|Service|Store|Tls|Scst'
Get-ChildItem -LiteralPath $Dir -File | Where-Object { ($_.Extension -eq '.dll' -or $_.Extension -eq '.exe') -and $_.Name -match $Pattern } | ForEach-Object {
    "################ $($_.Name)"
    try { $asm = [System.Reflection.Assembly]::LoadFrom($_.FullName) } catch { "  not loadable as .NET assembly here: $($_.Exception.Message)"; return }
    "  $($asm.FullName)"
    try { $tf = $asm.GetCustomAttributesData() | Where-Object { $_.AttributeType.Name -eq 'TargetFrameworkAttribute' }; if ($tf) { "  $tf" } } catch { }
    try { $types = $asm.GetTypes() } catch [System.Reflection.ReflectionTypeLoadException] { $types = $_.Exception.Types | Where-Object { $_ }; "  (partial type load)" }
    foreach ($t in $types) {
        $lines = New-Object System.Collections.Generic.List[string]
        try { foreach ($a in $t.GetCustomAttributesData()) { if ($a.AttributeType.Name -match $attrRx) { $lines.Add("    [type-attr] $a") } } } catch { }
        foreach ($m in $t.GetMembers($flags)) {
            try { foreach ($a in $m.GetCustomAttributesData()) { if ($a.AttributeType.Name -match $attrRx) { $lines.Add("    [$($m.MemberType)] $($m.Name) $a") } } } catch { }
        }
        $interesting = $t.FullName -match $typeRx -and -not $t.FullName.Contains('<')
        if ($lines.Count -eq 0 -and -not $interesting) { continue }
        "  == $($t.FullName)"
        $lines
        if (-not $interesting) { continue }
        if ($t.IsEnum) { try { [Enum]::GetNames($t) | ForEach-Object { "    enum $_" } } catch { } ; continue }
        foreach ($p in $t.GetProperties($flags)) { try { "    prop $($p.PropertyType.Name) $($p.Name)" } catch { } }
        foreach ($m in $t.GetMethods($flags)) {
            if ($m.IsSpecialName -or $m.Name.Contains('<')) { continue }
            try { "    method $($m.Name)(" + (($m.GetParameters() | ForEach-Object { $_.ParameterType.Name + ' ' + $_.Name }) -join ', ') + ") -> $($m.ReturnType.Name)" } catch { "    method $($m.Name)(?)" }
        }
    }
}
'@
    $tmp = Join-Path $env:TEMP ("scst_reflect_{0}.ps1" -f [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $tmp -Value $reflect -Encoding UTF8
    try {
        # Windows PowerShell loads .NET Framework assemblies, pwsh loads .NET (Core) ones: try both.
        $hosts = @((Get-Command powershell.exe).Source)
        $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($pwsh) { $hosts += $pwsh.Source }
        foreach ($dir in $ScstDirs) {
            foreach ($h in $hosts) {
                "==================== $h :: $dir"
                Invoke-Exe -Path $h -TimeoutSeconds 300 -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Dir "{1}" -Pattern "(?i)scst|connectivity"' -f $tmp, $dir)
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

Invoke-Section '06-scst-strings' {
    if (-not $ScstDirs) { 'No SCST folder found'; return }
    $keywords = '(?i)pfx|p12|certif|thumb|letsencrypt|acme|install|renew|reset|unregister|register|usage|--[a-z]|netsh|sslcert|bind|9100|9101|16203|5061|webhosting|localmachine|schtasks|scheduled|provision|fqdn|split|remoteconnector|restart|service|password|verb|command|option'
    foreach ($dir in $ScstDirs) {
        Get-ChildItem -LiteralPath $dir -File |
            Where-Object { ($_.Extension -eq '.dll' -or $_.Extension -eq '.exe') -and $_.Name -match '(?i)scst|connectivity' -and $_.Length -lt 100MB } |
            ForEach-Object {
                "################ $($_.FullName) (keyword-filtered)"
                Get-BinaryString -Path $_.FullName -MinLength 4 |
                    Where-Object { $_ -match $keywords -and $_.Length -lt 400 -and $_ -notmatch '>b__|^<>|^[gs]et_' }
                ""
            }
    }
    # Full UTF-16 string dump of the CLI itself: that is where verb/option names and help texts live.
    foreach ($f in @($ScstCli.FullName, ($ScstCli.FullName -replace '\.exe$', '.dll'))) {
        if ($f -and (Test-Path -LiteralPath $f)) {
            "################ $f (all UTF-16 strings)"
            Get-BinaryString -Path $f -MinLength 3 -Utf16Only
            ""
        }
    }
}

Invoke-Section '07-scheduled-tasks' {
    if (-not $SwyxTasks) { 'No Swyx/SCST related scheduled tasks found'; return }
    foreach ($t in $SwyxTasks) {
        "==== $($t.TaskPath)$($t.TaskName)  State=$($t.State)  RunAs=$($t.Principal.UserId)  RunLevel=$($t.Principal.RunLevel)"
        foreach ($a in $t.Actions) { "  Exec    : $($a.Execute)"; "  Args    : $($a.Arguments)"; "  WorkDir : $($a.WorkingDirectory)" }
        foreach ($tr in $t.Triggers) { "  Trigger : $($tr.CimClass.CimClassName) Start=$($tr.StartBoundary) Days=$($tr.DaysInterval) Repeat=$($tr.Repetition.Interval)" }
        $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        if ($info) { "  LastRun=$($info.LastRunTime) LastResult=$($info.LastTaskResult) NextRun=$($info.NextRunTime)" }
        "  --- XML"
        Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath
        ""
    }
}

Invoke-Section '08-certificates' {
    foreach ($store in 'My', 'WebHosting') {
        "===== Cert:\LocalMachine\$store"
        Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Subject       = $_.Subject
                DnsNames      = ($_.DnsNameList | ForEach-Object { $_.Unicode }) -join ', '
                Issuer        = $_.Issuer
                Thumbprint    = $_.Thumbprint
                NotBefore     = $_.NotBefore
                NotAfter      = $_.NotAfter
                FriendlyName  = $_.FriendlyName
                KeyAlgorithm  = $_.PublicKey.Oid.FriendlyName
                KeySize       = $(try { $_.PublicKey.Key.KeySize } catch { 'n/a' })   # .PublicKey.Key throws for ECDSA on .NET Framework
                EKU           = ($_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', '
                HasPrivateKey = $_.HasPrivateKey
                PrivateKey    = Get-PrivateKeyDetail $_
            }
        } | Format-List
    }
    "===== Swyx / Let's Encrypt related certificates in Root and CA stores"
    Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match "Swyx|IpPbx|Enreach|Let's Encrypt|ISRG" -or $_.Issuer -match "Swyx|IpPbx|Enreach|Let's Encrypt|ISRG" } |
        Format-Table @{ n = 'Store'; e = { $_.PSParentPath -replace '.*::', '' } }, Subject, Issuer, Thumbprint, NotAfter -AutoSize
}

Invoke-Section '09-bindings' {
    $certIndex = @{}
    foreach ($s in 'My', 'WebHosting') {
        Get-ChildItem "Cert:\LocalMachine\$s" -ErrorAction SilentlyContinue | ForEach-Object {
            $certIndex[$_.Thumbprint.ToUpperInvariant()] = "$s | $($_.Subject) | expires $($_.NotAfter.ToString('yyyy-MM-dd')) | issuer $($_.Issuer)"
        }
    }
    $raw = @(netsh http show sslcert)

    "--- HTTP.sys SSL bindings mapped to certificates"
    $endpoint = $null
    foreach ($line in $raw) {
        if ($line -match ':\s+(\S+:\d+)\s*$') { $endpoint = $Matches[1] }
        elseif ($endpoint -and $line -match ':\s+([0-9a-fA-F]{40})\s*$') {
            $hash = $Matches[1].ToUpperInvariant()
            $desc = $certIndex[$hash]
            if (-not $desc) { $desc = 'NOT FOUND in LocalMachine\My or WebHosting' }
            "{0,-28} {1}  -> {2}" -f $endpoint, $hash, $desc
            $endpoint = $null
        }
    }
    "`n--- netsh http show sslcert (raw)"
    $raw
    "`n--- netsh http show urlacl (raw)"
    netsh http show urlacl
    "`n--- IIS HTTPS bindings"
    if (Get-Module -ListAvailable WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Get-WebBinding -ErrorAction SilentlyContinue |
            Select-Object protocol, bindingInformation, certificateHash, certificateStoreName, @{ n = 'Site'; e = { $_.ItemXPath -replace '.*name=''([^'']+)''.*', '$1' } } |
            Format-Table -AutoSize
    }
    else { 'IIS WebAdministration module not installed' }
}

Invoke-Section '10-registry' {
    $interesting = '(?i)cert|thumb|tls|ssl|fqdn|scst|servername|publicname|hostname|port|letsencrypt|acme|pfx|store|remoteconnector|dns|https|provision|connectivity'
    $secret = '(?i)pass|pwd|secret|token|apikey|privatekey'
    foreach ($root in 'HKLM:\SOFTWARE\Swyx', 'HKLM:\SOFTWARE\WOW6432Node\Swyx', 'HKLM:\SOFTWARE\Enreach', 'HKLM:\SOFTWARE\WOW6432Node\Enreach') {
        if (-not (Test-Path $root)) { continue }
        "===== $root"
        $keys = @(Get-Item $root) + @(Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue)
        foreach ($k in $keys) {
            foreach ($n in $k.GetValueNames()) {
                if ("$($k.Name)\$n" -notmatch $interesting) { continue }
                $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                if ($n -match $secret) { $v = '***MASKED***' }
                elseif ($v -is [byte[]]) { $v = "<binary, $($v.Length) bytes>" }
                elseif ($v -is [array]) { $v = $v -join ' | ' }
                "{0}\{1} = {2}" -f ($k.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM'), $n, $v
            }
        }
    }
}

Invoke-Section '11-scst-config-files' {
    foreach ($dir in $ScstDirs) {
        Get-ChildItem -LiteralPath $dir -File -Recurse -Depth 1 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -match '(?i)^\.(config|json|xml)$' -and $_.Name -notmatch '\.deps\.json$' -and $_.Length -lt 1MB -and
                $_.Name -match '(?i)scst|connectivity|appsettings|nlog|log4net|serilog'
            } |
            ForEach-Object {
                "################ $($_.FullName)"
                Protect-Text (Get-Content -LiteralPath $_.FullName -Raw)
                ""
            }
    }
}

Invoke-Section '12-scst-logs' {
    $logDir = Join-Path $OutputPath 'logs'
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    $roots = @(
        (Join-Path $env:ProgramData 'Swyx'),
        (Join-Path $env:ProgramData 'Enreach'),
        (Join-Path $env:windir 'Temp')
    ) + $ScstDirs
    $roots += Get-ChildItem 'C:\Users\*\AppData\Local\Swyx*', 'C:\Users\*\AppData\Roaming\Swyx*', 'C:\Users\*\AppData\Local\Enreach*', 'C:\Users\*\AppData\Local\Temp' -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
    $roots = $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique

    $ownOutput = [System.IO.Path]::GetFullPath($OutputPath).TrimEnd('\') + '\'
    $logs = foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '(?i)scst|connectivity' -and $_.Extension -match '(?i)\.(log|txt|trc|json)$' -and
                -not $_.FullName.StartsWith($ownOutput, [System.StringComparison]::OrdinalIgnoreCase)
            }
    }
    $logs = @($logs | Sort-Object FullName -Unique | Sort-Object LastWriteTime -Descending)
    "Found $($logs.Count) SCST-looking log files:"
    $logs | Format-Table LastWriteTime, Length, FullName -AutoSize
    $i = 0
    foreach ($l in ($logs | Select-Object -First 10)) {
        $i++
        $dest = Join-Path $logDir ("{0:00}_{1}" -f $i, $l.Name)
        Protect-Text ((Get-Content -LiteralPath $l.FullName -Tail 5000 -ErrorAction SilentlyContinue) -join "`r`n") |
            Set-Content -LiteralPath $dest -Encoding UTF8
        "copied (last 5000 lines, secrets masked): $($l.FullName) -> logs\$(Split-Path -Leaf $dest)"
    }
}

Invoke-Section '13-swyx-db-scst-config' {
    $module = Get-Module -ListAvailable IpPbx | Select-Object -First 1 -ExpandProperty Path
    if (-not $module -and $SwyxRoots) {
        $module = Get-ChildItem -LiteralPath $SwyxRoots -Recurse -File -Filter 'IpPbx.psd1' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $module) { 'IpPbx PowerShell module not found'; return }
    "Module: $module"
    Import-Module $module -ErrorAction Stop
    Connect-IpPbx -ErrorAction Stop   # localhost, current Windows account (must be a SwyxWare administrator)
    $af = $Global:AdminFacade
    try {
        "`n--- SSL certificate bound to port 9100"
        $af.GetSslCertificateInfoForPort9100() | Format-List *
        "--- SSL certificate bound to port 9101"
        $af.GetSslCertificateInfoForPort9101() | Format-List *
        "--- RemoteConnector certificate info"
        $af.GetRemoteConnectorCertificateInfo() | Format-List *

        $names = @('', 'Default', 'default', 'Scst', 'SCST', 'scst', 'Tls', 'TLS', 'TlsCertificate', 'ServerCertificate',
            'Server', 'SwyxServer', 'IpPbx', 'LetsEncrypt', 'Manual', 'Automatic', $env:COMPUTERNAME)
        foreach ($n in $names) {
            try {
                $cfg = $af.GetScstConfiguration($n)
                if ($cfg) { "`n--- GetScstConfiguration('$n')"; $cfg | Format-List * }
            }
            catch { }
            try {
                $ci = $af.GetScstCertificateInfo($n)
                if ($ci) {
                    "`n--- GetScstCertificateInfo('$n')"
                    $ci | Format-List *
                    if ($ci.InstallationStates) { $ci.InstallationStates.GetEnumerator() | ForEach-Object { "  InstallationState[$($_.Key)] = $($_.Value)" } }
                }
            }
            catch { }
        }
    }
    finally {
        Disconnect-IpPbx -ErrorAction SilentlyContinue
    }
}

#endregion

#region Summary + zip --------------------------------------------------------------------------

$port80 = Get-NetTCPConnection -State Listen -LocalPort 80 -ErrorAction SilentlyContinue | Select-Object -First 1
$Summary.Add("TCP 80 listener (matters for HTTP-01 challenge): " + $(if ($port80) { "PID $($port80.OwningProcess) ($((Get-Process -Id $port80.OwningProcess -ErrorAction SilentlyContinue).ProcessName))" } else { 'none' }))
$Summary.Add("Output folder: $OutputPath")
Set-Content -LiteralPath (Join-Path $OutputPath '00-summary.txt') -Value $Summary -Encoding UTF8

$zip = "$OutputPath.zip"
Compress-Archive -Path (Join-Path $OutputPath '*') -DestinationPath $zip -Force
Write-Host ""
$Summary | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "Done. Review, then send back: $zip" -ForegroundColor Green

#endregion
