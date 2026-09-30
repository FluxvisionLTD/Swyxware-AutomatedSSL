function Get-DataRoot {
    # SWYXAUTOSSL_HOME relocates all state (used by the tests).
    if ($env:SWYXAUTOSSL_HOME) { return $env:SWYXAUTOSSL_HOME }
    Join-Path $env:ProgramData 'SwyxAutoSsl'
}

function Get-DataPath {
    param([Parameter(Mandatory)][ValidateSet('Config', 'State', 'Token', 'Logs', 'PoshAcme')][string]$Item)
    $root = Get-DataRoot
    switch ($Item) {
        'Config' { Join-Path $root 'config.json' }
        'State' { Join-Path $root 'state.json' }
        'Token' { Join-Path $root 'cloudflare.token' }
        'Logs' { Join-Path $root 'logs' }
        'PoshAcme' { Join-Path $root 'posh-acme' }
    }
}

function Initialize-DataDirectory {
    $root = Get-DataRoot
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    # Lock the root down before anything sensitive is written below it.
    Set-DataDirectoryAcl -Path $root
    foreach ($dir in (Get-DataPath Logs), (Get-DataPath PoshAcme)) {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }
}

function Set-DataDirectoryAcl {
    # The data directory holds the Cloudflare token, the ACME account key and certificate private keys:
    # SYSTEM and local Administrators only, nothing inherited. Well-known SIDs keep this working on localized Windows.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper; the public command owns confirmation.')]
    param([Parameter(Mandatory)][string]$Path)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-Administrator {
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This command must be run from an elevated PowerShell session (Run as administrator).'
    }
}

function Enable-Tls12 {
    # Windows PowerShell 5.1 can default to TLS 1.0; Let's Encrypt, Cloudflare and the PowerShell Gallery need TLS 1.2.
    $current = [Net.ServicePointManager]::SecurityProtocol
    if ($current -ne [Net.SecurityProtocolType]::SystemDefault -and -not ($current -band [Net.SecurityProtocolType]::Tls12)) {
        [Net.ServicePointManager]::SecurityProtocol = $current -bor [Net.SecurityProtocolType]::Tls12
    }
}

function Test-Fqdn {
    param([string]$Name)
    $Name -match '^(?=.{4,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'
}

function Test-EmailAddress {
    param([string]$Address)
    $Address -match '^[^@\s]+@[^@\s]+\.[^@\s]+$'
}

function New-RandomPassword {
    # Alphanumeric only: it is written to Scst.Cli.exe's stdin, so avoid anything encoding- or shell-sensitive.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure function; changes no state.')]
    param([int]$Length = 32)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'.ToCharArray()
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ConvertTo-ReadOnlySecureString -Chars ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function ConvertTo-ReadOnlySecureString {
    param([Parameter(Mandatory)][AllowEmptyCollection()][char[]]$Chars)
    $secure = New-Object System.Security.SecureString
    foreach ($c in $Chars) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    $secure
}

function ConvertFrom-SecureStringToPlain {
    param([Parameter(Mandatory)][securestring]$Value)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function ConvertTo-CommandLineArgument {
    # Quote one argument per the MSVC/CommandLineToArgvW rules used by .NET executables.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    '"' + $escaped + '"'
}
