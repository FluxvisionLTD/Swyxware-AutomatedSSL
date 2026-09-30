# Secrets are encrypted with DPAPI in LocalMachine scope so that both the unattended run and administrators
# can decrypt them; the data directory ACL (SYSTEM + Administrators) is what limits who can read the file.
$script:SecretEntropy = [System.Text.Encoding]::UTF8.GetBytes('SwyxAutoSsl.v1')

function Initialize-ProtectedData {
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) { Add-Type -AssemblyName System.Security }
}

function Save-Secret {
    param([Parameter(Mandatory)][securestring]$Value, [Parameter(Mandatory)][string]$Path)
    Initialize-ProtectedData
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureStringToPlain -Value $Value))
    try {
        $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $script:SecretEntropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        Set-Content -LiteralPath $Path -Value ([Convert]::ToBase64String($protected)) -Encoding Ascii
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Read-Secret {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Secret not found: $Path" }
    Initialize-ProtectedData
    $protected = [Convert]::FromBase64String((Get-Content -LiteralPath $Path -Raw).Trim())
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $script:SecretEntropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    try { ConvertTo-ReadOnlySecureString -Chars ([System.Text.Encoding]::UTF8.GetChars($bytes)) }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Get-Config {
    $path = Get-DataPath Config
    if (-not (Test-Path -LiteralPath $path)) { throw 'SwyxAutoSsl is not configured on this server. Run Install-SwyxAutoSsl first.' }
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function Get-ConfigValue {
    # Settings added in later versions are missing from older config.json files.
    param($Config, [Parameter(Mandatory)][string]$Name, $Default = $null)
    if ($Config -and $Config.PSObject.Properties[$Name] -and $null -ne $Config.$Name) { return $Config.$Name }
    $Default
}

function Save-Config {
    param([Parameter(Mandatory)]$Config)
    $Config | ConvertTo-Json | Set-Content -LiteralPath (Get-DataPath Config) -Encoding UTF8
}

function Get-State {
    $state = [pscustomobject][ordered]@{
        LastRun               = $null
        LastResult            = $null
        LastError             = $null
        CertificateThumbprint = $null
        CertificateExpires    = $null
        InstalledThumbprint   = $null
        InstalledAt           = $null
    }
    $path = Get-DataPath State
    if (Test-Path -LiteralPath $path) {
        $saved = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        foreach ($property in $saved.PSObject.Properties) {
            if ($state.PSObject.Properties[$property.Name]) { $state.($property.Name) = $property.Value }
        }
    }
    $state
}

function Save-State {
    param([Parameter(Mandatory)]$State)
    $State | ConvertTo-Json | Set-Content -LiteralPath (Get-DataPath State) -Encoding UTF8
}
