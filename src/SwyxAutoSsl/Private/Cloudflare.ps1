$script:CloudflareApiRoot = 'https://api.cloudflare.com/client/v4'

function Invoke-CloudflareApi {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][securestring]$Token,
        [hashtable]$Query
    )
    Enable-Tls12
    $params = @{
        Uri             = $script:CloudflareApiRoot + $Path
        Method          = 'Get'
        Headers         = @{ Authorization = 'Bearer ' + (ConvertFrom-SecureStringToPlain -Value $Token) }
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($Query) { $params.Body = $Query }
    Invoke-RestMethod @params
}

function Get-ZoneCandidate {
    # swyx.dept.example.com -> swyx.dept.example.com, dept.example.com, example.com
    param([Parameter(Mandatory)][string]$Fqdn)
    $labels = $Fqdn.TrimEnd('.').Split('.')
    for ($i = 0; $i -lt $labels.Count - 1; $i++) {
        $labels[$i..($labels.Count - 1)] -join '.'
    }
}
