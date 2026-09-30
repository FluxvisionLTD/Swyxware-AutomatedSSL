function Test-SwyxAutoSslCloudflareToken {
    <#
    .SYNOPSIS
        Checks that a Cloudflare API token can see the DNS zone of this server's FQDN.
    .DESCRIPTION
        Verifies the token and looks up the Cloudflare zone containing the FQDN (walking up the labels, the way the
        Posh-ACME Cloudflare plugin does). DNS:Edit permission itself is only proven by a certificate request; do a
        staging run for that.
    .PARAMETER Token
        Token to test. Defaults to the token stored on this server.
    .PARAMETER Fqdn
        Name to find the zone for. Defaults to the configured FQDN.
    .EXAMPLE
        Test-SwyxAutoSslCloudflareToken
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [securestring]$Token,
        [string]$Fqdn
    )

    if (-not $Fqdn) { $Fqdn = (Get-Config).Fqdn }
    if (-not $Token) { $Token = Read-Secret -Path (Get-DataPath Token) }

    $result = [pscustomobject][ordered]@{
        Fqdn        = $Fqdn
        TokenStatus = $null
        Zone        = $null
        ZoneId      = $null
        Valid       = $false
        Message     = $null
    }

    try {
        $result.TokenStatus = (Invoke-CloudflareApi -Path '/user/tokens/verify' -Token $Token).result.status
    }
    catch {
        # Account-owned tokens cannot use the user verify endpoint; the zone lookup below is the real test.
        $result.TokenStatus = 'unverified'
    }

    try {
        foreach ($candidate in Get-ZoneCandidate -Fqdn $Fqdn) {
            $zones = Invoke-CloudflareApi -Path '/zones' -Token $Token -Query @{ name = $candidate }
            if (@($zones.result).Count -gt 0) {
                $result.Zone = $candidate
                $result.ZoneId = @($zones.result)[0].id
                break
            }
        }
    }
    catch {
        $detail = $_.ErrorDetails.Message
        if (-not $detail) { $detail = $_.Exception.Message }
        $result.Message = "Cloudflare API call failed: $detail"
        return $result
    }

    if (-not $result.Zone) {
        $result.Message = "No Cloudflare zone visible to this token contains $Fqdn. The token needs Zone:Read and DNS:Edit on that zone."
    }
    elseif ($result.TokenStatus -notin 'active', 'unverified') {
        $result.Message = "Token status is '$($result.TokenStatus)'."
    }
    else {
        $result.Valid = $true
        $result.Message = "Token can see zone $($result.Zone)."
    }
    $result
}
