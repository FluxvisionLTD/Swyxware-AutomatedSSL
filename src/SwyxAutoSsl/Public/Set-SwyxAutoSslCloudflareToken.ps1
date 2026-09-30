function Set-SwyxAutoSslCloudflareToken {
    <#
    .SYNOPSIS
        Stores (or replaces) the Cloudflare API token used for DNS-01 validation.
    .DESCRIPTION
        The token is validated against this server's FQDN, then encrypted with DPAPI (LocalMachine scope) into the
        SwyxAutoSsl data directory, which only SYSTEM and Administrators can read. The next run uses the new token.

        With -ComputerName the same token is pushed to several servers over PowerShell remoting; each server
        validates it against its own FQDN.
    .PARAMETER Token
        Cloudflare API token with Zone:Read and DNS:Edit on the zone. Prompted for when omitted.
    .PARAMETER ComputerName
        Servers to update over PowerShell remoting (SwyxAutoSsl must be installed on them).
    .PARAMETER Credential
        Credential for the remoting connection.
    .PARAMETER SkipValidation
        Store the token without checking it against Cloudflare.
    .EXAMPLE
        Set-SwyxAutoSslCloudflareToken
    .EXAMPLE
        Set-SwyxAutoSslCloudflareToken -ComputerName swyx01, swyx02
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Local')]
    param(
        [securestring]$Token,
        [Parameter(Mandatory, ParameterSetName = 'Remote')][string[]]$ComputerName,
        [Parameter(ParameterSetName = 'Remote')][pscredential]$Credential,
        [switch]$SkipValidation
    )

    if (-not $Token) { $Token = Read-Host -Prompt 'Cloudflare API token' -AsSecureString }

    if ($PSCmdlet.ParameterSetName -eq 'Remote') {
        if (-not $PSCmdlet.ShouldProcess(($ComputerName -join ', '), 'Update Cloudflare API token')) { return }
        $invokeParams = @{
            ComputerName = $ComputerName
            ArgumentList = $Token, $SkipValidation.IsPresent
            ScriptBlock  = {
                param($RemoteToken, $Skip)
                Import-Module SwyxAutoSsl -ErrorAction Stop
                Set-SwyxAutoSslCloudflareToken -Token $RemoteToken -SkipValidation:$Skip -Confirm:$false
                [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Updated = $true }
            }
        }
        if ($Credential) { $invokeParams.Credential = $Credential }
        Invoke-Command @invokeParams
        return
    }

    Assert-Administrator
    $config = Get-Config
    if (-not $SkipValidation) {
        $test = Test-SwyxAutoSslCloudflareToken -Token $Token -Fqdn $config.Fqdn
        if (-not $test.Valid) { throw "Cloudflare token rejected for $($config.Fqdn): $($test.Message)" }
        Write-RunLog "Cloudflare token validated: zone $($test.Zone)."
    }
    if ($PSCmdlet.ShouldProcess($config.Fqdn, 'Store Cloudflare API token')) {
        Save-Secret -Value $Token -Path (Get-DataPath Token)
        Write-RunLog "Cloudflare API token updated for $($config.Fqdn)." -EventId 1200
    }
}
