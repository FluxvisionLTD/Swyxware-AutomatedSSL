function Uninstall-SwyxAutoSsl {
    <#
    .SYNOPSIS
        Removes the SwyxAutoSsl scheduled task and, optionally, all of its data.
    .DESCRIPTION
        SwyxWare keeps using the certificate that was installed last until it expires; nothing is changed in SCST.
        -RemoveData also deletes %ProgramData%\SwyxAutoSsl: configuration, Cloudflare token, the ACME account key
        and the issued certificates and keys.
    .PARAMETER RemoveData
        Delete the data directory as well.
    .EXAMPLE
        Uninstall-SwyxAutoSsl
    .EXAMPLE
        Uninstall-SwyxAutoSsl -RemoveData
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([switch]$RemoveData)

    Assert-Administrator
    if ($PSCmdlet.ShouldProcess("$($script:TaskPath)$($script:TaskName)", 'Remove scheduled task')) {
        Unregister-RenewalTask
    }
    $root = Get-DataRoot
    if ($RemoveData -and (Test-Path -LiteralPath $root) -and
        $PSCmdlet.ShouldProcess($root, 'Delete configuration, Cloudflare token, ACME account and certificates')) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
