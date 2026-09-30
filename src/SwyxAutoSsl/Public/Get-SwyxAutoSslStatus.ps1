function Get-SwyxAutoSslStatus {
    <#
    .SYNOPSIS
        Shows the SwyxAutoSsl configuration, last run result and the certificate SwyxWare is using.
    .EXAMPLE
        Get-SwyxAutoSslStatus
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    Assert-Administrator
    $config = Get-Config
    $state = Get-State
    $tokenFile = Get-Item -LiteralPath (Get-DataPath Token) -ErrorAction SilentlyContinue
    $task = Get-RenewalTask
    $taskInfo = $null
    if ($task) { $taskInfo = $task | Get-ScheduledTaskInfo }

    [pscustomobject][ordered]@{
        Fqdn                   = $config.Fqdn
        AcmeServer             = $config.AcmeServer
        ContactEmail           = $config.ContactEmail
        CloudflareTokenStored  = [bool]$tokenFile
        CloudflareTokenChanged = $(if ($tokenFile) { $tokenFile.LastWriteTime })
        CertificateThumbprint  = $state.CertificateThumbprint
        CertificateExpires     = $state.CertificateExpires
        ScstFqdn               = Get-ScstFqdn
        ScstThumbprint         = Get-ScstInstalledThumbprint
        LastRun                = $state.LastRun
        LastResult             = $state.LastResult
        LastError              = $state.LastError
        ScheduledTask          = $(if ($task) { [string]$task.State } else { 'Not registered' })
        TaskLastResult         = $(if ($taskInfo) { '0x{0:X}' -f $taskInfo.LastTaskResult })
        TaskNextRun            = $(if ($taskInfo) { $taskInfo.NextRunTime })
        DataDirectory          = Get-DataRoot
    }
}
