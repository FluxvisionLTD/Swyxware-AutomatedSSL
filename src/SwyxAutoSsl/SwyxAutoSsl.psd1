@{
    RootModule           = 'SwyxAutoSsl.psm1'
    ModuleVersion        = '0.1.1'
    GUID                 = '3f0c8d0e-6a3e-4c1b-9d52-7b1e2f4a9c61'
    Author               = 'SwyxAutoSsl contributors'
    Description          = "Unattended Let's Encrypt certificates for SwyxWare: Cloudflare DNS-01 validation via Posh-ACME, installed through the Swyx Connectivity Setup Tool CLI."
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Install-SwyxAutoSsl'
        'Invoke-SwyxAutoSsl'
        'Get-SwyxAutoSslStatus'
        'Set-SwyxAutoSslCloudflareToken'
        'Test-SwyxAutoSslCloudflareToken'
        'Uninstall-SwyxAutoSsl'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags = @('Swyx', 'SwyxWare', 'LetsEncrypt', 'ACME', 'Cloudflare', 'Certificate', 'Windows')
        }
    }
}
