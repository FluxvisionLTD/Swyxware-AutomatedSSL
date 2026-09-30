@{
    RootModule           = 'SwyxAutoSsl.psm1'
    ModuleVersion        = '0.2.0'
    GUID                 = '3f0c8d0e-6a3e-4c1b-9d52-7b1e2f4a9c61'
    Author               = 'FluxVision'
    CompanyName          = 'FluxVision (https://fluxvision.co.uk)'
    Copyright            = '(c) 2026 FluxVision Ltd. MIT License.'
    Description          = "Free tool by FluxVision (https://fluxvision.co.uk). Unattended Let's Encrypt certificates for SwyxWare 14 and later: Cloudflare DNS-01 validation via Posh-ACME, installed through the Swyx Connectivity Setup Tool CLI."
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
            Tags       = @('Swyx', 'SwyxWare', 'LetsEncrypt', 'ACME', 'Cloudflare', 'Certificate', 'Windows')
            ProjectUri = 'https://github.com/FluxvisionLTD/Swyxware-AutomatedSSL'
            LicenseUri = 'https://github.com/FluxvisionLTD/Swyxware-AutomatedSSL/blob/main/LICENSE'
        }
    }
}
