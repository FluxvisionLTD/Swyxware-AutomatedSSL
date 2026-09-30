# SwyxAutoSsl: unattended Let's Encrypt certificates for SwyxWare, validated through Cloudflare DNS
# and installed with the Swyx Connectivity Setup Tool command line (Scst.Cli.exe).

$script:EventSource = 'SwyxAutoSsl'
$script:PoshAcmeMinimumVersion = [version]'4.34.0'

foreach ($folder in 'Private', 'Public') {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1') {
        . $file.FullName
    }
}
