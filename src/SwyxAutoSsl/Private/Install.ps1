function Install-ModuleFile {
    # Copy this module to the machine-wide module path so it can be imported by name (remoting, unattended runs).
    $module = $MyInvocation.MyCommand.Module
    $target = Join-Path $env:ProgramFiles ('WindowsPowerShell\Modules\SwyxAutoSsl\{0}' -f $module.Version)
    $source = [System.IO.Path]::GetFullPath($module.ModuleBase).TrimEnd('\')
    if ($source -ieq [System.IO.Path]::GetFullPath($target).TrimEnd('\')) { return }
    if (-not (Test-Path -LiteralPath $target)) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
    Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force
    Write-RunLog "Module installed to $target."
}
