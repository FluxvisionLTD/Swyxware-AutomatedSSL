# Scst.Cli.exe connects to the SwyxWare ConfigDataStore as the Windows identity it runs under, and that identity must be
# a SwyxWare administrator. SYSTEM is not one on a default installation, so when the scheduled task runs as SYSTEM,
# Install-SwyxAutoSsl registers it (and Uninstall-SwyxAutoSsl removes it again if we added it).

$script:SystemSid = 'S-1-5-18'
$script:SwyxAdminProfile = 'IpPbxAdministrator'

function Import-IpPbxModule {
    if (Get-Command -Name Connect-IpPbx -ErrorAction SilentlyContinue) { return }
    $candidates = @(
        'IpPbx'
        (Join-Path $env:ProgramFiles 'Swyx\SwyxWare Administration\Modules\IpPbx\IpPbx.psd1')
        (Join-Path ${env:ProgramFiles(x86)} 'Swyx\SwyxWare Administration\Modules\IpPbx\IpPbx.psd1')
    )
    foreach ($candidate in $candidates) {
        try {
            Import-Module $candidate -Global -ErrorAction Stop -Verbose:$false
            return
        }
        catch {
            Write-Verbose "IpPbx module not loaded from '$candidate': $($_.Exception.Message)"
        }
    }
    throw 'The SwyxWare IpPbx PowerShell module (SwyxWare Administration) was not found. Run this in Windows PowerShell 5.1 on the SwyxWare server.'
}

function Get-IpPbxAdminFacade {
    # Connect-IpPbx publishes the SwyxWare admin API as the global variable $AdminFacade.
    $facade = Get-Variable -Name AdminFacade -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if (-not $facade) { throw 'Not connected to SwyxWare (Connect-IpPbx did not provide $AdminFacade).' }
    $facade
}

function Get-SystemSwyxAdminEntry {
    # Requires an open IpPbx connection.
    @((Get-IpPbxAdminFacade).GetAdminUsersView()) | Where-Object { $_.SID -eq $script:SystemSid }
}

function Grant-SystemSwyxAdmin {
    # Returns $true when SYSTEM was added now, $false when it already was a SwyxWare administrator.
    Import-IpPbxModule
    Connect-IpPbx -ErrorAction Stop | Out-Null
    try {
        if (Get-SystemSwyxAdminEntry) {
            Write-RunLog 'SYSTEM is already a SwyxWare administrator.'
            return $false
        }
        $name = ([Security.Principal.SecurityIdentifier]$script:SystemSid).Translate([Security.Principal.NTAccount]).Value
        (Get-IpPbxAdminFacade).AddAdminUser($name, $script:SwyxAdminProfile) | Out-Null
        if (-not (Get-SystemSwyxAdminEntry)) {
            throw "SwyxWare did not accept '$name' as an administrator. Add it manually or install with -TaskCredential."
        }
        Write-RunLog "Registered $name as a SwyxWare administrator (profile $($script:SwyxAdminProfile)) so the scheduled task can run Scst.Cli.exe." -EventId 1300
        $true
    }
    finally {
        Disconnect-IpPbx -ErrorAction SilentlyContinue
    }
}

function Revoke-SystemSwyxAdmin {
    Import-IpPbxModule
    Connect-IpPbx -ErrorAction Stop | Out-Null
    try {
        foreach ($entry in Get-SystemSwyxAdminEntry) {
            if (-not (Get-IpPbxAdminFacade).DeleteAdminUser($entry.AdminUserID)) {
                throw "Could not remove SwyxWare administrator '$($entry.WindowsIdentitiy)'."
            }
            Write-RunLog "Removed SwyxWare administrator rights from $($entry.WindowsIdentitiy)." -EventId 1300
        }
    }
    finally {
        Disconnect-IpPbx -ErrorAction SilentlyContinue
    }
}
