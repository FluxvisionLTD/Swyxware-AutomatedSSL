# SwyxAutoSsl

**A free tool by [FluxVision](https://fluxvision.co.uk), the call management platform for SwyxWare.**

Unattended Let's Encrypt certificates for **SwyxWare 14 and later** (including SwyxWare 15) servers that use their own
domain name.

SwyxAutoSsl is free for anyone to use. Install it on as many SwyxWare servers as you need.

The Swyx Connectivity Setup Tool (SCST) can only obtain Let's Encrypt certificates for SwyxON DNS names. With your own
FQDN it expects you to supply a PFX by hand, and to do it again before every expiry. SwyxAutoSsl automates that:

1. Requests a certificate from Let's Encrypt with [Posh-ACME](https://poshac.me), proving domain ownership with a
   Cloudflare DNS record (DNS-01, so no inbound port 80 is needed).
2. Installs it into SwyxWare with SCST's own command line, `Scst.Cli.exe`, which binds it to every SwyxWare service
   (ConfigDataStore 9100/9101, Management API 9201, Swyx Control Center 9443, e-mail service, global phonebook) and
   re-provisions phones.
3. Repeats daily from a scheduled task, running as SYSTEM (which the installation registers as a SwyxWare
   administrator) or as an account you choose. It only renews when Let's Encrypt says renewal is due, and only touches
   SwyxWare when the certificate actually changed.

After the one-time installation nothing needs a person, unless the Cloudflare token is revoked, the task account's
password changes (only when you use `-TaskCredential`), or a SwyxWare or Let's Encrypt change breaks something. All of
these show up as event ID 1100 in the Windows Application log.

> Not affiliated with, endorsed or supported by Enreach or Swyx. Use at your own risk.

## Requirements

- SwyxWare 14 or later, including SwyxWare 15, with the Swyx Connectivity Setup Tool
  (`C:\Program Files\Swyx\SwyxWare\SCST\Scst.Cli.exe`). Developed against SwyxWare 14.26; SCST must have been run once
  (the SwyxWare configuration wizard completed).
- Windows PowerShell 5.1 (Windows Server 2016 or later). Run the installation as an account that is both a local
  Administrator and a SwyxWare administrator.
- A public DNS name for the server (for example `swyx01.example.com`) in a zone hosted on Cloudflare, resolving to
  the server as SwyxWare clients and phones need it.
- Outbound HTTPS from the server to `acme-v02.api.letsencrypt.org` and `api.cloudflare.com`, and to the PowerShell
  Gallery during installation (to install Posh-ACME).

## Create the Cloudflare API token

In the Cloudflare dashboard: **My Profile → API Tokens → Create Token**, start from the **Edit zone DNS** template.

| Setting          | Value                                                              |
|------------------|--------------------------------------------------------------------|
| Permissions      | Zone → DNS → Edit, and Zone → Zone → Read                          |
| Zone Resources   | Include → Specific zone → the zone containing your server name    |
| Client IP filter | Recommended: the public IP addresses of your SwyxWare servers      |
| TTL              | Leave empty. An expiring token silently stops renewals; rotate it instead. |

One token can serve several servers when their names are in the same zone.

## Install on a server

Copy the `src\SwyxAutoSsl` folder to the server and open an **elevated** Windows PowerShell as an account that is a
local Administrator **and** a SwyxWare administrator (needed to register the scheduled task's account with SwyxWare).
Then run:

```powershell
Import-Module .\SwyxAutoSsl\SwyxAutoSsl.psd1
Install-SwyxAutoSsl -Fqdn swyx01.example.com -ContactEmail it@example.com -Staging -RunNow
```

You are prompted for the Cloudflare token (hidden input); it is validated before it is stored. `-Staging` uses the
Let's Encrypt test environment, whose certificates are never installed into SwyxWare, so this checks the whole chain
safely. After a few minutes:

```powershell
Get-SwyxAutoSslStatus
```

`LastResult : Success` with a `CertificateThumbprint` means Cloudflare and Let's Encrypt work. Then switch to
production (the stored token and the task time are kept):

```powershell
Install-SwyxAutoSsl -Fqdn swyx01.example.com -ContactEmail it@example.com -RunNow
```

This replaces the certificate SwyxWare currently uses, so do it in a maintenance window. If SCST is not yet in manual
mode for this name (for example a SwyxON DNS name or a different FQDN), the first run switches it with
`Scst.Cli.exe configure manual`, the command-line equivalent of the SCST wizard.

`Install-SwyxAutoSsl` also:

- installs Posh-ACME for all users if needed and copies this module to `C:\Program Files\WindowsPowerShell\Modules`;
- registers the `SwyxAutoSsl` event log source;
- adds SYSTEM as a SwyxWare administrator, unless it already is one or you use `-TaskCredential` (see below);
- registers the daily scheduled task `\SwyxAutoSsl\Renew certificate` (random time between 01:00 and 05:59, or
  `-DailyAt HH:mm`).

It is safe to re-run to change settings; the stored token, task time and task account are kept.

### Which account runs the scheduled task

`Scst.Cli.exe` only works for an account that is a local Administrator **and** a SwyxWare administrator. Choose one:

- **SYSTEM (default).** SYSTEM is not a SwyxWare administrator on a default installation, so `Install-SwyxAutoSsl`
  adds `NT AUTHORITY\SYSTEM` to the SwyxWare administrators (profile `IpPbxAdministrator`) using your own SwyxWare
  admin rights. It is skipped if SYSTEM is already listed, and removed again by `Uninstall-SwyxAutoSsl` if
  SwyxAutoSsl added it. No password is stored anywhere.
- **A named account.** Pass `-TaskCredential (Get-Credential)` with an account that is already a local Administrator
  and a SwyxWare administrator; SwyxWare's administrator list is then left alone. Task Scheduler stores the password,
  so re-run `Install-SwyxAutoSsl -TaskCredential ...` whenever that password changes, otherwise runs fail. Use
  `-RunAsSystem` to switch back to SYSTEM later.

```powershell
Install-SwyxAutoSsl -Fqdn swyx01.example.com -ContactEmail it@example.com -TaskCredential (Get-Credential EXAMPLE\svc-swyx)
```

### Install parameters

| Parameter                | Purpose                                                                     |
|--------------------------|-----------------------------------------------------------------------------|
| `-Fqdn`                  | Public name of this SwyxWare server.                                        |
| `-ContactEmail`          | Contact address for the Let's Encrypt account.                              |
| `-CloudflareToken`       | Token as a SecureString; prompted for when none is stored yet.              |
| `-Staging`               | Use Let's Encrypt staging; nothing is installed into SwyxWare.              |
| `-RunNow`                | Start the scheduled task immediately instead of at the next daily run.      |
| `-DailyAt`               | Time of the daily run, `HH:mm`.                                             |
| `-CertKeyLength`         | `2048` (default, best phone compatibility), `3072`, `4096`, `ec-256`, `ec-384`. |
| `-TaskCredential`        | Run the task as this account instead of SYSTEM (see above).                 |
| `-RunAsSystem`           | Switch a task installed with `-TaskCredential` back to SYSTEM.              |
| `-SkipScheduledTask`     | Configure only; runs happen when you call `Invoke-SwyxAutoSsl`.             |
| `-SkipDependencyInstall` | Do not install Posh-ACME from the PowerShell Gallery.                       |

## Day-to-day

| Command | What it does |
|---------|--------------|
| `Get-SwyxAutoSslStatus` | Configuration, last run result and error, current certificate, what SCST has installed, task state and next run. |
| `Start-ScheduledTask -TaskPath '\SwyxAutoSsl\' -TaskName 'Renew certificate'` | Run now, exactly as the unattended run does (as the task's account). |
| `Invoke-SwyxAutoSsl` | Run in the current session. `-ForceRenew` requests a new certificate now, `-ForceInstall` re-installs the current one into SCST, `-SkipScstInstall` only obtains the certificate. |
| `Test-SwyxAutoSslCloudflareToken` | Checks that the stored (or a given) token can see the server's zone. |
| `Set-SwyxAutoSslCloudflareToken` | Replaces the stored token after validating it. |
| `Uninstall-SwyxAutoSsl` | Removes the scheduled task, and SYSTEM's SwyxWare administrator entry if SwyxAutoSsl added it. `-RemoveData` also deletes all stored data. SwyxWare keeps its current certificate. |

### Rotating the Cloudflare token

On one server:

```powershell
Set-SwyxAutoSslCloudflareToken
```

On several servers at once, over PowerShell remoting (each server validates the token against its own FQDN):

```powershell
Set-SwyxAutoSslCloudflareToken -ComputerName swyx01, swyx02, swyx03
```

The next run uses the new token; nothing else needs to change.

### Updating SwyxAutoSsl

Copy the new `SwyxAutoSsl` folder to the server, open a **new** elevated PowerShell window (as a local and SwyxWare
administrator), then:

```powershell
Import-Module .\SwyxAutoSsl\SwyxAutoSsl.psd1 -Force
Install-SwyxAutoSsl -Fqdn swyx01.example.com -ContactEmail it@example.com
```

The new version is installed next to the old one and the scheduled task loads the newest. When updating from 0.1.x,
this also adds SYSTEM as a SwyxWare administrator if it is not one yet. If `Import-Module` complains about unsigned
files, run `Get-ChildItem .\SwyxAutoSsl -Recurse | Unblock-File` first.

## Monitoring

Let's Encrypt no longer e-mails expiry warnings, so watch the Windows **Application** log, source **SwyxAutoSsl**:

| Event ID | Level       | Meaning                                                                    |
|----------|-------------|----------------------------------------------------------------------------|
| 1000     | Information | Run finished; the installed certificate is still current.                  |
| 1001     | Information | A new certificate was installed into SwyxWare.                             |
| 1002     | Warning     | Certificate obtained but not installed (staging or `-SkipScstInstall`).     |
| 1100     | Error       | Run failed. `Get-SwyxAutoSslStatus` shows the error; see the logs.          |
| 1200     | Information | The Cloudflare token was changed.                                           |
| 1300     | Information | SwyxWare administrator rights were granted to, or removed from, SYSTEM.     |

Alert on **1100**. Renewals start well before expiry and a failed run is retried the next day, so a single failure is
not urgent, but repeated ones are.

## Files

Everything lives in `C:\ProgramData\SwyxAutoSsl`, readable only by SYSTEM and local Administrators:

| Path | Content |
|------|---------|
| `config.json` | Settings, including the task account and whether SwyxAutoSsl added SYSTEM as a SwyxWare administrator (no secrets). |
| `state.json` | Last run, result, error and certificate thumbprints (no secrets). |
| `cloudflare.token` | The Cloudflare token, encrypted with DPAPI (machine scope). |
| `logs\SwyxAutoSsl-YYYY-MM.log` | Summary log, including everything `Scst.Cli.exe` prints. |
| `logs\run-*.log` | Full transcript of each run. Logs older than 90 days are deleted. |
| `posh-acme\` | Posh-ACME's ACME account, orders and certificates (including private keys). |

SCST's own traces are in `C:\ProgramData\Swyx\Traces\scst.cli-*.log`.

## Security

- **Cloudflare token.** Entered at a hidden prompt (or passed as a SecureString), validated, then stored encrypted with
  Windows DPAPI in machine scope. The file cannot be decrypted on another machine, and the folder is limited to SYSTEM
  and local Administrators. It is never written to `config.json`, `state.json`, logs or a command line, and is
  decrypted only in memory during a run and sent only to `api.cloudflare.com`. Posh-ACME's own saved copy of the
  token (encrypted with a key kept in the same folder) is deleted at the end of every run.
- **Limit.** Any local administrator of the server, or anything running as SYSTEM, can decrypt the token. This is
  inherent in any unattended design: the scheduled task has to be able to use it. Keep the token's permissions and IP
  filter tight to limit the damage if it leaks.
- **Certificate installation.** `Scst.Cli.exe`'s `--password -` option is an interactive prompt, and a password
  argument would be visible in process-auditing logs. So no password is passed at all: SCST imports a password-less
  PFX copy written inside the protected folder and deleted immediately after installation. The private key is kept in
  memory only while creating that copy.
- **Scheduled task.** Runs as SYSTEM by default, which means SYSTEM becomes a SwyxWare administrator (see
  [Which account runs the scheduled task](#which-account-runs-the-scheduled-task)); SYSTEM is already the most
  privileged account on the server, and no password is stored. Organisations that prefer not to change the SwyxWare
  administrator list can use `-TaskCredential` instead.
- **Telemetry.** Posh-ACME's anonymous telemetry is disabled.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `TaskLastResult : 0x41303` | The task has not run yet. Start it with `Start-ScheduledTask` or use `-RunNow`. |
| Staging works but nothing changes in SwyxWare | Expected: staging certificates are never installed. Re-run `Install-SwyxAutoSsl` without `-Staging`. |
| `Cloudflare token rejected` / `No Cloudflare zone visible` | Check the token's permissions and zone; run `Test-SwyxAutoSslCloudflareToken`. |
| `Scst.Cli.exe refused ... administrator rights` | The task account is not a SwyxWare administrator. Re-run `Install-SwyxAutoSsl` (adds SYSTEM), or use `-TaskCredential` with an account that is one. |
| `LastResult : Failed` mentioning `Scst.Cli.exe` | See the `Scst.Cli:` lines in `logs\SwyxAutoSsl-YYYY-MM.log` and SCST's own trace. |
| Task stopped working after a password change | The `-TaskCredential` account's password changed; re-run `Install-SwyxAutoSsl -TaskCredential ...`. |
| Works interactively but not from the task | The task's account (SYSTEM by default) needs direct outbound HTTPS; check proxies and firewalls. |

## Development

```powershell
Invoke-Pester -Path .\tests          # Pester 5.5 or later
Invoke-ScriptAnalyzer -Path .\src -Recurse
```

The tests mock Posh-ACME, Cloudflare and `Scst.Cli.exe`, so they run on any Windows machine without SwyxWare.

## About FluxVision

SwyxAutoSsl is built and maintained by **[FluxVision](https://fluxvision.co.uk)**, the complete call management
platform for SwyxWare PBX environments. FluxVision brings AI call transcription and summaries, call recording, quality
assurance, call queues, live wallboards and reporting, and CRM integrations (HubSpot, Salesforce, Zoho) together in one
web portal, alongside custom Swyx ECR scripting and development.

We built SwyxAutoSsl to take manual certificate renewals off SwyxWare administrators' plates, and share it free of
charge with anyone running SwyxWare on their own domain.

- Website: [fluxvision.co.uk](https://fluxvision.co.uk)
- Contact: [info@fluxvision.co.uk](mailto:info@fluxvision.co.uk)
- Questions, bugs and feature requests for this tool: [GitHub Issues](https://github.com/FluxvisionLTD/Swyxware-AutomatedSSL/issues)

## License

[MIT](LICENSE), copyright FluxVision Ltd. Free for anyone to use, copy, modify and distribute, including commercially;
just keep the copyright notice and licence text with copies. Provided as is, without warranty.
