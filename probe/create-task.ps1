# Linknesis Probe — create the logon scheduled task and start it.
param(
    [Parameter(Mandatory=$true)] [string]$CoreAddress,
    [Parameter(Mandatory=$true)] [string]$ProbeHash
)
$ErrorActionPreference = 'Stop'

$exe = Join-Path $PSScriptRoot 'linknesis-probe.exe'
$argLine = "--core $CoreAddress --hash $ProbeHash"
# $env:USERDOMAIN is not reliable here: outside a genuine interactive logon
# session (e.g. invoked non-interactively, or in some elevated/UAC contexts)
# it can resolve to "WORKGROUP" instead of the machine's own name, and
# Register-ScheduledTask then fails outright ("No mapping between account
# names and security IDs was done") because "WORKGROUP\user" isn't a
# resolvable account. WindowsIdentity.Name always returns the correctly
# qualified "MACHINE\user" (or "DOMAIN\user"), matching what the legacy
# install-windows.ps1 already does for the same task-principal purpose.
$userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$action = New-ScheduledTaskAction -Execute $exe -Argument $argLine -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
$principal = New-ScheduledTaskPrincipal `
    -UserId $userId `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName 'LinknesisProbe' `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Force

Start-ScheduledTask -TaskName 'LinknesisProbe'
