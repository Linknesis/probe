# Linknesis Probe -- create/remove (and verify) the inbound Windows Firewall
# rules TCP/UDP MTR depends on.
#
# probe/src/mtr.zig's runWindowsMtrTcp/Udp[6] detect intermediate hops and
# the target via a raw IP capture socket (SIO_RCVALL) that only ever sees
# anything if these four rules exist -- without them every hop silently
# times out at the per-hop budget instead of erroring, so a broken/missing
# rule needs to be visible at install time rather than only ever showing up
# as "MTR is oddly slow" much later. A rule can go missing even on an
# already-working install: an in-place upgrade from Windows 10 to Windows 11
# resets custom inbound rules.
#
# Default (no -Remove) mode: creates and verifies each rule. Exit code 0 if
# every rule exists (or was created and verified) by the end of the run, 1
# if any rule could not be created/verified.
#
# -Remove mode (used by install-windows.nsi's Uninstall section): removes
# and verifies each rule is actually gone. Exit code 0 if every rule is
# confirmed absent by the end of the run, 1 otherwise -- the uninstaller's
# previous plain `Remove-NetFirewallRule -ErrorAction SilentlyContinue`
# calls (with no verification at all) left all four rules behind on a real
# uninstall+reboot: the rules were still
# present and still allowing ICMP Time Exceeded/Destination Unreachable in
# even after the probe was fully uninstalled.
#
# Neither mode ever throws -- a firewall-rule failure should not abort the
# rest of the install/uninstall.
param(
    [switch]$Remove
)

function Ensure-IcmpFirewallRule($displayName, $icmpType, $protocol) {
    $existing = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Output "[OK] Firewall rule already exists: $displayName"
        return $true
    }

    try {
        New-NetFirewallRule `
            -DisplayName $displayName `
            -Direction Inbound `
            -Protocol $protocol `
            -IcmpType $icmpType `
            -Action Allow `
            -Profile Any `
            -ErrorAction Stop | Out-Null
    } catch {
        Write-Output "[FAIL] Could not create firewall rule '$displayName': $($_.Exception.Message)"
        return $false
    }

    # Don't just trust that New-NetFirewallRule didn't throw -- verify the
    # rule actually landed in the policy store.
    $verify = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue
    if (-not $verify) {
        Write-Output "[FAIL] Firewall rule '$displayName' did not verify after creation"
        return $false
    }
    Write-Output "[OK] Created firewall rule: $displayName"
    return $true
}

function Remove-IcmpFirewallRule($displayName) {
    $existing = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Output "[OK] Firewall rule already absent: $displayName"
        return $true
    }

    try {
        # -DisplayName can match more than one rule (Windows Firewall does
        # not enforce DisplayName uniqueness) -- remove every match, not
        # just the first, or a duplicate left behind by an earlier
        # install/self-heal run would make this look like it worked while
        # a rule of the same name silently keeps allowing the traffic.
        Get-NetFirewallRule -DisplayName $displayName -ErrorAction Stop | Remove-NetFirewallRule -ErrorAction Stop
    } catch {
        Write-Output "[FAIL] Could not remove firewall rule '$displayName': $($_.Exception.Message)"
        return $false
    }

    $verify = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue
    if ($verify) {
        Write-Output "[FAIL] Firewall rule '$displayName' still present after removal"
        return $false
    }
    Write-Output "[OK] Removed firewall rule: $displayName"
    return $true
}

$rules = @(
    @{ Name = "Linknesis Allow ICMPv4 Time Exceeded"; Type = 11; Proto = "ICMPv4" },
    @{ Name = "Linknesis Allow ICMPv4 Destination Unreachable"; Type = 3; Proto = "ICMPv4" },
    @{ Name = "Linknesis Allow ICMPv6 Time Exceeded"; Type = 3; Proto = "ICMPv6" },
    @{ Name = "Linknesis Allow ICMPv6 Destination Unreachable"; Type = 1; Proto = "ICMPv6" }
)

$allOk = $true
foreach ($rule in $rules) {
    if ($Remove) {
        $allOk = (Remove-IcmpFirewallRule $rule.Name) -and $allOk
    } else {
        $allOk = (Ensure-IcmpFirewallRule $rule.Name $rule.Type $rule.Proto) -and $allOk
    }
}

if (-not $allOk) {
    if ($Remove) {
        Write-Output "[WARN] One or more MTR firewall rules could not be removed/verified absent."
        Write-Output "[WARN] Remove them manually via Windows Defender Firewall with Advanced Security"
        Write-Output "[WARN] (inbound rules named 'Linknesis Allow ICMPv4/ICMPv6 ...') if desired."
    } else {
        Write-Output "[WARN] One or more MTR firewall rules could not be created/verified."
        Write-Output "[WARN] TCP/UDP MTR will still run, but every hop before the target will"
        Write-Output "[WARN] time out (~5s each) instead of resolving normally. Re-run this"
        Write-Output "[WARN] installer as Administrator, or check Windows Defender Firewall."
    }
    exit 1
}

exit 0
