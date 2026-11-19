//! DSCP marking for iperf3 on Windows via a policy-based QoS rule.
//!
//! iperf3's `--dscp` sets IP_TOS on its sockets, which Windows silently
//! ignores for ordinary applications: the packets leave unmarked (TOS 0x00)
//! while the test still "succeeds" (verified with pktmon). The supported way to mark traffic is a QoS policy, so for
//! each client-mode iperf3 run with a DSCP value the runner adds a policy in
//! the non-persistent ActiveStore (gone on reboot) and removes it when the run
//! ends. Stale policies left by a crash are removed at probe startup.
//!
//! Matching: application `iperf3.exe` + destination port. The ActiveStore
//! ignores `-IPDstPrefixMatchCondition` (a policy for 1.2.3.4/32 still marked
//! traffic to another IP in the live test), but it does honour the port. Two
//! concurrent DSCP tests from one Windows probe to the same port would share
//! one marking; the Core already gives each inter-probe test its own port.
//!
//! Server mode (a Windows probe receiving a reverse test) is not covered: the
//! DSCP value is only known to the iperf3 client, which forwards it to the
//! server during setup. Windows probes are normally behind NAT and rarely the
//! server.

const std = @import("std");
const builtin = @import("builtin");

pub const policy_prefix = "Linknesis iperf3 ";

/// Parses a DSCP value the way iperf3's `--dscp` does: a number (decimal,
/// 0x-hex, or 0-prefixed octal, as with strtol base 0) or a symbolic name
/// (AF11..AF43, CS0..CS7, EF, VA, LE), case-insensitive. Returns null for
/// anything else or anything out of the 0-63 range.
pub fn parseDscp(raw: []const u8) ?u6 {
    const s = std.mem.trim(u8, raw, " \t");
    if (s.len == 0) return null;
    if (std.ascii.isDigit(s[0])) {
        const v: u64 = blk: {
            if (s.len > 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X'))
                break :blk std.fmt.parseInt(u64, s[2..], 16) catch return null;
            if (s.len > 1 and s[0] == '0')
                break :blk std.fmt.parseInt(u64, s[1..], 8) catch return null;
            break :blk std.fmt.parseInt(u64, s, 10) catch return null;
        };
        if (v > 63) return null;
        return @intCast(v);
    }
    var buf: [4]u8 = undefined;
    if (s.len > buf.len) return null;
    const n = std.ascii.lowerString(&buf, s);
    if (std.mem.eql(u8, n, "ef")) return 46;
    if (std.mem.eql(u8, n, "va")) return 44;
    if (std.mem.eql(u8, n, "le")) return 1;
    if (n.len == 3 and n[0] == 'c' and n[1] == 's' and n[2] >= '0' and n[2] <= '7')
        return @intCast(@as(u8, n[2] - '0') * 8);
    if (n.len == 4 and n[0] == 'a' and n[1] == 'f' and n[2] >= '1' and n[2] <= '4' and n[3] >= '1' and n[3] <= '3')
        return @intCast(@as(u8, n[2] - '0') * 8 + @as(u8, n[3] - '0') * 2);
    return null;
}

/// Writes a policy name safe to embed in a single-quoted PowerShell string:
/// the prefix plus the test id with anything outside [A-Za-z0-9_-] dropped.
fn policyName(buf: []u8, test_id: []const u8) []const u8 {
    var len: usize = 0;
    for (policy_prefix) |c| {
        buf[len] = c;
        len += 1;
    }
    for (test_id) |c| {
        if (len >= buf.len) break;
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') {
            buf[len] = c;
            len += 1;
        }
    }
    return buf[0..len];
}

/// Runs a PowerShell script hidden and returns true when it printed a line
/// equal to "OK". Logs stdout/stderr otherwise.
fn runPowerShell(pa: std.mem.Allocator, what: []const u8, script: []const u8) bool {
    var child = std.process.Child.init(
        &[_][]const u8{ "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script },
        pa,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (builtin.os.tag == .windows) child.create_no_window = true;
    child.spawn() catch |err| {
        std.log.err("DSCP QoS policy {s}: failed to spawn powershell.exe: {any}", .{ what, err });
        return false;
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(pa);
    var err_out: std.ArrayList(u8) = .empty;
    defer err_out.deinit(pa);
    child.collectOutput(pa, &out, &err_out, 64 * 1024) catch |err| {
        std.log.err("DSCP QoS policy {s}: failed to read powershell.exe output: {any}", .{ what, err });
        _ = child.kill() catch {};
        return false;
    };
    _ = child.wait() catch {};
    var lines = std.mem.splitScalar(u8, out.items, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r"), "OK")) return true;
    }
    std.log.err("DSCP QoS policy {s} failed: {s} {s}", .{ what, std.mem.trim(u8, out.items, " \r\n"), std.mem.trim(u8, err_out.items, " \r\n") });
    return false;
}

/// Adds the per-test policy. Returns true when it was created; on false the
/// test still runs, just unmarked.
pub fn addPolicy(pa: std.mem.Allocator, test_id: []const u8, port: u16, dscp: u6) bool {
    if (builtin.os.tag != .windows) return false;
    var name_buf: [128]u8 = undefined;
    const name = policyName(&name_buf, test_id);
    const script = std.fmt.allocPrint(pa,
        \\$ErrorActionPreference = 'Stop'
        \\try {{
        \\  Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq '{s}' }} | Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false
        \\  New-NetQosPolicy -Name '{s}' -AppPathNameMatchCondition 'iperf3.exe' -IPDstPortMatchCondition {d} -DSCPAction {d} -NetworkProfile All -PolicyStore ActiveStore | Out-Null
        \\  Write-Output 'OK'
        \\}} catch {{ Write-Output "ERR: $($_.Exception.Message)" }}
    , .{ name, name, port, dscp }) catch return false;
    defer pa.free(script);
    const ok = runPowerShell(pa, "add", script);
    if (ok) std.log.info("DSCP QoS policy added: '{s}' port={d} dscp={d}", .{ name, port, dscp });
    return ok;
}

pub fn removePolicy(pa: std.mem.Allocator, test_id: []const u8) void {
    if (builtin.os.tag != .windows) return;
    var name_buf: [128]u8 = undefined;
    const name = policyName(&name_buf, test_id);
    const script = std.fmt.allocPrint(pa,
        \\Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq '{s}' }} | Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false
        \\Write-Output 'OK'
    , .{name}) catch return;
    defer pa.free(script);
    if (runPowerShell(pa, "remove", script)) std.log.info("DSCP QoS policy removed: '{s}'", .{name});
}

/// Startup cleanup for policies a crashed or killed probe never removed.
/// Meant for a detached thread (powershell.exe cold start can take seconds).
pub fn removeStalePolicies() void {
    if (builtin.os.tag != .windows) return;
    _ = runPowerShell(std.heap.page_allocator, "startup cleanup",
        \\Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Linknesis iperf3 *' } | Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false
        \\Write-Output 'OK'
    );
}

test "parseDscp numbers and names" {
    const t = std.testing;
    try t.expectEqual(@as(?u6, 46), parseDscp("46"));
    try t.expectEqual(@as(?u6, 0), parseDscp("0"));
    try t.expectEqual(@as(?u6, 46), parseDscp("0x2e"));
    try t.expectEqual(@as(?u6, 46), parseDscp("056"));
    try t.expectEqual(@as(?u6, 46), parseDscp("EF"));
    try t.expectEqual(@as(?u6, 46), parseDscp(" ef "));
    try t.expectEqual(@as(?u6, 10), parseDscp("AF11"));
    try t.expectEqual(@as(?u6, 38), parseDscp("af43"));
    try t.expectEqual(@as(?u6, 56), parseDscp("CS7"));
    try t.expectEqual(@as(?u6, 0), parseDscp("cs0"));
    try t.expectEqual(@as(?u6, 44), parseDscp("VA"));
    try t.expectEqual(@as(?u6, 1), parseDscp("LE"));
    try t.expectEqual(@as(?u6, null), parseDscp("64"));
    try t.expectEqual(@as(?u6, null), parseDscp("AF44"));
    try t.expectEqual(@as(?u6, null), parseDscp("CS8"));
    try t.expectEqual(@as(?u6, null), parseDscp("bogus"));
    try t.expectEqual(@as(?u6, null), parseDscp(""));
    try t.expectEqual(@as(?u6, null), parseDscp("09"));
}

test "policyName strips unsafe characters" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("Linknesis iperf3 mwkmsvr7", policyName(&buf, "mwkmsvr7"));
    try std.testing.expectEqualStrings("Linknesis iperf3 ab_c-1x", policyName(&buf, "ab'_c-1;x"));
}
