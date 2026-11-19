const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform.zig");

// --- Linux: systemd's native sd_notify watchdog ---
//
// sd_notify(3): a single newline-delimited KEY=VALUE datagram sent to the
// Unix domain socket named by $NOTIFY_SOCKET. That's the entire wire
// protocol -- no libsystemd dependency needed. This replaced a hand-rolled
// heartbeat-file plus a separate polling watchdog process/systemd unit
// (`linknesis-probe-watchdog.service`, used by older versions): systemd itself (PID 1, already root) restarts the unit
// directly if WATCHDOG=1 pings stop arriving, so there is no longer any
// Linknesis-owned root-privileged process on a Linux host at all.
//
// Windows has no systemd/sd_notify equivalent, so it keeps the original
// heartbeat-file mechanism below unchanged -- this is a pre-existing,
// independent mechanism (predates the Linux rework) that an optional local
// watchdog (`scripts/probe_watchdog_windows.py`/`.ps1`, run via nssm) can
// poll; do not remove or gate it based on the Linux-side change above.

var g_notify_socket: ?[:0]const u8 = null;
var g_ping_interval_ns: u64 = 15 * std.time.ns_per_s;

// Reads $NOTIFY_SOCKET/$WATCHDOG_USEC (both set by systemd on a Type=notify
// unit with WatchdogSec= configured). Call once, early in startup, before
// spawning watchdogLoop(). A no-op -- and every function below stays a
// harmless no-op in turn -- when not launched under systemd at all (a
// manual/dev run, or the `--update` one-shot invocation, which uses
// Type=oneshot and sets neither variable).
pub fn init() void {
    if (builtin.os.tag == .windows) return;

    g_notify_socket = std.posix.getenv("NOTIFY_SOCKET");
    const usec_str = std.posix.getenv("WATCHDOG_USEC") orelse return;
    const usec = std.fmt.parseInt(u64, usec_str, 10) catch return;
    // systemd recommends pinging at roughly half the configured WatchdogSec
    // so one delayed/dropped send never causes a spurious restart.
    const interval = (usec * std.time.ns_per_us) / 2;
    if (interval > 0) g_ping_interval_ns = interval;
}

fn notify(msg: []const u8) void {
    if (builtin.os.tag == .windows) return;

    const path = g_notify_socket orelse return;
    if (path.len == 0 or path.len >= 108) return;

    const fd = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0) catch return;
    defer std.posix.close(fd);

    var addr: std.posix.sockaddr.un = .{ .path = undefined };
    @memset(&addr.path, 0);
    var addr_len: std.posix.socklen_t = @intCast(@offsetOf(std.posix.sockaddr.un, "path"));
    if (path[0] == '@') {
        // Abstract-namespace socket: sun_path[0] stays 0 (already zeroed
        // above), the name follows with no NUL terminator required.
        const name = path[1..];
        if (name.len > addr.path.len - 1) return;
        @memcpy(addr.path[1 .. 1 + name.len], name);
        addr_len += @intCast(1 + name.len);
    } else {
        @memcpy(addr.path[0..path.len], path);
        addr_len += @intCast(path.len + 1); // include the NUL terminator
    }

    _ = std.posix.sendto(fd, msg, 0, @ptrCast(&addr), addr_len) catch {};
}

// Call once startup has actually finished (runners initialized, transport
// ready) so a Type=notify unit is considered started immediately -- without
// this systemd just waits out the full TimeoutStartSec before deciding
// whether the service came up. A no-op on Windows.
pub fn ready() void {
    notify("READY=1\n");
}

// --- Windows: heartbeat-file watchdog (unchanged, pre-existing mechanism) ---

const HEARTBEAT_INTERVAL_SEC: u64 = 10;

var g_heartbeat_dir: []const u8 = "C:\\var\\lib\\linknesis\\watchdog";
var g_heartbeat_path: []const u8 = "C:\\var\\lib\\linknesis\\watchdog\\heartbeat";
var g_tick: u64 = 0;

fn ensureHeartbeatDir() void {
    std.fs.cwd().makePath(g_heartbeat_dir) catch {};
}

fn writeHeartbeat() void {
    ensureHeartbeatDir();
    var tmp_path_buf: [520]u8 = undefined;
    const tmp_path = std.fmt.bufPrint(&tmp_path_buf, "{s}.tmp", .{g_heartbeat_path}) catch return;
    const timestamp = std.time.timestamp();
    g_tick += 1;
    var buf: [256]u8 = undefined;
    const json = std.fmt.bufPrint(
        &buf,
        "{{\"timestamp\":{d},\"tick\":{d}}}",
        .{ timestamp, g_tick },
    ) catch return;

    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return;
    defer file.close();
    _ = file.writeAll(json) catch return;
    std.fs.cwd().rename(tmp_path, g_heartbeat_path) catch {};
}

// Runs for the life of the process on its own detached thread.
// Linux: pings systemd's watchdog socket (sd_notify above), a no-op if the
// probe wasn't launched under systemd (Type=notify/WatchdogSec=) at all.
// Windows: writes the heartbeat file an optional local watchdog script can
// poll (see the module doc comment above).
pub fn watchdogLoop() void {
    if (builtin.os.tag == .windows) {
        while (platform.isRunning()) {
            writeHeartbeat();
            std.Thread.sleep(HEARTBEAT_INTERVAL_SEC * std.time.ns_per_s);
        }
        return;
    }

    if (g_notify_socket == null) return;
    while (platform.isRunning()) {
        notify("WATCHDOG=1\n");
        std.Thread.sleep(g_ping_interval_ns);
    }
}
