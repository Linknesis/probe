const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const wss_client = @import("wss_client.zig");
const windows_qos = @import("windows_qos.zig");

const win = std.os.windows;

var g_allocator: std.mem.Allocator = undefined;
var g_mutex: std.Thread.Mutex = .{};
const ProcessHandle = if (builtin.os.tag == .windows) win.HANDLE else i32;
const ActiveProcess = struct {
    handle: ProcessHandle,
    generation: u64,
};
var g_active_pids: std.StringHashMap(ActiveProcess) = undefined;
var g_stopped_tests: std.StringHashMap(u64) = undefined;
var g_generations: std.StringHashMap(u64) = undefined;

pub fn init(allocator: std.mem.Allocator) void {
    g_allocator = allocator;
    g_active_pids = std.StringHashMap(ActiveProcess).init(allocator);
    g_stopped_tests = std.StringHashMap(u64).init(allocator);
    g_generations = std.StringHashMap(u64).init(allocator);
}

pub fn appendActiveTestIds(out: *std.ArrayList(u8), first: *bool) !void {
    g_mutex.lock();
    defer g_mutex.unlock();
    var it = g_active_pids.iterator();
    while (it.next()) |entry| {
        if (!first.*) try out.append(g_allocator, ',');
        first.* = false;
        try out.writer(g_allocator).print("\"{s}\"", .{entry.key_ptr.*});
    }
}

// ---------------------------------------------------------------------------
// Server readiness detection
// ---------------------------------------------------------------------------

fn isProcessAlive(handle: ProcessHandle) bool {
    if (builtin.os.tag == .windows) {
        var code: u32 = 0;
        const rc = std.os.windows.kernel32.GetExitCodeProcess(handle, &code);
        return rc != 0 and code == 259; // STILL_ACTIVE
    } else {
        std.posix.kill(handle, 0) catch return false;
        return true;
    }
}

fn isPortListening(port: u16, ipv6: bool) bool {
    if (builtin.os.tag == .windows) {
        return isPortListeningWindows(port, ipv6);
    } else {
        return isPortListeningLinux(port, ipv6);
    }
}

fn isPortListeningLinux(port: u16, ipv6: bool) bool {
    const pa = std.heap.page_allocator;
    const paths: []const []const u8 = if (ipv6)
        &[_][]const u8{"/proc/net/tcp6"}
    else
        &[_][]const u8{ "/proc/net/tcp", "/proc/net/tcp6" };

    var port_hex_buf: [5]u8 = undefined;
    const port_hex = std.fmt.bufPrint(&port_hex_buf, "{X:0>4}", .{port}) catch return false;

    for (paths) |path| {
        const content = std.fs.cwd().readFileAlloc(pa, path, 128 * 1024) catch continue;
        defer pa.free(content);

        var lines = std.mem.splitScalar(u8, content, '\n');
        _ = lines.next(); // skip header line

        while (lines.next()) |line| {
            if (line.len < 20) continue;

            // Format: "  sl: local_address remote_address st tx_queue:rx_queue ..."
            var it = std.mem.splitAny(u8, std.mem.trimLeft(u8, line, " \t"), " \t");
            _ = it.next(); // sl
            const local_addr = it.next() orelse continue;
            _ = it.next(); // remote_addr
            const state = it.next() orelse continue;

            // State 0A = TCP_LISTEN
            if (!std.mem.eql(u8, state, "0A")) continue;

            const colon_idx = std.mem.lastIndexOfScalar(u8, local_addr, ':');
            if (colon_idx == null) continue;
            const port_str = local_addr[colon_idx.? + 1 ..];
            if (port_str.len < 4) continue;

            // Compare case-insensitively since /proc/net/tcp uses lowercase
            var matches = true;
            for (port_hex, 0..) |c, i| {
                const pc = port_str[i];
                if (pc != c and pc != (c | 32)) {
                    matches = false;
                    break;
                }
            }
            if (matches) return true;
        }
    }
    return false;
}

const TCP_TABLE_BASIC_LISTENER: u32 = 0;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

const MIB_TCPROW = extern struct {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
};

const MIB_TCPTABLE = extern struct {
    dwNumEntries: u32,
    table: [1]MIB_TCPROW,
};

const MIB_TCP6ROW = extern struct {
    State: u32,
    ucLocalAddr: [16]u8,
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    ucRemoteAddr: [16]u8,
    dwRemoteScopeId: u32,
    dwRemotePort: u32,
};

const MIB_TCP6TABLE = extern struct {
    dwNumEntries: u32,
    table: [1]MIB_TCP6ROW,
};

extern "iphlpapi" fn GetExtendedTcpTable(
    pTcpTable: ?*anyopaque,
    pdwSize: *u32,
    bOrder: win.BOOL,
    ulAf: u32,
    TableClass: u32,
    Reserved: u32,
) callconv(.winapi) u32;

fn isPortListeningWindows(port: u16, ipv6: bool) bool {
    const pa = std.heap.page_allocator;
    const af = if (ipv6) AF_INET6 else AF_INET;

    var size: u32 = 16 * 1024;
    const table_buf = pa.alloc(u8, size) catch return false;
    defer pa.free(table_buf);

    const rc = GetExtendedTcpTable(table_buf.ptr, &size, 0, af, TCP_TABLE_BASIC_LISTENER, 0);
    if (rc != 0) return false;

    if (ipv6) {
        const table = @as(*MIB_TCP6TABLE, @ptrCast(@alignCast(table_buf.ptr)));
        const n = table.dwNumEntries;
        if (n == 0) return false;
        const rows = @as([*]MIB_TCP6ROW, @ptrCast(&table.table[0]));
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const row = &rows[i];
            if (row.dwLocalPort == std.mem.nativeToBig(u16, port)) {
                return true;
            }
        }
    } else {
        const table = @as(*MIB_TCPTABLE, @ptrCast(@alignCast(table_buf.ptr)));
        const n = table.dwNumEntries;
        if (n == 0) return false;
        const rows = @as([*]MIB_TCPROW, @ptrCast(&table.table[0]));
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const row = &rows[i];
            if (row.dwLocalPort == std.mem.nativeToBig(u16, port)) {
                return true;
            }
        }
    }
    return false;
}

const ServerReadyContext = struct {
    mutex: std.Thread.Mutex = .{},
    ready_sent: bool = false,
    error_sent: bool = false,
};

fn sendServerReadyIfNeeded(ctx: *ServerReadyContext, test_id: []const u8) void {
    ctx.mutex.lock();
    if (ctx.ready_sent or ctx.error_sent) {
        ctx.mutex.unlock();
        return;
    }
    ctx.ready_sent = true;
    ctx.mutex.unlock();
    sendServerReady(test_id);
}

fn sendServerErrorIfNeeded(ctx: *ServerReadyContext, test_id: []const u8, reason: []const u8) void {
    ctx.mutex.lock();
    if (ctx.ready_sent or ctx.error_sent) {
        ctx.mutex.unlock();
        return;
    }
    ctx.error_sent = true;
    ctx.mutex.unlock();
    sendServerError(test_id, reason);
}

/// Sends a server_error using whatever stderr text has been captured so far
/// (the real cause, when available), falling back to `default_reason` when
/// nothing has been captured yet -- e.g. a genuine network-level bind
/// failure never writes anything to stderr, so the generic message is still
/// the best available description in that case.
fn sendServerErrorWithReason(ctx: *ServerReadyContext, test_id: []const u8, stderr_capture: *StderrCapture, default_reason: []const u8) void {
    if (stderrReasonCopy(g_allocator, stderr_capture)) |r| {
        defer g_allocator.free(r);
        sendServerErrorIfNeeded(ctx, test_id, r);
    } else {
        sendServerErrorIfNeeded(ctx, test_id, default_reason);
    }
}

fn serverReadyWatcher(ctx: *ServerReadyContext, test_id: []const u8, server_port: u16, ipv6: bool, handle: ProcessHandle, stderr_capture: *StderrCapture) void {
    const test_id_copy = g_allocator.dupe(u8, test_id) catch return;
    defer g_allocator.free(test_id_copy);

    const max_wait_ms: u32 = 15000;
    const poll_interval_ms: u32 = 100;
    var waited_ms: u32 = 0;

    while (waited_ms < max_wait_ms) {
        if (!isProcessAlive(handle)) {
            sendServerErrorWithReason(ctx, test_id_copy, stderr_capture, "server process died before listening");
            return;
        }

        if (isPortListening(server_port, ipv6)) {
            // Give iperf3 a moment to move from "socket bound" to actually accepting
            // connections before telling the core the server is ready.
            std.Thread.sleep(300 * std.time.ns_per_ms);
            if (isProcessAlive(handle)) {
                sendServerReadyIfNeeded(ctx, test_id_copy);
            } else {
                sendServerErrorWithReason(ctx, test_id_copy, stderr_capture, "server process died before listening");
            }
            return;
        }

        std.Thread.sleep(poll_interval_ms * std.time.ns_per_ms);
        waited_ms += poll_interval_ms;
    }

    sendServerErrorWithReason(ctx, test_id_copy, stderr_capture, "server failed to bind port within timeout");
}

const StderrCaptureMaxBytes: usize = 4096;

/// Accumulates a bounded prefix of a child process's stderr on a background
/// thread, so it's available to whichever caller needs a real failure reason
/// once the process is gone. iperf3's own stderr is otherwise invisible: the
/// probe's only other source of detail is a JSON {"event":"error",...} line
/// on stdout, and iperf3 never emits one when it fails before getting that
/// far -- e.g. rejecting one of our own CLI flags (a version/build mismatch,
/// like RHEL9-family's default iperf3 package predating --json-stream/
/// --idle-timeout) prints plain usage text and exits,
/// with nothing parseable on stdout at all. See probe/iperf3-linux-static/
/// for the fix that made this scenario obsolete on a freshly-installed
/// probe, but a probe that only auto-updated its binary (not reinstalled)
/// can still be running a stale system iperf3 -- this capture is the
/// generic, protocol-agnostic fallback for that and any other CLI-level
/// failure.
const StderrCapture = struct {
    mutex: std.Thread.Mutex = .{},
    data: ?[]u8 = null,
};

fn readStderrCapped(stderr_file: std.fs.File, capture: *StderrCapture, allocator: std.mem.Allocator) void {
    var buf: [StderrCaptureMaxBytes]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = stderr_file.read(buf[total..]) catch break;
        if (n == 0) break;
        total += n;
        // Publish progressively (not just once at EOF) so a concurrent
        // reader -- the server-readiness watcher, which may decide to send
        // an error before this process has fully exited -- can see it too.
        if (allocator.dupe(u8, buf[0..total])) |copy| {
            capture.mutex.lock();
            const old = capture.data;
            capture.data = copy;
            capture.mutex.unlock();
            if (old) |o| allocator.free(o);
        } else |_| {}
    }
    // Drain (and discard) anything past the cap so the child can never block
    // on a full stderr pipe just because we stopped keeping it.
    var discard: [1024]u8 = undefined;
    while (true) {
        const n = stderr_file.read(&discard) catch break;
        if (n == 0) break;
    }
}

fn firstNonEmptyLine(s: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, s, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) return trimmed;
    }
    return s;
}

/// Copies out whatever stderr has been captured so far, trimmed to its first
/// non-empty line -- iperf3's own CLI errors (unsupported flag, etc.) always
/// put the actual complaint on the first line even when a full --help usage
/// dump follows it. Returns null if nothing has been captured yet.
fn stderrReasonCopy(allocator: std.mem.Allocator, capture: *StderrCapture) ?[]u8 {
    capture.mutex.lock();
    defer capture.mutex.unlock();
    const data = capture.data orelse return null;
    return allocator.dupe(u8, firstNonEmptyLine(data)) catch null;
}

fn isEarlyServerError(line: []const u8) bool {
    // iperf3 --json-stream emits {"event":"error",...} on bind failures etc.
    return std.mem.containsAtLeast(u8, line, 1, "\"event\":\"error\"") or
        std.mem.containsAtLeast(u8, line, 1, "\"event\": \"error\"");
}

/// Pulls the human-readable message out of an iperf3 --json-stream error line,
/// e.g. {"event":"error","data":"interrupt - the server has terminated"} ->
/// "interrupt - the server has terminated". Falls back to duping the raw line
/// if the shape doesn't match what's expected (still more useful than a fixed
/// generic string). Returns null only on allocation failure.
fn extractIperf3ErrorReason(allocator: std.mem.Allocator, line: []const u8) ?[]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch {
        return allocator.dupe(u8, line) catch null;
    };
    defer parsed.deinit();
    if (parsed.value == .object) {
        if (parsed.value.object.get("data")) |data| {
            if (data == .string) {
                return allocator.dupe(u8, data.string) catch null;
            }
        }
    }
    return allocator.dupe(u8, line) catch null;
}

/// Resolves the bundled iperf3 binary's absolute path, next to the running
/// probe executable -- mirroring the Windows probe's long-standing pattern
/// (`iperf3.exe` bundled by the installer alongside the probe binary) rather
/// than a bare "iperf3"/PATH lookup. This is what makes the probe immune to
/// the host distro's own iperf3 packaging policy: RHEL9-family distros
/// (RHEL 9, CentOS Stream 9, Rocky 9, Alma 9) ship a default-repo iperf3
/// permanently pinned at real upstream 3.9 (Red Hat only backports CVE
/// fixes, never bumps the feature version) -- too old for the --json-stream/
/// --idle-timeout flags this runner always passes, so every iperf3 test on
/// such a host used to fail immediately with a CLI-parse error, in either
/// role. See probe/iperf3-linux-static/README.md for
/// the statically-linked replacement `scripts/install_probe.sh` now
/// downloads into the same directory as the probe binary.
/// A probe that only auto-updated its *binary* (never reinstalled via
/// `install_probe.sh`) never had the bundled iperf3 placed next to it --
/// self-update only replaces the probe executable, it can't create a new
/// companion asset. Falling back unconditionally to the bundled path would
/// regress such a probe from "works" (its old system iperf3) to a hard
/// FileNotFound on every test, the moment it picks up this binary via normal
/// auto-update. Only trust the bundled path when it actually exists;
/// otherwise fall back to a bare "iperf3"/PATH lookup, i.e. exactly the
/// pre-fix behavior. Same "a mechanism fix needs a reinstall to take effect"
/// limitation as the api_port-learning fix --
/// only a fresh install_probe.sh run downloads the bundled binary itself.
fn resolveIperf3Path(allocator: std.mem.Allocator) ?[]u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.fs.selfExeDirPath(&dir_buf)) |self_dir| {
        const bin_name = if (builtin.os.tag == .windows) "iperf3.exe" else "iperf3";
        if (std.fs.path.join(allocator, &.{ self_dir, bin_name })) |bundled_path| {
            if (std.fs.cwd().access(bundled_path, .{})) {
                return bundled_path;
            } else |_| {
                allocator.free(bundled_path);
            }
        } else |_| {}
    } else |_| {}
    return allocator.dupe(u8, "iperf3") catch null;
}

pub fn run(test_id: []const u8, target: []const u8, duration: i64, reverse: bool, bidir: bool, parallel: i64, bandwidth: ?[]const u8, dscp: ?[]const u8, zerocopy: bool, server_mode: bool, server_port: u16, protocol: ?[]const u8, client_port: ?u16, interval: i64, omit: i64, report_to_test_id: ?[]const u8, skip_test_results: bool, ipv6: bool) void {
    std.log.info("iperf3_runner.run start test_id={s} target={s} duration={d} omit={d} server={} report_to={?s} skip={} ipv6={}", .{ test_id, target, duration, omit, server_mode, report_to_test_id, skip_test_results, ipv6 });
    const pa = std.heap.page_allocator;
    // This runner owns the page_allocator copies handed to it by
    // wss_client.handleMessage (they were duped specifically so this detached
    // thread has stable memory). Free them when the run finishes; the active/
    // generation maps keep their own duped keys, so freeing test_id here is safe.
    defer {
        pa.free(test_id);
        pa.free(target);
        if (bandwidth) |b| pa.free(b);
        if (dscp) |d| pa.free(d);
        if (protocol) |p| pa.free(p);
        if (report_to_test_id) |r| pa.free(r);
    }

    // Build argv
    var argv = std.ArrayList([]const u8){};
    defer argv.deinit(pa);
    // allocPrint'd argv entries are heap-owned: track and free them on exit.
    // With page_allocator each tiny string pins a whole page, so leaking them
    // (the previous behavior) OOMed high-churn probes running many tests.
    var owned_args = std.ArrayList([]const u8){};
    defer {
        for (owned_args.items) |a| pa.free(a);
        owned_args.deinit(pa);
    }
    const iperf3_path = resolveIperf3Path(pa) orelse {
        std.log.err("iperf3_runner: could not resolve bundled iperf3 path for test_id={s}", .{test_id});
        sendTestError(test_id, "iperf3 binary not found");
        return;
    };
    owned_args.append(pa, iperf3_path) catch {
        pa.free(iperf3_path);
        return;
    };
    argv.append(pa, iperf3_path) catch return;

    // Destination port of a client-mode run, for the Windows DSCP policy.
    var client_dst_port: u16 = 5201;

    if (server_mode) {
        argv.append(pa, "-s") catch return;
        if (ipv6) argv.append(pa, "-6") catch return;
        const effective_port = if (client_port) |cp| cp else server_port;
        if (effective_port > 0) {
            argv.append(pa, "-p") catch return;
            const arg = std.fmt.allocPrint(pa, "{d}", .{effective_port}) catch return;
            owned_args.append(pa, arg) catch {
                pa.free(arg);
                return;
            };
            argv.append(pa, arg) catch return;
        }
        argv.append(pa, "-1") catch return; // one-off server
        argv.append(pa, "--idle-timeout") catch return;
        argv.append(pa, "30") catch return;
        argv.append(pa, "--json-stream") catch return;
        argv.append(pa, "--forceflush") catch return;
        // The server is the one that actually reports results to the Core
        // for standard UDP tests (only the receiver observes jitter/loss)
        // and for reverse-mode tests of either protocol (see
        // test_orchestrator.zig's server_reports_to_client comment) -- in
        // both cases the client-side -i below never applies, so without this
        // the server always fell back to iperf3's own 1s default regardless
        // of the user's chosen interval.
        if (interval > 0) {
            argv.append(pa, "-i") catch return;
            const arg = std.fmt.allocPrint(pa, "{d}", .{interval}) catch return;
            owned_args.append(pa, arg) catch {
                pa.free(arg);
                return;
            };
            argv.append(pa, arg) catch return;
        }
    } else {
        if (ipv6) argv.append(pa, "-6") catch return;
        argv.append(pa, "-c") catch return;
        // Split target into host and optional port (e.g. 1.2.3.4:5201 or [2001:db8::1]:5201)
        var host: []const u8 = target;
        var port_from_target: ?[]const u8 = null;
        if (std.mem.startsWith(u8, target, "[")) {
            const bracket_end = std.mem.indexOf(u8, target, "]");
            if (bracket_end) |end| {
                host = target[1..end];
                if (end + 1 < target.len and target[end + 1] == ':') {
                    port_from_target = target[end + 2 ..];
                }
            }
        } else {
            // A bare (unbracketed) IPv6 literal like "2001:db8::1" contains
            // multiple colons that are part of the address itself, not a
            // port separator -- splitting at the *first* one (as if it were
            // "host:port") produced garbage like host="2001" port="db8::1".
            // A hostname or IPv4 address can only ever contain at most one
            // colon (the port separator), so only split when there's
            // exactly one; a multi-colon target with no brackets is treated
            // as the whole string being the host, with no port (matching
            // the convention that specifying a port alongside an IPv6
            // literal requires brackets).
            if (std.mem.count(u8, target, ":") == 1) {
                const host_port_sep = std.mem.indexOf(u8, target, ":").?;
                host = target[0..host_port_sep];
                port_from_target = target[host_port_sep + 1 ..];
            }
        }
        argv.append(pa, host) catch return;

        if (client_port) |cp| {
            client_dst_port = cp;
        } else if (port_from_target) |pt| {
            client_dst_port = std.fmt.parseInt(u16, pt, 10) catch 5201;
        }

        // Use explicit client_port if provided, otherwise port from target string
        if (client_port) |cp| {
            argv.append(pa, "-p") catch return;
            const arg = std.fmt.allocPrint(pa, "{d}", .{cp}) catch return;
            owned_args.append(pa, arg) catch {
                pa.free(arg);
                return;
            };
            argv.append(pa, arg) catch return;
        } else if (port_from_target) |pt| {
            argv.append(pa, "-p") catch return;
            argv.append(pa, pt) catch return;
        }

        argv.append(pa, "--json-stream") catch return;
        argv.append(pa, "--forceflush") catch return;
        argv.append(pa, "--connect-timeout") catch return;
        argv.append(pa, "5000") catch return;
        if (omit > 0) {
            argv.append(pa, "--omit") catch return;
            const omit_arg = std.fmt.allocPrint(pa, "{d}", .{omit}) catch return;
            owned_args.append(pa, omit_arg) catch {
                pa.free(omit_arg);
                return;
            };
            argv.append(pa, omit_arg) catch return;
        }

        if (interval > 0) {
            argv.append(pa, "-i") catch return;
            const arg = std.fmt.allocPrint(pa, "{d}", .{interval}) catch return;
            owned_args.append(pa, arg) catch {
                pa.free(arg);
                return;
            };
            argv.append(pa, arg) catch return;
        }

        if (duration >= 0) {
            argv.append(pa, "-t") catch return;
            const arg = std.fmt.allocPrint(pa, "{d}", .{duration}) catch return;
            owned_args.append(pa, arg) catch {
                pa.free(arg);
                return;
            };
            argv.append(pa, arg) catch return;
        }
        if (reverse) argv.append(pa, "--reverse") catch return;
        if (bidir) argv.append(pa, "--bidir") catch return;
        if (parallel > 1) {
            argv.append(pa, "-P") catch return;
            const arg = std.fmt.allocPrint(pa, "{d}", .{parallel}) catch return;
            owned_args.append(pa, arg) catch {
                pa.free(arg);
                return;
            };
            argv.append(pa, arg) catch return;
        }
        if (bandwidth) |b| {
            argv.append(pa, "-b") catch return;
            // User enters bandwidth in mbit/s; append "M" if no K/M/G suffix present
            const hasSuffix = b.len > 0 and (std.ascii.toLower(b[b.len - 1]) == 'k' or
                std.ascii.toLower(b[b.len - 1]) == 'm' or
                std.ascii.toLower(b[b.len - 1]) == 'g');
            if (hasSuffix) {
                argv.append(pa, b) catch return;
            } else {
                const bw_arg = std.fmt.allocPrint(pa, "{s}M", .{b}) catch return;
                owned_args.append(pa, bw_arg) catch {
                    pa.free(bw_arg);
                    return;
                };
                argv.append(pa, bw_arg) catch return;
            }
        }
        if (dscp) |d| {
            argv.append(pa, "--dscp") catch return;
            argv.append(pa, d) catch return;
        }
        if (zerocopy) argv.append(pa, "--zerocopy") catch return;
        if (protocol) |pr| {
            if (std.mem.eql(u8, pr, "udp")) {
                argv.append(pa, "-u") catch return;
            }
        }
    }

    // Log exact command line
    var cmd_buf: [4096]u8 = undefined;
    var cmd_len: usize = 0;
    for (argv.items, 0..) |arg, i| {
        if (i > 0) {
            if (cmd_len + 1 < cmd_buf.len) {
                cmd_buf[cmd_len] = ' ';
                cmd_len += 1;
            }
        }
        if (cmd_len + arg.len <= cmd_buf.len) {
            @memcpy(cmd_buf[cmd_len .. cmd_len + arg.len], arg);
            cmd_len += arg.len;
        }
    }
    std.log.info("iperf3 cmdline: {s}", .{cmd_buf[0..cmd_len]});

    // Windows ignores the IP_TOS iperf3 sets for --dscp, so mark the
    // traffic with a temporary QoS policy instead (see windows_qos.zig).
    var qos_added = false;
    if (builtin.os.tag == .windows and !server_mode) {
        if (dscp) |d| {
            if (windows_qos.parseDscp(d)) |v| {
                qos_added = windows_qos.addPolicy(pa, test_id, client_dst_port, v);
                if (!qos_added) std.log.warn("DSCP {s} could not be applied on Windows for test_id={s}; traffic will be unmarked", .{ d, test_id });
            } else {
                std.log.warn("DSCP value '{s}' not recognized for the Windows QoS policy (test_id={s}); traffic will be unmarked", .{ d, test_id });
            }
        }
    }
    defer if (qos_added) windows_qos.removePolicy(pa, test_id);

    const effective_port = if (client_port) |cp| cp else server_port;
    runProcess(pa, test_id, argv, server_mode, effective_port, ipv6, report_to_test_id, skip_test_results);
}

fn nextGenerationLocked(test_id: []const u8) u64 {
    // g_generations owns its keys (duped on first insert) and the entry is
    // removed by removeActiveIfGenerationLocked when the run ends, so the map
    // no longer grows without bound (previously it stored the caller's slice
    // as the key and never removed it, leaking one key per unique test_id).
    if (g_generations.getEntry(test_id)) |e| {
        e.value_ptr.* += 1;
        return e.value_ptr.*;
    }
    const key = g_allocator.dupe(u8, test_id) catch return 1;
    g_generations.put(key, 1) catch {
        g_allocator.free(key);
    };
    return 1;
}

fn takeStoppedFlagLocked(test_id: []const u8, generation: u64) bool {
    const entry = g_stopped_tests.getEntry(test_id);
    if (entry == null) return false;
    if (entry.?.value_ptr.* != generation) return false;
    // Remove the entry before freeing its key: remove() re-probes the table
    // and runs eql() against the stored key, so freeing it first is a
    // use-after-free that either segfaults here or, when the compare
    // mismatches on recycled memory, leaves a dangling key in the map that
    // crashes the next put() in stop(). This took down all six test probes
    // simultaneously under a stop_test burst.
    const key = entry.?.key_ptr.*;
    _ = g_stopped_tests.remove(test_id);
    g_allocator.free(key);
    return true;
}

fn removeActiveIfGenerationLocked(test_id: []const u8, generation: u64) void {
    if (g_active_pids.getEntry(test_id)) |entry| {
        if (entry.value_ptr.generation == generation) {
            const key = entry.key_ptr.*;
            _ = g_active_pids.remove(test_id);
            g_allocator.free(key);
        }
    }
    // Drop our generation entry unless a newer run of the same test_id has
    // already bumped it (stop -> restart overlap), so g_generations stays bounded.
    if (g_generations.getEntry(test_id)) |gentry| {
        if (gentry.value_ptr.* == generation) {
            const gkey = gentry.key_ptr.*;
            _ = g_generations.remove(test_id);
            g_allocator.free(gkey);
        }
    }
}

fn runProcess(pa: std.mem.Allocator, test_id: []const u8, argv: std.ArrayList([]const u8), server_mode: bool, effective_port: u16, ipv6: bool, report_to_test_id: ?[]const u8, skip_test_results: bool) void {
    var child = std.process.Child.init(argv.items, pa);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (@import("builtin").os.tag == .windows) {
        child.create_no_window = true;
    }

    child.spawn() catch |err| {
        std.log.err("iperf3 spawn error: {any}", .{err});
        if (std.fmt.allocPrint(pa, "spawn failed: {any}", .{err})) |reason| {
            defer pa.free(reason);
            sendTestError(test_id, reason);
        } else |_| {
            sendTestError(test_id, "spawn failed");
        }
        return;
    };

    const handle = child.id;

    g_mutex.lock();
    const generation = nextGenerationLocked(test_id);
    // g_active_pids owns its key too, freed by removeActiveIfGenerationLocked
    // or stop(); the caller's test_id slice is freed by run()'s defer.
    if (g_allocator.dupe(u8, test_id)) |key| {
        g_active_pids.put(key, .{ .handle = handle, .generation = generation }) catch {
            g_allocator.free(key);
        };
    } else |_| {}
    g_mutex.unlock();

    // Captured on a background thread for the life of the child; both the
    // server-readiness watcher and the post-exit reason selection below
    // consult it. Its stderr pipe closes (EOF) at process exit regardless of
    // whether wait() has been called yet, so joining stderr_thread below
    // never races child.wait()'s later reap.
    var stderr_capture: StderrCapture = .{};
    defer if (stderr_capture.data) |d| pa.free(d);
    const stderr_thread = std.Thread.spawn(.{}, readStderrCapped, .{ child.stderr.?, &stderr_capture, pa }) catch null;

    var ready_ctx: ServerReadyContext = .{};
    var watcher_thread: ?std.Thread = null;
    if (server_mode) {
        // Spawn a watcher that waits until the iperf3 process has actually
        // bound the requested port before signalling readiness to the Core.
        watcher_thread = std.Thread.spawn(.{}, serverReadyWatcher, .{
            &ready_ctx,
            test_id,
            effective_port,
            ipv6,
            handle,
            &stderr_capture,
        }) catch null;
        if (watcher_thread == null) {
            std.log.err("Failed to spawn server readiness watcher for {s}", .{test_id});
        }
    }

    // Remembers the most recent iperf3-reported error line's human-readable
    // text (e.g. "interrupt - the server has terminated"), so that if the
    // process later exits non-zero, sendTestError() can report *why* instead
    // of the fixed "iperf3 exited with error" string. This is the preferred
    // source when present (iperf3's own structured error event); stderr_capture
    // above is the fallback for a failure that never got far enough to emit
    // one (e.g. iperf3 rejecting one of our own CLI flags).
    var last_error_reason: ?[]u8 = null;
    defer if (last_error_reason) |r| pa.free(r);

    const stdout = child.stdout.?;
    var buf: [1024]u8 = undefined;
    // A fixed-size line buffer used to truncate (silently, byte-for-byte)
    // any JSON-stream line past its length -- bidir "end" summaries (two
    // full stream objects plus six sum variants) and any interval with
    // several parallel (-P) streams routinely exceed a couple KB, so a
    // fixed cap here corrupts the JSON and the line gets dropped ("Failed
    // to parse iperf3 line as JSON") instead of delivered. Grow instead.
    var line_buf = std.ArrayList(u8){};
    defer line_buf.deinit(pa);
    line_buf.ensureTotalCapacity(pa, 2048) catch {};
    read_loop: while (true) {
        const n = stdout.read(&buf) catch break;
        if (n == 0) break;
        for (buf[0..n]) |byte| {
            if (byte == '\n') {
                if (line_buf.items.len > 0) {
                    const line = line_buf.items;
                    std.log.info("iperf3 line: {s}", .{line});
                    if (isEarlyServerError(line)) {
                        const extracted = extractIperf3ErrorReason(pa, line);
                        if (server_mode) {
                            // Report iperf3's own message (e.g. "unable to start
                            // listener for connections: Address in use") so the
                            // Core can tell the user why the server failed.
                            sendServerErrorIfNeeded(&ready_ctx, test_id, extracted orelse "iperf3 server reported an error");
                        }
                        if (extracted) |ex| {
                            if (last_error_reason) |old| pa.free(old);
                            last_error_reason = ex;
                        }
                    }
                    if (config.get().uuid == null) break :read_loop;
                    if (!skip_test_results) {
                        sendTestResult(test_id, line, report_to_test_id);
                    }
                }
                line_buf.clearRetainingCapacity();
            } else {
                line_buf.append(pa, byte) catch {};
            }
        }
    }

    // Ensure the readiness watcher has finished before ready_ctx goes out of scope.
    if (watcher_thread) |t| t.join();
    // stderr closes at process exit regardless of when wait() reaps it, so
    // this returns promptly rather than racing child.wait() below.
    if (stderr_thread) |t| t.join();

    const term = child.wait() catch |err| {
        std.log.err("iperf3 wait error: {any}", .{err});
        g_mutex.lock();
        removeActiveIfGenerationLocked(test_id, generation);
        const was_stopped = takeStoppedFlagLocked(test_id, generation);
        g_mutex.unlock();
        if (!was_stopped) {
            ready_ctx.mutex.lock();
            const server_error_already_sent = ready_ctx.error_sent;
            ready_ctx.mutex.unlock();
            if (!server_error_already_sent) {
                if (std.fmt.allocPrint(pa, "wait failed: {any}", .{err})) |reason| {
                    defer pa.free(reason);
                    sendTestError(test_id, reason);
                } else |_| {
                    sendTestError(test_id, "wait failed");
                }
            }
        }
        return;
    };

    g_mutex.lock();
    removeActiveIfGenerationLocked(test_id, generation);
    const was_stopped = takeStoppedFlagLocked(test_id, generation);
    g_mutex.unlock();

    if (was_stopped) {
        // A stop->restart for the same test_id kills this run and immediately
        // starts a newer one; telling the Core "test_complete" now would tear
        // down the live replacement run. Complete only when no newer
        // generation of this test_id is registered.
        g_mutex.lock();
        const newer_exists = if (g_generations.getEntry(test_id)) |ge| ge.value_ptr.* != generation else false;
        g_mutex.unlock();
        if (!newer_exists) sendTestComplete(test_id);
        return;
    }

    var failed = false;
    switch (term) {
        .Exited => |code| {
            if (code != 0) failed = true;
        },
        else => failed = true,
    }

    if (config.get().uuid == null) return;

    // If the server-start phase already signalled an error, don't overwrite it
    // with a generic process-exit error.
    ready_ctx.mutex.lock();
    const server_error_already_sent = ready_ctx.error_sent;
    ready_ctx.mutex.unlock();

    if (failed) {
        if (server_mode and server_error_already_sent) {
            std.log.info("iperf3 server process exited after server_error was already reported for {s}", .{test_id});
        } else if (last_error_reason) |r| {
            sendTestError(test_id, r);
        } else if (stderrReasonCopy(pa, &stderr_capture)) |se| {
            // No JSON error event was ever seen on stdout -- iperf3 failed
            // before getting that far (e.g. it rejected one of our own CLI
            // flags and printed plain usage text instead). stderr is the
            // only place the real cause is visible in that case.
            defer pa.free(se);
            sendTestError(test_id, se);
        } else {
            const fallback = switch (term) {
                .Exited => |code| std.fmt.allocPrint(pa, "iperf3 exited with code {d}", .{code}) catch null,
                .Signal => |sig| std.fmt.allocPrint(pa, "iperf3 killed by signal {d}", .{sig}) catch null,
                else => null,
            };
            if (fallback) |f| {
                defer pa.free(f);
                sendTestError(test_id, f);
            } else {
                sendTestError(test_id, "iperf3 exited with error");
            }
        }
    } else {
        sendTestComplete(test_id);
    }
}

fn putString(root: *std.json.ObjectMap, key: []const u8, value: []const u8) void {
    const k = g_allocator.dupe(u8, key) catch return;
    const v = g_allocator.dupe(u8, value) catch {
        g_allocator.free(k);
        return;
    };
    root.put(k, .{ .string = v }) catch {
        g_allocator.free(k);
        g_allocator.free(v);
    };
}

fn sendJsonValue(value: std.json.Value) void {
    var list = std.ArrayList(u8){};
    defer list.deinit(g_allocator);
    list.print(g_allocator, "{f}", .{std.json.fmt(value, .{})}) catch {
        std.log.err("Failed to stringify message", .{});
        return;
    };
    const msg = list.toOwnedSlice(g_allocator) catch {
        std.log.err("Failed to allocate message", .{});
        return;
    };
    defer g_allocator.free(msg);
    wss_client.sendJson(msg);
}

fn freeRoot(root: *std.json.ObjectMap) void {
    var it = root.iterator();
    while (it.next()) |entry| {
        g_allocator.free(entry.key_ptr.*);
        switch (entry.value_ptr.*) {
            .string => |s| g_allocator.free(s),
            else => {},
        }
    }
    root.deinit();
}

fn sendTestResult(test_id: []const u8, line: []const u8, report_to_test_id: ?[]const u8) void {
    const effective_test_id = report_to_test_id orelse test_id;
    const data_parsed = std.json.parseFromSlice(std.json.Value, g_allocator, line, .{}) catch {
        std.log.err("Failed to parse iperf3 line as JSON", .{});
        return;
    };
    defer data_parsed.deinit();
    var root = std.json.ObjectMap.init(g_allocator);
    defer freeRoot(&root);
    putString(&root, "type", "test_result");
    putString(&root, "test_id", effective_test_id);
    putString(&root, "probe_uuid", config.get().uuid.?);
    const data_key = g_allocator.dupe(u8, "data") catch return;
    // iperf3 --json-stream emits one JSON object per line; anything else
    // (e.g. a bare JSON string from a malformed stream) must not be stored:
    // freeRoot() would free that value's bytes, which alias `line` or the
    // parse arena, not g_allocator memory -- an invalid free.
    if (data_parsed.value != .object) {
        g_allocator.free(data_key);
        std.log.err("Ignoring non-object iperf3 JSON line", .{});
        return;
    }
    root.put(data_key, data_parsed.value) catch {
        g_allocator.free(data_key);
        return;
    };
    std.log.info("Sending test_result", .{});
    sendJsonValue(.{ .object = root });
}

fn sendTestComplete(test_id: []const u8) void {
    var root = std.json.ObjectMap.init(g_allocator);
    defer freeRoot(&root);
    putString(&root, "type", "test_complete");
    putString(&root, "test_id", test_id);
    std.log.info("Sending test_complete", .{});
    sendJsonValue(.{ .object = root });
}

fn sendTestError(test_id: []const u8, reason: []const u8) void {
    var root = std.json.ObjectMap.init(g_allocator);
    defer freeRoot(&root);
    putString(&root, "type", "test_error");
    putString(&root, "test_id", test_id);
    putString(&root, "probe_uuid", config.get().uuid.?);
    putString(&root, "error", reason);
    std.log.info("Sending test_error", .{});
    sendJsonValue(.{ .object = root });
}

fn sendServerReady(test_id: []const u8) void {
    var root = std.json.ObjectMap.init(g_allocator);
    defer freeRoot(&root);
    putString(&root, "type", "server_ready");
    putString(&root, "test_id", test_id);
    std.log.info("Sending server_ready", .{});
    sendJsonValue(.{ .object = root });
}

fn sendServerError(test_id: []const u8, reason: []const u8) void {
    var root = std.json.ObjectMap.init(g_allocator);
    defer freeRoot(&root);
    putString(&root, "type", "server_error");
    putString(&root, "test_id", test_id);
    putString(&root, "error", reason);
    std.log.info("Sending server_error", .{});
    sendJsonValue(.{ .object = root });
}

/// Used when the replacement run for a stopped test can't be spawned:
/// stopForRestart's generation pre-bump suppresses the killed run's own
/// test_complete, so the Core must be told explicitly or the test hangs.
pub fn completeNow(test_id: []const u8) void {
    sendTestComplete(test_id);
}

pub fn stop(test_id: []const u8) void {
    stopInternal(test_id, false);
}

/// stop() + an atomic pre-bump of the generation counter under g_mutex, used
/// by the stop->restart path (handleMessage spawning a new run of the same
/// test_id). Guarantees the killed run's completion always observes that a
/// newer generation exists -- even if the replacement thread hasn't
/// registered yet -- so its stale test_complete is suppressed.
pub fn stopForRestart(test_id: []const u8) void {
    stopInternal(test_id, true);
}

fn stopInternal(test_id: []const u8, restarting: bool) void {
    g_mutex.lock();
    if (restarting) _ = nextGenerationLocked(test_id);
    const entry = g_active_pids.getEntry(test_id);
    if (entry) |e| {
        const handle = e.value_ptr.handle;
        const generation = e.value_ptr.generation;
        const active_key = e.key_ptr.*;
        _ = g_active_pids.remove(test_id);
        g_allocator.free(active_key);
        const key = g_allocator.dupe(u8, test_id) catch {
            g_mutex.unlock();
            return;
        };
        g_stopped_tests.put(key, generation) catch {
            g_allocator.free(key);
            g_mutex.unlock();
            return;
        };
        g_mutex.unlock();
        if (@import("builtin").os.tag == .windows) {
            _ = std.os.windows.kernel32.TerminateProcess(handle, 1);
        } else {
            std.posix.kill(handle, std.posix.SIG.TERM) catch {};
        }
    } else {
        g_mutex.unlock();
    }
}

pub fn stopAll() void {
    g_mutex.lock();
    var handles = std.ArrayList(ProcessHandle){};
    defer handles.deinit(g_allocator);
    var it = g_active_pids.iterator();
    while (it.next()) |entry| {
        handles.append(g_allocator, entry.value_ptr.handle) catch {};
    }
    g_mutex.unlock();

    for (handles.items) |handle| {
        if (@import("builtin").os.tag == .windows) {
            _ = std.os.windows.kernel32.TerminateProcess(handle, 1);
        } else {
            std.posix.kill(handle, std.posix.SIG.TERM) catch {};
        }
    }
}

const testing = std.testing;

test "firstNonEmptyLine: skips leading blank lines and trims whitespace" {
    try testing.expectEqualStrings(
        "usage: iperf3 [-s|-c host] [options]",
        firstNonEmptyLine("\n\n  usage: iperf3 [-s|-c host] [options]  \nmore text"),
    );
    try testing.expectEqualStrings("hello", firstNonEmptyLine("hello\nworld"));
}

test "firstNonEmptyLine: falls back to the original slice when every line is blank" {
    const blank = "\n\n  \n";
    try testing.expectEqualStrings(blank, firstNonEmptyLine(blank));
    try testing.expectEqualStrings("", firstNonEmptyLine(""));
}

test "isEarlyServerError: matches iperf3's --json-stream error event with or without a space after the colon" {
    try testing.expect(isEarlyServerError("{\"event\":\"error\",\"data\":\"unable to bind port\"}"));
    try testing.expect(isEarlyServerError("{\"event\": \"error\", \"data\": \"unable to bind port\"}"));
    try testing.expect(!isEarlyServerError("{\"event\":\"start\"}"));
    try testing.expect(!isEarlyServerError(""));
}

test "extractIperf3ErrorReason: pulls the human-readable message out of a well-formed error event" {
    const allocator = testing.allocator;
    const reason = extractIperf3ErrorReason(
        allocator,
        "{\"event\":\"error\",\"data\":\"unable to connect to server: Connection refused\"}",
    ).?;
    defer allocator.free(reason);
    try testing.expectEqualStrings("unable to connect to server: Connection refused", reason);
}

test "extractIperf3ErrorReason: falls back to the raw line when the shape doesn't match" {
    const allocator = testing.allocator;

    // Valid JSON object, but no "data" key at all.
    {
        const line = "{\"event\":\"error\"}";
        const reason = extractIperf3ErrorReason(allocator, line).?;
        defer allocator.free(reason);
        try testing.expectEqualStrings(line, reason);
    }

    // "data" present but not a string.
    {
        const line = "{\"event\":\"error\",\"data\":5}";
        const reason = extractIperf3ErrorReason(allocator, line).?;
        defer allocator.free(reason);
        try testing.expectEqualStrings(line, reason);
    }

    // Not valid JSON at all -- e.g. iperf3's own plain-text usage/error output.
    {
        const line = "iperf3: error: unrecognized option '--bogus-flag'";
        const reason = extractIperf3ErrorReason(allocator, line).?;
        defer allocator.free(reason);
        try testing.expectEqualStrings(line, reason);
    }

    // Valid JSON, but not an object (e.g. a bare JSON string).
    {
        const line = "\"just a string\"";
        const reason = extractIperf3ErrorReason(allocator, line).?;
        defer allocator.free(reason);
        try testing.expectEqualStrings(line, reason);
    }
}

test "stderrReasonCopy: null when nothing captured yet, first non-empty trimmed line otherwise" {
    const allocator = testing.allocator;
    var capture = StderrCapture{};
    try testing.expect(stderrReasonCopy(allocator, &capture) == null);

    // Mirrors iperf3's own real shape: the actual complaint on the first
    // line, followed by a full --help usage dump -- only the first line
    // should ever be surfaced as the failure reason.
    const raw = "usage: iperf3 [-s|-c host] [options]\n" ++
        "Try 'iperf3 --help' for more information.\n";
    capture.data = try allocator.dupe(u8, raw);
    defer allocator.free(capture.data.?);
    const reason = stderrReasonCopy(allocator, &capture).?;
    defer allocator.free(reason);
    try testing.expectEqualStrings("usage: iperf3 [-s|-c host] [options]", reason);
}

test {
    _ = windows_qos;
}
