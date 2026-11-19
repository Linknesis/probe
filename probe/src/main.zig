const std = @import("std");
const config = @import("config.zig");
const wss_client = @import("wss_client.zig");
const platform = @import("platform.zig");
const iperf3_runner = @import("iperf3_runner.zig");
const iperf3_embedded = @import("iperf3_embedded.zig");
const mtr = @import("mtr.zig");
const debug = @import("debug.zig");
const lock = @import("lock.zig");
const updater = @import("updater.zig");
const watchdog = @import("watchdog.zig");

pub const std_options: std.Options = .{
    .logFn = debug.logFn,
    .log_level = .debug,
};

pub var g_iperf3_available: bool = false;

pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;
    if (@import("builtin").os.tag == .windows) {
        // Write the panic log next to the executable (the portable install dir,
        // e.g. C:\Program Files\Linknesis Probe) instead of the legacy hardcoded
        // C:\linknesis path, which does not exist on standard installs and would
        // silently drop the crash log. Use stack buffers only (no allocation) so
        // this stays safe inside a panic.
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        if (std.fs.selfExeDirPath(&dir_buf)) |self_dir| {
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;
            if (std.fmt.bufPrint(&path_buf, "{s}\\panic.txt", .{self_dir})) |path| {
                const f = std.fs.cwd().createFile(path, .{ .truncate = false }) catch null;
                if (f) |file| {
                    _ = file.seekFromEnd(0) catch {};
                    _ = file.write(msg) catch {};
                    _ = file.write("\n") catch {};
                    file.close();
                }
            } else |_| {}
        } else |_| {}
    } else {
        std.debug.print("panic: {s}\n", .{msg});
    }
    @trap();
}

fn setupWindowsExceptionHandler() void {
    const win = std.os.windows;
    const EXCEPTION_CONTINUE_SEARCH: win.LONG = 0;

    const TopLevelExceptionFilter = *const fn (info: *anyopaque) callconv(.c) win.LONG;
    const SetUnhandledExceptionFilter = @extern(*const fn (handler: TopLevelExceptionFilter) callconv(.c) TopLevelExceptionFilter, .{ .name = "SetUnhandledExceptionFilter", .library_name = "kernel32" });

    const handler = struct {
        fn callback(info: *anyopaque) callconv(.c) win.LONG {
            // info is PEXCEPTION_POINTERS
            // EXCEPTION_POINTERS.ExceptionRecord is the first field (a pointer)
            const rec_ptr = @as(*usize, @ptrFromInt(@intFromPtr(info))).*;
            if (rec_ptr != 0) {
                // EXCEPTION_RECORD.ExceptionCode is at offset 0
                const code = @as(*u32, @ptrFromInt(rec_ptr)).*;
                // EXCEPTION_RECORD.ExceptionAddress is at offset 0x10 on x64
                const addr = @as(*usize, @ptrFromInt(rec_ptr + 0x10)).*;
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "[FATAL] Unhandled exception code=0x{X} at address=0x{X}", .{ code, addr }) catch "[FATAL] Unhandled exception";
                debug.writeToWindowsLog(msg);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }.callback;

    _ = SetUnhandledExceptionFilter(handler);
}

fn checkIperf3() bool {
    // iperf3 is bundled next to the probe binary on both platforms (Windows
    // has always worked this way; Linux switched from a PATH/system-package
    // lookup to the same bundled model to stop depending on the host
    // distro's own iperf3 packaging policy -- see
    // probe/iperf3-linux-static/README.md and iperf3_runner.zig's
    // resolveIperf3Path(), which this mirrors, including the PATH fallback
    // below for a probe that only auto-updated its binary and never had the
    // bundled copy placed (see resolveIperf3Path's comment for why that
    // fallback is load-bearing, not cosmetic).
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const bundled_path: ?[]u8 = blk: {
        const self_dir = std.fs.selfExeDirPath(&dir_buf) catch break :blk null;
        const bin_name = if (@import("builtin").os.tag == .windows) "iperf3.exe" else "iperf3";
        break :blk std.fs.path.join(std.heap.page_allocator, &.{ self_dir, bin_name }) catch null;
    };
    defer if (bundled_path) |p| std.heap.page_allocator.free(p);

    if (@import("builtin").os.tag == .windows) {
        // On Windows GUI subsystem, spawning child processes can be unreliable
        // -- a plain existence check is enough here (run() itself surfaces a
        // spawn failure at test time if this is somehow wrong). No PATH
        // fallback on Windows: there has never been a system iperf3 concept
        // there, only the installer-bundled copy.
        const path = bundled_path orelse return false;
        std.fs.cwd().access(path, .{}) catch return false;
        return true;
    } else {
        if (bundled_path) |path| {
            if (std.process.Child.run(.{
                .allocator = std.heap.page_allocator,
                .argv = &.{ path, "-v" },
            })) |result| {
                if (result.term.Exited == 0) return true;
            } else |_| {}
        }
        const result = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &.{ "iperf3", "-v" },
        }) catch return false;
        return result.term.Exited == 0;
    }
}

pub fn main() !void {
    if (@import("builtin").os.tag == .windows) {
        setupWindowsExceptionHandler();
    }
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Parsed up front, before lock.acquire()/config.load(), because --data-dir
    // changes which lock file and state.json those calls resolve to -- it lets
    // multiple probe instances run on one host, each isolated to its own
    // directory (see lock.zig/config.zig/watchdog.zig's setDataDir()).
    var service_mode = false;
    var update_only = false;
    var core_arg: ?[]const u8 = null;
    var hash_arg: ?[]const u8 = null;
    var data_dir_arg: ?[]const u8 = null;
    var label_arg: ?[]const u8 = null;
    // --version must exit before lock.acquire()/config.load()/config.save():
    // an admin running `linknesis-probe --version` next to a live service
    // previously fell through to a full startup attempt (unknown flags are
    // ignored) and failed with LockFailed instead of printing anything.
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-V")) {
            std.fs.File.stdout().writeAll("linknesis-probe " ++ @import("version.zig").VERSION ++ "\n") catch {};
            return;
        }
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--core")) {
            i += 1;
            if (i < args.len) core_arg = args[i];
        } else if (std.mem.eql(u8, args[i], "--hash")) {
            i += 1;
            if (i < args.len) hash_arg = args[i];
        } else if (std.mem.eql(u8, args[i], "--data-dir")) {
            i += 1;
            if (i < args.len) data_dir_arg = args[i];
        } else if (std.mem.eql(u8, args[i], "--label")) {
            i += 1;
            if (i < args.len) label_arg = args[i];
        } else if (std.mem.eql(u8, args[i], "--debug")) {
            debug.enabled = true;
        } else if (std.mem.eql(u8, args[i], "--service")) {
            service_mode = true;
        } else if (std.mem.eql(u8, args[i], "--update")) {
            update_only = true;
        }
    }

    if (data_dir_arg) |dir| {
        try config.setDataDir(dir, allocator);
        lock.setDataDir(dir);
    }

    try lock.acquire();

    try config.load(allocator);
    if (core_arg) |c| try config.setCoreAddress(c, allocator);
    if (hash_arg) |h| try config.setHash(h, allocator);
    if (label_arg) |l| try config.setLabel(l, allocator);

    if (update_only) {
        updater.setForceUpdate(true);
    }

    try config.save(allocator);
    if (config.get().core_address.len == 0) {
        std.log.err("No Core address configured. Start the probe with --core <core-host>:4443 (the install command from the Core's Probes page sets it).", .{});
        std.process.exit(2);
    }
    debug.init();
    std.log.info("Linknesis Probe starting... UUID: {s}", .{config.get().uuid orelse "(none)"});

    std.log.info("Ensuring bundled iperf3 is up to date...", .{});
    iperf3_embedded.ensureBundledIperf3(allocator);

    std.log.info("Checking iperf3...", .{});
    g_iperf3_available = checkIperf3();
    if (g_iperf3_available) {
        std.log.info("iperf3 dependency check passed", .{});
    } else {
        std.log.warn("bundled iperf3 not found next to the probe binary. Probe will run in degraded mode.", .{});
    }

    std.log.info("Init runners...", .{});
    iperf3_runner.init(allocator);
    mtr.init(allocator);
    if (@import("builtin").os.tag == .windows) {
        // Self-heal the inbound Windows Firewall rules TCP/UDP MTR depends
        // on (see mtr.zig's ensureWindowsMtrFirewallRules doc comment) --
        // detached so a slow powershell.exe cold start never delays the WSS
        // connection.
        const fw_thread = std.Thread.spawn(.{}, mtr.ensureWindowsMtrFirewallRules, .{}) catch |err| blk: {
            std.log.warn("Failed to spawn MTR firewall rule self-check thread: {any}", .{err});
            break :blk null;
        };
        if (fw_thread) |t| t.detach();
        // Remove DSCP QoS policies a previous crashed run left behind.
        const qos_thread = std.Thread.spawn(.{}, @import("windows_qos.zig").removeStalePolicies, .{}) catch |err| blk: {
            std.log.warn("Failed to spawn DSCP QoS policy cleanup thread: {any}", .{err});
            break :blk null;
        };
        if (qos_thread) |t| t.detach();
    }
    updater.init(allocator);
    wss_client.init(allocator);
    platform.setupSignals();

    watchdog.init();
    const watchdog_thread = try std.Thread.spawn(.{}, watchdog.watchdogLoop, .{});
    watchdog_thread.detach();
    watchdog.ready();

    std.log.info("Starting main loop...", .{});

    if (platform.isWindows() and !service_mode) {
        // On Windows, run WebSocket in a background thread so main thread can host GUI
        const ws_thread = try std.Thread.spawn(.{ .stack_size = 8 * 1024 * 1024 }, wsClientLoop, .{});
        ws_thread.detach();
        std.log.info("Running GUI...", .{});
        platform.runGuiIfNeeded(.{});
    } else {
        // Service mode or Linux: run the WebSocket loop on the main thread
        var attempt: usize = 0;
        const max_attempts: usize = if (update_only) 3 else 0;
        while (platform.isRunning()) {
            wss_client.run() catch |err| {
                std.log.err("WSS error: {any}. Reconnecting...", .{err});
                if (update_only) {
                    attempt += 1;
                    if (max_attempts > 0 and attempt >= max_attempts) {
                        std.log.err("Update mode: max connection attempts reached, exiting.", .{});
                        break;
                    }
                }
                std.Thread.sleep(5 * std.time.ns_per_s);
            };
        }
    }
    std.log.info("Probe shutting down...", .{});
    iperf3_runner.stopAll();
    mtr.stopAll();
    wss_client.closeTcpStream();
    debug.deinit();
}

fn wsClientLoop() void {
    var delay_ms: u64 = 1000;
    const max_delay_ms: u64 = 60000;
    while (platform.isRunning()) {
        wss_client.run() catch |err| {
            std.log.err("WSS error: {any}. Reconnecting in {d}ms...", .{ err, delay_ms });
            std.Thread.sleep(delay_ms * std.time.ns_per_ms);
            // Exponential backoff with jitter (+/- 25%)
            const jitter = std.crypto.random.int(u64) % (delay_ms / 2);
            delay_ms = (delay_ms * 2) + jitter - (delay_ms / 4);
            if (delay_ms > max_delay_ms) delay_ms = max_delay_ms;
            continue;
        };
        // On successful connection, reset backoff
        delay_ms = 1000;
    }
}
