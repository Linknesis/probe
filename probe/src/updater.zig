const std = @import("std");
const builtin = @import("builtin");
const version = @import("version.zig");
const config = @import("config.zig");

var g_allocator: std.mem.Allocator = undefined;
var g_core_version: ?[]u8 = null;
var g_auto_updates: bool = false;
// The Core's real externally-reachable API port, learned from the "config"
// message on every connect/reconnect. Defaults to the pre-fix universal
// constant so this probe still works against an older Core that never sends
// this field (the Core sends it in its probe config message).
var g_api_port: u16 = 4480;
var g_force_update: bool = false;
var g_update_state: ?UpdateState = null;
var g_update_mutex: std.Thread.Mutex = .{};
var g_url_update_in_progress = std.atomic.Value(bool).init(false);

const UpdateState = struct {
    file: std.fs.File,
    file_open: bool,
    temp_path: []u8,
    target_path: []u8,
    expected_size: usize,
    received: usize,
    expected_sha256: [64]u8,
    filename: []u8,
};

const UpdateRequestCtx = struct {
    force: bool,
    delay_ms: u64,
};

const UrlUpdateCtx = struct {
    temp_path: []u8,
    target_path: []u8,
    expected_size: usize,
    expected_sha256: [64]u8,
    filename: []u8,
};

pub fn init(allocator: std.mem.Allocator) void {
    g_allocator = allocator;
}

fn isValidUpdateFilename(filename: []const u8) bool {
    if (filename.len == 0 or filename.len > 128) return false;
    if (filename[0] == '.') return false;
    for (filename) |ch| {
        const ok = (ch >= 'a' and ch <= 'z') or
            (ch >= 'A' and ch <= 'Z') or
            (ch >= '0' and ch <= '9') or
            ch == '.' or ch == '-' or ch == '_';
        if (!ok) return false;
    }
    return true;
}

pub fn deinit() void {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    if (g_core_version) |v| {
        g_allocator.free(v);
        g_core_version = null;
    }
    resetUpdateStateLocked();
}

fn resetUpdateStateLocked() void {
    if (g_update_state) |*s| {
        // handleUpdateDone closes the file before the hash check; only close
        // it again if it's still open, or we'd double-close an fd that may
        // already have been reused by another thread.
        if (s.file_open) s.file.close();
        g_allocator.free(s.temp_path);
        g_allocator.free(s.target_path);
        g_allocator.free(s.filename);
        g_update_state = null;
    }
}

pub fn onConfig(core_version: []const u8, auto_updates: bool, api_port: u16) void {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    if (g_core_version) |v| g_allocator.free(v);
    g_core_version = g_allocator.dupe(u8, core_version) catch return;
    g_auto_updates = auto_updates;
    g_api_port = api_port;
}

pub fn setForceUpdate(force: bool) void {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    g_force_update = force;
}

pub fn isForceUpdate() bool {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    return g_force_update;
}

pub fn shouldUpdate() bool {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    if (g_force_update) return true;
    if (!g_auto_updates) return false;
    const cv = g_core_version orelse return false;
    return !std.mem.eql(u8, cv, version.VERSION);
}

pub fn scheduleUpdateRequest(force: bool) void {
    const max_delay_ms: u64 = if (force) 5_000 else 5 * 60 * 1000;
    const delay_ms = std.crypto.random.intRangeAtMost(u64, 0, max_delay_ms);
    const ctx = g_allocator.create(UpdateRequestCtx) catch return;
    ctx.* = .{ .force = force, .delay_ms = delay_ms };
    const thread = std.Thread.spawn(.{}, updateRequestThread, .{ctx}) catch {
        g_allocator.destroy(ctx);
        return;
    };
    thread.detach();
}

fn updateRequestThread(ctx: *UpdateRequestCtx) void {
    std.Thread.sleep(ctx.delay_ms * std.time.ns_per_ms);
    sendUpdateRequest(ctx.force);
    g_allocator.destroy(ctx);
}

fn sendUpdateRequest(force: bool) void {
    const msg = std.fmt.allocPrint(g_allocator, "{{\"type\":\"request_update\",\"os\":\"{s}\",\"arch\":\"{s}\",\"version\":\"{s}\",\"force\":{s},\"url_update\":true}}", .{
        @tagName(builtin.target.os.tag),
        @tagName(builtin.target.cpu.arch),
        version.VERSION,
        if (force) "true" else "false",
    }) catch return;
    defer g_allocator.free(msg);
    // sendJson re-resolves the live transport under g_send_mutex at send time.
    // Using the Transport captured when this request was scheduled (up to 5
    // minutes earlier) would be a use-after-free if the connection was torn
    // down in the meantime.
    @import("wss_client.zig").sendJson(msg);
}

pub fn handleUpdateStart(parsed: std.json.Value) !void {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    resetUpdateStateLocked();

    const size_val = parsed.object.get("size") orelse return error.MissingField;
    // 1 PiB is an absurdly generous upper bound for a probe binary download,
    // chosen to stay well inside f64's exact-integer range (2^53) so the
    // bounds check itself can't be fooled by float-rounding near the limit.
    const max_reasonable_size: f64 = 1 << 50;
    const expected_size: usize = switch (size_val) {
        .integer => |i| if (i >= 0) @intCast(i) else return error.InvalidSize,
        .float => |f| if (std.math.isFinite(f) and f >= 0 and f <= max_reasonable_size) @intFromFloat(f) else return error.InvalidSize,
        else => return error.InvalidSize,
    };
    const sha = @import("wss_client.zig").jsonString(parsed.object.get("sha256")) orelse return error.MissingField;
    if (sha.len != 64) return error.InvalidHash;
    const filename = @import("wss_client.zig").jsonString(parsed.object.get("filename")) orelse "linknesis-probe";
    // The filename is interpolated into filesystem paths (chunked + URL paths)
    // and, on Windows, into a PowerShell script. An allowlist (no separators,
    // no "..", no quotes) is what stands between a malicious/buggy Core and an
    // arbitrary file write / command injection on the probe host.
    if (!isValidUpdateFilename(filename)) {
        std.log.err("Refusing update with invalid filename: {s}", .{filename});
        return error.InvalidFilename;
    }
    // Both download paths verify the file by reading it with a 64 MiB cap, and
    // real probe binaries are a few MB -- reject absurd declared sizes up
    // front instead of letting a malicious Core fill the probe's disk.
    if (expected_size == 0 or expected_size > 64 * 1024 * 1024) {
        std.log.err("Refusing update with invalid size: {d}", .{expected_size});
        return error.InvalidSize;
    }

    const url_update = blk: {
        if (parsed.object.get("url_update")) |v| {
            if (v == .bool) break :blk v.bool;
        }
        break :blk false;
    };

    const self_path = try std.fs.selfExePathAlloc(g_allocator);
    defer g_allocator.free(self_path);
    const target_dir = std.fs.path.dirname(self_path) orelse ".";

    const temp_path = try std.fmt.allocPrint(g_allocator, "{s}/{s}.update", .{ target_dir, filename });
    errdefer g_allocator.free(temp_path);
    const target_path = try std.fmt.allocPrint(g_allocator, "{s}/{s}", .{ target_dir, filename });
    errdefer g_allocator.free(target_path);

    std.fs.deleteFileAbsolute(temp_path) catch {};

    if (url_update) {
        if (g_url_update_in_progress.swap(true, .seq_cst)) {
            std.log.warn("URL update already in progress, ignoring new update_start", .{});
            g_allocator.free(temp_path);
            g_allocator.free(target_path);
            return;
        }
        std.log.info("Probe URL update started: {s} ({d} bytes)", .{ filename, expected_size });
        const ctx = try g_allocator.create(UrlUpdateCtx);
        errdefer g_allocator.destroy(ctx);
        ctx.* = .{
            .temp_path = temp_path,
            .target_path = target_path,
            .expected_size = expected_size,
            .expected_sha256 = undefined,
            .filename = try g_allocator.dupe(u8, filename),
        };
        @memcpy(&ctx.expected_sha256, sha);
        const thread = try std.Thread.spawn(.{}, urlUpdateThread, .{ctx});
        thread.detach();
        return;
    }

    const filename_copy = try g_allocator.dupe(u8, filename);
    errdefer g_allocator.free(filename_copy);

    const file = try std.fs.createFileAbsolute(temp_path, .{});
    errdefer file.close();

    var state = UpdateState{
        .file = file,
        .file_open = true,
        .temp_path = temp_path,
        .target_path = target_path,
        .expected_size = expected_size,
        .received = 0,
        .expected_sha256 = undefined,
        .filename = filename_copy,
    };
    @memcpy(&state.expected_sha256, sha);
    g_update_state = state;
    std.log.info("Probe update started: {s} ({d} bytes)", .{ filename, expected_size });
}

pub fn handleBinaryChunk(data: []const u8) !void {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    const state = &(g_update_state orelse {
        std.log.warn("Received unexpected binary frame, ignoring", .{});
        return;
    });
    // Enforce the declared size during the transfer, not only at update_done:
    // a sender that keeps streaming past it would otherwise fill the disk.
    if (data.len > state.expected_size - state.received) {
        std.log.err("Update chunk exceeds declared size ({d} > {d}), aborting update", .{ state.received + data.len, state.expected_size });
        // Close the file before deleting it (deleting an open file fails on
        // Windows): dupe the path, reset (closes), then delete.
        const path_copy = g_allocator.dupe(u8, state.temp_path) catch null;
        resetUpdateStateLocked();
        if (path_copy) |p| {
            defer g_allocator.free(p);
            std.fs.deleteFileAbsolute(p) catch {};
        }
        return error.UpdateSizeExceeded;
    }
    try state.file.writeAll(data);
    state.received += data.len;
    std.log.debug("Update chunk: {d}/{d} bytes", .{ state.received, state.expected_size });
}

pub fn handleUpdateDone() !void {
    g_update_mutex.lock();
    defer g_update_mutex.unlock();
    var state = &(g_update_state orelse return error.NoUpdateInProgress);
    try state.file.sync();

    if (state.received != state.expected_size) {
        std.log.err("Update size mismatch: expected {d}, got {d}", .{ state.expected_size, state.received });
        resetUpdateStateLocked();
        return error.SizeMismatch;
    }

    state.file.close();
    state.file_open = false;

    const actual_hash = try computeSha256Hex(state.temp_path);
    if (!std.mem.eql(u8, &actual_hash, &state.expected_sha256)) {
        std.log.err("Update SHA256 mismatch", .{});
        resetUpdateStateLocked();
        return error.HashMismatch;
    }

    std.log.info("Probe update received and verified, applying from {s} to {s}", .{ state.temp_path, state.target_path });

    if (builtin.os.tag == .windows) {
        try applyWindowsUpdate(state.temp_path, state.target_path);
    } else {
        try applyLinuxUpdate(state.temp_path, state.target_path);
    }

    resetUpdateStateLocked();
}

fn urlUpdateThread(ctx: *UrlUpdateCtx) void {
    defer {
        _ = g_url_update_in_progress.swap(false, .seq_cst);
        g_allocator.free(ctx.temp_path);
        g_allocator.free(ctx.target_path);
        g_allocator.free(ctx.filename);
        g_allocator.destroy(ctx);
    }
    downloadUrlUpdate(ctx.temp_path, ctx.expected_size, ctx.expected_sha256) catch |err| {
        std.log.err("URL update download failed: {any}", .{err});
        return;
    };
    std.log.info("Probe update received and verified, applying from {s} to {s}", .{ ctx.temp_path, ctx.target_path });
    if (builtin.os.tag == .windows) {
        applyWindowsUpdate(ctx.temp_path, ctx.target_path) catch |err| {
            std.log.err("Failed to apply Windows URL update: {any}", .{err});
        };
    } else {
        applyLinuxUpdate(ctx.temp_path, ctx.target_path) catch |err| {
            std.log.err("Failed to apply Linux URL update: {any}", .{err});
        };
    }
}

fn buildUpdateUrl() ![]u8 {
    const cfg = config.get();
    var normalized = cfg.core_address;
    const is_wss = std.mem.startsWith(u8, normalized, "wss://");
    const is_ws = std.mem.startsWith(u8, normalized, "ws://");
    if (is_wss or is_ws) {
        normalized = normalized[if (is_wss) 6 else 5..];
    }
    const slash = std.mem.indexOf(u8, normalized, "/") orelse normalized.len;
    const host_port = normalized[0..slash];
    var host: []const u8 = host_port;
    if (std.mem.indexOf(u8, host_port, ":")) |colon| {
        host = host_port[0..colon];
    }
    const os = @tagName(builtin.target.os.tag);
    const arch = @tagName(builtin.target.cpu.arch);
    g_update_mutex.lock();
    const api_port = g_api_port;
    g_update_mutex.unlock();
    return std.fmt.allocPrint(g_allocator, "http://{s}:{d}/api/probe-update/{s}/{s}?hash={s}", .{ host, api_port, os, arch, cfg.hash });
}

fn downloadUrlUpdate(temp_path: []const u8, expected_size: usize, expected_sha256: [64]u8) !void {
    const url = try buildUpdateUrl();
    defer g_allocator.free(url);

    std.log.info("Downloading probe update from {s}", .{url});

    const use_curl = try downloadWithCurl(temp_path, url);
    if (!use_curl) {
        if (builtin.os.tag == .windows) {
            try downloadWithPowerShell(temp_path, url);
        } else {
            try downloadWithWget(temp_path, url);
        }
    }

    const actual_size = try std.fs.cwd().readFileAlloc(g_allocator, temp_path, 64 * 1024 * 1024);
    defer g_allocator.free(actual_size);
    if (actual_size.len != expected_size) {
        std.log.err("Update size mismatch: expected {d}, got {d}", .{ expected_size, actual_size.len });
        return error.SizeMismatch;
    }

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(actual_size, &hash, .{});
    var actual_sha256: [64]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (hash, 0..) |b, i| {
        actual_sha256[i * 2] = hex_chars[b >> 4];
        actual_sha256[i * 2 + 1] = hex_chars[b & 0x0F];
    }
    if (!std.mem.eql(u8, &actual_sha256, &expected_sha256)) {
        std.log.err("Update SHA256 mismatch", .{});
        return error.HashMismatch;
    }
    std.log.info("Probe update downloaded and verified ({d} bytes)", .{actual_size.len});
}

fn downloadWithCurl(temp_path: []const u8, url: []const u8) !bool {
    const argv = if (builtin.os.tag == .windows)
        &[_][]const u8{ "curl.exe", "-fsSL", "--connect-timeout", "30", "--max-time", "300", "-o", temp_path, url }
    else
        &[_][]const u8{ "curl", "-fsSL", "--connect-timeout", "30", "--max-time", "300", "-o", temp_path, url };
    // Not std.process.Child.run(): on Windows it never sets create_no_window,
    // so this console-subsystem child briefly flashes a visible console
    // window when spawned from the GUI-subsystem probe -- same pattern as
    // downloadWithPowerShell below and mtr.zig's
    // ensureWindowsMtrFirewallRules. Harmless on Linux, where the field is a
    // no-op.
    var child = std.process.Child.init(argv, g_allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.create_no_window = true;

    child.spawn() catch |err| {
        std.log.warn("curl download failed to spawn: {any}", .{err});
        return false;
    };

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(g_allocator);
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(g_allocator);
    child.collectOutput(g_allocator, &stdout_buf, &stderr_buf, 64 * 1024) catch |err| {
        std.log.warn("curl download failed to read output: {any}", .{err});
        _ = child.kill() catch {};
        return false;
    };
    const term = child.wait() catch |err| {
        std.log.warn("curl download failed to wait: {any}", .{err});
        return false;
    };
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                std.log.warn("curl exited with code {}: {s}", .{ code, stderr_buf.items });
                return false;
            }
        },
        // Killed by a signal (e.g. OOM mid-download); .Exited access would panic.
        else => {
            std.log.warn("curl terminated abnormally: {s}", .{stderr_buf.items});
            return false;
        },
    }
    return true;
}

fn downloadWithWget(temp_path: []const u8, url: []const u8) !void {
    const argv = &[_][]const u8{ "wget", "--timeout=30", "--tries=3", "-O", temp_path, url };
    const result = std.process.Child.run(.{
        .allocator = g_allocator,
        .argv = argv,
    }) catch |err| {
        std.log.err("wget download failed: {any}", .{err});
        return error.DownloadFailed;
    };
    defer {
        g_allocator.free(result.stdout);
        g_allocator.free(result.stderr);
    }
    switch (result.term) {
        .Exited => |code| {
            if (code != 0) {
                std.log.err("wget exited with code {}: {s}", .{ code, result.stderr });
                return error.DownloadFailed;
            }
        },
        else => {
            std.log.err("wget terminated abnormally: {s}", .{result.stderr});
            return error.DownloadFailed;
        },
    }
}

fn downloadWithPowerShell(temp_path: []const u8, url: []const u8) !void {
    const script = try std.fmt.allocPrint(g_allocator, "Invoke-WebRequest -Uri '{s}' -OutFile '{s}' -UseBasicParsing", .{ url, temp_path });
    defer g_allocator.free(script);
    // Not std.process.Child.run(): it never sets create_no_window, so a
    // "-WindowStyle Hidden" CLI arg alone doesn't stop the console host from
    // briefly flashing a window for this console-subsystem child spawned
    // from the GUI-subsystem probe (same pattern as mtr.zig's
    // ensureWindowsMtrFirewallRules, see that function's comment).
    var child = std.process.Child.init(
        &[_][]const u8{ "powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", script },
        g_allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.create_no_window = true;

    child.spawn() catch |err| {
        std.log.err("PowerShell download failed to spawn: {any}", .{err});
        return error.DownloadFailed;
    };

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(g_allocator);
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(g_allocator);
    child.collectOutput(g_allocator, &stdout_buf, &stderr_buf, 64 * 1024) catch |err| {
        std.log.err("PowerShell download failed to read output: {any}", .{err});
        _ = child.kill() catch {};
        return error.DownloadFailed;
    };
    const term = child.wait() catch |err| {
        std.log.err("PowerShell download failed to wait: {any}", .{err});
        return error.DownloadFailed;
    };

    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                std.log.err("PowerShell exited with code {}: {s}", .{ code, stderr_buf.items });
                return error.DownloadFailed;
            }
        },
        else => {
            std.log.err("PowerShell terminated abnormally: {s}", .{stderr_buf.items});
            return error.DownloadFailed;
        },
    }
}

fn computeSha256Hex(path: []const u8) ![64]u8 {
    const data = try std.fs.cwd().readFileAlloc(g_allocator, path, 64 * 1024 * 1024);
    defer g_allocator.free(data);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    var out: [64]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (hash, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0F];
    }
    return out;
}

fn applyLinuxUpdate(temp_path: []const u8, target_path: []const u8) !void {
    try std.fs.renameAbsolute(temp_path, target_path);
    const file = try std.fs.openFileAbsolute(target_path, .{});
    defer file.close();
    try file.chmod(0o755);

    // No setcap/sudo dance needed here: the raw-socket capability comes from
    // the systemd unit's own AmbientCapabilities=CAP_NET_RAW (see
    // scripts/install_probe.sh), not a file capability on this specific
    // binary -- so a freshly self-replaced binary already has it the moment
    // systemd execs it, with nothing for the probe itself to do.

    std.log.info("Linux probe updated, restarting process", .{});
    std.process.exit(0);
}

fn applyWindowsUpdate(temp_path: []const u8, target_path: []const u8) !void {
    // Write the helper script next to the actual install directory instead
    // of the legacy hardcoded C:\linknesis -- probes are now installed to
    // C:\Program Files\Linknesis Probe (config/log paths were already made
    // portable/relative to the executable directory; this script was the
    // one place that still hardcoded the old path).
    const install_dir = std.fs.path.dirname(target_path) orelse "C:\\Program Files\\Linknesis Probe";
    const script_path = try std.fmt.allocPrint(g_allocator, "{s}\\update.ps1", .{install_dir});
    defer g_allocator.free(script_path);
    const script = try std.fmt.allocPrint(g_allocator, "Start-Sleep -Seconds 5\r\n" ++
        "Move-Item -Path '{s}' -Destination '{s}' -Force\r\n" ++
        "Start-ScheduledTask -TaskName 'LinknesisProbe'\r\n", .{ temp_path, target_path });
    defer g_allocator.free(script);
    const file = try std.fs.createFileAbsolute(script_path, .{});
    defer file.close();
    try file.writeAll(script);

    const win = std.os.windows;
    const CreateProcessW = @extern(*const fn (
        application_name: ?win.LPCWSTR,
        command_line: win.LPWSTR,
        process_attrs: ?*anyopaque,
        thread_attrs: ?*anyopaque,
        inherit_handles: win.BOOL,
        creation_flags: win.DWORD,
        environment: ?*anyopaque,
        current_dir: ?win.LPCWSTR,
        startup_info: *win.STARTUPINFOW,
        process_info: *win.PROCESS_INFORMATION,
    ) callconv(.c) win.BOOL, .{ .name = "CreateProcessW", .library_name = "kernel32" });

    var si: win.STARTUPINFOW = std.mem.zeroes(win.STARTUPINFOW);
    si.cb = @sizeOf(win.STARTUPINFOW);
    si.dwFlags = win.STARTF_USESHOWWINDOW;
    si.wShowWindow = 0; // SW_HIDE
    var pi: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);

    const cmd_str = try std.fmt.allocPrint(g_allocator, "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{s}\"", .{script_path});
    defer g_allocator.free(cmd_str);
    const cmd = try std.unicode.utf8ToUtf16LeAllocZ(g_allocator, cmd_str);
    defer g_allocator.free(cmd);

    if (CreateProcessW(null, cmd, null, null, 0, 0x08000000, null, null, &si, &pi) == 0) {
        return error.WindowsSpawnFailed;
    }
    win.CloseHandle(pi.hProcess);
    win.CloseHandle(pi.hThread);

    std.log.info("Windows probe updated, exiting to allow replacement", .{});
    std.process.exit(0);
}
