const std = @import("std");

pub const Error = error{ AlreadyRunning, LockFailed };

extern "kernel32" fn CreateMutexW(lpMutexAttributes: ?*anyopaque, bInitialOwner: i32, lpName: ?[*:0]const u16) callconv(.c) ?*anyopaque;
extern "kernel32" fn GetLastError() callconv(.c) i32;

var g_lock_fd: i32 = -1;
var g_mutex_handle: ?*anyopaque = null;

var g_lock_path_buf: [512]u8 = undefined;
var g_lock_path: [:0]const u8 = "/tmp/linknesis-probe.lock";

// Called from main() before acquire(), when --data-dir is set, so multiple
// probe instances on one host (each given a distinct data dir) don't fight
// over the same default /tmp lock file. A no-op on Windows, which uses a
// named mutex instead of a lock file.
pub fn setDataDir(dir: []const u8) void {
    if (@import("builtin").os.tag == .windows) return;
    if (std.fmt.bufPrintZ(&g_lock_path_buf, "{s}/probe.lock", .{dir})) |p| {
        g_lock_path = p;
    } else |_| {}
}

pub fn acquire() Error!void {
    if (@import("builtin").os.tag == .windows) {
        return acquireWindows();
    } else {
        return acquirePosix();
    }
}

fn acquirePosix() Error!void {
    const c = @cImport({
        @cInclude("fcntl.h");
    });
    const path = g_lock_path;
    const fd = c.open(path, c.O_WRONLY | c.O_CREAT, @as(c.mode_t, 0o644));
    if (fd < 0) {
        std.log.err("Cannot create lock file {s}", .{path});
        return error.LockFailed;
    }
    var fl: c.struct_flock = .{
        .l_type = c.F_WRLCK,
        .l_whence = c.SEEK_SET,
        .l_start = 0,
        .l_len = 0,
        .l_pid = 0,
    };
    if (c.fcntl(fd, c.F_SETLK, &fl) < 0) {
        std.log.err("Another instance of linknesis-probe is already running", .{});
        return error.AlreadyRunning;
    }
    g_lock_fd = fd;
}

fn acquireWindows() Error!void {
    const name = comptime blk: {
        var buf: [64:0]u16 = undefined;
        const s = "LinknesisProbe";
        for (s, 0..) |ch, i| buf[i] = ch;
        buf[s.len] = 0;
        break :blk buf;
    };
    const h = CreateMutexW(null, 0, &name);
    if (h == null) {
        std.log.err("Failed to create mutex", .{});
        return error.LockFailed;
    }
    if (GetLastError() == 183) { // ERROR_ALREADY_EXISTS
        std.log.err("Another instance of linknesis-probe is already running", .{});
        return error.AlreadyRunning;
    }
    g_mutex_handle = h;
}
