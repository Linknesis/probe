const std = @import("std");

pub var enabled = false;

var g_syslog_opened = false;
var g_mutex = std.Thread.Mutex{};
var g_log_file: ?std.fs.File = null;

const MAX_LOG_SIZE = 5 * 1024 * 1024; // 5 MB
const KEEP_SIZE = MAX_LOG_SIZE / 2; // keep last ~2.5 MB

const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};
extern "kernel32" fn GetLocalTime(lpSystemTime: *SYSTEMTIME) callconv(.winapi) void;

const LocalHms = struct { h: u32, m: u32, s: u32 };

// Log lines are shown to the user (Windows tray "View Log" window), so the
// timestamp prefix must be local wall-clock time, not UTC.
fn getLocalHms() LocalHms {
    if (is_windows) {
        var st: SYSTEMTIME = undefined;
        GetLocalTime(&st);
        return .{ .h = st.wHour, .m = st.wMinute, .s = st.wSecond };
    } else {
        const now = std.time.timestamp();
        const es = std.time.epoch.EpochSeconds{ .secs = @intCast(now) };
        const d = es.getDaySeconds();
        return .{
            .h = @intCast(@mod(@divFloor(d.secs, 3600), 24)),
            .m = @intCast(@mod(@divFloor(d.secs, 60), 60)),
            .s = @intCast(@mod(d.secs, 60)),
        };
    }
}

const Syslog = if (is_windows) struct {
    pub fn openlog(_: [*]const u8, _: c_int, _: c_int) void {}
    pub fn closelog() void {}
    pub fn syslog(_: c_int, _: [*]const u8, _: [*]const u8) void {}
    pub const LOG_NDELAY = 0;
    pub const LOG_PID = 0;
    pub const LOG_DAEMON = 0;
    pub const LOG_ERR = 0;
    pub const LOG_WARNING = 0;
    pub const LOG_INFO = 0;
    pub const LOG_DEBUG = 0;
} else @cImport(@cInclude("syslog.h"));

pub fn init() void {
    if (is_windows) {
        // Log file opened lazily
    }
}

pub fn deinit() void {
    if (!is_windows) {
        if (g_syslog_opened) {
            Syslog.closelog();
            g_syslog_opened = false;
        }
    } else {
        if (g_log_file) |f| {
            f.close();
            g_log_file = null;
        }
    }
}

fn syslogLevel(level: std.log.Level) c_int {
    return switch (level) {
        .err => Syslog.LOG_ERR,
        .warn => Syslog.LOG_WARNING,
        .info => Syslog.LOG_INFO,
        .debug => Syslog.LOG_DEBUG,
    };
}

pub fn getWindowsLogPath(out: []u8) ![]const u8 {
    var exe_path_w: [260]u16 = undefined;
    @memset(&exe_path_w, 0);
    const len = std.os.windows.kernel32.GetModuleFileNameW(null, &exe_path_w, exe_path_w.len);
    if (len == 0 or len >= exe_path_w.len) return error.PathTooLong;
    var tmp: [512]u8 = undefined;
    const exe_len = try std.unicode.utf16LeToUtf8(&tmp, exe_path_w[0..len]);
    const exe_utf8 = tmp[0..exe_len];
    const dir = std.fs.path.dirname(exe_utf8) orelse return error.NoDir;
    return std.fmt.bufPrint(out, "{s}\\linknesis-debug.log", .{dir});
}

fn openWindowsLogFile() !std.fs.File {
    var path_buf: [512]u8 = undefined;
    const path = getWindowsLogPath(&path_buf) catch return error.PathError;
    if (std.fs.path.dirname(path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }

    if (is_windows) {
        // Use Win32 CreateFileW with FILE_SHARE_DELETE to allow hot-deletion
        const win = std.os.windows;
        var path_w_buf: [512]u16 = std.mem.zeroes([512]u16);
        const path_w_len = try std.unicode.utf8ToUtf16Le(&path_w_buf, path);
        path_w_buf[path_w_len] = 0;
        const path_w = path_w_buf[0..path_w_len :0];
        const handle = win.kernel32.CreateFileW(
            path_w,
            win.GENERIC_WRITE,
            win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE,
            null,
            win.OPEN_ALWAYS,
            win.FILE_ATTRIBUTE_NORMAL,
            null,
        );
        if (handle == win.INVALID_HANDLE_VALUE) {
            return error.OpenFailed;
        }
        // Seek to end
        var new_pos: i64 = 0;
        const rc = win.kernel32.SetFilePointerEx(handle, 0, &new_pos, win.FILE_END);
        if (rc == 0) {
            win.CloseHandle(handle);
            return error.SeekFailed;
        }
        return std.fs.File{ .handle = handle };
    } else {
        return std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch {
            return std.fs.cwd().createFile(path, .{});
        };
    }
}

fn rotateWindowsLogFile() !std.fs.File {
    var path_buf: [512]u8 = undefined;
    const path = getWindowsLogPath(&path_buf) catch return error.PathError;

    // Open for reading to capture the tail we want to keep.
    var read_file = std.fs.cwd().openFile(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return openWindowsLogFile(),
        else => return e,
    };

    const size = try read_file.getEndPos();
    if (size <= KEEP_SIZE) {
        read_file.close();
        return openWindowsLogFile();
    }

    const read_start = size - KEEP_SIZE;
    try read_file.seekTo(read_start);

    const keep_buf = try std.heap.page_allocator.alloc(u8, KEEP_SIZE);
    defer std.heap.page_allocator.free(keep_buf);

    const read_len = try read_file.readAll(keep_buf);
    read_file.close();

    // Skip to the next newline so we start with a complete log line.
    var start: usize = 0;
    while (start < read_len and keep_buf[start] != '\n') : (start += 1) {}
    if (start < read_len) start += 1; // skip the newline itself

    // Truncate the existing file in place and rewrite the preserved tail.
    var new_file = try std.fs.cwd().createFile(path, .{ .truncate = true });

    _ = try new_file.write(keep_buf[start..read_len]);
    _ = try new_file.write("\r\n");

    const trunc_msg = "[INFO] [default] Log file rotated (kept last ~2.5 MB)";
    _ = try new_file.write(trunc_msg);
    _ = try new_file.write("\r\n");

    return new_file;
}

pub fn writeToWindowsLog(msg: []const u8) void {
    g_mutex.lock();
    defer g_mutex.unlock();

    var file = g_log_file orelse (openWindowsLogFile() catch return);

    // Prevent unbounded growth: rotate the file, keeping the most recent half.
    const size = file.getEndPos() catch 0;
    if (size > MAX_LOG_SIZE) {
        file.close();
        g_log_file = null;
        file = rotateWindowsLogFile() catch |e| blk: {
            // If rotation fails for any reason, fall back to delete+recreate.
            var del_path_buf: [512]u8 = undefined;
            if (getWindowsLogPath(&del_path_buf)) |del_path| {
                std.fs.cwd().deleteFile(del_path) catch {};
            } else |_| {}
            var fallback = openWindowsLogFile() catch return;
            var trunc_buf: [256]u8 = undefined;
            const trunc_msg = std.fmt.bufPrint(&trunc_buf, "[INFO] [default] Log file truncated due to size limit (rotation failed: {s})", .{@errorName(e)}) catch "[INFO] [default] Log file truncated due to size limit";
            _ = fallback.write(trunc_msg) catch {};
            _ = fallback.write("\r\n") catch {};
            break :blk fallback;
        };
        g_log_file = file;
    }

    _ = file.seekFromEnd(0) catch {
        file.close();
        g_log_file = null;
        file = openWindowsLogFile() catch return;
        g_log_file = file;
    };
    _ = file.write(msg) catch {};
    _ = file.write("\r\n") catch {};
    g_log_file = file;
}

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (level == .debug and !enabled) return;

    const level_txt = switch (level) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };
    const scope_txt = if (@tagName(scope).len == 0) "default" else @tagName(scope);

    const t = getLocalHms();
    const h = t.h;
    const m = t.m;
    const s = t.s;

    // Always write to the log file on Windows (GUI apps have no console).
    // On Linux, only write if debug logging is enabled.
    const should_log = if (is_windows) (level != .debug or enabled) else enabled;

    if (should_log) {
        var buf: [4096]u8 = undefined;
        // Print into buf.len-1 and NUL-terminate: C syslog's "%s" reads until
        // a NUL byte, so a non-terminated slice leaks uninitialized stack.
        const msg = std.fmt.bufPrint(buf[0 .. buf.len - 1], "[{d:0>2}:{d:0>2}:{d:0>2}] [{s}] [{s}] " ++ format, .{ h, m, s, level_txt, scope_txt } ++ args) catch return;
        buf[msg.len] = 0;

        if (is_windows) {
            writeToWindowsLog(msg);
        } else {
            if (!g_syslog_opened) {
                Syslog.openlog("linknesis-probe", Syslog.LOG_NDELAY | Syslog.LOG_PID, Syslog.LOG_DAEMON);
                g_syslog_opened = true;
            }
            Syslog.syslog(syslogLevel(level), "%s", msg.ptr);
        }
    }

    // Also try to write to stderr (best-effort; may fail on Windows GUI).
    var buffer: [1024]u8 = undefined;
    const stderr = std.debug.lockStderrWriter(&buffer);
    defer std.debug.unlockStderrWriter();
    nosuspend stderr.print("[{d:0>2}:{d:0>2}:{d:0>2}] [{s}] [{s}] " ++ format ++ "\n", .{ h, m, s, level_txt, scope_txt } ++ args) catch {};

}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    if (!enabled) return;
    logFn(.debug, .default, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    logFn(.info, .default, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    logFn(.warn, .default, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    logFn(.err, .default, fmt, args);
}
