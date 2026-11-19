const std = @import("std");
const builtin = @import("builtin");

var g_running = std.atomic.Value(bool).init(true);

pub fn setupSignals() void {
    if (builtin.os.tag != .windows) {
        const empty_set = std.mem.zeroes(std.posix.sigset_t);
        _ = std.posix.sigaction(std.posix.SIG.INT, &std.posix.Sigaction{
            .handler = .{ .handler = signalHandler },
            .mask = empty_set,
            .flags = 0,
        }, null);
        _ = std.posix.sigaction(std.posix.SIG.TERM, &std.posix.Sigaction{
            .handler = .{ .handler = signalHandler },
            .mask = empty_set,
            .flags = 0,
        }, null);
    }
}

fn signalHandler(_: i32) callconv(.c) void {
    g_running.store(false, .seq_cst);
}

pub fn isRunning() bool {
    return g_running.load(.acquire);
}

pub fn shutdown() void {
    g_running.store(false, .seq_cst);
}

// Windows-specific GUI integration
pub const GuiCallbacks = struct {
    onConfigSave: ?*const fn (core: []const u8, hash: []const u8) void = null,
    onShowLog: ?*const fn () void = null,
};

pub fn runGuiIfNeeded(_: GuiCallbacks) void {
    if (builtin.os.tag == .windows) {
        @import("windows_gui.zig").runMessageLoop();
    }
}

pub fn isWindows() bool {
    return builtin.os.tag == .windows;
}
