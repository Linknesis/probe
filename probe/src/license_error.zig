const std = @import("std");
const builtin = @import("builtin");
const wss_client = @import("wss_client.zig");

// Whether the current license-error episode has already been surfaced to the
// user. Reset by clear() on a successful reconnect so a later rejection notifies
// again, while avoiding log/balloon spam on every retry in between.
var g_notified = std.atomic.Value(bool).init(false);

pub fn handle(reason: []const u8, max_probes: ?u32) void {
    const MAX_PROBES = max_probes orelse 0;
    var message_buf: [512]u8 = undefined;
    var message: []const u8 = "License error. Please check your Core configuration.";

    if (std.mem.eql(u8, reason, "probe_limit_exceeded")) {
        if (MAX_PROBES > 0) {
            message = std.fmt.bufPrint(&message_buf, "License limit reached. This plan allows up to {d} probe(s). Contact your administrator to upgrade.", .{MAX_PROBES}) catch message;
        } else {
            message = "License limit reached";
        }
    } else if (std.mem.eql(u8, reason, "license_invalid")) {
        message = "License invalid or expired. Check the token in your Core settings.";
    } else if (std.mem.eql(u8, reason, "already_bound")) {
        message = "This license token is already bound to another Core. Regenerate the token in the panel or wait for the migration grace period.";
    }

    // A license rejection is treated as recoverable, not fatal: signal the
    // WebSocket loop to back off and keep retrying every few minutes forever.
    // Rejections are frequently transient (e.g. the Core's license API/panel is
    // temporarily unreachable), so the probe must reconnect on its own once the
    // Core accepts it again instead of staying down until a manual restart.
    wss_client.setLicenseError();

    // Surface the error to the user only once per episode to avoid spamming the
    // log (and the Windows tray balloon) on every retry. clear() re-arms this on
    // a successful reconnect.
    if (g_notified.swap(true, .seq_cst)) return;

    std.log.err("License rejected by Core: {s}", .{message});
    if (builtin.os.tag == .windows) {
        @import("windows_gui.zig").showLicenseErrorBalloon("Linknesis License Error", message);
        @import("windows_gui.zig").setTrayStatus("License error");
    }
}

// Re-arm license-error notification after a successful reconnect and clear the
// Windows tray error status. Called on every successful WebSocket connection; it
// only does work when recovering from a prior license-error episode.
pub fn clear() void {
    if (!g_notified.swap(false, .seq_cst)) return;
    if (builtin.os.tag == .windows) {
        @import("windows_gui.zig").setTrayStatus("Connected");
    }
}
