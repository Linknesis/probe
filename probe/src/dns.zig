const std = @import("std");

pub fn resolveAndTime(allocator: std.mem.Allocator, hostname: []const u8) !struct { ip: []u8, duration_ms: u64 } {
    const start = std.time.milliTimestamp();
    const addr_list = try std.net.getAddressList(allocator, hostname, 443);
    defer addr_list.deinit();
    // milliTimestamp() is wall clock: an NTP backward step between the two
    // reads makes the delta negative, and a bare @intCast to u64 would panic
    // the whole probe. lossyCast saturates that to 0.
    const duration: u64 = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
    if (addr_list.addrs.len == 0) return error.NoAddresses;
    const ip_str = try formatAddress(allocator, addr_list.addrs[0]);
    return .{ .ip = ip_str, .duration_ms = duration };
}

fn formatAddress(allocator: std.mem.Allocator, addr: std.net.Address) error{OutOfMemory}![]u8 {
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const ip = addr.in.sa.addr;
            return try std.fmt.allocPrint(allocator, "{}.{}.{}.{}", .{
                (ip >> 0) & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff,
            });
        },
        else => {
            // std.net.Address (e.g. IPv6/AF_INET6) has a custom `format` method
            // that must be invoked with the `{f}` specifier in Zig 0.15 -- `{any}`
            // bypasses it and dumps the raw struct fields instead (this is what
            // was actually happening: DNS/MTR results showed a debug struct dump
            // like ".{ .any = .{ .family = 10, ... }" instead of an IPv6 address).
            // Address.format always renders as "[addr]:port"; strip the brackets
            // and port since callers only want the bare address.
            var buf: [64]u8 = undefined;
            const formatted = std.fmt.bufPrint(&buf, "{f}", .{addr}) catch return try allocator.dupe(u8, "");
            const start: usize = if (std.mem.startsWith(u8, formatted, "[")) 1 else 0;
            const end = std.mem.lastIndexOfScalar(u8, formatted, ']') orelse formatted.len;
            return try allocator.dupe(u8, formatted[start..end]);
        },
    }
}
