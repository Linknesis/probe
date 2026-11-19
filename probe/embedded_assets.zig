const builtin = @import("builtin");

// Rooted at the probe/ package root (not probe/src/) specifically so these
// @embedFile calls can reach the sibling iperf3-linux-static/ and
// iperf3-win-patch/ directories -- Zig's module package-path restriction
// only allows @embedFile to resolve within the importing file's own module
// root, and probe/src/main.zig's root module is rooted at probe/src/, one
// level too deep to reach these siblings of probe/ itself. See
// probe/build.zig's embedded_assets module wiring and
// probe/src/iperf3_embedded.zig, which imports this module and does the
// actual self-heal-to-disk logic.
pub const iperf3_bin: []const u8 = if (builtin.os.tag == .windows)
    @embedFile("iperf3-win-patch/iperf3.exe")
else
    @embedFile("iperf3-linux-static/iperf3-linux-x86_64");

pub const iperf3_license: []const u8 = @embedFile("iperf3_license.txt");
