const std = @import("std");
const builtin = @import("builtin");
const embedded_assets = @import("embedded_assets");

// The bundled iperf3 binary and its upstream license text, embedded directly
// into the probe executable (via the embedded_assets module, see
// probe/embedded_assets.zig and probe/build.zig for why that indirection is
// needed) so a plain binary self-update (see updater.zig) can refresh them
// too -- self-update only ever replaces the running process's own
// executable; it has no way to place a *new* companion file a fresh
// `install_probe.sh` run would. Embedding sidesteps that
// limitation entirely: whichever iperf3 build shipped inside a given probe
// VERSION travels with it through the exact same self-update path already
// used (and trusted) for the probe binary itself, with no new protocol,
// endpoint, or privilege step. The tradeoff is that bumping iperf3 now means
// rebuilding/republishing the probe binary itself -- already done on every
// release regardless (both probe binaries are rebuilt on every
// publish).
//
// Windows Cygwin runtime DLLs (cygwin1.dll) are deliberately NOT embedded --
// they're large, tied to the Cygwin toolchain version that built iperf3.exe
// rather than to iperf3's own version, and effectively never change on their
// own. They stay installer-only (NSIS-bundled), same as before.
pub const iperf3_bin: []const u8 = embedded_assets.iperf3_bin;
pub const iperf3_license: []const u8 = embedded_assets.iperf3_license;

const iperf3_bin_name = if (builtin.os.tag == .windows) "iperf3.exe" else "iperf3";
const iperf3_license_name = "iperf3_license.txt";

/// Write `contents` to `dir/name`, but only if what's already on disk (if
/// anything) doesn't already match byte-for-byte -- avoids a needless
/// write+rename (and, on Linux, a needless chmod) on every ordinary startup,
/// which is by far the common case once a probe is already up to date.
fn ensureFileMatches(allocator: std.mem.Allocator, dir: []const u8, name: []const u8, contents: []const u8, executable: bool) !bool {
    const target_path = try std.fs.path.join(allocator, &.{ dir, name });
    defer allocator.free(target_path);

    if (std.fs.cwd().readFileAlloc(allocator, target_path, contents.len + 1)) |existing| {
        defer allocator.free(existing);
        if (std.mem.eql(u8, existing, contents)) return false; // already current
    } else |_| {
        // Missing, unreadable, or size-mismatched (readFileAlloc's max_bytes
        // cap rejects anything larger than `contents`) -- fall through and
        // (re)write it either way.
    }

    // Write to a temp file in the same directory first, then rename over the
    // target -- atomic on the same filesystem, and safe even if the target is
    // currently open: a rename never disturbs an already-open file descriptor
    // (Linux) or an already-running process image, it only repoints the
    // directory entry for whoever opens the path next. This is the same
    // reasoning updater.zig's applyLinuxUpdate() already relies on for the
    // probe binary itself.
    const suffix = std.crypto.random.int(u32);
    const temp_name = try std.fmt.allocPrint(allocator, ".{s}.tmp{d}", .{ name, suffix });
    defer allocator.free(temp_name);
    const temp_path = try std.fs.path.join(allocator, &.{ dir, temp_name });
    defer allocator.free(temp_path);

    {
        const file = try std.fs.cwd().createFile(temp_path, .{});
        errdefer std.fs.cwd().deleteFile(temp_path) catch {};
        defer file.close();
        try file.writeAll(contents);
        if (executable and builtin.os.tag != .windows) {
            try file.chmod(0o755);
        }
    }

    std.fs.cwd().rename(temp_path, target_path) catch |err| {
        // Most likely cause on Windows: the existing file is locked by a
        // still-running (possibly orphaned -- see updater.zig's "no
        // coordination with an active test" gap) iperf3 process from before
        // this restart. Not fatal: leave the old file in place, clean up the
        // temp file, and let the next startup try again.
        std.fs.cwd().deleteFile(temp_path) catch {};
        return err;
    };
    return true;
}

/// Self-heal the bundled iperf3 binary and its license text next to the
/// running probe executable, so a probe that only ever auto-updates its
/// binary (never re-runs install_probe.sh) still ends up with whichever
/// iperf3 build its current VERSION actually embeds. Called once at startup,
/// before checkIperf3()'s dependency check -- cheap (a few hundred KB to a
/// couple MB, local disk only) and safe to run synchronously.
pub fn ensureBundledIperf3(allocator: std.mem.Allocator) void {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const self_dir = std.fs.selfExeDirPath(&dir_buf) catch |err| {
        std.log.warn("ensureBundledIperf3: could not resolve self exe dir: {any}", .{err});
        return;
    };

    if (ensureFileMatches(allocator, self_dir, iperf3_bin_name, iperf3_bin, true)) |updated| {
        if (updated) std.log.info("Bundled iperf3 ({s}) written/updated at {s}/{s}", .{ iperf3_bin_name, self_dir, iperf3_bin_name });
    } else |err| {
        std.log.warn("ensureBundledIperf3: failed to write {s}: {any} (will retry next startup)", .{ iperf3_bin_name, err });
    }

    if (ensureFileMatches(allocator, self_dir, iperf3_license_name, iperf3_license, false)) |updated| {
        if (updated) std.log.info("Bundled {s} written/updated at {s}/{s}", .{ iperf3_license_name, self_dir, iperf3_license_name });
    } else |err| {
        std.log.warn("ensureBundledIperf3: failed to write {s}: {any} (will retry next startup)", .{ iperf3_license_name, err });
    }
}
