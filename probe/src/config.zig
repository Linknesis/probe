const std = @import("std");

pub const Config = struct {
    uuid: ?[]u8 = null,
    // No built-in default: every install passes --core (installers always do),
    // and main() refuses to start without one rather than dialing a hardcoded host.
    core_address: []const u8 = "",
    hash: []const u8 = "changeme",
};

var g_config: Config = .{};
var g_allocator: std.mem.Allocator = undefined;
var g_config_path_buf: [512]u8 = undefined;
var g_config_path: ?[]const u8 = null;
var g_data_dir_override: ?[]const u8 = null;
var g_label: ?[]const u8 = null;

// Called from main() before load(), when --data-dir is set, so multiple probe
// instances on one host (each given a distinct data dir) get their own
// state.json instead of colliding on the default /var/lib/linknesis path.
// Linux only -- Windows already keys its config.json off the exe's own
// directory, so instances there are naturally isolated by install location.
pub fn setDataDir(dir: []const u8, allocator: std.mem.Allocator) !void {
    g_data_dir_override = try allocator.dupe(u8, dir);
}

// Called from main() when --label is set. Not persisted to state.json --
// the Core only ever consults hello's label field the one time a uuid is
// genuinely new (see ws_server.zig's hello handler), so this only needs to
// be available at process-start time on every run; the installer bakes
// --label into the systemd unit's ExecStart the same way it does --core/
// --hash, so a service restart still sends it, harmlessly ignored by the
// Core once the probe is already registered.
pub fn setLabel(label: []const u8, allocator: std.mem.Allocator) !void {
    g_label = try allocator.dupe(u8, label);
}

pub fn getLabel() ?[]const u8 {
    return g_label;
}

fn getConfigPath() []const u8 {
    if (g_config_path) |p| return p;
    if (@import("builtin").os.tag == .windows) {
        var exe_path_w: [260]u16 = undefined;
        @memset(&exe_path_w, 0);
        const len = std.os.windows.kernel32.GetModuleFileNameW(null, &exe_path_w, exe_path_w.len);
        if (len > 0 and len < exe_path_w.len) {
            var tmp: [512]u8 = undefined;
            if (std.unicode.utf16LeToUtf8(&tmp, exe_path_w[0..len])) |exe_len| {
                const exe_utf8 = tmp[0..exe_len];
                if (std.fs.path.dirname(exe_utf8)) |dir| {
                    if (std.fmt.bufPrint(&g_config_path_buf, "{s}\\config.json", .{dir})) |p| {
                        g_config_path = p;
                        return p;
                    } else |_| {}
                }
            } else |_| {}
        }
        // Fallback to legacy path if exe directory cannot be determined.
        g_config_path = "C:\\linknesis\\config.json";
        return g_config_path.?;
    }
    if (g_data_dir_override) |dir| {
        if (std.fmt.bufPrint(&g_config_path_buf, "{s}/state.json", .{dir})) |p| {
            g_config_path = p;
            return p;
        } else |_| {}
    }
    g_config_path = "/var/lib/linknesis/state.json";
    return g_config_path.?;
}

pub fn load(allocator: std.mem.Allocator) !void {
    g_allocator = allocator;
    const path = getConfigPath();
    const data = std.fs.cwd().readFileAlloc(allocator, path, 4096) catch |err| {
        if (err == error.FileNotFound) {
            g_config.uuid = try allocator.dupe(u8, try generateUuid(allocator));
            return;
        }
        return err;
    };
    defer allocator.free(data);
    const parsed = try std.json.parseFromSlice(Config, allocator, data, .{});
    defer parsed.deinit();
    g_config.uuid = if (parsed.value.uuid) |u| try allocator.dupe(u8, u) else null;
    // A config that exists and parses but lacks a uuid (truncated/disk-full
    // write, hand edit, older version) used to leave uuid null and panic
    // main() on every start with no recovery; heal it like a first boot.
    if (g_config.uuid == null) {
        g_config.uuid = try allocator.dupe(u8, try generateUuid(allocator));
    }
    g_config.core_address = try allocator.dupe(u8, parsed.value.core_address);
    g_config.hash = try allocator.dupe(u8, parsed.value.hash);
}

pub fn save(allocator: std.mem.Allocator) !void {
    const path = getConfigPath();
    if (std.fs.path.dirname(path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    const json_str = try std.json.Stringify.valueAlloc(allocator, g_config, .{});
    defer allocator.free(json_str);
    try file.writeAll(json_str);
    try file.writeAll("\n");
}

fn generateUuid(allocator: std.mem.Allocator) ![]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    var out = try allocator.alloc(u8, 36);
    const hex_chars = "0123456789abcdef";
    var i: usize = 0;
    var j: usize = 0;
    while (i < 16) : (i += 1) {
        out[j] = hex_chars[bytes[i] >> 4];
        out[j + 1] = hex_chars[bytes[i] & 0x0F];
        j += 2;
        if (i == 3 or i == 5 or i == 7 or i == 9) {
            out[j] = '-';
            j += 1;
        }
    }
    return out;
}

pub fn get() *const Config {
    return &g_config;
}

pub fn setCoreAddress(addr: []const u8, allocator: std.mem.Allocator) !void {
    g_config.core_address = try allocator.dupe(u8, addr);
}

pub fn setHash(h: []const u8, allocator: std.mem.Allocator) !void {
    g_config.hash = try allocator.dupe(u8, h);
}

const testing = std.testing;

test "generateUuid: produces a well-formed v4 UUID" {
    const allocator = testing.allocator;
    const id = try generateUuid(allocator);
    defer allocator.free(id);
    try testing.expectEqual(@as(usize, 36), id.len);
    try testing.expectEqual(@as(u8, '-'), id[8]);
    try testing.expectEqual(@as(u8, '-'), id[13]);
    try testing.expectEqual(@as(u8, '-'), id[18]);
    try testing.expectEqual(@as(u8, '-'), id[23]);
    try testing.expectEqual(@as(u8, '4'), id[14]); // RFC 4122 version nibble
    try testing.expect(id[19] == '8' or id[19] == '9' or id[19] == 'a' or id[19] == 'b'); // variant nibble
}

test "generateUuid: two calls never collide" {
    const allocator = testing.allocator;
    const a = try generateUuid(allocator);
    defer allocator.free(a);
    const b = try generateUuid(allocator);
    defer allocator.free(b);
    try testing.expect(!std.mem.eql(u8, a, b));
}

// The two tests below drive load()/save() through the real global Config
// singleton and real filesystem I/O (via a --data-dir override pointed at a
// temp dir) rather than testing a pure function -- this module was never
// designed to free g_config's previous heap values on reassignment (it's a
// process-lifetime singleton in production, so that's a non-issue there).
// Use page_allocator here instead of testing.allocator so the test verifies
// real load()/save() behavior without fighting that pre-existing, harmless
// leak-on-reassignment shape with per-call frees the production code itself
// doesn't do.
fn resetGlobalConfigStateForTest() void {
    g_config = .{};
    g_config_path = null;
    g_data_dir_override = null;
}

test "load/save round-trip: first boot generates a uuid, a reload preserves everything" {
    const allocator = std.heap.page_allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs_dir = try tmp.dir.realpathAlloc(allocator, ".");

    resetGlobalConfigStateForTest();
    try setDataDir(abs_dir, allocator);

    // First boot: no state.json yet -- load() must generate a fresh uuid
    // rather than error.
    try load(allocator);
    try testing.expect(g_config.uuid != null);
    const first_uuid = try allocator.dupe(u8, g_config.uuid.?);

    try setCoreAddress("wss://example.com:4443", allocator);
    try setHash("deadbeef", allocator);
    try save(allocator);

    // Simulate a fresh process picking the same state.json back up.
    resetGlobalConfigStateForTest();
    try setDataDir(abs_dir, allocator);
    try load(allocator);

    try testing.expectEqualStrings(first_uuid, g_config.uuid.?);
    try testing.expectEqualStrings("wss://example.com:4443", g_config.core_address);
    try testing.expectEqualStrings("deadbeef", g_config.hash);
}

test "load: a config that parses but has no uuid field self-heals instead of leaving uuid null" {
    // Regression test for a real fixed incident (see this file's load()
    // comment): a truncated/disk-full write or hand-edited state.json that
    // parses fine but is missing "uuid" used to leave config.uuid null and
    // panic main() on every subsequent start with no recovery path.
    const allocator = std.heap.page_allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs_dir = try tmp.dir.realpathAlloc(allocator, ".");

    try tmp.dir.writeFile(.{
        .sub_path = "state.json",
        .data = "{\"core_address\":\"wss://x.example:4443\",\"hash\":\"h\"}",
    });

    resetGlobalConfigStateForTest();
    try setDataDir(abs_dir, allocator);
    try load(allocator);

    try testing.expect(g_config.uuid != null);
    try testing.expectEqual(@as(usize, 36), g_config.uuid.?.len);
    try testing.expectEqualStrings("wss://x.example:4443", g_config.core_address);
}
