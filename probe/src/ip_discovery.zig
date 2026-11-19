const std = @import("std");
const builtin = @import("builtin");
const debug = @import("debug.zig");

const IpVersion = enum { ipv4, ipv6 };

const ReflectionService = struct {
    host: []const u8,
    path: []const u8,
};

const ipv6_services = [_]ReflectionService{
    .{ .host = "api6.ipify.org", .path = "/?format=text" },
    .{ .host = "ipv6.icanhazip.com", .path = "/" },
};

/// How long the hello waits for IPv6 discovery. A host with an IPv6 route but
/// no working IPv6 internet (common: a ULA-only LAN such as libvirt's
/// fd00:122::/64, or a broken ISP IPv6) makes every IPv6 connect wait out the
/// OS TCP connect timeout (~21 s per address on Windows, ~127 s on Linux).
/// Waiting for that synchronously delayed the hello, and so the probe's
/// registration with the Core, by ~42 s on every cold start of a Windows test machine; tests sent
/// in that window failed with ProbeNotConnected. A working
/// IPv6 path answers in well under a second.
const IPV6_WAIT_MS: u64 = 5000;

pub fn discoverPublicIp(allocator: std.mem.Allocator) !struct { ipv4: ?[]u8, ipv6: ?[]u8 } {
    // IPv6 runs on its own thread so it overlaps the IPv4 lookup and can be
    // abandoned at the deadline. IPv4 is still waited for in full: the Core
    // needs it for inter-probe tests and the map.
    const v6_job = Ipv6Job.start();

    const ipv4 = discoverAddress(allocator, .ipv4, &.{
        .{ .host = "api.ipify.org", .path = "/?format=text" },
        .{ .host = "checkip.amazonaws.com", .path = "/" },
        .{ .host = "ipv4.icanhazip.com", .path = "/" },
        .{ .host = "ifconfig.me", .path = "/ip" },
        .{ .host = "1.1.1.1", .path = "/cdn-cgi/trace" },
    }) catch |err| blk: {
        std.log.warn("IP discovery IPv4 failed on all services: {any}", .{err});
        break :blk null;
    };

    const ipv6 = if (v6_job) |job| job.finish(allocator, IPV6_WAIT_MS) else null;

    debug.debug("Discovered public IPs: ipv4={?s}, ipv6={?s}", .{ ipv4, ipv6 });
    return .{ .ipv4 = ipv4, .ipv6 = ipv6 };
}

/// One in-flight IPv6 lookup at a time: a lookup abandoned at the deadline
/// keeps running until its connects time out, and a reconnect loop must not
/// stack more of them behind it.
var g_ipv6_in_flight = std.atomic.Value(bool).init(false);

/// Shared between discoverPublicIp and the lookup thread. Whichever side
/// finishes last frees it: the caller when the result arrived in time, the
/// thread when the caller gave up (abandoned).
const Ipv6Job = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    done: bool = false,
    abandoned: bool = false,
    result: ?[]u8 = null, // page_allocator-owned

    const pa = std.heap.page_allocator;

    fn start() ?*Ipv6Job {
        if (g_ipv6_in_flight.swap(true, .acq_rel)) {
            debug.debug("IP discovery IPv6 skipped: a previous lookup is still running", .{});
            return null;
        }
        const job = pa.create(Ipv6Job) catch {
            g_ipv6_in_flight.store(false, .release);
            return null;
        };
        job.* = .{};
        const t = std.Thread.spawn(.{}, run, .{job}) catch {
            pa.destroy(job);
            g_ipv6_in_flight.store(false, .release);
            return null;
        };
        t.detach();
        return job;
    }

    fn run(job: *Ipv6Job) void {
        const result = discoverAddress(pa, .ipv6, &ipv6_services) catch |err| blk: {
            debug.debug("IP discovery IPv6 failed on all services: {any}", .{err});
            break :blk null;
        };
        g_ipv6_in_flight.store(false, .release);
        job.mutex.lock();
        if (job.abandoned) {
            job.mutex.unlock();
            if (result) |r| {
                debug.debug("IP discovery IPv6 finished after the hello was sent: {s}", .{r});
                pa.free(r);
            }
            pa.destroy(job);
            return;
        }
        job.result = result;
        job.done = true;
        job.cond.signal();
        job.mutex.unlock();
    }

    /// Waits up to timeout_ms for the result, copied into `allocator`.
    fn finish(job: *Ipv6Job, allocator: std.mem.Allocator, timeout_ms: u64) ?[]u8 {
        const deadline = std.time.nanoTimestamp() + @as(i128, timeout_ms) * std.time.ns_per_ms;
        job.mutex.lock();
        while (!job.done) {
            const left = deadline - std.time.nanoTimestamp();
            if (left <= 0) break;
            job.cond.timedWait(&job.mutex, @intCast(left)) catch {};
        }
        if (!job.done) {
            job.abandoned = true;
            job.mutex.unlock();
            std.log.info("IP discovery IPv6 gave no answer within {d} ms; sending hello without a public IPv6", .{timeout_ms});
            return null;
        }
        const result = job.result;
        job.mutex.unlock();
        pa.destroy(job);
        const r = result orelse return null;
        defer pa.free(r);
        return allocator.dupe(u8, r) catch null;
    }
};

fn discoverAddress(allocator: std.mem.Allocator, version: IpVersion, services: []const ReflectionService) ![]u8 {
    var last_err: anyerror = error.NoReflectionService;

    for (services) |service| {
        const body = fetchHttpText(allocator, service.host, service.path) catch |err| {
            debug.debug("IP discovery service {s}{s} failed: {any}", .{ service.host, service.path, err });
            last_err = err;
            continue;
        };
        defer allocator.free(body);

        const ip = extractIp(allocator, body, version) catch |err| {
            debug.debug("IP discovery service {s}{s} returned unusable body: {any}", .{ service.host, service.path, err });
            last_err = err;
            continue;
        };

        debug.debug("IP discovery service {s}{s} returned {s}", .{ service.host, service.path, ip });
        return ip;
    }

    return last_err;
}

fn fetchHttpText(allocator: std.mem.Allocator, host: []const u8, path: []const u8) ![]u8 {
    const port: u16 = 80;
    debug.debug("Fetching public IP from {s}:{d}{s}", .{ host, port, path });
    const stream = std.net.tcpConnectToHost(allocator, host, port) catch |err| {
        debug.debug("tcpConnectToHost failed for {s}: {any}", .{ host, err });
        return err;
    };
    defer stream.close();
    // These are plaintext-HTTP public-IP reflection services; an endpoint (or
    // on-path captive portal) that accepts and never replies must not hang the
    // WSS connect path forever. 5s per blocking read/write attempt.
    _ = @import("wss_client.zig").setSocketRecvTimeout(stream, 5000);
    _ = @import("wss_client.zig").setSocketSendTimeout(stream, 5000);

    const req = try std.fmt.allocPrint(allocator,
        "GET {s} HTTP/1.0\r\n" ++
        "Host: {s}\r\n" ++
        "User-Agent: Linknesis/1.0\r\n" ++
        "Accept: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "\r\n", .{ path, host });
    defer allocator.free(req);

    try writeAllStream(stream, req);

    var resp_buf: [4096]u8 = undefined;
    var resp_len: usize = 0;
    while (resp_len < resp_buf.len) {
        const n = readStream(stream, resp_buf[resp_len..]) catch break;
        if (n == 0) break;
        resp_len += n;
    }

    const resp = resp_buf[0..resp_len];
    debug.debug("HTTP response from {s}: {d} bytes", .{ host, resp_len });
    const body_start = std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return error.NoBody;
    const first_line_end = std.mem.indexOfScalar(u8, resp[0..body_start], '\n') orelse body_start;
    const first_line = std.mem.trim(u8, resp[0..first_line_end], " \r\n\t");
    if (!std.mem.containsAtLeast(u8, first_line, 1, " 200 ")) return error.HttpStatusNotOk;

    const body = std.mem.trim(u8, resp[body_start + 4 ..], " \r\n\t");
    if (body.len == 0) return error.EmptyBody;
    debug.debug("Got IP body from {s}: {s}", .{ host, body });
    return try allocator.dupe(u8, body);
}

fn readStream(stream: std.net.Stream, buf: []u8) !usize {
    if (builtin.os.tag == .windows) {
        const ws2_32 = std.os.windows.ws2_32;
        const max_len = @min(buf.len, std.math.maxInt(c_int));
        const result = ws2_32.recv(stream.handle, buf.ptr, @intCast(max_len), 0);
        if (result == ws2_32.SOCKET_ERROR) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAECONNRESET => error.ConnectionResetByPeer,
                .WSAECONNABORTED => error.ConnectionAborted,
                .WSAEWOULDBLOCK => error.WouldBlock,
                else => error.Unexpected,
            };
        }
        return @intCast(result);
    }

    return stream.read(buf);
}

fn writeAllStream(stream: std.net.Stream, buf: []const u8) !void {
    if (builtin.os.tag == .windows) {
        const ws2_32 = std.os.windows.ws2_32;
        var sent: usize = 0;
        while (sent < buf.len) {
            const remaining = @min(buf.len - sent, std.math.maxInt(c_int));
            const result = ws2_32.send(stream.handle, buf.ptr + sent, @intCast(remaining), 0);
            if (result == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAECONNRESET => error.ConnectionResetByPeer,
                    .WSAECONNABORTED => error.ConnectionAborted,
                    .WSAEWOULDBLOCK => error.WouldBlock,
                    else => error.Unexpected,
                };
            }
            if (result == 0) return error.ConnectionClosed;
            sent += @intCast(result);
        }
        return;
    }

    try stream.writeAll(buf);
}

fn extractIp(allocator: std.mem.Allocator, body: []const u8, version: IpVersion) ![]u8 {
    const trimmed = std.mem.trim(u8, body, " \r\n\t");
    if (isValidAddress(trimmed, version)) return try allocator.dupe(u8, trimmed);

    var lines = std.mem.splitScalar(u8, trimmed, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \r\n\t");
        if (std.mem.startsWith(u8, line, "ip=")) {
            const ip = std.mem.trim(u8, line[3..], " \r\n\t");
            if (isValidAddress(ip, version)) return try allocator.dupe(u8, ip);
        }
    }

    return error.InvalidIpDiscoveryBody;
}

fn isValidAddress(value: []const u8, version: IpVersion) bool {
    switch (version) {
        .ipv4 => {
            _ = std.net.Address.parseIp4(value, 0) catch return false;
            return true;
        },
        .ipv6 => {
            _ = std.net.Address.parseIp6(value, 0) catch return false;
            return true;
        },
    }
}

pub fn discoverPrivateIpv4(allocator: std.mem.Allocator) !?[]u8 {
    if (builtin.os.tag == .windows) {
        return try discoverPrivateIpv4Windows(allocator);
    } else {
        return try discoverPrivateIpv4Posix(allocator);
    }
}

fn isPrivateIpv4(octets: [4]u8) bool {
    // 10.0.0.0/8
    if (octets[0] == 10) return true;
    // 172.16.0.0/12
    if (octets[0] == 172 and octets[1] >= 16 and octets[1] <= 31) return true;
    // 192.168.0.0/16
    if (octets[0] == 192 and octets[1] == 168) return true;
    // 169.254.0.0/16 (link-local)
    if (octets[0] == 169 and octets[1] == 254) return true;
    return false;
}

fn formatIpv4(allocator: std.mem.Allocator, octets: [4]u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ octets[0], octets[1], octets[2], octets[3] });
}

// Well-known virtual/bridge interface name prefixes (Docker, libvirt, LXC/LXD,
// Kubernetes CNI, veth pairs). Addresses on these are container-network
// artifacts (e.g. docker0's 172.17.0.1), not addresses anyone uses to reach
// the probe host, so they must not win the "private IPv4" slot.
fn isVirtualIfaceName(name: []const u8) bool {
    const prefixes = [_][]const u8{ "docker", "br-", "virbr", "veth", "lxcbr", "lxdbr", "lxc", "cni", "flannel", "kube", "cbr" };
    for (prefixes) |p| {
        if (std.mem.startsWith(u8, name, p)) return true;
    }
    return false;
}

fn discoverPrivateIpv4Posix(allocator: std.mem.Allocator) !?[]u8 {
    const c = @cImport({
        @cInclude("ifaddrs.h");
        @cInclude("netinet/in.h");
    });
    var ifap: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&ifap) != 0) return null;
    defer if (ifap) |p| c.freeifaddrs(p);

    // Preference tiers: RFC1918 on a real interface wins immediately; then the
    // first non-loopback real-interface address; a virtual-bridge RFC1918
    // address is only a last resort so a host with nothing else still reports
    // something.
    var first_non_loopback: ?[]u8 = null;
    var virtual_private: ?[]u8 = null;
    var it = ifap;
    while (it) |ifa| : (it = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if (ifa.ifa_addr.*.sa_family != c.AF_INET) continue;
        const if_name: []const u8 = if (ifa.ifa_name != null) std.mem.sliceTo(ifa.ifa_name, 0) else "";
        const is_virtual = isVirtualIfaceName(if_name);
        const addr = @as(*c.struct_sockaddr_in, @ptrCast(@alignCast(ifa.ifa_addr)));
        const ip_bytes = @as([4]u8, @bitCast(addr.sin_addr.s_addr));
        if (ip_bytes[0] == 127) continue;
        const ip_str = try formatIpv4(allocator, ip_bytes);
        if (isPrivateIpv4(ip_bytes)) {
            if (!is_virtual) {
                if (first_non_loopback) |prev| allocator.free(prev);
                if (virtual_private) |prev| allocator.free(prev);
                return ip_str;
            }
            if (virtual_private == null) {
                virtual_private = ip_str;
            } else {
                allocator.free(ip_str);
            }
            continue;
        }
        if (!is_virtual and first_non_loopback == null) {
            first_non_loopback = ip_str;
        } else {
            allocator.free(ip_str);
        }
    }
    if (first_non_loopback) |v| {
        if (virtual_private) |prev| allocator.free(prev);
        return v;
    }
    return virtual_private;
}

pub fn discoverPrivateIpv6(allocator: std.mem.Allocator) !?[]u8 {
    if (builtin.os.tag == .windows) {
        return try discoverPrivateIpv6Windows(allocator);
    } else {
        return try discoverPrivateIpv6Posix(allocator);
    }
}

fn isUsableLocalIpv6(b: [16]u8) bool {
    // Skip unspecified (::) and loopback (::1).
    var all_zero = true;
    for (b[0..15]) |x| {
        if (x != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero and (b[15] == 0 or b[15] == 1)) return false;
    // Skip link-local fe80::/10 -- meaningless off-link and needs a %scope.
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return false;
    // Skip IPv4-mapped ::ffff:a.b.c.d.
    if (b[0] == 0 and b[1] == 0 and b[2] == 0 and b[3] == 0 and
        b[4] == 0 and b[5] == 0 and b[6] == 0 and b[7] == 0 and
        b[8] == 0 and b[9] == 0 and b[10] == 0xff and b[11] == 0xff) return false;
    return true;
}

fn formatIpv6(allocator: std.mem.Allocator, b: [16]u8) !?[]u8 {
    // std.net.Address.format renders "[addr]:port"; strip the wrapper.
    const addr = std.net.Address.initIp6(b, 0, 0, 0);
    var buf: [64]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{f}", .{addr}) catch return null;
    const start: usize = if (std.mem.startsWith(u8, formatted, "[")) 1 else 0;
    const end = std.mem.lastIndexOfScalar(u8, formatted, ']') orelse formatted.len;
    return try allocator.dupe(u8, formatted[start..end]);
}

fn discoverPrivateIpv6Posix(allocator: std.mem.Allocator) !?[]u8 {
    const c = @cImport({
        @cInclude("ifaddrs.h");
        @cInclude("netinet/in.h");
    });
    var ifap: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&ifap) != 0) return null;
    defer if (ifap) |p| c.freeifaddrs(p);

    // Prefer a global unicast address (2000::/3); fall back to a ULA
    // (fc00::/7). Link-local and loopback are skipped entirely.
    var fallback_ula: ?[]u8 = null;
    errdefer if (fallback_ula) |f| allocator.free(f);
    var it = ifap;
    while (it) |ifa| : (it = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if (ifa.ifa_addr.*.sa_family != c.AF_INET6) continue;
        const addr6 = @as(*c.struct_sockaddr_in6, @ptrCast(@alignCast(ifa.ifa_addr)));
        const b = @as([16]u8, @bitCast(addr6.sin6_addr));
        if (!isUsableLocalIpv6(b)) continue;
        const is_global = (b[0] & 0xe0) == 0x20; // 2000::/3
        const is_ula = (b[0] & 0xfe) == 0xfc; // fc00::/7
        if (is_global) {
            const s = (try formatIpv6(allocator, b)) orelse continue;
            if (fallback_ula) |f| allocator.free(f);
            return s;
        }
        if (is_ula and fallback_ula == null) {
            fallback_ula = (try formatIpv6(allocator, b)) orelse null;
        }
    }
    return fallback_ula;
}

fn discoverPrivateIpv6Windows(allocator: std.mem.Allocator) !?[]u8 {
    // UDP-connect trick: connecting a UDP socket sends no packets; the stack
    // just selects the local source address it would use to reach the target,
    // which getsockname then reports. Far simpler and less fragile than
    // hand-declaring the large IP_ADAPTER_ADDRESSES struct for
    // GetAdaptersAddresses.
    const ws2_32 = std.os.windows.ws2_32;
    const SockaddrIn6 = extern struct {
        family: u16,
        port: u16,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };
    const AF_INET6: i32 = 23;
    const SOCK_DGRAM: i32 = 2;

    const sock = ws2_32.socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock == ws2_32.INVALID_SOCKET) return null;
    defer _ = ws2_32.closesocket(sock);

    // Cloudflare public DNS over IPv6; any global address works, it is never
    // actually contacted.
    const target_addr = std.net.Address.parseIp6("2606:4700:4700::1111", 53) catch return null;
    var target = SockaddrIn6{
        .family = @intCast(AF_INET6),
        .port = std.mem.nativeToBig(u16, 53),
        .flowinfo = 0,
        .addr = target_addr.in6.sa.addr,
        .scope_id = 0,
    };
    if (ws2_32.connect(sock, @ptrCast(&target), @sizeOf(SockaddrIn6)) == ws2_32.SOCKET_ERROR) {
        return null; // no IPv6 route/connectivity
    }
    var local: SockaddrIn6 = undefined;
    var len: i32 = @sizeOf(SockaddrIn6);
    if (ws2_32.getsockname(sock, @ptrCast(&local), &len) == ws2_32.SOCKET_ERROR) return null;
    if (local.family != AF_INET6) return null;
    if (!isUsableLocalIpv6(local.addr)) return null;
    return try formatIpv6(allocator, local.addr);
}

fn discoverPrivateIpv4Windows(allocator: std.mem.Allocator) !?[]u8 {
    const IP_ADDR_STRING = extern struct {
        Next: ?*@This(),
        IpAddress: [16]u8,
        IpMask: [16]u8,
        Context: c_ulong,
    };
    const IP_ADAPTER_INFO = extern struct {
        Next: ?*@This(),
        ComboIndex: c_ulong,
        AdapterName: [260]u8,
        Description: [132]u8,
        AddressLength: c_uint,
        Address: [8]u8,
        Index: c_ulong,
        Type: c_uint,
        DhcpEnabled: c_uint,
        CurrentIpAddress: ?*IP_ADDR_STRING,
        IpAddressList: IP_ADDR_STRING,
        GatewayList: IP_ADDR_STRING,
        DhcpServer: IP_ADDR_STRING,
        HaveWins: c_int,
        PrimaryWinsServer: IP_ADDR_STRING,
        SecondaryWinsServer: IP_ADDR_STRING,
        LeaseObtained: c_ulong,
        LeaseExpires: c_ulong,
    };
    const GetAdaptersInfo = struct {
        extern "iphlpapi" fn GetAdaptersInfo(
            AdapterInfo: ?*IP_ADAPTER_INFO,
            SizePointer: *c_ulong,
        ) callconv(.winapi) c_ulong;
    }.GetAdaptersInfo;

    var buf_len: c_ulong = 0;
    _ = GetAdaptersInfo(null, &buf_len);
    if (buf_len == 0) return null;

    const buf = try allocator.alloc(u8, buf_len);
    defer allocator.free(buf);
    const ret = GetAdaptersInfo(@ptrCast(@alignCast(buf.ptr)), &buf_len);
    if (ret != 0) {
        std.log.warn("GetAdaptersInfo failed: {d}", .{ret});
        return null;
    }

    // Host-side virtual adapter descriptions to deprioritize. Deliberately
    // narrow so guest paravirtual NICs are NOT matched: a probe running inside
    // a VM uses e.g. "Red Hat VirtIO Ethernet Adapter" or "vmxnet3 Ethernet
    // Adapter", which must stay eligible.
    const virtual_descs = [_][]const u8{
        "hyper-v virtual", "vmware virtual ethernet adapter", "virtualbox host-only", "tap-windows", "loopback",
    };

    var first_non_loopback: ?[]u8 = null;
    var virtual_private: ?[]u8 = null;
    defer if (virtual_private) |v| allocator.free(v);
    var adapter: ?*IP_ADAPTER_INFO = @ptrCast(@alignCast(buf.ptr));
    while (adapter) |a| : (adapter = a.Next) {
        var desc_lower_buf: [132]u8 = undefined;
        const desc = std.mem.sliceTo(&a.Description, 0);
        const desc_lower = std.ascii.lowerString(desc_lower_buf[0..desc.len], desc);
        var is_virtual = false;
        for (virtual_descs) |vd| {
            if (std.mem.indexOf(u8, desc_lower, vd) != null) {
                is_virtual = true;
                break;
            }
        }
        var addr: ?*IP_ADDR_STRING = &a.IpAddressList;
        while (addr) |item| : (addr = item.Next) {
            const ip_cstr = std.mem.sliceTo(&item.IpAddress, 0);
            if (ip_cstr.len == 0) continue;
            const ip_parsed = std.net.Address.parseIp4(ip_cstr, 0) catch continue;
            const ip = ip_parsed.in.sa.addr;
            const ip_bytes = @as([4]u8, @bitCast(ip));
            if (ip_bytes[0] == 127) continue;
            const ip_str = try formatIpv4(allocator, ip_bytes);
            if (isPrivateIpv4(ip_bytes)) {
                if (!is_virtual) {
                    if (first_non_loopback) |prev| allocator.free(prev);
                    return ip_str;
                }
                if (virtual_private == null) {
                    virtual_private = ip_str;
                } else {
                    allocator.free(ip_str);
                }
                continue;
            }
            if (!is_virtual and first_non_loopback == null) {
                first_non_loopback = ip_str;
            } else {
                allocator.free(ip_str);
            }
        }
    }
    if (first_non_loopback) |v| return v;
    if (virtual_private) |v| {
        virtual_private = null; // ownership transferred to caller; defer must not free
        return v;
    }
    return null;
}

test "Ipv6Job hands over a finished result and frees itself" {
    const job = try std.heap.page_allocator.create(Ipv6Job);
    job.* = .{};
    job.result = try std.heap.page_allocator.dupe(u8, "2001:db8::1");
    job.done = true;
    const r = job.finish(std.testing.allocator, 10).?;
    defer std.testing.allocator.free(r);
    try std.testing.expectEqualStrings("2001:db8::1", r);
}

test "Ipv6Job times out when no result arrives" {
    const job = try std.heap.page_allocator.create(Ipv6Job);
    job.* = .{};
    const t0 = std.time.milliTimestamp();
    try std.testing.expect(job.finish(std.testing.allocator, 50) == null);
    try std.testing.expect(std.time.milliTimestamp() - t0 >= 45);
    // finish() marked it abandoned; the lookup thread would free it.
    try std.testing.expect(job.abandoned);
    std.heap.page_allocator.destroy(job);
}
