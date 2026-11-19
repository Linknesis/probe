const std = @import("std");
const wss_client = @import("wss_client.zig");
const config = @import("config.zig");
const debug = @import("debug.zig");

var g_allocator: std.mem.Allocator = undefined;
const RunningTest = struct {
    id: []u8,
    active: bool,
    generation: u64,
};
var g_running: std.ArrayList(RunningTest) = .{};
var g_generations: std.StringHashMap(u64) = undefined;
var g_mutex = std.Thread.Mutex{};

pub fn init(allocator: std.mem.Allocator) void {
    g_allocator = allocator;
    g_generations = std.StringHashMap(u64).init(allocator);
}

fn icmpChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += std.mem.readInt(u16, data[i..][0..2], .big);
    }
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return @intCast(~sum & 0xFFFF);
}

fn buildIcmpEchoPacket(id: u16, seq: u16, payload: []const u8) ![]u8 {
    const len = 8 + payload.len;
    const pkt = try g_allocator.alloc(u8, len);
    pkt[0] = 8; // Echo Request
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    std.mem.writeInt(u16, pkt[4..6], id, .big);
    std.mem.writeInt(u16, pkt[6..8], seq, .big);
    @memcpy(pkt[8..], payload);
    const cs = icmpChecksum(pkt);
    std.mem.writeInt(u16, pkt[2..4], cs, .big);
    return pkt;
}

// ICMPv6 Echo Request. Unlike ICMPv4, the checksum is left as zero: Linux
// mandates and automatically computes/fills the ICMPv6 checksum on send for
// raw ICMPv6 sockets (RFC 8200 requires it), including the IPv6 pseudo-header
// which userspace cannot easily compute without knowing the actual source
// address the kernel will pick.
fn buildIcmp6EchoPacket(id: u16, seq: u16, payload: []const u8) ![]u8 {
    const len = 8 + payload.len;
    const pkt = try g_allocator.alloc(u8, len);
    pkt[0] = 128; // Echo Request (ICMPv6)
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    std.mem.writeInt(u16, pkt[4..6], id, .big);
    std.mem.writeInt(u16, pkt[6..8], seq, .big);
    @memcpy(pkt[8..], payload);
    return pkt;
}

// Formats an ICMP source address for a hop report. std.net.Address has a
// custom `format` method that must be invoked with the `{f}` specifier in
// Zig 0.15 -- `{any}` bypasses it and dumps the raw struct fields instead,
// which is what was actually happening for every non-IPv4 (i.e. IPv6) hop:
// the "IP" shown was a debug struct dump like
// ".{ .any = .{ .family = 10, ... }" instead of a real IPv6 address.
// Address.format renders as "[addr]:port"; strip the brackets/port since
// callers only want the bare address.
fn formatSrcIp(pa: std.mem.Allocator, src_ip: std.net.Address) ?[]u8 {
    if (src_ip.any.family == std.posix.AF.INET) {
        const ip_addr = @as(u32, @bitCast(src_ip.in.sa.addr));
        return std.fmt.allocPrint(pa, "{d}.{d}.{d}.{d}", .{
            (ip_addr >> 0) & 0xFF,
            (ip_addr >> 8) & 0xFF,
            (ip_addr >> 16) & 0xFF,
            (ip_addr >> 24) & 0xFF,
        }) catch null;
    }
    var buf: [64]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{f}", .{src_ip}) catch return null;
    const start: usize = if (std.mem.startsWith(u8, formatted, "[")) 1 else 0;
    const end = std.mem.lastIndexOfScalar(u8, formatted, ']') orelse formatted.len;
    return pa.dupe(u8, formatted[start..end]) catch null;
}

// How many cycles' worth of per-hop latency samples to let accumulate
// before the probe self-resets them. Without this, hop_latencies (one
// std.ArrayList(u64) per hop) grows forever for the life of one continuous
// run -- a permanent/unlimited (counts=0) test never calls into any of the
// run* functions again, so nothing ever shrinks it. Every single cycle
// re-serializes and re-sends the WHOLE history-so-far for every hop in
// that cycle's test_result message, not just the newest sample (Core's
// db.upsertMtrHopStats() needs the cumulative shape to compute deltas via
// prev_lat_len). That means both probe memory and per-cycle WS message
// size grow unboundedly with test duration: at a typical 1s interval and a
// modest hop count, a single message crosses the 16 MiB WS frame cap
// (MAX_WS_FRAME_SIZE in wss_client.zig/ws_server.zig) within roughly one
// to a few weeks, after which the frame is rejected and the connection is
// torn down -- and since a plain reconnect does NOT restart this loop
// (only a genuine probe process crash/restart does), the test gets stuck
// silently failing to report, in a repeating disconnect loop, with no
// self-recovery.
//
// The reset below only ever touches the PROBE's own local counters, never
// Core's persisted totals: db.upsertMtrHopStats() already maintains
// sum_ms/sum_sq_ms/sent_total/etc. as running $inc/$min/$max accumulators
// in Mongo, entirely independent of what's in any one wire message.
// Resetting hop_sent/hop_latencies together makes the next cycle's
// sent/latencies-length values smaller than the previous cycle's, which
// upsertMtrHopStats already treats as a "new run" boundary (`h.sent <
// prev.prev_sent or lat_len_i64 < prev.prev_lat_len`) -- the exact same
// heuristic a real pause/resume already relies on -- so the Core-side
// accumulate-forever totals are completely unaffected by this; only the
// redundant, ever-growing per-message history gets discarded.
const MTR_LATENCY_TRIM_CYCLES: i64 = 3600;

fn maybeResetHopHistory(test_id: []const u8, cycle: i64, hop_latencies: *std.ArrayList(std.ArrayList(u64)), hop_sent: *std.ArrayList(u32)) void {
    if (cycle <= 0 or @rem(cycle, MTR_LATENCY_TRIM_CYCLES) != 0) return;
    for (hop_latencies.items) |*lat| lat.clearRetainingCapacity();
    for (hop_sent.items) |*s| s.* = 0;
    // Deliberately logged (not silent): this is the one piece of this fix
    // that can't be confirmed from Core-side symptoms alone -- Core's own
    // accumulated totals never show any sign a reset happened. A grep for
    // this line in a real permanent test's probe log is the way to confirm
    // it's actually firing on schedule rather than trusting the arithmetic.
    std.log.info("MTR hop history self-reset test_id={s} cycle={d}", .{ test_id, cycle });
}

fn putStringMtr(pa: std.mem.Allocator, root: *std.json.ObjectMap, key: []const u8, value: []const u8) void {
    const k = pa.dupe(u8, key) catch return;
    const v = pa.dupe(u8, value) catch { pa.free(k); return; };
    root.put(k, .{ .string = v }) catch { pa.free(k); pa.free(v); };
}

fn sendTestError(test_id: []const u8, reason: []const u8) void {
    const pa = std.heap.page_allocator;
    var root = std.json.ObjectMap.init(pa);
    defer {
        var it = root.iterator();
        while (it.next()) |entry| {
            pa.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .string => |s| pa.free(s),
                else => {},
            }
        }
        root.deinit();
    }
    putStringMtr(pa, &root, "type", "test_error");
    putStringMtr(pa, &root, "test_id", test_id);
    putStringMtr(pa, &root, "probe_uuid", config.get().uuid.?);
    putStringMtr(pa, &root, "error", reason);
    var list = std.ArrayList(u8){};
    defer list.deinit(pa);
    const root_value: std.json.Value = .{ .object = root };
    list.print(pa, "{f}", .{std.json.fmt(root_value, .{})}) catch return;
    std.log.info("MTR sending test_error", .{});
    wss_client.sendJson(list.items);
}

pub fn run(test_id: []const u8, target: []const u8, counts_in: i64, _: bool, _: bool, protocol: ?[]const u8, port: ?u16, no_dns: bool, first_ttl: ?u8, max_ttl: ?u8, interval_sec_in: i64, resumed: bool) void {
    const counts = if (counts_in < 0 or counts_in > 100000) 30 else counts_in;
    const interval_sec = if (interval_sec_in < 1 or interval_sec_in > 300) 1 else interval_sec_in;
    std.log.info("MTR run start test_id={s} target={s} counts={d} resumed={} interval={d} proto={?s} port={?d} no_dns={} first_ttl={?d} max_ttl={?d}", .{ test_id, target, counts, resumed, interval_sec, protocol, port, no_dns, first_ttl, max_ttl });
    const pa = std.heap.page_allocator;
    // This runner owns the page_allocator copies handed to it by
    // wss_client.handleMessage; free them when the run finishes. The g_running
    // and g_generations maps keep their own duped keys, so freeing test_id here
    // is safe.
    defer {
        pa.free(test_id);
        pa.free(target);
        if (protocol) |p| pa.free(p);
    }

    const addr = std.net.Address.parseIp4(target, 0) catch blk: {
        const list = std.net.getAddressList(g_allocator, target, 0) catch |err| {
            std.log.err("MTR DNS resolution failed for target={s}: {any}", .{ target, err });
            sendTestError(test_id, "DNS resolution failed");
            return;
        };
        defer list.deinit();
        if (list.addrs.len == 0) {
            std.log.err("MTR DNS resolution returned no addresses for target={s}", .{target});
            sendTestError(test_id, "DNS resolution returned no addresses");
            return;
        }
        break :blk list.addrs[0];
    };

    const proto = protocol orelse "icmp";
    const ft = first_ttl orelse 1;
    const mt = max_ttl orelse 30;

    const is_ipv6 = addr.any.family == std.posix.AF.INET6;

    if (@import("builtin").os.tag == .windows) {
        // All Windows MTR backends support IPv6: ICMP via Icmp6CreateFile/
        // Icmp6SendEcho2 (runWindowsMtrIcmp6), UDP/TCP via IPv6 probe sockets
        // with IPV6_UNICAST_HOPS plus a raw ICMPv6 capture socket
        // (runWindowsMtrUdp6/runWindowsMtrTcp6).
        if (std.mem.eql(u8, proto, "icmp")) {
            if (is_ipv6) {
                runWindowsMtrIcmp6(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runWindowsMtr(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        } else if (std.mem.eql(u8, proto, "udp")) {
            const p = port orelse 33434;
            if (is_ipv6) {
                runWindowsMtrUdp6(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runWindowsMtrUdp(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        } else if (std.mem.eql(u8, proto, "tcp")) {
            const p = port orelse 80;
            if (is_ipv6) {
                runWindowsMtrTcp6(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runWindowsMtrTcp(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        } else {
            std.log.warn("MTR protocol {s} not yet implemented on Windows, falling back to ICMP", .{proto});
            if (is_ipv6) {
                runWindowsMtrIcmp6(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runWindowsMtr(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        }
    } else {
        if (std.mem.eql(u8, proto, "icmp")) {
            if (is_ipv6) {
                runLinuxMtrIcmp6(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runLinuxMtr(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        } else if (std.mem.eql(u8, proto, "udp")) {
            const p = port orelse 33434;
            if (is_ipv6) {
                runLinuxMtrUdp6(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runLinuxMtrUdp(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        } else if (std.mem.eql(u8, proto, "tcp")) {
            const p = port orelse 80;
            if (is_ipv6) {
                runLinuxMtrTcp6(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runLinuxMtrTcp(pa, test_id, addr, p, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        } else {
            std.log.warn("MTR protocol {s} not yet implemented on Linux, falling back to ICMP", .{proto});
            if (is_ipv6) {
                runLinuxMtrIcmp6(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            } else {
                runLinuxMtr(pa, test_id, addr, no_dns, ft, mt, counts, interval_sec, resumed);
            }
        }
    }
}

// ------------------------------------------------------------------
// Reverse DNS
// ------------------------------------------------------------------

// resolvePtr() spawns this on a detached thread and waits up to
// PTR_RESOLVE_TIMEOUT_NS for it. getnameinfo() has no cancellation
// mechanism, so a hop whose PTR zone is slow/black-holed can still run this
// to completion in the background well after the caller has given up --
// ptrCtxRelease's refcount ensures whichever side (the timed-out caller or
// this thread finishing late) is last to touch ctx is the one that frees it,
// regardless of which happens first.
const PtrResolveCtx = struct {
    ip: []u8,
    result: ?[]u8 = null,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    refs: std.atomic.Value(u8) = std.atomic.Value(u8).init(2),
};

fn ptrCtxRelease(ctx: *PtrResolveCtx, free_result: bool) void {
    if (ctx.refs.fetchSub(1, .acq_rel) == 1) {
        if (free_result) {
            if (ctx.result) |r| std.heap.page_allocator.free(r);
        }
        std.heap.page_allocator.free(ctx.ip);
        std.heap.page_allocator.destroy(ctx);
    }
}

fn resolvePtrThread(ctx: *PtrResolveCtx) void {
    const result = resolvePtrBlocking(ctx.ip);
    ctx.result = result;
    ctx.done.store(true, .release);
    ptrCtxRelease(ctx, true);
}

const PTR_RESOLVE_TIMEOUT_NS: u64 = 2 * std.time.ns_per_s;
const PTR_RESOLVE_POLL_NS: u64 = 20 * std.time.ns_per_ms;

/// Bounded wrapper around resolvePtrBlocking(). MTR's forward-DNS lookup for
/// the test target already runs on a detached thread specifically because a
/// slow/unresponsive resolver shouldn't block the caller for tens of
/// seconds (see wss_client.zig's scheduleDnsResolution) -- per-hop PTR
/// lookups need the same isolation, since buildHopJson calls this
/// synchronously once per resolved hop per cycle, and an MTR run can have
/// dozens of hops. Times out silently (no hostname for this hop this cycle)
/// rather than stalling the whole cycle loop and delaying stop_test.
fn resolvePtr(ip: []const u8) ?[]u8 {
    const pa = std.heap.page_allocator;
    const ip_copy = pa.dupe(u8, ip) catch return null;
    const ctx = pa.create(PtrResolveCtx) catch {
        pa.free(ip_copy);
        return null;
    };
    ctx.* = .{ .ip = ip_copy };

    const thread = std.Thread.spawn(.{}, resolvePtrThread, .{ctx}) catch {
        pa.free(ip_copy);
        pa.destroy(ctx);
        return null;
    };
    thread.detach();

    var waited: u64 = 0;
    while (waited < PTR_RESOLVE_TIMEOUT_NS) {
        if (ctx.done.load(.acquire)) break;
        std.Thread.sleep(PTR_RESOLVE_POLL_NS);
        waited += PTR_RESOLVE_POLL_NS;
    }

    if (ctx.done.load(.acquire)) {
        const result = ctx.result;
        ptrCtxRelease(ctx, false); // caller takes ownership of `result` itself
        return result;
    }

    // Timed out: give up on this hop's hostname for this cycle and hand
    // cleanup responsibility to resolvePtrThread, which will free ctx (and
    // its own result) once it eventually finishes.
    ptrCtxRelease(ctx, true);
    return null;
}

fn resolvePtrBlocking(ip: []const u8) ?[]u8 {
    if (std.net.Address.parseIp4(ip, 0)) |addr| {
        if (@import("builtin").os.tag == .linux) {
            var sa = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = 0,
                .addr = addr.in.sa.addr,
                .zero = [_]u8{0} ** 8,
            };
            var hostbuf: [256]u8 = undefined;
            var servbuf: [256]u8 = undefined;
            const rc = std.c.getnameinfo(
                @ptrCast(&sa),
                @sizeOf(std.posix.sockaddr.in),
                &hostbuf,
                256,
                &servbuf,
                256,
                .{},
            );
            if (@intFromEnum(rc) != 0) return null;
            const hostlen = std.mem.len(@as([*c]u8, &hostbuf));
            if (hostlen == 0) return null;
            return std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{hostbuf[0..hostlen]}) catch null;
        }
        if (@import("builtin").os.tag == .windows) {
            var sa = ws2_32.sockaddr.in{
                .family = ws2_32.AF.INET,
                .port = 0,
                .addr = addr.in.sa.addr,
                .zero = [_]u8{0} ** 8,
            };
            var hostbuf: [ws2_32.NI_MAXHOST]u8 = undefined;
            const rc = ws2_32.getnameinfo(
                @ptrCast(&sa),
                @sizeOf(ws2_32.sockaddr.in),
                &hostbuf,
                ws2_32.NI_MAXHOST,
                null,
                0,
                0,
            );
            if (rc != 0) return null;
            const hostlen = std.mem.len(@as([*c]u8, &hostbuf));
            if (hostlen == 0) return null;
            return std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{hostbuf[0..hostlen]}) catch null;
        }
        return null;
    } else |_| {}

    // Not an IPv4 literal -- try IPv6. This previously fell straight through
    // to `return null` (parseIp4 on an IPv6 string always fails), which is
    // why reverse-DNS/PTR hostnames never appeared for IPv6 MTR hops even
    // with no_dns=false, even though the underlying getnameinfo mechanism
    // works fine for IPv6 -- it just needs a sockaddr_in6, not sockaddr_in.
    const addr6 = std.net.Address.parseIp6(ip, 0) catch return null;
    if (@import("builtin").os.tag == .linux) {
        var sa = addr6.in6.sa;
        sa.port = 0;
        var hostbuf: [256]u8 = undefined;
        var servbuf: [256]u8 = undefined;
        const rc = std.c.getnameinfo(
            @ptrCast(&sa),
            @sizeOf(std.posix.sockaddr.in6),
            &hostbuf,
            256,
            &servbuf,
            256,
            .{},
        );
        if (@intFromEnum(rc) != 0) return null;
        const hostlen = std.mem.len(@as([*c]u8, &hostbuf));
        if (hostlen == 0) return null;
        return std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{hostbuf[0..hostlen]}) catch null;
    }
    if (@import("builtin").os.tag == .windows) {
        var sa = ws2_32.sockaddr.in6{
            .family = ws2_32.AF.INET6,
            .port = 0,
            .flowinfo = 0,
            .addr = addr6.in6.sa.addr,
            .scope_id = 0,
        };
        var hostbuf: [ws2_32.NI_MAXHOST]u8 = undefined;
        const rc = ws2_32.getnameinfo(
            @ptrCast(&sa),
            @sizeOf(ws2_32.sockaddr.in6),
            &hostbuf,
            ws2_32.NI_MAXHOST,
            null,
            0,
            0,
        );
        if (rc != 0) return null;
        const hostlen = std.mem.len(@as([*c]u8, &hostbuf));
        if (hostlen == 0) return null;
        return std.fmt.allocPrint(std.heap.page_allocator, "{s}", .{hostbuf[0..hostlen]}) catch null;
    }
    return null;
}

// ------------------------------------------------------------------
// Linux MTR (raw ICMP socket)
// ------------------------------------------------------------------
fn pollRecvfrom(sock: std.posix.socket_t, buf: []u8, from_addr: *std.posix.sockaddr, from_len: *std.posix.socklen_t, timeout_ms: i32, start_ms: i64) !usize {
    const elapsed = std.time.milliTimestamp() - start_ms;
    if (elapsed >= timeout_ms) return error.WouldBlock;
    var pfds = [_]std.posix.pollfd{
        .{
            .fd = sock,
            .events = std.os.linux.POLL.IN,
            .revents = 0,
        },
    };
    const remaining = timeout_ms - @as(i32, @intCast(elapsed));
    if (remaining <= 0) return error.WouldBlock;
    const ready = std.posix.poll(&pfds, remaining) catch return error.WouldBlock;
    if (ready == 0) return error.WouldBlock;
    return std.posix.recvfrom(sock, buf, std.posix.MSG.DONTWAIT, from_addr, from_len);
}

fn runLinuxMtr(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: i32 = 5000;

    const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.ICMP) catch |err| {
        std.log.err("MTR socket error: {any}", .{err});
        return;
    };
    std.log.info("MTR raw socket created fd={d}", .{sock});
    defer std.posix.close(sock);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);

    for (0..@as(usize, max_ttl) + 1) |_| {
        hop_ips.append(pa, null) catch return;
        hop_latencies.append(pa, std.ArrayList(u64){}) catch return;
        hop_sent.append(pa, 0) catch return;
        hop_reached.append(pa, false) catch return;
    }

    // Randomized per test run (not a shared constant) because the raw ICMP
    // socket is unbound: the kernel delivers every ICMP reply reaching this
    // host to every such socket, filtered only by protocol. A hardcoded id
    // shared by all runs meant two concurrent ICMP MTR tests (whose
    // cycle/hop-derived sequence numbers can also coincide) could accept
    // each other's Time-Exceeded/Echo-Reply packets as their own, corrupting
    // reported hop IP/latency for one or both tests.
    const our_id: u16 = std.crypto.random.int(u16);
    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // u16 (not u8) so the loop-continuation increment below can never
        // overflow when max_ttl == 255 (a valid, user-suppliable value):
        // the last iteration runs with hop == 255 and then increments to
        // 256, which would panic/wrap a u8 counter.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            // Drain stale ICMP packets before sending
            var drain_buf: [256]u8 = undefined;
            var drain_addr: std.posix.sockaddr = undefined;
            var drain_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            while (true) {
                const drain_n = std.posix.recvfrom(sock, &drain_buf, std.posix.MSG.DONTWAIT, &drain_addr, &drain_len) catch break;
                if (drain_n == 0) break;
            }

            const seq: u16 = @intCast(@mod(@as(u64, @intCast(cycle)) * 256 + hop, 65536));
            const payload = buildIcmpEchoPacket(our_id, seq, &[_]u8{0} ** 32) catch |err| {
                std.log.err("MTR build packet error: {any}", .{err});
                continue;
            };
            defer g_allocator.free(payload);

            const hop_i32: i32 = hop;
            std.posix.setsockopt(sock, std.posix.SOL.IP, 2, std.mem.asBytes(&hop_i32)) catch continue;

            const start = std.time.milliTimestamp();
            const sent = std.posix.sendto(sock, payload, 0, &addr.any, addr.getOsSockLen()) catch |err| {
                std.log.err("MTR sendto error: {any}", .{err});
                continue;
            };
            if (sent != payload.len) {
                std.log.err("MTR sendto partial: {d}/{d}", .{ sent, payload.len });
                continue;
            }
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_echo_reply = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                var recv_buf: [256]u8 = undefined;
                var from_addr: std.posix.sockaddr align(4) = undefined;
                var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
                const recv_n = pollRecvfrom(sock, &recv_buf, &from_addr, &from_len, timeout_ms, start) catch break;
                if (recv_n < 20) {
                    if (std.time.milliTimestamp() - start >= timeout_ms) break;
                    continue;
                }

                const ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                if (recv_n < ip_hdr_len + 8) continue;
                const icmp_type = recv_buf[ip_hdr_len];

                if (icmp_type == 0) {
                    if (recv_n < ip_hdr_len + 8) continue;
                    const recv_id = @as(u16, recv_buf[ip_hdr_len + 4]) << 8 | recv_buf[ip_hdr_len + 5];
                    const recv_seq = @as(u16, recv_buf[ip_hdr_len + 6]) << 8 | recv_buf[ip_hdr_len + 7];
                    if (recv_id == our_id and recv_seq == seq) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_echo_reply = true;
                        const src_ip = std.net.Address.initPosix(@alignCast(&from_addr));
                        ip_str = formatSrcIp(pa, src_ip);
                        matched = true;
                        break;
                    }
                } else if (icmp_type == 11) {
                    // Unlike the UDP/TCP MTR variants (which have ephemeral
                    // source/destination ports as an unconditional, always-
                    // available identity check), ICMP has no other
                    // distinguishing field -- id+seq is the only proof this
                    // reply belongs to our probe. So default to rejecting
                    // (not accepting) when the packet is too short to embed
                    // the original datagram: on this unbound raw socket,
                    // any Time-Exceeded reaching the host would otherwise be
                    // accepted as ours with zero verification.
                    var valid = false;
                    const payload_offset = ip_hdr_len + 8;
                    if (recv_n >= payload_offset + 20 + 8) {
                        const orig_ip_hdr_len = (recv_buf[payload_offset] & 0x0F) * 4;
                        const orig_icmp_offset = payload_offset + orig_ip_hdr_len;
                        if (recv_n >= orig_icmp_offset + 8) {
                            const orig_id = @as(u16, recv_buf[orig_icmp_offset + 4]) << 8 | recv_buf[orig_icmp_offset + 5];
                            const orig_seq = @as(u16, recv_buf[orig_icmp_offset + 6]) << 8 | recv_buf[orig_icmp_offset + 7];
                            if (orig_id == our_id and orig_seq == seq) {
                                valid = true;
                            }
                        }
                    }
                    if (valid) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        const src_ip = std.net.Address.initPosix(@alignCast(&from_addr));
                        ip_str = formatSrcIp(pa, src_ip);
                        matched = true;
                        break;
                    }
                }
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_echo_reply) {
                    std.log.info("MTR reached target at hop={d}", .{hop});
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                std.log.debug("MTR no matching response hop={d} cycle={d}", .{ hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Linux MTR ICMPv6 (raw socket). ICMP MTR previously only ever opened an
// AF_INET/IPPROTO.ICMP socket regardless of the resolved target's address
// family: for an IPv6 target, every sendto() through that mismatched IPv4
// socket failed silently (caught and logged, then `continue`d), so every
// cycle produced zero hops. Structured as its own function (mirroring the
// existing per-protocol/per-OS duplication in this file) rather than
// threading family checks through runLinuxMtr, because raw ICMPv6 sockets on
// Linux behave differently enough from raw ICMPv4 ones to make a shared
// implementation more error-prone than clarifying: notably, received
// datagrams do NOT include the IPv6 header (unlike IPv4 raw sockets, which
// always prepend it), and the ICMPv6 checksum is computed by the kernel
// rather than by us.
// ------------------------------------------------------------------
fn runLinuxMtrIcmp6(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: i32 = 5000;

    const sock = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.ICMPV6) catch |err| {
        std.log.err("MTR IPv6 socket error: {any}", .{err});
        return;
    };
    std.log.info("MTR IPv6 raw socket created fd={d}", .{sock});
    defer std.posix.close(sock);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);

    for (0..@as(usize, max_ttl) + 1) |_| {
        hop_ips.append(pa, null) catch return;
        hop_latencies.append(pa, std.ArrayList(u64){}) catch return;
        hop_sent.append(pa, 0) catch return;
        hop_reached.append(pa, false) catch return;
    }

    const our_id: u16 = std.crypto.random.int(u16);
    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            // Drain stale ICMPv6 packets before sending. Must use a
            // sockaddr_storage-sized buffer (28+ bytes), not the 16-byte
            // generic std.posix.sockaddr: that's only big enough for
            // sockaddr_in (IPv4), so recvfrom would truncate the IPv6
            // sockaddr_in6 it needs to write here.
            var drain_buf: [256]u8 = undefined;
            var drain_storage: std.posix.sockaddr.storage = undefined;
            var drain_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            while (true) {
                const drain_n = std.posix.recvfrom(sock, &drain_buf, std.posix.MSG.DONTWAIT, @ptrCast(&drain_storage), &drain_len) catch break;
                if (drain_n == 0) break;
            }

            const seq: u16 = @intCast(@mod(@as(u64, @intCast(cycle)) * 256 + hop, 65536));
            const payload = buildIcmp6EchoPacket(our_id, seq, &[_]u8{0} ** 32) catch |err| {
                std.log.err("MTR build packet error: {any}", .{err});
                continue;
            };
            defer g_allocator.free(payload);

            const hop_i32: i32 = hop;
            std.posix.setsockopt(sock, std.posix.SOL.IPV6, std.os.linux.IPV6.UNICAST_HOPS, std.mem.asBytes(&hop_i32)) catch continue;

            const start = std.time.milliTimestamp();
            const sent = std.posix.sendto(sock, payload, 0, &addr.any, addr.getOsSockLen()) catch |err| {
                std.log.err("MTR sendto error: {any}", .{err});
                continue;
            };
            if (sent != payload.len) {
                std.log.err("MTR sendto partial: {d}/{d}", .{ sent, payload.len });
                continue;
            }
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_echo_reply = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                var recv_buf: [256]u8 = undefined;
                // sockaddr_storage-sized, not the 16-byte generic
                // std.posix.sockaddr: the latter is only big enough for
                // sockaddr_in (IPv4, 16 bytes); sockaddr_in6 needs 28. With
                // the undersized buffer, recvfrom silently truncated the
                // address it wrote back, so Address.initPosix read
                // uninitialized stack memory past the truncated part --
                // this is what produced the "aaaa:aaaa:aaaa:aaaa" garbage
                // hop addresses (0xAA is Zig's undefined-memory fill byte in
                // safety-checked builds).
                var from_storage: std.posix.sockaddr.storage = undefined;
                var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
                const recv_n = pollRecvfrom(sock, &recv_buf, @ptrCast(&from_storage), &from_len, timeout_ms, start) catch break;
                // Unlike IPv4 raw sockets, Linux never includes the IPv6
                // header on receive for IPPROTO_ICMPV6 raw sockets --
                // recv_buf starts directly at the ICMPv6 header.
                if (recv_n < 8) {
                    if (std.time.milliTimestamp() - start >= timeout_ms) break;
                    continue;
                }

                const icmp_type = recv_buf[0];

                if (icmp_type == 129) { // Echo Reply
                    const recv_id = @as(u16, recv_buf[4]) << 8 | recv_buf[5];
                    const recv_seq = @as(u16, recv_buf[6]) << 8 | recv_buf[7];
                    if (recv_id == our_id and recv_seq == seq) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_echo_reply = true;
                        const src_ip = std.net.Address.initPosix(@ptrCast(&from_storage));
                        ip_str = formatSrcIp(pa, src_ip);
                        matched = true;
                        break;
                    }
                } else if (icmp_type == 3) { // Time Exceeded
                    // As with the ICMPv4 path: id+seq is the only proof this
                    // reply is ours, so default to rejecting when the packet
                    // is too short to embed the original datagram. Time
                    // Exceeded layout: 4-byte ICMPv6 header + 4-byte
                    // unused/reserved, then "as much of the invoking packet
                    // as possible": the original IPv6 header (a fixed 40
                    // bytes, assuming no extension headers on our own
                    // outbound echo packet) followed by the original ICMPv6
                    // echo header (id at +4, seq at +6 within it).
                    var valid = false;
                    const payload_offset = 8;
                    const orig_icmp_offset = payload_offset + 40;
                    if (recv_n >= orig_icmp_offset + 8) {
                        const orig_id = @as(u16, recv_buf[orig_icmp_offset + 4]) << 8 | recv_buf[orig_icmp_offset + 5];
                        const orig_seq = @as(u16, recv_buf[orig_icmp_offset + 6]) << 8 | recv_buf[orig_icmp_offset + 7];
                        if (orig_id == our_id and orig_seq == seq) {
                            valid = true;
                        }
                    }
                    if (valid) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        const src_ip = std.net.Address.initPosix(@ptrCast(&from_storage));
                        ip_str = formatSrcIp(pa, src_ip);
                        matched = true;
                        break;
                    }
                }
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_echo_reply) {
                    std.log.info("MTR reached target at hop={d}", .{hop});
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                std.log.debug("MTR no matching response hop={d} cycle={d}", .{ hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Linux MTR UDP (raw ICMP socket for receiving errors)
// ------------------------------------------------------------------
fn runLinuxMtrUdp(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: i32 = 5000;

    const icmp_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.ICMP) catch |err| {
        std.log.err("MTR ICMP socket error: {any}", .{err});
        return;
    };
    defer std.posix.close(icmp_sock);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    const target_ip_u32 = addr.in.sa.addr;

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);

    for (0..@as(usize, max_ttl) + 1) |_| {
        hop_ips.append(pa, null) catch return;
        hop_latencies.append(pa, std.ArrayList(u64){}) catch return;
        hop_sent.append(pa, 0) catch return;
        hop_reached.append(pa, false) catch return;
    }

    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // u16 (not u8) so the loop-continuation increment below can never
        // overflow when max_ttl == 255 (a valid, user-suppliable value):
        // the last iteration runs with hop == 255 and then increments to
        // 256, which would panic/wrap a u8 counter.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            // Drain stale ICMP packets before sending this probe
            var drain_buf: [512]u8 = undefined;
            var drain_addr: std.posix.sockaddr = undefined;
            var drain_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            while (true) {
                const drain_n = std.posix.recvfrom(icmp_sock, &drain_buf, std.posix.MSG.DONTWAIT, &drain_addr, &drain_len) catch break;
                if (drain_n == 0) break;
            }

            const seq: u16 = @intCast(@mod(@as(u64, @intCast(cycle)) * 256 + hop, 65536));

            // Create a fresh UDP socket per probe so each probe has a unique source port.
            const udp_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch continue;
            defer std.posix.close(udp_sock);

            var bind_addr = std.net.Address.parseIp4("0.0.0.0", 0) catch continue;
            std.posix.bind(udp_sock, &bind_addr.any, bind_addr.getOsSockLen()) catch continue;

            var local_sockaddr: std.posix.sockaddr = undefined;
            var local_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            const local_port: u16 = blk: {
                std.posix.getsockname(udp_sock, &local_sockaddr, &local_len) catch break :blk 0;
                const port_bytes = std.mem.asBytes(&local_sockaddr)[2..4];
                break :blk std.mem.bigToNative(u16, std.mem.bytesToValue(u16, port_bytes));
            };

            const hop_i32: i32 = hop;
            std.posix.setsockopt(udp_sock, std.posix.SOL.IP, 2, std.mem.asBytes(&hop_i32)) catch continue;

            var target_addr = addr;
            target_addr.setPort(port); // fixed destination port

            // Embed sequence number in UDP payload for precise matching
            var udp_payload = [_]u8{0} ** 32;
            std.mem.writeInt(u16, udp_payload[0..2], seq, .big);

            const start = std.time.milliTimestamp();
            _ = std.posix.sendto(udp_sock, &udp_payload, 0, &target_addr.any, target_addr.getOsSockLen()) catch continue;
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                var recv_buf: [512]u8 = undefined;
                var from_addr: std.posix.sockaddr align(4) = undefined;
                var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
                const recv_n = pollRecvfrom(icmp_sock, &recv_buf, &from_addr, &from_len, timeout_ms, start) catch break;
                if (recv_n < 28 + 20 + 8) continue;

                const ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                const icmp_type = recv_buf[ip_hdr_len];
                const icmp_code = recv_buf[ip_hdr_len + 1];
                const payload_offset = ip_hdr_len + 8;
                if (recv_n < payload_offset + 20 + 8) continue;

                const orig_ip_hdr_len = (recv_buf[payload_offset] & 0x0F) * 4;
                const orig_proto = recv_buf[payload_offset + 9];
                const orig_udp_offset = payload_offset + orig_ip_hdr_len;
                if (recv_n < orig_udp_offset + 8) continue; // at least UDP header (8)

                const orig_src_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_udp_offset .. orig_udp_offset + 2]));
                const orig_dst_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_udp_offset + 2 .. orig_udp_offset + 4]));

                var orig_seq: u16 = 0xFFFF;
                if (recv_n >= orig_udp_offset + 8 + 2) {
                    orig_seq = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_udp_offset + 8 .. orig_udp_offset + 10]));
                }

                std.log.debug("MTR UDP icmp_type={d} code={d} orig_proto={d} orig_src_port={d} orig_dst_port={d} orig_seq={d} local_port={d} probe_port={d} seq={d} recv_n={d}", .{ icmp_type, icmp_code, orig_proto, orig_src_port, orig_dst_port, orig_seq, local_port, port, seq, recv_n });

                if (orig_proto != 17) continue; // not UDP
                if (orig_dst_port != port) continue; // not our destination port
                if (orig_src_port != local_port) continue; // not our source port
                // Verify sequence if available in ICMP payload; some routers truncate payload
                if (recv_n >= orig_udp_offset + 8 + 2 and orig_seq != seq) continue;

                elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                const src_ip = std.net.Address.initPosix(@alignCast(&from_addr));
                var src_ip_u32: u32 = 0;
                if (src_ip.any.family == std.posix.AF.INET) {
                    src_ip_u32 = @as(u32, @bitCast(src_ip.in.sa.addr));
                }
                ip_str = formatSrcIp(pa, src_ip) orelse continue;

                if (icmp_type == 3 and icmp_code == 3 and src_ip_u32 == target_ip_u32) {
                    std.log.info("MTR UDP reached target at hop={d} ip={s}", .{ hop, ip_str.? });
                    is_target = true;
                    matched = true;
                    break;
                } else if (icmp_type == 11) {
                    std.log.debug("MTR UDP time exceeded at hop={d} ip={s}", .{ hop, ip_str.? });
                    matched = true;
                    break;
                }
                // Unrelated error message: drop the formatted IP and keep waiting.
                pa.free(ip_str.?);
                ip_str = null;
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR UDP no matching response hop={d} cycle={d}", .{ hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Linux MTR TCP (normal TCP socket + raw ICMP socket)
// ------------------------------------------------------------------
fn getTcpSoError(sock: std.posix.socket_t) i32 {
    var so_error: i32 = 0;
    var optlen: std.posix.socklen_t = @sizeOf(i32);
    const rc = std.c.getsockopt(@intCast(sock), std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &optlen);
    if (rc != 0) return -1;
    return so_error;
}

fn runLinuxMtrTcp(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: i32 = 5000;

    const icmp_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.ICMP) catch |err| {
        std.log.err("MTR TCP ICMP socket error: {any}", .{err});
        return;
    };
    defer std.posix.close(icmp_sock);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    const target_ip_u32 = addr.in.sa.addr;

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);

    for (0..@as(usize, max_ttl) + 1) |_| {
        hop_ips.append(pa, null) catch return;
        hop_latencies.append(pa, std.ArrayList(u64){}) catch return;
        hop_sent.append(pa, 0) catch return;
        hop_reached.append(pa, false) catch return;
    }

    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // Drain stale ICMP before each cycle
        var drain_buf: [512]u8 = undefined;
        var drain_addr: std.posix.sockaddr = undefined;
        var drain_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        while (true) {
            const drain_n = std.posix.recvfrom(icmp_sock, &drain_buf, std.posix.MSG.DONTWAIT, &drain_addr, &drain_len) catch break;
            if (drain_n == 0) break;
        }

        // u16 (not u8) so the loop-continuation increment below can never
        // overflow when max_ttl == 255 (a valid, user-suppliable value):
        // the last iteration runs with hop == 255 and then increments to
        // 256, which would panic/wrap a u8 counter.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            // Create TCP socket (non-blocking from the start)
            const tcp_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.TCP) catch |err| {
                std.log.err("MTR TCP socket error: {any}", .{err});
                continue;
            };
            defer std.posix.close(tcp_sock);

            // Set SO_REUSEPORT to allow rapid port reuse
            const reuse: c_int = 1;
            std.posix.setsockopt(tcp_sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&reuse)) catch {};

            // Set TTL
            const hop_i32: i32 = hop;
            std.posix.setsockopt(tcp_sock, std.posix.SOL.IP, 2, std.mem.asBytes(&hop_i32)) catch |err| {
                std.log.err("MTR TCP setsockopt TTL error: {any}", .{err});
                continue;
            };

            var target_addr = addr;
            target_addr.setPort(port);

            const start = std.time.milliTimestamp();
            var connect_err_str: []const u8 = "ok";
            std.posix.connect(tcp_sock, &target_addr.any, target_addr.getOsSockLen()) catch |err| {
                if (err != error.WouldBlock) {
                    connect_err_str = @errorName(err);
                    std.log.debug("MTR TCP connect error: {any}", .{err});
                } else {
                    connect_err_str = "WouldBlock";
                }
            };

            // Get local port assigned by the kernel
            var local_sockaddr: std.posix.sockaddr = undefined;
            var local_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
            const local_port: u16 = blk: {
                std.posix.getsockname(tcp_sock, &local_sockaddr, &local_len) catch break :blk 0;
                const port_bytes = std.mem.asBytes(&local_sockaddr)[2..4];
                break :blk std.mem.bigToNative(u16, std.mem.bytesToValue(u16, port_bytes));
            };

            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            std.log.debug("MTR TCP probe start hop={d} connect={s} local_port={d}", .{ hop, connect_err_str, local_port });

            // Poll ICMP and TCP socket simultaneously using poll()
            while (true) {
                const elapsed_now = std.time.milliTimestamp() - start;
                if (elapsed_now >= timeout_ms) break;

                var pfds = [_]std.posix.pollfd{
                    .{ .fd = icmp_sock, .events = std.os.linux.POLL.IN, .revents = 0 },
                    .{ .fd = tcp_sock, .events = std.os.linux.POLL.OUT | std.os.linux.POLL.ERR, .revents = 0 },
                };
                const remaining = timeout_ms - @as(i32, @intCast(elapsed_now));
                if (remaining <= 0) break;

                const ready = std.posix.poll(&pfds, remaining) catch break;
                if (ready == 0) break;

                // Check ICMP socket for ICMP Time Exceeded or Port Unreachable
                if (pfds[0].revents & std.os.linux.POLL.IN != 0) {
                    var recv_buf: [512]u8 = undefined;
                    var from_addr: std.posix.sockaddr align(4) = undefined;
                    var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
                    const recv_n = std.posix.recvfrom(icmp_sock, &recv_buf, std.posix.MSG.DONTWAIT, &from_addr, &from_len) catch continue;
                    if (recv_n < 28 + 20 + 8) continue;

                    const ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                    const icmp_type = recv_buf[ip_hdr_len];
                    const icmp_code = recv_buf[ip_hdr_len + 1];
                    const payload_offset = ip_hdr_len + 8;
                    if (recv_n < payload_offset + 20 + 8) continue;

                    const orig_ip_hdr_len = (recv_buf[payload_offset] & 0x0F) * 4;
                    const orig_proto = recv_buf[payload_offset + 9];
                    const orig_tcp_offset = payload_offset + orig_ip_hdr_len;
                    if (recv_n < orig_tcp_offset + 8) continue;

                    const orig_src_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_tcp_offset .. orig_tcp_offset + 2]));
                    const orig_dst_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_tcp_offset + 2 .. orig_tcp_offset + 4]));

                    if (orig_proto != 6) continue;
                    if (orig_dst_port != port) continue;
                    if (orig_src_port != local_port) continue;

                    elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                    const src_ip = std.net.Address.initPosix(@alignCast(&from_addr));
                    var src_ip_u32: u32 = 0;
                    if (src_ip.any.family == std.posix.AF.INET) {
                        src_ip_u32 = @as(u32, @bitCast(src_ip.in.sa.addr));
                    }
                    ip_str = formatSrcIp(pa, src_ip) orelse continue;

                    if (icmp_type == 3 and icmp_code == 3 and src_ip_u32 == target_ip_u32) {
                        std.log.info("MTR TCP reached target at hop={d} ip={s}", .{ hop, ip_str.? });
                        is_target = true;
                        matched = true;
                        break;
                    } else if (icmp_type == 11) {
                        std.log.debug("MTR TCP time exceeded at hop={d} ip={s}", .{ hop, ip_str.? });
                        matched = true;
                        break;
                    }
                    // Unrelated error message: drop the formatted IP and keep waiting.
                    pa.free(ip_str.?);
                    ip_str = null;
                }

                // Check TCP socket for connection completion or error
                if (pfds[1].revents & (std.os.linux.POLL.OUT | std.os.linux.POLL.ERR) != 0) {
                    const so_err = getTcpSoError(tcp_sock);
                    std.log.debug("MTR TCP poll so_err={d} hop={d} elapsed={d}", .{ so_err, hop, std.time.milliTimestamp() - start });
                    if (so_err == 0) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_target = true;
                        const ip_addr = target_ip_u32;
                        ip_str = std.fmt.allocPrint(pa, "{d}.{d}.{d}.{d}", .{
                            (ip_addr >> 0) & 0xFF,
                            (ip_addr >> 8) & 0xFF,
                            (ip_addr >> 16) & 0xFF,
                            (ip_addr >> 24) & 0xFF,
                        }) catch continue;
                        std.log.info("MTR TCP reached target at hop={d} ip={s}", .{ hop, ip_str.? });
                        matched = true;
                        break;
                    } else if (so_err == @intFromEnum(std.posix.E.CONNREFUSED)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_target = true;
                        const ip_addr = target_ip_u32;
                        ip_str = std.fmt.allocPrint(pa, "{d}.{d}.{d}.{d}", .{
                            (ip_addr >> 0) & 0xFF,
                            (ip_addr >> 8) & 0xFF,
                            (ip_addr >> 16) & 0xFF,
                            (ip_addr >> 24) & 0xFF,
                        }) catch continue;
                        std.log.info("MTR TCP connection refused at hop={d} ip={s}", .{ hop, ip_str.? });
                        matched = true;
                        break;
                    } else if (so_err == @intFromEnum(std.os.linux.E.HOSTUNREACH)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        std.log.debug("MTR TCP EHOSTUNREACH at hop={d}", .{hop});
                        matched = true;
                        break;
                    }
                }
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR TCP no matching response hop={d} cycle={d}", .{ hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Shared ICMPv6 error parsing (Linux raw ICMPv6 + Windows raw ICMPv6)
// ------------------------------------------------------------------
// Raw ICMPv6 sockets on BOTH Linux and Windows deliver datagrams starting
// directly at the ICMPv6 header (the IPv6 header is never included, unlike
// IPv4 raw sockets which always prepend it). An ICMPv6 error message embeds
// the invoking packet after an 8-byte ICMPv6 header: the original IPv6
// header (fixed 40 bytes -- our own probes never carry extension headers)
// followed by the original L4 (UDP/TCP) header.
//
// ICMPv6 type numbers differ from ICMPv4:
//   Destination Unreachable = 1 (code 4 = port unreachable -> target reached
//   for UDP probes), Time Exceeded = 3 (code 0 = hop limit exceeded).
const Icmp6ErrorInfo = struct {
    icmp_type: u8,
    icmp_code: u8,
    orig_proto: u8,
    orig_src_port: u16,
    orig_dst_port: u16,
    orig_seq: ?u16, // first two payload bytes after the embedded UDP header
};

fn parseIcmp6Error(buf: []const u8) ?Icmp6ErrorInfo {
    const l4 = 8 + 40; // ICMPv6 error header + embedded IPv6 header
    if (buf.len < l4 + 8) return null; // need at least the embedded L4 header
    const icmp_type = buf[0];
    if (icmp_type != 1 and icmp_type != 3) return null;
    const orig_proto = buf[8 + 6]; // Next Header field of the embedded IPv6 header
    const orig_src_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, buf[l4 .. l4 + 2]));
    const orig_dst_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, buf[l4 + 2 .. l4 + 4]));
    var orig_seq: ?u16 = null;
    if (buf.len >= l4 + 8 + 2) {
        orig_seq = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, buf[l4 + 8 .. l4 + 10]));
    }
    return .{
        .icmp_type = icmp_type,
        .icmp_code = buf[1],
        .orig_proto = orig_proto,
        .orig_src_port = orig_src_port,
        .orig_dst_port = orig_dst_port,
        .orig_seq = orig_seq,
    };
}

fn sameIpv6(a: [16]u8, b: [16]u8) bool {
    return std.mem.eql(u8, &a, &b);
}

// Extract the port from a sockaddr written by getsockname into a
// storage-sized buffer. sockaddr_in and sockaddr_in6 both keep the port in
// network byte order at offset 2.
fn portFromSockaddrStorage(storage: *const std.posix.sockaddr.storage) u16 {
    const bytes = std.mem.asBytes(storage);
    return std.mem.bigToNative(u16, std.mem.bytesToValue(u16, bytes[2..4]));
}

// ------------------------------------------------------------------
// Linux MTR UDP over IPv6 (raw ICMPv6 socket for receiving errors)
// ------------------------------------------------------------------
fn runLinuxMtrUdp6(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: i32 = 5000;

    const icmp_sock = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.ICMPV6) catch |err| {
        std.log.err("MTR UDP6 ICMPv6 socket error: {any}", .{err});
        sendTestError(test_id, "ICMPv6 raw socket creation failed");
        return;
    };
    defer std.posix.close(icmp_sock);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    const target_ip6 = addr.in6.sa.addr;

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);
    initHopState(pa, max_ttl, &hop_ips, &hop_latencies, &hop_sent, &hop_reached) catch return;

    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            // Drain stale ICMPv6 packets (storage-sized address buffer: the
            // 16-byte generic sockaddr is too small for sockaddr_in6).
            var drain_buf: [512]u8 = undefined;
            var drain_storage: std.posix.sockaddr.storage = undefined;
            var drain_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            while (true) {
                const drain_n = std.posix.recvfrom(icmp_sock, &drain_buf, std.posix.MSG.DONTWAIT, @ptrCast(&drain_storage), &drain_len) catch break;
                if (drain_n == 0) break;
            }

            const seq: u16 = @intCast(@mod(@as(u64, @intCast(cycle)) * 256 + hop, 65536));

            // Fresh UDP socket per probe for a unique source port.
            const udp_sock = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.DGRAM, 0) catch continue;
            defer std.posix.close(udp_sock);

            var bind_addr = std.net.Address.parseIp6("::", 0) catch continue;
            std.posix.bind(udp_sock, &bind_addr.any, bind_addr.getOsSockLen()) catch continue;

            var local_storage: std.posix.sockaddr.storage = undefined;
            var local_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            const local_port: u16 = blk: {
                std.posix.getsockname(udp_sock, @ptrCast(&local_storage), &local_len) catch break :blk 0;
                break :blk portFromSockaddrStorage(&local_storage);
            };

            const hop_i32: i32 = hop;
            std.posix.setsockopt(udp_sock, std.posix.SOL.IPV6, std.os.linux.IPV6.UNICAST_HOPS, std.mem.asBytes(&hop_i32)) catch continue;

            var target_addr = addr;
            target_addr.setPort(port);

            var udp_payload = [_]u8{0} ** 32;
            std.mem.writeInt(u16, udp_payload[0..2], seq, .big);

            const start = std.time.milliTimestamp();
            _ = std.posix.sendto(udp_sock, &udp_payload, 0, &target_addr.any, target_addr.getOsSockLen()) catch continue;
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                var recv_buf: [512]u8 = undefined;
                var from_storage: std.posix.sockaddr.storage = undefined;
                var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
                const recv_n = pollRecvfrom(icmp_sock, &recv_buf, @ptrCast(&from_storage), &from_len, timeout_ms, start) catch break;

                const info = parseIcmp6Error(recv_buf[0..recv_n]) orelse continue;
                if (info.orig_proto != 17) continue; // not UDP
                if (info.orig_dst_port != port) continue;
                if (info.orig_src_port != local_port) continue;
                if (info.orig_seq) |s| {
                    if (s != seq) continue;
                }

                elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                const src_ip = std.net.Address.initPosix(@ptrCast(&from_storage));
                var src_is_target = false;
                if (src_ip.any.family == std.posix.AF.INET6) {
                    src_is_target = sameIpv6(src_ip.in6.sa.addr, target_ip6);
                }
                ip_str = formatSrcIp(pa, src_ip) orelse continue;

                if (info.icmp_type == 1 and info.icmp_code == 4 and src_is_target) {
                    std.log.info("MTR UDP6 reached target at hop={d} ip={s}", .{ hop, ip_str.? });
                    is_target = true;
                    matched = true;
                    break;
                } else if (info.icmp_type == 3) {
                    std.log.debug("MTR UDP6 time exceeded at hop={d} ip={s}", .{ hop, ip_str.? });
                    matched = true;
                    break;
                }
                // Unrelated error message: drop the formatted IP and keep waiting.
                pa.free(ip_str.?);
                ip_str = null;
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR UDP6 no matching response hop={d} cycle={d}", .{ hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Linux MTR TCP over IPv6 (TCP socket + raw ICMPv6 socket)
// ------------------------------------------------------------------
fn runLinuxMtrTcp6(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: i32 = 5000;

    const icmp_sock = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.RAW | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.ICMPV6) catch |err| {
        std.log.err("MTR TCP6 ICMPv6 socket error: {any}", .{err});
        sendTestError(test_id, "ICMPv6 raw socket creation failed");
        return;
    };
    defer std.posix.close(icmp_sock);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    const target_ip6 = addr.in6.sa.addr;

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);
    initHopState(pa, max_ttl, &hop_ips, &hop_latencies, &hop_sent, &hop_reached) catch return;

    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // Drain stale ICMPv6 before each cycle.
        var drain_buf: [512]u8 = undefined;
        var drain_storage: std.posix.sockaddr.storage = undefined;
        var drain_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        while (true) {
            const drain_n = std.posix.recvfrom(icmp_sock, &drain_buf, std.posix.MSG.DONTWAIT, @ptrCast(&drain_storage), &drain_len) catch break;
            if (drain_n == 0) break;
        }

        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            const tcp_sock = std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, std.posix.IPPROTO.TCP) catch |err| {
                std.log.err("MTR TCP6 socket error: {any}", .{err});
                continue;
            };
            defer std.posix.close(tcp_sock);

            const reuse: c_int = 1;
            std.posix.setsockopt(tcp_sock, std.posix.SOL.SOCKET, std.posix.SO.REUSEPORT, std.mem.asBytes(&reuse)) catch {};

            const hop_i32: i32 = hop;
            std.posix.setsockopt(tcp_sock, std.posix.SOL.IPV6, std.os.linux.IPV6.UNICAST_HOPS, std.mem.asBytes(&hop_i32)) catch |err| {
                std.log.err("MTR TCP6 setsockopt UNICAST_HOPS error: {any}", .{err});
                continue;
            };

            var target_addr = addr;
            target_addr.setPort(port);

            const start = std.time.milliTimestamp();
            std.posix.connect(tcp_sock, &target_addr.any, target_addr.getOsSockLen()) catch |err| {
                if (err != error.WouldBlock) {
                    std.log.debug("MTR TCP6 connect error: {any}", .{err});
                }
            };

            var local_storage: std.posix.sockaddr.storage = undefined;
            var local_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            const local_port: u16 = blk: {
                std.posix.getsockname(tcp_sock, @ptrCast(&local_storage), &local_len) catch break :blk 0;
                break :blk portFromSockaddrStorage(&local_storage);
            };

            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                const elapsed_now = std.time.milliTimestamp() - start;
                if (elapsed_now >= timeout_ms) break;

                var pfds = [_]std.posix.pollfd{
                    .{ .fd = icmp_sock, .events = std.os.linux.POLL.IN, .revents = 0 },
                    .{ .fd = tcp_sock, .events = std.os.linux.POLL.OUT | std.os.linux.POLL.ERR, .revents = 0 },
                };
                const remaining = timeout_ms - @as(i32, @intCast(elapsed_now));
                if (remaining <= 0) break;

                const ready = std.posix.poll(&pfds, remaining) catch break;
                if (ready == 0) break;

                if (pfds[0].revents & std.os.linux.POLL.IN != 0) {
                    var recv_buf: [512]u8 = undefined;
                    var from_storage: std.posix.sockaddr.storage = undefined;
                    var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
                    const recv_n = std.posix.recvfrom(icmp_sock, &recv_buf, std.posix.MSG.DONTWAIT, @ptrCast(&from_storage), &from_len) catch continue;

                    const info = parseIcmp6Error(recv_buf[0..recv_n]) orelse continue;
                    if (info.orig_proto != 6) continue;
                    if (info.orig_dst_port != port) continue;
                    if (info.orig_src_port != local_port) continue;

                    elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                    const src_ip = std.net.Address.initPosix(@ptrCast(&from_storage));
                    var src_is_target = false;
                    if (src_ip.any.family == std.posix.AF.INET6) {
                        src_is_target = sameIpv6(src_ip.in6.sa.addr, target_ip6);
                    }
                    ip_str = formatSrcIp(pa, src_ip) orelse continue;

                    if (info.icmp_type == 1 and info.icmp_code == 4 and src_is_target) {
                        std.log.info("MTR TCP6 reached target at hop={d} ip={s}", .{ hop, ip_str.? });
                        is_target = true;
                        matched = true;
                        break;
                    } else if (info.icmp_type == 3) {
                        std.log.debug("MTR TCP6 time exceeded at hop={d} ip={s}", .{ hop, ip_str.? });
                        matched = true;
                        break;
                    }
                    pa.free(ip_str.?);
                    ip_str = null;
                }

                if (pfds[1].revents & (std.os.linux.POLL.OUT | std.os.linux.POLL.ERR) != 0) {
                    const so_err = getTcpSoError(tcp_sock);
                    std.log.debug("MTR TCP6 poll so_err={d} hop={d} elapsed={d}", .{ so_err, hop, std.time.milliTimestamp() - start });
                    if (so_err == 0 or so_err == @intFromEnum(std.posix.E.CONNREFUSED)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_target = true;
                        ip_str = formatSrcIp(pa, addr) orelse continue;
                        std.log.info("MTR TCP6 reached target at hop={d} ip={s} so_err={d}", .{ hop, ip_str.?, so_err });
                        matched = true;
                        break;
                    } else if (so_err == @intFromEnum(std.os.linux.E.HOSTUNREACH)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        std.log.debug("MTR TCP6 EHOSTUNREACH at hop={d}", .{hop});
                        matched = true;
                        break;
                    }
                }
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR TCP6 no matching response hop={d} cycle={d}", .{ hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Windows MTR via IcmpSendEcho (iphlpapi.dll)
// ------------------------------------------------------------------
const win = std.os.windows;

// iphlpapi bindings
extern "iphlpapi" fn IcmpCreateFile() callconv(.winapi) win.HANDLE;
extern "iphlpapi" fn IcmpCloseHandle(IcmpHandle: win.HANDLE) callconv(.winapi) win.BOOL;
extern "iphlpapi" fn IcmpSendEcho(
    IcmpHandle: win.HANDLE,
    DestinationAddress: u32,
    RequestData: ?*const anyopaque,
    RequestSize: u16,
    RequestOptions: ?*const anyopaque,
    ReplyBuffer: ?*anyopaque,
    ReplySize: u32,
    Timeout: u32,
) callconv(.winapi) u32;

const IP_OPTION_INFORMATION = extern struct {
    Ttl: u8,
    Tos: u8,
    Flags: u8,
    OptionsSize: u8,
    OptionsData: ?[*]u8,
};

const ICMP_ECHO_REPLY = extern struct {
    Address: u32,
    Status: u32,
    RoundTripTime: u32,
    DataSize: u16,
    Reserved: u16,
    Data: ?*anyopaque,
    Options: IP_OPTION_INFORMATION,
};

// IPv6 ICMP echo via iphlpapi (the v6 counterparts of IcmpCreateFile/
// IcmpSendEcho). Icmp6SendEcho2 with Event/ApcRoutine null is synchronous,
// exactly like IcmpSendEcho, and IP_OPTION_INFORMATION.Ttl acts as the IPv6
// hop limit, so the per-hop probing model is identical to the IPv4 path.
extern "iphlpapi" fn Icmp6CreateFile() callconv(.winapi) win.HANDLE;
extern "iphlpapi" fn Icmp6SendEcho2(
    IcmpHandle: win.HANDLE,
    Event: ?win.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    SourceAddress: *const anyopaque, // sockaddr_in6
    DestinationAddress: *const anyopaque, // sockaddr_in6
    RequestData: ?*const anyopaque,
    RequestSize: u16,
    RequestOptions: ?*const IP_OPTION_INFORMATION,
    ReplyBuffer: ?*anyopaque,
    ReplySize: u32,
    Timeout: u32,
) callconv(.winapi) u32;

// Mirrors the Windows SDK's IPV6_ADDRESS_EX, which is declared inside
// #include <pshpack1.h> (1-byte packed, 26 bytes total) -- hence align(1) on
// every field. Getting this layout wrong silently misparses every reply.
const IPV6_ADDRESS_EX = extern struct {
    sin6_port: u16 align(1),
    sin6_flowinfo: u32 align(1),
    sin6_addr: [16]u8 align(1),
    sin6_scope_id: u32 align(1),
};

// ICMPV6_ECHO_REPLY itself is NOT packed in the SDK, so Status is padded to
// the next 4-byte boundary after the 26-byte Address (offset 28).
const ICMPV6_ECHO_REPLY = extern struct {
    Address: IPV6_ADDRESS_EX,
    Status: u32,
    RoundTripTime: u32,
};

const ws2_32 = win.ws2_32;
const WSA_SOCKET = ws2_32.SOCKET;
const WSA_INVALID_SOCKET = ws2_32.INVALID_SOCKET;
const WSA_SOCKET_ERROR = ws2_32.SOCKET_ERROR;
const WSA_AF_INET = ws2_32.AF.INET;
const WSA_SOCK_RAW = ws2_32.SOCK.RAW;
const WSA_SOCK_DGRAM = ws2_32.SOCK.DGRAM;
const WSA_SOCK_STREAM = ws2_32.SOCK.STREAM;
const WSA_IPPROTO_ICMP = ws2_32.IPPROTO.ICMP;
const WSA_IPPROTO_IP = ws2_32.IPPROTO.IP;
const WSA_IPPROTO_TCP = ws2_32.IPPROTO.TCP;
const WSA_IP_TTL = 4;
const WSA_SOL_SOCKET = 0xFFFF;
const WSA_SO_ERROR = 0x1007;
const WSA_SO_REUSEADDR = 4;
const SIO_RCVALL = 0x98000001;
const RCVALL_ON: u32 = 1;

extern "ws2_32" fn WSAIoctl(
    s: WSA_SOCKET,
    dwIoControlCode: u32,
    lpvInBuffer: ?*anyopaque,
    cbInBuffer: u32,
    lpvOutBuffer: ?*anyopaque,
    cbOutBuffer: u32,
    lpcbBytesReturned: *u32,
    lpOverlapped: ?*anyopaque,
    lpCompletionRoutine: ?*anyopaque,
) callconv(.winapi) i32;

fn winsockError() i32 {
    return @intFromEnum(ws2_32.WSAGetLastError());
}

fn closeWindowsSocket(s: WSA_SOCKET) void {
    _ = ws2_32.closesocket(s);
}

fn setWindowsSocketNonBlocking(s: WSA_SOCKET) bool {
    var mode: u32 = 1;
    return ws2_32.ioctlsocket(s, ws2_32.FIONBIO, &mode) != WSA_SOCKET_ERROR;
}

fn setWindowsSocketInt(s: WSA_SOCKET, level: i32, optname: i32, value: i32) bool {
    var val = value;
    return ws2_32.setsockopt(s, level, optname, @ptrCast(&val), @sizeOf(i32)) != WSA_SOCKET_ERROR;
}

fn getWindowsSocketInt(s: WSA_SOCKET, level: i32, optname: i32) i32 {
    var val: i32 = 0;
    var len: i32 = @sizeOf(i32);
    if (ws2_32.getsockopt(s, level, optname, @ptrCast(&val), &len) == WSA_SOCKET_ERROR) return -1;
    return val;
}

fn getWindowsLocalPort(s: WSA_SOCKET) u16 {
    var addr: ws2_32.sockaddr.in = undefined;
    var len: i32 = @sizeOf(ws2_32.sockaddr.in);
    if (ws2_32.getsockname(s, @ptrCast(&addr), &len) == WSA_SOCKET_ERROR) return 0;
    return ws2_32.ntohs(addr.port);
}

fn windowsSockaddrFromAddress(addr: std.net.Address) ws2_32.sockaddr.in {
    return .{
        .family = WSA_AF_INET,
        .port = ws2_32.htons(addr.in.sa.port),
        .addr = @bitCast(addr.in.sa.addr),
        .zero = [_]u8{0} ** 8,
    };
}

fn windowsFdSetZero(set: *ws2_32.fd_set) void {
    set.fd_count = 0;
}

fn windowsFdSetAdd(set: *ws2_32.fd_set, s: WSA_SOCKET) void {
    if (set.fd_count < ws2_32.FD_SETSIZE) {
        set.fd_array[set.fd_count] = s;
        set.fd_count += 1;
    }
}

fn windowsFdSetIsSet(set: *const ws2_32.fd_set, s: WSA_SOCKET) bool {
    for (set.fd_array[0..set.fd_count]) |fd| {
        if (fd == s) return true;
    }
    return false;
}

fn formatWindowsIp(pa: std.mem.Allocator, ip: u32) ?[]u8 {
    return std.fmt.allocPrint(pa, "{d}.{d}.{d}.{d}", .{
        (ip >> 0) & 0xFF,
        (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 24) & 0xFF,
    }) catch null;
}

// g_generations owns its own keys (duped on first insert); entries are
// removed by unregisterActiveTest when a run ends, so the map doesn't grow
// without bound. Shared by registerActiveTest (a new run claiming the next
// generation) and stopInternal's restart path (pre-bumping the counter
// before the old run's g_running entry is even removed -- see
// stopForRestart).
fn nextGenerationLocked(test_id: []const u8) u64 {
    if (g_generations.getEntry(test_id)) |e| {
        e.value_ptr.* += 1;
        return e.value_ptr.*;
    }
    const gen_key = g_allocator.dupe(u8, test_id) catch return 1;
    g_generations.put(gen_key, 1) catch {
        g_allocator.free(gen_key);
    };
    return 1;
}

fn registerActiveTest(test_id: []const u8) ?u64 {
    const id_copy = g_allocator.dupe(u8, test_id) catch return null;
    g_mutex.lock();
    const generation = nextGenerationLocked(test_id);
    g_running.append(g_allocator, .{ .id = id_copy, .active = true, .generation = generation }) catch {
        g_mutex.unlock();
        g_allocator.free(id_copy);
        return null;
    };
    g_mutex.unlock();
    return generation;
}

fn unregisterActiveTest(test_id: []const u8, generation: u64) void {
    g_mutex.lock();
    for (g_running.items, 0..) |it, i| {
        if (std.mem.eql(u8, it.id, test_id) and it.generation == generation) {
            _ = g_running.orderedRemove(i);
            g_allocator.free(it.id);
            break;
        }
    }
    // Drop our generation entry unless a newer run of the same test_id has
    // already bumped it (stop -> restart overlap), keeping g_generations bounded.
    if (g_generations.getEntry(test_id)) |gentry| {
        if (gentry.value_ptr.* == generation) {
            const gkey = gentry.key_ptr.*;
            _ = g_generations.remove(test_id);
            g_allocator.free(gkey);
        }
    }
    g_mutex.unlock();
}

fn initHopState(pa: std.mem.Allocator, max_ttl: u8, hop_ips: *std.ArrayList(?[]u8), hop_latencies: *std.ArrayList(std.ArrayList(u64)), hop_sent: *std.ArrayList(u32), hop_reached: *std.ArrayList(bool)) !void {
    for (0..@as(usize, max_ttl) + 1) |_| {
        try hop_ips.append(pa, null);
        try hop_latencies.append(pa, std.ArrayList(u64){});
        try hop_sent.append(pa, 0);
        try hop_reached.append(pa, false);
    }
}

fn drainWindowsIcmpSocket(sock: WSA_SOCKET) void {
    var drain_buf: [512]u8 = undefined;
    var drain_from: ws2_32.sockaddr.in = undefined;
    var drain_from_len: i32 = @sizeOf(ws2_32.sockaddr.in);
    while (true) {
        const n = ws2_32.recvfrom(sock, &drain_buf, drain_buf.len, 0, @ptrCast(&drain_from), &drain_from_len);
        if (n == WSA_SOCKET_ERROR or n <= 0) break;
    }
}

fn getWindowsLocalAddressForTarget(target: std.net.Address) ?ws2_32.sockaddr.in {
    const probe_sock = ws2_32.socket(WSA_AF_INET, WSA_SOCK_DGRAM, ws2_32.IPPROTO.UDP);
    if (probe_sock == WSA_INVALID_SOCKET) return null;
    defer closeWindowsSocket(probe_sock);

    var target_addr = windowsSockaddrFromAddress(target);
    target_addr.port = ws2_32.htons(33434);
    if (ws2_32.connect(probe_sock, @ptrCast(&target_addr), @sizeOf(ws2_32.sockaddr.in)) == WSA_SOCKET_ERROR) return null;

    var local_addr: ws2_32.sockaddr.in = undefined;
    var local_len: i32 = @sizeOf(ws2_32.sockaddr.in);
    if (ws2_32.getsockname(probe_sock, @ptrCast(&local_addr), &local_len) == WSA_SOCKET_ERROR) return null;
    local_addr.port = 0;
    return local_addr;
}

fn createWindowsIpCaptureSocket(target: std.net.Address) ?WSA_SOCKET {
    var local_addr = getWindowsLocalAddressForTarget(target) orelse {
        std.log.err("Windows packet capture could not determine local IPv4 address", .{});
        return null;
    };

    const capture_sock = ws2_32.socket(WSA_AF_INET, WSA_SOCK_RAW, WSA_IPPROTO_IP);
    if (capture_sock == WSA_INVALID_SOCKET) {
        std.log.err("Windows packet capture raw IP socket error: {d}", .{winsockError()});
        return null;
    }

    if (ws2_32.bind(capture_sock, @ptrCast(&local_addr), @sizeOf(ws2_32.sockaddr.in)) == WSA_SOCKET_ERROR) {
        std.log.err("Windows packet capture bind error: {d}", .{winsockError()});
        closeWindowsSocket(capture_sock);
        return null;
    }

    var in_value: u32 = RCVALL_ON;
    var bytes_returned: u32 = 0;
    if (WSAIoctl(
        capture_sock,
        SIO_RCVALL,
        &in_value,
        @sizeOf(u32),
        null,
        0,
        &bytes_returned,
        null,
        null,
    ) == WSA_SOCKET_ERROR) {
        std.log.err("Windows packet capture SIO_RCVALL error: {d}", .{winsockError()});
        closeWindowsSocket(capture_sock);
        return null;
    }

    if (!setWindowsSocketNonBlocking(capture_sock)) {
        std.log.err("Windows packet capture failed to set non-blocking mode", .{});
        closeWindowsSocket(capture_sock);
        return null;
    }

    return capture_sock;
}

// Windows TCP/UDP MTR both depend on a raw IP capture socket (SIO_RCVALL)
// to see inbound ICMPv4 Time Exceeded (type 11)/Destination Unreachable
// (type 3) replies -- which Windows Firewall drops by default unless the
// installer's four "Linknesis Allow ICMPv4/ICMPv6 ..." inbound rules exist
// (see probe/install-windows.nsi, probe/install-windows.ps1). If those
// rules are missing (never created, removed by an OS upgrade/reset, or
// blocked by third-party security software), every hop silently times out
// at the full per-hop budget instead of erroring -- a real test found this
// live on a Windows 10 probe that had been in-place upgraded to Windows 11
// (rules present before the upgrade, gone after, since a probe that only
// self-updates its binary never re-runs the installer that creates them).
// A cycle can still nominally "complete" for TCP (the final hop resolves
// directly via the TCP connect() handshake itself, without needing capture
// at all) but every hop before the target still burns the full timeout, and
// UDP has no equivalent fallback (detecting the target at all requires
// capturing its own Destination-Unreachable reply) so it can look
// completely stuck. Since a real multi-hop path essentially always
// produces at least one captured ICMP reply somewhere along the way, zero
// captures across an entire test with more than one hop in range is a
// strong, low-risk signal worth logging clearly rather than only ever
// surfacing as "this took a very long time" with no explanation.
fn logIcmpCaptureHealthWarning(test_id: []const u8, protocol: []const u8, first_ttl: u8, max_ttl: u8) void {
    std.log.warn(
        "MTR {s} Windows test_id={s}: raw ICMP capture socket received zero Time " ++
            "Exceeded/Destination Unreachable replies across the whole test (hops {d}-{d}). " ++
            "This almost always means the required inbound Windows Firewall rules are " ++
            "missing or blocked -- 'Linknesis Allow ICMPv4 Time Exceeded'/'Linknesis Allow " ++
            "ICMPv4 Destination Unreachable' (plus the ICMPv6 equivalents). Re-run the " ++
            "probe installer as Administrator to recreate them, or check Windows Defender " ++
            "Firewall (or a Windows feature upgrade may have reset custom inbound rules).",
        .{ protocol, test_id, first_ttl, max_ttl },
    );
}

// Windows only. Called once at probe startup (see main.zig, on a detached
// thread so it never delays the WSS connection) to self-heal the four
// inbound Windows Firewall rules TCP/UDP MTR depends on. Historically these
// were only ever created by the installer (probe/ensure-mtr-firewall-
// rules.ps1, probe/install-windows.ps1) -- but they can go missing even on
// an already-working install (an in-place Windows 10->11 upgrade resets
// them), and a probe that only ever self-updates its binary
// would otherwise stay broken until someone noticed and manually
// reinstalled. The probe process already runs elevated (see this project's
// requireAdministrator manifest), so it can recreate the rules itself.
// The whole check+create+verify script is embedded here rather than shipped
// as a separate .ps1 file specifically so it travels with the binary and
// survives a binary-only self-update -- unlike every other install-time-only
// asset.
pub fn ensureWindowsMtrFirewallRules() void {
    if (@import("builtin").os.tag != .windows) return;

    const script =
        \\$ErrorActionPreference = 'Stop'
        \\function Ensure($name, $type, $proto) {
        \\  if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { Write-Output "OK:$name"; return }
        \\  try {
        \\    New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol $proto -IcmpType $type -Action Allow -Profile Any -ErrorAction Stop | Out-Null
        \\  } catch {
        \\    Write-Output "FAILCREATE:$name : $($_.Exception.Message)"
        \\    return
        \\  }
        \\  if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { Write-Output "CREATED:$name" } else { Write-Output "FAILVERIFY:$name" }
        \\}
        \\Ensure 'Linknesis Allow ICMPv4 Time Exceeded' 11 'ICMPv4'
        \\Ensure 'Linknesis Allow ICMPv4 Destination Unreachable' 3 'ICMPv4'
        \\Ensure 'Linknesis Allow ICMPv6 Time Exceeded' 3 'ICMPv6'
        \\Ensure 'Linknesis Allow ICMPv6 Destination Unreachable' 1 'ICMPv6'
    ;

    // Not std.process.Child.run(): that convenience wrapper never sets
    // create_no_window, so the console host still briefly flashes a window
    // for a console-subsystem child (powershell.exe) spawned from this
    // GUI-subsystem probe: a "-WindowStyle Hidden" CLI arg
    // alone (what this used before, and what updater.zig's downloadWithPowerShell
    // still uses) only affects PowerShell's own window state *after* the OS
    // has already created and shown the console. Build the Child manually so
    // create_no_window (wired to the real Win32 CREATE_NO_WINDOW flag) can be
    // set before spawn -- the same flag updater.zig's applyWindowsUpdate
    // already sets via a raw CreateProcessW call; this is the same fix via
    // the stdlib's own supported field instead of reimplementing CreateProcess.
    var child = std.process.Child.init(
        &[_][]const u8{ "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script },
        g_allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.create_no_window = true;

    child.spawn() catch |err| {
        std.log.err("MTR firewall rule self-check: failed to spawn powershell.exe: {any}", .{err});
        return;
    };

    var stdout_buf: std.ArrayList(u8) = .empty;
    defer stdout_buf.deinit(g_allocator);
    var stderr_buf: std.ArrayList(u8) = .empty;
    defer stderr_buf.deinit(g_allocator);
    child.collectOutput(g_allocator, &stdout_buf, &stderr_buf, 64 * 1024) catch |err| {
        std.log.err("MTR firewall rule self-check: failed to read powershell.exe output: {any}", .{err});
        _ = child.kill() catch {};
        return;
    };
    const term = child.wait() catch |err| {
        std.log.err("MTR firewall rule self-check: failed to wait for powershell.exe: {any}", .{err});
        return;
    };
    const stdout = stdout_buf.items;
    const stderr = stderr_buf.items;

    var any_fail = false;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "OK:")) {
            std.log.info("MTR firewall rule already present: {s}", .{line["OK:".len..]});
        } else if (std.mem.startsWith(u8, line, "CREATED:")) {
            std.log.info("MTR firewall rule created: {s}", .{line["CREATED:".len..]});
        } else {
            any_fail = true;
            std.log.err("MTR firewall rule self-heal failed: {s}", .{line});
        }
    }

    switch (term) {
        .Exited => |code| {
            if (code != 0 and !any_fail) {
                std.log.err("MTR firewall rule self-check: powershell.exe exited with code {d}: {s}", .{ code, stderr });
                any_fail = true;
            }
        },
        else => {
            std.log.err("MTR firewall rule self-check: powershell.exe terminated abnormally: {s}", .{stderr});
            any_fail = true;
        },
    }

    if (any_fail) {
        std.log.warn("One or more MTR firewall rules could not be created/verified automatically -- TCP/UDP MTR may be slow (every hop before the target will time out). Check Windows Defender Firewall, or re-run the probe installer as Administrator.", .{});
    }
}

fn runWindowsMtrUdp(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    std.log.info("MTR UDP Windows run start test_id={s} port={d} first_ttl={d} max_ttl={d} counts={d} interval={d}", .{ test_id, port, first_ttl, max_ttl, counts, interval_sec });

    const timeout_ms: i64 = 5000;
    const target_ip_u32 = @as(u32, @bitCast(addr.in.sa.addr));

    const capture_sock = createWindowsIpCaptureSocket(addr) orelse {
        sendTestError(test_id, "Windows UDP MTR packet capture failed");
        return;
    };
    defer closeWindowsSocket(capture_sock);

    const generation = registerActiveTest(test_id) orelse return;
    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| if (maybe_ip) |ip| pa.free(ip);
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| list.deinit(pa);
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);
    initHopState(pa, max_ttl, &hop_ips, &hop_latencies, &hop_sent, &hop_reached) catch return;

    var reached_target = false;
    var first_reached_hop: u8 = 0;
    var any_icmp_captured = false;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;
        drainWindowsIcmpSocket(capture_sock);

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // u16 (not u8) so the loop-continuation increment below can never
        // overflow when max_ttl == 255 (a valid, user-suppliable value):
        // the last iteration runs with hop == 255 and then increments to
        // 256, which would panic/wrap a u8 counter.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            const udp_sock = ws2_32.socket(WSA_AF_INET, WSA_SOCK_DGRAM, ws2_32.IPPROTO.UDP);
            if (udp_sock == WSA_INVALID_SOCKET) {
                std.log.err("MTR UDP Windows probe socket error: {d}", .{winsockError()});
                continue;
            }

            var should_close_udp = true;
            defer if (should_close_udp) closeWindowsSocket(udp_sock);

            var bind_addr = windowsSockaddrFromAddress(std.net.Address.parseIp4("0.0.0.0", 0) catch continue);
            if (ws2_32.bind(udp_sock, @ptrCast(&bind_addr), @sizeOf(ws2_32.sockaddr.in)) == WSA_SOCKET_ERROR) continue;

            const local_port = getWindowsLocalPort(udp_sock);
            if (local_port == 0) continue;
            if (!setWindowsSocketInt(udp_sock, WSA_IPPROTO_IP, WSA_IP_TTL, hop)) continue;

            var target_addr = windowsSockaddrFromAddress(addr);
            target_addr.port = ws2_32.htons(port);

            const seq: u16 = @intCast(@mod(@as(u64, @intCast(cycle)) * 256 + hop, 65536));
            var udp_payload = [_]u8{0} ** 32;
            std.mem.writeInt(u16, udp_payload[0..2], seq, .big);

            const start = std.time.milliTimestamp();
            const sent = ws2_32.sendto(udp_sock, &udp_payload, udp_payload.len, 0, @ptrCast(&target_addr), @sizeOf(ws2_32.sockaddr.in));
            closeWindowsSocket(udp_sock);
            should_close_udp = false;
            if (sent == WSA_SOCKET_ERROR) continue;
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;
            var recv_packets: u32 = 0;
            var icmp_packets: u32 = 0;
            var protocol_misses: u32 = 0;
            var port_misses: u32 = 0;

            while (true) {
                const elapsed_now = std.time.milliTimestamp() - start;
                if (elapsed_now >= timeout_ms) break;

                var read_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&read_fds);
                windowsFdSetAdd(&read_fds, capture_sock);
                var tv = ws2_32.timeval{ .sec = 0, .usec = 100_000 };
                const ready = ws2_32.select(0, &read_fds, null, null, &tv);
                if (ready == WSA_SOCKET_ERROR or ready == 0) continue;
                if (!windowsFdSetIsSet(&read_fds, capture_sock)) continue;

                var recv_buf: [512]u8 = undefined;
                var from_addr: ws2_32.sockaddr.in = undefined;
                var from_len: i32 = @sizeOf(ws2_32.sockaddr.in);
                const recv_n = ws2_32.recvfrom(capture_sock, &recv_buf, recv_buf.len, 0, @ptrCast(&from_addr), &from_len);
                if (recv_n <= 0) continue;
                recv_packets += 1;
                if (recv_n < 28 + 20 + 8) continue;

                const ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                const icmp_type = recv_buf[ip_hdr_len];
                const icmp_code = recv_buf[ip_hdr_len + 1];
                if (icmp_type != 3 and icmp_type != 11) continue;
                icmp_packets += 1;
                const payload_offset = ip_hdr_len + 8;
                if (recv_n < payload_offset + 20 + 8) continue;

                const orig_ip_hdr_len = (recv_buf[payload_offset] & 0x0F) * 4;
                const orig_proto = recv_buf[payload_offset + 9];
                const orig_udp_offset = payload_offset + orig_ip_hdr_len;
                if (recv_n < orig_udp_offset + 8) continue;

                const orig_src_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_udp_offset .. orig_udp_offset + 2]));
                const orig_dst_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_udp_offset + 2 .. orig_udp_offset + 4]));

                var orig_seq: u16 = 0xFFFF;
                if (recv_n >= orig_udp_offset + 8 + 2) {
                    orig_seq = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_udp_offset + 8 .. orig_udp_offset + 10]));
                }

                if (orig_proto != 17) {
                    protocol_misses += 1;
                    continue;
                }
                if (orig_dst_port != port or orig_src_port != local_port) {
                    port_misses += 1;
                    continue;
                }
                if (recv_n >= orig_udp_offset + 8 + 2 and orig_seq != seq) continue;

                elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                const src_ip = @as(u32, @bitCast(from_addr.addr));
                ip_str = formatWindowsIp(pa, src_ip);

                if (icmp_type == 3 and icmp_code == 3 and src_ip == target_ip_u32) {
                    std.log.info("MTR UDP Windows reached target hop={d} ip={s}", .{ hop, ip_str orelse "" });
                    is_target = true;
                    matched = true;
                    break;
                } else if (icmp_type == 11) {
                    std.log.debug("MTR UDP Windows time exceeded hop={d} ip={s}", .{ hop, ip_str orelse "" });
                    matched = true;
                    break;
                }
                // Unrelated error message: drop the formatted IP and keep waiting.
                if (ip_str) |ip| pa.free(ip);
                ip_str = null;
            }

            if (icmp_packets > 0) any_icmp_captured = true;

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR UDP Windows no matching response test_id={s} hop={d} cycle={d} captured={d} icmp={d} protocol_misses={d} port_misses={d}", .{ test_id, hop, cycle, recv_packets, icmp_packets, protocol_misses, port_misses });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }

    if (!any_icmp_captured and max_ttl > first_ttl) {
        logIcmpCaptureHealthWarning(test_id, "UDP", first_ttl, max_ttl);
    }
}

fn runWindowsMtrTcp(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    std.log.info("MTR TCP Windows run start test_id={s} port={d} first_ttl={d} max_ttl={d} counts={d} interval={d}", .{ test_id, port, first_ttl, max_ttl, counts, interval_sec });

    const timeout_ms: i64 = 5000;
    const target_ip_u32 = @as(u32, @bitCast(addr.in.sa.addr));

    const capture_sock = createWindowsIpCaptureSocket(addr) orelse {
        sendTestError(test_id, "Windows TCP MTR packet capture failed");
        return;
    };
    defer closeWindowsSocket(capture_sock);

    const generation = registerActiveTest(test_id) orelse return;
    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| if (maybe_ip) |ip| pa.free(ip);
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| list.deinit(pa);
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);
    initHopState(pa, max_ttl, &hop_ips, &hop_latencies, &hop_sent, &hop_reached) catch return;

    var reached_target = false;
    var first_reached_hop: u8 = 0;
    var any_icmp_captured = false;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;
        drainWindowsIcmpSocket(capture_sock);

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // u16 (not u8) so the loop-continuation increment below can never
        // overflow when max_ttl == 255 (a valid, user-suppliable value):
        // the last iteration runs with hop == 255 and then increments to
        // 256, which would panic/wrap a u8 counter.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            const tcp_sock = ws2_32.socket(WSA_AF_INET, WSA_SOCK_STREAM, WSA_IPPROTO_TCP);
            if (tcp_sock == WSA_INVALID_SOCKET) {
                std.log.err("MTR TCP Windows probe socket error: {d}", .{winsockError()});
                continue;
            }
            var should_close_tcp = true;
            defer if (should_close_tcp) closeWindowsSocket(tcp_sock);

            if (!setWindowsSocketNonBlocking(tcp_sock)) continue;
            _ = setWindowsSocketInt(tcp_sock, WSA_SOL_SOCKET, WSA_SO_REUSEADDR, 1);
            if (!setWindowsSocketInt(tcp_sock, WSA_IPPROTO_IP, WSA_IP_TTL, hop)) continue;

            var target_addr = windowsSockaddrFromAddress(addr);
            target_addr.port = ws2_32.htons(port);

            const start = std.time.milliTimestamp();
            const conn_rc = ws2_32.connect(tcp_sock, @ptrCast(&target_addr), @sizeOf(ws2_32.sockaddr.in));
            if (conn_rc == WSA_SOCKET_ERROR) {
                const err = winsockError();
                if (err != @intFromEnum(ws2_32.WinsockError.WSAEWOULDBLOCK) and err != @intFromEnum(ws2_32.WinsockError.WSAEINPROGRESS)) {
                    closeWindowsSocket(tcp_sock);
                    should_close_tcp = false;
                    continue;
                }
            }

            const local_port = getWindowsLocalPort(tcp_sock);
            if (local_port == 0) {
                closeWindowsSocket(tcp_sock);
                should_close_tcp = false;
                continue;
            }
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;
            var recv_packets: u32 = 0;
            var icmp_packets: u32 = 0;
            var protocol_misses: u32 = 0;
            var port_misses: u32 = 0;

            while (true) {
                const elapsed_now = std.time.milliTimestamp() - start;
                if (elapsed_now >= timeout_ms) break;

                var read_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&read_fds);
                windowsFdSetAdd(&read_fds, capture_sock);
                var write_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&write_fds);
                windowsFdSetAdd(&write_fds, tcp_sock);
                var except_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&except_fds);
                windowsFdSetAdd(&except_fds, tcp_sock);

                const remaining = timeout_ms - elapsed_now;
                if (remaining <= 0) break;
                var tv = ws2_32.timeval{ .sec = @intCast(@divFloor(remaining, 1000)), .usec = @intCast(@mod(remaining, 1000) * 1000) };
                const ready = ws2_32.select(0, &read_fds, &write_fds, &except_fds, &tv);
                if (ready == WSA_SOCKET_ERROR or ready == 0) continue;

                if (windowsFdSetIsSet(&read_fds, capture_sock)) {
                    var recv_buf: [512]u8 = undefined;
                    var from_addr: ws2_32.sockaddr.in = undefined;
                    var from_len: i32 = @sizeOf(ws2_32.sockaddr.in);
                    const recv_n = ws2_32.recvfrom(capture_sock, &recv_buf, recv_buf.len, 0, @ptrCast(&from_addr), &from_len);
                    if (recv_n > 0) recv_packets += 1;
                    if (recv_n > 0 and recv_n >= 28 + 20 + 8) {
                        const ip_hdr_len = (recv_buf[0] & 0x0F) * 4;
                        const icmp_type = recv_buf[ip_hdr_len];
                        const icmp_code = recv_buf[ip_hdr_len + 1];
                        if (icmp_type != 3 and icmp_type != 11) continue;
                        icmp_packets += 1;
                        const payload_offset = ip_hdr_len + 8;
                        if (recv_n >= payload_offset + 20 + 8) {
                            const orig_ip_hdr_len = (recv_buf[payload_offset] & 0x0F) * 4;
                            const orig_proto = recv_buf[payload_offset + 9];
                            const orig_tcp_offset = payload_offset + orig_ip_hdr_len;
                            if (recv_n >= orig_tcp_offset + 8) {
                                const orig_src_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_tcp_offset .. orig_tcp_offset + 2]));
                                const orig_dst_port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, recv_buf[orig_tcp_offset + 2 .. orig_tcp_offset + 4]));
                                if (orig_proto != 6) {
                                    protocol_misses += 1;
                                } else if (orig_dst_port != port or orig_src_port != local_port) {
                                    port_misses += 1;
                                } else {
                                    elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                                    const src_ip = @as(u32, @bitCast(from_addr.addr));
                                    ip_str = formatWindowsIp(pa, src_ip);
                                    if (icmp_type == 3 and icmp_code == 3 and src_ip == target_ip_u32) {
                                        is_target = true;
                                        matched = true;
                                        break;
                                    } else if (icmp_type == 11) {
                                        matched = true;
                                        break;
                                    }
                                    // Unrelated error message: drop the formatted IP and keep waiting.
                                    if (ip_str) |ip| pa.free(ip);
                                    ip_str = null;
                                }
                            }
                        }
                    }
                }

                if (windowsFdSetIsSet(&write_fds, tcp_sock) or windowsFdSetIsSet(&except_fds, tcp_sock)) {
                    const so_err = getWindowsSocketInt(tcp_sock, WSA_SOL_SOCKET, WSA_SO_ERROR);
                    if (so_err == 0 or so_err == @intFromEnum(ws2_32.WinsockError.WSAECONNREFUSED)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_target = true;
                        if (ip_str) |ip| pa.free(ip);
                        ip_str = formatWindowsIp(pa, target_ip_u32);
                        std.log.info("MTR TCP Windows reached target hop={d} ip={s} so_err={d}", .{ hop, ip_str orelse "", so_err });
                        matched = true;
                        break;
                    } else if (so_err == @intFromEnum(ws2_32.WinsockError.WSAEHOSTUNREACH) or so_err == @intFromEnum(ws2_32.WinsockError.WSAENETUNREACH)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        if (ip_str) |ip| pa.free(ip);
                        ip_str = formatWindowsIp(pa, target_ip_u32);
                        matched = true;
                        break;
                    }
                }
            }

            closeWindowsSocket(tcp_sock);
            should_close_tcp = false;

            if (icmp_packets > 0) any_icmp_captured = true;

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR TCP Windows no matching response test_id={s} hop={d} cycle={d} captured={d} icmp={d} protocol_misses={d} port_misses={d}", .{ test_id, hop, cycle, recv_packets, icmp_packets, protocol_misses, port_misses });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }

    // Unlike UDP, a fully-reachable TCP target can complete every hop cycle
    // via the connect() handshake alone (see logIcmpCaptureHealthWarning's
    // doc comment) -- so zero captures here doesn't always mean the test
    // "looked stuck", just that every hop before the target silently ate
    // the full per-hop timeout. Still worth flagging under the same
    // condition as UDP.
    if (!any_icmp_captured and max_ttl > first_ttl) {
        logIcmpCaptureHealthWarning(test_id, "TCP", first_ttl, max_ttl);
    }
}

fn runWindowsMtr(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: u32 = 5000;

    const handle = IcmpCreateFile();
    if (handle == win.INVALID_HANDLE_VALUE) {
        std.log.err("MTR IcmpCreateFile failed", .{});
        return;
    }
    defer _ = IcmpCloseHandle(handle);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    const dest_ip = addr.in.sa.addr; // network byte order u32

    // Hop state arrays indexed by hop number (0 unused)
    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);

    for (0..@as(usize, max_ttl) + 1) |_| {
        hop_ips.append(pa, null) catch return;
        hop_latencies.append(pa, std.ArrayList(u64){}) catch return;
        hop_sent.append(pa, 0) catch return;
        hop_reached.append(pa, false) catch return;
    }

    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    const send_data = &[_]u8{0} ** 32;
    var reply_buf: [4096]u8 = undefined;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // u16 (not u8) so the loop-continuation increment below can never
        // overflow when max_ttl == 255 (a valid, user-suppliable value):
        // the last iteration runs with hop == 255 and then increments to
        // 256, which would panic/wrap a u8 counter.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;

            // Skip hops beyond target in subsequent cycles
            if (reached_target and hop > first_reached_hop) {
                continue;
            }

            var opts = IP_OPTION_INFORMATION{
                .Ttl = @intCast(hop),
                .Tos = 0,
                .Flags = 0,
                .OptionsSize = 0,
                .OptionsData = null,
            };
            const start = std.time.milliTimestamp();
            const replies = IcmpSendEcho(
                handle,
                dest_ip,
                send_data.ptr,
                @intCast(send_data.len),
                &opts,
                &reply_buf,
                reply_buf.len,
                timeout_ms,
            );
            const elapsed: u64 = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
            hop_sent.items[hop] += 1;

            if (replies == 0) {
                std.log.debug("MTR IcmpSendEcho no reply hop={d} cycle={d}", .{ hop, cycle });
                const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
                cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
                continue;
            }

            const echo_reply = std.mem.bytesAsValue(ICMP_ECHO_REPLY, reply_buf[0..@sizeOf(ICMP_ECHO_REPLY)]);
            const ip_addr = @as(u32, @bitCast(echo_reply.Address));
            const ip_str = std.fmt.allocPrint(pa, "{d}.{d}.{d}.{d}", .{
                (ip_addr >> 0) & 0xFF,
                (ip_addr >> 8) & 0xFF,
                (ip_addr >> 16) & 0xFF,
                (ip_addr >> 24) & 0xFF,
            }) catch continue;
            std.log.info("MTR got ip={s} hop={d} cycle={d}", .{ ip_str, hop, cycle });
            if (hop_ips.items[hop]) |h| pa.free(h);
            hop_ips.items[hop] = ip_str;
            hop_latencies.items[hop].append(pa, elapsed) catch {};

            // Status 0 is success (IP_SUCCESS)
            if (echo_reply.Status == 0) {
                std.log.info("MTR reached target at hop={d}", .{hop});
                hop_reached.items[hop] = true;
                if (!reached_target) {
                    reached_target = true;
                    first_reached_hop = @intCast(hop);
                }
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// Windows sockaddr_in6 (ws2ipdef.h layout). Defined locally so the extern
// signature of Icmp6SendEcho2 does not depend on std's ws2_32 definitions.
const WsaSockaddrIn6 = extern struct {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};
const WSA_AF_INET6: u16 = 23;

fn runWindowsMtrIcmp6(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    const timeout_ms: u32 = 5000;

    const handle = Icmp6CreateFile();
    if (handle == win.INVALID_HANDLE_VALUE) {
        std.log.err("MTR Icmp6CreateFile failed", .{});
        sendTestError(test_id, "ICMPv6 handle creation failed");
        return;
    }
    defer _ = IcmpCloseHandle(handle);

    const generation = registerActiveTest(test_id) orelse return;

    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    // Source is the unspecified address (::); the stack picks the real one.
    const src6 = WsaSockaddrIn6{
        .family = WSA_AF_INET6,
        .port = 0,
        .flowinfo = 0,
        .addr = [_]u8{0} ** 16,
        .scope_id = 0,
    };
    const dst6 = WsaSockaddrIn6{
        .family = WSA_AF_INET6,
        .port = 0,
        .flowinfo = 0,
        .addr = addr.in6.sa.addr,
        .scope_id = addr.in6.sa.scope_id,
    };

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| {
            if (maybe_ip) |ip| pa.free(ip);
        }
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| {
            list.deinit(pa);
        }
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);

    for (0..@as(usize, max_ttl) + 1) |_| {
        hop_ips.append(pa, null) catch return;
        hop_latencies.append(pa, std.ArrayList(u64){}) catch return;
        hop_sent.append(pa, 0) catch return;
        hop_reached.append(pa, false) catch return;
    }

    var reached_target: bool = false;
    var first_reached_hop: u8 = 0;

    const send_data = &[_]u8{0} ** 32;
    var reply_buf: [4096]u8 = undefined;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        // u16 counter for the same max_ttl == 255 overflow reason as the
        // IPv4 backend.
        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;

            if (reached_target and hop > first_reached_hop) {
                continue;
            }

            var opts = IP_OPTION_INFORMATION{
                .Ttl = @intCast(hop), // acts as the IPv6 hop limit
                .Tos = 0,
                .Flags = 0,
                .OptionsSize = 0,
                .OptionsData = null,
            };
            const start = std.time.milliTimestamp();
            const replies = Icmp6SendEcho2(
                handle,
                null,
                null,
                null,
                &src6,
                &dst6,
                send_data.ptr,
                @intCast(send_data.len),
                &opts,
                &reply_buf,
                reply_buf.len,
                timeout_ms,
            );
            const elapsed: u64 = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
            hop_sent.items[hop] += 1;

            if (replies == 0) {
                std.log.debug("MTR Icmp6SendEcho2 no reply hop={d} cycle={d}", .{ hop, cycle });
                const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
                cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
                continue;
            }

            const echo_reply = std.mem.bytesAsValue(ICMPV6_ECHO_REPLY, reply_buf[0..@sizeOf(ICMPV6_ECHO_REPLY)]);
            // Drop the scope_id for display: hops on a global-scope path have
            // scope 0, and a %scope suffix would only confuse the GUI.
            const reply_addr = std.net.Address.initIp6(echo_reply.Address.sin6_addr, 0, 0, 0);
            const ip_str = formatSrcIp(pa, reply_addr) orelse continue;
            std.log.info("MTR6 got ip={s} hop={d} cycle={d} status={d}", .{ ip_str, hop, cycle, echo_reply.Status });
            if (hop_ips.items[hop]) |h| pa.free(h);
            hop_ips.items[hop] = ip_str;
            hop_latencies.items[hop].append(pa, elapsed) catch {};

            // Status 0 is success (IP_SUCCESS); hop-limit-exceeded replies
            // carry a nonzero status with the intermediate router's address.
            if (echo_reply.Status == 0) {
                std.log.info("MTR6 reached target at hop={d}", .{hop});
                hop_reached.items[hop] = true;
                if (!reached_target) {
                    reached_target = true;
                    first_reached_hop = @intCast(hop);
                }
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }
}

// ------------------------------------------------------------------
// Windows MTR UDP/TCP over IPv6 (raw ICMPv6 capture socket)
// ------------------------------------------------------------------
// Capture uses a plain AF_INET6/SOCK_RAW/IPPROTO_ICMPV6 socket bound to the
// local address. Verified on the lab Windows VM: it receives Time Exceeded /
// Destination Unreachable errors for our closed/unconnected UDP and TCP
// probes -- but ONLY when inbound ICMPv6 Type 3 (Time Exceeded) and Type 1
// (Destination Unreachable) Windows Firewall rules exist (the installer
// creates them, mirroring the ICMPv4 Type 11/3 rules the IPv4 path needs).
// Without the firewall rules the stack silently drops the errors and every
// hop times out, which is exactly what a missing-rule deployment looks like.
// Do NOT switch this to SIO_RCVALL on an IPPROTO_IPV6 socket: unlike IPv4's
// SIO_RCVALL capture, it was measured to capture nothing at all on Windows
// (not even inbound echo replies). Received datagrams start directly at the
// ICMPv6 header (Windows raw IPv6 sockets never include the IPv6 header);
// parseWindowsIcmp6Capture keeps the header-detection fallback for safety.
const WSA_IPPROTO_ICMPV6: i32 = 58;
const WSA_IPPROTO_IPV6: i32 = 41;
const WSA_IPV6_UNICAST_HOPS: i32 = 4;

fn windowsSockaddrIn6FromAddress(addr: std.net.Address, port: u16) WsaSockaddrIn6 {
    return .{
        .family = WSA_AF_INET6,
        .port = ws2_32.htons(port),
        .flowinfo = 0,
        .addr = addr.in6.sa.addr,
        .scope_id = addr.in6.sa.scope_id,
    };
}

fn getWindowsLocalPort6(s: WSA_SOCKET) u16 {
    var local: WsaSockaddrIn6 = undefined;
    var len: i32 = @sizeOf(WsaSockaddrIn6);
    if (ws2_32.getsockname(s, @ptrCast(&local), &len) == WSA_SOCKET_ERROR) return 0;
    return ws2_32.ntohs(local.port);
}

fn getWindowsLocalAddressForTarget6(target: std.net.Address) ?WsaSockaddrIn6 {
    const probe_sock = ws2_32.socket(WSA_AF_INET6, WSA_SOCK_DGRAM, ws2_32.IPPROTO.UDP);
    if (probe_sock == WSA_INVALID_SOCKET) return null;
    defer closeWindowsSocket(probe_sock);

    var target_addr = windowsSockaddrIn6FromAddress(target, 33434);
    if (ws2_32.connect(probe_sock, @ptrCast(&target_addr), @sizeOf(WsaSockaddrIn6)) == WSA_SOCKET_ERROR) return null;

    var local_addr: WsaSockaddrIn6 = undefined;
    var local_len: i32 = @sizeOf(WsaSockaddrIn6);
    if (ws2_32.getsockname(probe_sock, @ptrCast(&local_addr), &local_len) == WSA_SOCKET_ERROR) return null;
    local_addr.port = 0;
    return local_addr;
}

fn createWindowsIcmp6CaptureSocket(target: std.net.Address) ?WSA_SOCKET {
    var local_addr = getWindowsLocalAddressForTarget6(target) orelse {
        std.log.err("Windows IPv6 capture could not determine local IPv6 address", .{});
        return null;
    };

    const capture_sock = ws2_32.socket(WSA_AF_INET6, WSA_SOCK_RAW, WSA_IPPROTO_ICMPV6);
    if (capture_sock == WSA_INVALID_SOCKET) {
        std.log.err("Windows IPv6 capture raw socket error: {d}", .{winsockError()});
        return null;
    }

    // Raw sockets on Windows must be bound before they can receive.
    if (ws2_32.bind(capture_sock, @ptrCast(&local_addr), @sizeOf(WsaSockaddrIn6)) == WSA_SOCKET_ERROR) {
        std.log.err("Windows IPv6 capture bind error: {d}", .{winsockError()});
        closeWindowsSocket(capture_sock);
        return null;
    }

    if (!setWindowsSocketNonBlocking(capture_sock)) {
        std.log.err("Windows IPv6 capture failed to set non-blocking mode", .{});
        closeWindowsSocket(capture_sock);
        return null;
    }

    return capture_sock;
}

const WinIcmp6Packet = struct {
    info: Icmp6ErrorInfo,
    // Source address parsed from the captured IPv6 header when present;
    // callers fall back to recvfrom's from_addr when null.
    src: ?[16]u8,
};

// SIO_RCVALL capture may hand us either a full IPv6 datagram (header
// included) or just the payload, and it captures ALL protocols, so detect
// and filter here: an IPv6 header starts with version nibble 6 and carries
// Next Header 58 for ICMPv6.
fn parseWindowsIcmp6Capture(buf: []const u8) ?WinIcmp6Packet {
    if (buf.len >= 40 + 8 and (buf[0] >> 4) == 6) {
        if (buf[6] != 58) return null; // not ICMPv6
        const info = parseIcmp6Error(buf[40..]) orelse return null;
        var src: [16]u8 = undefined;
        @memcpy(&src, buf[8..24]);
        return .{ .info = info, .src = src };
    }
    const info = parseIcmp6Error(buf) orelse return null;
    return .{ .info = info, .src = null };
}

fn drainWindowsIcmp6Socket(sock: WSA_SOCKET) void {
    var drain_buf: [512]u8 = undefined;
    var drain_from: WsaSockaddrIn6 = undefined;
    var drain_from_len: i32 = @sizeOf(WsaSockaddrIn6);
    while (true) {
        const n = ws2_32.recvfrom(sock, &drain_buf, drain_buf.len, 0, @ptrCast(&drain_from), &drain_from_len);
        if (n == WSA_SOCKET_ERROR or n <= 0) break;
    }
}

fn runWindowsMtrUdp6(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    std.log.info("MTR UDP6 Windows run start test_id={s} port={d} first_ttl={d} max_ttl={d} counts={d} interval={d}", .{ test_id, port, first_ttl, max_ttl, counts, interval_sec });

    const timeout_ms: i64 = 5000;
    const target_ip6 = addr.in6.sa.addr;

    const capture_sock = createWindowsIcmp6CaptureSocket(addr) orelse {
        sendTestError(test_id, "Windows UDP6 MTR ICMPv6 capture failed");
        return;
    };
    defer closeWindowsSocket(capture_sock);

    const generation = registerActiveTest(test_id) orelse return;
    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| if (maybe_ip) |ip| pa.free(ip);
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| list.deinit(pa);
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);
    initHopState(pa, max_ttl, &hop_ips, &hop_latencies, &hop_sent, &hop_reached) catch return;

    var reached_target = false;
    var first_reached_hop: u8 = 0;
    var any_icmp_captured = false;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;
        drainWindowsIcmp6Socket(capture_sock);

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            const udp_sock = ws2_32.socket(WSA_AF_INET6, WSA_SOCK_DGRAM, ws2_32.IPPROTO.UDP);
            if (udp_sock == WSA_INVALID_SOCKET) {
                std.log.err("MTR UDP6 Windows probe socket error: {d}", .{winsockError()});
                continue;
            }
            var should_close_udp = true;
            defer if (should_close_udp) closeWindowsSocket(udp_sock);

            const any6 = std.net.Address.parseIp6("::", 0) catch continue;
            var bind_addr = windowsSockaddrIn6FromAddress(any6, 0);
            if (ws2_32.bind(udp_sock, @ptrCast(&bind_addr), @sizeOf(WsaSockaddrIn6)) == WSA_SOCKET_ERROR) continue;

            const local_port = getWindowsLocalPort6(udp_sock);
            if (local_port == 0) continue;
            if (!setWindowsSocketInt(udp_sock, WSA_IPPROTO_IPV6, WSA_IPV6_UNICAST_HOPS, hop)) continue;

            var target_addr = windowsSockaddrIn6FromAddress(addr, port);

            const seq: u16 = @intCast(@mod(@as(u64, @intCast(cycle)) * 256 + hop, 65536));
            var udp_payload = [_]u8{0} ** 32;
            std.mem.writeInt(u16, udp_payload[0..2], seq, .big);

            const start = std.time.milliTimestamp();
            const sent = ws2_32.sendto(udp_sock, &udp_payload, udp_payload.len, 0, @ptrCast(&target_addr), @sizeOf(WsaSockaddrIn6));
            closeWindowsSocket(udp_sock);
            should_close_udp = false;
            if (sent == WSA_SOCKET_ERROR) continue;
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                const elapsed_now = std.time.milliTimestamp() - start;
                if (elapsed_now >= timeout_ms) break;

                var read_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&read_fds);
                windowsFdSetAdd(&read_fds, capture_sock);
                var tv = ws2_32.timeval{ .sec = 0, .usec = 100_000 };
                const ready = ws2_32.select(0, &read_fds, null, null, &tv);
                if (ready == WSA_SOCKET_ERROR or ready == 0) continue;
                if (!windowsFdSetIsSet(&read_fds, capture_sock)) continue;

                var recv_buf: [1024]u8 = undefined;
                var from_addr: WsaSockaddrIn6 = undefined;
                var from_len: i32 = @sizeOf(WsaSockaddrIn6);
                const recv_n = ws2_32.recvfrom(capture_sock, &recv_buf, recv_buf.len, 0, @ptrCast(&from_addr), &from_len);
                if (recv_n <= 0) continue;

                const pkt = parseWindowsIcmp6Capture(recv_buf[0..@intCast(recv_n)]) orelse continue;
                any_icmp_captured = true;
                const info = pkt.info;
                if (info.orig_proto != 17) continue;
                if (info.orig_dst_port != port or info.orig_src_port != local_port) continue;
                if (info.orig_seq) |s| {
                    if (s != seq) continue;
                }

                elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                const src_bytes: [16]u8 = pkt.src orelse from_addr.addr;
                const src_addr = std.net.Address.initIp6(src_bytes, 0, 0, 0);
                const src_is_target = sameIpv6(src_bytes, target_ip6);
                ip_str = formatSrcIp(pa, src_addr);

                if (info.icmp_type == 1 and info.icmp_code == 4 and src_is_target) {
                    std.log.info("MTR UDP6 Windows reached target hop={d} ip={s}", .{ hop, ip_str orelse "" });
                    is_target = true;
                    matched = true;
                    break;
                } else if (info.icmp_type == 3) {
                    std.log.debug("MTR UDP6 Windows time exceeded hop={d} ip={s}", .{ hop, ip_str orelse "" });
                    matched = true;
                    break;
                }
                if (ip_str) |ip| pa.free(ip);
                ip_str = null;
            }

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR UDP6 Windows no matching response test_id={s} hop={d} cycle={d}", .{ test_id, hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }

    if (!any_icmp_captured and max_ttl > first_ttl) {
        logIcmpCaptureHealthWarning(test_id, "UDP6", first_ttl, max_ttl);
    }
}

fn runWindowsMtrTcp6(pa: std.mem.Allocator, test_id: []const u8, addr: std.net.Address, port: u16, no_dns: bool, first_ttl: u8, max_ttl: u8, counts: i64, interval_sec: i64, resumed: bool) void {
    std.log.info("MTR TCP6 Windows run start test_id={s} port={d} first_ttl={d} max_ttl={d} counts={d} interval={d}", .{ test_id, port, first_ttl, max_ttl, counts, interval_sec });

    const timeout_ms: i64 = 5000;
    const target_ip6 = addr.in6.sa.addr;

    const capture_sock = createWindowsIcmp6CaptureSocket(addr) orelse {
        sendTestError(test_id, "Windows TCP6 MTR ICMPv6 capture failed");
        return;
    };
    defer closeWindowsSocket(capture_sock);

    const generation = registerActiveTest(test_id) orelse return;
    defer {
        // sendComplete must run BEFORE unregisterActiveTest: unregister removes
        // this test_id's g_generations entry, and sendComplete's isCurrentGeneration
        // check reads that entry to decide whether a newer run superseded this one.
        sendComplete(test_id, generation);
        unregisterActiveTest(test_id, generation);
    }

    var hop_ips = std.ArrayList(?[]u8){};
    defer {
        for (hop_ips.items) |maybe_ip| if (maybe_ip) |ip| pa.free(ip);
        hop_ips.deinit(pa);
    }
    var hop_latencies = std.ArrayList(std.ArrayList(u64)){};
    defer {
        for (hop_latencies.items) |*list| list.deinit(pa);
        hop_latencies.deinit(pa);
    }
    var hop_sent = std.ArrayList(u32){};
    defer hop_sent.deinit(pa);
    var hop_reached = std.ArrayList(bool){};
    defer hop_reached.deinit(pa);
    initHopState(pa, max_ttl, &hop_ips, &hop_latencies, &hop_sent, &hop_reached) catch return;

    var reached_target = false;
    var first_reached_hop: u8 = 0;
    var any_icmp_captured = false;

    var cycle: i64 = 0;
    while (counts == 0 or cycle < counts) : (cycle += 1) {
        if (!isTestActive(test_id, generation)) break;
        drainWindowsIcmp6Socket(capture_sock);

        var cycle_reports = std.ArrayList([]const u8){};
        defer {
            for (cycle_reports.items) |r| pa.free(r);
            cycle_reports.deinit(pa);
        }

        var hop: u16 = first_ttl;
        while (hop <= max_ttl) : (hop += 1) {
            if (!isTestActive(test_id, generation)) break;
            if (reached_target and hop > first_reached_hop) continue;

            var target_addr = windowsSockaddrIn6FromAddress(addr, port);
            const start = std.time.milliTimestamp();

            // "Tracer" SYN: sent from a socket that is closed immediately
            // after connect() so the resulting ICMPv6 Time Exceeded has no
            // owning socket. Windows only delivers UNOWNED ICMPv6 errors to
            // raw capture sockets (verified on the lab VM: with the probing
            // socket kept open the stack consumes the error silently -- the
            // connect just keeps retransmitting -- and the raw socket never
            // sees it, which is why intermediate hops showed no IPs). The
            // SYN itself is emitted synchronously during connect(), so
            // closing right after is safe.
            var tracer_port: u16 = 0;
            {
                const tracer = ws2_32.socket(WSA_AF_INET6, WSA_SOCK_STREAM, WSA_IPPROTO_TCP);
                if (tracer != WSA_INVALID_SOCKET) {
                    if (setWindowsSocketNonBlocking(tracer) and
                        setWindowsSocketInt(tracer, WSA_IPPROTO_IPV6, WSA_IPV6_UNICAST_HOPS, hop))
                    {
                        _ = ws2_32.connect(tracer, @ptrCast(&target_addr), @sizeOf(WsaSockaddrIn6));
                        tracer_port = getWindowsLocalPort6(tracer);
                    }
                    closeWindowsSocket(tracer);
                }
            }

            // "Reacher" SYN: kept open so target arrival is detectable via
            // connect success (SYN-ACK) or WSAECONNREFUSED (RST). Its own
            // Time Exceeded errors are consumed by the stack, which is fine:
            // the tracer covers intermediate-hop discovery.
            const tcp_sock = ws2_32.socket(WSA_AF_INET6, WSA_SOCK_STREAM, WSA_IPPROTO_TCP);
            if (tcp_sock == WSA_INVALID_SOCKET) {
                std.log.err("MTR TCP6 Windows probe socket error: {d}", .{winsockError()});
                continue;
            }
            var should_close_tcp = true;
            defer if (should_close_tcp) closeWindowsSocket(tcp_sock);

            if (!setWindowsSocketNonBlocking(tcp_sock)) continue;
            _ = setWindowsSocketInt(tcp_sock, WSA_SOL_SOCKET, WSA_SO_REUSEADDR, 1);
            if (!setWindowsSocketInt(tcp_sock, WSA_IPPROTO_IPV6, WSA_IPV6_UNICAST_HOPS, hop)) continue;

            const conn_rc = ws2_32.connect(tcp_sock, @ptrCast(&target_addr), @sizeOf(WsaSockaddrIn6));
            if (conn_rc == WSA_SOCKET_ERROR) {
                const err = winsockError();
                if (err != @intFromEnum(ws2_32.WinsockError.WSAEWOULDBLOCK) and err != @intFromEnum(ws2_32.WinsockError.WSAEINPROGRESS)) {
                    closeWindowsSocket(tcp_sock);
                    should_close_tcp = false;
                    continue;
                }
            }

            const local_port = getWindowsLocalPort6(tcp_sock);
            if (local_port == 0) {
                closeWindowsSocket(tcp_sock);
                should_close_tcp = false;
                continue;
            }
            hop_sent.items[hop] += 1;

            var matched = false;
            var is_target = false;
            var elapsed: u64 = 0;
            var ip_str: ?[]u8 = null;

            while (true) {
                const elapsed_now = std.time.milliTimestamp() - start;
                if (elapsed_now >= timeout_ms) break;

                var read_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&read_fds);
                windowsFdSetAdd(&read_fds, capture_sock);
                var write_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&write_fds);
                windowsFdSetAdd(&write_fds, tcp_sock);
                var except_fds: ws2_32.fd_set = undefined;
                windowsFdSetZero(&except_fds);
                windowsFdSetAdd(&except_fds, tcp_sock);

                const remaining = timeout_ms - elapsed_now;
                if (remaining <= 0) break;
                var tv = ws2_32.timeval{ .sec = @intCast(@divFloor(remaining, 1000)), .usec = @intCast(@mod(remaining, 1000) * 1000) };
                const ready = ws2_32.select(0, &read_fds, &write_fds, &except_fds, &tv);
                if (ready == WSA_SOCKET_ERROR or ready == 0) continue;

                if (windowsFdSetIsSet(&read_fds, capture_sock)) {
                    var recv_buf: [1024]u8 = undefined;
                    var from_addr: WsaSockaddrIn6 = undefined;
                    var from_len: i32 = @sizeOf(WsaSockaddrIn6);
                    const recv_n = ws2_32.recvfrom(capture_sock, &recv_buf, recv_buf.len, 0, @ptrCast(&from_addr), &from_len);
                    if (recv_n > 0) {
                        if (parseWindowsIcmp6Capture(recv_buf[0..@intCast(recv_n)])) |pkt| {
                            any_icmp_captured = true;
                            const info = pkt.info;
                            // Match errors from either of this hop's two SYNs:
                            // the closed "tracer" (whose errors reach us) or the
                            // kept-open "reacher" (usually consumed by the stack).
                            if (info.orig_proto == 6 and info.orig_dst_port == port and
                                (info.orig_src_port == local_port or (tracer_port != 0 and info.orig_src_port == tracer_port)))
                            {
                                elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                                const src_bytes: [16]u8 = pkt.src orelse from_addr.addr;
                                const src_addr = std.net.Address.initIp6(src_bytes, 0, 0, 0);
                                const src_is_target = sameIpv6(src_bytes, target_ip6);
                                ip_str = formatSrcIp(pa, src_addr);
                                if (info.icmp_type == 1 and info.icmp_code == 4 and src_is_target) {
                                    is_target = true;
                                    matched = true;
                                    break;
                                } else if (info.icmp_type == 3) {
                                    matched = true;
                                    break;
                                }
                                if (ip_str) |ip| pa.free(ip);
                                ip_str = null;
                            }
                        }
                    }
                }

                if (windowsFdSetIsSet(&write_fds, tcp_sock) or windowsFdSetIsSet(&except_fds, tcp_sock)) {
                    const so_err = getWindowsSocketInt(tcp_sock, WSA_SOL_SOCKET, WSA_SO_ERROR);
                    if (so_err == 0 or so_err == @intFromEnum(ws2_32.WinsockError.WSAECONNREFUSED)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        is_target = true;
                        ip_str = formatSrcIp(pa, addr);
                        std.log.info("MTR TCP6 Windows reached target hop={d} ip={s} so_err={d}", .{ hop, ip_str orelse "", so_err });
                        matched = true;
                        break;
                    } else if (so_err == @intFromEnum(ws2_32.WinsockError.WSAEHOSTUNREACH) or so_err == @intFromEnum(ws2_32.WinsockError.WSAENETUNREACH)) {
                        elapsed = std.math.lossyCast(u64, std.time.milliTimestamp() - start);
                        matched = true;
                        break;
                    }
                }
            }

            closeWindowsSocket(tcp_sock);
            should_close_tcp = false;

            if (matched) {
                if (hop_ips.items[hop]) |h| pa.free(h);
                hop_ips.items[hop] = ip_str;
                hop_latencies.items[hop].append(pa, elapsed) catch {};
                if (is_target) {
                    hop_reached.items[hop] = true;
                    if (!reached_target) {
                        reached_target = true;
                        first_reached_hop = @intCast(hop);
                    }
                }
            } else {
                if (ip_str) |ip| pa.free(ip);
                std.log.debug("MTR TCP6 Windows no matching response test_id={s} hop={d} cycle={d}", .{ test_id, hop, cycle });
            }
            const hop_json = buildHopJson(pa, @intCast(hop), hop_ips.items[hop], hop_latencies.items[hop].items, hop_sent.items[hop], no_dns, hop_reached.items[hop]) catch continue;
            cycle_reports.append(pa, hop_json) catch { pa.free(hop_json); continue; };
        }

        sendCycleReport(test_id, cycle_reports.items, cycle == 0 and resumed);
        maybeResetHopHistory(test_id, cycle, &hop_latencies, &hop_sent);

        if (interval_sec > 0 and (counts == 0 or cycle + 1 < counts)) {
            std.Thread.sleep(@as(u64, @intCast(interval_sec)) * std.time.ns_per_s);
        }
    }

    if (!any_icmp_captured and max_ttl > first_ttl) {
        logIcmpCaptureHealthWarning(test_id, "TCP6", first_ttl, max_ttl);
    }
}

fn isTestActive(test_id: []const u8, generation: u64) bool {
    g_mutex.lock();
    defer g_mutex.unlock();
    for (g_running.items) |it| {
        if (std.mem.eql(u8, it.id, test_id) and it.generation == generation) {
            return it.active;
        }
    }
    return false;
}

pub fn appendActiveTestIds(out: *std.ArrayList(u8), first: *bool) !void {
    g_mutex.lock();
    defer g_mutex.unlock();
    for (g_running.items) |it| {
        if (!it.active) continue;
        if (!first.*) try out.append(g_allocator, ',');
        first.* = false;
        try out.writer(g_allocator).print("\"{s}\"", .{it.id});
    }
}

/// Used when a new run for a stopped test can't be spawned at all: with no
/// replacement thread there is nobody left to report completion (e.g. a
/// permanent test resumed right after a probe process restart), so the Core
/// must be told explicitly or the test hangs at "running" forever. Mirrors
/// iperf3_runner.completeNow.
pub fn completeNow(test_id: []const u8) void {
    if (config.get().uuid == null) return;
    var complete_buf: [256]u8 = undefined;
    var complete_len: usize = 0;
    const complete_parts = [_][]const u8{
        "{\"type\":\"test_complete\",\"test_id\":\"",
        test_id,
        "\"}",
    };
    for (complete_parts) |part| {
        if (complete_len + part.len > complete_buf.len) break;
        @memcpy(complete_buf[complete_len .. complete_len + part.len], part);
        complete_len += part.len;
    }
    if (complete_len > 0) wss_client.sendJson(complete_buf[0..complete_len]);
}

fn isCurrentGeneration(test_id: []const u8, generation: u64) bool {
    g_mutex.lock();
    defer g_mutex.unlock();
    return (g_generations.get(test_id) orelse 0) == generation;
}

fn sendComplete(test_id: []const u8, generation: u64) void {
    // A newer run (fresh registerActiveTest call bumping g_generations) has
    // since started for this same test_id -- e.g. the Core restarted the
    // test while this stale worker was still unwinding. Sending
    // test_complete now would make the Core mark the test "completed" while
    // the new generation is still actively streaming results under the same
    // ID, so stay silent and let the new generation report its own
    // completion when it actually finishes.
    if (!isCurrentGeneration(test_id, generation)) return;
    if (config.get().uuid == null) return;
    var complete_buf: [256]u8 = undefined;
    var complete_len: usize = 0;
    const complete_parts = [_][]const u8{
        "{\"type\":\"test_complete\",\"test_id\":\"",
        test_id,
        "\"}",
    };
    for (complete_parts) |part| {
        if (complete_len + part.len > complete_buf.len) break;
        @memcpy(complete_buf[complete_len .. complete_len + part.len], part);
        complete_len += part.len;
    }
    if (complete_len > 0) wss_client.sendJson(complete_buf[0..complete_len]);
}

fn buildHopJson(pa: std.mem.Allocator, hop: u8, hop_ip: ?[]u8, latencies: []const u64, sent_count: u32, no_dns: bool, reached: bool) ![]u8 {
    var root = std.json.ObjectMap.init(pa);
    defer {
        var it = root.iterator();
        while (it.next()) |entry| {
            pa.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .string => |s| pa.free(s),
                .array => |arr| {
                    for (arr.items) |item| {
                        switch (item) {
                            .integer => {},
                            else => {},
                        }
                    }
                    arr.deinit();
                },
                else => {},
            }
        }
        root.deinit();
    }

    const hop_key = pa.dupe(u8, "hop") catch return error.OutOfMemory;
    root.put(hop_key, .{ .integer = hop }) catch { pa.free(hop_key); return error.OutOfMemory; };

    var ip_str: []u8 = "";
    if (hop_ip) |h| {
        ip_str = pa.dupe(u8, h) catch return error.OutOfMemory;
    }
    const ip_key = pa.dupe(u8, "ip") catch { if (hop_ip != null) pa.free(ip_str); return error.OutOfMemory; };
    root.put(ip_key, .{ .string = ip_str }) catch { pa.free(ip_key); if (hop_ip != null) pa.free(ip_str); return error.OutOfMemory; };

    var host: ?[]u8 = null;
    if (!no_dns and hop_ip != null) {
        host = resolvePtr(hop_ip.?);
    }
    defer if (host) |h| pa.free(h);
    const host_str = if (host) |h| h else "";
    const host_copy = pa.dupe(u8, host_str) catch return error.OutOfMemory;
    const host_key = pa.dupe(u8, "host") catch { pa.free(host_copy); return error.OutOfMemory; };
    root.put(host_key, .{ .string = host_copy }) catch { pa.free(host_key); pa.free(host_copy); return error.OutOfMemory; };

    const sent_key = pa.dupe(u8, "sent") catch return error.OutOfMemory;
    root.put(sent_key, .{ .integer = @intCast(sent_count) }) catch { pa.free(sent_key); return error.OutOfMemory; };

    const reached_key = pa.dupe(u8, "reached") catch return error.OutOfMemory;
    root.put(reached_key, .{ .bool = reached }) catch { pa.free(reached_key); return error.OutOfMemory; };

    var latencies_arr = std.json.Array.init(pa);
    errdefer {
        for (latencies_arr.items) |item| {
            switch (item) {
                .integer => {},
                else => {},
            }
        }
        latencies_arr.deinit();
    }
    for (latencies) |l| {
        latencies_arr.append(.{ .integer = @intCast(l) }) catch return error.OutOfMemory;
    }
    const lat_key = pa.dupe(u8, "latencies") catch { latencies_arr.deinit(); return error.OutOfMemory; };
    root.put(lat_key, .{ .array = latencies_arr }) catch { pa.free(lat_key); latencies_arr.deinit(); return error.OutOfMemory; };

    var list = std.ArrayList(u8){};
    defer list.deinit(pa);
    const root_value: std.json.Value = .{ .object = root };
    list.print(pa, "{f}", .{std.json.fmt(root_value, .{})}) catch return error.OutOfMemory;
    return list.toOwnedSlice(pa);
}

fn sendCycleReport(test_id: []const u8, hop_reports: []const []const u8, first_cycle_resumed: bool) void {
    const pa = std.heap.page_allocator;
    // Concatenate the already-serialized hop JSON objects directly. The
    // previous parse-each-hop-into-a-Value-and-re-serialize approach leaked
    // the parse arena of every hop of every cycle (page_allocator pins whole
    // pages per arena), OOMing long-running unlimited tests within days.
    var list = std.ArrayList(u8){};
    defer list.deinit(pa);
    list.print(pa, "{{\"type\":\"test_result\",\"test_id\":{f},\"probe_uuid\":{f},\"data\":{{", .{
        std.json.fmt(test_id, .{}),
        std.json.fmt(config.get().uuid orelse "", .{}),
    }) catch return;
    if (first_cycle_resumed) {
        list.appendSlice(pa, "\"resumed\":true,") catch return;
    }
    list.appendSlice(pa, "\"hops\":[") catch return;
    for (hop_reports, 0..) |hr, i| {
        if (i > 0) list.append(pa, ',') catch return;
        list.appendSlice(pa, hr) catch return;
    }
    list.appendSlice(pa, "]}}") catch return;
    wss_client.sendJson(list.items);
}

pub fn stop(test_id: []const u8) void {
    stopInternal(test_id, false);
}

/// stop() + an atomic pre-bump of the generation counter under g_mutex, used
/// by the stop->restart path (wss_client.handleMessage spawning a new MTR run
/// of the same test_id). Mirrors iperf3_runner.stopForRestart: guarantees the
/// killed run's own sendComplete() always observes that a newer generation
/// exists -- even if the replacement thread hasn't called registerActiveTest
/// yet -- so its stale test_complete is suppressed instead of racing ahead of
/// the restart and marking the test "completed" while the new generation
/// keeps streaming results under the same ID.
pub fn stopForRestart(test_id: []const u8) void {
    stopInternal(test_id, true);
}

fn stopInternal(test_id: []const u8, restarting: bool) void {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (restarting) _ = nextGenerationLocked(test_id);
    var i: usize = 0;
    while (i < g_running.items.len) {
        const it = g_running.items[i];
        if (std.mem.eql(u8, it.id, test_id)) {
            _ = g_running.orderedRemove(i);
            g_allocator.free(it.id);
            continue;
        }
        i += 1;
    }
}

pub fn stopAll() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    for (g_running.items) |*it| {
        it.active = false;
    }
}

const testing = std.testing;

test "icmpChecksum: satisfies the Internet checksum (RFC 1071) validation invariant" {
    // A general identity of one's-complement checksums, true for any data:
    // computing the checksum with the checksum field zeroed, writing that
    // result back into the field, then recomputing over the whole buffer
    // must yield exactly 0 -- this is what makes the checksum
    // self-validating on the receiving end. No hand-derived expected value
    // needed; the algorithm checks itself.
    var data = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g' };
    const cs = icmpChecksum(&data);
    std.mem.writeInt(u16, data[2..4], cs, .big);
    try testing.expectEqual(@as(u16, 0), icmpChecksum(&data));
}

test "icmpChecksum: also validates for odd-length data (padded byte)" {
    var data = [_]u8{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'x' };
    const cs = icmpChecksum(&data);
    std.mem.writeInt(u16, data[2..4], cs, .big);
    try testing.expectEqual(@as(u16, 0), icmpChecksum(&data));
}

// mtr.zig's generation/active-run bookkeeping and packet builders allocate
// through the module-global g_allocator (set by init()), which -- like
// config.zig's globals -- is a process-lifetime singleton never designed to
// be freed/reset between calls. Use page_allocator (no leak tracking) for
// these instead of fighting that pre-existing shape, same rationale as
// config.zig's load/save tests. Each test calls init() itself and uses a
// unique test_id, so tests stay independent regardless of run order.

test "buildIcmpEchoPacket: header fields are correct and the embedded checksum validates" {
    init(std.heap.page_allocator);
    const pkt = try buildIcmpEchoPacket(0x1234, 0x0001, "ping-payload");
    defer std.heap.page_allocator.free(pkt);

    try testing.expectEqual(@as(usize, 8 + "ping-payload".len), pkt.len);
    try testing.expectEqual(@as(u8, 8), pkt[0]); // Echo Request
    try testing.expectEqual(@as(u8, 0), pkt[1]); // Code
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, pkt[4..6], .big));
    try testing.expectEqual(@as(u16, 0x0001), std.mem.readInt(u16, pkt[6..8], .big));
    try testing.expectEqualStrings("ping-payload", pkt[8..]);
    try testing.expectEqual(@as(u16, 0), icmpChecksum(pkt));
}

test "buildIcmp6EchoPacket: header fields are correct, checksum field deliberately left zero" {
    init(std.heap.page_allocator);
    const pkt = try buildIcmp6EchoPacket(0x5678, 0x0002, "v6");
    defer std.heap.page_allocator.free(pkt);

    try testing.expectEqual(@as(u8, 128), pkt[0]); // Echo Request (ICMPv6)
    try testing.expectEqual(@as(u8, 0), pkt[1]);
    // The kernel computes the ICMPv6 checksum (incl. pseudo-header) on send
    // for a raw socket -- this function must never fill it in itself.
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, pkt[2..4], .big));
    try testing.expectEqual(@as(u16, 0x5678), std.mem.readInt(u16, pkt[4..6], .big));
    try testing.expectEqual(@as(u16, 0x0002), std.mem.readInt(u16, pkt[6..8], .big));
    try testing.expectEqual(@as(usize, 8 + 2), pkt.len);
    try testing.expectEqualStrings("v6", pkt[8..]);
}

test "formatSrcIp: IPv4 renders as plain dotted-decimal" {
    const allocator = testing.allocator;
    const addr = std.net.Address.parseIp4("192.168.1.5", 0) catch unreachable;
    const s = formatSrcIp(allocator, addr).?;
    defer allocator.free(s);
    try testing.expectEqualStrings("192.168.1.5", s);
}

test "formatSrcIp: IPv6 renders as a bare address, not a debug struct dump" {
    // Regression test for the documented {any}-vs-{f} bug: formatting a
    // std.net.Address with {any} bypasses its custom format method and
    // dumps raw struct fields (e.g. ".any = .{ .family = 10, ... }")
    // instead of a real address -- this must never resurface.
    const allocator = testing.allocator;
    const addr = std.net.Address.parseIp6("2001:db8::1", 0) catch unreachable;
    const s = formatSrcIp(allocator, addr).?;
    defer allocator.free(s);
    try testing.expectEqualStrings("2001:db8::1", s);
    try testing.expect(std.mem.indexOf(u8, s, "family") == null);
    try testing.expect(std.mem.indexOf(u8, s, "[") == null);
}

test "registerActiveTest/stopForRestart: the old run's generation reads as stale immediately, before any replacement registers" {
    // Regression test for the exact race stopForRestart's own doc comment
    // describes: without the pre-bump, a same-test_id restart could let the
    // old worker thread's stale sendComplete() slip through and mark the
    // test "completed" while a new generation is still streaming results
    // under the same ID.
    init(std.heap.page_allocator);
    const id = "mtr-test-restart-race";

    const gen1 = registerActiveTest(id).?;
    try testing.expectEqual(@as(u64, 1), gen1);
    try testing.expect(isTestActive(id, gen1));
    try testing.expect(isCurrentGeneration(id, gen1));

    stopForRestart(id);

    // Stale immediately -- no replacement has registered yet.
    try testing.expect(!isCurrentGeneration(id, gen1));
    try testing.expect(!isTestActive(id, gen1));

    const gen2 = registerActiveTest(id).?;
    try testing.expect(gen2 > gen1);
    try testing.expect(isCurrentGeneration(id, gen2));
    try testing.expect(isTestActive(id, gen2));
}

test "stop (a genuine, non-restart stop) does not bump the generation -- the worker's own completion still sends normally" {
    init(std.heap.page_allocator);
    const id = "mtr-test-plain-stop";

    const gen1 = registerActiveTest(id).?;
    stop(id);

    // Removed from the running set, but NOT made stale: a real stop (not a
    // restart) means the worker really is finishing, and its own eventual
    // sendComplete() must still be allowed through.
    try testing.expect(!isTestActive(id, gen1));
    try testing.expect(isCurrentGeneration(id, gen1));
}

test "unregisterActiveTest: never clears a generation counter a newer run has already bumped" {
    init(std.heap.page_allocator);
    const id = "mtr-test-unregister-race";

    const gen1 = registerActiveTest(id).?;
    stopForRestart(id); // bumps to gen2, simulating a restart racing ahead

    // The old worker's own cleanup path calls unregisterActiveTest with its
    // now-stale generation -- this must be a no-op against g_generations.
    unregisterActiveTest(id, gen1);
    try testing.expect(isCurrentGeneration(id, gen1 + 1));

    // Once the (only) call carrying the actually-current generation runs,
    // the counter is cleared for real.
    unregisterActiveTest(id, gen1 + 1);
    try testing.expect(!isCurrentGeneration(id, gen1 + 1));
}

test "appendActiveTestIds: only active runs are included, comma-joined with no trailing separator" {
    init(std.heap.page_allocator);
    const id_a = "mtr-test-append-active";
    const id_b = "mtr-test-append-inactive";

    _ = registerActiveTest(id_a).?;
    const gen_b = registerActiveTest(id_b).?;

    // Directly deactivate id_b's own entry without touching any other
    // test's state (stopAll() would deactivate every entry ever registered
    // in this test binary, which would make this test's outcome depend on
    // run order).
    g_mutex.lock();
    for (g_running.items) |*it| {
        if (std.mem.eql(u8, it.id, id_b) and it.generation == gen_b) it.active = false;
    }
    g_mutex.unlock();

    // appendActiveTestIds grows `out` using g_allocator (page_allocator,
    // set by init() above), not necessarily the allocator the caller
    // otherwise uses -- deinit must match that.
    var out = std.ArrayList(u8){};
    defer out.deinit(std.heap.page_allocator);
    var first = true;
    try appendActiveTestIds(&out, &first);

    const s = out.items;
    try testing.expect(std.mem.indexOf(u8, s, "\"mtr-test-append-active\"") != null);
    try testing.expect(std.mem.indexOf(u8, s, id_b) == null);
    try testing.expect(!std.mem.endsWith(u8, s, ","));
}

fn makeHopHistoryFixture(allocator: std.mem.Allocator, hops: usize, samples_per_hop: u64) !struct {
    latencies: std.ArrayList(std.ArrayList(u64)),
    sent: std.ArrayList(u32),
} {
    var latencies = std.ArrayList(std.ArrayList(u64)){};
    var sent = std.ArrayList(u32){};
    for (0..hops) |_| {
        var lat = std.ArrayList(u64){};
        for (0..samples_per_hop) |i| try lat.append(allocator, i);
        try latencies.append(allocator, lat);
        try sent.append(allocator, @intCast(samples_per_hop));
    }
    return .{ .latencies = latencies, .sent = sent };
}

fn freeHopHistoryFixture(allocator: std.mem.Allocator, fixture: anytype) void {
    for (fixture.latencies.items) |*lat| lat.deinit(allocator);
    var latencies = fixture.latencies;
    latencies.deinit(allocator);
    var sent = fixture.sent;
    sent.deinit(allocator);
}

test "maybeResetHopHistory: no-op below the trim threshold, including cycle 0" {
    const allocator = testing.allocator;
    var fx = try makeHopHistoryFixture(allocator, 3, MTR_LATENCY_TRIM_CYCLES - 1);
    defer freeHopHistoryFixture(allocator, fx);

    // cycle 0 in particular must never trim -- nothing has accumulated yet,
    // and @rem(0, N) == 0 would otherwise wrongly match the threshold check.
    maybeResetHopHistory("test", 0, &fx.latencies, &fx.sent);
    for (fx.latencies.items) |lat| try testing.expectEqual(MTR_LATENCY_TRIM_CYCLES - 1, @as(i64, @intCast(lat.items.len)));

    maybeResetHopHistory("test", MTR_LATENCY_TRIM_CYCLES - 1, &fx.latencies, &fx.sent);
    for (fx.latencies.items) |lat| try testing.expectEqual(MTR_LATENCY_TRIM_CYCLES - 1, @as(i64, @intCast(lat.items.len)));
    for (fx.sent.items) |s| try testing.expectEqual(@as(u32, @intCast(MTR_LATENCY_TRIM_CYCLES - 1)), s);
}

test "maybeResetHopHistory: clears every hop's latencies and sent count exactly at the threshold" {
    const allocator = testing.allocator;
    var fx = try makeHopHistoryFixture(allocator, 4, @intCast(MTR_LATENCY_TRIM_CYCLES));
    defer freeHopHistoryFixture(allocator, fx);

    maybeResetHopHistory("test", MTR_LATENCY_TRIM_CYCLES, &fx.latencies, &fx.sent);

    for (fx.latencies.items) |lat| try testing.expectEqual(@as(usize, 0), lat.items.len);
    for (fx.sent.items) |s| try testing.expectEqual(@as(u32, 0), s);

    // A hop's per-cycle *capacity* is retained (clearRetainingCapacity, not
    // a fresh alloc/free each reset) -- appending right after a reset must
    // not require a fresh allocation to succeed.
    try fx.latencies.items[0].append(allocator, 42);
    try testing.expectEqual(@as(usize, 1), fx.latencies.items[0].items.len);
}

test "maybeResetHopHistory: also fires on a later exact multiple of the threshold" {
    const allocator = testing.allocator;
    var fx = try makeHopHistoryFixture(allocator, 2, @intCast(MTR_LATENCY_TRIM_CYCLES * 2));
    defer freeHopHistoryFixture(allocator, fx);

    maybeResetHopHistory("test", MTR_LATENCY_TRIM_CYCLES * 2, &fx.latencies, &fx.sent);
    for (fx.latencies.items) |lat| try testing.expectEqual(@as(usize, 0), lat.items.len);
    for (fx.sent.items) |s| try testing.expectEqual(@as(u32, 0), s);
}
