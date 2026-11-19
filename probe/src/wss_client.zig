const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const ip_discovery = @import("ip_discovery.zig");
const dns = @import("dns.zig");
const iperf3_runner = @import("iperf3_runner.zig");
const mtr = @import("mtr.zig");
const platform = @import("platform.zig");
const license_error = @import("license_error.zig");
const version = @import("version.zig");
const updater = @import("updater.zig");
// Vendored std TLS client with fingerprint pinning (Windows path only).
const TlsClient = @import("tls_client.zig");

const c = if (builtin.os.tag == .linux) @import("c.zig").c else undefined;

var g_allocator: std.mem.Allocator = undefined;
var g_tcp_stream: ?std.net.Stream = null;
const SslPtr = if (builtin.os.tag == .linux) *c.SSL else *anyopaque;
var g_ssl: ?SslPtr = null;
var g_send_mutex: std.Thread.Mutex = .{};
var g_license_error = std.atomic.Value(bool).init(false);
const MAX_WS_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

// Bounded retry on SSL_ERROR_WANT_READ/WANT_WRITE, mirroring the Core's own
// WebSocket frame send/read rationale:
// these codes mean "call this exact same operation again", not "the peer is
// gone". The probe's sockets are blocking, so this only ever fires from
// OpenSSL needing an internal read/write partway through a logical
// read/write (e.g. a TLS 1.3 post-handshake session ticket/KeyUpdate
// interleaving with application data) -- not a real would-block condition a
// caller should propagate as fatal.
const MAX_SSL_TRANSIENT_RETRIES = 5;

fn isSslTransientError(err_code: c_int) bool {
    if (builtin.os.tag == .linux) {
        return err_code == c.SSL_ERROR_WANT_READ or err_code == c.SSL_ERROR_WANT_WRITE;
    }
    return false;
}

// Custom Io.Reader for Windows that reads directly into the buffer,
// avoiding the bug where std.net.Stream.Reader.stream() uses the writer
// parameter which is passed as undefined by std.Io.Reader.fill().
const WindowsStreamReader = struct {
    interface_state: std.Io.Reader,
    net_stream: std.net.Stream,
    error_state: ?std.net.Stream.ReadError = null,

    pub fn init(net_stream: std.net.Stream, buffer: []u8) WindowsStreamReader {
        return .{
            .interface_state = .{
                .vtable = &.{
                    .stream = stream_fn,
                    .readVec = readVec_fn,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .net_stream = net_stream,
            .error_state = null,
        };
    }

    pub fn interface(r: *WindowsStreamReader) *std.Io.Reader {
        return &r.interface_state;
    }

    pub fn getStream(r: *const WindowsStreamReader) std.net.Stream {
        return r.net_stream;
    }

    fn stream_fn(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        _ = io_w;
        _ = limit;
        const r: *WindowsStreamReader = @alignCast(@fieldParentPtr("interface_state", io_r));
        const buf = io_r.buffer[io_r.end..];
        if (buf.len == 0) return 0;

        const win = std.os.windows;
        var flags: u32 = 0;
        var overlapped: win.OVERLAPPED = std.mem.zeroes(win.OVERLAPPED);
        var n: u32 = undefined;
        var wsabuf = win.ws2_32.WSABUF{ .buf = buf.ptr, .len = @intCast(buf.len) };

        if (win.ws2_32.WSARecv(
            r.net_stream.handle,
            @ptrCast(&wsabuf),
            1,
            &n,
            &flags,
            &overlapped,
            null,
        ) == win.ws2_32.SOCKET_ERROR) {
            switch (win.ws2_32.WSAGetLastError()) {
                .WSA_IO_PENDING => {
                    var result_flags: u32 = undefined;
                    if (win.ws2_32.WSAGetOverlappedResult(
                        r.net_stream.handle,
                        &overlapped,
                        &n,
                        win.TRUE,
                        &result_flags,
                    ) == win.FALSE) {
                        r.error_state = error.InputOutput;
                        return error.ReadFailed;
                    }
                },
                else => {
                    r.error_state = error.InputOutput;
                    return error.ReadFailed;
                },
            }
        }

        io_r.end += n;
        return n;
    }

    fn readVec_fn(io_r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        const r: *WindowsStreamReader = @alignCast(@fieldParentPtr("interface_state", io_r));
        var iovecs: [8]std.os.windows.ws2_32.WSABUF = undefined;
        var total: usize = 0;
        var i: usize = 0;
        var read_internal = false;
        for (data) |buf| {
            if (buf.len == 0) continue;
            if (i >= iovecs.len) break;
            iovecs[i] = .{ .buf = buf.ptr, .len = @intCast(buf.len) };
            total += buf.len;
            i += 1;
        }
        if (i == 0) {
            // No external buffers; read into internal buffer.
            const buf = io_r.buffer[io_r.end..];
            if (buf.len == 0) return 0;
            iovecs[0] = .{ .buf = buf.ptr, .len = @intCast(buf.len) };
            i = 1;
            total = buf.len;
            read_internal = true;
        }

        const win = std.os.windows;
        var flags: u32 = 0;
        var overlapped: win.OVERLAPPED = std.mem.zeroes(win.OVERLAPPED);
        var n: u32 = undefined;

        if (win.ws2_32.WSARecv(
            r.net_stream.handle,
            @ptrCast(iovecs[0..i].ptr),
            @intCast(i),
            &n,
            &flags,
            &overlapped,
            null,
        ) == win.ws2_32.SOCKET_ERROR) {
            switch (win.ws2_32.WSAGetLastError()) {
                .WSA_IO_PENDING => {
                    var result_flags: u32 = undefined;
                    if (win.ws2_32.WSAGetOverlappedResult(
                        r.net_stream.handle,
                        &overlapped,
                        &n,
                        win.TRUE,
                        &result_flags,
                    ) == win.FALSE) {
                        r.error_state = error.InputOutput;
                        return error.ReadFailed;
                    }
                },
                else => {
                    r.error_state = error.InputOutput;
                    return error.ReadFailed;
                },
            }
        }

        if (n == 0) return error.EndOfStream;
        if (n > total) {
            io_r.end += n - total;
            return total;
        }
        if (read_internal) {
            io_r.end += n;
            return 0;
        }
        return n;
    }
};

// Set a receive timeout on the underlying socket. On Linux this is also the
// mechanism that keeps the read loop from holding the SSL mutex while idle:
// the loop polls for readability first, and only calls SSL_read when data is
// known to be available, so outbound messages (like server_ready) are not
// blocked waiting for inbound traffic.
pub fn setSocketRecvTimeout(stream: std.net.Stream, timeout_ms: u32) bool {
    if (builtin.os.tag == .windows) {
        const win = std.os.windows;
        var val: u32 = timeout_ms;
        const rc = win.ws2_32.setsockopt(
            stream.handle,
            0xFFFF, // SOL_SOCKET
            0x1006, // SO_RCVTIMEO
            @ptrCast(&val),
            @sizeOf(u32),
        );
        if (rc != 0) {
            std.log.warn("Failed to set SO_RCVTIMEO: {d}", .{win.ws2_32.WSAGetLastError()});
            return false;
        }
        return true;
    }
    if (builtin.os.tag == .linux) {
        const sec: isize = @intCast(timeout_ms / 1000);
        const usec: isize = @intCast((timeout_ms % 1000) * 1000);
        const tv = std.posix.timeval{ .sec = sec, .usec = usec };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            &std.mem.toBytes(tv),
        ) catch |err| {
            std.log.warn("Failed to set SO_RCVTIMEO: {any}", .{err});
            return false;
        };
        return true;
    }
    return true;
}

pub fn setSocketSendTimeout(stream: std.net.Stream, timeout_ms: u32) bool {
    if (builtin.os.tag == .windows) {
        const win = std.os.windows;
        var val: u32 = timeout_ms;
        const rc = win.ws2_32.setsockopt(
            stream.handle,
            0xFFFF, // SOL_SOCKET
            0x1005, // SO_SNDTIMEO
            @ptrCast(&val),
            @sizeOf(u32),
        );
        if (rc != 0) {
            std.log.warn("Failed to set SO_SNDTIMEO: {d}", .{win.ws2_32.WSAGetLastError()});
            return false;
        }
        return true;
    }
    if (builtin.os.tag == .linux) {
        const sec: isize = @intCast(timeout_ms / 1000);
        const usec: isize = @intCast((timeout_ms % 1000) * 1000);
        const tv = std.posix.timeval{ .sec = sec, .usec = usec };
        std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.SNDTIMEO,
            &std.mem.toBytes(tv),
        ) catch |err| {
            std.log.warn("Failed to set SO_SNDTIMEO: {any}", .{err});
            return false;
        };
        return true;
    }
    return true;
}

// Windows TLS state (vendored std TLS client, see tls_client.zig)
const WindowsTlsState = struct {
    buffers: struct {
        stream_read: [TlsClient.min_buffer_len]u8,
        stream_write: [TlsClient.min_buffer_len]u8,
        tls_read: [TlsClient.min_buffer_len]u8,
        tls_write: [TlsClient.min_buffer_len]u8,
    },
    stream_reader: WindowsStreamReader,
    stream_writer: std.net.Stream.Writer,
    tls_client: TlsClient,
};
var g_windows_tls_state: ?*WindowsTlsState = null;

var g_connected: bool = false;
var g_connected_mutex: std.Thread.Mutex = .{};
// Bumped every time a new connection is established. connectionWatchdog and
// pingSender each capture the generation active when they were spawned and
// exit if it no longer matches the live one, so a stale thread from a
// connection that already died (and was replaced by a fresh reconnect while
// this thread was sleeping) doesn't keep running against the new
// connection's state -- without this, fast reconnects (network flapping)
// could accumulate extra watchdog/ping threads that never exit until a
// long-enough true outage lets all of them observe isConnected()==false at
// once.
var g_connection_generation = std.atomic.Value(u64).init(0);
var g_last_message_time: i64 = 0;
var g_session_id: ?[]u8 = null;
// Mutex that serializes closing of the underlying TCP socket. The watchdog
// needs to be able to force a reconnect without taking g_send_mutex (which on
// Linux is held during SSL_read and would deadlock).
var g_socket_mutex: std.Thread.Mutex = .{};

// Maximum silence from the Core before the probe forces a reconnect.
// The Core pings every 30 s and times out probes after 120 s; 90 s gives
// us a safe margin while catching half-open/zombie connections quickly.
const HEARTBEAT_TIMEOUT_SEC: i64 = 90;
// Interval at which the probe sends its own keep-alive pings. This keeps
// NAT/firewall state fresh and exercises the write path.
const PROBE_PING_INTERVAL_SEC: u64 = 30;

pub fn isConnected() bool {
    g_connected_mutex.lock();
    const val = g_connected;
    g_connected_mutex.unlock();
    return val;
}

fn updateLastMessageTime() void {
    g_connected_mutex.lock();
    g_last_message_time = std.time.timestamp();
    g_connected_mutex.unlock();
}

fn secondsSinceLastMessage() i64 {
    g_connected_mutex.lock();
    const last = g_last_message_time;
    g_connected_mutex.unlock();
    return std.time.timestamp() - last;
}

// Cached public IPs to avoid blocking reconnects on slow IP discovery services
var g_cached_ipv4: ?[]u8 = null;
var g_cached_ipv6: ?[]u8 = null;
var g_cached_timestamp: i64 = 0;
const CACHE_TTL_SEC = 3600; // 1 hour

pub const Transport = struct {
    ssl: ?SslPtr,
    windows_tls: ?*WindowsTlsState,
    // Raw (non-TLS) mode carries the socket here so the handshake works
    // before the globals are published at hello time -- keeping hello-first
    // true on ws:// too (sendJson drops while the globals are null).
    raw: ?std.net.Stream,
};

const WsFrame = struct {
    opcode: u8,
    payload: []u8,
};

fn streamRead(stream: std.net.Stream, buf: []u8) !usize {
    if (builtin.os.tag == .windows) {
        const ws2_32 = std.os.windows.ws2_32;
        const max_len = @min(buf.len, std.math.maxInt(c_int));
        const result = ws2_32.recv(stream.handle, buf.ptr, @intCast(max_len), 0);
        if (result == ws2_32.SOCKET_ERROR) {
            const err = ws2_32.WSAGetLastError();
            return switch (err) {
                .WSAECONNRESET => error.ConnectionResetByPeer,
                .WSAECONNABORTED => error.ConnectionAborted,
                .WSAEWOULDBLOCK => error.WouldBlock,
                else => error.Unexpected,
            };
        }
        return @intCast(result);
    } else {
        return stream.read(buf);
    }
}

fn transportRead(t: Transport, buf: []u8) !usize {
    if (builtin.os.tag == .linux) {
        if (t.ssl) |ssl| {
            // OpenSSL SSL objects are not thread-safe. The main read loop and
            // background test threads share the same SSL connection, so all
            // SSL I/O must be serialized through the same mutex.
            g_send_mutex.lock();
            defer g_send_mutex.unlock();
            var retries: u32 = 0;
            while (true) {
                const r = c.SSL_read(ssl, buf.ptr, @intCast(buf.len));
                if (r <= 0) {
                    const err = c.SSL_get_error(ssl, r);
                    if (err == c.SSL_ERROR_ZERO_RETURN) return 0;
                    // WANT_READ/WANT_WRITE mean "call this exact same
                    // operation again", not "the peer is gone" -- retry a
                    // bounded number of times instead of surfacing it as a
                    // fatal error every caller here treats as connection loss.
                    if (isSslTransientError(err) and retries < MAX_SSL_TRANSIENT_RETRIES) {
                        retries += 1;
                        std.log.warn("SSL_read transient err={d}, retry {d}/{d}", .{ err, retries, MAX_SSL_TRANSIENT_RETRIES });
                        std.Thread.sleep(20 * std.time.ns_per_ms);
                        continue;
                    }
                    return error.TlsReadError;
                }
                return @intCast(r);
            }
        }
    }
    if (builtin.os.tag == .windows) {
        const tls_state = t.windows_tls orelse g_windows_tls_state orelse return error.NoTransport;
        const reader = &tls_state.tls_client.reader;
        // First, serve any data already in the TLS reader buffer.
        const buffered = reader.buffered();
        if (buffered.len > 0) {
            const n = @min(buf.len, buffered.len);
            @memcpy(buf[0..n], buffered[0..n]);
            reader.toss(n);
            return n;
        }
        // No buffered data; try to read the next TLS record.
        reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return 0,
            error.ReadFailed => return error.TlsReadError,
        };
        // After fillMore, copy whatever is now buffered (may be empty if the
        // record was non-application-data, e.g. a post-handshake message).
        const after = reader.buffered();
        const n = @min(buf.len, after.len);
        if (n > 0) {
            @memcpy(buf[0..n], after[0..n]);
            reader.toss(n);
        }
        return n;
    }
    if (t.raw) |s| return streamRead(s, buf);
    if (g_tcp_stream) |s| return streamRead(s, buf);
    return error.NoTransport;
}

fn transportReadAtLeast(t: Transport, buf: []u8, len: usize) !usize {
    var index: usize = 0;
    while (index < len) {
        const amt = try transportRead(t, buf[index..]);
        if (amt == 0) return error.EndOfStream;
        index += amt;
    }
    return index;
}

fn transportWriteAll(t: Transport, buf: []const u8) !void {
    if (builtin.os.tag == .linux) {
        if (t.ssl) |ssl| {
            // Callers already serialize all SSL I/O on this connection under
            // g_send_mutex (see sendWsTextLocked and transportRead above),
            // so no additional locking is needed here.
            var total: usize = 0;
            var retries: u32 = 0;
            while (total < buf.len) {
                const n = c.SSL_write(ssl, buf.ptr + total, @intCast(buf.len - total));
                if (n <= 0) {
                    const err = c.SSL_get_error(ssl, n);
                    // WANT_READ/WANT_WRITE mean "call this exact same
                    // operation again", not "the peer is gone" -- retry a
                    // bounded number of times instead of tearing the
                    // connection down on a transient OpenSSL condition.
                    if (isSslTransientError(err) and retries < MAX_SSL_TRANSIENT_RETRIES) {
                        retries += 1;
                        std.log.warn("SSL_write transient err={d}, retry {d}/{d}", .{ err, retries, MAX_SSL_TRANSIENT_RETRIES });
                        std.Thread.sleep(20 * std.time.ns_per_ms);
                        continue;
                    }
                    return error.TlsWriteError;
                }
                retries = 0;
                total += @intCast(n);
            }
            return;
        }
    }
    if (builtin.os.tag == .windows) {
        const tls_state = t.windows_tls orelse g_windows_tls_state orelse return error.NoTransport;
        const tls_client = &tls_state.tls_client;
        try tls_client.writer.writeAll(buf);
        try tls_client.writer.flush();
        try tls_client.output.flush();
        return;
    }
    if (t.raw) |s| {
        _ = try s.writeAll(buf);
        return;
    }
    if (g_tcp_stream) |s| {
        _ = try s.writeAll(buf);
    } else {
        return error.NoTransport;
    }
}

pub fn init(allocator: std.mem.Allocator) void {
    g_allocator = allocator;
    // Generate a per-process session ID so the Core can distinguish a reconnect
    // from the same process (brief network blip) from a new process after a
    // crash/reboot. The ID must never change for the lifetime of the process.
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const hex_len = bytes.len * 2;
    g_session_id = g_allocator.alloc(u8, hex_len) catch null;
    if (g_session_id) |sid| {
        const hex = std.fmt.bytesToHex(bytes, .lower);
        @memcpy(sid, &hex);
    }
}

fn parseWsUrl(url: []const u8) !struct { host: []const u8, port: u16, path: []const u8, tls: bool } {
    var normalized = url;
    const is_wss = std.mem.startsWith(u8, url, "wss://");
    const is_ws = std.mem.startsWith(u8, url, "ws://");
    if (!is_wss and !is_ws) {
        normalized = try std.fmt.allocPrint(g_allocator, "wss://{s}/ws", .{url});
    } else if (std.mem.indexOf(u8, url, "/") == null) {
        normalized = try std.fmt.allocPrint(g_allocator, "{s}/ws", .{url});
    }
    defer if (normalized.ptr != url.ptr) g_allocator.free(normalized);
    const ws_prefix = if (std.mem.startsWith(u8, normalized, "ws://")) "ws://" else "wss://";
    const rest = normalized[ws_prefix.len..];
    const slash = std.mem.indexOf(u8, rest, "/") orelse rest.len;
    const host_port = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";
    var host = host_port;
    var port: u16 = if (std.mem.eql(u8, ws_prefix, "ws://")) 80 else 443;
    if (std.mem.indexOf(u8, host_port, ":")) |colon| {
        host = host_port[0..colon];
        port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch port;
    }
    const host_copy = try g_allocator.dupe(u8, host);
    const path_copy = try g_allocator.dupe(u8, path);
    return .{ .host = host_copy, .port = port, .path = path_copy, .tls = std.mem.eql(u8, ws_prefix, "wss://") };
}

pub fn setLicenseError() void {
    g_license_error.store(true, .seq_cst);
}

pub fn hasLicenseError() bool {
    return g_license_error.load(.acquire);
}

// Watchdog that forces a reconnect if no traffic has been received from the
// Core for too long. This is required on Windows because the TLS reader uses
// overlapped WSARecv, which ignores SO_RCVTIMEO, so a half-open connection
// can block the read loop forever. It also provides a uniform safety net on
// Linux in case poll/SO_RCVTIMEO ever fails to detect a dead socket.
fn connectionWatchdog(generation: u64) void {
    while (platform.isRunning()) {
        std.Thread.sleep(10 * std.time.ns_per_s);
        if (g_connection_generation.load(.seq_cst) != generation) return; // superseded by a newer connection
        if (!isConnected()) break;
        if (secondsSinceLastMessage() > HEARTBEAT_TIMEOUT_SEC) {
            std.log.err("No message from core in {d}s, forcing reconnect", .{secondsSinceLastMessage()});
            g_connected_mutex.lock();
            g_connected = false;
            g_connected_mutex.unlock();
            closeSocketForReconnect();
            std.log.info("Watchdog closed socket, main loop should exit and reconnect", .{});
            break;
        }
    }
}

// Send a lightweight JSON ping to the Core every PROBE_PING_INTERVAL_SEC.
// The Core replies with a pong, which refreshes last_message_time, and the
// outbound traffic prevents NAT/firewall state from expiring.
fn pingSender(generation: u64) void {
    const ping_msg = "{\"type\":\"ping\"}";
    while (platform.isRunning() and isConnected()) {
        std.Thread.sleep(PROBE_PING_INTERVAL_SEC * std.time.ns_per_s);
        if (g_connection_generation.load(.seq_cst) != generation) return; // superseded by a newer connection
        if (!isConnected()) break;
        g_send_mutex.lock();
        const t: Transport = if (builtin.os.tag == .linux and g_ssl != null)
            .{ .ssl = g_ssl, .windows_tls = null, .raw = null }
        else
            .{ .ssl = null, .windows_tls = g_windows_tls_state, .raw = g_tcp_stream };
        if (t.ssl != null or g_tcp_stream != null or g_windows_tls_state != null) {
            sendWsTextLocked(t, ping_msg) catch |err| {
                std.log.err("pingSender failed: {any}", .{err});
            };
        }
        g_send_mutex.unlock();
    }
}

fn sleepMsInterruptible(total_ms: u64) void {
    var elapsed: u64 = 0;
    const chunk_ms: u64 = 1000;
    while (elapsed < total_ms) {
        if (!platform.isRunning()) return;
        const remaining = total_ms - elapsed;
        const step: u64 = if (remaining < chunk_ms) remaining else chunk_ms;
        std.Thread.sleep(step * std.time.ns_per_ms);
        elapsed += step;
    }
}

pub fn run() !void {
    const cfg = config.get();
    const url = try parseWsUrl(cfg.core_address);
    defer {
        g_allocator.free(url.host);
        g_allocator.free(url.path);
    }

    var delay_ms: u64 = 1000;
    const max_delay_ms: u64 = 60000;
    // A license rejection is recoverable, not fatal: the probe keeps retrying on
    // a long fixed interval (a few minutes) forever, because the rejection is
    // usually transient (e.g. the Core's license API/panel being temporarily
    // unreachable, as when the panel host is down). It reconnects automatically
    // once the Core accepts it again, instead of staying down until a manual
    // restart.
    const license_retry_ms: u64 = 5 * 60 * 1000;
    while (platform.isRunning()) {
        const connect_start_ms = std.time.milliTimestamp();
        connectAndRun(url.host, url.port, url.path, url.tls) catch |err| {
            if (g_license_error.swap(false, .seq_cst)) {
                std.log.err("License rejected by Core; will retry in {d} minutes.", .{license_retry_ms / 60000});
                sleepMsInterruptible(license_retry_ms);
                delay_ms = 1000;
                continue;
            }
            // connectAndRun's main loop only returns *without* an error when
            // the process is shutting down (platform.isRunning() went
            // false); every ordinary disconnect (server close, read/poll
            // error) returns via `err`, so the "reset backoff on successful
            // connection" line below this catch block never actually runs in
            // practice. Without this, one early transient failure would
            // permanently push every later reconnect toward the 60s cap for
            // the rest of the process's life. Treat a connection that stayed
            // up for a while before failing as healthy instead.
            const uptime_ms: u64 = @intCast(@max(0, std.time.milliTimestamp() - connect_start_ms));
            if (uptime_ms >= 30_000) {
                delay_ms = 1000;
            }
            std.log.err("Connection error: {any}. Retrying in {d}ms...", .{ err, delay_ms });
            if (delay_ms >= 10000) {
                std.log.info("Next reconnect attempt in {d}ms", .{delay_ms});
            }
            sleepMsInterruptible(delay_ms);
            // Exponential backoff with jitter (+/- 25%)
            const jitter = std.crypto.random.int(u64) % (delay_ms / 2);
            delay_ms = (delay_ms * 2) + jitter - (delay_ms / 4);
            if (delay_ms > max_delay_ms) delay_ms = max_delay_ms;
            continue;
        };
        // Reset backoff on successful connection
        delay_ms = 1000;
    }
}

fn connectAndRun(host: []const u8, port: u16, path: []const u8, use_tls: bool) !void {
    std.log.debug("connectAndRun start", .{});
    defer std.log.debug("connectAndRun exit", .{});
    const addr = std.net.Address.parseIp4(host, port) catch std.net.Address.parseIp6(host, port) catch blk: {
        std.log.debug("doing DNS lookup for {s}", .{host});
        const list = try std.net.getAddressList(g_allocator, host, port);
        defer list.deinit();
        if (list.addrs.len == 0) return error.UnknownHostName;
        break :blk list.addrs[0];
    };
    const tcp_stream = std.net.tcpConnectToAddress(addr) catch |err| {
        std.log.debug("tcpConnectToAddress error: {any}", .{err});
        return err;
    };
    std.log.debug("TCP connected", .{});
    // Set once the globals are published at hello time; the teardown uses it
    // to tell "handshake never completed" (fd still ours, must close) apart
    // from "published, then closed by the watchdog" (fd may be recycled).
    var transport_published = false;
    defer {
        g_send_mutex.lock();
        defer g_send_mutex.unlock();
        g_connected_mutex.lock();
        g_connected = false;
        g_connected_mutex.unlock();
        if (builtin.os.tag == .linux and g_ssl != null) {
            _ = c.SSL_shutdown(g_ssl.?);
            c.SSL_free(g_ssl.?);
            g_ssl = null;
        }
        if (builtin.os.tag == .windows and g_windows_tls_state != null) {
            // std.crypto.tls.Client does not have an explicit close method.
            // Closing the underlying TCP stream is sufficient.
            g_allocator.destroy(g_windows_tls_state.?);
            g_windows_tls_state = null;
        }
        // Coordinate with the watchdog so we do not double-close the socket.
        g_socket_mutex.lock();
        defer g_socket_mutex.unlock();
        if (g_tcp_stream != null and g_tcp_stream.?.handle == tcp_stream.handle) {
            g_tcp_stream = null;
            tcp_stream.close();
        } else if (g_tcp_stream == null) {
            if (!transport_published) {
                // Handshake/hello never completed: nothing else could have
                // closed this fd (the watchdog's close is a no-op while the
                // global is null), so closing it here can't hit a recycled
                // fd number. Previously this path leaked the socket on every
                // failed ws:// handshake.
                tcp_stream.close();
            }
            // else: published, then closed/nulled by the watchdog -- don't
            // touch a possibly-recycled fd number.
        } else {
            // A different connection owns g_tcp_stream; just close our local copy.
            tcp_stream.close();
        }
    }

    var transport: Transport = .{ .ssl = null, .windows_tls = null, .raw = if (use_tls) null else tcp_stream };
    var windows_state: ?*WindowsTlsState = null;

    if (use_tls and builtin.os.tag == .linux) {
        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.OpenSSLError;
        defer c.SSL_CTX_free(ctx);
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_3_VERSION);
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
        const ssl = c.SSL_new(ctx) orelse return error.OpenSSLError;
        errdefer {
            _ = c.SSL_shutdown(ssl);
            c.SSL_free(ssl);
        }
        _ = c.SSL_set_fd(ssl, @intCast(tcp_stream.handle));
        if (c.SSL_connect(ssl) <= 0) {
            std.log.err("SSL_connect failed", .{});
            return error.TlsHandshakeFailed;
        }
        std.log.info("TLS handshake completed", .{});

        // Certificate pinning
        const cert = c.SSL_get_peer_certificate(ssl) orelse {
            std.log.err("No peer certificate", .{});
            return error.NoPeerCert;
        };
        defer c.X509_free(cert);
        const der_len = c.i2d_X509(cert, null);
        if (der_len <= 0) return error.CertDerFailed;
        const der = try g_allocator.alloc(u8, @intCast(der_len));
        defer g_allocator.free(der);
        var p: [*c]u8 = der.ptr;
        _ = c.i2d_X509(cert, &p);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(der, &hash, .{});
        const expected = config.get().hash;
        var match = true;
        if (expected.len == 64) {
            const hex_chars = "0123456789abcdef";
            for (hash, 0..) |b, i| {
                if (expected[i * 2] != hex_chars[b >> 4] or expected[i * 2 + 1] != hex_chars[b & 0x0F]) {
                    match = false;
                    break;
                }
            }
        } else {
            match = false;
        }
        if (!match) {
            std.log.err("Certificate pinning failed. Expected {s}, got fingerprint mismatch.", .{expected});
            return error.CertPinningFailed;
        }
        std.log.info("Certificate pinning verified successfully", .{});
        transport.ssl = ssl;
    } else if (use_tls and builtin.os.tag == .windows) {
        // Zig-native TLS (vendored std client, see tls_client.zig).
        // We use a custom WindowsStreamReader to avoid a bug in
        // std.net.Stream.Reader.stream() which crashes when called with an
        // undefined writer (as std.Io.Reader.fill() does).
        //
        // Certificate pinning: same rule as the Linux path above -- the
        // Core's DER SHA-256 must equal the configured hash, and validity
        // dates are deliberately ignored (the Core's self-signed cert can't
        // be rotated without changing the PSK, so its expiry is meaningless).
        const expected = config.get().hash;
        var pin: [32]u8 = undefined;
        if (expected.len != 64) {
            std.log.err("Certificate pinning failed: configured hash is not a 64-char hex SHA-256", .{});
            return error.CertPinningFailed;
        }
        _ = std.fmt.hexToBytes(&pin, expected) catch {
            std.log.err("Certificate pinning failed: configured hash is not valid hex", .{});
            return error.CertPinningFailed;
        };

        const state = try g_allocator.create(WindowsTlsState);
        errdefer g_allocator.destroy(state);

        state.stream_reader = WindowsStreamReader.init(tcp_stream, &state.buffers.stream_read);
        state.stream_writer = tcp_stream.writer(&state.buffers.stream_write);

        std.log.debug("TLS init start", .{});
        state.tls_client = TlsClient.init(state.stream_reader.interface(), &state.stream_writer.interface, .{
            .host = .{ .explicit = "linknesis-ws" },
            .ca = .{ .pinned_sha256 = pin },
            .read_buffer = &state.buffers.tls_read,
            .write_buffer = &state.buffers.tls_write,
        }) catch |err| {
            if (err == error.TlsCertificatePinMismatch) {
                std.log.err("Certificate pinning failed. Expected {s}, got fingerprint mismatch.", .{expected});
                return error.CertPinningFailed;
            }
            return err;
        };
        std.log.info("TLS handshake completed, certificate pinning verified (Windows native)", .{});
        windows_state = state;
        transport.windows_tls = state;
    } else if (use_tls and builtin.os.tag != .linux and builtin.os.tag != .windows) {
        std.log.warn("TLS requested but not supported on this OS, falling back to raw WS", .{});
    }

    // Raw (non-TLS) mode: the socket travels inside Transport.raw, so the
    // handshake works without publishing the globals early -- hello-first
    // holds on ws:// too (concurrent sendJson drops while globals are null).
    // Timeouts go on now: the raw handshake has no TLS layer and would
    // otherwise wait forever for a silent server.
    if (!use_tls) {
        _ = setSocketRecvTimeout(tcp_stream, 15000);
        _ = setSocketSendTimeout(tcp_stream, 15000);
    }

    // WebSocket handshake
    const ws_key = try generateWsKey();
    defer g_allocator.free(ws_key);
    const req = try std.fmt.allocPrint(g_allocator, "GET {s} HTTP/1.1\r\n" ++
        "Host: {s}:{d}\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: {s}\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n", .{ path, host, port, ws_key });
    defer g_allocator.free(req);
    std.log.debug("WS sending handshake request", .{});
    try transportWriteAll(transport, req);

    // Read response incrementally until we get the full HTTP headers
    std.log.debug("WS reading handshake response", .{});
    var resp_buf: [4096]u8 = undefined;
    var resp_len: usize = 0;
    while (resp_len < resp_buf.len) {
        const n = transportRead(transport, resp_buf[resp_len..]) catch |err| {
            std.log.err("transport read error: {any}", .{err});
            break;
        };
        resp_len += n;
        if (std.mem.indexOf(u8, resp_buf[0..resp_len], "\r\n\r\n")) |_| break;
    }
    std.log.debug("WS handshake response received len={d}", .{resp_len});
    const resp = resp_buf[0..resp_len];
    if (!std.mem.containsAtLeast(u8, resp, 1, "101 Switching Protocols")) {
        std.log.err("WS handshake failed: {s}", .{resp});
        return error.WsHandshakeFailed;
    }

    std.log.info("WebSocket connected to {s}:{d}", .{ host, port });
    // Do NOT clear the license error here: the WS/TLS handshake succeeding
    // only means the transport is up, not that the Core accepted our license
    // -- that verdict (license_rejected vs. proceeding to send `config`)
    // only comes after `hello` is sent, later in this function. Clearing
    // here unconditionally re-armed the "notify once per episode" flag on
    // every single reconnect attempt, so a persistently-rejected license
    // spammed the log/tray balloon on every retry instead of once. It is
    // cleared instead when the `config` message arrives (see handleMessage),
    // since the Core only ever sends that after accepting the license.
    g_connected_mutex.lock();
    g_connected = true;
    g_last_message_time = std.time.timestamp();
    g_connected_mutex.unlock();
    const generation = g_connection_generation.fetchAdd(1, .seq_cst) + 1;

    // NOTE: the transport globals (g_tcp_stream/g_ssl/g_windows_tls_state)
    // are deliberately NOT published yet -- see the publish+hello critical
    // section below.

    // Prevent a dead or half-open connection from hanging the read loop forever.
    // On Linux we use a short timeout because the main loop polls for readability
    // before reading; the timeout is only a safety net for unexpected stalls.
    const recv_timeout_ms = if (builtin.os.tag == .windows) 120000 else 1000;
    _ = setSocketRecvTimeout(tcp_stream, recv_timeout_ms);
    // Bound outbound writes (including SSL_write and the underlying TCP send) so
    // the ping sender cannot hold g_send_mutex indefinitely when the network dies.
    _ = setSocketSendTimeout(tcp_stream, 15000);

    // NOTE: the watchdog and ping threads are spawned only AFTER hello is
    // sent (see below). Spawning them before the transport is published let
    // the watchdog fire in that window: its closeSocketForReconnect() was a
    // no-op (globals still null) yet it still marked the connection dead and
    // exited permanently, leaving the connection with no watchdog and no
    // pings for its whole lifetime.

    // Send hello (use cached IPs to avoid blocking on slow IP discovery services)
    var ipv4: ?[]u8 = null;
    var ipv6: ?[]u8 = null;
    const now = std.time.timestamp();
    if (g_cached_timestamp > 0 and now - g_cached_timestamp < CACHE_TTL_SEC) {
        ipv4 = if (g_cached_ipv4) |v| try g_allocator.dupe(u8, v) else null;
        ipv6 = if (g_cached_ipv6) |v| try g_allocator.dupe(u8, v) else null;
    } else {
        const discovered = ip_discovery.discoverPublicIp(g_allocator) catch |err| blk: {
            std.log.warn("Public IP discovery failed: {any}", .{err});
            break :blk .{ .ipv4 = null, .ipv6 = null };
        };
        ipv4 = discovered.ipv4;
        ipv6 = discovered.ipv6;

        if (g_cached_ipv4) |old| g_allocator.free(old);
        if (g_cached_ipv6) |old| g_allocator.free(old);
        g_cached_ipv4 = if (ipv4) |v| try g_allocator.dupe(u8, v) else null;
        g_cached_ipv6 = if (ipv6) |v| try g_allocator.dupe(u8, v) else null;
        g_cached_timestamp = if (ipv4 != null or ipv6 != null) now else 0;
    }
    defer {
        if (ipv4) |v| g_allocator.free(v);
        if (ipv6) |v| g_allocator.free(v);
    }
    const private_ipv4 = ip_discovery.discoverPrivateIpv4(g_allocator) catch null;
    defer if (private_ipv4) |v| g_allocator.free(v);
    const private_ipv6 = ip_discovery.discoverPrivateIpv6(g_allocator) catch null;
    defer if (private_ipv6) |v| g_allocator.free(v);
    const hostname = std.process.getEnvVarOwned(g_allocator, "HOSTNAME") catch null;
    defer if (hostname) |h| g_allocator.free(h);
    const status_str = if (@import("main.zig").g_iperf3_available) "ok" else "degraded";
    var active_tests = std.ArrayList(u8){};
    defer active_tests.deinit(g_allocator);
    try active_tests.append(g_allocator, '[');
    var first_active = true;
    try iperf3_runner.appendActiveTestIds(&active_tests, &first_active);
    try mtr.appendActiveTestIds(&active_tests, &first_active);
    try active_tests.append(g_allocator, ']');
    var hello_root = std.json.ObjectMap.init(g_allocator);
    defer freeJsonValue(g_allocator, .{ .object = hello_root });
    try hello_root.put(try g_allocator.dupe(u8, "type"), .{ .string = try g_allocator.dupe(u8, "hello") });
    try hello_root.put(try g_allocator.dupe(u8, "uuid"), .{ .string = try g_allocator.dupe(u8, config.get().uuid.?) });
    try hello_root.put(try g_allocator.dupe(u8, "hash"), .{ .string = try g_allocator.dupe(u8, config.get().hash) });
    try hello_root.put(try g_allocator.dupe(u8, "public_ipv4"), .{ .string = try g_allocator.dupe(u8, ipv4 orelse "") });
    try hello_root.put(try g_allocator.dupe(u8, "public_ipv6"), .{ .string = try g_allocator.dupe(u8, ipv6 orelse "") });
    try hello_root.put(try g_allocator.dupe(u8, "private_ipv4"), .{ .string = try g_allocator.dupe(u8, private_ipv4 orelse "") });
    try hello_root.put(try g_allocator.dupe(u8, "private_ipv6"), .{ .string = try g_allocator.dupe(u8, private_ipv6 orelse "") });
    try hello_root.put(try g_allocator.dupe(u8, "hostname"), .{ .string = try g_allocator.dupe(u8, hostname orelse "") });
    try hello_root.put(try g_allocator.dupe(u8, "os"), .{ .string = try g_allocator.dupe(u8, @tagName(@import("builtin").target.os.tag)) });
    try hello_root.put(try g_allocator.dupe(u8, "version"), .{ .string = try g_allocator.dupe(u8, version.VERSION) });
    try hello_root.put(try g_allocator.dupe(u8, "arch"), .{ .string = try g_allocator.dupe(u8, @tagName(@import("builtin").target.cpu.arch)) });
    try hello_root.put(try g_allocator.dupe(u8, "session_id"), .{ .string = try g_allocator.dupe(u8, g_session_id orelse "") });
    try hello_root.put(try g_allocator.dupe(u8, "status"), .{ .string = try g_allocator.dupe(u8, status_str) });
    // Only present when --label was passed at install time. The Core only
    // ever acts on this the one time the uuid is genuinely new -- it never
    // overwrites a label an admin has since set/changed via the GUI.
    if (config.getLabel()) |lbl| {
        try hello_root.put(try g_allocator.dupe(u8, "label"), .{ .string = try g_allocator.dupe(u8, lbl) });
    }
    // active_tests.items is already a JSON array string; parse it back to a
    // Value. parseFromSlice's Parsed(Value) is arena-backed, so its .value
    // must be deep-cloned into g_allocator-owned memory (not merged in
    // directly) before the arena is released, or the later top-level
    // freeJsonValue(g_allocator, .{.object = hello_root}) would call
    // g_allocator.free() on pointers the arena (not g_allocator) actually
    // owns -- an invalid free that would crash/corrupt the heap on every
    // reconnect while a test is active.
    const active_parsed = try std.json.parseFromSlice(std.json.Value, g_allocator, active_tests.items, .{});
    defer active_parsed.deinit();
    const active_tests_cloned = try cloneJsonValue(g_allocator, active_parsed.value);
    try hello_root.put(try g_allocator.dupe(u8, "active_tests"), active_tests_cloned);
    var hello_list = std.ArrayList(u8){};
    defer hello_list.deinit(g_allocator);
    const hello_value: std.json.Value = .{ .object = hello_root };
    try hello_list.print(g_allocator, "{f}", .{std.json.fmt(hello_value, .{})});
    const hello = try hello_list.toOwnedSlice(g_allocator);
    defer g_allocator.free(hello);
    std.log.debug("About to send hello", .{});
    // Publish the transport and send hello inside one g_send_mutex critical
    // section. Other threads' sendJson() re-resolves the globals under the
    // same mutex (dropping the message while they're null), so hello is now
    // guaranteed to be the first message on the wire. Previously the
    // transport was published before hello was even built, letting a queued
    // result overtake it -- the race that blocked the Core from gating
    // result messages on a completed hello.
    g_send_mutex.lock();
    g_tcp_stream = tcp_stream;
    if (builtin.os.tag == .linux and transport.ssl != null) {
        g_ssl = transport.ssl;
    }
    if (builtin.os.tag == .windows and windows_state != null) {
        g_windows_tls_state = windows_state.?;
    }
    transport_published = true;
    sendWsTextLocked(transport, hello) catch |err| {
        g_send_mutex.unlock();
        return err;
    };
    g_send_mutex.unlock();
    std.log.debug("Hello sent, entering main loop", .{});

    // Spawn the watchdog and keep-alive sender threads for this connection,
    // only now that hello is on the wire and the transport is published.
    // The watchdog is required on Windows because the TLS reader uses
    // overlapped WSARecv, which ignores SO_RCVTIMEO; a half-open socket can
    // block the read loop forever without it.
    const watchdog_thread = std.Thread.spawn(.{}, connectionWatchdog, .{generation}) catch |err| blk: {
        std.log.warn("Failed to spawn connection watchdog: {any}", .{err});
        break :blk null;
    };
    const ping_thread = std.Thread.spawn(.{}, pingSender, .{generation}) catch |err| blk: {
        std.log.warn("Failed to spawn ping sender: {any}", .{err});
        break :blk null;
    };
    if (watchdog_thread) |wt| wt.detach();
    if (ping_thread) |pt| pt.detach();

    // Main loop
    var running = true;
    while (platform.isRunning()) {
        // On Linux the SSL mutex is also held by SSL_read. Poll for readability
        // before reading so the mutex is not held while waiting for inbound
        // traffic. This allows background threads (e.g. the iperf3 server_ready
        // watcher) to send outbound messages promptly instead of being blocked
        // until the next Core ping.
        if (builtin.os.tag == .linux) {
            var has_pending = false;
            if (g_ssl) |ssl| {
                has_pending = c.SSL_pending(ssl) > 0;
            }
            if (!has_pending) {
                const stream = g_tcp_stream orelse return error.NoTransport;
                var pollfd: [1]std.posix.pollfd = .{.{
                    .fd = stream.handle,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                const ready = std.posix.poll(&pollfd, 1000) catch |err| {
                    std.log.info("poll error: {any}", .{err});
                    return err;
                };
                if (ready == 0) continue;
            }
        }

        const frame = readWsFrame(transport) catch |err| {
            std.log.info("readWsFrame error: {any}", .{err});
            return err;
        };
        if (frame) |f| {
            updateLastMessageTime();
            defer g_allocator.free(f.payload);
            if (f.opcode == 0x01) {
                std.log.debug("WS text frame: {s}", .{f.payload});
                handleMessage(f.payload, &running, transport) catch |err| {
                    std.log.err("Failed to handle WS message: {any}", .{err});
                };
            } else if (f.opcode == 0x02) {
                updater.handleBinaryChunk(f.payload) catch |err| {
                    std.log.err("Failed to handle update binary chunk: {any}", .{err});
                };
            } else {
                std.log.warn("Unexpected WS opcode {d}, ignoring", .{f.opcode});
            }
            if (!running) return;
        } else {
            std.log.info("WS connection closed by server", .{});
            return error.WsConnectionClosed;
        }
    }
}

fn generateWsKey() ![]u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);
    const len = std.base64.standard.Encoder.calcSize(bytes.len);
    const out = try g_allocator.alloc(u8, len);
    _ = std.base64.standard.Encoder.encode(out, &bytes);
    return out;
}

fn readWsFrame(t: Transport) !?WsFrame {
    // Loops (rather than recursing) on ping/pong control frames so a
    // malicious/buggy Core that floods pings/pongs cannot grow the call
    // stack without bound (ReleaseSafe does not guarantee TCO).
    while (true) {
        std.log.debug("readWsFrame: reading header", .{});
        var header: [2]u8 = undefined;
        _ = try transportReadAtLeast(t, &header, 2);
        std.log.debug("readWsFrame: header opcode={d} len={d}", .{ header[0] & 0x0F, header[1] & 0x7F });

        const fin = (header[0] & 0x80) != 0;
        const rsv = header[0] & 0x70;
        const opcode = header[0] & 0x0F;
        const masked = (header[1] & 0x80) != 0;
        var payload_len: u64 = @intCast(header[1] & 0x7F);

        if (rsv != 0) return error.WsReservedBits;

        if (payload_len == 126) {
            var len_buf: [2]u8 = undefined;
            _ = try transportReadAtLeast(t, &len_buf, 2);
            payload_len = std.mem.readInt(u16, &len_buf, .big);
        } else if (payload_len == 127) {
            var len_buf: [8]u8 = undefined;
            _ = try transportReadAtLeast(t, &len_buf, 8);
            payload_len = std.mem.readInt(u64, &len_buf, .big);
        }

        if (payload_len > MAX_WS_FRAME_SIZE) {
            std.log.err("WS frame too large: {d} bytes", .{payload_len});
            return error.WsFrameTooLarge;
        }

        var mask_key: [4]u8 = undefined;
        if (masked) {
            _ = try transportReadAtLeast(t, &mask_key, 4);
        }

        std.log.debug("readWsFrame: payload_len={d} masked={}", .{ payload_len, masked });
        const payload = try g_allocator.alloc(u8, payload_len);
        var payload_opt: ?[]u8 = payload;
        errdefer if (payload_opt) |p| g_allocator.free(p);

        var total: usize = 0;
        while (total < payload_len) {
            const n = try transportRead(t, payload[total..]);
            if (n == 0) return error.EndOfStream;
            total += n;
        }
        std.log.debug("readWsFrame: payload read complete", .{});

        if (masked) {
            for (payload, 0..) |b, i| {
                payload[i] = b ^ mask_key[i % 4];
            }
        }

        // Control frames must have FIN=1 and payload <= 125 bytes per RFC 6455.
        const is_control = opcode == 0x08 or opcode == 0x09 or opcode == 0x0A;
        if (is_control and (!fin or payload_len > 125)) {
            g_allocator.free(payload_opt.?);
            payload_opt = null;
            return error.WsControlFrameInvalid;
        }

        // Any traffic from the Core means the connection is alive.
        updateLastMessageTime();

        if (opcode == 0x08) {
            g_allocator.free(payload_opt.?);
            payload_opt = null;
            return null; // close
        }
        if (opcode == 0x09) {
            std.log.debug("readWsFrame: ping received, sending pong", .{});
            // ping: send pong, then keep waiting for the next frame
            var pong_header: [2]u8 = .{ 0x8A, 0x00 };
            if (payload_len <= 125) {
                pong_header[1] = @intCast(payload_len);
            } else {
                // Simplification: ignore large pings
            }
            g_send_mutex.lock();
            defer g_send_mutex.unlock();
            try transportWriteAll(t, &pong_header);
            if (payload_len > 0) {
                try transportWriteAll(t, payload[0..payload_len]);
            }
            g_allocator.free(payload_opt.?);
            payload_opt = null;
            std.log.debug("readWsFrame: pong sent, looping", .{});
            continue;
        }
        if (opcode == 0x0A) {
            g_allocator.free(payload_opt.?);
            payload_opt = null;
            continue;
        }
        if (!fin) {
            g_allocator.free(payload_opt.?);
            payload_opt = null;
            return error.WsFragmented;
        }

        std.log.debug("readWsFrame: returning payload frame opcode={d} len={d}", .{ opcode, payload_len });
        return WsFrame{ .opcode = opcode, .payload = payload };
    }
}

fn sendWsTextLocked(t: Transport, text: []const u8) !void {
    const len = text.len;
    var header_buf: [14]u8 = undefined;
    header_buf[0] = 0x81; // FIN + text opcode
    var mask_key: [4]u8 = undefined;
    std.crypto.random.bytes(&mask_key);
    var header_len: usize = 0;
    if (len < 126) {
        header_buf[1] = @as(u8, @intCast(len)) | 0x80;
        @memcpy(header_buf[2..6], &mask_key);
        header_len = 6;
    } else if (len < 65536) {
        header_buf[1] = 126 | 0x80;
        std.mem.writeInt(u16, header_buf[2..4], @intCast(len), .big);
        @memcpy(header_buf[4..8], &mask_key);
        header_len = 8;
    } else {
        header_buf[1] = 127 | 0x80;
        std.mem.writeInt(u64, header_buf[2..10], len, .big);
        @memcpy(header_buf[10..14], &mask_key);
        header_len = 14;
    }
    try transportWriteAll(t, header_buf[0..header_len]);
    var chunk: [1024]u8 = undefined;
    var i: usize = 0;
    while (i < len) {
        const end = @min(i + chunk.len, len);
        const n = end - i;
        for (0..n) |j| {
            chunk[j] = text[i + j] ^ mask_key[(i + j) % 4];
        }
        try transportWriteAll(t, chunk[0..n]);
        i = end;
    }
}

pub fn sendWsText(t: Transport, text: []const u8) !void {
    g_send_mutex.lock();
    defer g_send_mutex.unlock();
    try sendWsTextLocked(t, text);
}

pub fn sendJson(msg: []const u8) void {
    // This is called from other threads (iperf3, mtr) without transport context.
    // We fall back to g_ssl/g_tcp_stream/g_windows_tls_state if available.
    g_send_mutex.lock();
    defer g_send_mutex.unlock();
    const t: Transport = if (builtin.os.tag == .linux and g_ssl != null)
        .{ .ssl = g_ssl, .windows_tls = null, .raw = null }
    else
        .{ .ssl = null, .windows_tls = g_windows_tls_state, .raw = g_tcp_stream };
    if (t.ssl == null and g_tcp_stream == null and g_windows_tls_state == null) {
        std.log.err("sendJson: no active transport, dropping message", .{});
        return;
    }
    sendWsTextLocked(t, msg) catch |err| {
        std.log.err("sendJson failed: {any}", .{err});
    };
}

pub fn closeTcpStream() void {
    g_send_mutex.lock();
    defer g_send_mutex.unlock();
    closeSocketForReconnect();
    if (builtin.os.tag == .linux and g_ssl != null) {
        _ = c.SSL_shutdown(g_ssl.?);
        c.SSL_free(g_ssl.?);
        g_ssl = null;
    }
    if (builtin.os.tag == .windows and g_windows_tls_state != null) {
        g_allocator.destroy(g_windows_tls_state.?);
        g_windows_tls_state = null;
    }
}

// Close only the underlying TCP socket, without taking g_send_mutex. This is
// used by the watchdog to break a stuck read loop (e.g. a half-open connection
// on Windows where overlapped WSARecv ignores SO_RCVTIMEO). The read loop will
// then return an error and the connectAndRun defer block will clean up SSL/TLS
// state and the local stream copy.
fn closeSocketForReconnect() void {
    g_socket_mutex.lock();
    defer g_socket_mutex.unlock();
    if (g_tcp_stream) |s| {
        // shutdown() first: any thread blocked in SSL_read/SSL_write (or a
        // raw recv/send) wakes immediately with an error while the fd number
        // is still ours, so nothing can be reassigned that fd and then get
        // closed from under it. close() alone leaves that fd-reuse race.
        if (builtin.os.tag == .windows) {
            _ = std.os.windows.ws2_32.shutdown(s.handle, std.os.windows.ws2_32.SD_BOTH);
        } else {
            std.posix.shutdown(s.handle, .both) catch {};
        }
        s.close();
        g_tcp_stream = null;
    }
}

pub fn closeInheritedFds() void {
    // Called in the child process after fork, before exec.
    // The child shares the parent's SSL object in memory, so we must NOT call
    // SSL_shutdown or SSL_free here (that would corrupt the parent's TLS
    // session). Just close the duplicated file descriptors so they are not
    // leaked into the exec'd process.
    if (builtin.os.tag == .linux) {
        // Drop the child's reference without touching the shared SSL object.
        g_ssl = null;
        if (g_tcp_stream) |s| {
            std.posix.close(s.handle);
            g_tcp_stream = null;
        }
    }
}

fn targetIsFqdn(target: []const u8) bool {
    // A bare IPv6 literal ("2001:db8::1", no brackets/port) contains multiple
    // colons that belong to the address itself. The old code stripped
    // everything after the LAST colon as if it were a port, mangling the
    // literal so parseIp6 failed and the target was misclassified as an FQDN
    // -- which made the probe run a pointless DNS resolution and the GUI show
    // a "DNS Resolution" box for plain IP targets. Try the whole string first.
    if (std.net.Address.parseIp6(target, 0)) |_| return false else |_| {}

    // Strip optional port: [host]:port for bracketed IPv6, or host:port when
    // there is exactly one colon (hostnames/IPv4 can contain at most one).
    var host = target;
    if (host.len > 0 and host[0] == '[') {
        if (std.mem.indexOf(u8, host, "]")) |end| {
            host = host[1..end];
        }
    } else if (std.mem.count(u8, host, ":") == 1) {
        host = host[0..std.mem.indexOf(u8, host, ":").?];
    }
    if (std.net.Address.parseIp4(host, 0)) |_| return false else |_| {}
    if (std.net.Address.parseIp6(host, 0)) |_| return false else |_| {}
    return true;
}

pub fn jsonString(v: ?std.json.Value) ?[]const u8 {
    if (v) |val| {
        if (val == .string) return val.string;
    }
    return null;
}

fn jsonInteger(v: ?std.json.Value) ?i64 {
    if (v) |val| {
        if (val == .integer) return val.integer;
    }
    return null;
}

fn jsonBool(v: ?std.json.Value, default: bool) bool {
    if (v) |val| {
        if (val == .bool) return val.bool;
    }
    return default;
}

fn parsePort(v: ?std.json.Value) ?u16 {
    const i = jsonInteger(v) orelse return null;
    if (i < 0 or i > 65535) return null;
    return @intCast(i);
}

fn parseTtl(v: ?std.json.Value) ?u8 {
    const i = jsonInteger(v) orelse return null;
    if (i < 1 or i > 255) return null;
    return @intCast(i);
}

/// Deep-copies a parsed std.json.Value tree into `allocator`-owned memory.
/// std.json.parseFromSlice's Parsed(Value) allocates strings/arrays/objects
/// through an internal ArenaAllocator wrapping the allocator you pass it, not
/// through that allocator directly -- so its .value must never be merged
/// into a longer-lived structure that will later be freed field-by-field via
/// freeJsonValue(allocator, ...): that calls allocator.free() on pointers the
/// allocator never actually handed out (they were arena-suballocated),
/// which is an invalid free. Clone first, then let the caller deinit() the
/// Parsed(Value) (and its arena) right away.
fn cloneJsonValue(allocator: std.mem.Allocator, v: std.json.Value) !std.json.Value {
    return switch (v) {
        .null, .bool, .integer, .float => v,
        .number_string => |s| .{ .number_string = try allocator.dupe(u8, s) },
        .string => |s| .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| blk: {
            var new_arr = std.json.Array.init(allocator);
            errdefer {
                for (new_arr.items) |item| freeJsonValue(allocator, item);
                new_arr.deinit();
            }
            for (arr.items) |item| try new_arr.append(try cloneJsonValue(allocator, item));
            break :blk .{ .array = new_arr };
        },
        .object => |obj| blk: {
            var new_obj = std.json.ObjectMap.init(allocator);
            errdefer {
                var it = new_obj.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    freeJsonValue(allocator, entry.value_ptr.*);
                }
                new_obj.deinit();
            }
            var it = obj.iterator();
            while (it.next()) |entry| {
                try new_obj.put(try allocator.dupe(u8, entry.key_ptr.*), try cloneJsonValue(allocator, entry.value_ptr.*));
            }
            break :blk .{ .object = new_obj };
        },
    };
}

fn freeJsonValue(allocator: std.mem.Allocator, v: std.json.Value) void {
    switch (v) {
        .string => |s| allocator.free(s),
        .number_string => |s| allocator.free(s),
        .array => |arr| {
            for (arr.items) |item| freeJsonValue(allocator, item);
            arr.deinit();
        },
        .object => |obj| {
            var obj_mut = obj;
            var it = obj_mut.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj_mut.deinit();
        },
        else => {},
    }
}

fn buildDnsResultMsg(allocator: std.mem.Allocator, test_id: []const u8, probe_uuid: []const u8, ip: []const u8, duration_ms: u64) ![]u8 {
    var root = std.json.ObjectMap.init(allocator);
    errdefer {
        var it = root.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .string => |s| allocator.free(s),
                else => {},
            }
        }
        root.deinit();
    }
    try root.put(try allocator.dupe(u8, "type"), .{ .string = try allocator.dupe(u8, "dns_result") });
    try root.put(try allocator.dupe(u8, "test_id"), .{ .string = try allocator.dupe(u8, test_id) });
    try root.put(try allocator.dupe(u8, "probe_uuid"), .{ .string = try allocator.dupe(u8, probe_uuid) });
    try root.put(try allocator.dupe(u8, "ip"), .{ .string = try allocator.dupe(u8, ip) });
    try root.put(try allocator.dupe(u8, "duration_ms"), .{ .integer = @intCast(duration_ms) });
    var list = std.ArrayList(u8){};
    defer list.deinit(allocator);
    const root_value: std.json.Value = .{ .object = root };
    try list.print(allocator, "{f}", .{std.json.fmt(root_value, .{})});
    return list.toOwnedSlice(allocator);
}

const DnsResolveCtx = struct {
    test_id: []u8,
    target: []u8,
};

fn scheduleDnsResolution(test_id: []const u8, target: []const u8) void {
    const pa = std.heap.page_allocator;
    const ctx = pa.create(DnsResolveCtx) catch return;
    ctx.* = .{
        .test_id = pa.dupe(u8, test_id) catch {
            pa.destroy(ctx);
            return;
        },
        .target = pa.dupe(u8, target) catch {
            pa.free(ctx.test_id);
            pa.destroy(ctx);
            return;
        },
    };
    const thread = std.Thread.spawn(.{}, dnsResolveThread, .{ctx}) catch {
        pa.free(ctx.test_id);
        pa.free(ctx.target);
        pa.destroy(ctx);
        return;
    };
    thread.detach();
}

fn dnsResolveThread(ctx: *DnsResolveCtx) void {
    const pa = std.heap.page_allocator;
    defer {
        pa.free(ctx.test_id);
        pa.free(ctx.target);
        pa.destroy(ctx);
    }
    var dr_ip: []u8 = undefined;
    var dr_duration: u64 = 0;
    if (dns.resolveAndTime(pa, ctx.target)) |dr| {
        dr_ip = dr.ip;
        dr_duration = dr.duration_ms;
    } else |_| {
        dr_ip = pa.dupe(u8, ctx.target) catch return;
    }
    defer pa.free(dr_ip);
    const uuid = config.get().uuid orelse return;
    const dns_msg = buildDnsResultMsg(pa, ctx.test_id, uuid, dr_ip, dr_duration) catch return;
    defer pa.free(dns_msg);
    // sendJson re-resolves the live transport under g_send_mutex: no stale
    // transport capture, and the read loop never waits on the resolver.
    sendJson(dns_msg);
}

fn handleMessage(msg: []const u8, _: *bool, t: Transport) !void {
    std.log.info("Received WS message: {s}", .{msg});
    const parsed = try std.json.parseFromSlice(std.json.Value, g_allocator, msg, .{ .duplicate_field_behavior = .use_first });
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const msg_type = jsonString(parsed.value.object.get("type")) orelse return;

    if (std.mem.eql(u8, msg_type, "test")) {
        const test_id = jsonString(parsed.value.object.get("test_id")) orelse return;
        const test_type = jsonString(parsed.value.object.get("test_type")) orelse return;
        const target = jsonString(parsed.value.object.get("target")) orelse return;
        const params = parsed.value.object.get("params");

        // Only measure DNS resolution for FQDN targets, not IP addresses (with optional port).
        // Run it on a detached thread: a slow/unresponsive resolver would
        // otherwise block the WSS read loop (and with it stop_test commands
        // and ping/pong handling) for tens of seconds.
        if (targetIsFqdn(target)) {
            scheduleDnsResolution(test_id, target);
        }

        // Copy test_id and target with page_allocator so the spawned thread never touches GPA
        const pa = std.heap.page_allocator;
        const test_id_copy = try pa.dupe(u8, test_id);
        errdefer pa.free(test_id_copy);
        const target_copy = try pa.dupe(u8, target);
        errdefer pa.free(target_copy);

        var duration: i64 = 10;
        var counts: i64 = 30;
        var resumed: bool = false;
        var reverse: bool = false;
        var bidir: bool = false;
        var parallel: i64 = 1;
        var bandwidth: ?[]const u8 = null;
        var dscp: ?[]const u8 = null;
        var zerocopy: bool = false;
        var server_mode: bool = false;
        var server_port: u16 = 5201;
        var protocol: ?[]const u8 = null;
        var client_port: ?u16 = null;
        var interval: i64 = 1;
        var omit: i64 = 0;
        var report_to_test_id: ?[]const u8 = null;
        var skip_test_results: bool = false;
        var no_dns: bool = false;
        var first_ttl: ?u8 = null;
        var max_ttl: ?u8 = null;
        var ipv6: bool = false;
        ipv6 = jsonBool(parsed.value.object.get("ipv6"), false);
        if (params) |p| {
            if (p != .object) return;
            if (jsonInteger(p.object.get("duration"))) |d| duration = d;
            if (jsonInteger(p.object.get("counts"))) |cnt| counts = cnt;
            resumed = jsonBool(p.object.get("resumed"), false);
            reverse = jsonBool(p.object.get("reverse"), false);
            bidir = jsonBool(p.object.get("bidir"), false);
            if (jsonInteger(p.object.get("parallel"))) |pl| parallel = pl;
            if (jsonString(p.object.get("bandwidth"))) |bw| bandwidth = bw;
            if (jsonString(p.object.get("dscp"))) |ds| dscp = ds;
            zerocopy = jsonBool(p.object.get("zerocopy"), false);
            server_mode = jsonBool(p.object.get("server_mode"), false);
            if (parsePort(p.object.get("server_port"))) |sp| server_port = sp;
            if (jsonString(p.object.get("protocol"))) |pr| protocol = pr;
            if (parsePort(p.object.get("port"))) |pt| client_port = pt;
            if (jsonInteger(p.object.get("interval"))) |iv| interval = iv;
            if (jsonInteger(p.object.get("omit"))) |om| omit = om;
            no_dns = jsonBool(p.object.get("no_dns"), false);
            if (parseTtl(p.object.get("first_ttl"))) |ft| first_ttl = ft;
            if (parseTtl(p.object.get("max_ttl"))) |mt| max_ttl = mt;
        }
        if (jsonString(parsed.value.object.get("report_to_test_id"))) |rt| {
            report_to_test_id = rt;
        }
        skip_test_results = jsonBool(parsed.value.object.get("skip_test_results"), false);

        // Clamp numeric parameters to operational limits to avoid abuse/crashes.
        if (duration < 0 or duration > 86400) duration = 10;
        if (counts < 0 or counts > 100000) counts = 30;
        if (parallel < 1 or parallel > 64) parallel = 1;
        if (interval < 1 or interval > 300) interval = 1;
        if (omit < 0 or omit > 300) omit = 0;

        const bw_copy = if (bandwidth) |b| try pa.dupe(u8, b) else null;
        errdefer if (bw_copy) |b| pa.free(b);
        const ds_copy = if (dscp) |d| try pa.dupe(u8, d) else null;
        errdefer if (ds_copy) |d| pa.free(d);
        const proto_copy = if (protocol) |pr| try pa.dupe(u8, pr) else null;
        errdefer if (proto_copy) |pr| pa.free(pr);
        const report_copy = if (report_to_test_id) |rt| try pa.dupe(u8, rt) else null;
        errdefer if (report_copy) |rt| pa.free(rt);

        std.log.info("handleMessage test params test_id={s} type={s} target={s} duration={d} reverse={} bidir={} parallel={d} bandwidth={?s} dscp={?s} zerocopy={} server_mode={} server_port={d} protocol={?s} client_port={?d} interval={d} omit={d} report_to={?s} skip={} no_dns={} first_ttl={?d} max_ttl={?d}", .{
            test_id, test_type, target, duration, reverse, bidir, parallel, bandwidth, dscp, zerocopy, server_mode, server_port, protocol, client_port, interval, omit, report_to_test_id, skip_test_results, no_dns, first_ttl, max_ttl,
        });

        if (std.mem.eql(u8, test_type, "throughput") or std.mem.eql(u8, test_type, "iperf3")) {
            iperf3_runner.stopForRestart(test_id); // stop any existing instance first
            // iperf3_runner.run takes ownership of all six copies and frees them.
            const thread = std.Thread.spawn(.{}, iperf3_runner.run, .{ test_id_copy, target_copy, duration, reverse, bidir, parallel, bw_copy, ds_copy, zerocopy, server_mode, server_port, proto_copy, client_port, interval, omit, report_copy, skip_test_results, ipv6 }) catch |err| {
                std.log.err("Failed to spawn iperf3 runner for {s}: {any}", .{ test_id, err });
                // stopForRestart's generation pre-bump suppresses the killed
                // run's own test_complete, so the Core must be told the test
                // ended explicitly or it hangs forever.
                iperf3_runner.completeNow(test_id_copy);
                pa.free(test_id_copy);
                pa.free(target_copy);
                if (bw_copy) |b| pa.free(b);
                if (ds_copy) |d| pa.free(d);
                if (proto_copy) |p| pa.free(p);
                if (report_copy) |r| pa.free(r);
                return;
            };
            thread.detach();
        } else if (std.mem.eql(u8, test_type, "mtr")) {
            mtr.stopForRestart(test_id); // stop any existing instance first
            // mtr.run takes ownership of test_id_copy/target_copy/proto_copy and
            // frees them; it does not take bandwidth/dscp/report, so free those
            // here (they are normally null for MTR, but free unconditionally to
            // avoid leaking if a caller ever sets them).
            const thread = std.Thread.spawn(.{}, mtr.run, .{ test_id_copy, target_copy, counts, reverse, bidir, proto_copy, client_port, no_dns, first_ttl, max_ttl, interval, resumed }) catch |err| {
                std.log.err("Failed to spawn MTR runner for {s}: {any}", .{ test_id, err });
                // Same guard as the iperf3 branch above: with no replacement
                // thread there is nobody left to report completion, so tell
                // the Core explicitly or the test hangs at "running" forever.
                mtr.completeNow(test_id_copy);
                pa.free(test_id_copy);
                pa.free(target_copy);
                if (proto_copy) |p| pa.free(p);
                if (bw_copy) |b| pa.free(b);
                if (ds_copy) |d| pa.free(d);
                if (report_copy) |r| pa.free(r);
                return;
            };
            thread.detach();
            if (bw_copy) |b| pa.free(b);
            if (ds_copy) |d| pa.free(d);
            if (report_copy) |r| pa.free(r);
        } else {
            // Unknown test type: no runner takes ownership, so free every copy
            // here instead of leaking them (errdefer only covers error returns).
            pa.free(test_id_copy);
            pa.free(target_copy);
            if (bw_copy) |b| pa.free(b);
            if (ds_copy) |d| pa.free(d);
            if (proto_copy) |p| pa.free(p);
            if (report_copy) |r| pa.free(r);
        }
    } else if (std.mem.eql(u8, msg_type, "license_rejected")) {
        const reason = jsonString(parsed.value.object.get("reason")) orelse "unknown";
        var max_probes: ?u32 = null;
        if (parsed.value.object.get("max_probes")) |mp| {
            switch (mp) {
                .integer => |i| {
                    if (i > 0 and i <= std.math.maxInt(u32)) max_probes = @intCast(i);
                },
                .float => |f| {
                    if (std.math.isFinite(f) and f > 0 and f <= @as(f64, std.math.maxInt(u32))) {
                        max_probes = @intFromFloat(f);
                    }
                },
                else => {},
            }
        }
        license_error.handle(reason, max_probes);
    } else if (std.mem.eql(u8, msg_type, "stop_test")) {
        const test_id = jsonString(parsed.value.object.get("test_id")) orelse return;
        iperf3_runner.stop(test_id);
        mtr.stop(test_id);
    } else if (std.mem.eql(u8, msg_type, "ping")) {
        const pong = "{\"type\":\"pong\"}";
        sendWsText(t, pong) catch {};
    } else if (std.mem.eql(u8, msg_type, "config")) {
        // The Core only ever sends `config` right after accepting `hello`
        // (a rejected license gets `license_rejected` instead and never
        // reaches this point), so receiving it is the actual "license
        // accepted" signal -- re-arm the once-per-episode notification here.
        license_error.clear();
        const core_version = jsonString(parsed.value.object.get("version")) orelse return;
        const auto_updates = jsonBool(parsed.value.object.get("auto_probe_updates_enabled"), false);
        // Falls back to 4480 (the pre-fix universal default) when talking to
        // an older Core that never sent this field, so this probe stays
        // compatible with a not-yet-updated Core.
        const api_port = parsePort(parsed.value.object.get("api_port")) orelse 4480;
        updater.onConfig(core_version, auto_updates, api_port);
        if (updater.shouldUpdate()) {
            updater.scheduleUpdateRequest(updater.isForceUpdate());
        }
    } else if (std.mem.eql(u8, msg_type, "reinstall")) {
        std.log.info("Reinstall requested by core", .{});
        updater.scheduleUpdateRequest(true);
    } else if (std.mem.eql(u8, msg_type, "update_start")) {
        updater.handleUpdateStart(parsed.value) catch |err| {
            std.log.err("Update start failed: {any}", .{err});
        };
    } else if (std.mem.eql(u8, msg_type, "update_chunk")) {
        const data_field = parsed.value.object.get("data") orelse {
            std.log.err("update_chunk missing data field", .{});
            return;
        };
        if (data_field != .string) {
            std.log.err("update_chunk data is not a string", .{});
            return;
        }
        const encoded = data_field.string;
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch |err| {
            std.log.err("update_chunk invalid base64 length: {any}", .{err});
            return;
        };
        const decoded = g_allocator.alloc(u8, decoded_len) catch |err| {
            std.log.err("update_chunk alloc failed: {any}", .{err});
            return;
        };
        defer g_allocator.free(decoded);
        std.base64.standard.Decoder.decode(decoded, encoded) catch |err| {
            std.log.err("update_chunk base64 decode failed: {any}", .{err});
            return;
        };
        updater.handleBinaryChunk(decoded) catch |err| {
            std.log.err("Failed to handle update chunk: {any}", .{err});
        };
    } else if (std.mem.eql(u8, msg_type, "update_done")) {
        updater.handleUpdateDone() catch |err| {
            std.log.err("Update application failed: {any}", .{err});
        };
    }
}

const testing = std.testing;

test "targetIsFqdn: a bare IPv6 literal is never misclassified as an FQDN" {
    // Regression test for the exact bug described in targetIsFqdn's own
    // comment: the old code stripped everything after the LAST colon as if
    // it were a port, which mangled a bare IPv6 literal (multiple colons
    // belong to the address itself) into something parseIp6 could no longer
    // parse -- misclassifying it as an FQDN and triggering a pointless DNS
    // resolution plus a "DNS Resolution" box in the GUI for a plain IP target.
    try testing.expect(!targetIsFqdn("2001:db8::1"));
    try testing.expect(!targetIsFqdn("::1"));
    try testing.expect(!targetIsFqdn("fe80::1234:5678:9abc"));
}

test "targetIsFqdn: bracketed IPv6 with a port strips the port, not the address" {
    try testing.expect(!targetIsFqdn("[2001:db8::1]:8080"));
    try testing.expect(!targetIsFqdn("[::1]:4443"));
}

test "targetIsFqdn: IPv4/IPv4:port are never FQDNs" {
    try testing.expect(!targetIsFqdn("8.8.8.8"));
    try testing.expect(!targetIsFqdn("192.168.1.1:9000"));
}

test "targetIsFqdn: a real hostname, with or without a port, is an FQDN" {
    try testing.expect(targetIsFqdn("example.com"));
    try testing.expect(targetIsFqdn("core.example.com:4443"));
}

test "jsonString: only a .string value round-trips, everything else is null" {
    try testing.expectEqualStrings("hello", jsonString(std.json.Value{ .string = "hello" }).?);
    try testing.expect(jsonString(std.json.Value{ .integer = 5 }) == null);
    try testing.expect(jsonString(std.json.Value{ .bool = true }) == null);
    try testing.expect(jsonString(null) == null);
}

test "jsonInteger: only a .integer value round-trips, everything else is null" {
    try testing.expectEqual(@as(i64, 42), jsonInteger(std.json.Value{ .integer = 42 }).?);
    try testing.expect(jsonInteger(std.json.Value{ .float = 42.0 }) == null);
    try testing.expect(jsonInteger(std.json.Value{ .string = "42" }) == null);
    try testing.expect(jsonInteger(null) == null);
}

test "jsonBool: a wrong-typed or missing value silently falls back to the caller's default" {
    // This is the exact "silently substitute a hardcoded default, never
    // reject" rule this probe applies to untrusted Core input.
    try testing.expect(jsonBool(std.json.Value{ .bool = true }, false));
    try testing.expect(!jsonBool(std.json.Value{ .bool = false }, true));
    try testing.expect(jsonBool(std.json.Value{ .integer = 1 }, true)); // wrong type -> default, not truthy-1
    try testing.expect(!jsonBool(std.json.Value{ .integer = 1 }, false));
    try testing.expect(jsonBool(null, true));
}

test "parsePort: accepts 0-65535, rejects negative and out-of-range" {
    try testing.expectEqual(@as(u16, 0), parsePort(std.json.Value{ .integer = 0 }).?);
    try testing.expectEqual(@as(u16, 65535), parsePort(std.json.Value{ .integer = 65535 }).?);
    try testing.expect(parsePort(std.json.Value{ .integer = -1 }) == null);
    try testing.expect(parsePort(std.json.Value{ .integer = 65536 }) == null);
    try testing.expect(parsePort(std.json.Value{ .string = "80" }) == null);
    try testing.expect(parsePort(null) == null);
}

test "parseTtl: accepts 1-255 only, rejects 0 and out-of-range" {
    try testing.expectEqual(@as(u8, 1), parseTtl(std.json.Value{ .integer = 1 }).?);
    try testing.expectEqual(@as(u8, 255), parseTtl(std.json.Value{ .integer = 255 }).?);
    try testing.expect(parseTtl(std.json.Value{ .integer = 0 }) == null);
    try testing.expect(parseTtl(std.json.Value{ .integer = 256 }) == null);
    try testing.expect(parseTtl(std.json.Value{ .integer = -5 }) == null);
}

test {
    _ = ip_discovery;
}
