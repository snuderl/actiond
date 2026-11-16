//! Bazel persistent-worker support: `persistentWorkerKey` parsing, flagfile
//! expansion, WorkRequest/WorkResponse framing and the warm worker pool.
//!
//! The process side (spawning a worker in a chroot, feeding it requests) lives in
//! `action_runner.zig` and `action_executor.zig`; everything here is testable on
//! any host.
const builtin = @import("builtin");
const std = @import("std");
const protobuf = @import("protobuf_wire.zig");
const reapi = @import("reapi.zig");

pub const key_property = "persistentWorkerKey";
pub const protocol_property = "persistentWorkerProtocol";
pub const enable_property = "actiond.persistent_workers";
pub const cmdline_prefix = "actiond.persistent_workers=";
pub const persistent_worker_flag = "--persistent_worker";
pub const max_key_len = 128;
pub const max_flagfile_bytes = 16 * 1024 * 1024;
pub const max_flagfile_depth = 8;
pub const max_response_bytes = 16 * 1024 * 1024;
pub const default_idle_ttl_ns: i96 = 30 * std.time.ns_per_min;
pub const default_sticky_ns: i96 = 5 * std.time.ns_per_s;
pub const default_memory_per_worker_mib: u64 = 2048;
pub const burst_memory_per_worker_mib: u64 = 1365;

pub const Protocol = enum {
    proto,
    json,

    pub fn fromProperty(value: ?[]const u8) ?Protocol {
        const text = value orelse return .proto;
        if (text.len == 0 or std.mem.eql(u8, text, "proto")) return .proto;
        if (std.mem.eql(u8, text, "json")) return .json;
        return null;
    }
};

fn platformProperty(platform: ?reapi.Platform, name: []const u8) ?[]const u8 {
    const value = platform orelse return null;
    for (value.properties) |property| {
        if (std.mem.eql(u8, property.name, name)) return property.value;
    }
    return null;
}

fn propertyDisables(value: ?[]const u8) bool {
    const text = value orelse return false;
    return std.ascii.eqlIgnoreCase(text, "0") or
        std.ascii.eqlIgnoreCase(text, "false") or
        std.ascii.eqlIgnoreCase(text, "off") or
        std.ascii.eqlIgnoreCase(text, "no");
}

fn propertyEnables(value: ?[]const u8) bool {
    const text = value orelse return false;
    return std.ascii.eqlIgnoreCase(text, "1") or
        std.ascii.eqlIgnoreCase(text, "true") or
        std.ascii.eqlIgnoreCase(text, "on") or
        std.ascii.eqlIgnoreCase(text, "yes");
}

/// Bazel's `WorkerParser.FLAG_FILE_PATTERN`: `(?:@|--?flagfile=)(.+)`, excluding `@@`.
pub fn flagfilePath(arg: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, arg, "@")) {
        if (std.mem.startsWith(u8, arg, "@@")) return null;
        if (arg.len == 1) return null;
        return arg[1..];
    }
    for ([_][]const u8{ "--flagfile=", "-flagfile=" }) |prefix| {
        if (std.mem.startsWith(u8, arg, prefix)) {
            if (arg.len == prefix.len) return null;
            return arg[prefix.len..];
        }
    }
    return null;
}

fn validKey(key: []const u8) bool {
    if (key.len == 0 or key.len > max_key_len) return false;
    for (key) |byte| {
        if (!std.ascii.isHex(byte)) return false;
    }
    return true;
}

/// Everything the executor needs to decide that an action can run in a warm
/// worker, and how. `null` from `fromCommand` always means "use the cold path".
pub const Plan = struct {
    key: []const u8,
    protocol: Protocol,
    /// `<key>:<libc>:<shell>`; the chroot runtime mounts depend on the libc and
    /// bash properties, so workers are never shared across them.
    pool_key: []u8,
    /// Worker startup argv: every non-flagfile argument plus `--persistent_worker`.
    startup_args: [][]const u8,
    /// Flagfile arguments in command order, still in their `@`/`--flagfile=` form.
    flagfile_args: [][]const u8,

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.pool_key);
        allocator.free(self.startup_args);
        allocator.free(self.flagfile_args);
        self.* = undefined;
    }

    pub fn fromCommand(
        allocator: std.mem.Allocator,
        command: reapi.Command,
        platform: ?reapi.Platform,
    ) !?Plan {
        const key = platformProperty(platform, key_property) orelse return null;
        if (!validKey(key)) return null;
        const protocol = Protocol.fromProperty(platformProperty(platform, protocol_property)) orelse return null;
        if (propertyDisables(platformProperty(platform, enable_property))) return null;
        if (propertyEnables(platformProperty(platform, "mutates_inputs"))) return null;
        if (command.working_directory.len != 0) return null;
        if (command.arguments.len < 2) return null;
        if (flagfilePath(command.arguments[0]) != null) return null;

        var startup: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer startup.deinit(allocator);
        var flagfiles: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer flagfiles.deinit(allocator);
        for (command.arguments) |arg| {
            if (flagfilePath(arg) != null) {
                try flagfiles.append(allocator, arg);
            } else {
                try startup.append(allocator, arg);
            }
        }
        if (flagfiles.items.len == 0) return null;
        try startup.append(allocator, persistent_worker_flag);

        const libc = platformProperty(platform, "libc") orelse "";
        const shell: []const u8 = if (platformProperty(platform, "requires-bash") != null) "bash" else "";
        const pool_key = try std.fmt.allocPrint(allocator, "{s}:{s}:{s}", .{ key, libc, shell });
        errdefer allocator.free(pool_key);

        return .{
            .key = key,
            .protocol = protocol,
            .pool_key = pool_key,
            .startup_args = try startup.toOwnedSlice(allocator),
            .flagfile_args = try flagfiles.toOwnedSlice(allocator),
        };
    }
};

/// Reads a flagfile by its execroot-relative path. Implemented by the executor
/// over the mounted workspace, and by tests over an in-memory map.
pub const FlagfileReader = struct {
    context: *anyopaque,
    read: *const fn (context: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8,
};

/// Mirrors `WorkerSpawnRunner.expandArgument`: `@file` arguments become one
/// argument per line (recursively), `--flagfile=`/`-flagfile=` arguments are
/// passed through literally for the worker to read itself.
pub fn expandRequestArguments(
    allocator: std.mem.Allocator,
    flagfile_args: []const []const u8,
    reader: FlagfileReader,
) ![][]u8 {
    var out: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer freeArguments(allocator, out.items);
    errdefer out.deinit(allocator);
    for (flagfile_args) |arg| try expandArgument(allocator, arg, reader, &out, 0);
    return try out.toOwnedSlice(allocator);
}

pub fn freeArguments(allocator: std.mem.Allocator, arguments: []const []u8) void {
    for (arguments) |argument| allocator.free(argument);
}

fn expandArgument(
    allocator: std.mem.Allocator,
    arg: []const u8,
    reader: FlagfileReader,
    out: *std.ArrayListUnmanaged([]u8),
    depth: usize,
) !void {
    if (!std.mem.startsWith(u8, arg, "@") or std.mem.startsWith(u8, arg, "@@")) {
        try out.append(allocator, try allocator.dupe(u8, arg));
        return;
    }
    if (depth >= max_flagfile_depth) return error.FlagfileTooDeep;
    const path = arg[1..];
    if (path.len == 0) return error.InvalidFlagfile;
    const contents = try reader.read(reader.context, allocator, path);
    defer allocator.free(contents);
    if (contents.len > max_flagfile_bytes) return error.FlagfileTooLarge;

    var body = contents;
    if (std.mem.endsWith(u8, body, "\n")) body = body[0 .. body.len - 1];
    if (body.len == 0) return;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw_line| {
        const line = if (std.mem.endsWith(u8, raw_line, "\r")) raw_line[0 .. raw_line.len - 1] else raw_line;
        try expandArgument(allocator, line, reader, out, depth + 1);
    }
}

pub const WorkResponse = struct {
    exit_code: i32 = 0,
    output: []const u8 = "",
    request_id: i32 = 0,
    was_cancelled: bool = false,

    fn decodeProto(bytes: []const u8) !WorkResponse {
        var out: WorkResponse = .{};
        var reader = protobuf.Reader.init(bytes);
        while (try reader.next()) |tag| {
            switch (tag.field_number) {
                1 => out.exit_code = try reader.readInt32(),
                2 => out.output = try reader.readString(),
                3 => out.request_id = try reader.readInt32(),
                4 => out.was_cancelled = try reader.readBool(),
                else => try reader.skipField(tag.wire_type),
            }
        }
        return out;
    }
};

/// Encodes a singleplex `blaze.worker.WorkRequest` with only `arguments` set
/// (and `request_id` when non-zero), framed for the given protocol: a varint
/// length prefix for proto, one JSON object followed by a newline for json.
pub fn encodeWorkRequest(
    allocator: std.mem.Allocator,
    protocol: Protocol,
    arguments: []const []const u8,
    request_id: i32,
) ![]u8 {
    switch (protocol) {
        .proto => {
            var body = protobuf.Writer.init(allocator);
            defer body.deinit();
            for (arguments) |argument| try body.writeStringField(1, argument);
            if (request_id != 0) try body.writeInt32Field(3, request_id);
            const payload = body.writtenBytes();

            var framed = protobuf.Writer.init(allocator);
            defer framed.deinit();
            try framed.writeVarint(payload.len);
            var out: std.ArrayListUnmanaged(u8) = .empty;
            errdefer out.deinit(allocator);
            try out.appendSlice(allocator, framed.writtenBytes());
            try out.appendSlice(allocator, payload);
            return try out.toOwnedSlice(allocator);
        },
        .json => {
            var out: std.ArrayListUnmanaged(u8) = .empty;
            errdefer out.deinit(allocator);
            const Request = struct {
                arguments: []const []const u8,
                requestId: i32,
            };
            const encoded = try std.json.Stringify.valueAlloc(allocator, Request{
                .arguments = arguments,
                .requestId = request_id,
            }, .{});
            defer allocator.free(encoded);
            try out.appendSlice(allocator, encoded);
            try out.append(allocator, '\n');
            return try out.toOwnedSlice(allocator);
        },
    }
}

/// Accumulates worker stdout bytes until one complete WorkResponse is available.
pub const ResponseDecoder = struct {
    protocol: Protocol,
    buffer: std.ArrayListUnmanaged(u8) = .empty,
    owned_output: ?[]u8 = null,

    pub fn init(protocol: Protocol) ResponseDecoder {
        return .{ .protocol = protocol };
    }

    pub fn deinit(self: *ResponseDecoder, allocator: std.mem.Allocator) void {
        self.buffer.deinit(allocator);
        if (self.owned_output) |output| allocator.free(output);
        self.* = undefined;
    }

    /// Appends bytes and returns the decoded response once it is complete.
    /// The returned `output` is owned by the decoder until `deinit`.
    pub fn feed(self: *ResponseDecoder, allocator: std.mem.Allocator, bytes: []const u8) !?WorkResponse {
        if (self.buffer.items.len + bytes.len > max_response_bytes + 16) return error.ResponseTooLarge;
        try self.buffer.appendSlice(allocator, bytes);
        return switch (self.protocol) {
            .proto => try self.tryDecodeProto(allocator),
            .json => try self.tryDecodeJson(allocator),
        };
    }

    fn tryDecodeProto(self: *ResponseDecoder, allocator: std.mem.Allocator) !?WorkResponse {
        const available = self.buffer.items;
        var length: u64 = 0;
        var shift: u6 = 0;
        var index: usize = 0;
        while (true) {
            if (index >= available.len) return null;
            if (index >= 10) return error.MalformedResponse;
            const byte = available[index];
            index += 1;
            length |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) break;
            if (shift >= 63) return error.MalformedResponse;
            shift += 7;
        }
        if (length > max_response_bytes) return error.ResponseTooLarge;
        const message_len: usize = @intCast(length);
        if (available.len - index < message_len) return null;
        var response = try WorkResponse.decodeProto(available[index .. index + message_len]);
        const output = try allocator.dupe(u8, response.output);
        if (self.owned_output) |previous| allocator.free(previous);
        self.owned_output = output;
        response.output = output;
        return response;
    }

    fn tryDecodeJson(self: *ResponseDecoder, allocator: std.mem.Allocator) !?WorkResponse {
        const JsonResponse = struct {
            exitCode: i32 = 0,
            output: []const u8 = "",
            requestId: i32 = 0,
            wasCancelled: bool = false,
        };
        const text = std.mem.trim(u8, self.buffer.items, " \r\n\t");
        if (text.len == 0) return null;
        var parsed = std.json.parseFromSlice(JsonResponse, allocator, text, .{
            .ignore_unknown_fields = true,
        }) catch |err| switch (err) {
            error.UnexpectedEndOfInput, error.BufferUnderrun => return null,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedResponse,
        };
        defer parsed.deinit();
        const output = try allocator.dupe(u8, parsed.value.output);
        if (self.owned_output) |previous| allocator.free(previous);
        self.owned_output = output;
        return .{
            .exit_code = parsed.value.exitCode,
            .output = output,
            .request_id = parsed.value.requestId,
            .was_cancelled = parsed.value.wasCancelled,
        };
    }
};

pub const Config = struct {
    /// Warm workers across all keys before eviction starts; 0 disables the feature.
    max_workers: u32,
    /// Absolute cap: when the budget is full but every idle worker was used
    /// within `sticky_ns`, the pool grows up to this instead of evicting a
    /// worker that is about to be needed again. Never below `max_workers`.
    hard_max_workers: u32 = 0,
    idle_ttl_ns: i96 = default_idle_ttl_ns,
    sticky_ns: i96 = default_sticky_ns,

    /// `max_workers = clamp(memory_mib / 2048, 1, cpu_count)` (one warm JVM per
    /// 2 GiB), `hard_max_workers = clamp(memory_mib / 1365, max, cpu_count * 1.5)`:
    /// bursts may pack workers to about 1.3 GiB each and oversubscribe the vCPUs
    /// by half, because Bazel keeps more actions in flight than the VM has
    /// cores and a request waiting for a slot costs more than a JVM sharing
    /// a core (measured: 259 s of summed pool wait at a cap of 10 on 10 vCPUs).
    pub fn fromResources(memory_mib: u64, cpu_count: u64) Config {
        const cpus = @max(cpu_count, 1);
        const soft = @min(@max(memory_mib / default_memory_per_worker_mib, 1), cpus);
        const hard = @min(@max(memory_mib / burst_memory_per_worker_mib, soft), cpus + cpus / 2);
        return .{
            .max_workers = @intCast(@min(soft, std.math.maxInt(u32))),
            .hard_max_workers = @intCast(@min(hard, std.math.maxInt(u32))),
        };
    }

    /// Parses `actiond.persistent_workers=<N>` from the kernel command line;
    /// an explicit N is both the budget and the cap.
    pub fn fromCmdline(cmdline: []const u8, fallback: Config) Config {
        var tokens = std.mem.tokenizeAny(u8, cmdline, " \n\t");
        while (tokens.next()) |token| {
            if (!std.mem.startsWith(u8, token, cmdline_prefix)) continue;
            const value = token[cmdline_prefix.len..];
            const workers = std.fmt.parseInt(u32, value, 10) catch return fallback;
            var config = fallback;
            config.max_workers = workers;
            config.hard_max_workers = workers;
            return config;
        }
        return fallback;
    }

    fn hardMax(self: Config) u32 {
        return @max(self.hard_max_workers, self.max_workers);
    }
};

pub const Stats = struct {
    spawned: u64 = 0,
    evicted_idle: u64 = 0,
    evicted_lru: u64 = 0,
    destroyed_failed: u64 = 0,
    requests: u64 = 0,
    fallbacks: u64 = 0,
    waits: u64 = 0,
    over_budget: u64 = 0,
};

/// Process-agnostic bookkeeping for warm workers. The executor attaches the
/// Linux process state through `Worker.process`; the pool only decides which
/// worker serves which key and when workers are retired. `destroy` is the single
/// place a worker leaves the pool, so callers pass the hook that kills it.
pub const Pool = struct {
    pub const Worker = struct {
        id: u64,
        pool_key: []u8,
        busy: bool = true,
        /// Set once the executor spawned the process; a fresh worker from
        /// `acquire` has no process yet.
        process: ?*anyopaque = null,
        last_used: std.Io.Timestamp,
        requests: u64 = 0,
    };

    pub const DestroyFn = *const fn (context: *anyopaque, worker: *Worker) void;

    config: Config,
    mutex: std.Io.Mutex = .init,
    workers: std.ArrayListUnmanaged(*Worker) = .empty,
    next_id: u64 = 1,
    stats: Stats = .{},
    destroy_context: *anyopaque,
    destroy_fn: DestroyFn,

    pub fn init(config: Config, destroy_context: *anyopaque, destroy_fn: DestroyFn) Pool {
        return .{
            .config = config,
            .destroy_context = destroy_context,
            .destroy_fn = destroy_fn,
        };
    }

    pub fn deinit(self: *Pool, allocator: std.mem.Allocator) void {
        for (self.workers.items) |worker| {
            self.destroy_fn(self.destroy_context, worker);
            allocator.free(worker.pool_key);
            allocator.destroy(worker);
        }
        self.workers.deinit(allocator);
        self.* = undefined;
    }

    pub fn enabled(self: *const Pool) bool {
        return self.config.max_workers != 0;
    }

    pub const Acquired = struct {
        worker: *Worker,
        /// True when the caller must spawn the process before using the worker.
        fresh: bool,
    };

    /// Returns an idle worker for `pool_key`, or a fresh record when the budget
    /// allows, evicting the least recently used idle worker of another key when
    /// it does not. Waits (polling, honoring `cancellation`) while every worker
    /// is busy: a queued warm request still beats a cold JVM start.
    pub fn acquire(
        self: *Pool,
        io: std.Io,
        allocator: std.mem.Allocator,
        pool_key: []const u8,
        cancellation: ?*const std.atomic.Value(bool),
    ) !Acquired {
        var waited = false;
        while (true) {
            if (cancellation) |value| {
                if (value.load(.acquire)) return error.ExecutionCancelled;
            }
            const now = std.Io.Clock.awake.now(io);
            self.mutex.lockUncancelable(io);
            const decision = try self.acquireLocked(allocator, pool_key, now);
            if (decision) |acquired| {
                if (waited) self.stats.waits += 1;
                self.mutex.unlock(io);
                return acquired;
            }
            self.mutex.unlock(io);
            waited = true;
            try io.sleep(.fromMilliseconds(poll_interval_ms), .awake);
        }
    }

    const poll_interval_ms = 20;

    /// One scheduling step; `null` means every worker is busy and the caller
    /// should wait. Exposed for tests with a caller-chosen clock.
    pub fn acquireLocked(
        self: *Pool,
        allocator: std.mem.Allocator,
        pool_key: []const u8,
        now: std.Io.Timestamp,
    ) !?Acquired {
        if (!self.enabled()) return error.PersistentWorkersDisabled;
        self.reapIdleLocked(allocator, now);

        for (self.workers.items) |worker| {
            if (worker.busy or !std.mem.eql(u8, worker.pool_key, pool_key)) continue;
            worker.busy = true;
            worker.last_used = now;
            return .{ .worker = worker, .fresh = false };
        }

        if (self.workers.items.len >= self.config.max_workers) {
            if (self.leastRecentlyUsedIdleLocked(now)) |victim| {
                self.stats.evicted_lru += 1;
                self.removeLocked(allocator, victim);
            } else if (self.workers.items.len >= self.config.hardMax()) {
                return null;
            } else {
                self.stats.over_budget += 1;
            }
        }

        const worker = try allocator.create(Worker);
        errdefer allocator.destroy(worker);
        worker.* = .{
            .id = self.next_id,
            .pool_key = try allocator.dupe(u8, pool_key),
            .last_used = now,
        };
        errdefer allocator.free(worker.pool_key);
        try self.workers.append(allocator, worker);
        self.next_id += 1;
        self.stats.spawned += 1;
        return .{ .worker = worker, .fresh = true };
    }

    /// Returns a worker after a request. Unhealthy workers (crashed, timed out,
    /// protocol errors) leave the pool immediately.
    pub fn release(self: *Pool, io: std.Io, allocator: std.mem.Allocator, worker: *Worker, healthy: bool) void {
        const now = std.Io.Clock.awake.now(io);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.releaseLocked(allocator, worker, healthy, now);
    }

    pub fn releaseLocked(self: *Pool, allocator: std.mem.Allocator, worker: *Worker, healthy: bool, now: std.Io.Timestamp) void {
        if (!healthy) {
            self.stats.destroyed_failed += 1;
            self.removeLocked(allocator, worker);
            return;
        }
        worker.busy = false;
        worker.requests += 1;
        worker.last_used = now;
        self.stats.requests += 1;
        self.reapIdleLocked(allocator, now);
    }

    pub fn recordFallback(self: *Pool, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.stats.fallbacks += 1;
    }

    pub fn snapshot(self: *Pool, io: std.Io) Summary {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.summaryLocked();
    }

    pub const Summary = struct {
        stats: Stats,
        total: usize,
        busy: usize,
        max_workers: u32,
    };

    pub fn summaryLocked(self: *const Pool) Summary {
        var busy: usize = 0;
        for (self.workers.items) |worker| {
            if (worker.busy) busy += 1;
        }
        return .{
            .stats = self.stats,
            .total = self.workers.items.len,
            .busy = busy,
            .max_workers = self.config.max_workers,
        };
    }

    pub fn appendStats(self: *Pool, io: std.Io, allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8)) !void {
        const summary = self.snapshot(io);
        const text = try std.fmt.allocPrint(allocator,
            \\persistent_workers_max {d}
            \\persistent_workers_total {d}
            \\persistent_workers_busy {d}
            \\persistent_workers_spawned {d}
            \\persistent_workers_requests {d}
            \\persistent_workers_fallbacks {d}
            \\persistent_workers_waits {d}
            \\persistent_workers_over_budget {d}
            \\persistent_workers_evicted_idle {d}
            \\persistent_workers_evicted_lru {d}
            \\persistent_workers_destroyed_failed {d}
            \\
        , .{
            summary.max_workers,
            summary.total,
            summary.busy,
            summary.stats.spawned,
            summary.stats.requests,
            summary.stats.fallbacks,
            summary.stats.waits,
            summary.stats.over_budget,
            summary.stats.evicted_idle,
            summary.stats.evicted_lru,
            summary.stats.destroyed_failed,
        });
        defer allocator.free(text);
        try out.appendSlice(allocator, text);
    }

    /// LRU idle worker that has not been used within `sticky_ns`, preferring
    /// keys that keep at least one other worker so a burst of one mnemonic does
    /// not evict the only warm worker of another.
    fn leastRecentlyUsedIdleLocked(self: *Pool, now: std.Io.Timestamp) ?*Worker {
        var victim: ?*Worker = null;
        var victim_shared = false;
        for (self.workers.items) |worker| {
            if (worker.busy) continue;
            if (worker.last_used.durationTo(now).nanoseconds < self.config.sticky_ns) continue;
            const shared = self.keyWorkerCountLocked(worker.pool_key) > 1;
            const current = victim orelse {
                victim = worker;
                victim_shared = shared;
                continue;
            };
            if (shared != victim_shared) {
                if (shared) {
                    victim = worker;
                    victim_shared = true;
                }
                continue;
            }
            if (worker.last_used.toNanoseconds() < current.last_used.toNanoseconds()) victim = worker;
        }
        return victim;
    }

    fn keyWorkerCountLocked(self: *const Pool, pool_key: []const u8) usize {
        var count: usize = 0;
        for (self.workers.items) |worker| {
            if (std.mem.eql(u8, worker.pool_key, pool_key)) count += 1;
        }
        return count;
    }

    fn reapIdleLocked(self: *Pool, allocator: std.mem.Allocator, now: std.Io.Timestamp) void {
        var index: usize = 0;
        while (index < self.workers.items.len) {
            const worker = self.workers.items[index];
            if (!worker.busy and worker.last_used.durationTo(now).nanoseconds >= self.config.idle_ttl_ns) {
                self.stats.evicted_idle += 1;
                self.removeLocked(allocator, worker);
                continue;
            }
            index += 1;
        }
    }

    fn removeLocked(self: *Pool, allocator: std.mem.Allocator, worker: *Worker) void {
        for (self.workers.items, 0..) |candidate, index| {
            if (candidate != worker) continue;
            _ = self.workers.swapRemove(index);
            break;
        }
        self.destroy_fn(self.destroy_context, worker);
        allocator.free(worker.pool_key);
        allocator.destroy(worker);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn testCommand(arguments: []const []const u8, platform: ?reapi.Platform) reapi.Command {
    return .{ .arguments = arguments, .platform = platform };
}

test "Plan.fromCommand builds startup args and flagfiles from a keyed command" {
    const platform: reapi.Platform = .{ .properties = &.{
        .{ .name = "libc", .value = "glibc2.35" },
        .{ .name = "requires-bash", .value = "" },
        .{ .name = key_property, .value = test_key },
    } };
    var plan = (try Plan.fromCommand(std.testing.allocator, testCommand(&.{
        "bazel-out/exec/bin/external/rules_kotlin+/src/main/kotlin/build",
        "--flagfile=bazel-out/bin/foo-kt.jar-0.params",
    }, platform), platform)).?;
    defer plan.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(test_key, plan.key);
    try std.testing.expectEqual(Protocol.proto, plan.protocol);
    try std.testing.expectEqualStrings(test_key ++ ":glibc2.35:bash", plan.pool_key);
    try std.testing.expectEqual(@as(usize, 2), plan.startup_args.len);
    try std.testing.expectEqualStrings("bazel-out/exec/bin/external/rules_kotlin+/src/main/kotlin/build", plan.startup_args[0]);
    try std.testing.expectEqualStrings("--persistent_worker", plan.startup_args[1]);
    try std.testing.expectEqual(@as(usize, 1), plan.flagfile_args.len);
    try std.testing.expectEqualStrings("--flagfile=bazel-out/bin/foo-kt.jar-0.params", plan.flagfile_args[0]);
}

test "Plan.fromCommand keeps javac-style @flagfiles and interleaved startup args" {
    const platform: reapi.Platform = .{ .properties = &.{
        .{ .name = key_property, .value = "abc123" },
        .{ .name = protocol_property, .value = "json" },
    } };
    var plan = (try Plan.fromCommand(std.testing.allocator, testCommand(&.{
        "external/remotejdk/bin/java",
        "-Xmx1g",
        "-jar",
        "JavaBuilder.jar",
        "@bazel-out/bin/lib.jar-0.params",
        "--extra",
    }, platform), platform)).?;
    defer plan.deinit(std.testing.allocator);

    try std.testing.expectEqual(Protocol.json, plan.protocol);
    try std.testing.expectEqualStrings("abc123::", plan.pool_key);
    try std.testing.expectEqual(@as(usize, 6), plan.startup_args.len);
    try std.testing.expectEqualStrings("--extra", plan.startup_args[4]);
    try std.testing.expectEqualStrings("--persistent_worker", plan.startup_args[5]);
    try std.testing.expectEqualStrings("@bazel-out/bin/lib.jar-0.params", plan.flagfile_args[0]);
}

test "Plan.fromCommand falls back to the cold path for unsupported actions" {
    const keyed: reapi.Platform = .{ .properties = &.{.{ .name = key_property, .value = test_key }} };
    const argv: []const []const u8 = &.{ "tool", "--flagfile=x.params" };

    // No key at all.
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(argv, null), null)) == null);
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(argv, .{}), .{ .properties = &.{
        .{ .name = "libc", .value = "glibc2.35" },
    } })) == null);
    // Invalid key values.
    for ([_][]const u8{ "", "not hex!", "zz", "a" ** (max_key_len + 1) }) |bad_key| {
        try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(argv, null), .{ .properties = &.{
            .{ .name = key_property, .value = bad_key },
        } })) == null);
    }
    // Unknown protocol.
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(argv, null), .{ .properties = &.{
        .{ .name = key_property, .value = test_key },
        .{ .name = protocol_property, .value = "protobuf" },
    } })) == null);
    // Explicitly disabled.
    for ([_][]const u8{ "0", "false", "off", "NO" }) |value| {
        try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(argv, null), .{ .properties = &.{
            .{ .name = key_property, .value = test_key },
            .{ .name = enable_property, .value = value },
        } })) == null);
    }
    // Mutating inputs needs the overlay path.
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(argv, null), .{ .properties = &.{
        .{ .name = key_property, .value = test_key },
        .{ .name = "mutates_inputs", .value = "1" },
    } })) == null);
    // No flagfile, flagfile as argv[0], working directory, or too few args.
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(&.{ "tool", "--flag" }, null), keyed)) == null);
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(&.{ "tool", "@@literal" }, null), keyed)) == null);
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(&.{ "@params", "tool" }, null), keyed)) == null);
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, testCommand(&.{"tool"}, null), keyed)) == null);
    try std.testing.expect((try Plan.fromCommand(std.testing.allocator, .{
        .arguments = argv,
        .working_directory = "sub",
    }, keyed)) == null);
}

test "Protocol.fromProperty defaults to proto and rejects unknown values" {
    try std.testing.expectEqual(Protocol.proto, Protocol.fromProperty(null).?);
    try std.testing.expectEqual(Protocol.proto, Protocol.fromProperty("").?);
    try std.testing.expectEqual(Protocol.proto, Protocol.fromProperty("proto").?);
    try std.testing.expectEqual(Protocol.json, Protocol.fromProperty("json").?);
    try std.testing.expect(Protocol.fromProperty("JSON") == null);
    try std.testing.expect(Protocol.fromProperty("protobuf") == null);
}

test "flagfilePath matches Bazel's flagfile pattern" {
    try std.testing.expectEqualStrings("a.params", flagfilePath("@a.params").?);
    try std.testing.expectEqualStrings("b", flagfilePath("--flagfile=b").?);
    try std.testing.expectEqualStrings("c", flagfilePath("-flagfile=c").?);
    try std.testing.expect(flagfilePath("@@escaped") == null);
    try std.testing.expect(flagfilePath("@") == null);
    try std.testing.expect(flagfilePath("--flagfile=") == null);
    try std.testing.expect(flagfilePath("--flagfiles=x") == null);
    try std.testing.expect(flagfilePath("plain") == null);
}

const TestFiles = struct {
    entries: []const struct { path: []const u8, contents: []const u8 },

    fn read(context: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8 {
        const self: *TestFiles = @ptrCast(@alignCast(context));
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.path, path)) return try allocator.dupe(u8, entry.contents);
        }
        return error.FileNotFound;
    }

    fn reader(self: *TestFiles) FlagfileReader {
        return .{ .context = self, .read = read };
    }
};

test "expandRequestArguments expands @files line by line and keeps --flagfile literal" {
    var files = TestFiles{ .entries = &.{
        .{ .path = "a.params", .contents = "--output\nout.jar\n\n@nested.params\r\n--last" },
        .{ .path = "nested.params", .contents = "--nested=1\n" },
        .{ .path = "empty.params", .contents = "" },
    } };
    const expanded = try expandRequestArguments(std.testing.allocator, &.{
        "@a.params",
        "--flagfile=keep.params",
        "@empty.params",
        "@@literal",
    }, files.reader());
    defer {
        freeArguments(std.testing.allocator, expanded);
        std.testing.allocator.free(expanded);
    }

    const expected = [_][]const u8{ "--output", "out.jar", "", "--nested=1", "--last", "--flagfile=keep.params", "@@literal" };
    try std.testing.expectEqual(expected.len, expanded.len);
    for (expected, expanded) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "expandRequestArguments rejects missing, oversized and self-referential flagfiles" {
    var files = TestFiles{ .entries = &.{
        .{ .path = "loop.params", .contents = "@loop.params\n" },
    } };
    try std.testing.expectError(error.FileNotFound, expandRequestArguments(std.testing.allocator, &.{"@missing.params"}, files.reader()));
    try std.testing.expectError(error.FlagfileTooDeep, expandRequestArguments(std.testing.allocator, &.{"@loop.params"}, files.reader()));

    const big = try std.testing.allocator.alloc(u8, max_flagfile_bytes + 1);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');
    var big_files = TestFiles{ .entries = &.{.{ .path = "big.params", .contents = big }} };
    try std.testing.expectError(error.FlagfileTooLarge, expandRequestArguments(std.testing.allocator, &.{"@big.params"}, big_files.reader()));
}

test "encodeWorkRequest frames proto requests with a varint length prefix" {
    const framed = try encodeWorkRequest(std.testing.allocator, .proto, &.{ "--a", "b" }, 0);
    defer std.testing.allocator.free(framed);
    // 0x0a len "--a" | 0x0a len "b" = 5 + 3 = 8 bytes, prefixed by varint 8.
    try std.testing.expectEqualSlices(u8, &.{ 8, 0x0a, 3, '-', '-', 'a', 0x0a, 1, 'b' }, framed);

    const with_id = try encodeWorkRequest(std.testing.allocator, .proto, &.{"x"}, 7);
    defer std.testing.allocator.free(with_id);
    try std.testing.expectEqualSlices(u8, &.{ 5, 0x0a, 1, 'x', 0x18, 7 }, with_id);

    // A payload longer than 127 bytes needs a two-byte varint prefix.
    const long_arg = "y" ** 200;
    const long = try encodeWorkRequest(std.testing.allocator, .proto, &.{long_arg}, 0);
    defer std.testing.allocator.free(long);
    try std.testing.expectEqual(@as(u8, (203 & 0x7f) | 0x80), long[0]);
    try std.testing.expectEqual(@as(u8, 203 >> 7), long[1]);
    try std.testing.expectEqual(@as(usize, 2 + 203), long.len);
}

test "encodeWorkRequest frames json requests as one line" {
    const framed = try encodeWorkRequest(std.testing.allocator, .json, &.{ "--a", "quote\"d" }, 3);
    defer std.testing.allocator.free(framed);
    try std.testing.expectEqualStrings("{\"arguments\":[\"--a\",\"quote\\\"d\"],\"requestId\":3}\n", framed);
}

test "ResponseDecoder assembles a proto WorkResponse from partial reads" {
    var decoder = ResponseDecoder.init(.proto);
    defer decoder.deinit(std.testing.allocator);
    // exit_code=1 (0x08 0x01), output="warn" (0x12 0x04 w a r n), request_id=0.
    const message = [_]u8{ 0x08, 0x01, 0x12, 0x04, 'w', 'a', 'r', 'n' };
    const framed = [_]u8{message.len} ++ message;

    try std.testing.expect((try decoder.feed(std.testing.allocator, framed[0..1])) == null);
    try std.testing.expect((try decoder.feed(std.testing.allocator, framed[1..4])) == null);
    const response = (try decoder.feed(std.testing.allocator, framed[4..])).?;
    try std.testing.expectEqual(@as(i32, 1), response.exit_code);
    try std.testing.expectEqualStrings("warn", response.output);
    try std.testing.expect(!response.was_cancelled);
}

test "ResponseDecoder rejects oversized and malformed proto frames" {
    var decoder = ResponseDecoder.init(.proto);
    defer decoder.deinit(std.testing.allocator);
    // varint for 32 MiB: exceeds max_response_bytes.
    try std.testing.expectError(error.ResponseTooLarge, decoder.feed(std.testing.allocator, &.{ 0x80, 0x80, 0x80, 0x10 }));

    var bad = ResponseDecoder.init(.proto);
    defer bad.deinit(std.testing.allocator);
    // Eleven continuation bytes can never be a valid length varint.
    try std.testing.expectError(error.MalformedResponse, bad.feed(std.testing.allocator, &([_]u8{0x80} ** 11)));
}

test "ResponseDecoder parses json responses and waits for complete objects" {
    var decoder = ResponseDecoder.init(.json);
    defer decoder.deinit(std.testing.allocator);
    try std.testing.expect((try decoder.feed(std.testing.allocator, "{\"exitCode\":2,\"out")) == null);
    const response = (try decoder.feed(std.testing.allocator, "put\":\"boom\",\"extra\":1}\n")).?;
    try std.testing.expectEqual(@as(i32, 2), response.exit_code);
    try std.testing.expectEqualStrings("boom", response.output);

    var defaults = ResponseDecoder.init(.json);
    defer defaults.deinit(std.testing.allocator);
    const empty = (try defaults.feed(std.testing.allocator, "{}\n")).?;
    try std.testing.expectEqual(@as(i32, 0), empty.exit_code);
    try std.testing.expectEqualStrings("", empty.output);

    var malformed = ResponseDecoder.init(.json);
    defer malformed.deinit(std.testing.allocator);
    try std.testing.expectError(error.MalformedResponse, malformed.feed(std.testing.allocator, "not json\n"));
}

test "Config derives the worker budget from memory and cpus and honors the cmdline" {
    try std.testing.expectEqual(@as(u32, 8), Config.fromResources(16384, 10).max_workers);
    try std.testing.expectEqual(@as(u32, 12), Config.fromResources(16384, 10).hard_max_workers);
    try std.testing.expectEqual(@as(u32, 10), Config.fromResources(32768, 10).max_workers);
    try std.testing.expectEqual(@as(u32, 15), Config.fromResources(32768, 10).hard_max_workers);
    try std.testing.expectEqual(@as(u32, 4), Config.fromResources(16384, 4).max_workers);
    try std.testing.expectEqual(@as(u32, 6), Config.fromResources(16384, 4).hard_max_workers);
    try std.testing.expectEqual(@as(u32, 1), Config.fromResources(512, 2).max_workers);
    try std.testing.expectEqual(@as(u32, 1), Config.fromResources(512, 2).hard_max_workers);
    try std.testing.expectEqual(@as(u32, 1), Config.fromResources(0, 0).max_workers);
    try std.testing.expectEqual(@as(u32, 4), Config.fromResources(8192, 16).max_workers);
    try std.testing.expectEqual(@as(u32, 6), Config.fromResources(8192, 16).hard_max_workers);

    const fallback = Config.fromResources(16384, 10);
    const disabled = Config.fromCmdline("console=hvc0 actiond.persistent_workers=0 quiet", fallback);
    try std.testing.expectEqual(@as(u32, 0), disabled.max_workers);
    try std.testing.expectEqual(@as(u32, 0), disabled.hard_max_workers);
    const three = Config.fromCmdline("actiond.persistent_workers=3\n", fallback);
    try std.testing.expectEqual(@as(u32, 3), three.max_workers);
    try std.testing.expectEqual(@as(u32, 3), three.hard_max_workers);
    try std.testing.expectEqual(@as(u32, 8), Config.fromCmdline("actiond.persistent_workers=lots", fallback).max_workers);
    try std.testing.expectEqual(@as(u32, 8), Config.fromCmdline("console=hvc0", fallback).max_workers);
    try std.testing.expectEqual(@as(u32, 5), (Config{ .max_workers = 5, .hard_max_workers = 2 }).hardMax());
}

test "Pool grows over budget instead of evicting recently used workers, up to the hard cap" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{
        .max_workers = 2,
        .hard_max_workers = 3,
        .sticky_ns = 5 * std.time.ns_per_s,
    }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);

    const a = (try pool.acquireLocked(std.testing.allocator, "a", testTimestamp(0))).?;
    const b = (try pool.acquireLocked(std.testing.allocator, "b", testTimestamp(0))).?;
    pool.releaseLocked(std.testing.allocator, a.worker, true, testTimestamp(10));
    pool.releaseLocked(std.testing.allocator, b.worker, true, testTimestamp(10));

    // Both idle workers were used 1 s ago: nothing is evicted, the pool grows to 3.
    const c = (try pool.acquireLocked(std.testing.allocator, "c", testTimestamp(11))).?;
    try std.testing.expect(c.fresh);
    try std.testing.expectEqual(@as(usize, 3), pool.workers.items.len);
    try std.testing.expectEqual(@as(u64, 0), log.destroyed.items.len);
    try std.testing.expectEqual(@as(u64, 1), pool.stats.over_budget);

    // At the hard cap with only sticky idle workers, callers wait.
    try std.testing.expect((try pool.acquireLocked(std.testing.allocator, "d", testTimestamp(12))) == null);

    // Once a worker ages past the sticky window it becomes the LRU victim.
    const d = (try pool.acquireLocked(std.testing.allocator, "d", testTimestamp(16))).?;
    try std.testing.expect(d.fresh);
    try std.testing.expectEqualSlices(u64, &.{1}, log.destroyed.items);
    try std.testing.expectEqual(@as(usize, 3), pool.workers.items.len);
}

const TestDestroyLog = struct {
    destroyed: std.ArrayListUnmanaged(u64) = .empty,

    fn destroy(context: *anyopaque, worker: *Pool.Worker) void {
        const self: *TestDestroyLog = @ptrCast(@alignCast(context));
        self.destroyed.append(std.testing.allocator, worker.id) catch unreachable;
    }
};

fn testTimestamp(seconds: i96) std.Io.Timestamp {
    return std.Io.Timestamp.fromNanoseconds(seconds * std.time.ns_per_s);
}

test "Pool reuses idle workers per key, spawns within budget and waits when busy" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 2 }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);
    const t0 = testTimestamp(0);

    const first = (try pool.acquireLocked(std.testing.allocator, "k1", t0)).?;
    try std.testing.expect(first.fresh);
    try std.testing.expectEqual(@as(u64, 1), first.worker.id);
    const second = (try pool.acquireLocked(std.testing.allocator, "k1", t0)).?;
    try std.testing.expect(second.fresh);
    // Budget exhausted and nothing idle: caller must wait.
    try std.testing.expect((try pool.acquireLocked(std.testing.allocator, "k1", t0)) == null);
    try std.testing.expect((try pool.acquireLocked(std.testing.allocator, "k2", t0)) == null);

    pool.releaseLocked(std.testing.allocator, first.worker, true, testTimestamp(1));
    const reused = (try pool.acquireLocked(std.testing.allocator, "k1", testTimestamp(2))).?;
    try std.testing.expect(!reused.fresh);
    try std.testing.expectEqual(first.worker, reused.worker);
    try std.testing.expectEqual(@as(u64, 1), reused.worker.requests);
    try std.testing.expectEqual(@as(u64, 0), log.destroyed.items.len);
    try std.testing.expectEqual(@as(u64, 2), pool.stats.spawned);
    try std.testing.expectEqual(@as(u64, 1), pool.stats.requests);
}

test "Pool evicts the least recently used idle worker of another key when full" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 2, .sticky_ns = 0 }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);

    const a = (try pool.acquireLocked(std.testing.allocator, "a", testTimestamp(0))).?;
    const b = (try pool.acquireLocked(std.testing.allocator, "b", testTimestamp(0))).?;
    pool.releaseLocked(std.testing.allocator, a.worker, true, testTimestamp(5));
    pool.releaseLocked(std.testing.allocator, b.worker, true, testTimestamp(3));

    // b is older; it is evicted to make room for key c.
    const c = (try pool.acquireLocked(std.testing.allocator, "c", testTimestamp(6))).?;
    try std.testing.expect(c.fresh);
    try std.testing.expectEqualSlices(u64, &.{2}, log.destroyed.items);
    try std.testing.expectEqual(@as(usize, 2), pool.workers.items.len);
    try std.testing.expectEqual(@as(u64, 1), pool.stats.evicted_lru);

    // a is still idle and still serves key a without a spawn.
    const a_again = (try pool.acquireLocked(std.testing.allocator, "a", testTimestamp(7))).?;
    try std.testing.expect(!a_again.fresh);
}

test "Pool eviction spares the only worker of a key while another key has spares" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 3, .sticky_ns = 0 }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);

    // kotlin: worker 1 (idle, oldest). javac: workers 2 and 3 (idle, newer).
    const kotlin = (try pool.acquireLocked(std.testing.allocator, "kotlin", testTimestamp(0))).?;
    const javac_a = (try pool.acquireLocked(std.testing.allocator, "javac", testTimestamp(0))).?;
    const javac_b = (try pool.acquireLocked(std.testing.allocator, "javac", testTimestamp(0))).?;
    pool.releaseLocked(std.testing.allocator, kotlin.worker, true, testTimestamp(1));
    pool.releaseLocked(std.testing.allocator, javac_a.worker, true, testTimestamp(5));
    pool.releaseLocked(std.testing.allocator, javac_b.worker, true, testTimestamp(6));

    // A third key evicts the older javac spare, not the lone kotlin worker.
    _ = (try pool.acquireLocked(std.testing.allocator, "turbine", testTimestamp(7))).?;
    try std.testing.expectEqualSlices(u64, &.{2}, log.destroyed.items);
    const kotlin_again = (try pool.acquireLocked(std.testing.allocator, "kotlin", testTimestamp(8))).?;
    try std.testing.expect(!kotlin_again.fresh);
    pool.releaseLocked(std.testing.allocator, kotlin_again.worker, true, testTimestamp(9));

    // With every key down to one worker, plain LRU applies (javac b idle since 6).
    _ = (try pool.acquireLocked(std.testing.allocator, "ktfmt", testTimestamp(10))).?;
    try std.testing.expectEqualSlices(u64, &.{ 2, 3 }, log.destroyed.items);
}

test "Pool retires unhealthy workers and idle workers past their TTL" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 4, .idle_ttl_ns = 10 * std.time.ns_per_s }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);

    const crashed = (try pool.acquireLocked(std.testing.allocator, "k", testTimestamp(0))).?;
    pool.releaseLocked(std.testing.allocator, crashed.worker, false, testTimestamp(1));
    try std.testing.expectEqualSlices(u64, &.{1}, log.destroyed.items);
    try std.testing.expectEqual(@as(usize, 0), pool.workers.items.len);
    try std.testing.expectEqual(@as(u64, 1), pool.stats.destroyed_failed);

    const idle = (try pool.acquireLocked(std.testing.allocator, "k", testTimestamp(2))).?;
    pool.releaseLocked(std.testing.allocator, idle.worker, true, testTimestamp(3));
    // Still within TTL: reused.
    const soon = (try pool.acquireLocked(std.testing.allocator, "k", testTimestamp(12))).?;
    try std.testing.expect(!soon.fresh);
    pool.releaseLocked(std.testing.allocator, soon.worker, true, testTimestamp(12));
    // Past TTL: reaped, a fresh worker is handed out.
    const late = (try pool.acquireLocked(std.testing.allocator, "k", testTimestamp(23))).?;
    try std.testing.expect(late.fresh);
    try std.testing.expectEqualSlices(u64, &.{ 1, 2 }, log.destroyed.items);
    try std.testing.expectEqual(@as(u64, 1), pool.stats.evicted_idle);
}

test "Pool reports disabled configurations instead of handing out workers" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 0 }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);
    try std.testing.expect(!pool.enabled());
    try std.testing.expectError(error.PersistentWorkersDisabled, pool.acquireLocked(std.testing.allocator, "k", testTimestamp(0)));
}

test "Pool.acquire honors cancellation while every worker is busy" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 1 }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);
    _ = try pool.acquire(std.testing.io, std.testing.allocator, "k", null);
    var cancelled = std.atomic.Value(bool).init(true);
    try std.testing.expectError(error.ExecutionCancelled, pool.acquire(std.testing.io, std.testing.allocator, "k", &cancelled));
}

test "Pool stats render as actiondfs-stats lines" {
    var log: TestDestroyLog = .{};
    defer log.destroyed.deinit(std.testing.allocator);
    var pool = Pool.init(.{ .max_workers = 3 }, &log, TestDestroyLog.destroy);
    defer pool.deinit(std.testing.allocator);
    _ = try pool.acquireLocked(std.testing.allocator, "k", testTimestamp(0));
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try pool.appendStats(std.testing.io, std.testing.allocator, &out);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "persistent_workers_max 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "persistent_workers_busy 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "persistent_workers_spawned 1\n") != null);
}
