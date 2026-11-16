//! Execroot-style symlink forest for multiplex workers.
//!
//! A multiplex worker serves several requests at once from one working
//! directory, exactly like Bazel's own local multiplex workers run in the
//! shared execroot. Overlay-based unions of per-request actiondfs trees turned
//! out to be unsafe (overlayfs forbids sharing an upper between mounts and
//! misreads its own xattrs when an upper is reused as a lower), so the forest
//! is the plain thing Bazel itself does: a writable directory tree where every
//! input file is a symlink to its CAS blob, directories are real, and tools
//! write their outputs in place. Paths are consistent within a build, so the
//! forest is the superset of every request's tree; a request only adds or
//! re-points entries. Synced `Directory` digests are remembered per worker, so
//! unchanged subtrees (the JDK, the compiler jars) cost nothing after the
//! first request.
const builtin = @import("builtin");
const std = @import("std");
const cas = @import("cas.zig");
const protobuf = @import("protobuf_wire.zig");
const reapi = @import("reapi.zig");

pub const max_depth = 128;

pub const Stats = struct {
    directories_synced: u64 = 0,
    directories_skipped: u64 = 0,
    links_written: u64 = 0,
};

pub const Forest = struct {
    /// The forest root (the worker's `/workspace`).
    dir: std.Io.Dir,
    /// Absolute prefix under which `blobs/sha256/...` is reachable both from
    /// the guest and from inside the worker's chroot.
    blob_link_root: []const u8,
    sandbox_uid: u32,
    sandbox_gid: u32,
    mutex: std.Io.Mutex = .init,
    synced: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    stats: Stats = .{},

    pub fn deinit(self: *Forest, allocator: std.mem.Allocator) void {
        self.synced.deinit(allocator);
        self.* = undefined;
    }

    /// Makes every entry of `root_digest` present in the forest.
    pub fn sync(
        self: *Forest,
        io: std.Io,
        allocator: std.mem.Allocator,
        store: cas.Store,
        root_digest: cas.Digest,
        cancellation: ?*const std.atomic.Value(bool),
    ) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        try self.syncDirectory(io, allocator, store, root_digest, "", cancellation, 0);
    }

    fn syncDirectory(
        self: *Forest,
        io: std.Io,
        allocator: std.mem.Allocator,
        store: cas.Store,
        digest: cas.Digest,
        relative: []const u8,
        cancellation: ?*const std.atomic.Value(bool),
        depth: usize,
    ) !void {
        if (depth > max_depth) return error.InputTreeTooDeep;
        if (self.synced.contains(digest.hash)) {
            self.stats.directories_skipped += 1;
            return;
        }
        if (cancellation) |value| {
            if (value.load(.acquire)) return error.ExecutionCancelled;
        }
        const bytes = store.readAlloc(io, allocator, digest) catch |err| switch (err) {
            error.FileNotFound => return error.MissingInputDirectoryBlob,
            else => return err,
        };
        defer allocator.free(bytes);
        var reader = protobuf.Reader.init(bytes);
        var directory = try reapi.Directory.decodeOwned(allocator, &reader);
        defer directory.deinit(allocator);

        for (directory.files) |file| {
            try validateEntryName(file.name);
            const path = try joinPath(allocator, relative, file.name);
            defer allocator.free(path);
            const file_digest = try cas.Digest.fromReapi(file.digest orelse return error.MissingFileDigest);
            var blob_buffer: [cas.blob_path_len]u8 = undefined;
            const blob = cas.blobSubPath(file_digest, &blob_buffer);
            var target_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const target = try std.fmt.bufPrint(&target_buffer, "{s}/{s}", .{ self.blob_link_root, blob });
            try self.ensureSymlink(io, path, target);
        }
        for (directory.symlinks) |symlink| {
            try validateEntryName(symlink.name);
            const path = try joinPath(allocator, relative, symlink.name);
            defer allocator.free(path);
            try self.ensureSymlink(io, path, symlink.target);
        }
        for (directory.directories) |child| {
            try validateEntryName(child.name);
            const path = try joinPath(allocator, relative, child.name);
            defer allocator.free(path);
            try self.ensureDirectory(io, path);
            const child_digest = try cas.Digest.fromReapi(child.digest orelse return error.MissingDirectoryDigest);
            try self.syncDirectory(io, allocator, store, child_digest, path, cancellation, depth + 1);
        }
        try self.synced.put(allocator, digest.hash, {});
        self.stats.directories_synced += 1;
    }

    /// Creates `path` as a directory the sandbox uid can write into, replacing
    /// a stale file or symlink of the same name from an earlier tree shape.
    pub fn ensureDirectory(self: *Forest, io: std.Io, path: []const u8) !void {
        self.dir.createDir(io, path, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {
                const stat = try self.dir.statFile(io, path, .{ .follow_symlinks = false });
                if (stat.kind == .directory) return;
                try self.dir.deleteFile(io, path);
                try self.dir.createDir(io, path, .default_dir);
            },
            else => return err,
        };
        self.chown(path);
    }

    fn ensureSymlink(self: *Forest, io: std.Io, path: []const u8, target: []const u8) !void {
        var link_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        if (self.dir.readLink(io, path, &link_buffer)) |len| {
            if (std.mem.eql(u8, link_buffer[0..len], target)) return;
            try self.dir.deleteFile(io, path);
        } else |err| switch (err) {
            error.FileNotFound => {},
            // A regular file or directory left behind by an earlier tree.
            else => self.dir.deleteTree(io, path) catch {},
        }
        try self.dir.symLink(io, target, path, .{});
        self.stats.links_written += 1;
    }

    fn chown(self: *Forest, path: []const u8) void {
        if (comptime builtin.os.tag != .linux) return;
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path_z = std.fmt.bufPrintZ(&path_buffer, "{s}", .{path}) catch return;
        _ = std.os.linux.fchownat(self.dir.handle, path_z.ptr, self.sandbox_uid, self.sandbox_gid, 0);
    }
};

fn joinPath(allocator: std.mem.Allocator, relative: []const u8, name: []const u8) ![]u8 {
    if (relative.len == 0) return try allocator.dupe(u8, name);
    return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ relative, name });
}

fn validateEntryName(name: []const u8) !void {
    if (name.len == 0 or
        std.mem.indexOfScalar(u8, name, '/') != null or
        std.mem.indexOfScalar(u8, name, 0) != null or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, ".."))
    {
        return error.InvalidDirectoryEntryName;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn putDirectory(store: cas.Store, directory: reapi.Directory) !cas.Digest {
    const bytes = try reapi.encodeAlloc(std.testing.allocator, directory);
    defer std.testing.allocator.free(bytes);
    return try store.putBytes(std.testing.io, bytes);
}

test "Forest.sync mirrors files as CAS symlinks, directories as real directories, and skips synced subtrees" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cas_dir = try tmp.dir.createDirPathOpen(std.testing.io, "cas", .{});
    defer cas_dir.close(std.testing.io);
    const store = cas.Store.init(cas_dir);
    try store.ensureLayout(std.testing.io);
    try tmp.dir.createDirPath(std.testing.io, "workspace");
    var workspace = try tmp.dir.openDir(std.testing.io, "workspace", .{ .iterate = true });
    defer workspace.close(std.testing.io);

    const jar = try store.putBytes(std.testing.io, "jar bytes");
    const source = try store.putBytes(std.testing.io, "fun main() {}");
    var jar_hash: [64]u8 = undefined;
    var source_hash: [64]u8 = undefined;
    const lib = try putDirectory(store, .{ .files = &.{.{ .name = "kotlin-stdlib.jar", .digest = jar.toReapi(&jar_hash) }} });
    var lib_hash: [64]u8 = undefined;
    const external = try putDirectory(store, .{ .directories = &.{.{ .name = "lib", .digest = lib.toReapi(&lib_hash) }} });
    var external_hash: [64]u8 = undefined;
    const src = try putDirectory(store, .{
        .files = &.{.{ .name = "Main.kt", .digest = source.toReapi(&source_hash) }},
        .symlinks = &.{.{ .name = "link.kt", .target = "Main.kt" }},
    });
    var src_hash: [64]u8 = undefined;
    const root = try putDirectory(store, .{ .directories = &.{
        .{ .name = "external", .digest = external.toReapi(&external_hash) },
        .{ .name = "src", .digest = src.toReapi(&src_hash) },
    } });

    var forest = Forest{ .dir = workspace, .blob_link_root = "/cas", .sandbox_uid = 65534, .sandbox_gid = 65534 };
    defer forest.deinit(std.testing.allocator);
    try forest.sync(std.testing.io, std.testing.allocator, store, root, null);

    var link_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var blob_buffer: [cas.blob_path_len]u8 = undefined;
    var expected_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const len = try workspace.readLink(std.testing.io, "external/lib/kotlin-stdlib.jar", &link_buffer);
    try std.testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected_buffer, "/cas/{s}", .{cas.blobSubPath(jar, &blob_buffer)}),
        link_buffer[0..len],
    );
    const symlink_len = try workspace.readLink(std.testing.io, "src/link.kt", &link_buffer);
    try std.testing.expectEqualStrings("Main.kt", link_buffer[0..symlink_len]);
    try std.testing.expectEqual(std.Io.File.Kind.directory, (try workspace.statFile(std.testing.io, "src", .{ .follow_symlinks = false })).kind);
    try std.testing.expectEqual(@as(u64, 4), forest.stats.directories_synced);
    try std.testing.expectEqual(@as(u64, 3), forest.stats.links_written);

    // A second request with the same external/ subtree and a changed source:
    // external/ is skipped by digest, the source link is re-pointed, and a
    // file that became a directory is replaced.
    const source2 = try store.putBytes(std.testing.io, "fun main() { println() }");
    var source2_hash: [64]u8 = undefined;
    const main_dir = try putDirectory(store, .{});
    var main_dir_hash: [64]u8 = undefined;
    const src2 = try putDirectory(store, .{
        .files = &.{.{ .name = "Other.kt", .digest = source2.toReapi(&source2_hash) }},
        .directories = &.{.{ .name = "link.kt", .digest = main_dir.toReapi(&main_dir_hash) }},
    });
    var src2_hash: [64]u8 = undefined;
    const root2 = try putDirectory(store, .{ .directories = &.{
        .{ .name = "external", .digest = external.toReapi(&external_hash) },
        .{ .name = "src", .digest = src2.toReapi(&src2_hash) },
    } });
    try forest.sync(std.testing.io, std.testing.allocator, store, root2, null);
    try std.testing.expectEqual(@as(u64, 1), forest.stats.directories_skipped);
    try std.testing.expectEqual(std.Io.File.Kind.directory, (try workspace.statFile(std.testing.io, "src/link.kt", .{ .follow_symlinks = false })).kind);
    _ = try workspace.readLink(std.testing.io, "src/Other.kt", &link_buffer);
    // The superset keeps earlier entries, like Bazel's execroot does.
    _ = try workspace.readLink(std.testing.io, "src/Main.kt", &link_buffer);

    // Re-syncing an already synced root is a no-op.
    try forest.sync(std.testing.io, std.testing.allocator, store, root2, null);
    try std.testing.expectEqual(@as(u64, 2), forest.stats.directories_skipped);
}

test "Forest.sync rejects missing blobs, bad names and cancellation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cas_dir = try tmp.dir.createDirPathOpen(std.testing.io, "cas", .{});
    defer cas_dir.close(std.testing.io);
    const store = cas.Store.init(cas_dir);
    try store.ensureLayout(std.testing.io);
    try tmp.dir.createDirPath(std.testing.io, "workspace");
    var workspace = try tmp.dir.openDir(std.testing.io, "workspace", .{ .iterate = true });
    defer workspace.close(std.testing.io);
    var forest = Forest{ .dir = workspace, .blob_link_root = "/cas", .sandbox_uid = 65534, .sandbox_gid = 65534 };
    defer forest.deinit(std.testing.allocator);

    try std.testing.expectError(error.MissingInputDirectoryBlob, forest.sync(std.testing.io, std.testing.allocator, store, cas.Digest.fromBytes("absent"), null));
    const blob = try store.putBytes(std.testing.io, "x");
    var blob_hash: [64]u8 = undefined;
    const bad = try putDirectory(store, .{ .files = &.{.{ .name = "../escape", .digest = blob.toReapi(&blob_hash) }} });
    try std.testing.expectError(error.InvalidDirectoryEntryName, forest.sync(std.testing.io, std.testing.allocator, store, bad, null));
    var cancelled = std.atomic.Value(bool).init(true);
    const fine = try putDirectory(store, .{ .files = &.{.{ .name = "ok", .digest = blob.toReapi(&blob_hash) }} });
    try std.testing.expectError(error.ExecutionCancelled, forest.sync(std.testing.io, std.testing.allocator, store, fine, &cancelled));
}
