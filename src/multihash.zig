const std = @import("std");
const Multicodec = @import("multicodec.zig").Multicodec;
const testing = std.testing;

const Io = std.Io;

/// Multihash is a wrapper around a digest and a code.
/// S is larger or equal to the size of the digest.
pub fn Multihash(comptime S: usize) type {
    return struct {
        code: Multicodec,
        size: u8,
        digest: [S]u8,

        const Self = @This();

        /// wrap creates a new Multihash from a given code and digest.
        pub fn wrap(code: Multicodec, input_digest: []const u8) !Self {
            if (input_digest.len > S) {
                return error.InvalidSize;
            }

            var digest: [S]u8 = @splat(0);
            @memcpy(digest[0..input_digest.len], input_digest[0..input_digest.len]); // Specify exact length

            return Self{
                .code = code,
                .size = @intCast(input_digest.len),
                .digest = digest,
            };
        }

        /// getCode returns the code of the Multihash.
        pub fn getCode(self: *const Self) Multicodec {
            return self.code;
        }

        /// getSize returns the size of the Multihash.
        pub fn getSize(self: *const Self) u8 {
            return self.size;
        }

        /// getDigest returns the digest of the Multihash.
        pub fn getDigest(self: *const Self) []const u8 {
            return self.digest[0..self.size];
        }

        /// truncate creates a new Multihash with a truncated digest.
        pub fn truncate(self: *const Self, new_size: u8) Self {
            return Self{
                .code = self.code,
                .size = @min(self.size, new_size),
                .digest = self.digest,
            };
        }

        /// resize creates a new Multihash with a resized digest.
        pub fn resize(self: *const Self, comptime R: usize) !Multihash(R) {
            if (self.size > R) {
                return error.InvalidSize;
            }

            var new_digest: [R]u8 = @splat(0);
            @memcpy(new_digest[0..self.size], self.digest[0..self.size]);

            return Multihash(R){
                .code = self.code,
                .size = self.size,
                .digest = new_digest,
            };
        }

        pub fn encodedLen(self: *const Self) usize {
            var buf: [64]u8 = undefined;
            var discard: Io.Writer.Discarding = .init(&buf);
            try self.write(&discard.writer);
            return discard.fullCount();
        }

        /// write writes the Multihash to a writer.
        pub fn write(self: *const Self, writer: *Io.Writer) !void {
            try writer.writeLeb128(self.code.getCode());
            try writer.writeLeb128(self.size);
            try writer.writeAll(self.getDigest());
        }

        /// readBytes reads a Multihash from a byte slice.
        pub fn readBytes(bytes: []const u8) !Self {
            var fixed: Io.Reader = .fixed(bytes);
            return try Self.read(&fixed);
        }

        /// read reads a Multihash from a reader.
        pub fn read(reader: *Io.Reader) !Self {
            const code = try reader.takeLeb128(u64);
            const size = try reader.takeLeb128(u8);

            if (size > S) {
                return error.InvalidSize;
            }

            var digest: [S]u8 = @splat(0);
            try reader.readSliceAll(digest[0..size]);

            return Self{
                .code = try Multicodec.fromCode(code),
                .size = size,
                .digest = digest,
            };
        }

        /// toBytes converts the Multihash to a byte slice.
        pub fn toBytes(self: *const Self, dest: []u8) ![]const u8 {
            var fixed: Io.Writer = .fixed(dest);
            try self.write(&fixed);
            return fixed.buffered();
        }
    };
}

/// MultihashDigest is a generic type that can be used to create a Multihash from a given input.
pub fn MultihashDigest(comptime T: type) type {
    const DigestSize = struct {
        fn getSize(comptime code: T) comptime_int {
            return switch (code) {
                .SHA2_256 => 32,
                .SHA2_512 => 64,
                .SHA3_224 => 28,
                .SHA3_256 => 32,
                .SHA3_384 => 48,
                .SHA3_512 => 64,
                .KECCAK_224 => 28,
                .KECCAK_256 => 32,
                .KECCAK_384 => 48,
                .KECCAK_512 => 64,
                .BLAKE2B_256 => 32,
                .BLAKE2B_512 => 64,
                .BLAKE2S_128 => 16,
                .BLAKE2S_256 => 32,
                .BLAKE3 => 64,
            };
        }
    };

    return struct {
        /// digest creates a new Multihash from the given input.
        pub fn digest(comptime code: T, input: []const u8) !Multihash(DigestSize.getSize(code)) {
            var hasher = Hasher.init(code);
            try hasher.update(input);
            return switch (hasher) {
                inline else => |*h| blk: {
                    const digest_bytes = h.finalize();
                    break :blk try Multihash(DigestSize.getSize(code)).wrap(try Multicodec.fromCode(@backingInt(code)), &digest_bytes);
                },
            };
        }
    };
}

/// Multihash is a generic type that can be used to create a Multihash from a given input.
pub const Hasher = union(enum) {
    sha2_256: Sha2_256,
    sha2_512: Sha2_512,
    sha3_224: Sha3_224,
    sha3_256: Sha3_256,
    sha3_384: Sha3_384,
    sha3_512: Sha3_512,
    keccak_224: Keccak_224,
    keccak_256: Keccak_256,
    keccak_384: Keccak_384,
    keccak_512: Keccak_512,
    blake2b256: Blake2b256,
    blake2b512: Blake2b512,
    blake2s128: Blake2s128,
    blake2s256: Blake2s256,
    blake3: Blake3,

    /// init initializes a new Hasher.
    pub fn init(code: MultihashCodecs) Hasher {
        return switch (code) {
            .SHA2_256 => .{ .sha2_256 = Sha2_256.init() },
            .SHA2_512 => .{ .sha2_512 = Sha2_512.init() },
            .SHA3_224 => .{ .sha3_224 = Sha3_224.init() },
            .SHA3_256 => .{ .sha3_256 = Sha3_256.init() },
            .SHA3_384 => .{ .sha3_384 = Sha3_384.init() },
            .SHA3_512 => .{ .sha3_512 = Sha3_512.init() },
            .KECCAK_224 => .{ .keccak_224 = Keccak_224.init() },
            .KECCAK_256 => .{ .keccak_256 = Keccak_256.init() },
            .KECCAK_384 => .{ .keccak_384 = Keccak_384.init() },
            .KECCAK_512 => .{ .keccak_512 = Keccak_512.init() },
            .BLAKE2B_256 => .{ .blake2b256 = Blake2b256.init() },
            .BLAKE2B_512 => .{ .blake2b512 = Blake2b512.init() },
            .BLAKE2S_128 => .{ .blake2s128 = Blake2s128.init() },
            .BLAKE2S_256 => .{ .blake2s256 = Blake2s256.init() },
            .BLAKE3 => .{ .blake3 = Blake3.init() },
        };
    }

    /// update updates the Hasher with the given data.
    pub fn update(self: *Hasher, data: []const u8) !void {
        switch (self.*) {
            inline else => |*h| try h.update(data),
        }
    }
};

/// MultihashCodecs is an enum that represents the different multihash codecs.
/// It is used to implement the MultihashDigest trait for all multihash digests.
pub const MultihashCodecs = enum(u64) {
    SHA2_256 = Multicodec.SHA2_256.getCode(),
    SHA2_512 = Multicodec.SHA2_512.getCode(),
    SHA3_224 = Multicodec.SHA3_224.getCode(),
    SHA3_256 = Multicodec.SHA3_256.getCode(),
    SHA3_384 = Multicodec.SHA3_384.getCode(),
    SHA3_512 = Multicodec.SHA3_512.getCode(),
    KECCAK_256 = Multicodec.KECCAK_256.getCode(),
    KECCAK_512 = Multicodec.KECCAK_512.getCode(),
    KECCAK_224 = Multicodec.KECCAK_224.getCode(),
    KECCAK_384 = Multicodec.KECCAK_384.getCode(),
    BLAKE2B_256 = Multicodec.BLAKE2B_256.getCode(),
    BLAKE2B_512 = Multicodec.BLAKE2B_512.getCode(),
    BLAKE2S_128 = Multicodec.BLAKE2S_128.getCode(),
    BLAKE2S_256 = Multicodec.BLAKE2S_256.getCode(),
    BLAKE3 = Multicodec.BLAKE3.getCode(),

    pub fn getSize(comptime c: MultihashCodecs) comptime_int {
        return switch (c) {
            .BLAKE3 => return Blake3.SIZE,
            .BLAKE2S_256 => return Blake2s256.SIZE,
            .BLAKE2S_128 => return Blake2s128.SIZE,
            .BLAKE2B_512 => return Blake2b512.SIZE,
            .BLAKE2B_256 => return Blake2b256.SIZE,
            .KECCAK_384 => return Keccak_384.SIZE,
            .KECCAK_224 => return Keccak_224.SIZE,
            .KECCAK_512 => return Keccak_512.SIZE,
            .KECCAK_256 => return Keccak_256.SIZE,
            .SHA3_512 => return Sha3_512.SIZE,
            .SHA3_384 => return Sha3_384.SIZE,
            .SHA3_256 => return Sha3_256.SIZE,
            .SHA3_224 => return Sha3_224.SIZE,
            .SHA2_512 => return Sha2_512.SIZE,
            .SHA2_256 => return Sha2_256.SIZE,
        };
    }

    /// digest creates a new Multihash from the given input.
    pub fn digest(comptime code: MultihashCodecs, input: []const u8) !Multihash(code.getSize()) {
        var hasher = Hasher.init(code);
        try hasher.update(input);
        return switch (hasher) {
            inline else => |*h| blk: {
                const digest_bytes = h.finalize();
                const inner = try Multicodec.fromCode(@backingInt(code));
                break :blk try Multihash(code.getSize()).wrap(inner, &digest_bytes);
            },
        };
    }
};

fn StdWrapper(comptime H: type) type {
    return StdWrapper2(H, H.digest_length);
}
/// Implements the MultihashDigest trait for any std hash algorithm
fn StdWrapper2(comptime H: type, comptime S: usize) type {
    return struct {
        const Self = @This();
        pub const Hasher = H;
        pub const SIZE = S;

        ctx: H,

        pub fn init() Self {
            return .{ .ctx = .init(.{}) };
        }

        pub fn update(this: *Self, data: []const u8) !void {
            this.ctx.update(data);
        }

        pub fn finalize(this: *Self) [S]u8 {
            if (comptime @hasDecl(H, "finalResult")) {
                return this.ctx.finalResult();
            }

            if (comptime @hasDecl(H, "final")) {
                var out: [S]u8 = @splat(0);
                this.ctx.final(&out);
                return out;
            }

            comptime unreachable;
        }
    };
}

pub const Sha2_256 = StdWrapper(std.crypto.hash.sha2.Sha256);
pub const Sha2_512 = StdWrapper(std.crypto.hash.sha2.Sha512);
pub const Sha3_224 = StdWrapper(std.crypto.hash.sha3.Sha3_224);
pub const Sha3_256 = StdWrapper(std.crypto.hash.sha3.Sha3_256);
pub const Sha3_384 = StdWrapper(std.crypto.hash.sha3.Sha3_384);
pub const Sha3_512 = StdWrapper(std.crypto.hash.sha3.Sha3_512);
pub const Keccak_224 = StdWrapper(std.crypto.hash.sha3.Keccak(1600, 224, 0x01, 24));
pub const Keccak_256 = StdWrapper(std.crypto.hash.sha3.Keccak256);
pub const Keccak_384 = StdWrapper(std.crypto.hash.sha3.Keccak(1600, 384, 0x01, 24));
pub const Keccak_512 = StdWrapper(std.crypto.hash.sha3.Keccak512);
pub const Blake2b256 = StdWrapper(std.crypto.hash.blake2.Blake2b256);
pub const Blake2b512 = StdWrapper(std.crypto.hash.blake2.Blake2b512);
pub const Blake2s128 = StdWrapper(std.crypto.hash.blake2.Blake2s128);
pub const Blake2s256 = StdWrapper(std.crypto.hash.blake2.Blake2s256);
pub const Blake3 = StdWrapper(std.crypto.hash.Blake3);

test "basic multihash operations" {
    const expected_digest = [_]u8{
        0xB9, 0x4D, 0x27, 0xB9, 0x93, 0x4D, 0x3E, 0x08,
        0xA5, 0x2E, 0x52, 0xD7, 0xDA, 0x7D, 0xAB, 0xFA,
        0xC4, 0x84, 0xEF, 0xE3, 0x7A, 0x53, 0x80, 0xEE,
        0x90, 0x88, 0xF7, 0xAC, 0xE2, 0xEF, 0xCD, 0xE9,
    };

    var mh = try Multihash(32).wrap(Multicodec.SHA2_256, &expected_digest);
    try testing.expectEqual(mh.getCode(), Multicodec.SHA2_256);
    try testing.expectEqual(mh.getSize(), expected_digest.len);
    try testing.expectEqualSlices(u8, mh.getDigest(), &expected_digest);
}
test "multihash resize" {
    const input = "test data";
    var mh = try Multihash(32).wrap(Multicodec.CIDV1, input);

    // Resize up
    var larger = try mh.resize(64);
    try testing.expectEqual(larger.getSize(), input.len);
    try testing.expectEqualSlices(u8, larger.getDigest(), input);

    // Resize down should fail
    try testing.expectError(error.InvalidSize, mh.resize(4));
}

test "multihash serialization" {
    const expected_bytes = [_]u8{ 0x12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var mh = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

    var buf: [100]u8 = undefined;
    var fixed: Io.Writer = .fixed(&buf);
    try mh.write(&fixed);
    try testing.expectEqualSlices(u8, fixed.buffered(), &expected_bytes);
}

test "multihash deserialization" {
    const input = [_]u8{ 0x12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

    var fixed: Io.Reader = .fixed(&input);
    var mh = try Multihash(32).read(&fixed);

    try testing.expectEqual(mh.getCode().getCode(), 0x12);
    try testing.expectEqual(mh.getSize(), 10);
    try testing.expectEqualSlices(u8, mh.getDigest(), input[2..]);
}

test "multihash truncate" {
    var mh = try Multihash(32).wrap(Multicodec.CIDV1, "hello world");
    const truncated = mh.truncate(5);
    try testing.expectEqual(truncated.getSize(), 5);
    try testing.expectEqualSlices(u8, truncated.getDigest(), "hello");
}

test "sha256 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.SHA2_256;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x12), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha2.Sha256.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha512 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.SHA2_512;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x13), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha2.Sha512.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_224 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.SHA3_224;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x17), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Sha3_224.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_256 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.SHA3_256;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x16), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Sha3_256.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_384 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.SHA3_384;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x15), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Sha3_384.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "sha3_512 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.SHA3_512;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x14), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Sha3_512.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "keccak_224 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.KECCAK_224;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x1a), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Keccak(1600, 224, 0x01, 24).init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "keccak_256 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.KECCAK_256;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x1b), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Keccak256.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "keccak_384 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.KECCAK_384;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x1c), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Keccak(1600, 384, 0x01, 24).init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "keccak_512 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.KECCAK_512;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x1d), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.sha3.Keccak512.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "blake2b_256 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.BLAKE2B_256;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0xb220), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.blake2.Blake2b256.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "blake2b_512 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.BLAKE2B_512;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0xb240), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.blake2.Blake2b512.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "blake2s_128 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.BLAKE2S_128;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0xb250), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.blake2.Blake2s128.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "blake2s_256 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.BLAKE2S_256;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0xb260), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.blake2.Blake2s256.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "blake3 hash operations" {
    const input = "hello world";
    const codec = MultihashCodecs.BLAKE3;
    const hash = try codec.digest(input);
    try testing.expectEqual(@as(u64, 0x1e), hash.code.getCode());
    var out: [codec.getSize()]u8 = undefined;

    var hash1 = std.crypto.hash.Blake3.init(.{});
    hash1.update(input);
    hash1.final(&out);
    try testing.expectEqualSlices(u8, &out, hash.getDigest());
}

test "multihash readBytes" {
    const input = [_]u8{ 0x12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var mh = try Multihash(32).readBytes(&input);

    try testing.expectEqual(mh.getCode().getCode(), 0x12);
    try testing.expectEqual(mh.getSize(), 10);
    try testing.expectEqualSlices(u8, mh.getDigest(), input[2..]);
}

test "multihash toBytes" {
    const expected_bytes = [_]u8{ 0x12, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var mh = try Multihash(32).wrap(Multicodec.SHA2_256, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

    var buf: [100]u8 = undefined;
    const bytes = try mh.toBytes(buf[0..]);
    try testing.expectEqualSlices(u8, bytes, &expected_bytes);
}
