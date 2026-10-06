const std = @import("std");
const multibase = @import("multibase.zig");

const period_arg = "--period";
const times_arg_prefix = "--times";
const code_arg = "--code";
const method_arg = "--method";

const Error = error{
    InvalidTimesValue,
    InvalidPeriodValue,
    InvalidMethodValue,
    MissingTimes,
    MissingCode,
    MissingMethod,
};

const BenchConfig = struct {
    period: u64,
    times: u64,
    code: multibase.MultiBaseCodec,
    method: []const u8,
};

const BenchResult = struct {
    name: []const u8,
    method: []const u8,
    period: u64,
    times: u64,
    max_time: i128,
    min_time: i128,
    avg_time: i128,
    data_len: u64,
    pub fn format(self: @This(), writer: *std.Io.Writer) !void {
        // print formated benchmark result
        try writer.print(
            \\Benchmark {s} Results:
            \\=========================================
            \\Name          : {s}
            \\Period        : {d}
            \\Times         : {d}
            \\Max Time (ns) : {d}
            \\Min Time (ns) : {d}
            \\Avg Time (ns) : {d}
            \\Data Length   : {d}
            \\=========================================
            \\
        ,
            .{
                self.method,
                self.name,
                self.period,
                self.times,
                self.max_time,
                self.min_time,
                self.avg_time,
                self.data_len,
            },
        );
    }
};

const Func = struct {
    fn_ptr: *const fn (codec: multibase.MultiBaseCodec, dest: []u8, data: []const u8) void,
    codec: multibase.MultiBaseCodec,
    fn call(self: @This(), dest: []u8, data: []const u8) void {
        self.fn_ptr(self.codec, dest, data);
    }
};

fn call_encode(codec: multibase.MultiBaseCodec, dest: []u8, data: []const u8) void {
    _ = codec.encode(dest, data);
}

fn call_decode(codec: multibase.MultiBaseCodec, dest: []u8, data: []const u8) void {
    _ = codec.decode(dest, data) catch |err| {
        std.debug.print("Error: {}\n", .{err});
    };
}

const bench_data_path = "./test/data/bench_data";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    var buffer: [2048]u8 = undefined;
    const stdout = init.preopens.get("stdout").?.file;
    var out = stdout.writer(io, &buffer);

    const bench_data = try loadBenchData(io, allocator, bench_data_path);
    defer allocator.free(bench_data);

    const config = try parse_args(init.minimal.args);
    var bench_res = try run_bench(io, bench_data, config);
    try bench_res.format(&out.interface);

    try out.interface.flush();
}

fn parse_args(a: std.process.Args) !BenchConfig {
    var period: u64 = 10;
    var times: u64 = 1_000_000;
    var code: ?multibase.MultiBaseCodec = null;
    var method: []const u8 = "encode";

    var iter = a.iterate();
    _ = iter.skip();

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, times_arg_prefix)) {
            const value = iter.next().?;
            times = try handle_times(value);
        } else if (std.mem.startsWith(u8, arg, times_arg_prefix)) {
            const value = arg[times_arg_prefix.len + 1 ..];
            times = try handle_times(value);
        } else if (std.mem.eql(u8, arg, period_arg)) {
            const value = iter.next().?;
            period = try handle_period(value);
        } else if (std.mem.startsWith(u8, arg, period_arg)) {
            const value = arg[period_arg.len + 1 ..];
            period = try handle_period(value);
        } else if (std.mem.eql(u8, arg, code_arg)) {
            const value = iter.next().?;
            code = try multibase.MultiBaseCodec.fromCode(value);
        } else if (std.mem.startsWith(u8, arg, code_arg)) {
            const value = arg[code_arg.len + 1 ..];
            code = try multibase.MultiBaseCodec.fromCode(value);
        } else if (std.mem.eql(u8, arg, method_arg)) {
            const value = iter.next().?;
            method = try handle_method(value);
        } else if (std.mem.startsWith(u8, arg, method_arg)) {
            const value = arg[method_arg.len + 1 ..];
            method = try handle_method(value);
        }
    }

    if (code == null) return Error.MissingCode;

    return .{
        .period = period,
        .times = times,
        .code = code.?,
        .method = method,
    };
}

fn handle_period(value: []const u8) !u64 {
    const period = try std.fmt.parseUnsigned(u64, value, 10);
    if (period == 0) {
        return Error.InvalidPeriodValue;
    }
    return period;
}

fn handle_times(value: []const u8) !u64 {
    const times = try std.fmt.parseUnsigned(u64, value, 10);
    if (times == 0) {
        return Error.InvalidTimesValue;
    }
    return times;
}

fn handle_method(value: []const u8) ![]const u8 {
    if (std.mem.eql(u8, "encode", value)) {
        return "encode";
    } else if (std.mem.eql(u8, "decode", value)) {
        return "decode";
    } else {
        return Error.InvalidMethodValue;
    }
}

fn run_bench(io: std.Io, bench_data: []const u8, config: BenchConfig) !BenchResult {
    const clock: std.Io.Clock = .real;

    var dest_len = config.code.encodedLen(bench_data);
    var action = Func{
        .fn_ptr = call_encode,
        .codec = config.code,
    };
    var data: []const u8 = bench_data;
    if (std.mem.eql(u8, "decode", config.method)) {
        const encoded_data = try std.heap.page_allocator.alloc(u8, config.code.encodedLen(bench_data));
        data = config.code.encode(encoded_data, bench_data)[1..];
        dest_len = config.code.decodedLen(data);
        action = Func{
            .fn_ptr = call_decode,
            .codec = config.code,
        };
    }
    const dest = try std.heap.page_allocator.alloc(u8, dest_len);
    defer std.heap.page_allocator.free(dest);
    var i: u64 = 0;
    var max_time: i128 = 0;
    var min_time: i128 = 0;
    var time_records = try std.heap.page_allocator.alloc(i128, config.period);
    defer std.heap.page_allocator.free(time_records);
    while (i < config.period) : (i += 1) {
        const start = clock.now(io);
        for (0..config.times) |_| {
            action.call(dest, data);
            // _ = config.code.encode(dest, bench_data);
        }
        const end = clock.now(io);
        const elapsed = start.durationTo(end);
        const elapsed_ns = elapsed.toNanoseconds();
        time_records[i] = elapsed_ns;
        if (elapsed_ns > max_time) {
            max_time = elapsed_ns;
        }
        if (min_time == 0 or elapsed_ns < min_time) {
            min_time = elapsed_ns;
        }
    }

    var sum_time: i128 = 0;
    for (time_records) |time| {
        sum_time += time;
    }
    const avg_time = @divFloor(sum_time, config.period);
    return .{
        .name = config.code.code(),
        .method = config.method,
        .period = config.period,
        .times = config.times,
        .max_time = max_time,
        .min_time = min_time,
        .avg_time = avg_time,
        .data_len = bench_data.len,
    };
}

fn loadBenchData(io: std.Io, allocator: std.mem.Allocator, filePath: []const u8) ![]const u8 {
    const cwd = std.Io.Dir.cwd();

    var file = try cwd.openFile(io, filePath, .{ .mode = .read_only });
    defer file.close(io);

    const stat = try file.stat(io);
    const content = try allocator.alloc(u8, stat.size);

    var buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &buffer);

    try reader.interface.readSliceAll(content);
    return content;
}
