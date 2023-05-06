const builtin = @import("builtin");
const std = @import("std");

const mem = std.mem;
const log = std.log;
const process = std.process;

const teavpn = @import("teavpn.zig");
const Config = @import("Config.zig");
const util = @import("util.zig");

const stdout = util.stdout;

var g_udp: *teavpn.Udp = undefined;
var real_buffer: [1024 * 1024]u8 = undefined;

fn help(app_name: [*:0]const u8) void {
    stdout.print(
        \\TeaVPN Client - Unofficial
        \\
        \\Usage: {s} [CONFIG]
        \\Example:
        \\  {s} ~/config.fc
        \\
    ,
        .{ app_name, app_name },
    );
}

fn runUdp(allocator: mem.Allocator, config: *const Config) !void {
    var udp = teavpn.Udp.init(allocator, config);
    defer udp.deinit();

    g_udp = &udp;
    try util.setSignalHandler(signalHandler);

    return udp.run();
}

fn signalHandler(sig: c_int) callconv(.C) void {
    util.stdout.write("\n");
    log.info("signalHandler: signal number: {}", .{sig});
    g_udp.stop();
}

pub fn main() !void {
    var buffer = std.heap.FixedBufferAllocator.init(&real_buffer);
    const alloca = buffer.allocator();

    var args = try process.argsAlloc(alloca);
    if (args.len != 2) {
        help(args[0]);
        return error.InvalidArgument;
    }

    var config: Config = undefined;
    try config.load(args[1]);

    log.info("Running...", .{});
    config.dump();

    buffer.reset();
    return switch (config.socket.type_) {
        .UDP => runUdp(alloca, &config),
        else => unreachable,
    };
}
