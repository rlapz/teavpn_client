const std = @import("std");
const mem = std.mem;
const os = std.os;
const SIG = os.SIG;

pub const signalHandlerFn = fn (c_int) callconv(.C) void;

pub fn setSignalHandler(handler: *const signalHandlerFn) !void {
    var act = mem.zeroInit(os.Sigaction, .{
        .handler = .{ .handler = SIG.IGN },
    });

    try os.sigaction(SIG.PIPE, &act, null);

    act.handler = .{ .handler = handler };
    try os.sigaction(SIG.TERM, &act, null);
    try os.sigaction(SIG.INT, &act, null);
    try os.sigaction(SIG.HUP, &act, null);
}

pub fn setNonBlockingFd(fd: os.fd_t) !void {
    const fl = try os.fcntl(fd, os.F.GETFL, 0);
    _ = try os.fcntl(fd, os.F.SETFL, fl | os.O.NONBLOCK);
}
