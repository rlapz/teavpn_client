const std = @import("std");
const mem = std.mem;
const os = std.os;
const linux = os.linux;

pub const tun = struct {
    const TUNSETIFF = linux.IOCTL.IOW('T', 202, c_int);
    const IFF_TUN = 0x0001;
    const IFF_NO_PI = 0x1000;

    pub fn create(path: []const u8, name: []const u8) !os.fd_t {
        if (name.len >= os.IFNAMESIZE)
            return error.TunNameTooLong;

        var ifreq: linux.ifreq = undefined;
        const fd = try os.open(path, os.O.RDWR, 0);

        @memset(@ptrCast([*]u8, &ifreq), 0, @sizeOf(linux.ifreq));
        mem.copy(u8, &ifreq.ifrn.name, name);
        ifreq.ifru.flags = IFF_TUN | IFF_NO_PI;

        const ioc = linux.ioctl(fd, TUNSETIFF, @ptrToInt(&ifreq));
        switch (os.errno(ioc)) {
            .SUCCESS => return fd,
            .PERM => return error.AccessDenied,
            .BADF => unreachable,
            .FAULT => unreachable,
            .NOTTY => unreachable,
            .INVAL => unreachable,
            else => |err| return os.unexpectedErrno(err),
        }
    }
};

pub fn splice(in: os.fd_t, out: os.fd_t, size: usize, flags: u32) !usize {
    const rc = linux.syscall6(
        .splice,
        @bitCast(usize, @as(isize, in)),
        0,
        @bitCast(usize, @as(isize, out)),
        0,
        size,
        flags,
    );

    switch (os.errno(rc)) {
        .SUCCESS => return rc,
        .AGAIN => return error.WouldBlock,
        .CONNRESET => return error.ConnectionResetByPeer,
        .BADF => unreachable,
        .INVAL => unreachable,
        .NOMEM => unreachable,
        .SPIPE => unreachable,
        else => |err| return os.unexpectedErrno(err),
    }
}

pub fn spipe(in: os.fd_t, out: os.fd_t, pipe: [*]const os.fd_t, size: usize) !void {
    const flags = 0x1 | 0x2; // MOVE | NONBLOCK
    var rd = try splice(in, pipe[1], size, flags);
    if (rd == 0)
        return error.EndOfFile;

    while (rd > 0) {
        const wr = try splice(pipe[0], out, rd, flags);
        if (wr == 0)
            return error.EndOfFile;

        rd -= wr;
    }
}
