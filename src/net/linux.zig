const std = @import("std");
const mem = std.mem;
const os = std.os;
const linux = os.linux;

const snet = @import("../net.zig");

pub const tun = struct {
    // zig fmt: off
    pub const IFF_TUN         = 0x0001;
    pub const IFF_MULTI_QUEUE = 0x0100;
    pub const IFF_NO_PI       = 0x1000;
    // zig fmt: on

    const TUNSETIFF = linux.IOCTL.IOW('T', 202, c_int);

    pub fn create(path: []const u8, name: []const u8, flags: i16) !os.fd_t {
        if (name.len >= os.IFNAMESIZE)
            return error.TunNameTooLong;

        var ifreq: linux.ifreq = undefined;
        const fd = try os.open(path, os.O.RDWR, 0);

        @memset(@ptrCast([*]u8, &ifreq), 0, @sizeOf(linux.ifreq));
        mem.copy(u8, &ifreq.ifrn.name, name);
        ifreq.ifru.flags = flags;

        const ioc = linux.ioctl(fd, TUNSETIFF, @ptrToInt(&ifreq));
        switch (os.errno(ioc)) {
            .SUCCESS => return fd,
            .PERM => return error.AccessDenied,
            .BUSY => return error.DeviceBusy,
            .BADF => unreachable,
            .FAULT => unreachable,
            .NOTTY => unreachable,
            .INVAL => unreachable,
            else => |err| return os.unexpectedErrno(err),
        }
    }
};

//
// Copied from: https://github.com/teainside/teavpn2/src/teavpn2/linux/iface.c
//
pub fn setIpRoute(iff: *const snet.Iff) !void {
    // test
    const cmd = "/usr/sbin/ip";
    _ = cmd;
    _ = iff;
}
