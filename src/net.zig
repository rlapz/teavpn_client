const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const net = std.net;
const os = std.os;
const linux = os.linux;

const impl = switch (builtin.os.tag) {
    .linux => @import("linux/net.zig"),
    else => @compileError("not supported os"),
};
pub const tun = impl.tun;
pub const spipe = impl.spipe;

pub const ifacenamesize = 16;
pub const inet4_addrstrlen = 16;

pub const Iff = extern struct {
    // zig fmt: off
    dev:          [ifacenamesize]u8,
    ipv4_pub:     [inet4_addrstrlen]u8,
    ipv4:         [inet4_addrstrlen]u8,
    ipv4_netmask: [inet4_addrstrlen]u8,
    ipv4_gateway: [inet4_addrstrlen]u8,
    ipv4_mtu:     u16,
    // zig fmt: on

    pub const size = @sizeOf(Iff);
    comptime {
        assert(@offsetOf(Iff, "dev") == 0);
        assert(@offsetOf(Iff, "ipv4_pub") == 16);
        assert(@offsetOf(Iff, "ipv4") == 32);
        assert(@offsetOf(Iff, "ipv4_netmask") == 48);
        assert(@offsetOf(Iff, "ipv4_gateway") == 64);
        assert(@offsetOf(Iff, "ipv4_mtu") == 80);
        assert(size == ifacenamesize + (inet4_addrstrlen * 4) + 2); // 82
    }
};

//
// UDP
//
pub const udp = struct {
    pub fn connect(allocator: mem.Allocator, host: []const u8, port: u16) !os.socket_t {
        var addr_list = try net.getAddressList(allocator, host, port);
        defer addr_list.deinit();

        if (addr_list.addrs.len == 0)
            return error.UnknownHostName;

        //const flags = os.SOCK.DGRAM | os.SOCK.NONBLOCK;
        const flags = os.SOCK.DGRAM;
        for (addr_list.addrs) |v| {
            const fd = os.socket(v.any.family, flags, os.IPPROTO.UDP) catch
                continue;

            os.connect(fd, &v.any, v.getOsSockLen()) catch {
                os.close(fd);
                continue;
            };

            // success
            return fd;
        }

        return error.ConnectionRefused;
    }

    pub fn sendTo(fd: os.socket_t, buffer: []const u8) !usize {
        return os.sendto(fd, buffer, 0, null, 0);
    }

    pub fn recvFrom(fd: os.socket_t, buffer: []u8) !usize {
        return os.recvfrom(fd, buffer, 0, null, null);
    }
};

test "Iff" {
    _ = Iff;
}

test "udp.connect" {
    const fd = try udp.connect(std.testing.allocator, "127.0.0.1", 80);
    defer os.close(fd);
}

const time = std.time;
test "tun" {
    const fd = try tun.create("/dev/net/tun", "test_tun0");
    defer os.close(fd);

    time.sleep(time.ns_per_s * 3);
}
