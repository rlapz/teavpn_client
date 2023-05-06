const builtin = @import("builtin");
const std = @import("std");

const assert = std.debug.assert;
const mem = std.mem;
const net = std.net;
const os = std.os;
const linux = os.linux;

const util = @import("util.zig");

const cstr = util.cstr;

const impl = switch (builtin.os.tag) {
    .linux => @import("net/linux.zig"),
    else => @compileError("not supported os"),
};
pub const tun = impl.tun;
// TODO: handle ip routes; toggle
pub const setIpRoute = impl.setIpRoute;

pub const ifacenamesize = os.IFNAMESIZE;
pub const inet4_addrstrlen = os.IFNAMESIZE;

//
// UDP
//
pub const udp = struct {
    pub fn connect(allocator: mem.Allocator, host: []const u8, port: u16) !os.socket_t {
        var addr_list = try net.getAddressList(allocator, host, port);
        defer addr_list.deinit();

        if (addr_list.addrs.len == 0)
            return error.UnknownHostName;

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

    pub fn send(fd: os.socket_t, buffer: []const u8) !usize {
        return os.sendto(fd, buffer, 0, null, 0);
    }

    pub fn recv(fd: os.socket_t, buffer: []u8) !usize {
        return os.recvfrom(fd, buffer, 0, null, null);
    }
};

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

    pub fn setDev(self: *Iff, dev: []const u8) void {
        cstr.copy(&self.dev, ifacenamesize, dev);
    }

    pub fn setIpv4Pub(self: *Iff, addr: []const u8) void {
        cstr.copy(&self.ipv4_pub, inet4_addrstrlen, addr);
    }

    pub fn dump(self: *const Iff) void {
        util.stdout.print(
            \\[IFF]----------------------------------------
            \\"|-> dev:          {s}
            \\"|-> ipv4_pub:     {s}
            \\"|-> ipv4:         {s}
            \\"|-> ipv4_netmask: {s}
            \\"|-> ipv4_gateway: {s}
            \\"`-> ipv4_mtu:     {}
            \\---------------------------------------------
            \\
        , .{
            self.dev,          self.ipv4_pub,
            self.ipv4,         self.ipv4_netmask,
            self.ipv4_gateway, self.ipv4_mtu,
        });
    }

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
