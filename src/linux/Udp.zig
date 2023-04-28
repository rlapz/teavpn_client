const std = @import("std");
const mem = std.mem;
const os = std.os;
const log = std.log;

const packet = @import("../packet.zig");
const snet = @import("../net.zig");
const util = @import("../util.zig");
const Config = @import("../Config.zig");

const Packet = packet.Packet;
const ver = Config.version;

const Udp = @This();
allocator: mem.Allocator,
config: *const Config,
is_alive: bool,
state: State,
sock_fd: os.socket_t,
tun_fd: os.socket_t,
packet: extern union {
    pkt: Packet,
    raw: [Packet.size]u8,
},

const State = enum {
    handshake,
    auth,
    tun_data,
    failed,
    finish,
};

pub fn init(allocator: mem.Allocator, config: *const Config) Udp {
    return .{
        .allocator = allocator,
        .config = config,
        .is_alive = false,
        .state = .handshake,
        .sock_fd = undefined,
        .tun_fd = undefined,
        .packet = undefined,
    };
}

pub fn deinit(self: *Udp) void {
    self.* = undefined;
}

pub fn run(self: *Udp) !void {
    const cfg = self.config;
    const saddr = cfg.socket.getServerAddr();
    const sport = cfg.socket.server_port;
    const devn = cfg.iface.getDev();

    log.info("connecting to: {s}:{}...", .{ saddr, sport });
    self.sock_fd = try snet.udp.connect(self.allocator, saddr, sport);
    defer os.close(self.sock_fd);

    log.info("creating virtual network interface: {s}...", .{devn});
    //self.tun_fd = try snet.tun.create("/dev/net/tun", devn);
    //defer os.close(self.tun_fd);

    self.is_alive = true;
    return self.handleState();
}

pub fn stop(self: *Udp) void {
    self.is_alive = false;
    os.shutdown(self.sock_fd, .both) catch {};
}

// private
inline fn handleState(self: *Udp) !void {
    defer log.info("stopped!", .{});

    while (self.is_alive) {
        self.state = switch (self.state) {
            .handshake => self.stateHandshake(),
            .auth => self.stateAuth(),
            .tun_data => self.stateTunData(),
            .finish => break, // success
            .failed => return error.ErrorOccured,
        };
    }
}

fn stateHandshake(self: *Udp) State {
    log.info("preparing handshake packet...", .{});
    const pkt = &self.packet.pkt;
    const raw = &self.packet.raw;
    var buffer: [1024]u8 = undefined;

    // send "close" packet, cleaning up stale connection(s)
    pkt.set(.close, 0);
    var sz = snet.udp.sendTo(self.sock_fd, raw[0..Packet.header_size]) catch |err| {
        log.err("failed to send `close` packet: {s}", .{@errorName(err)});
        return .failed;
    };

    log.info("sent bytes: {}", .{sz});

    // send "handshake" packet
    const hnsk = &pkt.body.handshake;
    const vers = &hnsk.version;
    vers.major = ver.major;
    vers.patch = ver.patch;
    vers.sub = ver.sub;
    vers.setExtra(ver.extra) catch |err| {
        log.err("failed to set packet version: {s}", .{@errorName(err)});
        return .failed;
    };
    pkt.set(.handshake, packet.Handshake.size);

    log.info("request version: {s}", .{vers.toStr(&buffer)});

    log.info("sending handshake packet...", .{});
    const hsnk_size = Packet.header_size + packet.Handshake.size;
    sz = snet.udp.sendTo(self.sock_fd, raw[0..hsnk_size]) catch |err| {
        log.err("failed to send `handshake` packet: {s}", .{@errorName(err)});
        return .failed;
    };

    log.info("sent bytes: {}", .{sz});

    // recv "handshake" packet
    log.info("receiving handshake packet...", .{});
    sz = snet.udp.recvFrom(self.sock_fd, raw) catch |err| {
        log.err("failed to recv `handshake` packet: {s}", .{@errorName(err)});
        return .failed;
    };

    log.info("received bytes: {}", .{sz});
    self.handshakeResponse() catch |err| {
        log.err("resp: {s}", .{@errorName(err)});
        return .failed;
    };

    return .auth;
}

fn handshakeResponse(self: *Udp) !void {
    const pkt = &self.packet.pkt;
    const hnsk = &pkt.body.handshake;
    var buffer: [1024]u8 = undefined;

    switch (pkt.code) {
        .handshake => brk: {
            const rsp_len = pkt.getBodyLen();
            if (rsp_len != packet.Handshake.size) {
                log.err("invalid response packet body length: {}:{}", .{
                    rsp_len,
                    packet.Handshake.size,
                });
                break :brk;
            }

            log.info("handshake response: server version: {s}", .{
                hnsk.version.toStr(&buffer),
            });

            const vers = &hnsk.version;
            if ((vers.major != ver.major) or (vers.patch != ver.patch) or
                (vers.sub != ver.sub))
            {
                log.err("server version is not supported for this client", .{});
                return error.InvalidPacketVersion;
            }

            // success
            return;
        },
        .handshake_reject => {
            log.err("server rejected the handshake request: {s}", .{
                pkt.body.handshake_reject.toStr(&buffer),
            });
            return error.HandshakeRejected;
        },
        .close => {
            log.err("server closed the connection", .{});
            return error.ClosedConnection;
        },
        else => {},
    }

    return error.InvalidResponse;
}

fn stateAuth(self: *Udp) State {
    log.info("preparing auth packet...", .{});

    const pkt = &self.packet.pkt;
    const raw = &self.packet.raw;
    const body = &pkt.body;

    // send "auth" packet
    const auth = &body.auth;
    const cfg = &self.config.auth;
    auth.set(cfg.getUsername(), cfg.getPassword()) catch |err| {
        log.err("failed to prepare auth packet: {s}", .{@errorName(err)});
        return .failed;
    };
    pkt.set(.auth, packet.Auth.size);

    log.info("sending auth packet...", .{});
    const auth_size = Packet.header_size + packet.Auth.size;
    var sz = snet.udp.sendTo(self.sock_fd, raw[0..auth_size]) catch |err| {
        log.err("failed to send auth packet: {s}", .{@errorName(err)});
        return .failed;
    };

    log.info("sent bytes: {}", .{sz});

    log.info("receiving auth response packet...", .{});
    sz = snet.udp.recvFrom(self.sock_fd, raw) catch |err| {
        log.err("failed to recv `auth` packet: {s}", .{@errorName(err)});
        return .failed;
    };

    log.info("received bytes: {}", .{sz});
    self.authResponse() catch |err| {
        log.err("resp: {s}", .{@errorName(err)});
        return .failed;
    };

    return .tun_data;
}

fn authResponse(self: *Udp) !void {
    const pkt = &self.packet.pkt;
    switch (pkt.code) {
        .auth => brk: {
            const rsp_len = pkt.getBodyLen();
            if (rsp_len != packet.AuthResp.size) {
                log.err("invalid response packet body length: {}:{}", .{
                    rsp_len,
                    packet.AuthResp.size,
                });
                break :brk;
            }

            log.info("authentication success", .{});

            // success
            return;
        },
        .auth_reject => {
            log.err("auth response: wrong username or password", .{});
            return error.AuthRejected;
        },
        .close => {
            log.err("server closed the connection", .{});
            return error.ClosedConnection;
        },
        else => {},
    }

    return error.InvalidResponse;
}

fn stateTunData(self: *Udp) State {
    _ = self;
    return .finish;
}
