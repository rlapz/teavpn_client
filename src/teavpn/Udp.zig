const std = @import("std");

const fmt = std.fmt;
const mem = std.mem;
const os = std.os;
const log = std.log;
const time = std.time;

const packet = @import("../packet.zig");
const snet = @import("../net.zig");
const util = @import("../util.zig");
const Config = @import("../Config.zig");
const EvLoopUdp = @import("EvLoopUdp.zig");

const bytes = util.bytes;
const tun = snet.tun;
const udp = snet.udp;
const ver = Config.version;

const Packet = packet.Packet;
const Handshake = packet.Handshake;
const HandshakeReject = packet.HandshakeReject;
const Auth = packet.Auth;
const AuthResp = packet.AuthResp;

const timeout = mem.zeroInit(os.timeval, .{ .tv_sec = 15 });

const Udp = @This();
allocator: mem.Allocator,
config: *const Config,
is_interrupted: bool,
is_established: bool,
has_sock_fd: bool,
sock_fd: os.socket_t,
ev_loop: EvLoopUdp,
packet: Packet,

pub fn init(allocator: mem.Allocator, config: *const Config) Udp {
    return .{
        .allocator = allocator,
        .config = config,
        .is_interrupted = false,
        .is_established = false,
        .has_sock_fd = false,
        .sock_fd = undefined,
        .ev_loop = undefined,
        .packet = undefined,
    };
}

pub fn deinit(self: *Udp) void {
    self.* = undefined;
}

pub fn run(self: *Udp) !void {
    const cfg = self.config;
    const dev_name = cfg.iface.getDev();
    log.info("creating virtual network interface: {s}...", .{dev_name});

    const path = cfg.iface.getTunPath();
    const tun_fd = try tun.create(path, dev_name, tun.IFF_TUN | tun.IFF_NO_PI);
    defer os.close(tun_fd);

    while (true) {
        self.runWrp(dev_name, tun_fd) catch |err|
            log.err("disconnected: {}", .{err});

        if (self.is_interrupted or !cfg.sys.auto_reconnect)
            break;

        log.info("reconnecting...", .{});
        time.sleep(time.ns_per_s);
    }
}

pub fn stop(self: *Udp) void {
    if (self.is_established)
        self.ev_loop.stop()
    else if (self.has_sock_fd)
        os.shutdown(self.sock_fd, .both) catch {};

    self.is_interrupted = true;
}

fn runWrp(self: *Udp, dev_name: []const u8, tun_fd: os.fd_t) !void {
    const cfg = self.config;
    const saddr = cfg.socket.getServerAddr();
    const sport = cfg.socket.server_port;

    bytes.reset(&self.packet);

    log.info("connecting to: {s}:{}...", .{ saddr, sport });
    const sfd = try udp.connect(self.allocator, saddr, sport);
    defer {
        self.is_established = false;
        self.has_sock_fd = false;
        os.close(sfd);
    }

    // add timeout
    log.info("add connection timeout: {}s", .{timeout.tv_sec});
    try os.setsockopt(sfd, os.SOL.SOCKET, os.SO.RCVTIMEO, mem.asBytes(&timeout));
    self.sock_fd = sfd;
    self.has_sock_fd = true;

    if (!self.handleHandshake()) {
        if (self.is_interrupted)
            return error.Interrupted;

        return error.HandshakeFailed;
    }

    // loop: handle NOP code, (NOP => returns true)
    while (!self.is_established) {
        if (!self.handleAuth()) {
            if (self.is_interrupted)
                return error.Interrupted;

            return error.AuthFailed;
        }
    }

    log.info("setting up ip routes...", .{});

    var iff = self.packet.body.auth_resp.iff;
    iff.setDev(dev_name);
    if (cfg.iface.override_default)
        iff.setIpv4Pub(saddr);

    iff.dump();

    try snet.setIpRoute(&iff);
    return self.ev_loop.run(self.sock_fd, tun_fd);
}

//
// Handshake handler
//
fn handleHandshake(self: *Udp) bool {
    const fd = self.sock_fd;
    const pkt = &self.packet;
    var buffer: [4096]u8 = undefined;

    // send "close" packet, cleaning up stale connection(s)
    log.info("sending `close` packet... (cleaning up stale connections)", .{});
    var sz = udp.send(fd, pkt.create(.close, 0)) catch |err| {
        log.err("failed to send `close` packet: {}", .{err});
        return false;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return false;

    // send "handshake" packet
    const version = &pkt.body.handshake.version;
    version.set(ver.major, ver.patch, ver.sub, ver.extra);

    log.info("request version: {s}", .{version.toStr(&buffer)});

    log.info("sending `handshake` packet...", .{});
    sz = udp.send(fd, pkt.create(.handshake, Handshake.size)) catch |err| {
        log.err("failed to send `handshake` packet: {}", .{err});
        return false;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return false;

    // recv "handshake" packet
    log.debug("receiving `handshake` packet...", .{});
    sz = udp.recv(fd, mem.asBytes(pkt)) catch |err| {
        log.err("failed to recv `handshake` packet: {}", .{err});
        return false;
    };

    if (sz == 0)
        return false;

    if (sz < Packet.header_size) {
        log.err("invalid response size: {}:{}", .{ sz, Packet.header_size });
        return false;
    }

    log.debug("received bytes: {}", .{sz});
    return self.handleHandshakeResponse(&buffer);
}

fn handleHandshakeResponse(self: *Udp, buffer: []u8) bool {
    const pkt = &self.packet;
    const hnsk = &pkt.body.handshake;
    const len = pkt.getBodyLen();

    switch (pkt.code) {
        .handshake => {
            if (len != Handshake.size) {
                log.err("invalid response packet body length: {}:{}", .{
                    len,
                    Handshake.size,
                });

                return false;
            }

            const v = &hnsk.version;
            log.info("handshake response: server version: {s}", .{v.toStr(buffer)});

            if ((v.major != ver.major) or
                (v.patch != ver.patch) or
                (v.sub != ver.sub))
            {
                log.err("server version is not supported for this client", .{});
                return false;
            }

            // success
            return true;
        },
        .handshake_reject => {
            if (len != HandshakeReject.size) {
                log.err("invalid response packet body length: {}:{}", .{
                    len,
                    HandshakeReject.size,
                });
            } else {
                log.err("server rejected the `handshake` request: {s}", .{
                    pkt.body.handshake_reject.toStr(buffer),
                });
            }
        },
        .close => {
            log.err("server closed the connection", .{});
        },
        else => |code| {
            log.err("invalid response code: {s}: {s}", .{
                @tagName(code),
                code.toStr(),
            });
        },
    }

    return false;
}

//
// Auth handler
//
fn handleAuth(self: *Udp) bool {
    const fd = self.sock_fd;
    const pkt = &self.packet;

    // send "auth" packet
    const cfg = &self.config.auth;
    pkt.body.auth.set(cfg.getUsername(), cfg.getPassword()) catch |err| {
        log.err("failed to prepare auth packet: {}", .{err});
        return false;
    };

    log.info("sending `auth` packet...", .{});
    var sz = udp.send(fd, pkt.create(.auth, Auth.size)) catch |err| {
        log.err("failed to send `auth` packet: {}", .{err});
        return false;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return false;

    log.debug("receiving `auth` response packet...", .{});
    sz = udp.recv(fd, mem.asBytes(pkt)) catch |err| {
        log.err("failed to recv `auth` packet: {}", .{err});
        return false;
    };

    if (sz == 0)
        return false;

    if (sz < Packet.header_size) {
        log.err("invalid response size: {}:{}", .{ sz, Packet.header_size });
        return false;
    }

    log.debug("received bytes: {}", .{sz});
    return self.handleAuthResponse();
}

fn handleAuthResponse(self: *Udp) bool {
    const pkt = &self.packet;
    switch (pkt.code) {
        .auth => {
            const rsp_len = pkt.getBodyLen();
            if (rsp_len != AuthResp.size) {
                log.err("invalid response packet body length: {}:{}", .{
                    rsp_len,
                    AuthResp.size,
                });

                return false;
            }

            log.info("authentication success", .{});

            // success
            self.is_established = true;
            return true;
        },
        .auth_reject => {
            log.err("auth response: wrong username or password", .{});
        },
        .handshake => |code| {
            log.debug("NOP code: {s}: {s}", .{ @tagName(code), code.toStr() });
            return true;
        },
        .close => {
            log.err("server closed the connection", .{});
        },
        else => |code| {
            log.err("invalid response code: {s}: {s}", .{
                @tagName(code),
                code.toStr(),
            });
        },
    }

    return false;
}
