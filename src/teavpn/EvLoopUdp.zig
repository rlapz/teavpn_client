const builtin = @import("builtin");
const std = @import("std");

const fmt = std.fmt;
const mem = std.mem;
const os = std.os;
const log = std.log;
const time = std.time;
const POLL = os.POLL;

const packet = @import("../packet.zig");
const snet = @import("../net.zig");
const util = @import("../util.zig");

const Packet = packet.Packet;

const bytes = util.bytes;
const udp = snet.udp;

// pollfd indices
const udp_idx = 0;
const tun_idx = 1;

// in milliseconds, default: 100 miliseconds
const poll_timeout = 100;

// send `reqsync` packet frequency,
//  default: every `(reqsync_freq * poll_timeout)` miliseconds
const sync_req_freq = 131; // starting from 0
const sync_res_max_try = 4; // starting from 0

//
// TODO: multithreading support
//
const EvLoopUdp = @This();
is_alive: bool,
sfd: os.socket_t,
tfd: os.fd_t,
sync_req_count: u32,
sync_res_count: u32,
packet: Packet,

pub fn run(self: *EvLoopUdp, sfd: os.socket_t, tfd: os.fd_t) !void {
    bytes.reset(self);

    // set NONBLOCK-ing fds
    try util.setNonBlockingFd(sfd);
    try util.setNonBlockingFd(sfd);

    log.info("EvLoopUdp: running...", .{});
    defer log.info("EvLoopUdp: stopped", .{});

    var pfds: [2]os.pollfd = undefined;
    bytes.reset(&pfds);

    pfds[udp_idx].fd = sfd;
    pfds[udp_idx].events = POLL.IN | POLL.PRI;
    pfds[tun_idx].fd = tfd;
    pfds[tun_idx].events = POLL.IN;

    self.sfd = sfd;
    self.tfd = tfd;
    return self.runWrp(&pfds);
}

pub fn stop(self: *EvLoopUdp) void {
    log.info("stopping event loop...", .{});

    const Counter = struct {
        var counter: usize = 3;
        fn isAvailable() bool {
            if (counter == 0)
                return false;

            counter -= 1;
            return true;
        }

        fn reset() void {
            counter = 3;
        }
    };

    const fd = self.sfd;
    if (Counter.isAvailable()) {
        sendClosePkt(&self.packet, fd) catch {
            os.shutdown(fd, .both) catch {};
        };
    } else {
        log.info("force close", .{});
        os.shutdown(fd, .both) catch {};
        Counter.reset();
    }

    self.is_alive = false;
}

fn runWrp(self: *EvLoopUdp, pfds: []os.pollfd) !void {
    self.is_alive = true;
    while (self.is_alive) {
        log.debug("req: {}, res: {}", .{
            self.sync_req_count,
            self.sync_res_count,
        });

        if ((try os.poll(pfds, poll_timeout)) != 0) {
            if (self.handleEvs(pfds))
                continue;

            break;
        }

        // poll() timeout
        const sync_req = self.sync_req_count;
        if (sync_req >= sync_req_freq) {
            const sync_res = self.sync_res_count;
            if (sync_res >= sync_res_max_try)
                return error.Disconnected;

            try sendReqsyncPkt(&self.packet, self.sfd);
            self.sync_res_count = sync_res + 1;
            self.sync_req_count = 0;
        } else {
            self.sync_req_count = sync_req + 1;
        }
    }
}

inline fn handleEvs(self: *EvLoopUdp, pfds: []const os.pollfd) bool {
    // UDP FD
    var rv = pfds[udp_idx].revents;
    if (((rv & POLL.ERR) != 0) or ((rv & POLL.HUP) != 0)) {
        log.info("poll: udp: {}: error/hup", .{pfds[udp_idx].fd});
        return false;
    }

    if ((rv & POLL.IN) != 0) {
        self.handleUdp() catch |err| if (err != error.WouldBlock) {
            log.err("handleUdp: {}", .{err});
            return false;
        };
    }

    // TUN_FD
    rv = pfds[tun_idx].revents;
    if (((rv & POLL.ERR) != 0) or ((rv & POLL.HUP) != 0)) {
        log.info("poll: tun: {}: error/hup", .{pfds[tun_idx].fd});
        sendClosePkt(&self.packet, pfds[udp_idx].fd) catch {};
        return false;
    }

    if ((rv & POLL.IN) != 0) {
        self.handleTun() catch |err| if (err != error.WouldBlock) {
            log.err("handleTun: {}", .{err});
            return false;
        };
    }

    return true;
}

fn handleUdp(self: *EvLoopUdp) !void {
    const pkt = &self.packet;
    var sz = udp.recv(self.sfd, mem.asBytes(pkt)) catch |err| {
        log.err("failed to recv packet from the server: {}", .{err});
        return err;
    };

    log.debug("received bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;

    if (sz < Packet.header_size) {
        log.err("invalid response size: {}:{}", .{ sz, Packet.header_size });
        return error.InvalidResponse;
    }

    switch (pkt.code) {
        // High priority
        .tun_data => {
            try writeTunPkt(pkt, self.tfd);
        },
        .reqsync => {
            try sendSyncPkt(pkt, self.sfd);
        },
        .sync => {
            log.debug("recvd `sync` packet", .{});
            self.sync_res_count = 0;
        },
        .handshake, .auth => |code| {
            log.debug("NOP code: {s}: {s}", .{ @tagName(code), code.toStr() });
        },
        .close => {
            log.info("server closed the connection", .{});
            self.is_alive = false;
        },
        else => |code| {
            log.err("invalid response code: {s}: {s}", .{
                @tagName(code),
                code.toStr(),
            });

            return error.InvalidResponse;
        },
    }
}

fn handleTun(self: *EvLoopUdp) !void {
    const pkt = &self.packet;

    log.debug("reading `tun_data` <- TUN fd: {}...", .{self.tfd});
    var sz = os.read(self.tfd, &pkt.body.raw) catch |err| {
        log.err("failed to read `tun_data` <- TUN fd: {}: {}", .{ self.tfd, err });
        return err;
    };

    log.debug("read bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;

    log.debug("sending `tun_data` -> UDP fd: {}...", .{self.sfd});
    sz = udp.send(self.sfd, pkt.create(.tun_data, @intCast(u16, sz))) catch |err| {
        log.err("failed to send `tun_data` -> UDP fd: {}: {}", .{ self.sfd, err });
        return err;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;
}

//
// Sender
//
fn sendSyncPkt(self: *Packet, fd: os.fd_t) !void {
    log.debug("sending `sync` packet...", .{});
    const sz = udp.send(fd, self.create(.sync, 0)) catch |err| {
        log.err("failed to send `sync` packet: {}", .{err});
        return err;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;
}

fn sendReqsyncPkt(self: *Packet, fd: os.fd_t) !void {
    log.debug("sending `reqsync` packet...", .{});
    const sz = udp.send(fd, self.create(.reqsync, 0)) catch |err| {
        log.err("failed to send `reqsync` packet: {}", .{err});
        return err;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;
}

noinline fn sendClosePkt(self: *Packet, fd: os.fd_t) !void {
    log.debug("sending `close` packet...", .{});
    const sz = udp.send(fd, self.create(.close, 0)) catch |err| {
        log.err("failed to send `close` packet: {}", .{err});
        return err;
    };

    log.debug("sent bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;
}

//
// writer
//
fn writeTunPkt(self: *const Packet, fd: os.fd_t) !void {
    log.debug("writing `tun_data` -> TUN fd: {}...", .{fd});
    const sz = os.write(fd, self.getBodyRaw()) catch |err| {
        log.err("failed to write `tun_data` -> TUN fd: {}: {}", .{ fd, err });
        return err;
    };

    log.debug("received bytes: {}", .{sz});
    if (sz == 0)
        return error.EOF;
}
