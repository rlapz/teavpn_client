const std = @import("std");

const assert = std.debug.assert;
const fmt = std.fmt;
const mem = std.mem;
const os = std.os;

const snet = @import("net.zig");
const util = @import("util.zig");

const cstr = util.cstr;

//
// Each packet should contains `size` property
//

// ***
// Please edit this comment if you add, remove, or modify packet data structure(s)
// ***
//
// Packet list:
// - Packet
// - Handshake
// - HandshakeReject
// - Auth
// - AuthResp
//

//
// Packet
//
pub const Packet = extern struct {
    // header
    code: Code,
    __pad: u8,
    body_len: u16,

    // body
    body: extern union {
        handshake: Handshake,
        handshake_reject: HandshakeReject,
        auth: Auth,
        auth_resp: AuthResp,
        raw: [body_size]u8,
    },

    pub const size = @sizeOf(Packet);
    pub const body_size = 4096;
    pub const header_size = (size - body_size);

    pub const Code = enum(u8) {
        handshake,
        auth,
        tun_data,
        reqsync,
        sync,
        close,
        handshake_reject,
        auth_reject,
        _,

        pub fn toStr(self: Code) []const u8 {
            return switch (self) {
                .handshake => "handshake",
                .auth => "authentication",
                .tun_data => "tun data",
                .reqsync => "request synchronize",
                .sync => "synchronize",
                .close => "close connection",
                .handshake_reject => "handshake request rejected",
                .auth_reject => "authentication request rejected",
                else => "unknown code",
            };
        }
    };

    // get body raw with body_len offset
    pub fn getBodyRaw(self: *const Packet) []const u8 {
        return self.body.raw[0..self.getBodyLen()];
    }

    pub fn getBodyLen(self: *const Packet) u16 {
        return mem.bigToNative(u16, self.body_len);
    }

    pub fn create(self: *Packet, code: Code, len: u16) []const u8 {
        self.code = code;
        self.body_len = mem.nativeToBig(u16, len);
        return mem.asBytes(self)[0 .. header_size + len];
    }

    comptime {
        assert(@offsetOf(Packet, "code") == 0);
        assert(@offsetOf(Packet, "__pad") == 1);
        assert(@offsetOf(Packet, "body_len") == 2);
        assert(@offsetOf(Packet, "body") == 4);
        assert(size == 1 + 1 + 2 + body_size); // 4100
    }
};

//
// Handshake
//
pub const Handshake = extern struct {
    version: Version,
    __resv0: [Version.size]u8,
    __resv1: [Version.size]u8,

    pub const size = @sizeOf(Handshake);

    pub const Version = extern struct {
        major: u8,
        patch: u8,
        sub: u8,
        extra: [extra_size]u8,

        pub const extra_size = 29;
        pub const size = @sizeOf(Version);

        pub fn set(self: *Version, m: u8, p: u8, s: u8, e: []const u8) void {
            self.major = m;
            self.patch = p;
            self.sub = s;
            return cstr.copy(&self.extra, extra_size, e);
        }

        pub fn toStr(self: *const Version, buffer: []u8) []const u8 {
            const extra = cstr.toSlice(&self.extra, extra_size);
            return fmt.bufPrint(
                buffer,
                "{}.{}.{}{s}",
                .{ self.major, self.patch, self.sub, extra },
            ) catch {
                unreachable;
            };
        }

        comptime {
            assert(@offsetOf(Version, "major") == 0);
            assert(@offsetOf(Version, "patch") == 1);
            assert(@offsetOf(Version, "sub") == 2);
            assert(@offsetOf(Version, "extra") == 3);
            assert(Version.size == 1 + 1 + 1 + extra_size); // 32
        }
    };

    comptime {
        assert(@offsetOf(Handshake, "version") == 0);
        assert(@offsetOf(Handshake, "__resv0") == Version.size);
        assert(@offsetOf(Handshake, "__resv1") == Version.size * 2);
        assert(size == Version.size * 3); // 96
    }
};

//
// HandshakeReject
//
pub const HandshakeReject = extern struct {
    reason: Reason,
    message: [message_len]u8,

    pub const size = @sizeOf(HandshakeReject);
    pub const message_len = 511;

    pub const Reason = enum(u8) {
        inval = (1 << 0), // invalid
        vnsupp = (1 << 1), // version not supported
        _,

        pub fn toStr(self: Reason) []const u8 {
            return switch (self) {
                .inval => "invalid", // TODO: proper reason message
                .vnsupp => "not supported version",
                else => "unknown reason",
            };
        }
    };

    pub fn getMessage(self: *const HandshakeReject) []const u8 {
        return cstr.toSlice(&self.message, message_len);
    }

    pub fn toStr(self: *const HandshakeReject, buffer: []u8) []const u8 {
        return fmt.bufPrint(buffer, "{s}: {s}", .{
            self.reason.toStr(),
            self.getMessage(),
        }) catch {
            unreachable;
        };
    }

    comptime {
        assert(@offsetOf(HandshakeReject, "reason") == 0);
        assert(@offsetOf(HandshakeReject, "message") == 1);
        assert(size == 1 + message_len); // 512
    }
};

//
// Auth
//
pub const Auth = extern struct {
    username: [username_size]u8,
    password: [password_size]u8,

    pub const username_size = 256;
    pub const password_size = 256;
    pub const size = @sizeOf(Auth);

    pub fn set(self: *Auth, uname: []const u8, passw: []const u8) !void {
        var _len = uname.len;
        if (_len == 0)
            return error.AuthUsernameIsEmpty;

        if (_len >= username_size)
            return error.AuthUsernameTooLong;

        _len = passw.len;
        if (_len == 0)
            return error.AuthPasswordIsEmpty;

        if (_len >= password_size)
            return error.AuthPasswordTooLong;

        cstr.copy(&self.username, username_size, uname);
        cstr.copy(&self.password, password_size, passw);
    }

    comptime {
        assert(@offsetOf(Auth, "username") == 0);
        assert(@offsetOf(Auth, "password") == username_size);
        assert(size == username_size + password_size); // 512
    }
};

//
// AuthResp
//
pub const AuthResp = extern struct {
    status: u8, // I'm not sure what is this
    __pad: u8,
    iff: snet.Iff,

    pub const size = @sizeOf(AuthResp);
    comptime {
        assert(@offsetOf(AuthResp, "status") == 0);
        assert(@offsetOf(AuthResp, "__pad") == 1);
        assert(@offsetOf(AuthResp, "iff") == 2);
        assert(size == 1 + 1 + snet.Iff.size); // 84
    }
};

//
test "packet" {
    _ = Packet;
    _ = Handshake;
    _ = HandshakeReject;
    _ = Auth;
    _ = AuthResp;
}
