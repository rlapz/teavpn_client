const std = @import("std");
const assert = std.debug.assert;
const fmt = std.fmt;
const mem = std.mem;

const snet = @import("net.zig");
const util = @import("util.zig");

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
    code: Code,
    __pad: u8,
    body_len: u16,
    body: Body,

    pub const header_size = @sizeOf(Code) + 1 + 2;
    pub const size = @sizeOf(Packet);

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

    pub const Body = extern union {
        handshake: Handshake,
        handshake_reject: HandshakeReject,
        auth: Auth,
        auth_resp: AuthResp,
        raw: [raw_size - 1:0]u8,

        pub const raw_size = 4096;
        pub const size = @sizeOf(Body);
    };

    pub fn set(self: *Packet, code: Code, len: u16) void {
        self.code = code;
        self.body_len = mem.nativeToBig(u16, len);
    }

    pub fn getBodyLen(self: *const Packet) u16 {
        return mem.bigToNative(u16, self.body_len);
    }

    comptime {
        assert(@offsetOf(Packet, "code") == 0);
        assert(@offsetOf(Packet, "__pad") == 1);
        assert(@offsetOf(Packet, "body_len") == 2);
        assert(@offsetOf(Packet, "body") == 4);
        assert(size == 1 + 1 + 2 + Body.raw_size); // 4100
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
        extra: [extra_size - 1:0]u8,

        pub const extra_size = 29;
        pub const size = @sizeOf(Version);

        pub fn setExtra(self: *Version, extra: []const u8) !void {
            if (extra.len >= extra_size)
                return error.VersionExtraTooLong;

            return util.cstrCopy(&self.extra, extra_size, extra);
        }

        pub fn toStr(self: *const Version, buffer: []u8) []const u8 {
            const extra = util.cstrToSlice(&self.extra, extra_size);
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
    message: [message_len - 1:0]u8,

    pub const message_len = 511;
    pub const size = @sizeOf(HandshakeReject);

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
        return util.cstrToSlice(&self.message, message_len);
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
    username: [username_size - 1:0]u8,
    password: [password_size - 1:0]u8,

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

        util.cstrCopy(&self.username, username_size, uname);
        util.cstrCopy(&self.password, password_size, passw);
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
