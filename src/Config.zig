const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const mem = std.mem;
const log = std.log;

const packet = @import("packet.zig");
const snet = @import("net.zig");
const util = @import("util.zig");
const stdout = util.stdout;
const fsconf = util.fsconf;

pub const version = struct {
    pub const major = 0;
    pub const patch = 1;
    pub const sub = 2;
    pub const extra = "-rc1";
};

pub const default = struct {
    pub const config_file = "~/.config/teavpn_client/config.fc";

    pub const socket = struct {
        pub const tun_path = "/dev/net/tun";
        pub const type_ = "UDP";
        pub const use_encryption = "1"; // 0: false, >0 true
        pub const server_addr = "127.0.0.1";
        pub const server_port = "44444";
    };

    pub const iface = struct {
        pub const override_default = "1"; // 0: false, >0 true
        pub const dev = "tvpn0";
    };

    pub const auth = struct {
        pub const username = "public_user";
        pub const password = "public_user";
    };
};

pub const buffer_size = 8192;

pub const Config = @This();
sys: Sys,
socket: Socket,
iface: Iface,
auth: Auth,
//////

pub const Sys = struct {
    queue_depth: u13,
};

pub const Socket = struct {
    tun_path: [tun_path_size]u8,
    type_: Type,
    use_encryption: bool,
    server_addr: [server_addr_size]u8,
    server_port: u16,

    pub const tun_path_size = 256;
    pub const server_addr_size = 64;
    pub const Type = enum(u8) {
        UDP,
        _,

        pub fn toStr(self: Type) []const u8 {
            return switch (self) {
                .UDP => "UDP",
                else => "unknown socket type",
            };
        }

        pub fn fromStr(str: []const u8) !Type {
            var buff: [32]u8 = undefined;
            if (str.len >= @sizeOf(@TypeOf(buff)))
                return error.SocketTypeTooLong;

            const _str = util.strToUpper(&buff, str);
            if (util.strCmp(_str, Type.UDP.toStr()))
                return .UDP;

            return error.SocketTypeInvalid;
        }
    };

    pub fn setTunPath(self: *Socket, tun_path: []const u8) !void {
        if (tun_path.len >= tun_path_size)
            return error.TunPathTooLong;

        return util.cstrCopy(&self.tun_path, tun_path_size, tun_path);
    }

    pub fn setServerAddr(self: *Socket, addr: []const u8) !void {
        if (addr.len >= server_addr_size)
            return error.ServerAddrTooLong;

        return util.cstrCopy(&self.server_addr, server_addr_size, addr);
    }

    pub fn getServerAddr(self: *const Socket) []const u8 {
        return util.cstrToSlice(&self.server_addr, server_addr_size);
    }

    pub fn getTunPath(self: *const Socket) []const u8 {
        return util.cstrToSlice(&self.tun_path, tun_path_size);
    }
};

pub const Iface = struct {
    override_default: bool,
    dev: [dev_size]u8,

    pub const dev_size = snet.ifacenamesize;
    pub fn setDev(self: *Iface, name: []const u8) !void {
        if (name.len >= dev_size)
            return error.IfaceDevNameTooLong;

        return util.cstrCopy(&self.dev, dev_size, name);
    }

    pub fn getDev(self: *const Iface) []const u8 {
        return util.cstrToSlice(&self.dev, dev_size);
    }
};

pub const Auth = struct {
    username: [username_size]u8,
    password: [password_size]u8,

    pub const username_size = packet.Auth.username_size;
    pub const password_size = packet.Auth.password_size;

    pub fn setUsername(self: *Auth, uname: []const u8) !void {
        if (uname.len >= username_size)
            return error.AuthUsernameTooLong;

        return util.cstrCopy(&self.username, username_size, uname);
    }

    pub fn setPassword(self: *Auth, passw: []const u8) !void {
        if (passw.len >= password_size)
            return error.AuthPasswordTooLong;

        return util.cstrCopy(&self.password, password_size, passw);
    }

    pub fn getUsername(self: *const Auth) []const u8 {
        return util.cstrToSlice(&self.username, username_size);
    }

    pub fn getPassword(self: *const Auth) []const u8 {
        return util.cstrToSlice(&self.password, password_size);
    }
};

// path: null -> use default file path
pub fn load(self: *Config, path: ?[]const u8) !void {
    const cfg = if (path != null)
        path.?
    else
        default.config_file;

    var file = fs.cwd().openFile(cfg, .{}) catch |err| {
        if (err == error.FileNotFound)
            log.err("file: {s}: {s}", .{ cfg, @errorName(err) });

        return err;
    };
    defer file.close();

    var buffer: [buffer_size]u8 = undefined;
    const sz = try file.readAll(&buffer);
    return self.parse(buffer[0..sz]);
}

fn parse(self: *Config, buff: []const u8) !void {
    // socket_*
    const sock = default.socket;
    var val = fsconf.get(buff, "socket_tun_path") orelse sock.tun_path;
    try self.socket.setTunPath(val);

    val = fsconf.get(buff, "socket_type") orelse sock.type_;
    self.socket.type_ = try Socket.Type.fromStr(val);

    val = fsconf.get(buff, "socket_use_encryption") orelse sock.use_encryption;
    if (try fmt.parseUnsigned(i32, val, 10) != 0)
        self.socket.use_encryption = true
    else
        self.socket.use_encryption = false;

    val = fsconf.get(buff, "socket_server_addr") orelse sock.server_addr;
    try self.socket.setServerAddr(val);

    val = fsconf.get(buff, "socket_server_port") orelse sock.server_port;
    self.socket.server_port = try fmt.parseUnsigned(u16, val, 10);

    // iface_*
    const iface = default.iface;
    val = fsconf.get(buff, "iface_override_default") orelse iface.override_default;
    if (try fmt.parseUnsigned(i32, val, 10) != 0)
        self.iface.override_default = true
    else
        self.iface.override_default = false;

    val = fsconf.get(buff, "iface_dev") orelse iface.dev;
    try self.iface.setDev(val);

    // auth_*
    const auth = default.auth;
    val = fsconf.get(buff, "auth_username") orelse auth.username;
    try self.auth.setUsername(val);

    val = fsconf.get(buff, "auth_password") orelse auth.password;
    try self.auth.setPassword(val);
}

pub fn dump(self: *Config) void {
    stdout.print(
        \\---------------------------------------------
        \\Config
        \\|-> sock
        \\|   |-> type:             {s}
        \\|   |-> use_encryption:   {}
        \\|   |-> server_addr:      {s}
        \\|   `-> server_port:      {}
        \\|-> iface
        \\|   |-> override_default: {}
        \\|   `-> dev:              {s}
        \\`-> auth
        \\    `-> username:         {s}
        \\---------------------------------------------
        \\
    ,
        .{
            self.socket.type_.toStr(),
            self.socket.use_encryption,
            self.socket.getServerAddr(),
            self.socket.server_port,
            self.iface.override_default,
            self.iface.getDev(),
            self.auth.getUsername(),
        },
    );
}

test {
    _ = try Socket.Type.fromStr("UDP");
}
