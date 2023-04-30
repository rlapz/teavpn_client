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
const cstr = util.cstr;
const str = util.str;

pub const thread_max = 128;

pub const version = struct {
    pub const major = 0;
    pub const patch = 1;
    pub const sub = 2;
    pub const extra = "-rc1";
};

pub const default = struct {
    pub const config_file = "~/.config/teavpn_client/config.fc";

    pub const sys = struct {
        pub const auto_reconnect = "1"; // 0: false, ~0 true
    };

    pub const socket = struct {
        pub const type_ = "UDP";
        pub const use_encryption = "1"; // 0: false, ~0 true
        pub const server_addr = "127.0.0.1";
        pub const server_port = "44444";
    };

    pub const iface = struct {
        pub const override_default = "1"; // 0: false, ~0 true
        pub const tun_path = "/dev/net/tun";
        pub const dev = "tvpn0";
    };

    pub const auth = struct {
        pub const username = "public_user";
        pub const password = "public_user";
    };
};

pub const Config = @This();
sys: Sys,
socket: Socket,
iface: Iface,
auth: Auth,
//////

pub const Sys = struct {
    auto_reconnect: bool,
};

pub const Socket = struct {
    type_: Type,
    use_encryption: bool,
    server_addr: [server_addr_size]u8,
    server_port: u16,

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

        pub fn fromStr(_str: []const u8) !Type {
            var buff: [32]u8 = undefined;
            const upper = str.toUpper(&buff, _str);
            if (mem.eql(u8, upper, Type.UDP.toStr()))
                return .UDP;

            return error.SocketTypeUnknown;
        }
    };

    pub fn setServerAddr(self: *Socket, addr: []const u8) !void {
        if (addr.len >= server_addr_size)
            return error.ServerAddrTooLong;

        return cstr.copy(&self.server_addr, server_addr_size, addr);
    }

    pub fn getServerAddr(self: *const Socket) []const u8 {
        return cstr.toSlice(&self.server_addr, server_addr_size);
    }
};

pub const Iface = struct {
    override_default: bool,
    tun_path: [tun_path_size]u8,
    dev: [dev_size]u8,

    pub const tun_path_size = 256;
    pub const dev_size = snet.ifacenamesize;
    pub fn setTunPath(self: *Iface, tun_path: []const u8) !void {
        if (tun_path.len >= tun_path_size)
            return error.TunPathTooLong;

        return cstr.copy(&self.tun_path, tun_path_size, tun_path);
    }

    pub fn getTunPath(self: *const Iface) []const u8 {
        return cstr.toSlice(&self.tun_path, tun_path_size);
    }

    pub fn setDev(self: *Iface, name: []const u8) !void {
        if (name.len >= dev_size)
            return error.IfaceDevNameTooLong;

        return cstr.copy(&self.dev, dev_size, name);
    }

    pub fn getDev(self: *const Iface) []const u8 {
        return cstr.toSlice(&self.dev, dev_size);
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

        return cstr.copy(&self.username, username_size, uname);
    }

    pub fn setPassword(self: *Auth, passw: []const u8) !void {
        if (passw.len >= password_size)
            return error.AuthPasswordTooLong;

        return cstr.copy(&self.password, password_size, passw);
    }

    pub fn getUsername(self: *const Auth) []const u8 {
        return cstr.toSlice(&self.username, username_size);
    }

    pub fn getPassword(self: *const Auth) []const u8 {
        return cstr.toSlice(&self.password, password_size);
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

    var buffer: [4096]u8 = undefined;
    const sz = try file.readAll(&buffer);
    return self.parse(buffer[0..sz]);
}

fn parse(self: *Config, buff: []const u8) !void {
    // sys_*
    const sys = default.sys;
    var val = fsconf.get(buff, "sys_auto_reconnect") orelse sys.auto_reconnect;
    if (try fmt.parseInt(i32, val, 10) != 0)
        self.sys.auto_reconnect = true
    else
        self.sys.auto_reconnect = false;

    // socket_*
    const sock = default.socket;
    val = fsconf.get(buff, "socket_type") orelse sock.type_;
    self.socket.type_ = try Socket.Type.fromStr(val);

    val = fsconf.get(buff, "socket_use_encryption") orelse sock.use_encryption;
    if (try fmt.parseInt(i32, val, 10) != 0)
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
    if (try fmt.parseInt(i32, val, 10) != 0)
        self.iface.override_default = true
    else
        self.iface.override_default = false;

    val = fsconf.get(buff, "iface_tun_path") orelse iface.tun_path;
    try self.iface.setTunPath(val);

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
        \\[Config---------------------------------------
        \\|-> sock
        \\|   |-> type:             {s}
        \\|   |-> use_encryption:   {}
        \\|   |-> server_addr:      {s}
        \\|   `-> server_port:      {}
        \\|-> iface
        \\|   |-> override_default: {}
        \\|   |-> tun_path:         {s}
        \\|   `-> dev:              {s}
        \\`-> auth
        \\    `-> username:         {s}
        \\---------------------------------------------
        \\
    , .{
        self.socket.type_.toStr(),   self.socket.use_encryption,
        self.socket.getServerAddr(), self.socket.server_port,
        self.iface.override_default, self.iface.getTunPath(),
        self.iface.getDev(),         self.auth.getUsername(),
    });
}

test {
    _ = try Socket.Type.fromStr("UDP");
}
