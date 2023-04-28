const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const mem = std.mem;
const log = std.log;

const ini = @import("lib/ini/src/ini.zig");
const packet = @import("packet.zig");
const snet = @import("net.zig");
const util = @import("util.zig");
const stdout = util.stdout;

pub const version = struct {
    pub const major = 0;
    pub const patch = 1;
    pub const sub = 2;
    pub const extra = "-rc1";
};

pub const buffer_size = 8192;
pub const default_config_file = "~/.config/teavpn_client/config.ini";

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
    type_: Type,
    use_encryption: bool,
    server_addr: [server_addr_size - 1:0]u8,
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

    pub fn setServerAddr(self: *Socket, addr: []const u8) !void {
        if (addr.len >= server_addr_size)
            return error.ServerAddrTooLong;

        return util.cstrCopy(&self.server_addr, server_addr_size, addr);
    }

    pub fn getServerAddr(self: *const Socket) []const u8 {
        return util.cstrToSlice(&self.server_addr, server_addr_size);
    }
};

pub const Iface = struct {
    override_default: bool,
    dev: [dev_size - 1:0]u8,

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
    username: [username_size - 1:0]u8,
    password: [password_size - 1:0]u8,

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

// set default values
pub fn init() Config {
    var self: Config = undefined;
    @memset(@ptrCast([*]u8, &self), 0, @sizeOf(Config));

    const sys = &self.sys;
    sys.queue_depth = 32;

    const socket = &self.socket;
    socket.type_ = .UDP;
    socket.use_encryption = false;
    socket.setServerAddr("127.0.0.1") catch
        unreachable;
    socket.server_port = 44444;

    const iface = &self.iface;
    iface.override_default = false;
    iface.setDev("tvpn0") catch
        unreachable;

    return self;
}

// path: null -> use default file path
pub fn load(self: *Config, allocator: mem.Allocator, path: ?[]const u8) !void {
    const cfg = if (path != null)
        path.?
    else
        default_config_file;

    var file = fs.cwd().openFile(cfg, .{}) catch |err| {
        if (err == error.FileNotFound)
            log.err("file: {s}: {s}", .{ cfg, @errorName(err) });

        return err;
    };
    defer file.close();

    return self.parse(allocator, &file);
}

fn parse(self: *Config, allocator: mem.Allocator, file: *const fs.File) !void {
    var parser = ini.parse(allocator, file.reader());
    defer parser.deinit();

    const sys = &self.sys;
    const socket = &self.socket;
    const iface = &self.iface;
    const auth = &self.auth;

    // TODO: carefully handle key-value in a section
    while (try parser.next()) |p| {
        switch (p) {
            .property => |prop| {
                const key = prop.key;
                const val = prop.value;

                // sys
                if (util.strCmp(key, "queue_depth"))
                    sys.queue_depth = try fmt.parseUnsigned(u13, val, 10);

                // socket
                if (util.strCmp(key, "sock_type"))
                    socket.type_ = try Socket.Type.fromStr(val);

                if (util.strCmp(key, "use_encryption")) {
                    const v = try fmt.parseUnsigned(i32, val, 10);
                    socket.use_encryption = if (v != 0) true else false;
                }

                if (util.strCmp(key, "server_addr"))
                    try socket.setServerAddr(val);

                if (util.strCmp(key, "server_port"))
                    socket.server_port = try fmt.parseUnsigned(u16, val, 10);

                // iface
                if (util.strCmp(key, "override_default")) {
                    const v = try fmt.parseUnsigned(i32, val, 10);
                    iface.override_default = if (v != 0) true else false;
                }

                if (util.strCmp(key, "dev"))
                    try iface.setDev(val);

                // auth
                if (util.strCmp(key, "username"))
                    try auth.setUsername(val);

                if (util.strCmp(key, "password"))
                    try auth.setPassword(val);
            },
            else => {},
        }
    }
}

pub fn dump(self: *Config) void {
    stdout.print(
        \\---------------------------------------------
        \\Config
        \\|-> sys
        \\|   `-> queue_depth:      {}
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
            self.sys.queue_depth,
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
