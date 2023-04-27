const builtin = @import("builtin");

pub const Udp = switch (builtin.os.tag) {
    .linux => @import("linux/Udp.zig"),
    else => @compileError("not supported os"),
};
pub const Tcp = @compileError("not yet supported!");
