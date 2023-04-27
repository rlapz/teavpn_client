const builtin = @import("builtin");
const std = @import("std");
const ascii = std.ascii;
const mem = std.mem;
const fmt = std.fmt;
const io = std.io;
const os = std.os;

const impl = switch (builtin.os.tag) {
    .linux => @import("linux/util.zig"),
    else => @compileError("not supported os"),
};

pub const setSignalHandler = impl.setSignalHandler;

pub fn cstrToSlice(src: [*:0]const u8, size: usize) []const u8 {
    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (src[i] == '\x00')
            break;
    }

    return src[0..i];
}

pub fn ctstrLen(src: [*:0]const u8) usize {
    var i: usize = 0;
    while (true) {
        if (src[i] == '\x00')
            break;

        i += 1;
    }

    return i;
}

pub fn cstrCopy(dest: [*:0]u8, size: usize, src: []const u8) void {
    var i: usize = 0;
    for (src) |v| {
        if (i == size)
            break;

        dest[i] = v;
        i += 1;
    }

    dest[i] = '\x00';
}

pub fn strCmp(str1: []const u8, str2: []const u8) bool {
    return mem.eql(u8, str1, str2);
}

pub fn strToUpper(buffer: []u8, str: []const u8) []u8 {
    var i: usize = 0;
    for (str) |v| {
        if (i == buffer.len)
            break;

        buffer[i] = ascii.toUpper(v);
        i += 1;
    }

    return buffer[0..i];
}

pub const stdout = struct {
    pub fn print(comptime format: []const u8, args: anytype) void {
        io.getStdOut().writer().print(format, args) catch {};
    }

    pub fn write(comptime bytes: []const u8) void {
        io.getStdOut().writeAll(bytes) catch {};
    }
};

const expect = std.testing.expect;
test "toUpper" {
    const str = "helloWorld";
    var buff: [str.len]u8 = undefined;

    const res = strToUpper(&buff, str);
    try expect(mem.eql(u8, res, "HELLOWORLD"));
}
