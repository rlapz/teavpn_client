const builtin = @import("builtin");
const std = @import("std");

const ascii = std.ascii;
const mem = std.mem;
const fmt = std.fmt;
const io = std.io;
const os = std.os;

const impl = switch (builtin.os.tag) {
    .linux => @import("util/linux.zig"),
    else => @compileError("not supported os"),
};

pub const setSignalHandler = impl.setSignalHandler;
pub const setNonBlockingFd = impl.setNonBlockingFd;

pub const bytes = struct {
    pub fn reset(dest: anytype) void {
        @memset(@ptrCast([*]u8, dest), 0, @sizeOf(@TypeOf(dest.*)));
    }
};

pub const cstr = struct {
    pub fn toSlice(src: [*]const u8, size: usize) []const u8 {
        var i: usize = 0;
        while (i < size) {
            if (src[i] == '\x00')
                break;

            i += 1;
        }

        return src[0..i];
    }

    pub fn copy(dest: [*]u8, size: usize, src: []const u8) void {
        var i: usize = 0;
        for (src) |v| {
            if (i == size)
                break;

            dest[i] = v;
            i += 1;
        }

        dest[i] = '\x00';
    }
};

pub const str = struct {
    pub fn toUpper(buffer: []u8, _str: []const u8) []u8 {
        var i: usize = 0;
        const len = buffer.len;
        for (_str) |v| {
            if (i == len)
                break;

            buffer[i] = ascii.toUpper(v);
            i += 1;
        }

        return buffer[0..i];
    }
};

pub const stdout = struct {
    pub fn writer() type {
        return io.getStdOut().writer();
    }

    pub fn print(comptime format: []const u8, args: anytype) void {
        io.getStdOut().writer().print(format, args) catch {};
    }

    pub fn write(comptime _bytes: []const u8) void {
        io.getStdOut().writeAll(_bytes) catch {};
    }
};

pub const fsconf = struct {
    // get a value from `key`
    pub fn get(buffer: []const u8, key: []const u8) ?[]const u8 {
        var start = mem.indexOf(u8, buffer, key) orelse
            return null;

        start += key.len;
        if (start >= buffer.len)
            return null;

        if (buffer[start] != '(')
            return null;

        // skips '('
        start += 1;

        var end = mem.indexOf(u8, buffer[start..], ")\n") orelse
            return null;

        // get the real end index
        end += start;
        return mem.trim(u8, buffer[start..end], " ");
    }
};

pub fn hexDump(lbl: []const u8, _bytes: []const u8) void {
    const writer = io.getStdOut().writer();

    writer.writeAll(lbl) catch {};
    for (_bytes, 0..) |v, i| {
        if (i % 9 != 0) {
            writer.print("{} ", .{fmt.fmtSliceHexUpper(mem.asBytes(&v))}) catch {};
        } else {
            writer.writeByte('\n') catch {};
        }
    }

    writer.print("\nlen: {}\n", .{_bytes.len}) catch {};
}
