//! A UDP packet

const std = @import("std");
const UdpPacket = @This();

pub const Port = u16;

source_port: Port,
destination_port: Port,
checksum: u16,
payload: []u8,

// TODO: Handle Jumbograms properly
pub fn getLength(packet: UdpPacket) u16 {
    return if (packet.payload.len + 8 > 65_535)
        0
    else
        8 + @intCast(u16, packet.payload.len);
}

pub fn encode(packet: UdpPacket, writer: anytype) !void {
    var buffer: [8]u8 = undefined;
    var fbs_writer = std.io.fixedBufferStream(&buffer).writer();

    try fbs_writer.writeIntBig(Port, packet.source_port);
    try fbs_writer.writeIntBig(Port, packet.destination_port);
    try fbs_writer.writeIntBig(u16, packet.getLength());
    try fbs_writer.writeIntBig(u16, packet.checksum); // TODO: Calculate checksum!

    try writer.writeAll(&buffer);
    try writer.writeAll(packet.payload);
}

pub fn decode(allocator: *std.mem.Allocator, data: []const u8) !UdpPacket {
    if (data.len < 8)
        return error.TooShort;

    var reader = std.io.fixedBufferStream(data).reader();

    var packet: UdpPacket = undefined;
    packet.source_port = try reader.readIntBig(Port);
    packet.destination_port = try reader.readIntBig(Port);
    var length = try reader.readIntBig(u16);
    packet.checksum = try reader.readIntBig(u16);

    packet.payload = try allocator.dupe(u8, if (length == 0)
        data[8..]
    else if (length >= 8)
        data[8..length]
    else
        return error.TooShort);

    return packet;
}

pub fn deinit(self: *UdpPacket, allocator: *std.mem.Allocator) void {
    allocator.free(self.payload);
}

test "UDP packet encode / decode (xkcd.com DNS answer)" {
    const raw_packet = @embedFile("test-data/udp/xkcd.com.bin");
    var packet = try decode(std.testing.allocator, raw_packet);
    defer packet.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(Port, 53), packet.source_port);
    try std.testing.expectEqual(@as(Port, 57452), packet.destination_port);
    try std.testing.expectEqual(@as(u16, 146), packet.getLength());
    try std.testing.expectEqual(@as(u16, 0x4eb1), packet.checksum);

    // zig-fmt: off
    const expected_payload = [_]u8{
        0x00, 0x03, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x78, 0x6b, 0x63,
        0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01,
        0x00, 0x00, 0x0e, 0x09, 0x00, 0x10, 0x2a, 0x04,
        0x4e, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0xc0, 0x0c,
        0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x09,
        0x00, 0x10, 0x2a, 0x04, 0x4e, 0x42, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x67, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01,
        0x00, 0x00, 0x0e, 0x09, 0x00, 0x10, 0x2a, 0x04,
        0x4e, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0xc0, 0x0c,
        0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x09,
        0x00, 0x10, 0x2a, 0x04, 0x4e, 0x42, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x67,
    };
    // zig-fmt: on

    try std.testing.expectEqualSlices(u8, &expected_payload, packet.payload);

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try packet.encode(buffer.writer());
    try std.testing.expectEqualSlices(u8, raw_packet, buffer.items);
}
