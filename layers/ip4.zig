//! An IPv4 packet

const std = @import("std");
const Ip4Packet = @This();

pub const Flags = enum(u3) {
    dont_fragment = 0b010,
    more_fragments = 0b001,
    _,
};

pub const Protocol = enum(u8) {
    ipv6_hop_by_hop = 0,
    icmpv4 = 1,
    igmp = 2,
    ipv4 = 4,
    tcp = 6,
    udp = 17,
    rudp = 27,
    ipv6 = 41,
    ipv6_routing = 43,
    ipv6_fragment = 44,
    gre = 47,
    esp = 50,
    ah = 51,
    icmpv6 = 58,
    no_next_header = 59,
    ipv6_destination = 60,
    ospf = 89,
    ipip = 94,
    etherip = 97,
    vrrp = 112,
    sctp = 132,
    udp_lite = 136,
    mpls_in_ip = 137,
    _,
};

pub const OptionKind = enum(u8) {
    /// End of Option List
    eool = 0,
    /// No Operation
    nop = 1,
    /// Security (defunct)
    sec_defunct = 2,
    /// Record Route
    rr = 7,
    /// Experimental Measurement
    zsu = 10,
    /// MTU Probe
    mtup = 11,
    /// MTU Reply
    mtur = 12,
    /// ENCODE
    encode = 15,
    /// Quick-Start
    qs = 25,
    /// RFC3692-style Experiment
    exp1 = 30,
    /// Time Stamp
    ts = 68,
    /// Traceroute
    tr = 82,
    /// RFC3692-style Experiment
    exp2 = 94,
    /// Security (RIPSO)
    sec = 130,
    /// Loose Source Route
    lsr = 131,
    /// Extended Security (RIPSO)
    e_sec = 133,
    /// Commercial IP Security Option
    cipso = 134,
    /// Stream ID
    sid = 136,
    /// Strict Source Route
    ssr = 137,
    /// Experimental Access Control
    visa = 142,
    /// IMI Traffic Descriptor
    imitd = 144,
    /// Extended Internet Protocol
    eip = 145,
    /// Address Extension
    addext = 147,
    /// Router Alert
    rtralt = 148,
    /// Selective Directed Broadcast
    sdb = 149,
    /// Dynamic Packet State
    dps = 151,
    /// Upstream Multicast Pkt.
    ump = 152,
    /// RFC3692-style Experiment
    exp3 = 158,
    /// Experimental Flow Control
    finn = 205,
    /// RFC3692-style Experiment
    exp4 = 222,

    pub fn isExperiment(self: OptionKind) bool {
        return self == .exp1 or self == .exp2 or self == .exp3 or self == .exp4;
    }
};

pub const Option = struct {
    kind: OptionKind,
    data: []u8,
};

version: u4,
/// Multiply by 32 to get the header length in bits, by 4 to get it in bytes!
header_length: u4,
/// Differentiated Services Code Point, used by real-time data
dscp: u6,
/// Explicit Congestion Notification
ecn: u2,
total_length: u16,
id: u16,
flags: Flags,
fragment_offset: u13,
ttl: u8,
protocol: Protocol,
checksum: u16,
source_ip: [4]u8,
destination_ip: [4]u8,
options: std.ArrayListUnmanaged(Option),
payload: []u8,

pub fn decode(allocator: *std.mem.Allocator, data: []const u8) !Ip4Packet {
    var reader = std.io.fixedBufferStream(data).reader();

    if (data.len < 20)
        return error.TooShort;

    var packet: Ip4Packet = undefined;

    var byte = try reader.readByte();
    packet.version = @truncate(u4, byte >> 4);
    if (packet.version != 4)
        return error.InvalidVersion;
    packet.header_length = @truncate(u4, byte & 0b1111);

    byte = try reader.readByte();
    packet.dscp = @truncate(u6, byte >> 2);
    packet.ecn = @truncate(u2, byte & 0b11);

    packet.total_length = try reader.readIntBig(u16);
    packet.id = try reader.readIntBig(u16);

    var two_bytes = try reader.readIntBig(u16);
    packet.flags = @intToEnum(Flags, @truncate(u3, two_bytes >> 13));
    packet.fragment_offset = @truncate(u13, two_bytes & 0b1111111111111);

    packet.ttl = try reader.readIntBig(u8);
    packet.protocol = @intToEnum(Protocol, try reader.readIntBig(u8));
    packet.checksum = try reader.readIntBig(u16);

    _ = try reader.readAll(&packet.source_ip);
    _ = try reader.readAll(&packet.destination_ip);

    if (packet.total_length < 20 or packet.header_length < 5) {
        return error.TooShort;
    } else if (@as(u8, packet.header_length) * 4 > packet.total_length) {
        return error.InvalidLength;
    }

    packet.options = std.ArrayListUnmanaged(Option){};

    packet.payload = try allocator.dupe(u8, data[@as(u8, packet.header_length) * 4 ..]);

    var options_counter = packet.header_length;
    while (options_counter > 5) : (options_counter -= 1) {
        if (packet.options.capacity == 0)
            try packet.options.ensureTotalCapacity(allocator, 4);

        var kind = @intToEnum(OptionKind, try reader.readByte());
        switch (kind) {
            .eool, .nop => {},
            else => {
                var option = try packet.options.addOne(allocator);
                option.kind = kind;
                var length = try reader.readByte();

                if (length <= 2)
                    return error.OptionTooSmall;

                option.data = try allocator.alloc(u8, length);
                _ = try reader.readAll(option.data);
            },
        }
    }

    return packet;
}

pub fn deinit(self: *Ip4Packet, allocator: *std.mem.Allocator) void {
    self.options.deinit(allocator);
    allocator.free(self.payload);
}

test "Basic TCP packet parsing (example.com)" {
    const raw_packet = @embedFile("test-data/ip4/example.com.bin");
    var packet = try decode(std.testing.allocator, raw_packet);
    defer packet.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u4, 4), packet.version);
    try std.testing.expectEqual(@as(u4, 5), packet.header_length);
    try std.testing.expectEqual(@as(u6, 0), packet.dscp);
    try std.testing.expectEqual(@as(u2, 0), packet.ecn);
    try std.testing.expectEqual(@as(u16, 478), packet.total_length);
    try std.testing.expectEqual(@as(u16, 33239), packet.id);
    try std.testing.expectEqual(Flags.dont_fragment, packet.flags);
    try std.testing.expectEqual(@as(u13, 0), packet.fragment_offset);
    try std.testing.expectEqual(@as(u8, 128), packet.ttl);
    try std.testing.expectEqual(Protocol.tcp, packet.protocol);
    try std.testing.expectEqual(@as(u16, 0), packet.checksum);
    try std.testing.expectEqual([4]u8{ 192, 168, 0, 112 }, packet.source_ip);
    try std.testing.expectEqual([4]u8{ 93, 184, 216, 34 }, packet.destination_ip);
}
