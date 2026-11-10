const r4os = @import("r4os");

const TYPE_IPV4: u16 = 0x0800;
const TYPE_ARP: u16 = 0x0806;
const HTYPE_ETHERNET: u16 = 1;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;
const ETHERNET_HEADER_SIZE: usize = 14;
const ARP_PACKET_SIZE: usize = 28;
const ARP_FRAME_SIZE: usize = ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE;
const MIN_FRAME_SIZE: usize = 60;

comptime {
    if (!@import("builtin").is_test) asm (r4os.technical2.protocolEntriesAsm("netarp_init", "netarp_shutdown", "netarp_query", "netarp_dispatch"));
}

export fn netarp_init(api: *const r4os.technical2.abi.ProtocolApi2) callconv(.c) i32 {
    const view = r4os.technical2.Protocol.init(api) orelse return r4os.abi.network_error_backend;
    const log = view.function("log_info") orelse return r4os.abi.err_no_fn;
    const register = view.function("register_role") orelse return r4os.abi.err_no_fn;
    const status = view.function("set_status") orelse return r4os.abi.err_no_fn;
    log("NETARP.R4P init");
    const registered = register("net.arp", @intFromEnum(r4os.abi.ProtocolCategory.net), 0);
    if (registered != 0) return registered;
    return status(@intFromEnum(r4os.abi.ProtocolState.active), "ARP R4P active");
}

export fn netarp_shutdown() callconv(.c) i32 {
    return 0;
}

export fn netarp_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("ARP R4P ready"),
    };
    return 0;
}

export fn netarp_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.arp_op_handle_rx => handleRx(request),
        r4os.abi.arp_op_handle_tx => handleTx(request),
        r4os.abi.arp_op_build_request => buildRequest(request),
        else => return -4,
    }
    return request.result;
}

fn handleRx(request: *r4os.abi.ArpOp) void {
    request.flags = 0;
    request.opcode = 0;
    if (!isArpFrame(request)) {
        request.result = r4os.abi.arp_result_not_arp;
        return;
    }
    if (request.frame_len < ARP_FRAME_SIZE) {
        request.result = r4os.abi.arp_result_short;
        return;
    }
    const frame = request.frame[0..@intCast(request.frame_len)];
    if (readBe16(frame, 14) != HTYPE_ETHERNET or readBe16(frame, 16) != TYPE_IPV4 or frame[18] != 6 or frame[19] != 4) {
        request.result = r4os.abi.arp_result_shape;
        return;
    }
    parsePayload(request, frame);
}

fn handleTx(request: *r4os.abi.ArpOp) void {
    request.flags = 0;
    request.opcode = 0;
    if (!isArpFrame(request)) {
        request.result = r4os.abi.arp_result_not_arp;
        return;
    }
    if (request.frame_len < ARP_FRAME_SIZE) {
        request.result = r4os.abi.arp_result_short;
        return;
    }
    parsePayload(request, request.frame[0..@intCast(request.frame_len)]);
}

fn parsePayload(request: *r4os.abi.ArpOp, frame: []const u8) void {
    const opcode = readBe16(frame, 20);
    request.opcode = opcode;
    copyMacFromSlice(&request.sender_mac, frame[22..28]);
    copyIpFromSlice(&request.sender_ip, frame[28..32]);
    copyMacFromSlice(&request.target_mac, frame[32..38]);
    copyIpFromSlice(&request.seen_target_ip, frame[38..42]);
    if (opcode == OP_REQUEST) {
        request.flags = r4os.abi.arp_flag_request;
        request.result = r4os.abi.arp_result_ok;
    } else if (opcode == OP_REPLY) {
        request.flags = r4os.abi.arp_flag_reply;
        request.result = r4os.abi.arp_result_ok;
    } else {
        request.result = r4os.abi.arp_result_opcode;
    }
}

fn buildRequest(request: *r4os.abi.ArpOp) void {
    if (request.frame.len < MIN_FRAME_SIZE) {
        request.result = r4os.abi.arp_result_buffer_small;
        return;
    }
    var i: usize = 0;
    while (i < MIN_FRAME_SIZE) : (i += 1) request.frame[i] = 0;
    i = 0;
    while (i < 6) : (i += 1) request.frame[i] = 0xFF;
    i = 0;
    while (i < 6) : (i += 1) request.frame[6 + i] = request.source_mac[i];
    writeBe16(request.frame[0..], 12, TYPE_ARP);
    writeBe16(request.frame[0..], 14, HTYPE_ETHERNET);
    writeBe16(request.frame[0..], 16, TYPE_IPV4);
    request.frame[18] = 6;
    request.frame[19] = 4;
    writeBe16(request.frame[0..], 20, OP_REQUEST);
    copyMac(request.frame[22..28], request.source_mac);
    copyIp(request.frame[28..32], request.local_ip);
    copyIp(request.frame[38..42], request.target_ip);
    request.frame_len = MIN_FRAME_SIZE;
    request.opcode = OP_REQUEST;
    request.flags = r4os.abi.arp_flag_request;
    request.result = r4os.abi.arp_result_ok;
}

fn isArpFrame(request: *const r4os.abi.ArpOp) bool {
    if (request.frame_len < ETHERNET_HEADER_SIZE or request.frame_len > request.frame.len) return false;
    return readBe16(request.frame[0..], 12) == TYPE_ARP;
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.ArpOp {
    // The legacy operation is an exclusive in/out native record, despite
    // the const transport metadata. No packet bytes are native-cast here.
    const native = r4os.native_protocol_view;
    var metadata = buffer.*;
    const view = native.InOut(r4os.abi.ArpOp).init(&metadata, native.Policy.record(r4os.abi.ArpOp, .inout, .prefix)) catch return null;
    return view.value;
}

fn readBe16(buf: []const u8, offset: usize) u16 {
    var reader = r4os.binary_cursor.Reader.init(buf) catch unreachable;
    _ = reader.take(offset) catch unreachable;
    return reader.readInt(u16, .big) catch unreachable;
}

fn writeBe16(buf: []u8, offset: usize, value: u16) void {
    var writer = r4os.binary_cursor.Writer.init(buf) catch unreachable;
    writer.position = offset;
    writer.writeInt(u16, value, .big) catch unreachable;
}

fn copyMac(dst: []u8, src: [6]u8) void {
    var i: usize = 0;
    while (i < 6) : (i += 1) dst[i] = src[i];
}

fn copyIp(dst: []u8, src: [4]u8) void {
    var i: usize = 0;
    while (i < 4) : (i += 1) dst[i] = src[i];
}

fn copyMacFromSlice(dst: *[6]u8, src: []const u8) void {
    var i: usize = 0;
    while (i < 6) : (i += 1) dst[i] = src[i];
}

fn copyIpFromSlice(dst: *[4]u8, src: []const u8) void {
    var i: usize = 0;
    while (i < 4) : (i += 1) dst[i] = src[i];
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
