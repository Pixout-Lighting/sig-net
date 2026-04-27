//==============================================================================
// sig-net — Core Types Example
//==============================================================================
//
// Build:
//   cargo run -p sig-net --example core
//
// Demonstrates usage with only core types (default-features = false):
//   sig-net = { version = "0.5", default-features = false }
//==============================================================================

use sig_net::*;

fn main() {
    println!("=== Sig-Net Core Types Example ===\n");

    //--------------------------------------------------------------------------
    // CoAP Header
    //--------------------------------------------------------------------------
    let header = CoAPHeader::new(42);
    let bytes = header.to_bytes();
    let parsed = CoAPHeader::from_bytes(&bytes);

    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.type_, COAP_TYPE_NON);
    assert_eq!(parsed.code, COAP_CODE_POST);
    assert_eq!(parsed.message_id, 42);
    println!("CoAP header: ver={} type={} code={} msg_id={}",
        parsed.version, parsed.type_, parsed.code, parsed.message_id);

    //--------------------------------------------------------------------------
    // PacketBuffer
    //--------------------------------------------------------------------------
    let mut buf = PacketBuffer::new();
    buf.write_byte(0x01).unwrap();
    buf.write_u16(0x0203).unwrap();
    buf.write_u32(0x04050607).unwrap();
    println!("PacketBuffer: {} bytes written, remaining={}", buf.len(), buf.remaining());

    buf.reset();
    assert!(buf.is_empty());
    println!("PacketBuffer reset OK");

    //--------------------------------------------------------------------------
    // TUID
    //--------------------------------------------------------------------------
    let tuid = TUID::from_hex(b"534C00000001").unwrap();
    let hex = tuid.to_hex_upper();
    let hex_str = core::str::from_utf8(&hex).unwrap();
    assert_eq!(hex_str, "534C00000001");
    println!("TUID: {} -> {}", hex_str, hex_str);

    //--------------------------------------------------------------------------
    // SigNetOptions
    //--------------------------------------------------------------------------
    let opts = SigNetOptions::default();
    assert_eq!(opts.security_mode, 0);
    assert_eq!(opts.hmac, [0u8; 32]);
    println!("SigNetOptions: security_mode={}", opts.security_mode);

    //--------------------------------------------------------------------------
    // Receiver state
    //--------------------------------------------------------------------------
    let state = ReceiverSenderState::default();
    println!("Receiver state: {} packets received", state.total_packets_received);

    let stats = ReceiverStatistics::default();
    println!("Receiver stats: {} packets total", stats.total_packets);

    //--------------------------------------------------------------------------
    // Multicast address
    //--------------------------------------------------------------------------
    let addr = calculate_multicast_address(1).unwrap();
    assert_eq!(addr, [239, 254, 0, 1]);
    println!("Multicast (universe 1): {}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);

    let addr = calculate_multicast_address(517).unwrap();
    assert_eq!(addr, [239, 254, 0, 17]);
    println!("Multicast (universe 517): {}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);

    // Out of range
    assert!(calculate_multicast_address(0).is_err());
    assert!(calculate_multicast_address(64000).is_err());
    println!("Multicast out-of-range: correctly rejected");

    //--------------------------------------------------------------------------
    // Sequence
    //--------------------------------------------------------------------------
    assert_eq!(increment_sequence(1), 2);
    assert_eq!(increment_sequence(0xFFFFFFFF), 1);
    assert!(!should_increment_session(100));
    assert!(should_increment_session(0xFFFFFFFF));
    println!("Sequence: increment + rollover OK");

    //--------------------------------------------------------------------------
    // TLVBlock
    //--------------------------------------------------------------------------
    let data = [0x00, 0xFF, 0x7F];
    let tlv = TLVBlock { type_id: TID_LEVEL, value: &data };
    assert_eq!(tlv.length(), 3);
    println!("TLV block: type=0x{:04X} length={}", tlv.type_id, tlv.length());

    //--------------------------------------------------------------------------
    // CoAP + URI options (available even without crypto feature)
    //--------------------------------------------------------------------------
    let mut pb = PacketBuffer::new();
    coap::build_coap_header(&mut pb, 100).unwrap();
    assert_eq!(pb.len(), 4);
    println!("CoAP header built: {} bytes", pb.len());

    let mut uri_buf = [0u8; 96];
    let uri_len = coap::build_uri_string(1, "local", &mut uri_buf).unwrap();
    let uri = core::str::from_utf8(&uri_buf[..uri_len]).unwrap();
    assert_eq!(uri, "/sig-net/v1/local/level/1");
    println!("URI string: {}", uri);

    //--------------------------------------------------------------------------
    // TLV encoding (available without crypto)
    //--------------------------------------------------------------------------
    let mut tlv_buf = PacketBuffer::new();
    tlv::encode_tid_sync(&mut tlv_buf).unwrap();
    assert_eq!(tlv_buf.len(), 4);
    println!("TID_SYNC TLV: {} bytes", tlv_buf.len());

    let dmx = [0x00, 0x40, 0x80, 0xFF];
    let mut dmx_buf = PacketBuffer::new();
    tlv::encode_tid_level(&mut dmx_buf, &dmx).unwrap();
    println!("TID_LEVEL TLV ({} slots): {} bytes", dmx.len(), dmx_buf.len());

    //--------------------------------------------------------------------------
    // Parse (available without crypto)
    //--------------------------------------------------------------------------
    let packet = [0x50, 0x02, 0x00, 0x01];

    // Parse hex bytes
    let mut out = [0u8; 3];
    parse::parse_hex_bytes(b"AABBCC", &mut out, 3).unwrap();
    assert_eq!(out, [0xAA, 0xBB, 0xCC]);
    println!("Hex parse AABBCC: OK");

    let mut reader = parse::PacketReader::new(&packet, 4);
    let h = reader.parse_coap_header().unwrap();
    assert_eq!(h.version, 1);
    assert_eq!(h.code, COAP_CODE_POST);
    assert_eq!(h.message_id, 1);
    println!("Parse CoAP header: ver={} code=POST msg_id={}", h.version, h.message_id);

    println!("\n=== Core types example passed ===");
}
