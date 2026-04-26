//==============================================================================
// sig-net — Full Protocol Example (DMX Level Transmitter)
//==============================================================================
//
// Build:
//   cargo run -p sig-net --example full
//
// Demonstrates full usage with default features (crypto + net):
//   sig-net = { version = "0.5", default-features = true }
//==============================================================================

use sig_net::*;

fn main() {
    println!("=== Sig-Net Full Protocol Example ===\n");

    //--------------------------------------------------------------------------
    // 1. Setup: K0 → role keys
    //--------------------------------------------------------------------------
    let mut k0 = [0u8; K0_KEY_LENGTH];
    crypto::derive_k0_from_passphrase(b"Ge2p$E$4*A", &mut k0).unwrap();
    println!("K0 root key: derived from passphrase");

    let mut sender_key = [0u8; DERIVED_KEY_LENGTH];
    crypto::derive_sender_key(&k0, &mut sender_key).unwrap();
    println!("Sender key: derived");

    //--------------------------------------------------------------------------
    // 2. Build a DMX level packet
    //--------------------------------------------------------------------------
    let tuid = TUID::from_hex(b"534C00000001").unwrap();
    let dmx_data: Vec<u8> = (0..64).map(|i| (i * 4) as u8).collect();

    let mut buf = PacketBuffer::new();

    send::build_dmx_packet(
        &mut buf,           // packet buffer
        1,                  // universe
        &dmx_data,          // DMX slot values (64 slots)
        &tuid.0,            // transmitter TUID
        0,                  // endpoint
        0x0000,             // manufacturer code (standard)
        1,                  // session ID
        1,                  // sequence number
        &sender_key,        // signing key
        1,                  // CoAP message ID
    ).unwrap();

    println!("DMX packet: {} bytes", buf.len());
    print!("Hex dump (first 48 bytes): ");
    for (i, &b) in buf.as_slice().iter().enumerate().take(48) {
        print!("{:02X}", b);
        if (i + 1) % 2 == 0 { print!(" "); }
    }
    println!();

    // Verify CoAP header
    let coap_header = CoAPHeader::from_bytes(&{
        let mut h = [0u8; 4];
        h.copy_from_slice(&buf.as_slice()[..4]);
        h
    });
    assert_eq!(coap_header.version, 1);
    assert_eq!(coap_header.code, COAP_CODE_POST);
    assert_eq!(coap_header.message_id, 1);
    println!("CoAP header: version=1 type=NON code=POST message_id=1");

    //--------------------------------------------------------------------------
    // 3. Build an announce packet
    //--------------------------------------------------------------------------
    let mut announce_buf = PacketBuffer::new();
    send::build_announce_packet(
        &mut announce_buf,
        &tuid.0,
        0x534C,
        0x0001,
        0x0001,
        "Sig-Net Node v1.0",
        0x01,
        ROLE_CAP_SENDER,
        0,
        1,
        1,
        &sender_key,
        2,
    ).unwrap();
    println!("Announce packet: {} bytes", announce_buf.len());

    //--------------------------------------------------------------------------
    // 4. Build a poll packet
    //--------------------------------------------------------------------------
    let mgr_tuid = TUID::from_hex(b"534C00000002").unwrap();
    let mgr_key = {
        let mut k = [0u8; 32];
        crypto::derive_manager_global_key(&k0, &mut k).unwrap();
        k
    };
    let mut poll_buf = PacketBuffer::new();
    send::build_poll_packet(
        &mut poll_buf,
        &mgr_tuid.0,
        0x534C,
        0x0001,
        &[0u8; 6],  // tuid_lo (broadcast)
        &[0xFFu8; 6], // tuid_hi (broadcast)
        0xFFFF,     // all endpoints
        QUERY_HEARTBEAT,
        1,
        1,
        &mgr_key,
        1,
    ).unwrap();
    println!("Poll packet: {} bytes", poll_buf.len());

    //--------------------------------------------------------------------------
    // 5. Parse a packet
    //--------------------------------------------------------------------------
    // --- Parse from beginning with a fresh reader ---
    let packet = buf.as_slice();
    let packet_len = buf.len();

    // Parse CoAP header
    let mut reader = parse::PacketReader::new(packet, packet_len);
    let parsed_header = reader.parse_coap_header().unwrap();
    println!("Parsed CoAP header: ver={} type={} code=0x{:02X} msg_id={}",
        parsed_header.version, parsed_header.type_, parsed_header.code, parsed_header.message_id);

    // Extract URI (consumes Uri-Path options)
    reader.skip_token(parsed_header.token_length).unwrap();
    let mut uri_buf = [0u8; 96];
    let uri_len = reader.extract_uri_string(&mut uri_buf).unwrap();
    let uri_str = core::str::from_utf8(&uri_buf[..uri_len]).unwrap();
    println!("Extracted URI: {}", uri_str);

    // Parse SigNet options (fresh reader from start, skip header + token)
    let mut opt_reader = parse::PacketReader::new(packet, packet_len);
    opt_reader.parse_coap_header().unwrap();
    opt_reader.skip_token(parsed_header.token_length).unwrap();
    let parsed_options = opt_reader.parse_signet_options().unwrap();
    println!("SigNet options: sec_mode={} sender_hmac_len={}", 
        parsed_options.security_mode, parsed_options.hmac.len());

    //--------------------------------------------------------------------------
    // 6. UDP multicast (dry-run: no real send)
    //--------------------------------------------------------------------------
    let addr = calculate_multicast_address(1).unwrap();
    println!("\nTarget multicast: {}.{}.{}.{}:{}",
        addr[0], addr[1], addr[2], addr[3], SIGNET_UDP_PORT);
    println!("DMX slots: {}", dmx_data.len());
    println!("Session: 1, Sequence: 1");

    // Create socket (no actual I/O in this example)
    println!("\nTo send on real hardware:");
    println!("  use net::UdpMulticastSocket::bind(5683)");
    println!("  socket.join_multicast_group(...)");
    println!("  socket.send_multicast(packet, universe)");

    println!("\n=== Full protocol example passed ===");
}
