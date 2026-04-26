use sig_net::*;

#[test]
fn rfc_4231_test_case_1() {
    let key = [0x0Bu8; 20];
    let data = b"Hi There";
    let expected_hex = "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7";

    let mut output = [0u8; HMAC_SHA256_LENGTH];
    sig_net::crypto::hmac_sha256(&key, data, &mut output).unwrap();

    let out_hex: String = output.iter().map(|b| format!("{:02X}", b)).collect();
    assert_eq!(out_hex, expected_hex, "RFC 4231 Test Case 1 failed");
}

#[test]
fn rfc_4231_test_case_2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected_hex = "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843";

    let mut output = [0u8; HMAC_SHA256_LENGTH];
    sig_net::crypto::hmac_sha256(key, data, &mut output).unwrap();

    let out_hex: String = output.iter().map(|b| format!("{:02X}", b)).collect();
    assert_eq!(out_hex, expected_hex, "RFC 4231 Test Case 2 failed");
}

#[test]
fn hkdf_expand_basic() {
    let prk = [0x0Bu8; 32];
    let info = b"Sig-Net-Sender-v1";
    let mut output = [0u8; DERIVED_KEY_LENGTH];

    sig_net::crypto::hkdf_expand(&prk, info, &mut output).unwrap();
    assert_ne!(output, [0u8; DERIVED_KEY_LENGTH]);
}

#[test]
fn pbkdf2_k0_derivation() {
    let passphrase = b"Ge2p$E$4*A";
    let mut k0 = [0u8; K0_KEY_LENGTH];

    sig_net::crypto::derive_k0_from_passphrase(passphrase, &mut k0).unwrap();

    let expected_hex = "52FCC2E7749F40358BA00B1D557DC11861E89868E139F23014F6A0CFE59CF173";
    let k0_hex: String = k0.iter().map(|b| format!("{:02X}", b)).collect();
    assert_eq!(k0_hex, expected_hex, "K0 derivation from TEST_PASSPHRASE failed");
}

#[test]
fn key_derivation_chain() {
    let mut k0 = [0u8; K0_KEY_LENGTH];
    sig_net::crypto::generate_random_k0(&mut k0).unwrap();

    let mut sender_key = [0u8; DERIVED_KEY_LENGTH];
    sig_net::crypto::derive_sender_key(&k0, &mut sender_key).unwrap();

    let mut citizen_key = [0u8; DERIVED_KEY_LENGTH];
    sig_net::crypto::derive_citizen_key(&k0, &mut citizen_key).unwrap();

    assert_ne!(sender_key, citizen_key);
    assert_ne!(sender_key, [0u8; DERIVED_KEY_LENGTH]);
    assert_ne!(citizen_key, [0u8; DERIVED_KEY_LENGTH]);
}

#[test]
fn coap_header_roundtrip() {
    let header = CoAPHeader::new(42);
    let bytes = header.to_bytes();
    let parsed = CoAPHeader::from_bytes(&bytes);

    assert_eq!(header.version, parsed.version);
    assert_eq!(header.type_, parsed.type_);
    assert_eq!(header.token_length, parsed.token_length);
    assert_eq!(header.code, parsed.code);
    assert_eq!(header.message_id, parsed.message_id);
}

#[test]
fn packet_buffer_basic() {
    let mut buf = PacketBuffer::new();
    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());

    buf.write_byte(0x01).unwrap();
    buf.write_u16(0x0203).unwrap();
    buf.write_u32(0x04050607).unwrap();

    assert_eq!(buf.len(), 7);
    assert_eq!(buf.as_slice(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
}

#[test]
fn packet_buffer_overflow() {
    let mut buf = PacketBuffer::new();
    let large = vec![0u8; MAX_UDP_PAYLOAD as usize + 1];
    assert!(buf.write_bytes(&large).is_err());
}

#[test]
fn tuid_hex_roundtrip() {
    let original = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let tuid = TUID(original);
    let hex = tuid.to_hex();
    let hex_str = core::str::from_utf8(&hex).unwrap();
    assert_eq!(hex_str, "123456789ABC");

    let parsed = TUID::from_hex(&hex).unwrap();
    assert_eq!(parsed.0, original);
}

#[test]
fn passphrase_validation_valid() {
    assert!(sig_net::crypto::validate_passphrase(b"Ge2p$E$4*A").is_ok());
}

#[test]
fn passphrase_validation_too_short() {
    assert!(sig_net::crypto::validate_passphrase(b"Ab1!x").is_err());
}

#[test]
fn passphrase_validation_too_long() {
    let long = vec![b'A'; 65];
    assert!(sig_net::crypto::validate_passphrase(&long).is_err());
}

#[test]
fn passphrase_validation_insufficient_classes() {
    assert!(sig_net::crypto::validate_passphrase(b"abcdefghij").is_err());
    assert!(sig_net::crypto::validate_passphrase(b"ABCDEFGHIJ").is_err());
    assert!(sig_net::crypto::validate_passphrase(b"1234567890").is_err());
}

#[test]
fn increment_sequence_basic() {
    assert_eq!(increment_sequence(1), 2);
    assert_eq!(increment_sequence(100), 101);
}

#[test]
fn increment_sequence_rollover() {
    assert_eq!(increment_sequence(0xFFFFFFFF), 1);
}

#[test]
fn multicast_address_calculation() {
    let octets = calculate_multicast_address(1).unwrap();
    assert_eq!(octets, [239, 254, 0, 1]);

    let octets = calculate_multicast_address(100).unwrap();
    assert_eq!(octets, [239, 254, 0, 100]);

    let octets = calculate_multicast_address(101).unwrap();
    assert_eq!(octets, [239, 254, 0, 1]);

    let octets = calculate_multicast_address(517).unwrap();
    assert_eq!(octets, [239, 254, 0, 17]);
}

#[test]
fn multicast_address_out_of_range() {
    assert!(calculate_multicast_address(0).is_err());
    assert!(calculate_multicast_address(64000).is_err());
}

#[test]
fn parse_hex_bytes_basic() {
    let mut out = [0u8; 3];
    sig_net::parse::parse_hex_bytes(b"AABBCC", &mut out, 3).unwrap();
    assert_eq!(out, [0xAA, 0xBB, 0xCC]);
}

#[test]
fn parse_hex_bytes_with_prefix() {
    let mut out = [0u8; 2];
    sig_net::parse::parse_hex_bytes(b"0x1234", &mut out, 2).unwrap();
    assert_eq!(out, [0x12, 0x34]);
}

#[test]
fn ephemeral_tuid_generation() {
    let tuid = sig_net::crypto::generate_ephemeral_tuid(0x534C).unwrap();
    assert_eq!(tuid[0], 0x53);
    assert_eq!(tuid[1], 0x4C);
    assert!(tuid[2] >= 0x80);
}

#[test]
fn generate_random_k0() {
    let mut k0 = [0u8; K0_KEY_LENGTH];
    sig_net::crypto::generate_random_k0(&mut k0).unwrap();
    assert_ne!(k0, [0u8; K0_KEY_LENGTH]);
}

#[test]
fn generate_random_passphrase() {
    let mut buf = [0u8; 11];
    sig_net::crypto::generate_random_passphrase(&mut buf).unwrap();
    let len = buf.iter().position(|&b| b == 0).unwrap_or(10);
    assert!(len >= 10);
    assert!(sig_net::crypto::validate_passphrase(&buf[..len]).is_ok());
}

fn make_test_options(key: &[u8], uri: &str, payload: &[u8]) -> SigNetOptions {
    let mut options = SigNetOptions::default();
    options.security_mode = SECURITY_MODE_HMAC_SHA256;
    options.sender_id = [0x01u8; 8];
    options.mfg_code = 0x1234;
    options.session_id = 1;
    options.seq_num = 1;
    sig_net::crypto::calculate_and_encode_hmac(uri, &mut options, payload, key).unwrap();
    options
}

#[test]
fn constant_time_hmac_verify() {
    let key = [0x0Bu8; 32];
    let uri = "/sig-net/v1/local/level/1";
    let payload = b"test data";
    let options = make_test_options(&key, uri, payload);

    let result = sig_net::crypto::verify_packet_hmac(uri, &options, payload, &key);
    assert!(result.is_ok());
}

#[test]
fn constant_time_hmac_reject() {
    let key = [0x0Bu8; 32];
    let mut options = SigNetOptions::default();
    options.hmac = [0xFFu8; HMAC_SHA256_LENGTH];

    let result = sig_net::crypto::verify_packet_hmac(
        "/sig-net/v1/local/level/1",
        &options,
        b"test data",
        &key,
    );
    assert!(result.is_err());
}
