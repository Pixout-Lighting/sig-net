//==============================================================================
// sig-net — Cryptography Example
//==============================================================================
//
// Build:
//   cargo run -p sig-net --example crypto
//
// Demonstrates usage with crypto feature:
//   sig-net = { version = "0.5", features = ["crypto"] }
//==============================================================================

use sig_net::*;

fn main() {
    println!("=== Sig-Net Cryptography Example ===\n");

    //--------------------------------------------------------------------------
    // 1. HMAC-SHA256 (RFC 4231 Test Case 1)
    //--------------------------------------------------------------------------
    let key = [0x0Bu8; 20];
    let data = b"Hi There";
    let expected = "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7";

    let mut hmac = [0u8; HMAC_SHA256_LENGTH];
    crypto::hmac_sha256(&key, data, &mut hmac).unwrap();

    let hex: String = hmac.iter().map(|b| format!("{:02X}", b)).collect();
    assert_eq!(hex, expected);
    println!("HMAC-SHA256 (RFC 4231 TC1): {}", hex);

    //--------------------------------------------------------------------------
    // 2. HKDF-Expand
    //--------------------------------------------------------------------------
    let prk = [0x0Bu8; 32];
    let mut okm = [0u8; DERIVED_KEY_LENGTH];
    crypto::hkdf_expand(&prk, HKDF_INFO_SENDER, &mut okm).unwrap();
    assert_ne!(okm, [0u8; 32]);
    println!("HKDF-Expand (info=Sig-Net-Sender-v1): {} bytes derived", okm.len());

    //--------------------------------------------------------------------------
    // 3. PBKDF2 — K0 from passphrase
    //--------------------------------------------------------------------------
    let mut k0 = [0u8; K0_KEY_LENGTH];
    crypto::derive_k0_from_passphrase(b"Ge2p$E$4*A", &mut k0).unwrap();
    println!("PBKDF2 K0 derivation: OK (100k iterations)");

    //--------------------------------------------------------------------------
    // 4. Role key derivation
    //--------------------------------------------------------------------------
    let mut sender_key = [0u8; DERIVED_KEY_LENGTH];
    crypto::derive_sender_key(&k0, &mut sender_key).unwrap();
    println!("Sender key (Ks): derived");

    let mut citizen_key = [0u8; DERIVED_KEY_LENGTH];
    crypto::derive_citizen_key(&k0, &mut citizen_key).unwrap();
    println!("Citizen key (Kc): derived");

    let mut mgr_global_key = [0u8; DERIVED_KEY_LENGTH];
    crypto::derive_manager_global_key(&k0, &mut mgr_global_key).unwrap();
    println!("Manager global key (Km): derived");

    let tuid = TUID::from_hex(b"534C00000001").unwrap();
    let mut mgr_local_key = [0u8; DERIVED_KEY_LENGTH];
    crypto::derive_manager_local_key(&k0, &tuid.0, &mut mgr_local_key).unwrap();
    println!("Manager local key (Km_local): derived");

    assert_ne!(sender_key, citizen_key);
    assert_ne!(sender_key, mgr_global_key);
    println!("All role keys are distinct: OK");

    //--------------------------------------------------------------------------
    // 5. Passphrase validation
    //--------------------------------------------------------------------------
    assert!(crypto::validate_passphrase(b"Ge2p$E$4*A").is_ok());
    println!("Valid passphrase: ACCEPTED");

    assert!(crypto::validate_passphrase(b"weak").is_err());
    println!("Too short passphrase: REJECTED");

    assert!(crypto::validate_passphrase(b"abcdefghij").is_err());
    println!("One-class passphrase: REJECTED");

    // Passphrase analysis
    let checks = crypto::analyse_passphrase(b"Ge2p$E$4*A").unwrap();
    println!("Passphrase analysis: {} chars, {} classes, {} ok",
        checks.length, checks.class_count, if checks.classes_ok { "✓" } else { "✗" });

    //--------------------------------------------------------------------------
    // 6. TUID conversion
    //--------------------------------------------------------------------------
    let hex = tuid.to_hex();
    let hex_str = core::str::from_utf8(&hex).unwrap();
    assert_eq!(hex_str, "534C00000001");
    println!("TUID to hex: {}", hex_str);

    let back = crypto::tuid_from_hex_string(b"534C00000001").unwrap();
    assert_eq!(back, tuid.0);
    println!("TUID hex round-trip: OK");

    //--------------------------------------------------------------------------
    // 7. Ephemeral TUID generation
    //--------------------------------------------------------------------------
    let ep_tuid = crypto::generate_ephemeral_tuid(0x534C).unwrap();
    assert!(ep_tuid[2] >= 0x80);
    println!("Ephemeral TUID: {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        ep_tuid[0], ep_tuid[1], ep_tuid[2], ep_tuid[3], ep_tuid[4], ep_tuid[5]);

    //--------------------------------------------------------------------------
    // 8. Random key generation
    //--------------------------------------------------------------------------
    let mut rnd_k0 = [0u8; K0_KEY_LENGTH];
    crypto::generate_random_k0(&mut rnd_k0).unwrap();
    assert_ne!(rnd_k0, [0u8; K0_KEY_LENGTH]);
    println!("Random K0 generated");

    //--------------------------------------------------------------------------
    // 9. Random passphrase generation
    //--------------------------------------------------------------------------
    let mut rnd_pp = [0u8; 11];
    crypto::generate_random_passphrase(&mut rnd_pp).unwrap();
    let pp_len = rnd_pp.iter().position(|&b| b == 0).unwrap_or(10);
    let pp_str = core::str::from_utf8(&rnd_pp[..pp_len]).unwrap();
    assert!(crypto::validate_passphrase(pp_str.as_bytes()).is_ok());
    println!("Random passphrase: {}", pp_str);

    //--------------------------------------------------------------------------
    // 10. HMAC input / verify
    //--------------------------------------------------------------------------
    let mut opts = SigNetOptions::default();
    opts.security_mode = SECURITY_MODE_HMAC_SHA256;
    opts.sender_id = [0x01u8; 8];
    opts.mfg_code = 0x534C;
    opts.session_id = 1;
    opts.seq_num = 1;

    crypto::calculate_and_encode_hmac(
        "/sig-net/v1/local/level/1", &mut opts, b"payload data", &sender_key,
    ).unwrap();
    println!("HMAC calculated and encoded");

    let result = crypto::verify_packet_hmac(
        "/sig-net/v1/local/level/1", &opts, b"payload data", &sender_key,
    );
    assert!(result.is_ok());
    println!("HMAC verification: PASS");

    // Reject with wrong key
    let result = crypto::verify_packet_hmac(
        "/sig-net/v1/local/level/1", &opts, b"payload data", &citizen_key,
    );
    assert!(result.is_err());
    println!("HMAC verification with wrong key: REJECTED");

    println!("\n=== Cryptography example passed ===");
}
