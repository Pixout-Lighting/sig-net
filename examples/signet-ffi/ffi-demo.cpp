//==============================================================================
// sig-net C++ FFI Example — DMX Level Transmitter
//==============================================================================
//
// Build:
//   cd signet && cargo build -p signet-ffi --release
//   c++ -std=c++17 examples/cpp-dmx-tx.cpp \
//       -I include \
//       target/release/libsignet_ffi.a \
//       -o dmx-tx
//
// Run:
//   ./dmx-tx
//==============================================================================

#include "signet.h"
#include <cstdio>
#include <cstring>
#include <cassert>

// Hex dump helper
static void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%-30s ", label);
    for (int i = 0; i < len && i < 48; ++i)
        printf("%02X ", data[i]);
    if (len > 48) printf("...");
    printf(" (%d bytes)\n", len);
}

int main() {
    printf("=== Sig-Net C++ FFI Example ===\n\n");

    //--------------------------------------------------------------------------
    // 1. Derive K0 from passphrase (PBKDF2-HMAC-SHA256, 100k iterations)
    //--------------------------------------------------------------------------
    uint8_t k0[32];
    int32_t ret = signet_derive_k0_from_passphrase("Ge2p$E$4*A", 10, k0);
    assert(ret == 0 && "K0 derivation failed");
    print_hex("K0 (root key):", k0, 32);

    //--------------------------------------------------------------------------
    // 2. Derive role keys (HKDF-Expand)
    //--------------------------------------------------------------------------
    uint8_t sender_key[32];
    ret = signet_derive_sender_key(k0, sender_key);
    assert(ret == 0);
    print_hex("Ks (sender key):", sender_key, 32);

    uint8_t citizen_key[32];
    ret = signet_derive_citizen_key(k0, citizen_key);
    assert(ret == 0);
    print_hex("Kc (citizen key):", citizen_key, 32);

    uint8_t manager_key[32];
    ret = signet_derive_manager_global_key(k0, manager_key);
    assert(ret == 0);
    print_hex("Km (manager key):", manager_key, 32);

    //--------------------------------------------------------------------------
    // 3. Validate passphrase
    //--------------------------------------------------------------------------
    ret = signet_validate_passphrase("Ge2p$E$4*A", 10);
    printf("Passphrase validation:        %s\n", ret == 0 ? "PASS" : "FAIL");

    // Weak passphrase should fail
    ret = signet_validate_passphrase("weak", 4);
    printf("Weak passphrase rejection:    %s\n", ret != 0 ? "PASS" : "FAIL");

    //--------------------------------------------------------------------------
    // 4. Generate random K0
    //--------------------------------------------------------------------------
    uint8_t random_k0[32];
    ret = signet_generate_random_k0(random_k0);
    assert(ret == 0);
    print_hex("Random K0:", random_k0, 32);

    //--------------------------------------------------------------------------
    // 5. Generate random passphrase
    //--------------------------------------------------------------------------
    char passphrase[11] = {0};
    ret = signet_generate_random_passphrase(passphrase, 11);
    assert(ret == 0);
    printf("Random passphrase:            %s\n", passphrase);

    //--------------------------------------------------------------------------
    // 6. TUID hex conversion
    //--------------------------------------------------------------------------
    const uint8_t tuid_bytes[6] = {0x53, 0x4C, 0x00, 0x00, 0x00, 0x01};
    char tuid_hex[13] = {0};
    ret = signet_tuid_to_hex(tuid_bytes, tuid_hex);
    assert(ret == 0);
    printf("TUID to hex:                  %s\n", tuid_hex);

    uint8_t tuid_back[6];
    ret = signet_tuid_from_hex("534C00000001", tuid_back);
    assert(ret == 0 && memcmp(tuid_back, tuid_bytes, 6) == 0);
    printf("TUID hex round-trip:          PASS\n");

    //--------------------------------------------------------------------------
    // 7. Generate dynamic TUID
    //--------------------------------------------------------------------------
    uint8_t ep_tuid[6];
    ret = signet_generate_dynamic_tuid(0x534C, ep_tuid);
    assert(ret == 0);
    print_hex("Dynamic TUID:", ep_tuid, 6);

    //--------------------------------------------------------------------------
    // 8. Calculate multicast address
    //--------------------------------------------------------------------------
    char ip[16] = {0};
    ret = signet_calculate_multicast_address(1, ip, sizeof(ip));
    assert(ret == 0);
    printf("Multicast (universe 1):       %s\n", ip);

    ret = signet_calculate_multicast_address(517, ip, sizeof(ip));
    assert(ret == 0);
    printf("Multicast (universe 517):     %s\n", ip);

    //--------------------------------------------------------------------------
    // 9. HMAC-SHA256 (RFC 4231 Test Case 1)
    //--------------------------------------------------------------------------
    uint8_t key[20];
    memset(key, 0x0B, 20);
    const uint8_t* data = (const uint8_t*)"Hi There";
    uint8_t hmac[32];
    ret = signet_hmac_sha256(key, 20, data, 8, hmac);
    assert(ret == 0);
    print_hex("HMAC-SHA256 (RFC 4231 TC1):", hmac, 32);
    printf("Expected:                     B0344C61 D8DB3853 5CA8AFCE AF0BF12B "
           "881DC200 C9833DA7 26E9376C 2E32CFF7\n");

    //--------------------------------------------------------------------------
    // 10. HKDF-Expand
    //--------------------------------------------------------------------------
    uint8_t derived[32];
    const uint8_t* info = (const uint8_t*)"Sig-Net-Sender-v1";
    ret = signet_hkdf_expand(k0, 32, info, 17, derived);
    assert(ret == 0);
    print_hex("HKDF-Expand (sender):", derived, 32);

    printf("\n=== All FFI examples passed ===\n");
    return 0;
}
