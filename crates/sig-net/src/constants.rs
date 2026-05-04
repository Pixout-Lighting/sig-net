pub const COAP_VERSION: u8 = 1;
pub const COAP_TYPE_CON: u8 = 0;
pub const COAP_TYPE_NON: u8 = 1;
pub const COAP_TYPE_ACK: u8 = 2;
pub const COAP_TYPE_RST: u8 = 3;
pub const COAP_CODE_EMPTY: u8 = 0x00;
pub const COAP_CODE_GET: u8 = 0x01;
pub const COAP_CODE_POST: u8 = 0x02;
pub const COAP_CODE_PUT: u8 = 0x03;
pub const COAP_CODE_DELETE: u8 = 0x04;
pub const COAP_OPTION_URI_PATH: u16 = 11;
pub const COAP_OPTION_INLINE_MAX: u8 = 12;
pub const COAP_OPTION_EXT8_NIBBLE: u8 = 13;
pub const COAP_OPTION_EXT16_NIBBLE: u8 = 14;
pub const COAP_OPTION_EXT8_BASE: u16 = 13;
pub const COAP_OPTION_EXT16_BASE: u16 = 269;
pub const COAP_PAYLOAD_MARKER: u8 = 0xFF;

pub const SIGNET_OPTION_SECURITY_MODE: u16 = 2076;
pub const SIGNET_OPTION_SENDER_ID: u16 = 2108;
pub const SIGNET_OPTION_MFG_CODE: u16 = 2140;
pub const SIGNET_OPTION_SESSION_ID: u16 = 2172;
pub const SIGNET_OPTION_SEQ_NUM: u16 = 2204;
pub const SIGNET_OPTION_HMAC: u16 = 2236;
pub const SECURITY_MODE_HMAC_SHA256: u8 = 0x00;
pub const SECURITY_MODE_OPEN_MODE: u8 = 0x01;
pub const SECURITY_MODE_UNPROVISIONED: u8 = 0xFF;

pub const TID_POLL: u16 = 0x0001;
pub const TID_POLL_REPLY: u16 = 0x0002;
/// TID_POLL value length: 3×TUID(6) + soem_code(4) + endpoint(2) + query(1) = 25
pub const TID_POLL_VALUE_LEN: u16 = 25;
/// TID_POLL_REPLY value length: TUID(6) + soem_code(4) + change_count(2) = 12
pub const TID_POLL_REPLY_VALUE_LEN: u16 = 12;
pub const TID_LEVEL: u16 = 0x0101;
pub const TID_PRIORITY: u16 = 0x0102;
pub const TID_PREVIEW: u16 = 0x0103;
pub const TID_SYNC: u16 = 0x0201;
pub const TID_TIMECODE: u16 = 0x0202;
pub const TID_UNIVERSE: u16 = 0x0203;
pub const TID_RDM_COMMAND: u16 = 0x0301;
pub const TID_RDM_RESPONSE: u16 = 0x0302;
pub const TID_RDM_TOD_CONTROL: u16 = 0x0303;
pub const TID_RDM_TOD_DATA: u16 = 0x0304;
pub const TID_RDM_TOD_BACKGROUND: u16 = 0x0305;
pub const TID_RDM_FLOW_CONTROL: u16 = 0x0306;
pub const TID_RT_OFFBOARD: u16 = 0x0401;
pub const TID_NW_MAC_ADDRESS: u16 = 0x0501;
pub const TID_NW_IPV4_MODE: u16 = 0x0502;
pub const TID_NW_IPV4_ADDRESS: u16 = 0x0503;
pub const TID_NW_IPV4_NETMASK: u16 = 0x0504;
pub const TID_NW_IPV4_GATEWAY: u16 = 0x0505;
pub const TID_NW_IPV4_CURRENT: u16 = 0x0506;
pub const TID_NW_IPV6_MODE: u16 = 0x0581;
pub const TID_NW_IPV6_ADDRESS: u16 = 0x0582;
pub const TID_NW_IPV6_PREFIX: u16 = 0x0583;
pub const TID_NW_IPV6_GATEWAY: u16 = 0x0584;
pub const TID_NW_IPV6_CURRENT: u16 = 0x0585;
pub const TID_RT_SUPPORTED_TIDS: u16 = 0x0601;
pub const TID_RT_ENDPOINT_COUNT: u16 = 0x0602;
pub const TID_RT_PROTOCOL_VERSION: u16 = 0x0603;
pub const TID_RT_FIRMWARE_VERSION: u16 = 0x0604;
pub const TID_RT_DEVICE_LABEL: u16 = 0x0605;
pub const TID_RT_MULT_OVERRIDE: u16 = 0x0606;
pub const TID_RT_IDENTIFY: u16 = 0x0607;
pub const TID_RT_STATUS: u16 = 0x0608;
pub const TID_RT_ROLE_CAPABILITY: u16 = 0x0609;
pub const TID_RT_REBOOT: u16 = 0x060A;
pub const TID_RT_MODEL_NAME: u16 = 0x060B;
pub const TID_RT_SCOPE: u16 = 0x060C;
pub const TID_RT_OTW_CAPABILITY: u16 = 0x060D;
pub const TID_EP_UNIVERSE: u16 = 0x0901;
pub const TID_EP_LABEL: u16 = 0x0902;
pub const TID_EP_MULT_OVERRIDE: u16 = 0x0903;
pub const TID_EP_CAPABILITY: u16 = 0x0904;
pub const TID_EP_DIRECTION: u16 = 0x0905;
pub const TID_EP_INPUT_PRIORITY: u16 = 0x0906;
pub const TID_EP_STATUS: u16 = 0x0907;
pub const TID_EP_FAILOVER: u16 = 0x0908;
pub const TID_EP_DMX_TIMING: u16 = 0x0909;
pub const TID_EP_REFRESH_CAPABILITY: u16 = 0x090A;
pub const TID_DG_SECURITY_EVENT: u16 = 0xFF01;
pub const TID_DG_MESSAGE: u16 = 0xFF02;
pub const TID_DG_LEVEL_FOLDBACK: u16 = 0xFF03;

pub const QUERY_HEARTBEAT: u8 = 0x00;
pub const QUERY_CONFIG: u8 = 0x01;
pub const QUERY_FULL: u8 = 0x02;
pub const QUERY_EXTENDED: u8 = 0x03;

pub const SIGNET_UDP_PORT: u16 = 5683;
pub const MULTICAST_BASE_OCTET_0: u8 = 239;
pub const MULTICAST_BASE_OCTET_1: u8 = 254;
pub const MULTICAST_BASE_OCTET_2: u8 = 0;
pub const MULTICAST_MIN_INDEX: u8 = 1;
pub const MULTICAST_MAX_INDEX: u8 = 100;
pub const MULTICAST_TTL: u8 = 32;

pub const MAX_DMX_SLOTS: u16 = 512;
pub const MIN_UNIVERSE: u16 = 1;
pub const MAX_UNIVERSE: u16 = 63999;
pub const MAX_UDP_PAYLOAD: u16 = 1400;
pub const COAP_HEADER_SIZE: u16 = 4;
pub const URI_STRING_MIN_BUFFER: u16 = 96;

pub const MAX_ACTIVE_RATE_HZ: u32 = 44;
pub const KEEPALIVE_RATE_HZ: u32 = 1;
pub const STREAM_LOSS_TIMEOUT_MS: u32 = 3000;

// Protocol timing constants (§16 Appendix B)
pub const POLL_BACKOFF_MAX_MS: u32 = 1000;
pub const POLL_TIME_SECS: u32 = 3;
pub const NODE_LOST_TIMEOUT_POLLS: u32 = 3;
pub const UNIVERSE_LOST_TIMEOUT_SECS: u32 = 3;
pub const OFFBOARD_LOCKOUT_SECS: u32 = 300;
pub const SYNC_LOST_TIMEOUT_MS: u32 = 250;
pub const IP_ROLLBACK_TIMER_SECS: u32 = 60;
pub const TIMECODE_LOST_TIMEOUT_SECS: u32 = 1;
pub const MANAGER_POLL_JITTER_MS: u32 = 500;
pub const BEACON_MIN_INTERVAL_SECS: u32 = 5;
pub const BEACON_TIMEOUT_SECS: u32 = 30;
pub const NODE_PROCESSING_MAX_MS: u32 = 500;
pub const ENDPOINT_SPACING_DELAY_MS: u32 = 1;
pub const UNIVERSE_ANNOUNCE_INTERVAL_SECS: u32 = 5;
pub const STATUS_PUBLISH_RATE_SECS: u32 = 1;

pub const K0_KEY_LENGTH: usize = 32;
pub const DERIVED_KEY_LENGTH: usize = 32;
pub const HMAC_SHA256_LENGTH: usize = 32;
pub const TUID_LENGTH: usize = 6;
pub const TUID_HEX_LENGTH: usize = 12;
pub const SOEM_CODE_LENGTH: usize = 4;
pub const SENDER_ID_LENGTH: usize = 8;
pub const HKDF_INFO_INPUT_MAX: usize = 63;
/// Maximum HMAC input size: URI(96) + options(19) + MAX_UDP_PAYLOAD(1400) = 1515
pub const HMAC_INPUT_MAX: usize = 1600;

pub const SIGNET_URI_PREFIX: &str = "sig-net";
pub const SIGNET_URI_VERSION: &str = "v1";
pub const SIGNET_URI_SCOPE_DEFAULT: &str = "local";
pub const SIGNET_URI_LEVEL: &str = "level";
pub const SIGNET_URI_PRIORITY: &str = "priority";
pub const SIGNET_URI_SYNC: &str = "sync";
pub const SIGNET_URI_NODE: &str = "node";
pub const SIGNET_URI_POLL: &str = "poll";

pub const MULTICAST_NODE_SEND_IP: &str = "239.254.255.253";
pub const MULTICAST_MANAGER_POLL_IP: &str = "239.254.255.252";
pub const MULTICAST_MANAGER_SEND_IP: &str = "239.254.255.251";
pub const MULTICAST_TIME_IP: &str = "239.254.255.250";
pub const MULTICAST_NODE_BEACON_IP: &str = "239.254.255.255";
pub const MULTICAST_NODE_LOST_IP: &str = "239.254.255.254";
pub const MULTICAST_PREVIEW_IP: &str = "239.254.255.249";

pub const HKDF_INFO_SENDER: &[u8] = b"Sig-Net-Sender-v1";
pub const HKDF_INFO_CITIZEN: &[u8] = b"Sig-Net-Citizen-v1";
pub const HKDF_INFO_MANAGER_GLOBAL: &[u8] = b"Sig-Net-Manager-v1";
pub const HKDF_INFO_MANAGER_LOCAL_PREFIX: &[u8] = b"Sig-Net-Manager-v1-";

pub const PBKDF2_SALT: &[u8] = b"Sig-Net-K0-Salt-v1";
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const PASSPHRASE_MIN_LENGTH: usize = 10;
pub const PASSPHRASE_MAX_LENGTH: usize = 64;
pub const PASSPHRASE_GENERATED_LENGTH: usize = 10;

pub const TEST_K0: &str = "52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173";
pub const TEST_PASSPHRASE: &str = "Ge2p$E$4*A";
pub const TEST_TUID: &str = "534C00000001";

pub const ROLE_CAP_NODE: u8 = 0x01;
pub const ROLE_CAP_SENDER: u8 = 0x02;
pub const ROLE_CAP_MANAGER: u8 = 0x04;
pub const ROLE_VISUALISER: u8 = 0x08;

pub const UNPROVISION_MAGIC_WORD: u32 = 0x57495045;
pub const REBOOT_MAGIC_WORD: u32 = 0x424F4F54;

pub const PASSPHRASE_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:',.<>?/";
pub const PASSPHRASE_GEN_UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
pub const PASSPHRASE_GEN_LOWERCASE: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
pub const PASSPHRASE_GEN_DIGITS: &[u8] = b"23456789";
pub const PASSPHRASE_GEN_SYMBOLS: &[u8] = b"!@#$%^&*-_=+";

// Deprecated aliases (backward compatibility)
#[deprecated(since = "0.18.0", note = "renamed to TID_RT_OFFBOARD per spec §11.4.1")]
pub use TID_RT_OFFBOARD as TID_RT_UNPROVISION;
#[deprecated(since = "0.18.0", note = "renamed to TID_RT_MULT_OVERRIDE per spec §11.6.6")]
pub use TID_RT_MULT_OVERRIDE as TID_RT_MULT;
#[deprecated(since = "0.19.0", note = "renamed to TID_UNIVERSE per spec")]
pub use TID_UNIVERSE as TID_PATCH;
