namespace Toxide.Network;

/// <summary>
/// The first byte of every UDP packet identifies its kind, so the receiver knows which
/// component (DHT, onion, net_crypto, ...) must handle it.
/// Group chats, TCP relays and DHT announcements (0x5a-0x5c, 0x90-0x98) are not implemented.
/// </summary>
public enum PacketKind : byte
{
    // --- DHT (level 3) ---
    PingRequest = 0x00,
    PingResponse = 0x01,
    NodesRequest = 0x02,
    NodesResponse = 0x04,

    // --- net_crypto (level 7) ---
    CookieRequest = 0x18,
    CookieResponse = 0x19,
    CryptoHandshake = 0x1a,
    CryptoData = 0x1b,

    // --- DHT encrypted request routed to a node (NAT ping, ...) ---
    Crypto = 0x20,

    // --- LAN discovery (level 4) ---
    LanDiscovery = 0x21,

    // --- Onion (level 6) ---
    OnionSendInitial = 0x80,
    OnionSend1 = 0x81,
    OnionSend2 = 0x82,
    AnnounceRequest = 0x83,   // "old" format, still the one toxcore clients send
    AnnounceResponse = 0x84,
    OnionDataRequest = 0x85,
    OnionDataResponse = 0x86,
    AnnounceRequestNew = 0x87, // same request; the response carries an explicit node count
    AnnounceResponseNew = 0x88,
    OnionReceive3 = 0x8c,
    OnionReceive2 = 0x8d,
    OnionReceive1 = 0x8e,

    // --- Bootstrap node info (version / MOTD) ---
    BootstrapInfo = 0xf0,
}