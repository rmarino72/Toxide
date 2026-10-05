using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.NetCrypto;

internal enum CryptoConnectionStatus
{
    /// <summary>We are sending cookie requests.</summary>
    CookieRequesting = 1,

    /// <summary>We have a cookie and are sending handshakes.</summary>
    HandshakeSent,

    /// <summary>Handshakes exchanged; waiting for the first data packet to confirm the session.</summary>
    NotConfirmed,

    Established,
}

/// <summary>What we learn from a valid handshake of a peer we have no connection with yet.</summary>
internal sealed record NewConnection(
    IpPort Source,
    byte[] PublicKey,
    byte[] DhtPublicKey,
    byte[] ReceiveNonce,
    byte[] PeerSessionPublicKey,
    byte[] Cookie);

/// <summary>State of one net_crypto session (toxcore's Crypto_Connection, minus TCP).</summary>
internal sealed class CryptoConnection
{
    public CryptoConnection(int id, byte[] publicKey, byte[] dhtPublicKey, KeyPair sessionKeys)
    {
        Id = id;
        PublicKey = publicKey;
        DhtPublicKey = dhtPublicKey;
        SessionKeys = sessionKeys;
    }

    public int Id { get; }

    /// <summary>The peer's long-term (real) public key.</summary>
    public byte[] PublicKey { get; }

    public byte[] DhtPublicKey { get; set; }

    /// <summary>Fresh for every session: compromising long-term keys does not reveal past sessions.</summary>
    public KeyPair SessionKeys { get; }

    public byte[] PeerSessionPublicKey { get; set; } = new byte[CryptoConstants.PublicKeySize];

    /// <summary>During cookie requests: DHT shared key. Afterwards: session shared key.</summary>
    public byte[] SharedKey { get; set; } = new byte[CryptoConstants.SharedKeySize];

    public byte[] SentNonce { get; set; } = Nonce.Random();
    public byte[] ReceiveNonce { get; set; } = new byte[CryptoConstants.NonceSize];

    public CryptoConnectionStatus Status { get; set; }
    public ulong CookieRequestNumber { get; set; }

    /// <summary>The cookie request or handshake, resent every second until answered.</summary>
    public byte[]? TempPacket { get; set; }
    public long TempPacketSentTime { get; set; }
    public int TempPacketSendCount { get; set; }

    public IpPort? EndpointV4 { get; set; }
    public IpPort? EndpointV6 { get; set; }
    public DateTimeOffset LastReceivedV4 { get; set; } = DateTimeOffset.UnixEpoch;
    public DateTimeOffset LastReceivedV6 { get; set; } = DateTimeOffset.UnixEpoch;
    public DateTimeOffset DirectSendAttempt { get; set; } = DateTimeOffset.UnixEpoch;

    public PacketsArray SendArray { get; } = new();
    public PacketsArray ReceiveArray { get; } = new();

    // Callbacks set by friend_connection.
    public Action<bool>? StatusChanged { get; set; }
    public Action<byte[]>? DataReceived { get; set; }
    public Action<byte[]>? LossyReceived { get; set; }
    public Action<byte[]>? DhtPublicKeyChanged { get; set; }

    // Congestion control (all times in milliseconds).
    public long LastRequestPacketSent { get; set; }
    public uint PacketCounter { get; set; }
    public double PacketReceiveRate { get; set; }
    public long PacketCounterSet { get; set; }
    public double PacketSendRate { get; set; } = NetCrypto.MinPacketRate;
    public uint PacketsLeft { get; set; } = NetCrypto.MinQueueLength;
    public long LastPacketsLeftSet { get; set; }
    public double LastPacketsLeftRemainder { get; set; }
    public double PacketSendRateRequested { get; set; } = NetCrypto.MinPacketRate;
    public uint PacketsLeftRequested { get; set; }
    public long LastPacketsLeftRequestedSet { get; set; }
    public double LastPacketsLeftRequestedRemainder { get; set; }
    public uint[] LastSendQueueSize { get; } = new uint[NetCrypto.CongestionQueueArraySize];
    public uint LastSendQueueCounter { get; set; }
    public long[] LastNumPacketsSent { get; } = new long[NetCrypto.CongestionLastSentArraySize];
    public long[] LastNumPacketsResent { get; } = new long[NetCrypto.CongestionLastSentArraySize];
    public uint PacketsSent { get; set; }
    public uint PacketsResent { get; set; }
    public long LastCongestionEvent { get; set; }
    public long RttTime { get; set; } = NetCrypto.DefaultPingConnection;
    public bool MaximumSpeedReached { get; set; }
}
