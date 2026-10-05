using System.Buffers.Binary;
using System.Security.Cryptography;
using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Network;

namespace Toxide.NetCrypto;

/// <summary>
/// Encrypted, reliable sessions between two Tox identities (toxcore net_crypto.c), over UDP.
///
/// Connection setup (each side may start it; crossing handshakes are merged):
///   1. cookie request (0x18): "here is my real key", encrypted with the DHT keys;
///   2. cookie response (0x19): a cookie only the responder can open (stateless, like TCP SYN cookies);
///   3. handshake (0x1a): sent back with the cookie; carries our session key and base nonce,
///      encrypted with the long-term keys, so each side authenticates the other's Tox identity;
///   4. data (0x1b): encrypted with the session keys; the first data packet confirms the session.
///
/// Data packets carry, in clear, only the low 2 bytes of the nonce: both sides increment nonces
/// in lockstep, and the receiver reconstructs the full nonce from that hint.
///
/// Lossless packets (ids 16-191) are numbered, buffered and retransmitted on request (packet
/// kind 1, a bitmap of missing packets); lossy packets (192-254) are fire-and-forget.
/// TCP relays are not implemented: connections need direct UDP reachability (NAT punching helps).
/// </summary>
internal sealed class NetCrypto : IDisposable
{
    public const int MaxPacketSize = 1400;
    public const int DataPacketMinSize = 1 + sizeof(ushort) + sizeof(uint) * 2 + CryptoConstants.MacSize;
    public const int MaxDataSize = MaxPacketSize - DataPacketMinSize; // 1373

    public const byte PacketIdRequest = 1;
    public const byte PacketIdKill = 2;
    public const byte LosslessStart = 16;
    public const byte LosslessEnd = 191;
    public const byte LossyStart = 192;
    public const byte LossyEnd = 254;

    public const double MinPacketRate = 4.0;
    public const uint MinQueueLength = 64;
    public const int CongestionQueueArraySize = 12;
    public const int CongestionLastSentArraySize = CongestionQueueArraySize * 2;
    public const long DefaultPingConnection = 1000;

    private const int CookieDataLength = CryptoConstants.PublicKeySize * 2;
    private const int CookieContentsLength = sizeof(ulong) + CookieDataLength;
    private const int CookieLength = CryptoConstants.NonceSize + CookieContentsLength + CryptoConstants.MacSize; // 112
    private const int CookieRequestPlainLength = CookieDataLength + sizeof(ulong);
    private const int CookieRequestLength = 1 + CryptoConstants.PublicKeySize + CryptoConstants.NonceSize
                                            + CookieRequestPlainLength + CryptoConstants.MacSize;             // 145
    private const int CookieResponseLength = 1 + CryptoConstants.NonceSize + CookieLength + sizeof(ulong)
                                             + CryptoConstants.MacSize;                                        // 161
    private const int Sha512Size = 64;
    private const int HandshakeLength = 1 + CookieLength + CryptoConstants.NonceSize + CryptoConstants.NonceSize
                                        + CryptoConstants.PublicKeySize + Sha512Size + CookieLength
                                        + CryptoConstants.MacSize;                                             // 385
    private static readonly TimeSpan CookieTimeout = TimeSpan.FromSeconds(15);

    private const long SendPacketInterval = 1000;
    private const int MaxSendPacketTries = 8;
    private static readonly TimeSpan UdpDirectTimeout = TimeSpan.FromSeconds(8);
    private const int MaxPadding = 8;
    private const uint DataNumThreshold = 21845;
    private const int CookieRequestMaxTokens = 10;
    private const long CookieRequestTokenInterval = 100;
    private const long PacketCounterAverageInterval = 50;
    private const double RequestPacketsCompareConstant = 0.125 * 100.0;
    private const long CongestionEventTimeout = 1000;
    private const double SendQueueRatio = 2.0;

    private readonly DhtNode _dht;
    private readonly ICryptoCore _crypto;
    private readonly IPacketSender _sender;
    private readonly TimeProvider _time;
    private readonly KeyPair _identity;
    private readonly byte[] _cookieKey = CryptoExtensions.NewSymmetricKey();
    private readonly List<CryptoConnection?> _connections = [];
    private readonly Dictionary<IpPort, CryptoConnection> _byEndpoint = new();
    private long _cookieRequestLastTime;
    private int _cookieRequestTokens = CookieRequestMaxTokens;

    public NetCrypto(DhtNode dht, KeyPair identity, TimeProvider time)
    {
        _dht = dht;
        _crypto = dht.Crypto;
        _sender = dht.Sender;
        _time = time;
        _identity = identity;
        _cookieRequestLastTime = NowMs;
    }

    /// <summary>Called for a valid handshake from a peer we have no session with; returns true if accepted.</summary>
    public Func<NewConnection, bool>? NewConnectionHandler { get; set; }

    /// <summary>Milliseconds the caller may sleep before the next <see cref="Tick"/>.</summary>
    public long RunInterval { get; private set; } = SendPacketInterval;

    private DateTimeOffset Now => _time.GetUtcNow();
    private long NowMs => _time.GetUtcNow().ToUnixTimeMilliseconds();

    public void Attach(PacketDispatcher dispatcher)
    {
        dispatcher.Register(PacketKind.CookieRequest, HandleCookieRequest);
        dispatcher.Register(PacketKind.CookieResponse, HandleUdpPacket);
        dispatcher.Register(PacketKind.CryptoHandshake, HandleUdpPacket);
        dispatcher.Register(PacketKind.CryptoData, HandleUdpPacket);
    }

    public CryptoConnection? Get(int id) => id >= 0 && id < _connections.Count ? _connections[id] : null;

    private CryptoConnection? FindByPublicKey(ReadOnlySpan<byte> publicKey)
    {
        foreach (var conn in _connections)
            if (conn is not null && conn.PublicKey.AsSpan().SequenceEqual(publicKey))
                return conn;
        return null;
    }

    // ================================================================ cookies

    private byte[] CreateCookie(ReadOnlySpan<byte> realPublicKey, ReadOnlySpan<byte> dhtPublicKey)
    {
        var contents = new byte[CookieContentsLength];
        BinaryPrimitives.WriteUInt64LittleEndian(contents, (ulong)Now.ToUnixTimeSeconds());
        realPublicKey.CopyTo(contents.AsSpan(sizeof(ulong)));
        dhtPublicKey.CopyTo(contents.AsSpan(sizeof(ulong) + CryptoConstants.PublicKeySize));

        var nonce = Nonce.Random();
        var cookie = new byte[CookieLength];
        nonce.CopyTo(cookie, 0);
        _crypto.Encrypt(_cookieKey, nonce, contents).CopyTo(cookie, CryptoConstants.NonceSize);
        return cookie;
    }

    /// <summary>Returns [real key][DHT key] if the cookie is ours and less than 15 seconds old.</summary>
    private byte[]? OpenCookie(ReadOnlySpan<byte> cookie)
    {
        var contents = _crypto.Decrypt(_cookieKey, cookie[..CryptoConstants.NonceSize], cookie[CryptoConstants.NonceSize..CookieLength]);
        if (contents is null || contents.Length != CookieContentsLength)
            return null;

        ulong created = BinaryPrimitives.ReadUInt64LittleEndian(contents);
        ulong now = (ulong)Now.ToUnixTimeSeconds();
        if (created + (ulong)CookieTimeout.TotalSeconds < now || now < created)
            return null;

        return contents[sizeof(ulong)..];
    }

    /// <summary>[0x18][our DHT key][nonce][encrypted with DHT keys: our real key, 32 zeros, request number].</summary>
    private byte[]? CreateCookieRequest(CryptoConnection conn)
    {
        if (!_dht.TryGetSharedKey(conn.DhtPublicKey, out var sharedKey))
            return null;
        conn.SharedKey = sharedKey;

        var plain = new byte[CookieRequestPlainLength];
        _identity.PublicKey.CopyTo(plain, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(plain.AsSpan(CookieDataLength), conn.CookieRequestNumber);

        var nonce = Nonce.Random();
        var packet = new byte[CookieRequestLength];
        packet[0] = (byte)PacketKind.CookieRequest;
        _dht.PublicKey.CopyTo(packet, 1);
        nonce.CopyTo(packet, 1 + CryptoConstants.PublicKeySize);
        _crypto.Encrypt(sharedKey, nonce, plain).CopyTo(packet, 1 + CryptoConstants.PublicKeySize + CryptoConstants.NonceSize);
        return packet;
    }

    /// <summary>Answers any valid cookie request (rate limited): we keep no state until the handshake.</summary>
    private void HandleCookieRequest(IpPort source, ReadOnlySpan<byte> packet)
    {
        long now = NowMs;
        long newTokens = (now - _cookieRequestLastTime) / CookieRequestTokenInterval;
        if (newTokens > 0)
        {
            _cookieRequestTokens = (int)Math.Min(CookieRequestMaxTokens, _cookieRequestTokens + newTokens);
            _cookieRequestLastTime = _cookieRequestTokens == CookieRequestMaxTokens
                ? now
                : _cookieRequestLastTime + newTokens * CookieRequestTokenInterval;
        }
        if (_cookieRequestTokens == 0)
            return;
        _cookieRequestTokens--;

        if (packet.Length != CookieRequestLength)
            return;

        var senderDhtKey = packet.Slice(1, CryptoConstants.PublicKeySize).ToArray();
        if (!_dht.TryGetSharedKey(senderDhtKey, out var sharedKey))
            return;

        var plain = _crypto.Decrypt(sharedKey, packet.Slice(1 + CryptoConstants.PublicKeySize, CryptoConstants.NonceSize),
            packet[(1 + CryptoConstants.PublicKeySize + CryptoConstants.NonceSize)..]);
        if (plain is null || plain.Length != CookieRequestPlainLength)
            return;

        // The cookie binds the requester's real key and DHT key; the request number is echoed.
        var response = new byte[CookieLength + sizeof(ulong)];
        CreateCookie(plain.AsSpan(0, CryptoConstants.PublicKeySize), senderDhtKey).CopyTo(response, 0);
        plain.AsSpan(CookieDataLength, sizeof(ulong)).CopyTo(response.AsSpan(CookieLength));

        var nonce = Nonce.Random();
        var reply = new byte[CookieResponseLength];
        reply[0] = (byte)PacketKind.CookieResponse;
        nonce.CopyTo(reply, 1);
        _crypto.Encrypt(sharedKey, nonce, response).CopyTo(reply, 1 + CryptoConstants.NonceSize);
        _sender.Send(source, reply);
    }

    // ================================================================ handshake

    private byte[]? CreateHandshake(CryptoConnection conn, ReadOnlySpan<byte> cookie, byte[] peerDhtPublicKey)
    {
        var plain = new byte[CryptoConstants.NonceSize + CryptoConstants.PublicKeySize + Sha512Size + CookieLength];
        conn.SentNonce.CopyTo(plain, 0);
        conn.SessionKeys.PublicKey.CopyTo(plain, CryptoConstants.NonceSize);
        SHA512.HashData(cookie[..CookieLength]).CopyTo(plain, CryptoConstants.NonceSize + CryptoConstants.PublicKeySize);
        CreateCookie(conn.PublicKey, peerDhtPublicKey)
            .CopyTo(plain, CryptoConstants.NonceSize + CryptoConstants.PublicKeySize + Sha512Size);

        var nonce = Nonce.Random();
        var cipher = _crypto.Box(conn.PublicKey, _identity.SecretKey, nonce, plain);
        if (cipher is null)
            return null;

        var packet = new byte[HandshakeLength];
        packet[0] = (byte)PacketKind.CryptoHandshake;
        cookie[..CookieLength].CopyTo(packet.AsSpan(1));
        nonce.CopyTo(packet, 1 + CookieLength);
        cipher.CopyTo(packet, 1 + CookieLength + CryptoConstants.NonceSize);
        return packet;
    }

    private sealed record Handshake(byte[] ReceiveNonce, byte[] SessionPublicKey, byte[] PeerRealKey, byte[] PeerDhtKey,
        byte[] Cookie);

    private Handshake? OpenHandshake(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> expectedRealKey)
    {
        if (packet.Length != HandshakeLength)
            return null;

        // Our cookie proves the peer completed a cookie exchange with us within 15 seconds.
        var cookiePlain = OpenCookie(packet.Slice(1, CookieLength));
        if (cookiePlain is null)
            return null;

        var peerRealKey = cookiePlain.AsSpan(0, CryptoConstants.PublicKeySize).ToArray();
        if (!expectedRealKey.IsEmpty && !expectedRealKey.SequenceEqual(peerRealKey))
            return null;

        var plain = _crypto.Unbox(peerRealKey, _identity.SecretKey,
            packet.Slice(1 + CookieLength, CryptoConstants.NonceSize),
            packet[(1 + CookieLength + CryptoConstants.NonceSize)..]);
        if (plain is null || plain.Length != HandshakeLength - (1 + CookieLength + CryptoConstants.NonceSize + CryptoConstants.MacSize))
            return null;

        var cookieHash = SHA512.HashData(packet.Slice(1, CookieLength));
        if (!CryptographicOperations.FixedTimeEquals(cookieHash,
                plain.AsSpan(CryptoConstants.NonceSize + CryptoConstants.PublicKeySize, Sha512Size)))
            return null;

        return new Handshake(
            plain[..CryptoConstants.NonceSize],
            plain[CryptoConstants.NonceSize..(CryptoConstants.NonceSize + CryptoConstants.PublicKeySize)],
            peerRealKey,
            cookiePlain[CryptoConstants.PublicKeySize..],
            plain[(CryptoConstants.NonceSize + CryptoConstants.PublicKeySize + Sha512Size)..]);
    }

    private bool SendHandshake(CryptoConnection conn, ReadOnlySpan<byte> cookie, byte[] peerDhtPublicKey)
    {
        var packet = CreateHandshake(conn, cookie, peerDhtPublicKey);
        if (packet is null)
            return false;
        SetTempPacket(conn, packet);
        SendTempPacket(conn);
        return true;
    }

    // ================================================================ connections

    private CryptoConnection NewSlot(byte[] publicKey, byte[] dhtPublicKey)
    {
        int id = _connections.IndexOf(null);
        if (id < 0)
        {
            id = _connections.Count;
            _connections.Add(null);
        }

        var conn = new CryptoConnection(id, (byte[])publicKey.Clone(), (byte[])dhtPublicKey.Clone(), _crypto.GenerateKeyPair());
        _connections[id] = conn;
        return conn;
    }

    /// <summary>Starts connecting to a friend (cookie request first); reuses an existing connection.</summary>
    public int Create(byte[] realPublicKey, byte[] dhtPublicKey)
    {
        if (FindByPublicKey(realPublicKey) is { } existing)
            return existing.Id;

        var conn = NewSlot(realPublicKey, dhtPublicKey);
        conn.Status = CryptoConnectionStatus.CookieRequesting;
        conn.CookieRequestNumber = BinaryPrimitives.ReadUInt64LittleEndian(RandomNumberGenerator.GetBytes(8));

        var request = CreateCookieRequest(conn);
        if (request is null)
        {
            Wipe(conn);
            return -1;
        }
        SetTempPacket(conn, request);
        return conn.Id;
    }

    /// <summary>Accepts a connection started by the peer (we answer its handshake with ours).</summary>
    public int Accept(NewConnection n)
    {
        if (FindByPublicKey(n.PublicKey) is not null)
            return -1;

        var conn = NewSlot(n.PublicKey, n.DhtPublicKey);
        conn.ReceiveNonce = n.ReceiveNonce;
        conn.PeerSessionPublicKey = n.PeerSessionPublicKey;
        if (!_crypto.TryShared(conn.PeerSessionPublicKey, conn.SessionKeys.SecretKey, out var shared))
        {
            Wipe(conn);
            return -1;
        }
        conn.SharedKey = shared;
        conn.Status = CryptoConnectionStatus.NotConfirmed;
        AddSource(conn, n.Source); // before the handshake, so it can go out right away

        if (!SendHandshake(conn, n.Cookie, n.DhtPublicKey))
        {
            Wipe(conn);
            return -1;
        }
        return conn.Id;
    }

    /// <summary>The address at which we believe the peer is (from the DHT); <paramref name="connected"/> if confirmed.</summary>
    public bool SetDirectEndpoint(int id, IpPort endpoint, bool connected)
    {
        if (Get(id) is not { } conn || !AddEndpoint(conn, endpoint))
            return false;

        var lastReceived = connected ? Now : DateTimeOffset.UnixEpoch;
        if (endpoint.IsIPv4)
            conn.LastReceivedV4 = lastReceived;
        else
            conn.LastReceivedV6 = lastReceived;
        return true;
    }

    /// <summary>Associates an address with a connection; a LAN IPv4 address is never replaced.</summary>
    private bool AddEndpoint(CryptoConnection conn, IpPort endpoint)
    {
        if (endpoint.IsIPv4)
        {
            if (conn.EndpointV4 == endpoint || (conn.EndpointV4 is { } current && current.IsLan()))
                return false;
            if (conn.EndpointV4 is { } old)
                _byEndpoint.Remove(old);
            conn.EndpointV4 = endpoint;
        }
        else
        {
            if (conn.EndpointV6 == endpoint)
                return false;
            if (conn.EndpointV6 is { } old)
                _byEndpoint.Remove(old);
            conn.EndpointV6 = endpoint;
        }

        _byEndpoint[endpoint] = conn;
        return true;
    }

    /// <summary>We received a valid packet of this connection from <paramref name="source"/>.</summary>
    private void AddSource(CryptoConnection conn, IpPort source)
    {
        AddEndpoint(conn, source);
        if (source.IsIPv4)
            conn.LastReceivedV4 = Now;
        else
            conn.LastReceivedV6 = Now;
    }

    public bool IsDirectlyConnected(int id) => Get(id) is { } conn && IsDirect(conn, Now);

    private static bool IsDirect(CryptoConnection conn, DateTimeOffset now) =>
        conn.LastReceivedV4 + UdpDirectTimeout > now || conn.LastReceivedV6 + UdpDirectTimeout > now;

    /// <summary>Prefers recently confirmed addresses; ties go to LAN IPv4, then IPv6, then IPv4.</summary>
    private static IpPort? BestEndpoint(CryptoConnection conn, DateTimeOffset now)
    {
        bool v4 = conn.LastReceivedV4 + UdpDirectTimeout > now;
        bool v6 = conn.LastReceivedV6 + UdpDirectTimeout > now;

        if (v4 && conn.EndpointV4 is { } a && a.IsLan()) return a;
        if (v6 && conn.EndpointV6 is { } b) return b;
        if (v4 && conn.EndpointV4 is { } c) return c;
        if (conn.EndpointV4 is { } d && d.IsLan()) return d;
        return conn.EndpointV6 ?? conn.EndpointV4;
    }

    private bool SendPacketTo(CryptoConnection conn, ReadOnlySpan<byte> packet)
    {
        var now = Now;
        if (BestEndpoint(conn, now) is not { } endpoint)
            return false;

        if (IsDirect(conn, now))
            return _sender.Send(endpoint, packet);

        // Not confirmed yet: only handshake packets, and small packets every 4 seconds, to probe the address.
        bool probe = (conn.DirectSendAttempt + UdpDirectTimeout / 2 < now && packet.Length < 96)
                     || packet[0] == (byte)PacketKind.CookieRequest || packet[0] == (byte)PacketKind.CryptoHandshake;
        if (probe && _sender.Send(endpoint, packet))
        {
            conn.DirectSendAttempt = now;
            return true;
        }
        return false;
    }

    private static void SetTempPacket(CryptoConnection conn, byte[] packet)
    {
        conn.TempPacket = packet;
        conn.TempPacketSentTime = 0;
        conn.TempPacketSendCount = 0;
    }

    private static void ClearTempPacket(CryptoConnection conn) => SetTempPacket(conn, null!);

    private bool SendTempPacket(CryptoConnection conn)
    {
        if (conn.TempPacket is null || !SendPacketTo(conn, conn.TempPacket))
            return false;
        conn.TempPacketSentTime = NowMs;
        conn.TempPacketSendCount++;
        return true;
    }

    public void Kill(int id)
    {
        if (Get(id) is not { } conn)
            return;

        if (conn.Status == CryptoConnectionStatus.Established)
            SendDataPacketHelper(conn, conn.ReceiveArray.Start, conn.SendArray.End, [PacketIdKill]);

        Wipe(conn);
    }

    private void Wipe(CryptoConnection conn)
    {
        if (conn.EndpointV4 is { } v4 && _byEndpoint.TryGetValue(v4, out var a) && a == conn)
            _byEndpoint.Remove(v4);
        if (conn.EndpointV6 is { } v6 && _byEndpoint.TryGetValue(v6, out var b) && b == conn)
            _byEndpoint.Remove(v6);
        conn.SendArray.Clear();
        conn.ReceiveArray.Clear();
        conn.SessionKeys.Dispose();
        CryptographicOperations.ZeroMemory(conn.SharedKey);
        _connections[conn.Id] = null;
    }

    /// <summary>The peer went away: notify, then free the slot.</summary>
    private void ConnectionLost(CryptoConnection conn)
    {
        conn.StatusChanged?.Invoke(false);
        if (Get(conn.Id) == conn)
            Kill(conn.Id);
    }

    // ================================================================ packets in

    private void HandleUdpPacket(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.Length <= 1 + sizeof(ushort) + CryptoConstants.MacSize || packet.Length > MaxPacketSize)
            return;

        if (!_byEndpoint.TryGetValue(source, out var conn))
        {
            if (packet[0] == (byte)PacketKind.CryptoHandshake)
                HandleNewConnectionHandshake(source, packet);
            return;
        }

        if (!HandlePacket(conn, packet))
            return;

        // The connection may have been killed by a callback.
        if (Get(conn.Id) != conn)
            return;
        if (source.IsIPv4)
            conn.LastReceivedV4 = Now;
        else
            conn.LastReceivedV6 = Now;
    }

    private bool HandlePacket(CryptoConnection conn, ReadOnlySpan<byte> packet) =>
        (PacketKind)packet[0] switch
        {
            PacketKind.CookieResponse => HandleCookieResponse(conn, packet),
            PacketKind.CryptoHandshake => HandleHandshake(conn, packet),
            PacketKind.CryptoData => conn.Status is CryptoConnectionStatus.NotConfirmed or CryptoConnectionStatus.Established
                                     && HandleDataPacket(conn, packet),
            _ => false,
        };

    private bool HandleCookieResponse(CryptoConnection conn, ReadOnlySpan<byte> packet)
    {
        if (conn.Status != CryptoConnectionStatus.CookieRequesting || packet.Length != CookieResponseLength)
            return false;

        var plain = _crypto.Decrypt(conn.SharedKey, packet.Slice(1, CryptoConstants.NonceSize), packet[(1 + CryptoConstants.NonceSize)..]);
        if (plain is null || plain.Length != CookieLength + sizeof(ulong))
            return false;
        if (BinaryPrimitives.ReadUInt64LittleEndian(plain.AsSpan(CookieLength)) != conn.CookieRequestNumber)
            return false;

        if (!SendHandshake(conn, plain.AsSpan(0, CookieLength), conn.DhtPublicKey))
            return false;
        conn.Status = CryptoConnectionStatus.HandshakeSent;
        return true;
    }

    private bool HandleHandshake(CryptoConnection conn, ReadOnlySpan<byte> packet)
    {
        if (conn.Status is not (CryptoConnectionStatus.CookieRequesting or CryptoConnectionStatus.HandshakeSent
            or CryptoConnectionStatus.NotConfirmed))
            return false;

        var hs = OpenHandshake(packet, conn.PublicKey);
        if (hs is null)
            return false;

        if (!hs.PeerDhtKey.AsSpan().SequenceEqual(conn.DhtPublicKey))
        {
            // The peer restarted with a new DHT key: let friend_connection reconnect.
            conn.DhtPublicKeyChanged?.Invoke(hs.PeerDhtKey);
            return true;
        }

        conn.ReceiveNonce = hs.ReceiveNonce;
        conn.PeerSessionPublicKey = hs.SessionPublicKey;
        if (!_crypto.TryShared(conn.PeerSessionPublicKey, conn.SessionKeys.SecretKey, out var shared))
            return false;
        conn.SharedKey = shared;

        if (conn.Status == CryptoConnectionStatus.CookieRequesting && !SendHandshake(conn, hs.Cookie, hs.PeerDhtKey))
            return false;

        conn.Status = CryptoConnectionStatus.NotConfirmed;
        return true;
    }

    private void HandleNewConnectionHandshake(IpPort source, ReadOnlySpan<byte> packet)
    {
        var hs = OpenHandshake(packet, default);
        if (hs is null)
            return;

        var n = new NewConnection(source, hs.PeerRealKey, hs.PeerDhtKey, hs.ReceiveNonce, hs.SessionPublicKey, hs.Cookie);

        if (FindByPublicKey(hs.PeerRealKey) is { } conn)
        {
            if (!hs.PeerDhtKey.AsSpan().SequenceEqual(conn.DhtPublicKey))
            {
                ConnectionLost(conn); // stale session: replace it with the new one below
            }
            else
            {
                // Both sides started connecting at once: adopt the peer's handshake.
                if (conn.Status is not (CryptoConnectionStatus.CookieRequesting or CryptoConnectionStatus.HandshakeSent))
                    return;

                conn.ReceiveNonce = hs.ReceiveNonce;
                conn.PeerSessionPublicKey = hs.SessionPublicKey;
                if (!_crypto.TryShared(conn.PeerSessionPublicKey, conn.SessionKeys.SecretKey, out var shared))
                    return;
                conn.SharedKey = shared;
                AddSource(conn, source);
                if (SendHandshake(conn, hs.Cookie, hs.PeerDhtKey))
                    conn.Status = CryptoConnectionStatus.NotConfirmed;
                return;
            }
        }

        NewConnectionHandler?.Invoke(n);
    }

    /// <summary>Decrypts a data packet, reconstructing the nonce from its 2-byte hint.</summary>
    private byte[]? DecryptDataPacket(CryptoConnection conn, ReadOnlySpan<byte> packet)
    {
        if (packet.Length <= 1 + sizeof(ushort) + CryptoConstants.MacSize || packet.Length > MaxPacketSize)
            return null;

        var nonce = (byte[])conn.ReceiveNonce.Clone();
        ushort current = BinaryPrimitives.ReadUInt16BigEndian(nonce.AsSpan(CryptoConstants.NonceSize - 2));
        ushort received = BinaryPrimitives.ReadUInt16BigEndian(packet[1..]);
        ushort diff = unchecked((ushort)(received - current));
        Nonce.Add(nonce, diff);

        var plain = _crypto.Decrypt(conn.SharedKey, nonce, packet[(1 + sizeof(ushort))..]);
        if (plain is null)
            return null;

        // Move our base forward once the peer is far enough ahead, keeping the window centred.
        if (diff > DataNumThreshold * 2)
            Nonce.Add(conn.ReceiveNonce, DataNumThreshold);
        return plain;
    }

    private bool HandleDataPacket(CryptoConnection conn, ReadOnlySpan<byte> packet)
    {
        if (packet.Length > MaxPacketSize || packet.Length <= DataPacketMinSize)
            return false;

        var data = DecryptDataPacket(conn, packet);
        if (data is null || data.Length <= sizeof(uint) * 2)
            return false;

        uint bufferStart = BinaryPrimitives.ReadUInt32BigEndian(data);
        uint number = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(sizeof(uint)));

        // The peer has received everything before bufferStart: free those packets.
        long rttCalcTime = 0;
        if (bufferStart != conn.SendArray.Start)
        {
            if (conn.SendArray.TryGet(conn.SendArray.Start, out var first) == 1)
                rttCalcTime = first!.SentTime;
            if (!conn.SendArray.ClearUntil(bufferStart))
                return false;
        }

        int offset = sizeof(uint) * 2;
        while (data[offset] == 0)
        {
            if (++offset == data.Length)
                return false; // padding only
        }
        var real = data.AsSpan(offset);

        if (real[0] == PacketIdKill)
        {
            ConnectionLost(conn);
            return true;
        }

        if (conn.Status == CryptoConnectionStatus.NotConfirmed)
        {
            ClearTempPacket(conn);
            conn.Status = CryptoConnectionStatus.Established;
            conn.StatusChanged?.Invoke(true);
            if (Get(conn.Id) != conn)
                return false;
        }

        if (real[0] == PacketIdRequest)
        {
            if (!HandleRequestPacket(conn, real, ref rttCalcTime))
                return false;
            conn.ReceiveArray.SetEnd(number);
        }
        else if (real[0] >= LosslessStart && real[0] <= LosslessEnd)
        {
            if (!conn.ReceiveArray.TryAdd(number, new PacketData(real.ToArray())))
                return false;

            // Deliver everything now in order.
            while (conn.ReceiveArray.TryTakeFirst(out var ready))
            {
                conn.DataReceived?.Invoke(ready!.Data);
                if (Get(conn.Id) != conn)
                    return false; // killed in the callback
            }
            conn.PacketCounter++;
        }
        else if (real[0] >= LossyStart && real[0] <= LossyEnd)
        {
            conn.ReceiveArray.SetEnd(number);
            conn.LossyReceived?.Invoke(real.ToArray());
        }
        else
        {
            return false;
        }

        if (rttCalcTime != 0)
        {
            long rtt = NowMs - rttCalcTime;
            if (rtt < conn.RttTime)
                conn.RttTime = rtt;
        }
        return true;
    }

    /// <summary>
    /// The peer's request packet: a run-length list of the packets it is missing. Everything not
    /// listed has arrived and is freed; listed packets older than one RTT are marked for resending.
    /// </summary>
    private bool HandleRequestPacket(CryptoConnection conn, ReadOnlySpan<byte> data, ref long latestSendTime)
    {
        if (data.IsEmpty || data[0] != PacketIdRequest)
            return false;
        if (data.Length == 1)
            return true;

        data = data[1..];
        var array = conn.SendArray;
        long now = NowMs;
        long lastSent = 0;
        uint n = 1;

        for (uint i = array.Start; i != array.End; i = unchecked(i + 1))
        {
            if (data.IsEmpty)
                break;

            if (n == data[0])
            {
                if (array[i] is { } requested && requested.SentTime + conn.RttTime < now)
                    requested.SentTime = 0;
                data = data[1..];
                n = 0;
            }
            else if (array.Remove(i) is { } received)
            {
                lastSent = Math.Max(lastSent, received.SentTime);
            }

            if (n == 255)
            {
                n = 1;
                if (data.IsEmpty)
                    break;
                if (data[0] != 0)
                    return false;
                data = data[1..];
            }
            else
            {
                n++;
            }
        }

        latestSendTime = Math.Max(latestSendTime, lastSent);
        return true;
    }

    // ================================================================ packets out

    private bool SendDataPacket(CryptoConnection conn, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data.Length > MaxPacketSize - (1 + sizeof(ushort) + CryptoConstants.MacSize))
            return false;

        var cipher = _crypto.Encrypt(conn.SharedKey, conn.SentNonce, data);
        var packet = new byte[1 + sizeof(ushort) + cipher.Length];
        packet[0] = (byte)PacketKind.CryptoData;
        conn.SentNonce.AsSpan(CryptoConstants.NonceSize - sizeof(ushort)).CopyTo(packet.AsSpan(1));
        cipher.CopyTo(packet, 1 + sizeof(ushort));
        Nonce.Increment(conn.SentNonce);
        return SendPacketTo(conn, packet);
    }

    /// <summary>[our receive window start][packet number][zero padding][data]: padding hides exact lengths.</summary>
    private bool SendDataPacketHelper(CryptoConnection conn, uint bufferStart, uint number, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data.Length > MaxDataSize)
            return false;

        int padding = (MaxDataSize - data.Length) % MaxPadding;
        var packet = new byte[sizeof(uint) * 2 + padding + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(packet, bufferStart);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(sizeof(uint)), number);
        data.CopyTo(packet.AsSpan(sizeof(uint) * 2 + padding));
        return SendDataPacket(conn, packet);
    }

    /// <summary>Retries the packet that hit the send limit last time, before queueing new ones.</summary>
    private bool ResetMaxSpeedReached(CryptoConnection conn)
    {
        if (!conn.MaximumSpeedReached)
            return true;

        uint last = unchecked(conn.SendArray.End - 1);
        if (conn.SendArray.TryGet(last, out var pending) == 1 && pending!.SentTime == 0)
        {
            if (!SendDataPacketHelper(conn, conn.ReceiveArray.Start, last, pending.Data))
                return false;
            pending.SentTime = NowMs;
        }
        conn.MaximumSpeedReached = false;
        return true;
    }

    /// <summary>True if the last packet could not be handed to the network and still cannot: the link is full.</summary>
    public bool MaxSpeedReached(int id) => Get(id) is not { } conn || !ResetMaxSpeedReached(conn);

    /// <summary>
    /// Queues a lossless packet (first byte 16-191). Returns its packet number, usable with
    /// <see cref="IsPacketReceived"/> for delivery receipts, or -1 if the queue is full.
    /// </summary>
    public long WriteLossless(int id, ReadOnlySpan<byte> data, bool congestionControl)
    {
        if (data.IsEmpty || data[0] < LosslessStart || data[0] > LosslessEnd || data.Length > MaxDataSize)
            return -1;
        if (Get(id) is not { } conn || conn.Status != CryptoConnectionStatus.Established)
            return -1;
        if (congestionControl && conn.PacketsLeft == 0)
            return -1;

        ResetMaxSpeedReached(conn);
        if (conn.MaximumSpeedReached && congestionControl)
            return -1;

        var packetData = new PacketData(data.ToArray());
        long number = conn.SendArray.Append(packetData);
        if (number < 0)
            return -1;

        if (congestionControl || !conn.MaximumSpeedReached)
        {
            if (SendDataPacketHelper(conn, conn.ReceiveArray.Start, (uint)number, data))
                packetData.SentTime = NowMs;
            else
                conn.MaximumSpeedReached = true;
        }

        if (congestionControl)
        {
            conn.PacketsLeft--;
            conn.PacketsLeftRequested = conn.PacketsLeftRequested == 0 ? 0 : conn.PacketsLeftRequested - 1;
            conn.PacketsSent++;
        }
        return number;
    }

    /// <summary>True once the peer has confirmed receiving lossless packet <paramref name="number"/>.</summary>
    public bool IsPacketReceived(int id, uint number)
    {
        if (Get(id) is not { } conn)
            return false;
        return conn.SendArray.Count < unchecked(number - conn.SendArray.Start);
    }

    public bool SendLossy(int id, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data.Length > MaxDataSize || data[0] < LossyStart || data[0] > LossyEnd)
            return false;
        if (Get(id) is not { } conn)
            return false;
        return SendDataPacketHelper(conn, conn.ReceiveArray.Start, conn.SendArray.End, data);
    }

    /// <summary>Free slots in the send queue (bounded by congestion control).</summary>
    public uint FreeSendQueueSlots(int id)
    {
        if (Get(id) is not { } conn)
            return 0;
        uint max = PacketsArray.Capacity - conn.SendArray.Count;
        return Math.Min(conn.PacketsLeft, max);
    }

    /// <summary>[1][run lengths]: for each missing packet, how many packets since the previous gap.</summary>
    private bool SendRequestPacket(CryptoConnection conn)
    {
        var data = new List<byte>(64) { PacketIdRequest };
        var array = conn.ReceiveArray;
        if (array.Start != array.End)
        {
            uint n = 1;
            for (uint i = array.Start; i != array.End; i = unchecked(i + 1))
            {
                if (array[i] is null)
                {
                    data.Add((byte)n);
                    n = 0;
                }
                else if (n == 255)
                {
                    data.Add(0);
                    n = 0;
                }
                if (data.Count >= MaxDataSize)
                    break;
                n++;
            }
        }

        return SendDataPacketHelper(conn, array.Start, conn.SendArray.End, data.ToArray());
    }

    private int SendRequestedPackets(CryptoConnection conn, uint max)
    {
        if (max == 0)
            return -1;

        long now = NowMs;
        int sent = 0;
        var array = conn.SendArray;
        for (uint i = 0; i < array.Count; i++)
        {
            uint number = unchecked(array.Start + i);
            if (array[number] is not { SentTime: 0 } packet)
                continue;

            if (SendDataPacketHelper(conn, conn.ReceiveArray.Start, number, packet.Data))
            {
                packet.SentTime = now;
                sent++;
            }
            if (sent >= max)
                break;
        }
        return sent;
    }

    // ================================================================ main loop

    public void Tick()
    {
        KillTimedOut();
        SendCryptoPackets();
    }

    private void KillTimedOut()
    {
        foreach (var conn in _connections.ToList())
        {
            if (conn is null || conn.Status == CryptoConnectionStatus.Established)
                continue;
            if (conn.TempPacketSendCount >= MaxSendPacketTries)
                ConnectionLost(conn);
        }
    }

    /// <summary>Resends handshakes, sends request packets, and runs congestion control (toxcore's send_crypto_packets).</summary>
    private void SendCryptoPackets()
    {
        long now = NowMs;
        double totalSendRate = 0;
        double peakRequestInterval = double.MaxValue;

        foreach (var conn in _connections.ToList())
        {
            if (conn is null || Get(conn.Id) != conn)
                continue;

            if (SendPacketInterval + conn.TempPacketSentTime < now)
                SendTempPacket(conn);

            if (conn.Status is CryptoConnectionStatus.NotConfirmed or CryptoConnectionStatus.Established
                && SendPacketInterval + conn.LastRequestPacketSent < now
                && SendRequestPacket(conn))
                conn.LastRequestPacketSent = now;

            if (conn.Status != CryptoConnectionStatus.Established)
                continue;

            if (conn.PacketReceiveRate > MinPacketRate)
            {
                double interval = RequestPacketsCompareConstant / ((conn.ReceiveArray.Count + 1.0) / (conn.PacketReceiveRate + 1.0));
                double interval2 = MinPacketRate / conn.PacketReceiveRate * SendPacketInterval + PacketCounterAverageInterval;
                interval = Math.Clamp(Math.Min(interval, interval2), PacketCounterAverageInterval, SendPacketInterval);

                if (now - conn.LastRequestPacketSent > (long)interval && SendRequestPacket(conn))
                    conn.LastRequestPacketSent = now;
                peakRequestInterval = Math.Min(peakRequestInterval, interval);
            }

            if (PacketCounterAverageInterval + conn.PacketCounterSet < now)
                UpdateSendRate(conn, now);

            UpdatePacketsLeft(conn, now);

            int resent = SendRequestedPackets(conn, conn.PacketsLeftRequested);
            if (resent != -1)
            {
                conn.PacketsLeftRequested -= (uint)Math.Min(resent, conn.PacketsLeftRequested);
                conn.PacketsResent += (uint)resent;
                if ((uint)resent < conn.PacketsLeft)
                {
                    conn.PacketsLeft -= (uint)resent;
                }
                else
                {
                    conn.LastCongestionEvent = now;
                    conn.PacketsLeft = 0;
                }
            }

            if (conn.PacketSendRate > MinPacketRate * 1.5)
                totalSendRate += conn.PacketSendRate;
        }

        double sleep = Math.Min(peakRequestInterval, SendPacketInterval);
        if (totalSendRate > MinPacketRate)
            sleep = Math.Min(sleep, 1000.0 / totalSendRate + 1);
        RunInterval = (long)sleep;
    }

    /// <summary>
    /// Every 50 ms: the send rate follows what actually got through (packets sent minus the growth of
    /// the send queue), +20% when no congestion was seen recently, -10% otherwise.
    /// </summary>
    private void UpdateSendRate(CryptoConnection conn, long now)
    {
        double dt = now - conn.PacketCounterSet;
        conn.PacketReceiveRate = conn.PacketCounter / (dt / 1000.0);
        conn.PacketCounter = 0;
        conn.PacketCounterSet = now;

        uint packetsSent = conn.PacketsSent;
        conn.PacketsSent = 0;
        uint packetsResent = conn.PacketsResent;
        conn.PacketsResent = 0;

        int pos = (int)(conn.LastSendQueueCounter % CongestionQueueArraySize);
        conn.LastSendQueueSize[pos] = conn.SendArray.Count;
        long sum = conn.LastSendQueueSize[pos] - (long)conn.LastSendQueueSize[(pos + 1) % CongestionQueueArraySize];

        int sentPos = (int)(conn.LastSendQueueCounter % CongestionLastSentArraySize);
        conn.LastNumPacketsSent[sentPos] = packetsSent;
        conn.LastNumPacketsResent[sentPos] = packetsResent;
        conn.LastSendQueueCounter = (conn.LastSendQueueCounter + 1) % (CongestionQueueArraySize * CongestionLastSentArraySize);

        long totalSent = 0, totalResent = 0;
        int delay = (int)(conn.RttTime / (double)PacketCounterAverageInterval + 0.5);
        const int remArray = CongestionLastSentArraySize - CongestionQueueArraySize;
        delay = Math.Min(delay, remArray);

        for (int j = 0; j < CongestionQueueArraySize; j++)
        {
            int index = (j + (remArray - delay) + sentPos) % CongestionLastSentArraySize;
            totalSent += conn.LastNumPacketsSent[index];
            totalResent += conn.LastNumPacketsResent[index];
        }

        if (sum > 0)
            totalSent -= sum;
        else if (totalResent > -sum)
            totalResent = -sum;

        uint queued = conn.SendArray.Count;
        double minSpeed = 1000.0 * (totalSent / ((double)CongestionQueueArraySize * PacketCounterAverageInterval));
        double minSpeedRequest = 1000.0 * ((totalSent + totalResent) / ((double)CongestionQueueArraySize * PacketCounterAverageInterval));
        if (minSpeed < MinPacketRate)
            minSpeed = MinPacketRate;

        double sendArrayRatio = queued / minSpeed;
        if (sendArrayRatio > SendQueueRatio && MinQueueLength < queued)
            conn.PacketSendRate = minSpeed * (1.0 / (sendArrayRatio / SendQueueRatio));
        else if (conn.LastCongestionEvent + CongestionEventTimeout < now)
            conn.PacketSendRate = minSpeed * 1.2;
        else
            conn.PacketSendRate = minSpeed * 0.9;

        conn.PacketSendRateRequested = minSpeedRequest * 1.2;
        if (conn.PacketSendRate < MinPacketRate)
            conn.PacketSendRate = MinPacketRate;
        if (conn.PacketSendRateRequested < conn.PacketSendRate)
            conn.PacketSendRateRequested = conn.PacketSendRate;
    }

    /// <summary>Token buckets: how many new packets, and how many resends, may go out now.</summary>
    private static void UpdatePacketsLeft(CryptoConnection conn, long now)
    {
        if (conn.LastPacketsLeftSet == 0 || conn.LastPacketsLeftRequestedSet == 0)
        {
            conn.LastPacketsLeftRequestedSet = now;
            conn.LastPacketsLeftSet = now;
            conn.PacketsLeftRequested = MinQueueLength;
            conn.PacketsLeft = MinQueueLength;
            return;
        }

        if ((long)(1000.0 / conn.PacketSendRate + 0.5) + conn.LastPacketsLeftSet <= now)
        {
            double packets = conn.PacketSendRate * ((now - conn.LastPacketsLeftSet) / 1000.0) + conn.LastPacketsLeftRemainder;
            uint whole = (uint)packets;
            if (conn.PacketsLeft > whole * 4 + MinQueueLength)
                conn.PacketsLeft = whole * 4 + MinQueueLength;
            else
                conn.PacketsLeft += whole;
            conn.LastPacketsLeftSet = now;
            conn.LastPacketsLeftRemainder = packets - whole;
        }

        if ((long)(1000.0 / conn.PacketSendRateRequested + 0.5) + conn.LastPacketsLeftRequestedSet <= now)
        {
            double packets = conn.PacketSendRateRequested * ((now - conn.LastPacketsLeftRequestedSet) / 1000.0)
                             + conn.LastPacketsLeftRequestedRemainder;
            uint whole = (uint)packets;
            conn.PacketsLeftRequested = whole;
            conn.LastPacketsLeftRequestedSet = now;
            conn.LastPacketsLeftRequestedRemainder = packets - whole;
        }

        if (conn.PacketsLeft > conn.PacketsLeftRequested)
            conn.PacketsLeftRequested = conn.PacketsLeft;
    }

    public void Dispose()
    {
        foreach (var conn in _connections.ToList())
            if (conn is not null)
                Kill(conn.Id);
        CryptographicOperations.ZeroMemory(_cookieKey);
    }
}
