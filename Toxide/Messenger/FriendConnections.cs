using Toxide.Dht;
using Toxide.Network;
using Toxide.NetCrypto;
using Toxide.Onion;

namespace Toxide.Messenger;

internal enum FriendConnectionStatus
{
    Connecting,
    Connected,
}

internal sealed class FriendConnection
{
    public FriendConnection(int id, byte[] realPublicKey, int onionFriendNumber)
    {
        Id = id;
        RealPublicKey = realPublicKey;
        OnionFriendNumber = onionFriendNumber;
    }

    public int Id { get; }
    public byte[] RealPublicKey { get; }
    public int OnionFriendNumber { get; }

    /// <summary>The friend's current (temporary) DHT key, once it told us through the onion or a handshake.</summary>
    public byte[]? DhtPublicKey { get; set; }
    public Action<IpPort>? DhtSearch { get; set; }
    public DateTimeOffset DhtPublicKeyLastReceived { get; set; } = DateTimeOffset.UnixEpoch;

    public IpPort? DhtEndpoint { get; set; }
    public DateTimeOffset DhtEndpointLastReceived { get; set; } = DateTimeOffset.UnixEpoch;

    public int CryptoConnectionId { get; set; } = -1;
    public FriendConnectionStatus Status { get; set; } = FriendConnectionStatus.Connecting;
    public DateTimeOffset PingLastSent { get; set; } = DateTimeOffset.UnixEpoch;
    public DateTimeOffset PingLastReceived { get; set; } = DateTimeOffset.UnixEpoch;

    /// <summary>Extra users of this connection beyond the first (toxcore's lock_count).</summary>
    public int LockCount { get; set; }

    public Action<bool>? StatusChanged { get; set; }
    public Action<byte[]>? DataReceived { get; set; }
    public Action<byte[]>? LossyReceived { get; set; }
}

/// <summary>
/// Glues the layers together for each friend (toxcore friend_connection.c):
///   onion   -> tells us the friend's DHT key;
///   DHT     -> finds the friend's IP address from that key;
///   net_crypto -> opens the encrypted session to that address.
/// Once connected, it keeps the session alive with a ping every 8 seconds and declares the friend
/// offline after 32 seconds of silence. It also carries friend requests and LAN discovery.
/// </summary>
internal sealed class FriendConnections
{
    public const byte PacketIdAlive = 16;
    public const byte PacketIdShareRelays = 17;
    public const byte PacketIdFriendRequests = 18;

    private static readonly TimeSpan PingInterval = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan ConnectionTimeout = PingInterval * 4;
    private static readonly TimeSpan DhtTimeout = DhtNode.BadNodeTimeout;

    private readonly DhtNode _dht;
    private readonly OnionClient _onion;
    private readonly NetCrypto.NetCrypto _netCrypto;
    private readonly TimeProvider _time;
    private readonly LanDiscovery? _lanDiscovery;
    private readonly List<FriendConnection?> _connections = [];

    public FriendConnections(DhtNode dht, OnionClient onion, NetCrypto.NetCrypto netCrypto, TimeProvider time,
        LanDiscovery? lanDiscovery)
    {
        _dht = dht;
        _onion = onion;
        _netCrypto = netCrypto;
        _time = time;
        _lanDiscovery = lanDiscovery;

        netCrypto.NewConnectionHandler = HandleNewConnection;
        onion.RegisterDataHandler(OnionClient.DataFriendRequest, (key, data) => FriendRequestReceived?.Invoke(key, data));
    }

    /// <summary>Raw friend request: [32 or 18][nospam 4][message]. Arrives through the onion.</summary>
    public Action<byte[], byte[]>? FriendRequestReceived { get; set; }

    private DateTimeOffset Now => _time.GetUtcNow();

    public FriendConnection? Get(int id) => id >= 0 && id < _connections.Count ? _connections[id] : null;

    public int Find(ReadOnlySpan<byte> realPublicKey)
    {
        for (int i = 0; i < _connections.Count; i++)
            if (_connections[i] is { } c && c.RealPublicKey.AsSpan().SequenceEqual(realPublicKey))
                return i;
        return -1;
    }

    /// <summary>Starts looking for and connecting to a friend; reference counted.</summary>
    public int Add(byte[] realPublicKey)
    {
        int existing = Find(realPublicKey);
        if (existing >= 0)
        {
            _connections[existing]!.LockCount++;
            return existing;
        }

        int onionNumber = _onion.AddFriend(realPublicKey);
        int id = _connections.IndexOf(null);
        if (id < 0)
        {
            id = _connections.Count;
            _connections.Add(null);
        }

        var fc = new FriendConnection(id, (byte[])realPublicKey.Clone(), onionNumber);
        _connections[id] = fc;
        _onion.SetDhtPublicKeyCallback(onionNumber, key => OnDhtPublicKey(fc, key));
        return id;
    }

    public void Kill(int id)
    {
        if (Get(id) is not { } fc)
            return;

        if (fc.LockCount > 0)
        {
            fc.LockCount--;
            return;
        }

        _onion.RemoveFriend(fc.OnionFriendNumber);
        _netCrypto.Kill(fc.CryptoConnectionId);
        StopDhtSearch(fc);
        _connections[id] = null;
    }

    public bool IsConnected(int id) => Get(id)?.Status == FriendConnectionStatus.Connected;

    public long WriteLossless(int id, ReadOnlySpan<byte> data, bool congestionControl) =>
        Get(id) is { } fc ? _netCrypto.WriteLossless(fc.CryptoConnectionId, data, congestionControl) : -1;

    public bool SendLossy(int id, ReadOnlySpan<byte> data) =>
        Get(id) is { } fc && _netCrypto.SendLossy(fc.CryptoConnectionId, data);

    public bool IsPacketReceived(int id, uint packetNumber) =>
        Get(id) is { } fc && _netCrypto.IsPacketReceived(fc.CryptoConnectionId, packetNumber);

    public bool MaxSpeedReached(int id) => Get(id) is not { } fc || _netCrypto.MaxSpeedReached(fc.CryptoConnectionId);

    public uint FreeSendQueueSlots(int id) =>
        Get(id) is { } fc ? _netCrypto.FreeSendQueueSlots(fc.CryptoConnectionId) : 0;

    /// <summary>
    /// Sends a friend request: directly if already connected, otherwise through the onion.
    /// Returns -1 on failure (e.g. the friend was not found on the onion yet), else &gt;= 0.
    /// </summary>
    public int SendFriendRequest(int id, ReadOnlySpan<byte> noSpam, ReadOnlySpan<byte> message)
    {
        if (Get(id) is not { } fc || message.IsEmpty || 1 + noSpam.Length + message.Length > OnionClient.MaxDataSize)
            return -1;

        var packet = new byte[1 + noSpam.Length + message.Length];
        noSpam.CopyTo(packet.AsSpan(1));
        message.CopyTo(packet.AsSpan(1 + noSpam.Length));

        if (fc.Status == FriendConnectionStatus.Connected)
        {
            packet[0] = PacketIdFriendRequests;
            return _netCrypto.WriteLossless(fc.CryptoConnectionId, packet, false) != -1 ? 1 : 0;
        }

        packet[0] = OnionClient.DataFriendRequest;
        int sent = _onion.SendData(fc.OnionFriendNumber, packet);
        return sent <= 0 ? -1 : sent;
    }

    // ================================================================ DHT key and address

    private void OnDhtPublicKey(FriendConnection fc, byte[] dhtPublicKey)
    {
        if (Get(fc.Id) != fc)
            return;

        fc.DhtPublicKeyLastReceived = Now; // refreshed even when unchanged: the friend is alive
        if (fc.DhtPublicKey is not null && fc.DhtPublicKey.AsSpan().SequenceEqual(dhtPublicKey))
            return;

        ChangeDhtPublicKey(fc, dhtPublicKey);

        // A new DHT key means the friend restarted: the old session is dead.
        if (fc.CryptoConnectionId != -1)
        {
            _netCrypto.Kill(fc.CryptoConnectionId);
            fc.CryptoConnectionId = -1;
            HandleStatus(fc, false);
        }

        _onion.SetFriendDhtPublicKey(fc.OnionFriendNumber, dhtPublicKey);
    }

    private void ChangeDhtPublicKey(FriendConnection fc, byte[] dhtPublicKey)
    {
        fc.DhtPublicKeyLastReceived = Now;
        StopDhtSearch(fc);

        fc.DhtPublicKey = (byte[])dhtPublicKey.Clone();
        fc.DhtSearch = endpoint => OnDhtEndpoint(fc, endpoint);
        _dht.AddFriend(fc.DhtPublicKey, fc.DhtSearch);
    }

    private void StopDhtSearch(FriendConnection fc)
    {
        if (fc.DhtPublicKey is not null && fc.DhtSearch is not null)
            _dht.RemoveFriend(fc.DhtPublicKey, fc.DhtSearch);
        fc.DhtSearch = null;
    }

    /// <summary>The DHT confirmed the friend's address.</summary>
    private void OnDhtEndpoint(FriendConnection fc, IpPort endpoint)
    {
        if (Get(fc.Id) != fc)
            return;

        _netCrypto.SetDirectEndpoint(fc.CryptoConnectionId, endpoint, true);
        fc.DhtEndpoint = endpoint;
        fc.DhtEndpointLastReceived = Now;
    }

    // ================================================================ net_crypto session

    private void HandleStatus(FriendConnection fc, bool online)
    {
        bool changed = false;
        if (online)
        {
            changed = true;
            fc.Status = FriendConnectionStatus.Connected;
            fc.PingLastReceived = Now;
            _onion.SetFriendOnline(fc.OnionFriendNumber, true);
        }
        else
        {
            if (fc.Status != FriendConnectionStatus.Connecting)
            {
                changed = true;
                fc.DhtPublicKeyLastReceived = Now;
                _onion.SetFriendOnline(fc.OnionFriendNumber, false);
            }
            fc.Status = FriendConnectionStatus.Connecting;
            fc.CryptoConnectionId = -1;
        }

        if (changed)
            fc.StatusChanged?.Invoke(online);
    }

    private void HandlePacket(FriendConnection fc, byte[] data)
    {
        if (data.Length == 0)
            return;

        switch (data[0])
        {
            case PacketIdFriendRequests:
                FriendRequestReceived?.Invoke(fc.RealPublicKey, data);
                return;
            case PacketIdAlive:
                fc.PingLastReceived = Now;
                return;
            case PacketIdShareRelays:
                return; // TCP relays are not supported
            default:
                fc.DataReceived?.Invoke(data);
                return;
        }
    }

    /// <summary>Wires a net_crypto session to its friend; callbacks ignore a session that was replaced.</summary>
    private void Bind(FriendConnection fc, int cryptoId)
    {
        fc.CryptoConnectionId = cryptoId;
        var conn = _netCrypto.Get(cryptoId)!;
        conn.StatusChanged = online =>
        {
            if (Get(fc.Id) == fc && fc.CryptoConnectionId == cryptoId)
                HandleStatus(fc, online);
        };
        conn.DataReceived = data =>
        {
            if (Get(fc.Id) == fc && fc.CryptoConnectionId == cryptoId)
                HandlePacket(fc, data);
        };
        conn.LossyReceived = data =>
        {
            if (Get(fc.Id) == fc && fc.CryptoConnectionId == cryptoId)
                fc.LossyReceived?.Invoke(data);
        };
        conn.DhtPublicKeyChanged = key => OnDhtPublicKey(fc, key);
    }

    private bool HandleNewConnection(NewConnection n)
    {
        int id = Find(n.PublicKey);
        if (Get(id) is not { } fc || fc.CryptoConnectionId != -1)
            return false; // not a friend, or already connecting

        int cryptoId = _netCrypto.Accept(n);
        if (cryptoId == -1)
            return false;

        Bind(fc, cryptoId);
        fc.DhtEndpoint = n.Source;
        fc.DhtEndpointLastReceived = Now;

        if (fc.DhtPublicKey is null || !fc.DhtPublicKey.AsSpan().SequenceEqual(n.DhtPublicKey))
            ChangeDhtPublicKey(fc, n.DhtPublicKey);
        return true;
    }

    private bool StartConnection(FriendConnection fc)
    {
        if (fc.CryptoConnectionId != -1 || fc.DhtPublicKey is null || fc.DhtSearch is null)
            return false;

        int cryptoId = _netCrypto.Create(fc.RealPublicKey, fc.DhtPublicKey);
        if (cryptoId == -1)
            return false;

        Bind(fc, cryptoId);
        return true;
    }

    // ================================================================ main loop

    public void Tick(bool lanDiscoveryEnabled)
    {
        var now = Now;
        foreach (var fc in _connections.ToList())
        {
            if (fc is null || Get(fc.Id) != fc)
                continue;

            if (fc.Status == FriendConnectionStatus.Connecting)
            {
                // A DHT key not refreshed for 2 minutes is probably stale.
                if (fc.DhtPublicKeyLastReceived + DhtTimeout < now && fc.DhtSearch is not null)
                {
                    StopDhtSearch(fc);
                    fc.DhtPublicKey = null;
                }

                if (fc.DhtEndpointLastReceived + DhtTimeout < now)
                    fc.DhtEndpoint = null;

                if (fc.DhtSearch is not null && StartConnection(fc) && fc.DhtEndpoint is { } endpoint)
                    _netCrypto.SetDirectEndpoint(fc.CryptoConnectionId, endpoint, false);
            }
            else
            {
                if (fc.PingLastSent + PingInterval < now
                    && _netCrypto.WriteLossless(fc.CryptoConnectionId, [PacketIdAlive], false) != -1)
                    fc.PingLastSent = now;

                if (fc.PingLastReceived + ConnectionTimeout < now)
                {
                    _netCrypto.Kill(fc.CryptoConnectionId);
                    fc.CryptoConnectionId = -1;
                    HandleStatus(fc, false);
                }
            }
        }

        if (lanDiscoveryEnabled)
            _lanDiscovery?.Tick(_dht.PublicKey);
    }
}
