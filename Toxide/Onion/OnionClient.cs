using System.Buffers.Binary;
using System.Security.Cryptography;
using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Network;

namespace Toxide.Onion;

/// <summary>Handles onion data from a friend; <paramref name="data"/> starts with its type byte.</summary>
internal delegate void OnionDataHandler(byte[] senderRealPublicKey, byte[] data);

internal enum OnionConnectionStatus
{
    None,
    Udp,
}

/// <summary>
/// The client side of the onion (toxcore onion_client.c): how friends find each other without
/// revealing their IP addresses to anyone but each other.
///
///  1. Announce: through onion paths, we ask the nodes closest to our long-term public key to
///     store our announcement. We give them a temporary "data key" for others to encrypt with.
///  2. Search: for each friend, through other paths and with a throwaway key, we ask the nodes
///     closest to the friend's public key whether the friend is announced there.
///  3. Data: once we have a node storing the friend's announcement, we send small encrypted
///     messages there (friend requests, our current DHT key) which the node forwards along the
///     return path the friend left.
///
/// The DHT key we send this way is what lets the DHT find the friend's IP (see DhtNode.Friends.cs).
/// </summary>
internal sealed class OnionClient : IDisposable
{
    public static readonly DateTimeOffset Never = DateTimeOffset.UnixEpoch;

    public const int MaxFriendNodes = 8;
    public const int MaxAnnounceNodes = 12;
    public const int NodeMaxPings = 3;
    public static readonly TimeSpan NodePingInterval = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan NodeTimeout = NodePingInterval;

    public const byte DataFriendRequest = CryptoRequest.FriendRequest;
    public const byte DataDhtPublicKey = CryptoRequest.DhtPublicKey;

    /// <summary>Largest payload <see cref="SendData"/> accepts (toxcore's ONION_CLIENT_MAX_DATA_SIZE).</summary>
    public const int MaxDataSize = MaxDataRequestSize - DataInResponseMinSize;

    private const int MaxPathNodes = 32;
    private const int MaxPathNoResponseUses = 4;
    private const int MaxSendbacks = 256;
    private const int DataInResponseMinSize = CryptoConstants.PublicKeySize + CryptoConstants.MacSize;
    private const int DataRequestMinSize = 1 + CryptoConstants.PublicKeySize + CryptoConstants.NonceSize
                                           + CryptoConstants.PublicKeySize + CryptoConstants.MacSize;
    private const int MaxDataRequestSize = OnionPacket.MaxDataSize - DataRequestMinSize;
    private const int AnnounceResponseMinSize = 2 + OnionAnnounceServer.SendbackSize + CryptoConstants.NonceSize
                                                + TimedAuth.Size + CryptoConstants.MacSize;
    private const int DhtPkDataMinSize = 1 + sizeof(ulong) + CryptoConstants.PublicKeySize;
    private const int DhtPkDataMaxSize = DhtPkDataMinSize + NodeInfo.PackedSizeIPv6 * DhtPayloads.MaxNodes;

    private static readonly TimeSpan SendbackTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan PathFirstTimeout = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan PathTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan PathMaxLifetime = TimeSpan.FromSeconds(1200);
    private static readonly TimeSpan OfflineTimeout = NodePingInterval * (NodeMaxPings + 2);
    private static readonly TimeSpan DhtPkOnionInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DhtPkDhtInterval = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan AnnounceIntervalNotAnnounced = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan AnnounceIntervalAnnounced = NodePingInterval;
    private static readonly TimeSpan TimeToStable = NodePingInterval * 6;
    private static readonly TimeSpan AnnounceIntervalStable = NodePingInterval * 8;
    private static readonly TimeSpan PopulateTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ConnectionSeconds = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan ConnectedTimeout = TimeSpan.FromSeconds(10);
    private const uint FriendNewInterval = 3;
    private const uint FriendRunCountBeginning = 5;
    private const uint FriendMaxInterval = 60 * 60;
    private const int MaxRunCountExponent = 12;
    private const int OnionConnectionSeconds = 3;

    private sealed record Sendback(uint Number, byte[] PublicKey, IpPort Endpoint, uint PathNumber, DateTimeOffset SentAt);

    private readonly DhtNode _dht;
    private readonly ICryptoCore _crypto;
    private readonly IPacketSender _sender;
    private readonly TimeProvider _time;
    private readonly KeyPair _identity;
    private readonly KeyPair _tempKeys;

    private readonly OnionNode[] _announceNodes = OnionNode.CreateList(MaxAnnounceNodes);
    private readonly RecentlyPinged _recentlyPinged = new();
    private readonly OnionPathSet _selfPaths = new();
    private readonly OnionPathSet _friendPaths = new();
    private readonly List<NodeInfo> _pathNodes = [];
    private readonly List<NodeInfo> _bootstrapPathNodes = [];
    private int _pathNodesNext;
    private int _bootstrapPathNodesNext;
    private readonly Dictionary<ulong, Sendback> _sendbacks = new();
    private readonly List<OnionFriend?> _friends = [];
    private readonly Dictionary<byte, OnionDataHandler> _dataHandlers = new();

    private DateTimeOffset _lastAnnounce = Never;
    private DateTimeOffset _lastPopulated = Never;
    private DateTimeOffset _lastPacketReceived = Never;
    private DateTimeOffset _lastTimeConnected = Never;
    private DateTimeOffset _firstRun = Never;
    private long _lastRunSecond;
    private int _onionConnected;

    public OnionClient(DhtNode dht, KeyPair identity, TimeProvider time)
    {
        _dht = dht;
        _crypto = dht.Crypto;
        _sender = dht.Sender;
        _time = time;
        _identity = identity;
        _tempKeys = _crypto.GenerateKeyPair();

        _dataHandlers[DataDhtPublicKey] = HandleDhtPkAnnounce;
        dht.RegisterCryptoHandler(CryptoRequest.DhtPublicKey, HandleDhtPkFromDht);
    }

    public OnionConnectionStatus ConnectionStatus =>
        _onionConnected >= OnionConnectionSeconds ? OnionConnectionStatus.Udp : OnionConnectionStatus.None;

    /// <summary>How many announce nodes currently store our announcement.</summary>
    internal int AnnouncedCount => _announceNodes.Count(n => !n.IsTimedOut(Now) && n.IsStored != 0);

    private DateTimeOffset Now => _time.GetUtcNow();

    public static bool IsTimeout(DateTimeOffset now, DateTimeOffset since, TimeSpan timeout) => since + timeout <= now; // toxcore's mono_time_is_timeout

    public void Attach(PacketDispatcher dispatcher)
    {
        dispatcher.Register(PacketKind.AnnounceResponse, (s, p) => HandleAnnounceResponse(s, p, withCount: false));
        dispatcher.Register(PacketKind.AnnounceResponseNew, (s, p) => HandleAnnounceResponse(s, p, withCount: true));
        dispatcher.Register(PacketKind.OnionDataResponse, HandleDataResponse);
    }

    public void RegisterDataHandler(byte type, OnionDataHandler handler) => _dataHandlers[type] = handler;

    // ================================================================ friends

    public int AddFriend(byte[] realPublicKey)
    {
        int existing = FindFriend(realPublicKey);
        if (existing >= 0)
            return existing;

        var friend = new OnionFriend((byte[])realPublicKey.Clone(), _crypto.GenerateKeyPair());
        int slot = _friends.IndexOf(null);
        if (slot < 0)
        {
            _friends.Add(friend);
            return _friends.Count - 1;
        }
        _friends[slot] = friend;
        return slot;
    }

    public void RemoveFriend(int friendNumber)
    {
        if (GetFriend(friendNumber) is not { } friend)
            return;
        friend.Dispose();
        _friends[friendNumber] = null;
    }

    public int FindFriend(ReadOnlySpan<byte> realPublicKey)
    {
        for (int i = 0; i < _friends.Count; i++)
            if (_friends[i] is { } f && f.RealPublicKey.AsSpan().SequenceEqual(realPublicKey))
                return i;
        return -1;
    }

    public void SetDhtPublicKeyCallback(int friendNumber, Action<byte[]> callback)
    {
        if (GetFriend(friendNumber) is { } friend)
            friend.DhtPublicKeyReceived = callback;
    }

    public void SetFriendDhtPublicKey(int friendNumber, byte[] dhtPublicKey)
    {
        if (GetFriend(friendNumber) is { } friend)
            friend.DhtPublicKey = (byte[])dhtPublicKey.Clone();
    }

    public byte[]? GetFriendDhtPublicKey(int friendNumber) => GetFriend(friendNumber)?.DhtPublicKey;

    /// <summary>While a friend is online we stop searching for it (we talk to it directly).</summary>
    public void SetFriendOnline(int friendNumber, bool online)
    {
        if (GetFriend(friendNumber) is not { } friend)
            return;

        friend.IsOnline = online;
        if (!online)
        {
            // Clock related safety: the friend's next DHT key announcement must be accepted.
            friend.LastNoReplay = 0;
            friend.RunCount = 0;
        }
    }

    private OnionFriend? GetFriend(int friendNumber) =>
        friendNumber >= 0 && friendNumber < _friends.Count ? _friends[friendNumber] : null;

    // ================================================================ path nodes

    /// <summary>Bootstrap nodes double as path nodes until the DHT gives us better ones.</summary>
    public void AddBootstrapPathNode(NodeInfo node) =>
        AddRing(_bootstrapPathNodes, ref _bootstrapPathNodesNext, node);

    private void AddPathNode(NodeInfo node) => AddRing(_pathNodes, ref _pathNodesNext, node);

    private static void AddRing(List<NodeInfo> ring, ref int next, NodeInfo node)
    {
        if (node.Protocol != TransportProtocol.Udp)
            return;
        if (ring.Exists(n => n.PublicKey.AsSpan().SequenceEqual(node.PublicKey)))
            return;

        if (ring.Count < MaxPathNodes)
            ring.Add(node);
        else
            ring[next % MaxPathNodes] = node;
        next++;
    }

    /// <summary>Nodes worth saving: they will be our first path nodes next time.</summary>
    public List<NodeInfo> GetBackupNodes(int max)
    {
        var result = new List<NodeInfo>();
        for (int i = 0; i < _pathNodes.Count && result.Count < max; i++)
            result.Add(_pathNodes[(_pathNodesNext - 1 - i + _pathNodes.Count * 2) % _pathNodes.Count]);
        foreach (var node in _bootstrapPathNodes)
        {
            if (result.Count >= max)
                break;
            if (!result.Exists(n => n.PublicKey.AsSpan().SequenceEqual(node.PublicKey)))
                result.Add(node);
        }
        return result;
    }

    // ================================================================ paths

    private bool PathTimedOut(OnionPathSet set, int slot, DateTimeOffset now)
    {
        bool isNew = set.LastSuccess[slot] == set.CreationTime[slot];
        var timeout = isNew ? PathFirstTimeout : PathTimeout;
        return (set.UsedTimes[slot] >= MaxPathNoResponseUses && IsTimeout(now, set.LastUsed[slot], timeout))
               || IsTimeout(now, set.CreationTime[slot], PathMaxLifetime)
               || set.Paths[slot] is null;
    }

    /// <summary>Picks (and if needed builds) a path; <paramref name="pathNumber"/> = uint.MaxValue for a random one.</summary>
    private OnionPath? GetPath(OnionPathSet set, uint pathNumber)
    {
        var now = Now;
        int slot = pathNumber == uint.MaxValue ? Random.Shared.Next(OnionPathSet.Count) : (int)(pathNumber % OnionPathSet.Count);

        if (PathTimedOut(set, slot, now))
        {
            var nodes = RandomPathNodes();
            if (nodes is null)
                return null;

            int reuse = FindSimilarPath(set, nodes, now);
            if (reuse < 0)
            {
                var path = OnionPath.Create(_crypto, _dht.PublicKey, _dht.SecretKey, nodes);
                if (path is null)
                    return null;

                uint random = (uint)Random.Shared.NextInt64(0, uint.MaxValue);
                path.PathNumber = random / OnionPathSet.Count * OnionPathSet.Count + (uint)slot;
                set.Paths[slot] = path;
                set.CreationTime[slot] = now;
                set.LastSuccess[slot] = now;
                set.UsedTimes[slot] = MaxPathNoResponseUses / 2;
            }
            else
            {
                slot = reuse;
            }
        }

        if (set.UsedTimes[slot] < MaxPathNoResponseUses)
            set.LastUsed[slot] = now;
        set.UsedTimes[slot]++;
        return set.Paths[slot];
    }

    private static int FindSimilarPath(OnionPathSet set, List<NodeInfo> nodes, DateTimeOffset now)
    {
        for (int i = 0; i < OnionPathSet.Count; i++)
        {
            if (set.Paths[i] is not { } path)
                continue;
            if (IsTimeout(now, set.LastSuccess[i], PathTimeout) || IsTimeout(now, set.CreationTime[i], PathMaxLifetime))
                continue;
            if (path.Endpoint1 == nodes[OnionPacket.PathLength - 1].Endpoint)
                return i;
        }
        return -1;
    }

    /// <summary>Three relay nodes, distinct when we know enough of them.</summary>
    private List<NodeInfo>? RandomPathNodes()
    {
        var pool = _dht.IsConnected && _pathNodes.Count > 0 ? _pathNodes : _bootstrapPathNodes;
        if (pool.Count == 0)
            return null;

        if (pool.Count >= OnionPacket.PathLength)
        {
            var copy = pool.ToArray();
            Random.Shared.Shuffle(copy);
            return copy.Take(OnionPacket.PathLength).ToList();
        }

        var nodes = new List<NodeInfo>(OnionPacket.PathLength);
        for (int i = 0; i < OnionPacket.PathLength; i++)
            nodes.Add(pool[Random.Shared.Next(pool.Count)]);
        return nodes;
    }

    /// <summary>A response came back through this path: it works. Its nodes are good path nodes too.</summary>
    private uint MarkPathSuccess(uint number, uint pathNumber)
    {
        var set = number == 0 ? _selfPaths : _friendPaths;
        int slot = (int)(pathNumber % OnionPathSet.Count);
        if (set.Paths[slot] is not { } path || path.PathNumber != pathNumber)
            return uint.MaxValue;

        set.LastSuccess[slot] = Now;
        set.UsedTimes[slot] = 0;
        foreach (var node in path.Nodes)
            AddPathNode(node);
        return pathNumber;
    }

    private bool SendThroughPath(OnionPath path, IpPort destination, ReadOnlySpan<byte> data)
    {
        var packet = OnionPacket.Create(_crypto, path, destination, data);
        return packet is not null && _sender.Send(path.Endpoint1, packet);
    }

    // ================================================================ announce requests

    /// <summary>
    /// Sends an announce request (number 0: our own announcement) or a search request
    /// (number = 1 + friend number) to an announce node.
    /// </summary>
    private bool SendAnnounceRequest(uint number, IpPort destination, byte[] destinationKey, byte[]? pingId, uint pathNumber)
    {
        OnionFriend? friend = null;
        if (number != 0 && (friend = GetFriend((int)number - 1)) is null)
            return false;

        var path = GetPath(number == 0 ? _selfPaths : _friendPaths, pathNumber);
        if (path is null)
            return false;

        ulong sendback = NewSendback(number, destinationKey, destination, path.PathNumber);
        if (sendback == 0)
            return false;

        byte[]? request = friend is null
            ? CreateAnnounceRequest(destinationKey, _identity, pingId, _identity.PublicKey, _tempKeys.PublicKey, sendback)
            : CreateAnnounceRequest(destinationKey, friend.TempKeys, null, friend.RealPublicKey,
                new byte[CryptoConstants.PublicKeySize], sendback);

        return request is not null && SendThroughPath(path, destination, request);
    }

    /// <summary>[0x83][nonce][our key][encrypted for the node: ping id, searched key, data key, sendback].</summary>
    private byte[]? CreateAnnounceRequest(byte[] nodeKey, KeyPair keys, byte[]? pingId, byte[] searchedKey,
        byte[] dataPublicKey, ulong sendback)
    {
        var plain = new byte[TimedAuth.Size + CryptoConstants.PublicKeySize * 2 + OnionAnnounceServer.SendbackSize];
        pingId?.CopyTo(plain, 0);
        searchedKey.CopyTo(plain, TimedAuth.Size);
        dataPublicKey.CopyTo(plain, TimedAuth.Size + CryptoConstants.PublicKeySize);
        BinaryPrimitives.WriteUInt64LittleEndian(plain.AsSpan(TimedAuth.Size + CryptoConstants.PublicKeySize * 2), sendback);

        var nonce = Nonce.Random();
        var cipher = _crypto.Box(nodeKey, keys.SecretKey, nonce, plain);
        if (cipher is null)
            return null;

        var request = new byte[1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize + cipher.Length];
        request[0] = (byte)PacketKind.AnnounceRequest;
        nonce.CopyTo(request, 1);
        keys.PublicKey.CopyTo(request, 1 + CryptoConstants.NonceSize);
        cipher.CopyTo(request, 1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize);
        return request;
    }

    /// <summary>The sendback is an opaque id the node echoes: it tells us which request a response answers.</summary>
    private ulong NewSendback(uint number, byte[] publicKey, IpPort endpoint, uint pathNumber)
    {
        var now = Now;
        if (_sendbacks.Count >= MaxSendbacks)
        {
            foreach (var (key, value) in _sendbacks.ToList())
                if (IsTimeout(now, value.SentAt, SendbackTimeout))
                    _sendbacks.Remove(key);
            if (_sendbacks.Count >= MaxSendbacks)
                _sendbacks.Remove(_sendbacks.MinBy(s => s.Value.SentAt).Key);
        }

        ulong id;
        do id = BinaryPrimitives.ReadUInt64LittleEndian(RandomNumberGenerator.GetBytes(8));
        while (id == 0 || _sendbacks.ContainsKey(id));

        _sendbacks[id] = new Sendback(number, publicKey, endpoint, pathNumber, now);
        return id;
    }

    private Sendback? TakeSendback(ReadOnlySpan<byte> bytes)
    {
        ulong id = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        if (!_sendbacks.Remove(id, out var sendback) || IsTimeout(Now, sendback.SentAt, SendbackTimeout))
            return null;
        return sendback;
    }

    // ================================================================ announce responses

    private void HandleAnnounceResponse(IpPort source, ReadOnlySpan<byte> packet, bool withCount)
    {
        if (packet.Length < AnnounceResponseMinSize || packet.Length > OnionPacket.MaxPacketSize)
            return;

        var sendback = TakeSendback(packet.Slice(1, OnionAnnounceServer.SendbackSize));
        if (sendback is null)
            return;

        uint number = sendback.Number;
        byte[] secretKey;
        if (number == 0)
        {
            secretKey = _identity.SecretKey;
        }
        else
        {
            if (GetFriend((int)number - 1) is not { } friend)
                return;
            secretKey = friend.TempKeys.SecretKey;
        }

        const int nonceOffset = 1 + OnionAnnounceServer.SendbackSize;
        var plain = _crypto.Unbox(sendback.PublicKey, secretKey, packet.Slice(nonceOffset, CryptoConstants.NonceSize),
            packet[(nonceOffset + CryptoConstants.NonceSize)..]);
        if (plain is null || plain.Length < 1 + TimedAuth.Size)
            return;

        uint pathUsed = MarkPathSuccess(number, sendback.PathNumber);
        if (!AddToList(number, sendback.PublicKey, sendback.Endpoint, plain[0], plain.AsSpan(1, TimedAuth.Size).ToArray(), pathUsed))
            return;

        var rest = plain.AsSpan(1 + TimedAuth.Size);
        List<NodeInfo> nodes;
        if (withCount)
        {
            if (rest.IsEmpty || rest[0] > DhtPayloads.MaxNodes
                             || !NodeInfo.TryUnpackMany(rest[1..], rest[0], out nodes!, out _))
                return;
        }
        else
        {
            nodes = UnpackNodes(rest, DhtPayloads.MaxNodes);
        }

        PingNodes(number, nodes, source);
        _lastPacketReceived = Now;
    }

    /// <summary>toxcore's client_add_to_list: keep the closest live nodes to the key we announce or search.</summary>
    private bool AddToList(uint number, byte[] publicKey, IpPort endpoint, byte isStored, byte[] pingIdOrKey, uint pathUsed)
    {
        OnionNode[] list;
        byte[] reference;
        if (number == 0)
        {
            list = _announceNodes;
            reference = _identity.PublicKey;
            if (isStored == 1 && !pingIdOrKey.AsSpan().SequenceEqual(_tempKeys.PublicKey))
                isStored = 0;
        }
        else
        {
            if (isStored >= 2 || GetFriend((int)number - 1) is not { } friend)
                return false;
            list = friend.Nodes;
            reference = friend.RealPublicKey;
        }

        var now = Now;
        OnionNode.Sort(list, reference, now);

        int index = -1;
        bool alreadyStored = false;
        if (list[0].IsTimedOut(now) || XorDistance.Compare(reference, publicKey, list[0].PublicKey) < 0)
            index = 0;
        for (int i = 0; i < list.Length; i++)
        {
            if (list[i].PublicKey.AsSpan().SequenceEqual(publicKey))
            {
                index = i;
                alreadyStored = true;
                break;
            }
        }

        if (index < 0)
            return true;

        var node = list[index];
        node.PublicKey = publicKey;
        node.Endpoint = endpoint;
        AddPathNode(new NodeInfo(TransportProtocol.Udp, endpoint, publicKey));

        if (isStored == 1)
            node.DataPublicKey = pingIdOrKey;
        else
            node.PingId = pingIdOrKey;

        node.IsStored = isStored;
        node.Timestamp = now;
        node.PingsSinceLastResponse = 0;
        if (!alreadyStored)
        {
            node.LastPinged = Never;
            node.AddedTime = now;
        }
        node.PathUsed = pathUsed;
        return true;
    }

    /// <summary>Nodes from a response that are closer than our worst ones get an announce request too.</summary>
    private void PingNodes(uint number, List<NodeInfo> nodes, IpPort source)
    {
        OnionNode[] list;
        byte[] reference;
        RecentlyPinged recent;
        if (number == 0)
        {
            list = _announceNodes;
            reference = _identity.PublicKey;
            recent = _recentlyPinged;
        }
        else
        {
            if (GetFriend((int)number - 1) is not { } friend)
                return;
            list = friend.Nodes;
            reference = friend.RealPublicKey;
            recent = friend.RecentlyPinged;
        }

        var now = Now;
        bool lanAccepted = source.IsLan();
        foreach (var node in nodes)
        {
            if (node.Protocol != TransportProtocol.Udp || (!lanAccepted && node.Endpoint.IsLan()))
                continue;

            bool better = list[0].IsTimedOut(now) || XorDistance.Compare(reference, node.PublicKey, list[0].PublicKey) < 0
                          || list[1].IsTimedOut(now) || XorDistance.Compare(reference, node.PublicKey, list[1].PublicKey) < 0;
            if (!better)
                continue;
            if (Array.Exists(list, n => n.PublicKey.AsSpan().SequenceEqual(node.PublicKey)))
                continue;
            if (!_sender.CanReach(node.Endpoint) || !recent.TryMark(node.PublicKey, now))
                continue;

            SendAnnounceRequest(number, node.Endpoint, node.PublicKey, null, uint.MaxValue);
        }
    }

    private static List<NodeInfo> UnpackNodes(ReadOnlySpan<byte> data, int max)
    {
        var nodes = new List<NodeInfo>();
        while (!data.IsEmpty && nodes.Count < max && NodeInfo.TryUnpack(data, out var node, out int read))
        {
            nodes.Add(node);
            data = data[read..];
        }
        return nodes;
    }

    // ================================================================ data packets

    /// <summary>
    /// [0x86][nonce][temp key][encrypted for our data key: [sender real key][encrypted for our real key: data]].
    /// The double encryption authenticates the sender's long-term key end to end.
    /// </summary>
    private void HandleDataResponse(IpPort source, ReadOnlySpan<byte> packet)
    {
        const int headerSize = 1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize;
        if (packet.Length <= headerSize + CryptoConstants.MacSize + DataInResponseMinSize || packet.Length > MaxDataRequestSize)
            return;

        var nonce = packet.Slice(1, CryptoConstants.NonceSize);
        var outer = _crypto.Unbox(packet.Slice(1 + CryptoConstants.NonceSize, CryptoConstants.PublicKeySize),
            _tempKeys.SecretKey, nonce, packet[headerSize..]);
        if (outer is null || outer.Length <= DataInResponseMinSize)
            return;

        var senderKey = outer.AsSpan(0, CryptoConstants.PublicKeySize).ToArray();
        var plain = _crypto.Unbox(senderKey, _identity.SecretKey, nonce, outer.AsSpan(CryptoConstants.PublicKeySize));
        if (plain is null || plain.Length == 0)
            return;

        if (_dataHandlers.TryGetValue(plain[0], out var handler))
            handler(senderKey, plain);
    }

    /// <summary>
    /// Sends data to a friend through the nodes storing its announcement (toxcore's send_onion_data).
    /// Returns the number of copies sent, or -1 if we do not know enough nodes for that friend yet.
    /// </summary>
    public int SendData(int friendNumber, ReadOnlySpan<byte> data)
    {
        if (GetFriend(friendNumber) is not { } friend || data.IsEmpty || data.Length > MaxDataSize)
            return -1;

        var now = Now;
        var good = new List<OnionNode>();
        int alive = 0;
        foreach (var node in friend.Nodes)
        {
            if (node.IsTimedOut(now))
                continue;
            alive++;
            if (node.IsStored != 0)
                good.Add(node);
        }

        if (alive == 0 || good.Count < (alive - 1) / 4 + 1)
            return -1;

        var nonce = Nonce.Random();
        var inner = _crypto.Box(friend.RealPublicKey, _identity.SecretKey, nonce, data);
        if (inner is null)
            return -1;

        var payload = new byte[CryptoConstants.PublicKeySize + inner.Length];
        _identity.PublicKey.CopyTo(payload, 0);
        inner.CopyTo(payload, CryptoConstants.PublicKeySize);

        int sent = 0;
        foreach (var node in good)
        {
            var path = GetPath(_friendPaths, uint.MaxValue);
            if (path is null)
                continue;

            var request = CreateDataRequest(friend.RealPublicKey, node.DataPublicKey, nonce, payload);
            if (request is not null && SendThroughPath(path, node.Endpoint, request))
                sent++;
        }
        return sent;
    }

    /// <summary>[0x85][friend real key][nonce][random key][encrypted for the friend's data key].</summary>
    private byte[]? CreateDataRequest(byte[] friendKey, byte[] dataKey, byte[] nonce, byte[] payload)
    {
        if (DataRequestMinSize + payload.Length > OnionPacket.MaxDataSize)
            return null;

        using var temp = _crypto.GenerateKeyPair();
        var cipher = _crypto.Box(dataKey, temp.SecretKey, nonce, payload);
        if (cipher is null)
            return null;

        var request = new byte[1 + CryptoConstants.PublicKeySize * 2 + CryptoConstants.NonceSize + cipher.Length];
        request[0] = (byte)PacketKind.OnionDataRequest;
        friendKey.CopyTo(request, 1);
        nonce.CopyTo(request, 1 + CryptoConstants.PublicKeySize);
        temp.PublicKey.CopyTo(request, 1 + CryptoConstants.PublicKeySize + CryptoConstants.NonceSize);
        cipher.CopyTo(request, 1 + CryptoConstants.PublicKeySize * 2 + CryptoConstants.NonceSize);
        return request;
    }

    // ================================================================ DHT key announcements

    /// <summary>
    /// [156][no-replay 8][our DHT key][up to 4 nodes close to it]. Sent through the onion and, when
    /// some DHT node knows the friend, through the DHT as a crypto request. The receiver searches
    /// our DHT key starting from the nodes listed.
    /// </summary>
    private int SendDhtPkAnnounce(int friendNumber, bool viaOnion, bool viaDht)
    {
        if (GetFriend(friendNumber) is not { } friend)
            return -1;

        var nodes = _dht.FindClosest(_dht.PublicKey, DhtPayloads.MaxNodes).Where(n => n.Protocol == TransportProtocol.Udp).ToList();
        var data = new byte[DhtPkDataMinSize + nodes.Sum(n => n.PackedSize)];
        data[0] = DataDhtPublicKey;
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(1), (ulong)Now.ToUnixTimeSeconds());
        _dht.PublicKey.CopyTo(data, 1 + sizeof(ulong));
        NodeInfo.PackMany(nodes, data.AsSpan(DhtPkDataMinSize));

        int sent = -1;
        if (viaOnion)
            sent = SendData(friendNumber, data);

        if (viaDht && friend.DhtPublicKey is not null)
        {
            int viaDhtCount = SendDhtPkViaDht(friend, data);
            sent = sent < 0 ? viaDhtCount : sent + viaDhtCount;
        }
        return sent;
    }

    private int SendDhtPkViaDht(OnionFriend friend, byte[] data)
    {
        var nonce = Nonce.Random();
        var cipher = _crypto.Box(friend.RealPublicKey, _identity.SecretKey, nonce, data);
        if (cipher is null)
            return -1;

        var temp = new byte[CryptoConstants.PublicKeySize + CryptoConstants.NonceSize + cipher.Length];
        _identity.PublicKey.CopyTo(temp, 0);
        nonce.CopyTo(temp, CryptoConstants.PublicKeySize);
        cipher.CopyTo(temp, CryptoConstants.PublicKeySize + CryptoConstants.NonceSize);

        var packet = _dht.CreateCryptoRequest(friend.DhtPublicKey!, CryptoRequest.DhtPublicKey, temp);
        return packet is null ? -1 : _dht.RouteToFriend(friend.DhtPublicKey!, packet);
    }

    /// <summary>The DHT variant: [sender real key][nonce][encrypted announcement].</summary>
    private void HandleDhtPkFromDht(IpPort source, byte[] senderDhtKey, byte[] data)
    {
        const int overhead = DataInResponseMinSize + CryptoConstants.NonceSize;
        if (data.Length < DhtPkDataMinSize + overhead || data.Length > DhtPkDataMaxSize + overhead)
            return;

        var realKey = data.AsSpan(0, CryptoConstants.PublicKeySize).ToArray();
        var plain = _crypto.Unbox(realKey, _identity.SecretKey,
            data.AsSpan(CryptoConstants.PublicKeySize, CryptoConstants.NonceSize),
            data.AsSpan(CryptoConstants.PublicKeySize + CryptoConstants.NonceSize));
        if (plain is null || plain.Length < DhtPkDataMinSize)
            return;

        // The DHT key inside must be the one that signed the crypto request.
        if (!plain.AsSpan(1 + sizeof(ulong), CryptoConstants.PublicKeySize).SequenceEqual(senderDhtKey))
            return;

        HandleDhtPkAnnounce(realKey, plain);
    }

    private void HandleDhtPkAnnounce(byte[] senderRealKey, byte[] data)
    {
        if (data.Length < DhtPkDataMinSize || data.Length > DhtPkDataMaxSize)
            return;

        int friendNumber = FindFriend(senderRealKey);
        if (GetFriend(friendNumber) is not { } friend)
            return;

        ulong noReplay = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(1));
        if (noReplay <= friend.LastNoReplay)
            return;
        friend.LastNoReplay = noReplay;

        var dhtKey = data.AsSpan(1 + sizeof(ulong), CryptoConstants.PublicKeySize).ToArray();
        friend.DhtPublicKeyReceived?.Invoke(dhtKey);
        friend.DhtPublicKey = dhtKey;

        foreach (var node in UnpackNodes(data.AsSpan(DhtPkDataMinSize), DhtPayloads.MaxNodes))
            if (node.Protocol == TransportProtocol.Udp)
                _dht.SendNodesRequest(node, dhtKey);
    }

    // ================================================================ main loop

    /// <summary>Runs at most once per second, like toxcore's do_onion_client.</summary>
    public void Tick()
    {
        var now = Now;
        long second = now.ToUnixTimeSeconds();
        if (second == _lastRunSecond)
            return;

        if (IsTimeout(now, _firstRun, ConnectionSeconds))
        {
            foreach (var node in _dht.GetRandomNodes(MaxFriendNodes))
                AddPathNode(node);
            DoAnnounce(now);
        }

        if (IsConnected(now))
        {
            if (IsTimeout(now, _lastTimeConnected, ConnectedTimeout))
            {
                foreach (var friend in _friends)
                    if (friend is not null)
                        friend.RunCount = 0;
            }
            _lastTimeConnected = now;
            if (_onionConnected < OnionConnectionSeconds * 2)
                _onionConnected++;
        }
        else if (_onionConnected > 0)
        {
            _onionConnected--;
        }

        if (ConnectionStatus != OnionConnectionStatus.None)
            for (int i = 0; i < _friends.Count; i++)
                DoFriend(i, now);

        if (_lastRunSecond == 0)
            _firstRun = now;
        _lastRunSecond = second;
    }

    private bool IsConnected(DateTimeOffset now)
    {
        if (IsTimeout(now, _lastPacketReceived, OfflineTimeout) || _pathNodes.Count == 0)
        {
            _lastPopulated = Never;
            return false;
        }

        int live = 0, announced = 0;
        foreach (var node in _announceNodes)
        {
            if (node.IsTimedOut(now))
                continue;
            live++;
            if (node.IsStored != 0)
                announced++;
        }

        int pathNodes = Math.Min(_pathNodes.Count, MaxAnnounceNodes);
        if (live != 0 && announced != 0 && live / 2 <= announced && pathNodes / 2 <= live)
            return true;

        _lastPopulated = Never;
        return false;
    }

    /// <summary>Keeps our announcement alive on the closest nodes, and looks for closer ones.</summary>
    private void DoAnnounce(DateTimeOffset now)
    {
        int count = 0;
        foreach (var node in _announceNodes)
        {
            if (node.IsTimedOut(now))
                continue;
            count++;

            // Don't announce to new nodes the first time round.
            if (node.LastPinged == Never)
            {
                node.LastPinged = Never.AddSeconds(1);
                continue;
            }

            if (node.PingsSinceLastResponse >= NodeMaxPings)
                continue;

            var interval = AnnounceIntervalNotAnnounced;
            if (node.IsStored != 0 && PathExists(_selfPaths, node.PathUsed, now))
            {
                interval = AnnounceIntervalAnnounced;
                if (PathIsStable(_selfPaths, (int)(node.PathUsed % OnionPathSet.Count), node, now))
                    interval = AnnounceIntervalStable;
            }

            if (!IsTimeout(now, node.LastPinged, interval) && !IsTimeout(now, _lastAnnounce, NodePingInterval))
                continue;

            uint path = node.PathUsed;
            if (node.PingsSinceLastResponse == NodeMaxPings - 1 && IsTimeout(now, node.AddedTime, TimeToStable))
                path = uint.MaxValue; // last chance for a long-lived node: try another path

            if (SendAnnounceRequest(0, node.Endpoint, node.PublicKey, node.PingId, path))
            {
                node.LastPinged = now;
                node.PingsSinceLastResponse++;
                _lastAnnounce = now;
            }
        }

        if (count == MaxAnnounceNodes)
        {
            _lastPopulated = now;
            return;
        }

        if (count > MaxAnnounceNodes / 2 && !IsTimeout(now, _lastPopulated, PopulateTimeout))
            return;

        var pool = _pathNodes.Count == 0 ? _bootstrapPathNodes : _pathNodes;
        if (pool.Count == 0)
            return;

        var targets = new HashSet<byte[]>(PublicKeyComparer.Instance);
        for (int i = 0; i < MaxAnnounceNodes / 2; i++)
        {
            var target = pool[Random.Shared.Next(pool.Count)];
            if (targets.Add(target.PublicKey))
                SendAnnounceRequest(0, target.Endpoint, target.PublicKey, null, uint.MaxValue);
        }
    }

    private bool PathExists(OnionPathSet set, uint pathNumber, DateTimeOffset now)
    {
        int slot = (int)(pathNumber % OnionPathSet.Count);
        return !PathTimedOut(set, slot, now) && set.Paths[slot]?.PathNumber == pathNumber;
    }

    private static bool PathIsStable(OnionPathSet set, int slot, OnionNode node, DateTimeOffset now) =>
        IsTimeout(now, node.AddedTime, TimeToStable)
        && !(node.PingsSinceLastResponse > 0 && IsTimeout(now, node.LastPinged, NodeTimeout))
        && IsTimeout(now, set.CreationTime[slot], TimeToStable)
        && !(set.UsedTimes[slot] > 0 && IsTimeout(now, set.LastUsed[slot], PathTimeout));

    /// <summary>Searches an offline friend and sends it our DHT key; the longer it stays offline, the less often.</summary>
    private void DoFriend(int friendNumber, DateTimeOffset now)
    {
        if (GetFriend(friendNumber) is not { } friend || friend.IsOnline)
            return;

        bool isNew = friend.RunCount <= FriendRunCountBeginning;
        uint interval = isNew
            ? FriendNewInterval
            : Math.Min(1u << (int)Math.Min(MaxRunCountExponent, friend.RunCount - 2), FriendMaxInterval);
        var intervalSpan = TimeSpan.FromSeconds(interval);

        if (IsTimeout(now, friend.LastDhtPkOnionSent, DhtPkOnionInterval) && SendDhtPkAnnounce(friendNumber, true, false) >= 1)
            friend.LastDhtPkOnionSent = now;
        if (IsTimeout(now, friend.LastDhtPkDhtSent, DhtPkDhtInterval) && SendDhtPkAnnounce(friendNumber, false, true) >= 1)
            friend.LastDhtPkDhtSent = now;

        int count = 0;
        foreach (var node in friend.Nodes)
        {
            if (node.IsTimedOut(now))
                continue;
            count++;

            if (node.LastPinged == Never)
            {
                node.LastPinged = now; // new nodes are not pinged immediately
                continue;
            }

            if (node.PingsSinceLastResponse >= NodeMaxPings)
                continue;
            if (!IsTimeout(now, friend.TimeLastPinged, TimeSpan.FromSeconds(interval / (MaxFriendNodes / 2)))) // integer division, as in toxcore
                continue;
            if (!IsTimeout(now, node.LastPinged, intervalSpan))
                continue;

            if (SendAnnounceRequest((uint)friendNumber + 1, node.Endpoint, node.PublicKey, null, uint.MaxValue))
            {
                node.LastPinged = now;
                friend.TimeLastPinged = now;
                node.PingsSinceLastResponse++;
                friend.Pings++;
                if (friend.Pings % (MaxFriendNodes / 2) == 0)
                    friend.RunCount++;
            }
        }

        if (count == MaxFriendNodes)
        {
            if (!isNew)
                friend.LastPopulated = now;
            return;
        }

        if (count > MaxFriendNodes / 2 && !IsTimeout(now, friend.LastPopulated, PopulateTimeout))
            return;

        int n = Math.Min(_pathNodes.Count, MaxPathNodes / 4);
        if (n == 0)
            return;

        friend.LastPopulated = now;
        for (int i = 0; i < n; i++)
        {
            var target = _pathNodes[Random.Shared.Next(_pathNodes.Count)];
            SendAnnounceRequest((uint)friendNumber + 1, target.Endpoint, target.PublicKey, null, uint.MaxValue);
        }
    }

    public void Dispose()
    {
        _tempKeys.Dispose();
        foreach (var friend in _friends)
            friend?.Dispose();
    }
}
