using System.Diagnostics.CodeAnalysis;
using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>Handles a DHT crypto request addressed to us; <paramref name="data"/> excludes the request id.</summary>
internal delegate void CryptoRequestHandler(IpPort source, byte[] senderPublicKey, byte[] data);

/// <summary>
/// A Tox DHT participant.
///
/// What it does:
///  - answers pings and nodes requests from other nodes (this is how we serve the network);
///  - joins the network by asking a bootstrap node for the nodes closest to our own key, then
///    asking those nodes in turn: each answer brings us closer, like an iterative Kademlia lookup;
///  - keeps the routing table fresh: pings every node every 60 s and drops nodes silent for 122 s;
///  - searches the DHT keys of our friends to learn their IP address (see DhtNode.Friends.cs);
///  - forwards crypto requests (0x20) to nodes it knows, and helps friends behind NATs (DhtNode.Nat.cs).
///
/// A node enters the routing table only after it has answered one of our requests
/// (valid ping response or nodes response). Nodes merely mentioned by others are just candidates.
///
/// The DHT key pair is temporary (new on every start): it is NOT the Tox identity, so DHT
/// nodes cannot link our IP address to our Tox ID.
///
/// Not thread-safe by design: everything runs on the event loop.
/// </summary>
public sealed partial class DhtNode : IDisposable
{
    public static readonly TimeSpan PingInterval = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan BadNodeTimeout = TimeSpan.FromSeconds(122);
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan NodesRequestInterval = TimeSpan.FromSeconds(20);

    /// <summary>Saved nodes are retried in groups of this size while we are offline.</summary>
    private const int SavedNodesPerRound = 8;

    private readonly ICryptoCore _crypto;
    private readonly IPacketSender _sender;
    private readonly TimeProvider _time;
    private readonly KeyPair _keys;
    private readonly RoutingTable _table;
    private readonly PendingRequests _pending;
    private readonly SharedKeyCache _sharedKeys;
    private readonly List<NodeInfo> _bootstrapNodes = [];
    private readonly List<NodeInfo> _savedNodes = [];
    private readonly CryptoRequestHandler?[] _cryptoHandlers = new CryptoRequestHandler?[256];
    private int _savedNodesIndex;
    private int _bootstrapTimes;
    private DateTimeOffset _lastNodesRequest = DateTimeOffset.MinValue;
    private DateTimeOffset _lastSecondTick = DateTimeOffset.MinValue;

    /// <summary>Raised when a node is verified and enters the routing table.</summary>
    public event Action<NodeInfo>? NodeAdded;

    public DhtNode(ICryptoCore crypto, IPacketSender sender, TimeProvider? timeProvider = null)
    {
        _crypto = crypto;
        _sender = sender;
        _time = timeProvider ?? TimeProvider.System;
        _keys = crypto.GenerateKeyPair();
        _table = new RoutingTable(_keys.PublicKey, BadNodeTimeout);
        _pending = new PendingRequests(RequestTimeout, capacity: 512);
        _sharedKeys = new SharedKeyCache(crypto, _keys.SecretKey);

        _cryptoHandlers[CryptoRequest.NatPing] = HandleNatPing;
    }

    /// <summary>Our temporary DHT public key.</summary>
    public byte[] PublicKey => _keys.PublicKey;

    internal byte[] SecretKey => _keys.SecretKey;

    internal ICryptoCore Crypto => _crypto;

    internal IPacketSender Sender => _sender;

    public int KnownNodeCount => _table.Count;

    /// <summary>True when at least one verified node is alive.</summary>
    public bool IsConnected => _table.Entries.Any(e => !e.IsBad(Now, BadNodeTimeout));

    /// <summary>True when a verified node outside our LAN is alive (we are on the Internet DHT).</summary>
    public bool IsConnectedToInternet =>
        _table.Entries.Any(e => !e.IsBad(Now, BadNodeTimeout) && !e.Node.Endpoint.IsLan());

    public bool HolePunchingEnabled { get; set; } = true;
    public bool LanDiscoveryEnabled { get; set; } = true;

    public IReadOnlyList<NodeInfo> GetKnownNodes() => _table.Entries.Select(e => e.Node).ToList();

    /// <summary>The <paramref name="count"/> known nodes closest to a key (used by the onion layer).</summary>
    public IReadOnlyList<NodeInfo> FindClosest(ReadOnlySpan<byte> target, int count) =>
        _table.FindClosest(target, count, Now);

    /// <summary>Closest good nodes for a peer at <paramref name="requester"/>; LAN nodes only for LAN peers.</summary>
    internal List<NodeInfo> FindClosestFor(ReadOnlySpan<byte> target, int count, IpPort requester) =>
        _table.FindClosest(target, count, Now,
            n => n.Protocol == TransportProtocol.Udp && (requester.IsLan() || !n.Endpoint.IsLan()));

    /// <summary>Up to <paramref name="count"/> distinct random good nodes (onion path candidates).</summary>
    internal List<NodeInfo> GetRandomNodes(int count)
    {
        var now = Now;
        var good = _table.Entries.Where(e => !e.IsBad(now, BadNodeTimeout)).Select(e => e.Node).ToArray();
        Random.Shared.Shuffle(good);
        return good.Take(count).ToList();
    }

    private DateTimeOffset Now => _time.GetUtcNow();

    public void Attach(PacketDispatcher dispatcher)
    {
        dispatcher.Register(PacketKind.PingRequest, HandlePingRequest);
        dispatcher.Register(PacketKind.PingResponse, HandlePingResponse);
        dispatcher.Register(PacketKind.NodesRequest, HandleNodesRequest);
        dispatcher.Register(PacketKind.NodesResponse, HandleNodesResponse);
        dispatcher.Register(PacketKind.Crypto, HandleCryptoRequest);
        dispatcher.Register(PacketKind.LanDiscovery, HandleLanDiscovery);
    }

    internal void RegisterCryptoHandler(byte requestId, CryptoRequestHandler handler) =>
        _cryptoHandlers[requestId] = handler;

    /// <summary>Contacts a well-known node; it is remembered and retried while our table is empty.</summary>
    public void Bootstrap(IpPort endpoint, byte[] publicKey)
    {
        var node = new NodeInfo(TransportProtocol.Udp, endpoint, publicKey);
        if (!_bootstrapNodes.Exists(n => n.Endpoint == endpoint))
            _bootstrapNodes.Add(node);

        SendNodesRequest(node, _keys.PublicKey);
    }

    /// <summary>Nodes from a previous session (savedata): contacted a few at a time while offline.</summary>
    internal void AddSavedNodes(IEnumerable<NodeInfo> nodes)
    {
        foreach (var node in nodes)
            if (node.Protocol == TransportProtocol.Udp && !_savedNodes.Exists(n => n.Endpoint == node.Endpoint))
                _savedNodes.Add(node);
    }

    /// <summary>Periodic maintenance, called by the event loop.</summary>
    public void Tick()
    {
        var now = Now;
        _pending.Prune(now);
        _table.RemoveBad(now);

        // Keep-alive: a node that stops answering becomes "bad" and will be replaced. Like toxcore,
        // the keep-alive is a nodes request for our own key: the answer proves the node is alive and
        // also keeps our lookup converging as the network changes.
        foreach (var entry in _table.Entries.ToList())
        {
            if (now - entry.LastPinged >= PingInterval)
            {
                entry.LastPinged = now;
                SendNodesRequest(entry.Node, _keys.PublicKey);
            }
        }

        // Keep looking for nodes closer to us (every second while bootstrapping, then every 20 s);
        // with an empty table, fall back to bootstrap nodes.
        if (now - _lastNodesRequest >= NodesRequestInterval
            || (_bootstrapTimes < MaxBootstrapTimes && now - _lastNodesRequest >= TimeSpan.FromSeconds(1)))
        {
            _lastNodesRequest = now;
            var candidates = _table.Count > 0 ? GetKnownNodes() : _bootstrapNodes;
            if (candidates.Count > 0)
            {
                SendNodesRequest(candidates[Random.Shared.Next(candidates.Count)], _keys.PublicKey);
                if (_table.Count > 0)
                    _bootstrapTimes++;
            }
        }

        if (now - _lastSecondTick < TimeSpan.FromSeconds(1))
            return;
        _lastSecondTick = now;

        if (!IsConnectedToInternet && _savedNodes.Count > 0)
        {
            for (int i = 0; i < SavedNodesPerRound && i < _savedNodes.Count; i++)
                SendNodesRequest(_savedNodes[_savedNodesIndex++ % _savedNodes.Count], _keys.PublicKey);
        }

        TickFriends(now);
        if (HolePunchingEnabled)
            TickNat(now);
    }

    // ---------------------------------------------------------------- handlers

    private void HandlePingRequest(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (!TryOpen(packet, out var senderKey, out var payload))
            return;
        if (!DhtPayloads.TryReadPing(payload, DhtPayloads.PingRequestType, out ulong id))
            return;

        Send(PacketKind.PingResponse, source, senderKey, DhtPayloads.WritePing(DhtPayloads.PingResponseType, id));
        ConsiderCandidate(new NodeInfo(TransportProtocol.Udp, source, senderKey), lookup: false);
    }

    private void HandlePingResponse(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (!TryOpen(packet, out var senderKey, out var payload))
            return;
        if (!DhtPayloads.TryReadPing(payload, DhtPayloads.PingResponseType, out ulong id))
            return;
        if (!_pending.TryComplete(id, RequestKind.Ping, source, senderKey, Now, out _))
            return;

        AddVerified(new NodeInfo(TransportProtocol.Udp, source, senderKey));
    }

    private void HandleNodesRequest(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (!TryOpen(packet, out var senderKey, out var payload))
            return;
        if (!DhtPayloads.TryReadNodesRequest(payload, out var target, out ulong id))
            return;

        // Never send the requester back to itself, and only nodes it could reach over UDP.
        var closest = _table.FindClosest(target, DhtPayloads.MaxNodes, Now,
            n => n.Protocol == TransportProtocol.Udp && !n.PublicKey.AsSpan().SequenceEqual(senderKey)
                                                     && (source.IsLan() || !n.Endpoint.IsLan()));

        // A friend we search for may be asked about itself (or about a node close to it): also
        // offer friends we have direct contact with, so lookups for them converge.
        AddDirectFriendsTo(closest, target, senderKey, source);

        Send(PacketKind.NodesResponse, source, senderKey, DhtPayloads.WriteNodesResponse(closest, id));
        ConsiderCandidate(new NodeInfo(TransportProtocol.Udp, source, senderKey), lookup: false);
    }

    private void HandleNodesResponse(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (!TryOpen(packet, out var senderKey, out var payload))
            return;
        if (!DhtPayloads.TryReadNodesResponse(payload, out var nodes, out ulong id))
            return;
        if (!_pending.TryComplete(id, RequestKind.Nodes, source, senderKey, Now, out var request))
            return;

        var responder = new NodeInfo(TransportProtocol.Udp, source, senderKey);
        AddVerified(responder);

        // The returned nodes are only candidates: ask them for nodes close to the key we are
        // looking for. Their answer verifies them and continues the lookup towards that key.
        foreach (var node in nodes)
        {
            OnReturnedNode(responder, node);
            ConsiderCandidate(node, lookup: true);
        }
    }

    private void HandleCryptoRequest(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (!CryptoRequest.HasValidLength(packet))
            return;

        var receiver = packet.Slice(CryptoRequest.ReceiverOffset, CryptoConstants.PublicKeySize);
        if (!receiver.SequenceEqual(_keys.PublicKey))
        {
            // Not for us: forward it if we know the receiver (this is what makes NAT ping and
            // DHT key announcements reach peers we cannot contact directly).
            if (TryFindNode(receiver, out var target))
                _sender.Send(target.Endpoint, packet);
            return;
        }

        var senderKey = packet.Slice(CryptoRequest.SenderOffset, CryptoConstants.PublicKeySize).ToArray();
        if (!_sharedKeys.TryGet(senderKey, out var sharedKey))
            return;
        if (!CryptoRequest.TryOpen(_crypto, packet, sharedKey, out byte requestId, out var data))
            return;

        _cryptoHandlers[requestId]?.Invoke(source, senderKey, data);
    }

    private void HandleLanDiscovery(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (!LanDiscoveryEnabled || !source.IsLan() || packet.Length != 1 + CryptoConstants.PublicKeySize)
            return;

        var key = packet[1..].ToArray();
        if (key.AsSpan().SequenceEqual(_keys.PublicKey))
            return; // our own broadcast

        SendNodesRequest(new NodeInfo(TransportProtocol.Udp, source, key), _keys.PublicKey);
    }

    // ---------------------------------------------------------------- helpers

    private void AddVerified(NodeInfo node)
    {
        var now = Now;
        if (_table.AddOrUpdate(node, now, out bool added) && added)
            NodeAdded?.Invoke(node);
        OfferToFriends(node, now);
    }

    private void ConsiderCandidate(NodeInfo node, bool lookup)
    {
        if (node.Protocol != TransportProtocol.Udp || !_sender.CanReach(node.Endpoint))
            return;
        if (node.PublicKey.AsSpan().SequenceEqual(_keys.PublicKey))
            return;
        if (_pending.IsPending(node.PublicKey))
            return;

        // A node close to one of our friends' keys: ask it about that friend.
        if (lookup && TryFriendLookup(node))
            return;

        if (_table.Find(node.PublicKey) is not null)
            return; // already known: kept alive by the periodic pings
        if (!_table.CanAccept(node.PublicKey, Now))
            return;

        if (lookup)
            SendNodesRequest(node, _keys.PublicKey);
        else
            SendPing(node);
    }

    /// <summary>A node we have verified, in the routing table or among a friend's close nodes.</summary>
    internal bool TryFindNode(ReadOnlySpan<byte> publicKey, [NotNullWhen(true)] out NodeInfo? node)
    {
        var entry = _table.Find(publicKey);
        if (entry is not null && !entry.IsBad(Now, BadNodeTimeout))
        {
            node = entry.Node;
            return true;
        }

        foreach (var friend in _friends.Values)
        {
            foreach (var close in friend.CloseNodes)
            {
                if (close.Node.PublicKey.AsSpan().SequenceEqual(publicKey) && !close.IsBad(Now, BadNodeTimeout))
                {
                    node = close.Node;
                    return true;
                }
            }
        }

        node = null;
        return false;
    }

    internal void SendPing(NodeInfo node)
    {
        if (!_pending.TryAdd(new PendingRequest(RequestKind.Ping, node.Endpoint, node.PublicKey, Now), Now, out ulong id))
            return;
        Send(PacketKind.PingRequest, node.Endpoint, node.PublicKey, DhtPayloads.WritePing(DhtPayloads.PingRequestType, id));
    }

    internal void SendNodesRequest(NodeInfo node, byte[] target)
    {
        if (!_pending.TryAdd(new PendingRequest(RequestKind.Nodes, node.Endpoint, node.PublicKey, Now, target), Now,
                out ulong id))
            return;
        Send(PacketKind.NodesRequest, node.Endpoint, node.PublicKey, DhtPayloads.WriteNodesRequest(target, id));
    }

    private void Send(PacketKind kind, IpPort destination, byte[] receiverKey, ReadOnlySpan<byte> payload)
    {
        if (!_sharedKeys.TryGet(receiverKey, out var sharedKey))
            return;
        _sender.Send(destination, DhtPacket.Create(_crypto, kind, _keys.PublicKey, sharedKey, payload));
    }

    /// <summary>Shared key between our DHT key and <paramref name="publicKey"/>, from the cache.</summary>
    internal bool TryGetSharedKey(byte[] publicKey, [NotNullWhen(true)] out byte[]? sharedKey)
    {
        if (_sharedKeys.TryGet(publicKey, out var key))
        {
            sharedKey = key;
            return true;
        }
        sharedKey = null;
        return false;
    }

    /// <summary>Builds a crypto request (0x20) from our DHT key to <paramref name="receiverPublicKey"/>.</summary>
    internal byte[]? CreateCryptoRequest(byte[] receiverPublicKey, byte requestId, ReadOnlySpan<byte> data)
    {
        if (!_sharedKeys.TryGet(receiverPublicKey, out var sharedKey))
            return null;
        return CryptoRequest.Create(_crypto, _keys.PublicKey, sharedKey, receiverPublicKey, requestId, data);
    }

    /// <summary>Validates and decrypts a DHT packet. Anything malformed is silently dropped.</summary>
    private bool TryOpen(ReadOnlySpan<byte> packet, [NotNullWhen(true)] out byte[]? senderKey,
        [NotNullWhen(true)] out byte[]? payload)
    {
        senderKey = null;
        payload = null;
        if (packet.Length < DhtPacket.MinSize)
            return false;

        var key = packet.Slice(DhtPacket.SenderKeyOffset, CryptoConstants.PublicKeySize);
        if (key.SequenceEqual(_keys.PublicKey))
            return false; // our own packet reflected back

        var keyArray = key.ToArray();
        if (!_sharedKeys.TryGet(keyArray, out var sharedKey))
            return false;

        var nonce = packet.Slice(DhtPacket.NonceOffset, CryptoConstants.NonceSize);
        payload = _crypto.Decrypt(sharedKey, nonce, packet[DhtPacket.PayloadOffset..]);
        if (payload is null)
            return false;

        senderKey = keyArray;
        return true;
    }

    public void Dispose() => _keys.Dispose();
}
