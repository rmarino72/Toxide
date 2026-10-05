using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Network;

namespace Toxide.Onion;

/// <summary>
/// The "rendezvous" side of the onion (toxcore onion_announce.c), run by every DHT node.
///
/// A Tox client announces itself, through an onion path, to the nodes whose DHT keys are closest
/// to its long-term public key. Those nodes remember the return path of the announcement, never
/// the client's IP. A friend looking for that public key asks the same nodes; data it sends there
/// (0x85) is forwarded to the client along the stored return path.
///
///   Announce request (0x83 / 0x87), as received from node 3:
///     [ kind ][ nonce ][ sender key ][ encrypted: ping id 32, searched key 32, data key 32, sendback 8 ][ return 3 ]
///   Response (0x84 / 0x88), sent back through the onion:
///     [ kind ][ sendback 8 ][ nonce ][ encrypted: is_stored 1, ping id or data key 32, (count 1), nodes ]
/// </summary>
internal sealed class OnionAnnounceServer
{
    public const int MaxEntries = 160;
    public static readonly TimeSpan EntryTimeout = TimeSpan.FromSeconds(300);
    public const int SendbackSize = sizeof(ulong);

    private const int PlainSize = TimedAuth.Size + CryptoConstants.PublicKeySize * 2 + SendbackSize; // 104
    private const int RequestSize = 1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize + PlainSize
                                    + CryptoConstants.MacSize;                                        // 177
    private const int ReceivedRequestSize = RequestSize + OnionPacket.Return3;
    private const int DataRequestMinSize = 1 + CryptoConstants.PublicKeySize + CryptoConstants.NonceSize
                                           + CryptoConstants.PublicKeySize + CryptoConstants.MacSize; // 105

    private sealed class Entry
    {
        public required byte[] PublicKey { get; init; }
        public required byte[] DataPublicKey { get; set; }
        public required IpPort ReturnEndpoint { get; set; }
        public required byte[] Return { get; set; }
        public DateTimeOffset AnnouncedAt { get; set; }
    }

    private readonly DhtNode _dht;
    private readonly ICryptoCore _crypto;
    private readonly IPacketSender _sender;
    private readonly TimeProvider _time;
    private readonly TimedAuth _pingIds = new(EntryTimeout);
    private readonly List<Entry> _entries = [];

    public OnionAnnounceServer(DhtNode dht, TimeProvider time)
    {
        _dht = dht;
        _crypto = dht.Crypto;
        _sender = dht.Sender;
        _time = time;
    }

    public int EntryCount => _entries.Count(e => !IsExpired(e, _time.GetUtcNow()));

    public void Attach(PacketDispatcher dispatcher)
    {
        dispatcher.Register(PacketKind.AnnounceRequest, (s, p) => HandleAnnounce(s, p, PacketKind.AnnounceResponse));
        dispatcher.Register(PacketKind.AnnounceRequestNew, (s, p) => HandleAnnounce(s, p, PacketKind.AnnounceResponseNew));
        dispatcher.Register(PacketKind.OnionDataRequest, HandleDataRequest);
    }

    private void HandleAnnounce(IpPort source, ReadOnlySpan<byte> packet, PacketKind responseKind)
    {
        // Group chat announcements (larger 0x87 packets with extra data) are not supported.
        if (packet.Length != ReceivedRequestSize)
            return;

        var senderKey = packet.Slice(1 + CryptoConstants.NonceSize, CryptoConstants.PublicKeySize).ToArray();
        if (!_dht.TryGetSharedKey(senderKey, out var sharedKey))
            return;

        var plain = _crypto.Decrypt(sharedKey, packet.Slice(1, CryptoConstants.NonceSize),
            packet.Slice(1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize, PlainSize + CryptoConstants.MacSize));
        if (plain is null || plain.Length != PlainSize)
            return;

        var now = _time.GetUtcNow();
        var pingId = plain.AsSpan(0, TimedAuth.Size);
        var searchedKey = plain.AsSpan(TimedAuth.Size, CryptoConstants.PublicKeySize);
        var dataKey = plain.AsSpan(TimedAuth.Size + CryptoConstants.PublicKeySize, CryptoConstants.PublicKeySize);
        var sendback = plain.AsSpan(TimedAuth.Size + CryptoConstants.PublicKeySize * 2, SendbackSize);

        // The ping id binds the sender key to the address the request came from.
        var pingIdData = new byte[CryptoConstants.PublicKeySize + PackedIpPort.Size];
        senderKey.CopyTo(pingIdData, 0);
        PackedIpPort.Write(pingIdData.AsSpan(CryptoConstants.PublicKeySize), source);

        Entry? entry = _pingIds.Check(now, pingIdData, pingId)
            ? AddOrUpdate(senderKey, dataKey.ToArray(), source, packet[^OnionPacket.Return3..].ToArray(), now)
            : Find(searchedKey, now);

        var ourPingId = _pingIds.Generate(now, pingIdData);
        var nodes = _dht.FindClosestFor(searchedKey, DhtPayloads.MaxNodes, source);
        bool withCount = responseKind == PacketKind.AnnounceResponseNew;

        var response = new byte[1 + 32 + (withCount ? 1 : 0) + nodes.Sum(n => n.PackedSize)];
        if (entry is null)
        {
            response[0] = 0; // not stored: here is a ping id to prove your address
            ourPingId.CopyTo(response, 1);
        }
        else if (entry.PublicKey.AsSpan().SequenceEqual(senderKey))
        {
            // The sender's own announcement: 2 = stored (with this data key), 0 = data key changed.
            response[0] = (byte)(entry.DataPublicKey.AsSpan().SequenceEqual(dataKey) ? 2 : 0);
            ourPingId.CopyTo(response, 1);
        }
        else
        {
            response[0] = 1; // someone searching: here is the data key to encrypt data for the announcer
            entry.DataPublicKey.CopyTo(response, 1);
        }

        int offset = 1 + 32;
        if (withCount)
            response[offset++] = (byte)nodes.Count;
        NodeInfo.PackMany(nodes, response.AsSpan(offset));

        var nonce = Nonce.Random();
        var cipher = _crypto.Encrypt(sharedKey, nonce, response);
        var data = new byte[1 + SendbackSize + CryptoConstants.NonceSize + cipher.Length];
        data[0] = (byte)responseKind;
        sendback.CopyTo(data.AsSpan(1));
        nonce.CopyTo(data, 1 + SendbackSize);
        cipher.CopyTo(data, 1 + SendbackSize + CryptoConstants.NonceSize);

        SendResponse(source, data, packet[^OnionPacket.Return3..]);
    }

    /// <summary>[0x85][announcer key][nonce][temp key][encrypted data][return 3] -> forwarded as 0x86.</summary>
    private void HandleDataRequest(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.Length <= DataRequestMinSize + OnionPacket.Return3 || packet.Length > OnionPacket.MaxPacketSize)
            return;

        var entry = Find(packet.Slice(1, CryptoConstants.PublicKeySize), _time.GetUtcNow());
        if (entry is null)
            return;

        var body = packet[(1 + CryptoConstants.PublicKeySize)..^OnionPacket.Return3];
        var data = new byte[1 + body.Length];
        data[0] = (byte)PacketKind.OnionDataResponse;
        body.CopyTo(data.AsSpan(1));
        SendResponse(entry.ReturnEndpoint, data, entry.Return);
    }

    /// <summary>[0x8c][return 3][data]: node 3 opens it and starts the trip back.</summary>
    private void SendResponse(IpPort destination, ReadOnlySpan<byte> data, ReadOnlySpan<byte> ret)
    {
        if (data.IsEmpty || data.Length > OnionPacket.MaxResponseDataSize)
            return;

        var packet = new byte[1 + OnionPacket.Return3 + data.Length];
        packet[0] = (byte)PacketKind.OnionReceive3;
        ret.CopyTo(packet.AsSpan(1));
        data.CopyTo(packet.AsSpan(1 + OnionPacket.Return3));
        _sender.Send(destination, packet);
    }

    private static bool IsExpired(Entry entry, DateTimeOffset now) => now - entry.AnnouncedAt > EntryTimeout;

    private Entry? Find(ReadOnlySpan<byte> publicKey, DateTimeOffset now)
    {
        foreach (var entry in _entries)
            if (!IsExpired(entry, now) && entry.PublicKey.AsSpan().SequenceEqual(publicKey))
                return entry;
        return null;
    }

    /// <summary>
    /// Stores an announcement. When full, keys closer to our own DHT key win: announcements end
    /// up on the nodes "responsible" for them, where searchers will look.
    /// </summary>
    private Entry? AddOrUpdate(byte[] publicKey, byte[] dataKey, IpPort returnEndpoint, byte[] ret, DateTimeOffset now)
    {
        var entry = Find(publicKey, now);
        if (entry is null)
        {
            _entries.RemoveAll(e => IsExpired(e, now));
            if (_entries.Count >= MaxEntries)
            {
                var farthest = _entries.MaxBy(e => e, Comparer<Entry>.Create(
                    (a, b) => XorDistance.Compare(_dht.PublicKey, a.PublicKey, b.PublicKey)))!;
                if (XorDistance.Compare(_dht.PublicKey, publicKey, farthest.PublicKey) >= 0)
                    return null;
                _entries.Remove(farthest);
            }

            entry = new Entry { PublicKey = publicKey, DataPublicKey = dataKey, ReturnEndpoint = returnEndpoint, Return = ret };
            _entries.Add(entry);
        }

        entry.DataPublicKey = dataKey;
        entry.ReturnEndpoint = returnEndpoint;
        entry.Return = ret;
        entry.AnnouncedAt = now;
        return entry;
    }
}
