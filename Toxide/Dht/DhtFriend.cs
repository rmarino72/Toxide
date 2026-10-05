using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>A node that told us, in a nodes response, at which address it sees one of our friends.</summary>
internal sealed record ReturnedAddress(NodeInfo Relay, IpPort FriendEndpoint, DateTimeOffset ReportedAt);

/// <summary>
/// A DHT key we are searching for (a friend's temporary DHT key).
/// We keep the 8 verified nodes closest to that key: they are the nodes most likely to know the
/// friend, and the ones that will report its address. Once the friend itself answers one of our
/// requests we know its IP and port, which is what net_crypto needs to connect.
/// </summary>
internal sealed class DhtFriend
{
    public const int MaxCloseNodes = 8;

    private readonly List<Action<IpPort>> _callbacks = [];

    public DhtFriend(byte[] publicKey, ulong natPingId)
    {
        PublicKey = publicKey;
        NatPingId = natPingId;
    }

    public byte[] PublicKey { get; }

    /// <summary>Verified nodes closest to <see cref="PublicKey"/>.</summary>
    public List<DhtEntry> CloseNodes { get; } = new(MaxCloseNodes);

    /// <summary>Who reported the friend's address, keyed by the reporting node's key.</summary>
    public Dictionary<byte[], ReturnedAddress> Returned { get; } = new(PublicKeyComparer.Instance);

    public IpPort? DirectEndpoint { get; set; }
    public DateTimeOffset DirectSeen { get; set; }

    public DateTimeOffset LastNodesRequest { get; set; } = DateTimeOffset.MinValue;
    public int BootstrapTimes { get; set; }

    // NAT traversal state (see DhtNode.Nat.cs).
    public ulong NatPingId { get; set; }
    public DateTimeOffset NatPingSent { get; set; } = DateTimeOffset.MinValue;
    public DateTimeOffset NatPingReceived { get; set; } = DateTimeOffset.MinValue;
    public DateTimeOffset PunchingTime { get; set; } = DateTimeOffset.MinValue;
    public bool HolePunching { get; set; }
    public uint PunchingIndex { get; set; }
    public uint PunchingIndex2 { get; set; }
    public int PunchingTries { get; set; }

    public IReadOnlyList<Action<IpPort>> Callbacks => _callbacks;
    public bool IsUnused => _callbacks.Count == 0;

    public void AddCallback(Action<IpPort> callback) => _callbacks.Add(callback);
    public bool RemoveCallback(Action<IpPort> callback) => _callbacks.Remove(callback);

    /// <summary>True if <paramref name="key"/> would be stored among the close nodes.</summary>
    public bool WouldStore(ReadOnlySpan<byte> key, DateTimeOffset now, TimeSpan badTimeout)
    {
        if (CloseNodes.Count < MaxCloseNodes)
            return true;

        foreach (var entry in CloseNodes)
        {
            if (entry.IsBad(now, badTimeout))
                return true;
            if (XorDistance.Compare(PublicKey, key, entry.Node.PublicKey) < 0)
                return true;
        }
        return false;
    }

    /// <summary>Stores or refreshes a verified node; returns false if it is farther than all 8 stored nodes.</summary>
    public bool AddOrUpdate(NodeInfo node, DateTimeOffset now, TimeSpan badTimeout)
    {
        foreach (var entry in CloseNodes)
        {
            if (entry.Node.PublicKey.AsSpan().SequenceEqual(node.PublicKey))
            {
                entry.Node = node;
                entry.LastSeen = now;
                return true;
            }
        }

        if (CloseNodes.Count < MaxCloseNodes)
        {
            CloseNodes.Add(new DhtEntry(node, now));
            return true;
        }

        // Replace a bad node first, otherwise the farthest one if the newcomer is closer.
        int victim = CloseNodes.FindIndex(e => e.IsBad(now, badTimeout));
        if (victim < 0)
        {
            victim = 0;
            for (int i = 1; i < CloseNodes.Count; i++)
                if (XorDistance.Compare(PublicKey, CloseNodes[i].Node.PublicKey, CloseNodes[victim].Node.PublicKey) > 0)
                    victim = i;
            if (XorDistance.Compare(PublicKey, node.PublicKey, CloseNodes[victim].Node.PublicKey) >= 0)
                return false;
        }

        CloseNodes[victim] = new DhtEntry(node, now);
        return true;
    }

    public void AddReturned(NodeInfo relay, IpPort friendEndpoint, DateTimeOffset now)
    {
        Returned[relay.PublicKey] = new ReturnedAddress(relay, friendEndpoint, now);
        if (Returned.Count <= MaxCloseNodes)
            return;

        var oldest = Returned.MinBy(r => r.Value.ReportedAt).Key;
        Returned.Remove(oldest);
    }

    /// <summary>Fresh reports of the friend's address, at most one per reporting node.</summary>
    public List<ReturnedAddress> FreshReturned(DateTimeOffset now, TimeSpan timeout)
    {
        var fresh = new List<ReturnedAddress>();
        foreach (var r in Returned.Values)
            if (now - r.ReportedAt <= timeout)
                fresh.Add(r);
        return fresh;
    }

    public bool HasDirectConnection(DateTimeOffset now, TimeSpan timeout) =>
        DirectEndpoint is not null && now - DirectSeen <= timeout;
}
