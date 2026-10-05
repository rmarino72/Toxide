using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Network;

namespace Toxide.Onion;

/// <summary>An announce node: one of the DHT nodes closest to a key we announce or search.</summary>
internal sealed class OnionNode
{
    public byte[] PublicKey { get; set; } = new byte[CryptoConstants.PublicKeySize];
    public IpPort Endpoint { get; set; }

    /// <summary>For our own announcements: the ping id to send back to get stored.</summary>
    public byte[] PingId { get; set; } = new byte[TimedAuth.Size];

    /// <summary>For friend searches: the key the friend wants data encrypted with.</summary>
    public byte[] DataPublicKey { get; set; } = new byte[CryptoConstants.PublicKeySize];

    /// <summary>0 = not stored, 1 = the searched key is stored here (friend found), 2 = we are stored here.</summary>
    public byte IsStored { get; set; }

    public DateTimeOffset AddedTime { get; set; } = OnionClient.Never;

    /// <summary>Last valid response from the node; <see cref="OnionClient.Never"/> marks an empty slot.</summary>
    public DateTimeOffset Timestamp { get; set; } = OnionClient.Never;

    public DateTimeOffset LastPinged { get; set; } = OnionClient.Never;
    public int PingsSinceLastResponse { get; set; }
    public uint PathUsed { get; set; } = uint.MaxValue;

    public bool IsTimedOut(DateTimeOffset now) =>
        Timestamp == OnionClient.Never
        || (PingsSinceLastResponse >= OnionClient.NodeMaxPings && OnionClient.IsTimeout(now, LastPinged, OnionClient.NodeTimeout));

    /// <summary>
    /// Sorts timed-out slots first, then the farthest from <paramref name="reference"/> first:
    /// index 0 is always the slot a better node should replace.
    /// </summary>
    public static void Sort(OnionNode[] list, byte[] reference, DateTimeOffset now) =>
        Array.Sort(list, (a, b) =>
        {
            bool ta = a.IsTimedOut(now), tb = b.IsTimedOut(now);
            if (ta && tb) return 0;
            if (ta) return -1;
            if (tb) return 1;
            return -XorDistance.Compare(reference, a.PublicKey, b.PublicKey);
        });

    public static OnionNode[] CreateList(int length)
    {
        var list = new OnionNode[length];
        for (int i = 0; i < length; i++)
            list[i] = new OnionNode();
        return list;
    }
}

/// <summary>Remembers recently pinged keys so a node mentioned by many responses is pinged once.</summary>
internal sealed class RecentlyPinged
{
    private const int Capacity = 9;
    private static readonly TimeSpan MinPingInterval = TimeSpan.FromSeconds(10);

    private readonly (byte[]? Key, DateTimeOffset At)[] _entries = new (byte[]?, DateTimeOffset)[Capacity];
    private int _index;

    public bool TryMark(ReadOnlySpan<byte> publicKey, DateTimeOffset now)
    {
        foreach (var (key, at) in _entries)
            if (key is not null && !OnionClient.IsTimeout(now, at, MinPingInterval) && publicKey.SequenceEqual(key))
                return false;

        _entries[_index++ % Capacity] = (publicKey.ToArray(), now);
        return true;
    }
}

/// <summary>A friend as seen by the onion client: whom we search and how to reach them.</summary>
internal sealed class OnionFriend : IDisposable
{
    public OnionFriend(byte[] realPublicKey, KeyPair tempKeys)
    {
        RealPublicKey = realPublicKey;
        TempKeys = tempKeys;
    }

    public byte[] RealPublicKey { get; }

    /// <summary>A throwaway key pair for searching: announce nodes cannot tell who is searching.</summary>
    public KeyPair TempKeys { get; }

    public OnionNode[] Nodes { get; } = OnionNode.CreateList(OnionClient.MaxFriendNodes);
    public RecentlyPinged RecentlyPinged { get; } = new();

    public byte[]? DhtPublicKey { get; set; }
    public DateTimeOffset LastDhtPkOnionSent { get; set; } = OnionClient.Never;
    public DateTimeOffset LastDhtPkDhtSent { get; set; } = OnionClient.Never;
    public ulong LastNoReplay { get; set; }
    public bool IsOnline { get; set; }

    public uint RunCount { get; set; }
    public uint Pings { get; set; }
    public DateTimeOffset TimeLastPinged { get; set; } = OnionClient.Never;
    public DateTimeOffset LastPopulated { get; set; } = OnionClient.Never;

    /// <summary>Called when the friend tells us (through the onion or the DHT) its current DHT key.</summary>
    public Action<byte[]>? DhtPublicKeyReceived { get; set; }

    public void Dispose() => TempKeys.Dispose();
}

/// <summary>The onion paths of one kind (our announcements, or friend searches) and their health.</summary>
internal sealed class OnionPathSet
{
    public const int Count = 6;

    public OnionPath?[] Paths { get; } = new OnionPath?[Count];
    public DateTimeOffset[] CreationTime { get; } = Enumerable.Repeat(OnionClient.Never, Count).ToArray();
    public DateTimeOffset[] LastSuccess { get; } = Enumerable.Repeat(OnionClient.Never, Count).ToArray();
    public DateTimeOffset[] LastUsed { get; } = Enumerable.Repeat(OnionClient.Never, Count).ToArray();
    public int[] UsedTimes { get; } = new int[Count];
}
