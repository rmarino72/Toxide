using Toxide.Network;

namespace Toxide.Dht;

/// <summary>A node in the routing table plus its liveness bookkeeping.</summary>
internal sealed class DhtEntry
{
    public DhtEntry(NodeInfo node, DateTimeOffset now)
    {
        Node = node;
        LastSeen = now;
        LastPinged = now;
    }

    public NodeInfo Node { get; set; }

    /// <summary>Last time the node proved it is alive (valid ping or nodes response).</summary>
    public DateTimeOffset LastSeen { get; set; }

    public DateTimeOffset LastPinged { get; set; }

    public bool IsBad(DateTimeOffset now, TimeSpan timeout) => now - LastSeen > timeout;
}

/// <summary>
/// Kademlia k-buckets, k = 8.
/// Bucket i holds nodes sharing exactly i leading bits with our own DHT key.
/// Half of the key space falls in bucket 0, a quarter in bucket 1, and so on: we know few far
/// nodes and proportionally many close ones, which is what makes lookups take O(log n) steps.
/// A full bucket accepts a newcomer only by replacing a bad (unresponsive) node: long-lived
/// nodes are preferred, which also makes the table hard to flood with fake nodes.
/// </summary>
internal sealed class RoutingTable
{
    public const int BucketSize = 8;
    public const int BucketCount = 256;

    private readonly byte[] _ownKey;
    private readonly TimeSpan _badNodeTimeout;
    private readonly List<DhtEntry>[] _buckets;

    public RoutingTable(byte[] ownKey, TimeSpan badNodeTimeout)
    {
        _ownKey = ownKey;
        _badNodeTimeout = badNodeTimeout;
        _buckets = new List<DhtEntry>[BucketCount];
        for (int i = 0; i < BucketCount; i++)
            _buckets[i] = new List<DhtEntry>(BucketSize);
    }

    public int Count => _buckets.Sum(b => b.Count);

    public IEnumerable<DhtEntry> Entries => _buckets.SelectMany(b => b);

    public DhtEntry? Find(ReadOnlySpan<byte> publicKey)
    {
        int index = XorDistance.CommonPrefixLength(_ownKey, publicKey);
        if (index >= BucketCount)
            return null;

        foreach (var entry in _buckets[index])
            if (entry.Node.PublicKey.AsSpan().SequenceEqual(publicKey))
                return entry;
        return null;
    }

    /// <summary>True if a node with this key would be stored (or is already stored).</summary>
    public bool CanAccept(ReadOnlySpan<byte> publicKey, DateTimeOffset now)
    {
        int index = XorDistance.CommonPrefixLength(_ownKey, publicKey);
        if (index >= BucketCount)
            return false; // our own key

        var bucket = _buckets[index];
        if (bucket.Count < BucketSize)
            return true;

        foreach (var entry in bucket)
            if (entry.IsBad(now, _badNodeTimeout) || entry.Node.PublicKey.AsSpan().SequenceEqual(publicKey))
                return true;
        return false;
    }

    /// <summary>
    /// Stores a verified node, or refreshes it if already known (its address may have changed).
    /// Returns false if the bucket is full of good nodes; <paramref name="added"/> is true only for new nodes.
    /// </summary>
    public bool AddOrUpdate(NodeInfo node, DateTimeOffset now, out bool added)
    {
        added = false;
        int index = XorDistance.CommonPrefixLength(_ownKey, node.PublicKey);
        if (index >= BucketCount)
            return false;

        var bucket = _buckets[index];
        var existing = Find(node.PublicKey);
        if (existing is not null)
        {
            existing.Node = node;
            existing.LastSeen = now;
            return true;
        }

        var entry = new DhtEntry(node, now);
        if (bucket.Count < BucketSize)
        {
            bucket.Add(entry);
            added = true;
            return true;
        }

        int bad = bucket.FindIndex(e => e.IsBad(now, _badNodeTimeout));
        if (bad < 0)
            return false;

        bucket[bad] = entry;
        added = true;
        return true;
    }

    /// <summary>Drops nodes that have not answered for longer than the timeout.</summary>
    public int RemoveBad(DateTimeOffset now)
    {
        int removed = 0;
        foreach (var bucket in _buckets)
            removed += bucket.RemoveAll(e => e.IsBad(now, _badNodeTimeout));
        return removed;
    }

    /// <summary>The <paramref name="count"/> good nodes closest to <paramref name="target"/>, closest first.</summary>
    public List<NodeInfo> FindClosest(ReadOnlySpan<byte> target, int count, DateTimeOffset now,
        Func<NodeInfo, bool>? filter = null)
    {
        var targetKey = target.ToArray();
        var candidates = new List<NodeInfo>();

        foreach (var bucket in _buckets)
            foreach (var entry in bucket)
                if (!entry.IsBad(now, _badNodeTimeout) && (filter is null || filter(entry.Node)))
                    candidates.Add(entry.Node);

        candidates.Sort((a, b) => XorDistance.Compare(targetKey, a.PublicKey, b.PublicKey));
        if (candidates.Count > count)
            candidates.RemoveRange(count, candidates.Count - count);
        return candidates;
    }
}