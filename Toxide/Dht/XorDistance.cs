using System.Numerics;

namespace Toxide.Dht;

/// <summary>
/// The Kademlia metric: distance(a, b) = a XOR b, read as a 256-bit big-endian unsigned integer.
/// It is not geographic: it only decides which nodes are "responsible" for which keys.
/// Useful properties: distance(a, a) = 0, it is symmetric, and for a given key and distance
/// there is exactly one other key, so lookups converge.
/// </summary>
public static class XorDistance
{
    /// <summary>Negative if <paramref name="a"/> is closer to <paramref name="target"/> than <paramref name="b"/>.</summary>
    public static int Compare(ReadOnlySpan<byte> target, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < target.Length; i++)
        {
            int da = a[i] ^ target[i];
            int db = b[i] ^ target[i];
            if (da != db)
                return da.CompareTo(db);
        }
        return 0;
    }

    /// <summary>
    /// Number of leading bits the two keys have in common (0-255), or 256 if they are identical.
    /// This is the k-bucket index: a high value means "very close".
    /// </summary>
    public static int CommonPrefixLength(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < a.Length; i++)
        {
            int x = a[i] ^ b[i];
            if (x != 0)
                return i * 8 + BitOperations.LeadingZeroCount((uint)x) - 24;
        }
        return a.Length * 8;
    }
}