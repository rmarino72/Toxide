namespace Toxide.Crypto;

/// <summary>Value equality for keys stored as byte arrays, so they can be used as dictionary keys.</summary>
internal sealed class PublicKeyComparer : IEqualityComparer<byte[]>
{
    public static readonly PublicKeyComparer Instance = new();

    public bool Equals(byte[]? x, byte[]? y) =>
        ReferenceEquals(x, y) || (x is not null && y is not null && x.AsSpan().SequenceEqual(y));

    public int GetHashCode(byte[] obj)
    {
        var hash = new HashCode();
        hash.AddBytes(obj);
        return hash.ToHashCode();
    }
}