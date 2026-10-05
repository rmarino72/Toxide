using System.Diagnostics.CodeAnalysis;

namespace Toxide.Crypto;

/// <summary>
/// Tox address (38 bytes, displayed as 76 hex characters):
///   [ public key 32 ][ nospam 4 ][ checksum 2 ]
/// - nospam: random value; changing it invalidates the old ID for new friend requests.
/// - checksum: pairwise XOR of the previous 36 bytes, catches typos and copy errors.
/// </summary>
public sealed class ToxId
{
    public const int NoSpamSize = 4;
    public const int ChecksumSize = 2;
    public const int Size = CryptoConstants.PublicKeySize + NoSpamSize + ChecksumSize; // 38

    public byte[] PublicKey { get; }
    public byte[] NoSpam { get; }

    public ToxId(byte[] publicKey, byte[] noSpam)
    {
        if (publicKey.Length != CryptoConstants.PublicKeySize)
            throw new ArgumentException("Invalid public key length.", nameof(publicKey));
        if (noSpam.Length != NoSpamSize)
            throw new ArgumentException("Invalid nospam length.", nameof(noSpam));

        PublicKey = publicKey;
        NoSpam = noSpam;
    }

    public byte[] ToBytes()
    {
        var bytes = new byte[Size];
        PublicKey.CopyTo(bytes, 0);
        NoSpam.CopyTo(bytes, CryptoConstants.PublicKeySize);
        ComputeChecksum(bytes.AsSpan(0, Size - ChecksumSize))
            .CopyTo(bytes.AsSpan(Size - ChecksumSize));
        return bytes;
    }

    public override string ToString() => Convert.ToHexString(ToBytes());

    public static ToxId Parse(string hex)
    {
        return !TryParse(hex, out var id) ? throw new FormatException("Invalid Tox ID (length, format or checksum).") : id;
    }

    public static bool TryParse([NotNullWhen(true)] string? hex, [NotNullWhen(true)] out ToxId? id)
    {
        id = null;
        if (hex is null || hex.Length != Size * 2)
            return false;

        byte[] bytes;
        try { bytes = Convert.FromHexString(hex); }
        catch (FormatException) { return false; }

        var expected = ComputeChecksum(bytes.AsSpan(0, Size - ChecksumSize));
        if (!bytes.AsSpan(Size - ChecksumSize).SequenceEqual(expected))
            return false;

        id = new ToxId(
            bytes[..CryptoConstants.PublicKeySize],
            bytes[CryptoConstants.PublicKeySize..(CryptoConstants.PublicKeySize + NoSpamSize)]);
        return true;
    }

    /// <summary>checksum[i % 2] ^= data[i] over public key + nospam.</summary>
    private static byte[] ComputeChecksum(ReadOnlySpan<byte> data)
    {
        var checksum = new byte[ChecksumSize];
        for (var i = 0; i < data.Length; i++)
            checksum[i % ChecksumSize] ^= data[i];
        return checksum;
    }
}