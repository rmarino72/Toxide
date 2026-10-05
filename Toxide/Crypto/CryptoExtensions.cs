using System.Security.Cryptography;

namespace Toxide.Crypto;

/// <summary>One-shot crypto_box helpers (shared key computed on the fly) for packets that are rare
/// enough not to need a <c>SharedKeyCache</c>.</summary>
internal static class CryptoExtensions
{
    /// <summary>crypto_box: returns null if <paramref name="theirPublicKey"/> is invalid.</summary>
    public static byte[]? Box(this ICryptoCore crypto, ReadOnlySpan<byte> theirPublicKey, ReadOnlySpan<byte> ourSecretKey,
        ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plain)
    {
        if (!TryShared(crypto, theirPublicKey, ourSecretKey, out var shared))
            return null;
        try { return crypto.Encrypt(shared, nonce, plain); }
        finally { CryptographicOperations.ZeroMemory(shared); }
    }

    /// <summary>crypto_box_open: returns null if the key is invalid or the MAC does not verify.</summary>
    public static byte[]? Unbox(this ICryptoCore crypto, ReadOnlySpan<byte> theirPublicKey, ReadOnlySpan<byte> ourSecretKey,
        ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipher)
    {
        if (!TryShared(crypto, theirPublicKey, ourSecretKey, out var shared))
            return null;
        try { return crypto.Decrypt(shared, nonce, cipher); }
        finally { CryptographicOperations.ZeroMemory(shared); }
    }

    public static bool TryShared(this ICryptoCore crypto, ReadOnlySpan<byte> theirPublicKey, ReadOnlySpan<byte> ourSecretKey,
        out byte[] sharedKey)
    {
        try
        {
            sharedKey = crypto.ComputeSharedKey(theirPublicKey, ourSecretKey);
            return true;
        }
        catch (CryptographicException)
        {
            sharedKey = [];
            return false;
        }
    }

    /// <summary>A random 32-byte key for symmetric secretbox use (cookies, onion return paths).</summary>
    public static byte[] NewSymmetricKey()
    {
        var key = new byte[CryptoConstants.SharedKeySize];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
