using System.Security.Cryptography;

namespace Toxide.Crypto;

/// <summary>
/// Helpers for 24-byte nonces.
/// Golden rule: the same (key, nonce) pair must NEVER encrypt two different messages.
/// Tox uses random nonces for standalone packets (DHT, onion) and incremented nonces for streams (net_crypto).
/// </summary>
public static class Nonce
{
    public static byte[] Random()
    {
        var n = new byte[CryptoConstants.NonceSize];
        RandomNumberGenerator.Fill(n);
        return n;
    }

    /// <summary>Increments the nonce by 1, treating it as a big-endian integer (as toxcore does).</summary>
    public static void Increment(Span<byte> nonce)
    {
        for (int i = nonce.Length - 1; i >= 0; i--)
        {
            if (++nonce[i] != 0)
                break; // no carry: done
        }
    }
}