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

    /// <summary>Adds <paramref name="value"/> to the nonce, big-endian (toxcore's increment_nonce_number).</summary>
    public static void Add(Span<byte> nonce, uint value)
    {
        uint carry = value;
        for (int i = nonce.Length - 1; i >= 0 && carry != 0; i--)
        {
            uint sum = nonce[i] + (carry & 0xFF);
            nonce[i] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }
    }
}
