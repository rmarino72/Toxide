using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Toxide.Crypto;

/// <summary>
/// Fully managed implementation of NaCl crypto_box, byte-compatible with libsodium/toxcore.
///  - X25519 and Poly1305: BouncyCastle (vetted, constant-time).
///  - Salsa20 / HSalsa20 / XSalsa20: Toxide's own implementation (<see cref="Salsa20"/>).
/// </summary>
public sealed class ManagedCryptoCore : ICryptoCore
{
    /// <summary>
    /// The first 32 bytes of the keystream become the one-time Poly1305 key;
    /// the message is encrypted with the keystream that follows.
    /// </summary>
    private const int PolyKeySize = 32;

    public KeyPair GenerateKeyPair()
    {
        var secretKey = new byte[CryptoConstants.SecretKeySize];
        RandomNumberGenerator.Fill(secretKey);
        return BuildKeyPair(secretKey);
    }

    public KeyPair DeriveKeyPair(ReadOnlySpan<byte> secretKey)
    {
        RequireLength(secretKey, CryptoConstants.SecretKeySize, nameof(secretKey));
        return BuildKeyPair(secretKey.ToArray());
    }

    public byte[] ComputeSharedKey(ReadOnlySpan<byte> theirPublicKey, ReadOnlySpan<byte> ourSecretKey)
    {
        RequireLength(theirPublicKey, CryptoConstants.PublicKeySize, nameof(theirPublicKey));
        RequireLength(ourSecretKey, CryptoConstants.SecretKeySize, nameof(ourSecretKey));

        var secret = ourSecretKey.ToArray();
        var dh = new byte[X25519.PointSize];
        try
        {
            // Diffie-Hellman: both sides obtain the same 32 bytes.
            // Returns false when the result is all zeros (low-order public key): reject it, like libsodium.
            if (!X25519.CalculateAgreement(secret, 0, theirPublicKey.ToArray(), 0, dh, 0))
                throw new CryptographicException("Invalid public key: the shared secret is all zeros.");

            // The raw DH output is not uniformly distributed: HSalsa20 turns it into a proper key.
            var sharedKey = new byte[CryptoConstants.SharedKeySize];
            Salsa20.HSalsa20(dh, stackalloc byte[16], sharedKey);
            return sharedKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(dh);
        }
    }

    public byte[] Encrypt(ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plain)
    {
        RequireLength(sharedKey, CryptoConstants.SharedKeySize, nameof(sharedKey));
        RequireLength(nonce, CryptoConstants.NonceSize, nameof(nonce));

        var stream = new byte[PolyKeySize + plain.Length];
        var output = new byte[CryptoConstants.MacSize + plain.Length];
        try
        {
            Salsa20.XSalsa20Stream(sharedKey, nonce, stream);

            // Encrypt: ciphertext = plaintext XOR keystream (skipping the Poly1305 key bytes).
            var cipher = output.AsSpan(CryptoConstants.MacSize);
            for (int i = 0; i < plain.Length; i++)
                cipher[i] = (byte)(plain[i] ^ stream[PolyKeySize + i]);

            // Encrypt-then-MAC: the tag authenticates the ciphertext.
            ComputeTag(stream.AsSpan(0, PolyKeySize), cipher, output.AsSpan(0, CryptoConstants.MacSize));
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stream);
        }
    }

    public byte[]? Decrypt(ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipher)
    {
        RequireLength(sharedKey, CryptoConstants.SharedKeySize, nameof(sharedKey));
        RequireLength(nonce, CryptoConstants.NonceSize, nameof(nonce));

        if (cipher.Length < CryptoConstants.MacSize)
            return null;

        var body = cipher[CryptoConstants.MacSize..];
        var stream = new byte[PolyKeySize + body.Length];
        Span<byte> expectedTag = stackalloc byte[CryptoConstants.MacSize];
        try
        {
            Salsa20.XSalsa20Stream(sharedKey, nonce, stream);

            // Verify BEFORE decrypting, in constant time: never release unauthenticated data.
            ComputeTag(stream.AsSpan(0, PolyKeySize), body, expectedTag);
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, cipher[..CryptoConstants.MacSize]))
                return null;

            var plain = new byte[body.Length];
            for (int i = 0; i < body.Length; i++)
                plain[i] = (byte)(body[i] ^ stream[PolyKeySize + i]);
            return plain;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stream);
            expectedTag.Clear();
        }
    }

    private static KeyPair BuildKeyPair(byte[] secretKey)
    {
        // The secret key is stored as-is: X25519 applies the "clamping" internally, like libsodium.
        var publicKey = new byte[CryptoConstants.PublicKeySize];
        X25519.GeneratePublicKey(secretKey, 0, publicKey, 0);
        return new KeyPair(publicKey, secretKey);
    }

    private static void ComputeTag(ReadOnlySpan<byte> polyKey, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        var key = polyKey.ToArray();
        var input = data.ToArray();
        var result = new byte[CryptoConstants.MacSize];
        try
        {
            var mac = new Poly1305(); // raw Poly1305: key = r (clamped internally) || s
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(input, 0, input.Length);
            mac.DoFinal(result, 0);
            result.CopyTo(tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(result);
        }
    }

    private static void RequireLength(ReadOnlySpan<byte> value, int expected, string name)
    {
        if (value.Length != expected)
            throw new ArgumentException($"Expected {expected} bytes, got {value.Length}.", name);
    }
}
