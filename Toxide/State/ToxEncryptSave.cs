using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Toxide.Crypto;

namespace Toxide.State;

/// <summary>
/// Password protection of profiles, compatible with toxcore's toxencryptsave (the format qTox
/// uses for encrypted profiles):
///   [ "toxEsave" 8 ][ salt 32 ][ nonce 24 ][ MAC 16 + encrypted data ]
/// key = scrypt(SHA-256(passphrase), salt, N = 2^14, r = 8, p = 2), i.e. libsodium's
/// crypto_pwhash_scryptsalsa208sha256 with twice the "interactive" ops limit; the data is
/// encrypted with XSalsa20-Poly1305 (crypto_secretbox).
/// </summary>
public static class ToxEncryptSave
{
    public const int SaltSize = 32;
    public const int KeySize = 32;

    /// <summary>Bytes added to the plaintext: magic + salt + nonce + MAC.</summary>
    public const int ExtraLength = MagicLength + SaltSize + CryptoConstants.NonceSize + CryptoConstants.MacSize; // 80

    private const int MagicLength = 8;
    private const int ScryptN = 1 << 14;
    private const int ScryptR = 8;
    private const int ScryptP = 2;
    private static readonly byte[] Magic = "toxEsave"u8.ToArray();

    private static readonly ICryptoCore Crypto = new ManagedCryptoCore();

    /// <summary>True if <paramref name="data"/> starts with the toxEsave magic number.</summary>
    public static bool IsEncrypted(ReadOnlySpan<byte> data) =>
        data.Length >= MagicLength && data[..MagicLength].SequenceEqual(Magic);

    /// <summary>Derives the 32-byte key from a passphrase and salt (slow on purpose: about 16 MiB of memory).</summary>
    public static byte[] DeriveKey(string passphrase, ReadOnlySpan<byte> salt)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        if (salt.Length != SaltSize)
            throw new ArgumentException($"Salt must be {SaltSize} bytes.", nameof(salt));

        var passwordBytes = Encoding.UTF8.GetBytes(passphrase);
        var hashed = SHA256.HashData(passwordBytes);
        try
        {
            return SCrypt.Generate(hashed, salt.ToArray(), ScryptN, ScryptR, ScryptP, KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(hashed);
        }
    }

    public static byte[] Encrypt(ReadOnlySpan<byte> plain, string passphrase)
    {
        if (plain.IsEmpty)
            throw new ArgumentException("Nothing to encrypt.", nameof(plain));

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = DeriveKey(passphrase, salt);
        try
        {
            var nonce = Nonce.Random();
            var cipher = Crypto.Encrypt(key, nonce, plain);

            var result = new byte[MagicLength + SaltSize + CryptoConstants.NonceSize + cipher.Length];
            Magic.CopyTo(result, 0);
            salt.CopyTo(result, MagicLength);
            nonce.CopyTo(result, MagicLength + SaltSize);
            cipher.CopyTo(result, MagicLength + SaltSize + CryptoConstants.NonceSize);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Decrypts a toxEsave blob; throws <see cref="CryptographicException"/> on a wrong passphrase.</summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> data, string passphrase)
    {
        if (!IsEncrypted(data) || data.Length <= ExtraLength)
            throw new FormatException("Not a toxEsave encrypted blob.");

        var salt = data.Slice(MagicLength, SaltSize);
        var nonce = data.Slice(MagicLength + SaltSize, CryptoConstants.NonceSize);
        var key = DeriveKey(passphrase, salt);
        try
        {
            return Crypto.Decrypt(key, nonce, data[(MagicLength + SaltSize + CryptoConstants.NonceSize)..])
                   ?? throw new CryptographicException("Wrong passphrase or corrupted data.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
