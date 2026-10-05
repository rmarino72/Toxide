using System.Security.Cryptography;
using Toxide.Crypto;

namespace Toxide.State;

/// <summary>
/// A key derived once from a passphrase and salt, reusable for many encryptions in the toxEsave
/// format (toxcore's Tox_Pass_Key). Deriving is slow on purpose; encrypting with a derived key is not.
/// </summary>
public sealed class ToxPassKey : IDisposable
{
    private static readonly ICryptoCore Crypto = new ManagedCryptoCore();
    private readonly byte[] _key;

    private ToxPassKey(byte[] key, byte[] salt)
    {
        _key = key;
        Salt = salt;
    }

    public byte[] Salt { get; }

    /// <summary>Derives a key with a new random salt.</summary>
    public static ToxPassKey Derive(string passphrase) => Derive(passphrase, RandomNumberGenerator.GetBytes(ToxEncryptSave.SaltSize));

    public static ToxPassKey Derive(string passphrase, ReadOnlySpan<byte> salt) =>
        new(ToxEncryptSave.DeriveKey(passphrase, salt), salt.ToArray());

    /// <summary>The salt stored in a toxEsave blob, or null if <paramref name="data"/> is not one.</summary>
    public static byte[]? GetSalt(ReadOnlySpan<byte> data) =>
        ToxEncryptSave.IsEncrypted(data) && data.Length >= ToxEncryptSave.ExtraLength
            ? data.Slice(8, ToxEncryptSave.SaltSize).ToArray()
            : null;

    public byte[] Encrypt(ReadOnlySpan<byte> plain)
    {
        var nonce = Nonce.Random();
        var cipher = Crypto.Encrypt(_key, nonce, plain);
        var result = new byte[8 + ToxEncryptSave.SaltSize + CryptoConstants.NonceSize + cipher.Length];
        "toxEsave"u8.CopyTo(result);
        Salt.CopyTo(result, 8);
        nonce.CopyTo(result, 8 + ToxEncryptSave.SaltSize);
        cipher.CopyTo(result, 8 + ToxEncryptSave.SaltSize + CryptoConstants.NonceSize);
        return result;
    }

    /// <summary>Decrypts a blob encrypted with this key (same salt); throws <see cref="CryptographicException"/> otherwise.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> data)
    {
        var salt = GetSalt(data) ?? throw new FormatException("Not a toxEsave encrypted blob.");
        if (!salt.AsSpan().SequenceEqual(Salt))
            throw new CryptographicException("The data was encrypted with a different salt.");

        return Crypto.Decrypt(_key, data.Slice(8 + ToxEncryptSave.SaltSize, CryptoConstants.NonceSize),
                   data[(8 + ToxEncryptSave.SaltSize + CryptoConstants.NonceSize)..])
               ?? throw new CryptographicException("Wrong passphrase or corrupted data.");
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
