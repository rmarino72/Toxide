using System.Security.Cryptography;

namespace Toxide.Crypto;

/// <summary>
/// Curve25519 key pair.
/// Tox uses three kinds of key pairs:
///  - identity (long-term): part of the Tox ID and stored in the savedata;
///  - DHT: temporary, regenerated on every start, so DHT nodes cannot link the IP to the identity;
///  - session (net_crypto): one per connection, provides forward secrecy.
/// </summary>
public sealed class KeyPair : IDisposable
{
    public byte[] PublicKey { get; }
    public byte[] SecretKey { get; }

    public KeyPair(byte[] publicKey, byte[] secretKey)
    {
        if (publicKey.Length != CryptoConstants.PublicKeySize)
            throw new ArgumentException("Invalid public key length.", nameof(publicKey));
        if (secretKey.Length != CryptoConstants.SecretKeySize)
            throw new ArgumentException("Invalid secret key length.", nameof(secretKey));

        PublicKey = publicKey;
        SecretKey = secretKey;
    }

    /// <summary>Wipes the secret key from memory.</summary>
    public void Dispose() => CryptographicOperations.ZeroMemory(SecretKey);
}