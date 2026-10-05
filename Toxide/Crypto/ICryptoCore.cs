namespace Toxide.Crypto;

/// <summary>
/// The primitives required by the rest of Toxide.
/// Defined as an interface so a didactic implementation can be compared against a reference one
/// to verify that both produce identical bytes.
/// </summary>
public interface ICryptoCore
{
    /// <summary>New random Curve25519 (X25519) key pair.</summary>
    KeyPair GenerateKeyPair();

    /// <summary>Rebuilds a key pair from an existing secret key (e.g. loaded from savedata).</summary>
    KeyPair DeriveKeyPair(ReadOnlySpan<byte> secretKey);

    /// <summary>
    /// crypto_box_beforenm: HSalsa20(X25519(secret, public), 0^16).
    /// Computed once per peer and reused: this is the expensive operation.
    /// </summary>
    byte[] ComputeSharedKey(ReadOnlySpan<byte> theirPublicKey, ReadOnlySpan<byte> ourSecretKey);

    /// <summary>XSalsa20-Poly1305. Output: [MAC 16][ciphertext].</summary>
    byte[] Encrypt(ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plain);

    /// <summary>Returns null if the MAC is invalid (tampered packet or wrong key).</summary>
    byte[]? Decrypt(ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipher);
}