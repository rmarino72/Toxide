namespace Toxide.Crypto;

/// <summary>
/// Sizes of the cryptographic primitives used by Tox (identical to NaCl/libsodium crypto_box).
/// </summary>
public static class CryptoConstants
{
    /// <summary>Curve25519 public key.</summary>
    public const int PublicKeySize = 32;

    /// <summary>Curve25519 secret key.</summary>
    public const int SecretKeySize = 32;

    /// <summary>Precomputed shared key (crypto_box_beforenm).</summary>
    public const int SharedKeySize = 32;

    /// <summary>XSalsa20 nonce: 24 bytes, large enough to be generated randomly without collisions.</summary>
    public const int NonceSize = 24;

    /// <summary>Poly1305 authentication tag, prepended to the ciphertext.</summary>
    public const int MacSize = 16;
}