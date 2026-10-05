using System.Security.Cryptography;
using Toxide.Crypto;

namespace Toxide.Tests.Crypto;

/// <summary>
/// Expected values were produced by libsodium (via PyNaCl), the same library used by toxcore.
/// Matching them byte for byte proves wire compatibility.
/// Alice and Bob secret keys are the RFC 7748 / NaCl test keys.
/// </summary>
public class ManagedCryptoCoreTests
{
    private static readonly byte[] AliceSecret = Convert.FromHexString(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    private static readonly byte[] AlicePublic = Convert.FromHexString(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    private static readonly byte[] BobSecret = Convert.FromHexString(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    private static readonly byte[] BobPublic = Convert.FromHexString(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    private static readonly byte[] SharedKey = Convert.FromHexString(
        "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
    private static readonly byte[] TestNonce = Convert.FromHexString(
        "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");

    // 86 bytes: spans two Salsa20 blocks, so the block counter is exercised too.
    private static readonly byte[] Message =
        "Hello Tox! This message spans more than one 64-byte Salsa20 block to test the counter."u8.ToArray();

    private static readonly byte[] ExpectedCipher = Convert.FromHexString(
        "05ab585c495a0ea69d90e2eae302aea2" + // Poly1305 MAC
        "78fb08361bc9b4c975a363f8b17e0995777e98fe3b4838507f795d3026a53af9" +
        "57565ba7c300f341380ebde584108539647a9b2eebc682655b89335630f3a36a" +
        "d19572a93895599403f858528cf1c59607ba6267f5e5");

    private static readonly byte[] ExpectedEmptyCipher = Convert.FromHexString(
        "2539121d8e234e652d651fa4c8cff880");

    private readonly ManagedCryptoCore _crypto = new();

    [Fact]
    public void DeriveKeyPair_MatchesRfc7748PublicKeys()
    {
        Assert.Equal(AlicePublic, _crypto.DeriveKeyPair(AliceSecret).PublicKey);
        Assert.Equal(BobPublic, _crypto.DeriveKeyPair(BobSecret).PublicKey);
    }

    [Fact]
    public void ComputeSharedKey_MatchesLibsodium()
    {
        Assert.Equal(SharedKey, _crypto.ComputeSharedKey(BobPublic, AliceSecret));
    }

    [Fact]
    public void ComputeSharedKey_IsSymmetric()
    {
        var aliceSide = _crypto.ComputeSharedKey(BobPublic, AliceSecret);
        var bobSide = _crypto.ComputeSharedKey(AlicePublic, BobSecret);

        Assert.Equal(aliceSide, bobSide);
    }

    [Fact]
    public void ComputeSharedKey_RejectsAllZeroPublicKey()
    {
        Assert.Throws<CryptographicException>(() => _crypto.ComputeSharedKey(new byte[32], AliceSecret));
    }

    [Fact]
    public void Encrypt_MatchesLibsodium()
    {
        Assert.Equal(ExpectedCipher, _crypto.Encrypt(SharedKey, TestNonce, Message));
    }

    [Fact]
    public void Encrypt_EmptyMessage_ProducesOnlyMac()
    {
        Assert.Equal(ExpectedEmptyCipher, _crypto.Encrypt(SharedKey, TestNonce, []));
    }

    [Fact]
    public void Decrypt_LibsodiumCipher_ReturnsMessage()
    {
        Assert.Equal(Message, _crypto.Decrypt(SharedKey, TestNonce, ExpectedCipher));
    }

    [Fact]
    public void Decrypt_AnyFlippedBit_ReturnsNull()
    {
        for (int i = 0; i < ExpectedCipher.Length; i++)
        {
            var tampered = (byte[])ExpectedCipher.Clone();
            tampered[i] ^= 0x01;

            Assert.Null(_crypto.Decrypt(SharedKey, TestNonce, tampered));
        }
    }

    [Fact]
    public void Decrypt_WrongNonce_ReturnsNull()
    {
        var nonce = (byte[])TestNonce.Clone();
        Nonce.Increment(nonce);

        Assert.Null(_crypto.Decrypt(SharedKey, nonce, ExpectedCipher));
    }

    [Fact]
    public void Decrypt_WrongKey_ReturnsNull()
    {
        var key = (byte[])SharedKey.Clone();
        key[0] ^= 0xFF;

        Assert.Null(_crypto.Decrypt(key, TestNonce, ExpectedCipher));
    }

    [Fact]
    public void Decrypt_ShorterThanMac_ReturnsNull()
    {
        Assert.Null(_crypto.Decrypt(SharedKey, TestNonce, new byte[15]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1373)] // max Tox UDP payload order of magnitude
    public void EncryptThenDecrypt_RoundTrips(int length)
    {
        using var alice = _crypto.GenerateKeyPair();
        using var bob = _crypto.GenerateKeyPair();
        var plain = RandomNumberGenerator.GetBytes(length);
        var nonce = Nonce.Random();

        var cipher = _crypto.Encrypt(_crypto.ComputeSharedKey(bob.PublicKey, alice.SecretKey), nonce, plain);
        var decrypted = _crypto.Decrypt(_crypto.ComputeSharedKey(alice.PublicKey, bob.SecretKey), nonce, cipher);

        Assert.Equal(CryptoConstants.MacSize + length, cipher.Length);
        Assert.Equal(plain, decrypted);
    }

    [Fact]
    public void Methods_RejectWrongLengths()
    {
        Assert.Throws<ArgumentException>(() => _crypto.DeriveKeyPair(new byte[31]));
        Assert.Throws<ArgumentException>(() => _crypto.ComputeSharedKey(new byte[31], AliceSecret));
        Assert.Throws<ArgumentException>(() => _crypto.Encrypt(new byte[31], TestNonce, Message));
        Assert.Throws<ArgumentException>(() => _crypto.Encrypt(SharedKey, new byte[23], Message));
    }
}