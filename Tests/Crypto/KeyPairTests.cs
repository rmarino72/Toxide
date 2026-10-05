using Toxide.Crypto;

namespace Tests.Crypto;

public class KeyPairTests
{
    [Fact]
    public void Constructor_RejectsWrongLengths()
    {
        Assert.Throws<ArgumentException>(() => new KeyPair(new byte[31], new byte[32]));
        Assert.Throws<ArgumentException>(() => new KeyPair(new byte[32], new byte[33]));
    }

    [Fact]
    public void Dispose_WipesSecretKey()
    {
        var secret = Enumerable.Repeat((byte)0xAA, 32).ToArray();
        var pair = new KeyPair(new byte[32], secret);

        pair.Dispose();

        Assert.All(secret, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Dispose_LeavesPublicKeyIntact()
    {
        var pub = Enumerable.Repeat((byte)0x55, 32).ToArray();
        var pair = new KeyPair(pub, new byte[32]);

        pair.Dispose();

        Assert.All(pub, b => Assert.Equal(0x55, b));
    }
}