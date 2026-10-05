using Toxide.Crypto;

namespace Tests.Crypto;

public class NonceTests
{
    [Fact]
    public void Random_Has24Bytes()
    {
        Assert.Equal(CryptoConstants.NonceSize, Nonce.Random().Length);
    }

    [Fact]
    public void Random_ProducesDifferentValues()
    {
        // Probability of a collision on 192 random bits is negligible.
        Assert.NotEqual(Nonce.Random(), Nonce.Random());
    }

    [Fact]
    public void Increment_AddsOneToLastByte()
    {
        var nonce = new byte[24];

        Nonce.Increment(nonce);

        Assert.Equal(1, nonce[23]);
        Assert.All(nonce[..23], b => Assert.Equal(0, b));
    }

    [Fact]
    public void Increment_PropagatesCarry()
    {
        var nonce = new byte[24];
        nonce[22] = 0x00;
        nonce[23] = 0xFF;

        Nonce.Increment(nonce);

        Assert.Equal(0x01, nonce[22]);
        Assert.Equal(0x00, nonce[23]);
    }

    [Fact]
    public void Increment_PropagatesCarryAcrossMultipleBytes()
    {
        var nonce = new byte[24];
        nonce[20] = 0x05;
        nonce[21] = 0xFF;
        nonce[22] = 0xFF;
        nonce[23] = 0xFF;

        Nonce.Increment(nonce);

        Assert.Equal(new byte[] { 0x06, 0x00, 0x00, 0x00 }, nonce[20..]);
    }

    [Fact]
    public void Increment_AllOnes_WrapsToZero()
    {
        var nonce = Enumerable.Repeat((byte)0xFF, 24).ToArray();

        Nonce.Increment(nonce);

        Assert.All(nonce, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Add_PropagatesCarryBigEndian()
    {
        var nonce = new byte[24];
        nonce[23] = 0xFF;
        nonce[22] = 0xFF;

        Nonce.Add(nonce, 2);

        Assert.Equal(1, nonce[23]);
        Assert.Equal(0, nonce[22]);
        Assert.Equal(1, nonce[21]);
    }

    [Fact]
    public void Add_MatchesRepeatedIncrement()
    {
        var a = Nonce.Random();
        var b = (byte[])a.Clone();

        Nonce.Add(a, 70_000);
        for (int i = 0; i < 70_000; i++)
            Nonce.Increment(b);

        Assert.Equal(b, a);
    }
}
