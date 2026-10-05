using Toxide.Crypto;

namespace Tests.Crypto;

public class ToxIdTests
{
    // Public key = bytes 0x00..0x1F, nospam = 0x20..0x23.
    // Expected checksum computed independently (Python): even bytes XOR = 0x02, odd bytes XOR = 0x02.
    private const string KnownId =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" + // public key
        "20212223" +                                                         // nospam
        "0202";                                                              // checksum

    private static byte[] Seq(int start, int count) =>
        Enumerable.Range(start, count).Select(i => (byte)i).ToArray();

    [Fact]
    public void ToString_ProducesKnownVector()
    {
        var id = new ToxId(Seq(0, 32), Seq(32, 4));

        Assert.Equal(KnownId, id.ToString());
    }

    [Fact]
    public void ToString_Has76HexCharacters()
    {
        var id = new ToxId(new byte[32], new byte[4]);

        Assert.Equal(ToxId.Size * 2, id.ToString().Length);
    }

    [Fact]
    public void Parse_KnownVector_ExtractsFields()
    {
        var id = ToxId.Parse(KnownId);

        Assert.Equal(Seq(0, 32), id.PublicKey);
        Assert.Equal(Seq(32, 4), id.NoSpam);
    }

    [Fact]
    public void Parse_ThenToString_RoundTrips()
    {
        var original = new ToxId(Seq(100, 32), Seq(7, 4));

        var parsed = ToxId.Parse(original.ToString());

        Assert.Equal(original.ToString(), parsed.ToString());
    }

    [Fact]
    public void TryParse_AcceptsLowercase()
    {
        Assert.True(ToxId.TryParse(KnownId.ToLowerInvariant(), out _));
    }

    [Fact]
    public void TryParse_RejectsWrongChecksum()
    {
        var corrupted = KnownId[..^4] + "0000";

        Assert.False(ToxId.TryParse(corrupted, out var id));
        Assert.Null(id);
    }

    [Fact]
    public void TryParse_RejectsSingleCharacterTypo()
    {
        // Change one character inside the public key: the checksum must catch it.
        var typo = "1" + KnownId[1..];

        Assert.False(ToxId.TryParse(typo, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ABCD")]
    public void TryParse_RejectsNullOrWrongLength(string? input)
    {
        Assert.False(ToxId.TryParse(input, out _));
    }

    [Fact]
    public void TryParse_RejectsNonHexCharacters()
    {
        var invalid = "ZZ" + KnownId[2..];

        Assert.False(ToxId.TryParse(invalid, out _));
    }

    [Fact]
    public void Parse_Invalid_ThrowsFormatException()
    {
        Assert.Throws<FormatException>(() => ToxId.Parse("not a tox id"));
    }

    [Fact]
    public void Constructor_RejectsWrongLengths()
    {
        Assert.Throws<ArgumentException>(() => new ToxId(new byte[31], new byte[4]));
        Assert.Throws<ArgumentException>(() => new ToxId(new byte[32], new byte[3]));
    }
}