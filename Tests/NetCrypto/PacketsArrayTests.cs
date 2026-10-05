using Toxide.NetCrypto;

namespace Tests.NetCrypto;

public class PacketsArrayTests
{
    private static PacketData Data(byte b) => new([b]);

    [Fact]
    public void Append_AssignsConsecutiveNumbers()
    {
        var array = new PacketsArray();
        Assert.Equal(0, array.Append(Data(1)));
        Assert.Equal(1, array.Append(Data(2)));
        Assert.Equal(2u, array.Count);
    }

    [Fact]
    public void TryTakeFirst_DeliversInOrder_AndWaitsForGaps()
    {
        var array = new PacketsArray();
        Assert.True(array.TryAdd(1, Data(1)));   // packet 0 still missing
        Assert.False(array.TryTakeFirst(out _));

        Assert.True(array.TryAdd(0, Data(0)));
        Assert.True(array.TryTakeFirst(out var first));
        Assert.Equal(0, first!.Data[0]);
        Assert.True(array.TryTakeFirst(out var second));
        Assert.Equal(1, second!.Data[0]);
        Assert.False(array.TryTakeFirst(out _));
    }

    [Fact]
    public void TryAdd_RejectsDuplicatesAndOutOfWindow()
    {
        var array = new PacketsArray();
        Assert.True(array.TryAdd(5, Data(5)));
        Assert.False(array.TryAdd(5, Data(5)));
        Assert.False(array.TryAdd(PacketsArray.Capacity, Data(0)));
    }

    [Fact]
    public void ClearUntil_FreesConfirmedPackets()
    {
        var array = new PacketsArray();
        for (int i = 0; i < 10; i++)
            array.Append(Data((byte)i));

        Assert.True(array.ClearUntil(7));
        Assert.Equal(7u, array.Start);
        Assert.Equal(3u, array.Count);
        Assert.Equal(-1, array.TryGet(6, out _));
        Assert.Equal(1, array.TryGet(7, out var seven));
        Assert.Equal(7, seven!.Data[0]);
    }

    [Fact]
    public void Numbers_WrapAroundUInt32()
    {
        var array = new PacketsArray(uint.MaxValue - 1);
        var numbers = Enumerable.Range(0, 4).Select(i => array.Append(Data((byte)i))).ToList();

        Assert.Equal(new long[] { uint.MaxValue - 1, uint.MaxValue, 0, 1 }, numbers);
        Assert.Equal(4u, array.Count);
        Assert.True(array.ClearUntil(1));
        Assert.Equal(1u, array.Start);
        Assert.Equal(1u, array.Count);
        Assert.Equal(1, array.TryGet(1, out var last));
        Assert.Equal(3, last!.Data[0]);
    }
}
