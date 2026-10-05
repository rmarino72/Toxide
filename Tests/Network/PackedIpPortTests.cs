using System.Net;
using Toxide.Network;

namespace Tests.Network;

public class PackedIpPortTests
{
    [Theory]
    [InlineData("198.51.100.7", 33445)]
    [InlineData("2001:db8::42", 1)]
    public void WriteThenRead_RoundTrips(string ip, int port)
    {
        var endpoint = new IpPort(IPAddress.Parse(ip), (ushort)port);
        var bytes = PackedIpPort.ToBytes(endpoint);

        Assert.Equal(PackedIpPort.Size, bytes.Length);
        Assert.True(PackedIpPort.TryRead(bytes, out var read));
        Assert.Equal(endpoint, read);
    }

    [Fact]
    public void IPv4_IsPaddedToFixedSize()
    {
        var bytes = PackedIpPort.ToBytes(new IpPort(IPAddress.Parse("1.2.3.4"), 0x1234));

        Assert.Equal(new byte[] { 2, 1, 2, 3, 4 }, bytes[..5]);
        Assert.All(bytes[5..17], b => Assert.Equal(0, b));
        Assert.Equal(new byte[] { 0x12, 0x34 }, bytes[17..]);
    }

    [Fact]
    public void TryRead_RejectsUnknownFamilyAndShortInput()
    {
        var bytes = PackedIpPort.ToBytes(new IpPort(IPAddress.Loopback, 1));
        bytes[0] = 130; // TCP family: relays are not supported
        Assert.False(PackedIpPort.TryRead(bytes, out _));
        Assert.False(PackedIpPort.TryRead(new byte[5], out _));
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.10.10", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("fe80::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("2001:db8::1", false)]
    public void IsLan_ClassifiesAddresses(string ip, bool lan)
    {
        Assert.Equal(lan, IPAddress.Parse(ip).IsLan());
    }
}
