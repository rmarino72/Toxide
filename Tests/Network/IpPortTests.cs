using System.Net;
using Toxide.Network;

namespace Tests.Network;

public class IpPortTests
{
    [Fact]
    public void Constructor_NormalizesIPv4MappedAddress()
    {
        var mapped = IPAddress.Parse("::ffff:192.168.1.10");

        var ipPort = new IpPort(mapped, 33445);

        Assert.True(ipPort.IsIPv4);
        Assert.Equal(IPAddress.Parse("192.168.1.10"), ipPort.Address);
    }

    [Fact]
    public void MappedAndPlainIPv4_AreEqual()
    {
        var a = new IpPort(IPAddress.Parse("::ffff:10.0.0.1"), 1234);
        var b = new IpPort(IPAddress.Parse("10.0.0.1"), 1234);

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void DifferentPorts_AreNotEqual()
    {
        Assert.NotEqual(new IpPort(IPAddress.Loopback, 1), new IpPort(IPAddress.Loopback, 2));
    }

    [Fact]
    public void IPv6_IsNotIPv4()
    {
        Assert.False(new IpPort(IPAddress.IPv6Loopback, 1).IsIPv4);
    }
}