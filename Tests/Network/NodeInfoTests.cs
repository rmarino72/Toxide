using System.Net;
using Toxide.Network;

namespace Tests.Network;

public class NodeInfoTests
{
    private static byte[] Key(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    [Fact]
    public void Pack_UdpIPv4_ProducesKnownBytes()
    {
        var node = new NodeInfo(TransportProtocol.Udp, new IpPort(IPAddress.Parse("192.168.1.10"), 33445), Key(0xAB));
        var buffer = new byte[NodeInfo.PackedSizeIPv4];

        int written = node.Pack(buffer);

        var expected = new byte[] { 0x02, 192, 168, 1, 10, 0x82, 0xA5 } // 33445 = 0x82A5, big-endian
            .Concat(Key(0xAB)).ToArray();
        Assert.Equal(39, written);
        Assert.Equal(expected, buffer);
    }

    [Theory]
    [InlineData(TransportProtocol.Udp, "10.0.0.1", 0x02)]
    [InlineData(TransportProtocol.Udp, "2001:db8::1", 0x0A)]
    [InlineData(TransportProtocol.Tcp, "10.0.0.1", 0x82)]
    [InlineData(TransportProtocol.Tcp, "2001:db8::1", 0x8A)]
    public void Pack_WritesCorrectTypeByte(TransportProtocol protocol, string ip, int expectedType)
    {
        var node = new NodeInfo(protocol, new IpPort(IPAddress.Parse(ip), 1), Key(1));
        var buffer = new byte[node.PackedSize];

        node.Pack(buffer);

        Assert.Equal((byte)expectedType, buffer[0]);
    }

    [Theory]
    [InlineData(TransportProtocol.Udp, "203.0.113.7", 33445)]
    [InlineData(TransportProtocol.Tcp, "2001:db8::42", 443)]
    public void PackThenUnpack_RoundTrips(TransportProtocol protocol, string ip, int port)
    {
        var original = new NodeInfo(protocol, new IpPort(IPAddress.Parse(ip), (ushort)port), Key(0x5A));
        var buffer = new byte[original.PackedSize];
        original.Pack(buffer);

        Assert.True(NodeInfo.TryUnpack(buffer, out var parsed, out int read));
        Assert.Equal(original.PackedSize, read);
        Assert.Equal(original.Protocol, parsed.Protocol);
        Assert.Equal(original.Endpoint, parsed.Endpoint);
        Assert.Equal(original.PublicKey, parsed.PublicKey);
    }

    [Fact]
    public void TryUnpack_RejectsUnknownType()
    {
        var buffer = new byte[NodeInfo.PackedSizeIPv6];
        buffer[0] = 0x07;

        Assert.False(NodeInfo.TryUnpack(buffer, out _, out _));
    }

    [Fact]
    public void TryUnpack_RejectsTruncatedInput()
    {
        var node = new NodeInfo(TransportProtocol.Udp, new IpPort(IPAddress.Loopback, 1), Key(1));
        var buffer = new byte[node.PackedSize];
        node.Pack(buffer);

        Assert.False(NodeInfo.TryUnpack(buffer.AsSpan(0, buffer.Length - 1), out _, out _));
    }

    [Fact]
    public void TryUnpack_RejectsEmptyInput()
    {
        Assert.False(NodeInfo.TryUnpack([], out _, out _));
    }

    [Fact]
    public void PackManyThenUnpackMany_HandlesMixedFamilies()
    {
        var nodes = new List<NodeInfo>
        {
            new(TransportProtocol.Udp, new IpPort(IPAddress.Parse("1.2.3.4"), 1000), Key(1)),
            new(TransportProtocol.Udp, new IpPort(IPAddress.Parse("2001:db8::5"), 2000), Key(2)),
            new(TransportProtocol.Tcp, new IpPort(IPAddress.Parse("5.6.7.8"), 3000), Key(3)),
        };
        var buffer = new byte[nodes.Sum(n => n.PackedSize)];

        int written = NodeInfo.PackMany(nodes, buffer);

        Assert.True(NodeInfo.TryUnpackMany(buffer, nodes.Count, out var parsed, out int read));
        Assert.Equal(written, read);
        Assert.Equal(nodes.Select(n => n.Endpoint), parsed.Select(n => n.Endpoint));
        Assert.Equal(nodes.Select(n => n.PublicKey[0]), parsed.Select(n => n.PublicKey[0]));
    }

    [Fact]
    public void TryUnpackMany_FailsIfFewerNodesThanDeclared()
    {
        var node = new NodeInfo(TransportProtocol.Udp, new IpPort(IPAddress.Loopback, 1), Key(1));
        var buffer = new byte[node.PackedSize];
        node.Pack(buffer);

        Assert.False(NodeInfo.TryUnpackMany(buffer, 2, out _, out _));
    }
}