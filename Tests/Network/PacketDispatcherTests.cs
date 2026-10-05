using System.Net;
using Toxide.Network;

namespace Tests.Network;

public class PacketDispatcherTests
{
    private static readonly IpPort Source = new(IPAddress.Loopback, 33445);

    [Fact]
    public void Dispatch_RoutesByFirstByte()
    {
        var dispatcher = new PacketDispatcher();
        byte[]? received = null;
        dispatcher.Register(PacketKind.PingRequest, (_, p) => received = p.ToArray());

        bool handled = dispatcher.Dispatch(Source, [0x00, 0xAA, 0xBB]);

        Assert.True(handled);
        Assert.Equal(new byte[] { 0x00, 0xAA, 0xBB }, received); // kind byte included
    }

    [Fact]
    public void Dispatch_PassesSource()
    {
        var dispatcher = new PacketDispatcher();
        IpPort? from = null;
        dispatcher.Register(PacketKind.NodesRequest, (s, _) => from = s);

        dispatcher.Dispatch(Source, [(byte)PacketKind.NodesRequest]);

        Assert.Equal(Source, from);
    }

    [Fact]
    public void Dispatch_UnregisteredKind_ReturnsFalse()
    {
        Assert.False(new PacketDispatcher().Dispatch(Source, [0x42]));
    }

    [Fact]
    public void Dispatch_EmptyPacket_ReturnsFalse()
    {
        Assert.False(new PacketDispatcher().Dispatch(Source, []));
    }

    [Fact]
    public void Register_Twice_Throws()
    {
        var dispatcher = new PacketDispatcher();
        dispatcher.Register(PacketKind.PingRequest, (_, _) => { });

        Assert.Throws<InvalidOperationException>(() => dispatcher.Register(PacketKind.PingRequest, (_, _) => { }));
    }

    [Fact]
    public void Unregister_StopsRouting()
    {
        var dispatcher = new PacketDispatcher();
        dispatcher.Register(PacketKind.PingRequest, (_, _) => { });
        dispatcher.Unregister(PacketKind.PingRequest);

        Assert.False(dispatcher.Dispatch(Source, [0x00]));
    }
}