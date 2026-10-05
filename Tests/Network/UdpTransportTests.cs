using System.Net;
using Toxide.Network;

namespace Toxide.Tests.Network;

/// <summary>Integration tests on the loopback interface: real sockets, no external network.</summary>
public class UdpTransportTests
{
    private static async Task<ReceivedPacket> ReceiveAsync(UdpTransport transport)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        return await transport.Incoming.ReadAsync(timeout.Token);
    }

    [Fact]
    public async Task SendAsync_Loopback_DeliversPacketAndSource()
    {
        await using var alice = UdpTransport.Bind(0, 0);
        await using var bob = UdpTransport.Bind(0, 0);
        byte[] payload = [0x00, 1, 2, 3];

        Assert.True(await alice.SendAsync(new IpPort(IPAddress.Loopback, bob.LocalPort), payload));
        var received = await ReceiveAsync(bob);

        Assert.Equal(payload, received.Data);
        // On a dual-stack socket the source arrives as ::ffff:127.0.0.1 and must be normalized.
        Assert.Equal(new IpPort(IPAddress.Loopback, alice.LocalPort), received.Source);
    }

    [Fact]
    public async Task Bind_SkipsPortInUse()
    {
        await using var first = UdpTransport.Bind(0, 0);
        ushort taken = first.LocalPort;

        // Range starts at the taken port: the transport must move on to the next one.
        await using var second = UdpTransport.Bind(taken, (ushort)Math.Min(taken + 10, ushort.MaxValue));

        Assert.NotEqual(taken, second.LocalPort);
    }

    [Fact]
    public async Task SendAsync_RejectsOversizedPacket()
    {
        await using var transport = UdpTransport.Bind(0, 0);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await transport.SendAsync(new IpPort(IPAddress.Loopback, 1), new byte[UdpTransport.MaxPacketSize + 1]));
    }

    [Fact]
    public async Task Received_PacketsCanBeDispatched()
    {
        await using var alice = UdpTransport.Bind(0, 0);
        await using var bob = UdpTransport.Bind(0, 0);
        var dispatcher = new PacketDispatcher();
        var handled = false;
        dispatcher.Register(PacketKind.PingRequest, (_, _) => handled = true);

        await alice.SendAsync(new IpPort(IPAddress.Loopback, bob.LocalPort), new byte[] { 0x00, 0xFF });
        var packet = await ReceiveAsync(bob);
        dispatcher.Dispatch(packet.Source, packet.Data);

        Assert.True(handled);
    }
}