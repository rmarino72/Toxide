using Tests.Infrastructure;
using Toxide.Network;
using Toxide.Onion;

namespace Tests.Onion;

public class OnionRelayTests
{
    [Fact]
    public void Request_TravelsThreeHops_AndResponseComesBack()
    {
        using var h = new DhtHarness();
        var relays = Enumerable.Range(0, 3).Select(_ => h.Add(p => new OnionRelay(p.Node, h.Time).Attach(p.Dispatcher))).ToList();
        // The client and the destination are raw sockets: the test reads what reaches them.
        using var clientKeys = h.Crypto.GenerateKeyPair();
        var client = h.Network.AddHost(new IpPort(System.Net.IPAddress.Parse("203.0.113.100"), 1));
        var destination = h.Network.AddHost(new IpPort(System.Net.IPAddress.Parse("203.0.113.200"), 1));

        var path = OnionPath.Create(h.Crypto, clientKeys.PublicKey, clientKeys.SecretKey,
            relays.Select(r => new NodeInfo(TransportProtocol.Udp, r.Endpoint, r.Node.PublicKey)).ToList())!;
        byte[] request = [(byte)PacketKind.AnnounceRequest, 1, 2, 3, 4, 5];

        client.Send(path.Endpoint1, OnionPacket.Create(h.Crypto, path, destination.Endpoint, request)!);
        h.Pump();

        // The destination gets the request from node 3, followed by the 177-byte return block.
        Assert.True(destination.Incoming.TryRead(out var delivered));
        Assert.Equal(relays[2].Endpoint, delivered.Source);
        Assert.Equal(request, delivered.Data[..request.Length]);
        Assert.Equal(request.Length + OnionPacket.Return3, delivered.Data.Length);

        // Answer through the return path: [0x8c][return 3][response].
        byte[] response = [(byte)PacketKind.AnnounceResponse, 9, 8, 7];
        var back = new byte[] { (byte)PacketKind.OnionReceive3 }
            .Concat(delivered.Data[request.Length..]).Concat(response).ToArray();
        destination.Send(delivered.Source, back);
        h.Pump();

        Assert.True(client.Incoming.TryRead(out var answer));
        Assert.Equal(relays[0].Endpoint, answer.Source); // only node 1 ever talks to the client
        Assert.Equal(response, answer.Data);
    }

    [Fact]
    public void Node3_RefusesToDeliverArbitraryPackets()
    {
        using var h = new DhtHarness();
        var relays = Enumerable.Range(0, 3).Select(_ => h.Add(p => new OnionRelay(p.Node, h.Time).Attach(p.Dispatcher))).ToList();
        var client = h.Add();
        var victim = h.Network.AddHost(new IpPort(System.Net.IPAddress.Parse("203.0.113.201"), 1));
        var path = OnionPath.Create(h.Crypto, client.Node.PublicKey, client.Node.SecretKey,
            relays.Select(r => new NodeInfo(TransportProtocol.Udp, r.Endpoint, r.Node.PublicKey)).ToList())!;

        client.Socket.Send(path.Endpoint1, OnionPacket.Create(h.Crypto, path, victim.Endpoint, [(byte)PacketKind.PingRequest, 0])!);
        h.Pump();

        Assert.False(victim.Incoming.TryRead(out _));
    }
}
