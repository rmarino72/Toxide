using Tests.Infrastructure;
using Toxide.Dht;
using Toxide.Network;

namespace Tests.Dht;

public class DhtNodeTests
{
    [Fact]
    public void Bootstrap_VerifiesBothSides()
    {
        using var h = new DhtHarness();
        var a = h.Add();
        var b = h.Add();

        a.Node.Bootstrap(b.Endpoint, b.Node.PublicKey);
        h.Pump();

        Assert.Equal(1, a.Node.KnownNodeCount); // b answered our nodes request
        h.Run(TimeSpan.FromSeconds(2));
        Assert.Equal(1, b.Node.KnownNodeCount); // b pinged a back after a's request
        Assert.True(a.Node.IsConnected);
    }

    [Fact]
    public void Lookup_FindsTheClosestNodesToEachKey()
    {
        using var h = new DhtHarness();
        var peers = Enumerable.Range(0, 16).Select(_ => h.Add()).ToList();
        foreach (var p in peers.Skip(1))
            p.Node.Bootstrap(peers[0].Endpoint, peers[0].Node.PublicKey);

        h.Run(TimeSpan.FromSeconds(120));

        // Kademlia's invariant: every node ends up knowing the nodes closest to its own key, which
        // are the ones a search for that key converges on. (In a network this small the 3rd and 4th
        // closest can sit in the far half of the key space, which lookups reach only eventually.)
        foreach (var p in peers)
        {
            var closest = peers.Where(o => o != p)
                .OrderBy(o => o.Node.PublicKey, Comparer<byte[]>.Create((a, b) => XorDistance.Compare(p.Node.PublicKey, a, b)))
                .Take(2);
            var known = p.Node.GetKnownNodes().Select(n => Convert.ToHexString(n.PublicKey)).ToHashSet();
            foreach (var c in closest)
            {
                bool reverse = c.Node.GetKnownNodes().Any(n => n.PublicKey.AsSpan().SequenceEqual(p.Node.PublicKey));
                Assert.True(known.Contains(Convert.ToHexString(c.Node.PublicKey)),
                    $"peer {peers.IndexOf(p)} (knows {known.Count}) misses {peers.IndexOf(c)} (knows {c.Node.KnownNodeCount}, knows peer: {reverse}); " +
                    $"cpl={XorDistance.CommonPrefixLength(p.Node.PublicKey, c.Node.PublicKey)}");
            }
        }
    }

    [Fact]
    public void CryptoRequest_IsForwardedToItsReceiver()
    {
        using var h = new DhtHarness();
        var a = h.Add();
        var relay = h.Add();
        var c = h.Add();
        a.Node.Bootstrap(relay.Endpoint, relay.Node.PublicKey);
        c.Node.Bootstrap(relay.Endpoint, relay.Node.PublicKey);
        h.Run(TimeSpan.FromSeconds(3));

        byte[]? sender = null, data = null;
        c.Node.RegisterCryptoHandler(200, (_, key, d) => (sender, data) = (key, d));

        var packet = a.Node.CreateCryptoRequest(c.Node.PublicKey, 200, "hello"u8)!;
        a.Socket.Send(relay.Endpoint, packet); // a sends it to the relay, which knows c
        h.Pump();

        Assert.Equal(a.Node.PublicKey, sender);
        Assert.Equal("hello"u8.ToArray(), data);
    }

    [Fact]
    public void FriendSearch_FindsTheFriendsAddress()
    {
        using var h = new DhtHarness();
        var peers = Enumerable.Range(0, 10).Select(_ => h.Add()).ToList();
        foreach (var p in peers.Skip(1))
            p.Node.Bootstrap(peers[0].Endpoint, peers[0].Node.PublicKey);
        h.Run(TimeSpan.FromSeconds(30));

        var searcher = peers[3];
        var friend = peers[8];
        IpPort? found = null;
        searcher.Node.AddFriend(friend.Node.PublicKey, ep => found = ep);
        h.Run(TimeSpan.FromSeconds(30));

        Assert.Equal(friend.Endpoint, found);
        Assert.True(searcher.Node.TryGetFriendEndpoint(friend.Node.PublicKey, out var endpoint));
        Assert.Equal(friend.Endpoint, endpoint);
    }

    [Fact]
    public void ResponsesToUnsentRequests_AreIgnored()
    {
        using var h = new DhtHarness();
        var a = h.Add();
        var b = h.Add();

        // b answers a request a never made: a must not add b (no unsolicited table poisoning).
        var forged = DhtPacket.Create(h.Crypto, PacketKind.NodesResponse, b.Node.PublicKey,
            h.Crypto.ComputeSharedKey(a.Node.PublicKey, b.Node.SecretKey),
            DhtPayloads.WriteNodesResponse([], 12345));
        b.Socket.Send(a.Endpoint, forged);
        h.Pump();

        Assert.Equal(0, a.Node.KnownNodeCount);
    }
}
