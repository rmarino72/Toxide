using Tests.Infrastructure;
using Xunit.Abstractions;

namespace Tests.Integration;

/// <summary>Whole-stack scenarios on a simulated network (DHT, onion, net_crypto, messenger).</summary>
public class MessagingTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(3);

    [Fact]
    public void Nodes_JoinNetwork_AndGoOnline()
    {
        using var sim = new Simulation();
        var nodes = sim.AddBootstrapNodes(10);

        bool online = sim.RunUntil(() => nodes.All(n => n.ConnectionStatus == ToxConnection.Udp), Timeout);

        output.WriteLine($"t={sim.Time.GetUtcNow():HH:mm:ss} online={nodes.Count(n => n.ConnectionStatus == ToxConnection.Udp)} " +
                         $"dht={string.Join(",", nodes.Select(n => n.DhtNode.KnownNodeCount))} " +
                         $"announced={string.Join(",", nodes.Select(n => n.OnionClient.AnnouncedCount))}");
        Assert.True(online);
    }

    [Fact]
    public void FriendRequest_Accepted_ThenMessagesAndReceiptsFlow()
    {
        using var sim = new Simulation();
        var network = sim.AddBootstrapNodes(8);
        var alice = sim.AddNode();
        var bob = sim.AddNode();
        sim.Bootstrap(alice, network[0]);
        sim.Bootstrap(bob, network[1]);
        alice.Name = "Alice";
        bob.Name = "Bob";
        bob.StatusMessage = "busy coding";

        var received = new List<string>();
        var receipts = new List<uint>();
        string? requestMessage = null;
        bob.FriendRequestReceived += (_, e) =>
        {
            requestMessage = e.Message;
            bob.AddFriendNoRequest(e.PublicKey);
        };
        bob.FriendMessageReceived += (_, e) => received.Add(e.Message);
        alice.FriendReadReceipt += (_, e) => receipts.Add(e.MessageId);

        Assert.True(sim.RunUntil(() => alice.ConnectionStatus == ToxConnection.Udp && bob.ConnectionStatus == ToxConnection.Udp,
            Timeout), "clients did not come online");

        uint bobNumber = alice.AddFriend(bob.Address, "Hi Bob, it's Alice");

        bool connected = sim.RunUntil(() => bob.FriendList.Count == 1
                                            && alice.GetFriendConnectionStatus(bobNumber) == ToxConnection.Udp
                                            && bob.GetFriendConnectionStatus(bob.FriendList[0]) == ToxConnection.Udp, Timeout);
        output.WriteLine($"t={sim.Time.GetUtcNow():HH:mm:ss} request={requestMessage} bobFriends={bob.FriendList.Count}");
        Assert.True(connected, "friends did not connect");
        Assert.Equal("Hi Bob, it's Alice", requestMessage);

        uint id = alice.SendMessage(bobNumber, "hello over Toxide");
        Assert.True(sim.RunUntil(() => received.Count == 1 && receipts.Contains(id), TimeSpan.FromSeconds(10)));
        Assert.Equal("hello over Toxide", received[0]);

        Assert.True(sim.RunUntil(() => alice.GetFriendName(bobNumber) == "Bob"
                                       && alice.GetFriendStatusMessage(bobNumber) == "busy coding"
                                       && bob.GetFriendName(bob.FriendList[0]) == "Alice", TimeSpan.FromSeconds(10)));
    }
}

public class ResilienceTests
{
    [Fact]
    public void Messages_AreDelivered_OnALossyNetwork()
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, _) = sim.CreateFriends();
        sim.Network.LossRate = 0.2;

        var received = new List<string>();
        bob.FriendMessageReceived += (_, e) => received.Add(e.Message);
        var ids = Enumerable.Range(0, 50).Select(i => alice.SendMessage(bobOnAlice, $"message {i}")).ToList();

        Assert.True(sim.RunUntil(() => received.Count == 50, TimeSpan.FromMinutes(2)));
        Assert.Equal(Enumerable.Range(0, 50).Select(i => $"message {i}"), received); // lossless and in order
    }

    [Fact]
    public void Friend_GoesOffline_WhenItDisappears_AndReconnectsAfterRestart()
    {
        using var sim = new Simulation();
        var network = sim.AddBootstrapNodes(8);
        var alice = sim.AddNode();
        var bob = sim.AddNode();
        sim.Bootstrap(alice, network[0]);
        sim.Bootstrap(bob, network[1]);
        bob.FriendRequestReceived += (_, e) => bob.AddFriendNoRequest(e.PublicKey);
        Assert.True(sim.RunUntil(() => alice.ConnectionStatus == ToxConnection.Udp && bob.ConnectionStatus == ToxConnection.Udp,
            TimeSpan.FromMinutes(3)));
        uint bobOnAlice = alice.AddFriend(bob.Address, "hi");
        Assert.True(sim.RunUntil(() => alice.GetFriendConnectionStatus(bobOnAlice) == ToxConnection.Udp, TimeSpan.FromMinutes(3)));

        // Bob vanishes without saying goodbye (crash, network loss): Alice notices by timeout.
        var bobProfile = bob.GetSaveData();
        sim.Network.Remove(sim.EndpointOf(bob));
        Assert.True(sim.RunUntil(() => alice.GetFriendConnectionStatus(bobOnAlice) == ToxConnection.None, TimeSpan.FromMinutes(1)));

        // Bob comes back from his profile, with a new DHT key, at another address.
        var bob2 = sim.AddNode(bobProfile);
        Assert.Equal(bob.Address.ToString(), bob2.Address.ToString());
        Assert.Single(bob2.FriendList);
        sim.Bootstrap(bob2, network[2]);

        var received = new List<string>();
        bob2.FriendMessageReceived += (_, e) => received.Add(e.Message);
        Assert.True(sim.RunUntil(() => alice.GetFriendConnectionStatus(bobOnAlice) == ToxConnection.Udp
                                       && bob2.GetFriendConnectionStatus(bob2.FriendList[0]) == ToxConnection.Udp,
            TimeSpan.FromMinutes(3)));
        alice.SendMessage(bobOnAlice, "welcome back");
        Assert.True(sim.RunUntil(() => received.Contains("welcome back"), TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public void GracefulShutdown_IsSeenImmediately()
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, _) = sim.CreateFriends();
        sim.Remove(bob);
        Assert.True(sim.RunUntil(() => alice.GetFriendConnectionStatus(bobOnAlice) == ToxConnection.None, TimeSpan.FromSeconds(2)));
    }
}
