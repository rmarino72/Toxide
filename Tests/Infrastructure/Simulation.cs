using System.Net;
using Toxide.Network;
using Toxide.State;

namespace Tests.Infrastructure;

/// <summary>Several Tox instances on a virtual network, all driven by one manual clock.</summary>
public sealed class Simulation : IDisposable
{
    public static readonly TimeSpan Step = TimeSpan.FromMilliseconds(50);

    private readonly List<Tox> _instances = [];
    private readonly Dictionary<Tox, IpPort> _endpoints = new();
    private int _nextHost = 1;

    public VirtualNetwork Network { get; } = new();
    public ManualTimeProvider Time { get; } = new();
    public IReadOnlyList<Tox> Instances => _instances;

    /// <summary>A new instance at 203.0.113.N:33445 (a public-looking, non-LAN address).</summary>
    public Tox AddNode(byte[]? saveData = null, string? passphrase = null)
    {
        var endpoint = new IpPort(IPAddress.Parse($"203.0.113.{_nextHost++}"), 33445);
        var socket = Network.AddHost(endpoint);
        var options = new ToxOptions
        {
            TimeProvider = Time,
            LocalDiscoveryEnabled = false,
            SaveDataType = saveData is null ? ToxSaveDataType.None : ToxSaveDataType.ToxSave,
            SaveData = saveData,
            SaveDataPassphrase = passphrase,
        };

        var save = saveData is null
            ? new SaveData { NoSpam = [1, 2, 3, 4] }
            : SaveData.Parse(passphrase is null ? saveData : ToxEncryptSave.Decrypt(saveData, passphrase));
        var tox = new Tox(options, save, socket, socket.Incoming, endpoint.Port);
        _instances.Add(tox);
        _endpoints[tox] = endpoint;
        return tox;
    }

    public IpPort EndpointOf(Tox tox) => _endpoints[tox];

    /// <summary>A small network: <paramref name="count"/> nodes, each bootstrapped from the first one.</summary>
    public List<Tox> AddBootstrapNodes(int count)
    {
        var nodes = new List<Tox>();
        for (int i = 0; i < count; i++)
            nodes.Add(AddNode());
        for (int i = 1; i < nodes.Count; i++)
            Bootstrap(nodes[i], nodes[0]);
        return nodes;
    }

    public void Bootstrap(Tox tox, Tox from) =>
        tox.Bootstrap(EndpointOf(from).ToEndPoint(), from.DhtId);

    /// <summary>Two clients on a fresh network of <paramref name="relays"/> nodes, friends and connected.</summary>
    public (Tox Alice, Tox Bob, uint BobOnAlice, uint AliceOnBob) CreateFriends(int relays = 8)
    {
        var network = AddBootstrapNodes(relays);
        var alice = AddNode();
        var bob = AddNode();
        Bootstrap(alice, network[0]);
        Bootstrap(bob, network[^1]);
        bob.FriendRequestReceived += (_, e) => bob.AddFriendNoRequest(e.PublicKey);

        if (!RunUntil(() => alice.ConnectionStatus == ToxConnection.Udp && bob.ConnectionStatus == ToxConnection.Udp,
                TimeSpan.FromMinutes(3)))
            throw new TimeoutException("clients did not come online");

        uint bobOnAlice = alice.AddFriend(bob.Address, "hi");
        if (!RunUntil(() => bob.FriendList.Count == 1
                            && alice.GetFriendConnectionStatus(bobOnAlice) == ToxConnection.Udp
                            && bob.GetFriendConnectionStatus(bob.FriendList[0]) == ToxConnection.Udp, TimeSpan.FromMinutes(3)))
            throw new TimeoutException("friends did not connect");

        return (alice, bob, bobOnAlice, bob.FriendList[0]);
    }

    public void RunFor(TimeSpan duration)
    {
        for (var t = TimeSpan.Zero; t < duration; t += Step)
            Tick();
    }

    /// <summary>Runs until <paramref name="condition"/> holds; returns false if it did not within <paramref name="timeout"/>.</summary>
    public bool RunUntil(Func<bool> condition, TimeSpan timeout)
    {
        for (var t = TimeSpan.Zero; t < timeout; t += Step)
        {
            if (condition())
                return true;
            Tick();
        }
        return condition();
    }

    private void Tick()
    {
        Time.Advance(Step);
        foreach (var tox in _instances.ToList())
            tox.Iterate();
    }

    public void Remove(Tox tox)
    {
        Network.Remove(EndpointOf(tox));
        _instances.Remove(tox);
        tox.Dispose();
    }

    public void Dispose()
    {
        foreach (var tox in _instances)
            tox.Dispose();
    }
}
