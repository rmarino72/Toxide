using System.Net;
using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Network;

namespace Tests.Infrastructure;

/// <summary>Bare DHT nodes (no onion, no messenger) on a virtual network, pumped by hand.</summary>
public sealed class DhtHarness : IDisposable
{
    public sealed record Peer(DhtNode Node, VirtualSocket Socket, PacketDispatcher Dispatcher)
    {
        public IpPort Endpoint => Socket.Endpoint;
    }

    private readonly List<Peer> _peers = [];

    public VirtualNetwork Network { get; } = new();
    public ManualTimeProvider Time { get; } = new();
    public ICryptoCore Crypto { get; } = new ManagedCryptoCore();
    public IReadOnlyList<Peer> Peers => _peers;

    public Peer Add(Action<Peer>? attach = null)
    {
        var socket = Network.AddHost(new IpPort(IPAddress.Parse($"198.51.100.{_peers.Count + 1}"), 33445));
        var node = new DhtNode(Crypto, socket, Time);
        var dispatcher = new PacketDispatcher();
        node.Attach(dispatcher);
        var peer = new Peer(node, socket, dispatcher);
        attach?.Invoke(peer);
        _peers.Add(peer);
        return peer;
    }

    /// <summary>Delivers queued packets until the network is quiet.</summary>
    public void Pump()
    {
        bool any;
        do
        {
            any = false;
            foreach (var peer in _peers)
            {
                while (peer.Socket.Incoming.TryRead(out var packet))
                {
                    peer.Dispatcher.Dispatch(packet.Source, packet.Data);
                    any = true;
                }
            }
        } while (any);
    }

    /// <summary>Advances time in 1 s steps, ticking every node and pumping packets.</summary>
    public void Run(TimeSpan duration)
    {
        for (var t = TimeSpan.Zero; t < duration; t += TimeSpan.FromSeconds(1))
        {
            Time.Advance(TimeSpan.FromSeconds(1));
            foreach (var peer in _peers)
                peer.Node.Tick();
            Pump();
        }
    }

    public void Dispose()
    {
        foreach (var peer in _peers)
            peer.Node.Dispose();
    }
}
