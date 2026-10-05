using System.Net;
using System.Threading.Channels;
using Toxide.Network;

namespace Tests.Infrastructure;

/// <summary>
/// An in-memory UDP network: every host gets an address and an incoming queue; a send puts the
/// datagram straight into the destination's queue (or drops it, if a loss rate is set).
/// </summary>
public sealed class VirtualNetwork
{
    private readonly Dictionary<IpPort, VirtualSocket> _hosts = new();
    private readonly Random _random = new(1234);

    /// <summary>Probability of losing each datagram.</summary>
    public double LossRate { get; set; }

    public long Delivered { get; private set; }

    public VirtualSocket AddHost(IpPort endpoint)
    {
        var socket = new VirtualSocket(this, endpoint);
        _hosts.Add(endpoint, socket);
        return socket;
    }

    public void Remove(IpPort endpoint) => _hosts.Remove(endpoint);

    internal bool Deliver(IpPort source, IpPort destination, ReadOnlySpan<byte> packet)
    {
        if (!_hosts.TryGetValue(destination, out var target))
            return true; // like UDP: sending to nobody "succeeds"
        if (LossRate > 0 && _random.NextDouble() < LossRate)
            return true;

        Delivered++;
        target.Queue.Writer.TryWrite(new ReceivedPacket(source, packet.ToArray()));
        return true;
    }
}

public sealed class VirtualSocket : IPacketSender
{
    private readonly VirtualNetwork _network;

    internal VirtualSocket(VirtualNetwork network, IpPort endpoint)
    {
        _network = network;
        Endpoint = endpoint;
    }

    public IpPort Endpoint { get; }

    internal Channel<ReceivedPacket> Queue { get; } = Channel.CreateUnbounded<ReceivedPacket>();

    public ChannelReader<ReceivedPacket> Incoming => Queue.Reader;

    public bool CanReach(IpPort destination) => destination.IsIPv4;

    public bool Send(IpPort destination, ReadOnlySpan<byte> packet) => _network.Deliver(Endpoint, destination, packet);
}
