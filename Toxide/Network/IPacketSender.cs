namespace Toxide.Network;

/// <summary>
/// Outgoing side of the transport, as seen by protocol components.
/// Components depend on this interface rather than on <see cref="UdpTransport"/>, so they can be
/// tested on an in-memory network with no sockets.
/// </summary>
public interface IPacketSender
{
    /// <summary>False if this host cannot send to that address family (e.g. IPv6 on an IPv4-only socket).</summary>
    bool CanReach(IpPort destination);

    /// <summary>Fire-and-forget send. True only means the datagram was handed to the OS.</summary>
    bool Send(IpPort destination, ReadOnlySpan<byte> packet);
}