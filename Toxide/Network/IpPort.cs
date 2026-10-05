using System.Net;
using System.Net.Sockets;

namespace Toxide.Network;

/// <summary>
/// IP address + port of a peer (toxcore's IP_Port).
/// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d), which a dual-stack socket reports for IPv4 peers,
/// are normalized to plain IPv4: the same peer must always compare equal, whichever socket saw it.
/// </summary>
public readonly record struct IpPort
{
    public IPAddress Address { get; }
    public ushort Port { get; }

    public IpPort(IPAddress address, ushort port)
    {
        ArgumentNullException.ThrowIfNull(address);
        Address = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        Port = port;
    }

    public bool IsIPv4 => Address.AddressFamily == AddressFamily.InterNetwork;

    public static IpPort FromEndPoint(IPEndPoint endPoint) => new(endPoint.Address, (ushort)endPoint.Port);

    public IPEndPoint ToEndPoint() => new(Address, Port);

    public override string ToString() => ToEndPoint().ToString();
}