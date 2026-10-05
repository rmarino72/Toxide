using System.Net;
using System.Net.Sockets;

namespace Toxide.Network;

internal static class IpPortExtensions
{
    /// <summary>
    /// Loopback, private (RFC 1918), CGNAT (100.64/10), link-local and IPv6 link-local / ULA addresses.
    /// LAN peers get special treatment: they are trusted for LAN discovery and are never handed out
    /// to peers on the Internet, which could not reach them anyway.
    /// </summary>
    public static bool IsLan(this IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return true;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> b = stackalloc byte[4];
            address.TryWriteBytes(b, out _);
            return b[0] == 10
                   || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                   || (b[0] == 192 && b[1] == 168)
                   || (b[0] == 169 && b[1] == 254)
                   || (b[0] == 100 && (b[1] & 0xC0) == 64);
        }

        if (address.IsIPv4MappedToIPv6)
            return address.MapToIPv4().IsLan();

        return address.IsIPv6LinkLocal || address.IsIPv6UniqueLocal || address.IsIPv6Multicast;
    }

    public static bool IsLan(this IpPort endpoint) => endpoint.Address.IsLan();
}
