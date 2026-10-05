using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Toxide.Crypto;

namespace Toxide.Network;

/// <summary>
/// LAN discovery (packet kind 0x21): every 10 seconds we broadcast our DHT key on the local
/// networks. Tox nodes on the same LAN then bootstrap from each other with no Internet access,
/// and friends on the same LAN connect directly.
///   [ 0x21 ][ DHT public key 32 ]
/// The default port is always tried; a few other ports of the Tox range are added each round,
/// for clients that had to bind a different port.
/// </summary>
internal sealed class LanDiscovery
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(10);
    private const int PortsPerRound = 10;

    private readonly IPacketSender _sender;
    private readonly TimeProvider _time;
    private readonly List<IPAddress> _broadcastAddresses;
    private ushort _nextPort = UdpTransport.DefaultPortStart + 1;
    private DateTimeOffset _lastSent = DateTimeOffset.MinValue;

    public LanDiscovery(IPacketSender sender, TimeProvider time)
    {
        _sender = sender;
        _time = time;
        _broadcastAddresses = FindBroadcastAddresses();
    }

    public void Tick(byte[] dhtPublicKey)
    {
        var now = _time.GetUtcNow();
        if (now - _lastSent < Interval)
            return;
        _lastSent = now;

        var packet = new byte[1 + CryptoConstants.PublicKeySize];
        packet[0] = (byte)PacketKind.LanDiscovery;
        dhtPublicKey.CopyTo(packet, 1);

        ushort first = _nextPort;
        ushort last = (ushort)Math.Min(first + PortsPerRound, UdpTransport.DefaultPortEnd);

        foreach (var address in _broadcastAddresses)
        {
            _sender.Send(new IpPort(address, UdpTransport.DefaultPortStart), packet);
            for (ushort port = first; port < last; port++)
                _sender.Send(new IpPort(address, port), packet);
        }

        _nextPort = last != UdpTransport.DefaultPortEnd ? last : (ushort)(UdpTransport.DefaultPortStart + 1);
    }

    private static List<IPAddress> FindBroadcastAddresses()
    {
        var result = new List<IPAddress> { IPAddress.Broadcast };
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(unicast.Address))
                        continue;

                    var ip = unicast.Address.GetAddressBytes();
                    var mask = unicast.IPv4Mask.GetAddressBytes();
                    if (mask.Length != 4)
                        continue;

                    for (int i = 0; i < 4; i++)
                        ip[i] |= (byte)~mask[i];
                    var broadcast = new IPAddress(ip);
                    if (!result.Contains(broadcast))
                        result.Add(broadcast);
                }
            }
        }
        catch (NetworkInformationException)
        {
            // Interface enumeration is not available everywhere (sandboxes, some mobile platforms).
        }
        catch (PlatformNotSupportedException)
        {
        }

        // All-nodes link-local multicast: reaches IPv6-only peers on the same link.
        result.Add(IPAddress.Parse("ff02::1"));
        return result;
    }
}
