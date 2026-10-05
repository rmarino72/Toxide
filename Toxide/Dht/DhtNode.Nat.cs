using System.Buffers.Binary;
using System.Net;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>
/// NAT hole punching (toxcore's do_nat).
///
/// When several nodes report our friend's address but the friend does not answer us directly,
/// both sides are probably behind NATs. Both peers then exchange "NAT pings" through the DHT
/// (crypto request 254, relayed by the nodes that know the friend). Once each side knows the other
/// is trying, both send pings to the friend's public IP at the reported ports, plus guesses around
/// them: the outgoing packets open mappings in our NAT through which the friend's packets can enter.
/// </summary>
public sealed partial class DhtNode
{
    private const byte NatPingRequest = 0;
    private const byte NatPingResponse = 1;
    private const int MaxPunchingPorts = 48;
    private const int MaxNormalPunchingTries = 5;
    private const int MinReportsToPunch = DhtFriend.MaxCloseNodes / 2;
    private static readonly TimeSpan PunchInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan PunchResetTime = TimeSpan.FromSeconds(40);

    private void TickNat(DateTimeOffset now)
    {
        foreach (var friend in _friends.Values)
        {
            if (friend.HasDirectConnection(now, BadNodeTimeout))
                continue;

            var reports = friend.FreshReturned(now, BadNodeTimeout);
            if (reports.Count < MinReportsToPunch)
                continue; // friend offline, or not enough evidence of where it is

            if (friend.NatPingSent + PunchInterval < now)
            {
                SendNatPing(friend.PublicKey, friend.NatPingId, NatPingRequest);
                friend.NatPingSent = now;
            }

            if (!friend.HolePunching || friend.PunchingTime + PunchInterval >= now
                                     || friend.NatPingReceived + PunchInterval * 2 < now)
                continue;

            var ip = CommonAddress(reports, MinReportsToPunch);
            if (ip is null)
                continue;

            if (friend.PunchingTime + PunchResetTime < now)
            {
                friend.PunchingTries = 0;
                friend.PunchingIndex = 0;
                friend.PunchingIndex2 = 0;
            }

            var ports = reports.Where(r => r.FriendEndpoint.Address.Equals(ip)).Select(r => r.FriendEndpoint.Port).ToList();
            PunchHoles(friend, ip, ports);
            friend.PunchingTime = now;
            friend.HolePunching = false;
        }
    }

    private void SendNatPing(byte[] friendKey, ulong pingId, byte type)
    {
        Span<byte> data = stackalloc byte[1 + sizeof(ulong)];
        data[0] = type;
        BinaryPrimitives.WriteUInt64LittleEndian(data[1..], pingId);

        var packet = CreateCryptoRequest(friendKey, CryptoRequest.NatPing, data);
        if (packet is null)
            return;

        // A request goes through every node that knows the friend; a reply through one of them.
        if (type == NatPingRequest)
            RouteToFriend(friendKey, packet);
        else
            RouteOneToFriend(friendKey, packet);
    }

    private void HandleNatPing(IpPort source, byte[] senderKey, byte[] data)
    {
        if (data.Length != 1 + sizeof(ulong) || !_friends.TryGetValue(senderKey, out var friend))
            return;

        ulong pingId = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(1));
        if (data[0] == NatPingRequest)
        {
            SendNatPing(senderKey, pingId, NatPingResponse);
            friend.NatPingReceived = Now;
        }
        else if (data[0] == NatPingResponse && pingId == friend.NatPingId)
        {
            friend.NatPingId = RandomUInt64();
            friend.HolePunching = true;
        }
    }

    /// <summary>The address reported at least <paramref name="minCount"/> times, if any.</summary>
    private static IPAddress? CommonAddress(List<ReturnedAddress> reports, int minCount) =>
        reports.GroupBy(r => r.FriendEndpoint.Address)
            .FirstOrDefault(g => g.Count() >= minCount)?.Key;

    private void PunchHoles(DhtFriend friend, IPAddress ip, List<ushort> ports)
    {
        if (ports.Count == 0 || ports.Count > DhtFriend.MaxCloseNodes)
            return;

        if (ports.TrueForAll(p => p == ports[0]))
        {
            // Every node sees the same port: the NAT keeps ports stable, one ping is enough.
            Punch(friend, ip, ports[0]);
        }
        else
        {
            // Symmetric-ish NAT: try ports around the reported ones, alternating above and below.
            uint i;
            for (i = 0; i < MaxPunchingPorts; i++)
            {
                uint it = i + friend.PunchingIndex;
                int sign = it % 2 != 0 ? -1 : 1;
                int delta = sign * (int)(it / (2 * (uint)ports.Count));
                int index = (int)(it / 2 % (uint)ports.Count);
                Punch(friend, ip, unchecked((ushort)(ports[index] + delta)));
            }
            friend.PunchingIndex += i;
        }

        if (friend.PunchingTries > MaxNormalPunchingTries)
        {
            // Last resort: sweep ports upwards from 1024.
            uint i;
            for (i = 0; i < MaxPunchingPorts; i++)
                Punch(friend, ip, unchecked((ushort)(1024 + i + friend.PunchingIndex2)));
            friend.PunchingIndex2 += i - MaxPunchingPorts / 2;
        }

        friend.PunchingTries++;
    }

    private void Punch(DhtFriend friend, IPAddress ip, ushort port) =>
        SendPing(new NodeInfo(TransportProtocol.Udp, new IpPort(ip, port), friend.PublicKey));
}
