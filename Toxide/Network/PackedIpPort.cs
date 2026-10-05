using System.Buffers.Binary;
using System.Net;

namespace Toxide.Network;

/// <summary>
/// Fixed-size IP_Port encoding used inside onion packets and sendback data (toxcore's ipport_pack):
///   [ family 1 ][ address 16 ][ port 2, big-endian ]   = 19 bytes
/// IPv4 addresses occupy the first 4 address bytes, the rest is zero. A fixed size matters here:
/// the length of an onion layer must not reveal whether the next hop is IPv4 or IPv6.
/// </summary>
internal static class PackedIpPort
{
    public const int Size = 1 + 16 + 2;

    private const byte FamilyIPv4 = 2;
    private const byte FamilyIPv6 = 10;

    public static void Write(Span<byte> destination, IpPort endpoint)
    {
        destination[..Size].Clear();
        destination[0] = endpoint.IsIPv4 ? FamilyIPv4 : FamilyIPv6;
        endpoint.Address.TryWriteBytes(destination.Slice(1, 16), out _);
        BinaryPrimitives.WriteUInt16BigEndian(destination[17..], endpoint.Port);
    }

    public static byte[] ToBytes(IpPort endpoint)
    {
        var bytes = new byte[Size];
        Write(bytes, endpoint);
        return bytes;
    }

    /// <summary>Only UDP IPv4/IPv6 families are accepted: TCP relays are not implemented.</summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out IpPort endpoint)
    {
        endpoint = default;
        if (source.Length < Size)
            return false;

        IPAddress address;
        switch (source[0])
        {
            case FamilyIPv4:
                address = new IPAddress(source.Slice(1, 4));
                break;
            case FamilyIPv6:
                address = new IPAddress(source.Slice(1, 16));
                break;
            default:
                return false;
        }

        endpoint = new IpPort(address, BinaryPrimitives.ReadUInt16BigEndian(source[17..]));
        return true;
    }
}
