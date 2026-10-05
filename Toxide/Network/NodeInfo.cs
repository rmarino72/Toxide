using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using Toxide.Crypto;

namespace Toxide.Network;

/// <summary>
/// A node as exchanged on the wire ("packed node format"):
///   [ type 1 ][ IP address 4 or 16 ][ port 2, big-endian ][ public key 32 ]
/// Type byte: 2 = UDP/IPv4, 10 = UDP/IPv6, 130 = TCP/IPv4, 138 = TCP/IPv6.
/// (2 and 10 are the Linux AF_INET / AF_INET6 values; bit 7 marks TCP.)
/// The public key is the node's DHT key, not its long-term identity.
/// </summary>
public sealed class NodeInfo
{
    public const int PackedSizeIPv4 = 1 + 4 + 2 + CryptoConstants.PublicKeySize;  // 39
    public const int PackedSizeIPv6 = 1 + 16 + 2 + CryptoConstants.PublicKeySize; // 51

    private const byte FamilyIPv4 = 2;
    private const byte FamilyIPv6 = 10;
    private const byte TcpFlag = 0x80;

    public TransportProtocol Protocol { get; }
    public IpPort Endpoint { get; }
    public byte[] PublicKey { get; }

    public NodeInfo(TransportProtocol protocol, IpPort endpoint, byte[] publicKey)
    {
        if (publicKey.Length != CryptoConstants.PublicKeySize)
            throw new ArgumentException("Invalid public key length.", nameof(publicKey));

        Protocol = protocol;
        Endpoint = endpoint;
        PublicKey = publicKey;
    }

    public int PackedSize => Endpoint.IsIPv4 ? PackedSizeIPv4 : PackedSizeIPv6;

    /// <summary>Writes the node in packed format and returns the number of bytes written.</summary>
    public int Pack(Span<byte> destination)
    {
        if (destination.Length < PackedSize)
            throw new ArgumentException("Destination buffer too small.", nameof(destination));

        int addressLength = Endpoint.IsIPv4 ? 4 : 16;

        byte type = Endpoint.IsIPv4 ? FamilyIPv4 : FamilyIPv6;
        if (Protocol == TransportProtocol.Tcp)
            type |= TcpFlag;

        destination[0] = type;
        Endpoint.Address.TryWriteBytes(destination.Slice(1, addressLength), out _); // network byte order
        BinaryPrimitives.WriteUInt16BigEndian(destination[(1 + addressLength)..], Endpoint.Port);
        PublicKey.CopyTo(destination[(3 + addressLength)..]);

        return PackedSize;
    }

    /// <summary>Reads one node; fails on unknown type or truncated input (data from the network is untrusted).</summary>
    public static bool TryUnpack(ReadOnlySpan<byte> source, [NotNullWhen(true)] out NodeInfo? node, out int bytesRead)
    {
        node = null;
        bytesRead = 0;
        if (source.IsEmpty)
            return false;

        byte type = source[0];
        var protocol = (type & TcpFlag) != 0 ? TransportProtocol.Tcp : TransportProtocol.Udp;
        int addressLength = (type & ~TcpFlag) switch
        {
            FamilyIPv4 => 4,
            FamilyIPv6 => 16,
            _ => 0,
        };
        if (addressLength == 0)
            return false;

        int size = 1 + addressLength + 2 + CryptoConstants.PublicKeySize;
        if (source.Length < size)
            return false;

        var address = new IPAddress(source.Slice(1, addressLength));
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(source[(1 + addressLength)..]);
        var publicKey = source.Slice(3 + addressLength, CryptoConstants.PublicKeySize).ToArray();

        node = new NodeInfo(protocol, new IpPort(address, port), publicKey);
        bytesRead = size;
        return true;
    }

    /// <summary>Packs several nodes back to back (e.g. the up to 4 nodes of a Nodes response).</summary>
    public static int PackMany(IReadOnlyList<NodeInfo> nodes, Span<byte> destination)
    {
        int offset = 0;
        foreach (var node in nodes)
            offset += node.Pack(destination[offset..]);
        return offset;
    }

    /// <summary>Unpacks exactly <paramref name="count"/> consecutive nodes.</summary>
    public static bool TryUnpackMany(ReadOnlySpan<byte> source, int count,
        [NotNullWhen(true)] out List<NodeInfo>? nodes, out int bytesRead)
    {
        nodes = null;
        bytesRead = 0;
        var result = new List<NodeInfo>(count);
        int offset = 0;

        for (int i = 0; i < count; i++)
        {
            if (!TryUnpack(source[offset..], out var node, out int read))
                return false;
            result.Add(node);
            offset += read;
        }

        nodes = result;
        bytesRead = offset;
        return true;
    }

    public override string ToString() => $"{Protocol} {Endpoint} {Convert.ToHexString(PublicKey)}";
}