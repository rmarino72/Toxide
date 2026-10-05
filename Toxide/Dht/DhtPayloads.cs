using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>
/// Plaintext payloads carried inside <see cref="DhtPacket"/>.
///
///   Ping request / response (kinds 0x00 / 0x01):
///     [ ping type 1: 0x00 request, 0x01 response ][ ping ID 8 ]
///
///   Nodes request (kind 0x02): "give me the nodes you know closest to this key"
///     [ requested public key 32 ][ request ID 8 ]
///
///   Nodes response (kind 0x04):
///     [ node count 1 (max 4) ][ nodes, packed format ][ request ID 8 ]
///
/// IDs are opaque random values echoed back by the peer; they are written big-endian.
/// </summary>
internal static class DhtPayloads
{
    public const byte PingRequestType = 0x00;
    public const byte PingResponseType = 0x01;
    public const int PingSize = 1 + sizeof(ulong);
    public const int NodesRequestSize = CryptoConstants.PublicKeySize + sizeof(ulong);
    public const int MaxNodes = 4;

    public static byte[] WritePing(byte type, ulong id)
    {
        var payload = new byte[PingSize];
        payload[0] = type;
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(1), id);
        return payload;
    }

    public static bool TryReadPing(ReadOnlySpan<byte> payload, byte expectedType, out ulong id)
    {
        id = 0;
        if (payload.Length != PingSize || payload[0] != expectedType)
            return false;

        id = BinaryPrimitives.ReadUInt64BigEndian(payload[1..]);
        return true;
    }

    public static byte[] WriteNodesRequest(ReadOnlySpan<byte> targetKey, ulong id)
    {
        var payload = new byte[NodesRequestSize];
        targetKey.CopyTo(payload);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(CryptoConstants.PublicKeySize), id);
        return payload;
    }

    public static bool TryReadNodesRequest(ReadOnlySpan<byte> payload, [NotNullWhen(true)] out byte[]? targetKey,
        out ulong id)
    {
        targetKey = null;
        id = 0;
        if (payload.Length != NodesRequestSize)
            return false;

        targetKey = payload[..CryptoConstants.PublicKeySize].ToArray();
        id = BinaryPrimitives.ReadUInt64BigEndian(payload[CryptoConstants.PublicKeySize..]);
        return true;
    }

    public static byte[] WriteNodesResponse(IReadOnlyList<NodeInfo> nodes, ulong id)
    {
        if (nodes.Count > MaxNodes)
            throw new ArgumentException($"At most {MaxNodes} nodes per response.", nameof(nodes));

        var payload = new byte[1 + nodes.Sum(n => n.PackedSize) + sizeof(ulong)];
        payload[0] = (byte)nodes.Count;
        int written = NodeInfo.PackMany(nodes, payload.AsSpan(1));
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(1 + written), id);
        return payload;
    }

    public static bool TryReadNodesResponse(ReadOnlySpan<byte> payload, [NotNullWhen(true)] out List<NodeInfo>? nodes,
        out ulong id)
    {
        nodes = null;
        id = 0;
        if (payload.Length < 1 + sizeof(ulong))
            return false;

        int count = payload[0];
        if (count > MaxNodes)
            return false;

        var body = payload[1..^sizeof(ulong)];
        if (!NodeInfo.TryUnpackMany(body, count, out var parsed, out int read) || read != body.Length)
            return false; // trailing garbage or truncated nodes

        nodes = parsed;
        id = BinaryPrimitives.ReadUInt64BigEndian(payload[^sizeof(ulong)..]);
        return true;
    }
}