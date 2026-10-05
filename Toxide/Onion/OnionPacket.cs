using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Onion;

/// <summary>
/// Sizes of the onion packet layers (toxcore onion.h).
///
/// A request travels  client -> node 1 -> node 2 -> node 3 -> destination.
/// Each node peels one encryption layer and learns only the next hop. On the way, each node appends
/// a "return" block: the previous hop's address encrypted with a key only that node knows, so the
/// response can travel back along the same path without any node keeping state.
/// </summary>
internal static class OnionPacket
{
    public const int MaxPacketSize = 1400;
    public const int PathLength = 3;

    public const int Return1 = CryptoConstants.NonceSize + PackedIpPort.Size + CryptoConstants.MacSize;   // 59
    public const int Return2 = CryptoConstants.NonceSize + PackedIpPort.Size + CryptoConstants.MacSize + Return1; // 118
    public const int Return3 = CryptoConstants.NonceSize + PackedIpPort.Size + CryptoConstants.MacSize + Return2; // 177

    public const int SendBase = CryptoConstants.PublicKeySize + PackedIpPort.Size + CryptoConstants.MacSize; // 67
    public const int Send3 = CryptoConstants.NonceSize + SendBase + Return2;     // 209
    public const int Send2 = CryptoConstants.NonceSize + SendBase * 2 + Return1; // 217
    public const int Send1 = CryptoConstants.NonceSize + SendBase * 3;           // 225

    public const int MaxDataSize = MaxPacketSize - (Send1 + 1);              // 1174
    public const int MaxResponseDataSize = MaxPacketSize - (1 + Return3);    // 1222

    /// <summary>
    /// Builds the 0x80 packet carrying <paramref name="data"/> to <paramref name="destination"/> along
    /// <paramref name="path"/>. All three layers share one random nonce; each uses a different key.
    ///   layer 3 (for node 3): [ destination ][ data ]
    ///   layer 2 (for node 2): [ node 3 address ][ temp key 3 ][ layer 3 encrypted ]
    ///   layer 1 (for node 1): [ node 2 address ][ temp key 2 ][ layer 2 encrypted ]
    ///   packet:  [ 0x80 ][ nonce ][ our DHT key ][ layer 1 encrypted ]
    /// </summary>
    public static byte[]? Create(ICryptoCore crypto, OnionPath path, IpPort destination, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || 1 + data.Length + Send1 > MaxPacketSize)
            return null;

        var nonce = Nonce.Random();

        var step1 = new byte[PackedIpPort.Size + data.Length];
        PackedIpPort.Write(step1, destination);
        data.CopyTo(step1.AsSpan(PackedIpPort.Size));

        var step2 = Wrap(crypto, path.Endpoint3, path.PublicKey3, path.SharedKey3, nonce, step1);
        var step3 = Wrap(crypto, path.Endpoint2, path.PublicKey2, path.SharedKey2, nonce, step2);
        var layer1 = crypto.Encrypt(path.SharedKey1, nonce, step3);

        var packet = new byte[1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize + layer1.Length];
        packet[0] = (byte)PacketKind.OnionSendInitial;
        nonce.CopyTo(packet, 1);
        path.PublicKey1.CopyTo(packet, 1 + CryptoConstants.NonceSize);
        layer1.CopyTo(packet, 1 + CryptoConstants.NonceSize + CryptoConstants.PublicKeySize);
        return packet;
    }

    /// <summary>[ next hop ][ our temporary key for that hop ][ inner layer encrypted for it ].</summary>
    private static byte[] Wrap(ICryptoCore crypto, IpPort nextHop, byte[] publicKey, byte[] sharedKey, byte[] nonce,
        byte[] inner)
    {
        var encrypted = crypto.Encrypt(sharedKey, nonce, inner);
        var layer = new byte[PackedIpPort.Size + CryptoConstants.PublicKeySize + encrypted.Length];
        PackedIpPort.Write(layer, nextHop);
        publicKey.CopyTo(layer, PackedIpPort.Size);
        encrypted.CopyTo(layer, PackedIpPort.Size + CryptoConstants.PublicKeySize);
        return layer;
    }
}
