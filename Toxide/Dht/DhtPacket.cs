using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>
/// Envelope shared by every DHT packet:
///   [ kind 1 ][ sender DHT public key 32 ][ nonce 24 ][ encrypted payload: MAC 16 + data ]
/// The sender key travels in clear so the receiver can compute the shared key and decrypt
/// with no prior handshake. Because crypto_box authenticates the sender, a valid packet also
/// proves it was produced by the owner of that key.
/// </summary>
internal static class DhtPacket
{
    public const int SenderKeyOffset = 1;
    public const int NonceOffset = SenderKeyOffset + CryptoConstants.PublicKeySize; // 33
    public const int PayloadOffset = NonceOffset + CryptoConstants.NonceSize;       // 57
    public const int MinSize = PayloadOffset + CryptoConstants.MacSize;             // 73

    public static byte[] Create(ICryptoCore crypto, PacketKind kind, ReadOnlySpan<byte> senderPublicKey,
        ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> plain)
    {
        var nonce = Nonce.Random();
        var cipher = crypto.Encrypt(sharedKey, nonce, plain);

        var packet = new byte[PayloadOffset + cipher.Length];
        packet[0] = (byte)kind;
        senderPublicKey.CopyTo(packet.AsSpan(SenderKeyOffset));
        nonce.CopyTo(packet, NonceOffset);
        cipher.CopyTo(packet, PayloadOffset);
        return packet;
    }
}