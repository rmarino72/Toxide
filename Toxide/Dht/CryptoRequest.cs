using System.Diagnostics.CodeAnalysis;
using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>
/// DHT "crypto request" (packet kind 0x20): a message for a node we may not be able to reach
/// directly. Any DHT node that has the receiver in its lists forwards it unchanged.
///   [ 0x20 ][ receiver DHT key 32 ][ sender DHT key 32 ][ nonce 24 ][ encrypted: request id 1 + data ]
/// Used for NAT ping (254) and for announcing our DHT key to a friend (156).
/// </summary>
internal static class CryptoRequest
{
    public const byte NatPing = 254;
    public const byte DhtPublicKey = 156;
    public const byte FriendRequest = 32;

    public const int ReceiverOffset = 1;
    public const int SenderOffset = ReceiverOffset + CryptoConstants.PublicKeySize;   // 33
    public const int NonceOffset = SenderOffset + CryptoConstants.PublicKeySize;      // 65
    public const int PayloadOffset = NonceOffset + CryptoConstants.NonceSize;         // 89

    /// <summary>toxcore's MAX_CRYPTO_REQUEST_SIZE.</summary>
    public const int MaxSize = 1024;

    public static byte[]? Create(ICryptoCore crypto, ReadOnlySpan<byte> senderPublicKey, ReadOnlySpan<byte> sharedKey,
        ReadOnlySpan<byte> receiverPublicKey, byte requestId, ReadOnlySpan<byte> data)
    {
        if (PayloadOffset + 1 + data.Length + CryptoConstants.MacSize > MaxSize)
            return null;

        var plain = new byte[1 + data.Length];
        plain[0] = requestId;
        data.CopyTo(plain.AsSpan(1));

        var nonce = Nonce.Random();
        var cipher = crypto.Encrypt(sharedKey, nonce, plain);

        var packet = new byte[PayloadOffset + cipher.Length];
        packet[0] = (byte)PacketKind.Crypto;
        receiverPublicKey.CopyTo(packet.AsSpan(ReceiverOffset));
        senderPublicKey.CopyTo(packet.AsSpan(SenderOffset));
        nonce.CopyTo(packet, NonceOffset);
        cipher.CopyTo(packet, PayloadOffset);
        return packet;
    }

    public static bool HasValidLength(ReadOnlySpan<byte> packet) =>
        packet.Length > PayloadOffset + CryptoConstants.MacSize && packet.Length <= MaxSize + CryptoConstants.MacSize;

    /// <summary>Decrypts a request addressed to us; <paramref name="data"/> excludes the request id.</summary>
    public static bool TryOpen(ICryptoCore crypto, ReadOnlySpan<byte> packet, ReadOnlySpan<byte> sharedKey,
        out byte requestId, [NotNullWhen(true)] out byte[]? data)
    {
        requestId = 0;
        data = null;
        var plain = crypto.Decrypt(sharedKey, packet.Slice(NonceOffset, CryptoConstants.NonceSize), packet[PayloadOffset..]);
        if (plain is null || plain.Length == 0)
            return false;

        requestId = plain[0];
        data = plain[1..];
        return true;
    }
}
