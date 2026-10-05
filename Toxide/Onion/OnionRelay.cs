using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Network;

namespace Toxide.Onion;

/// <summary>
/// The relay side of the onion (toxcore onion.c): every DHT node forwards onion packets for others.
///
/// Requests (0x80 -> 0x81 -> 0x82): decrypt one layer with our DHT key, forward the inner layer to
/// the next hop, and append the encrypted address of whoever sent it to us (the "return" block).
/// Responses (0x8c -> 0x8d -> 0x8e): decrypt our return block to learn where to send the response.
///
/// The return blocks are encrypted with a symmetric key only we know, rotated every 2 hours, so
/// relays keep no per-request state and old paths eventually stop working.
/// </summary>
internal sealed class OnionRelay
{
    private static readonly TimeSpan KeyRefreshInterval = TimeSpan.FromHours(2);

    private readonly DhtNode _dht;
    private readonly ICryptoCore _crypto;
    private readonly IPacketSender _sender;
    private readonly TimeProvider _time;
    private byte[] _secretKey = CryptoExtensions.NewSymmetricKey();
    private DateTimeOffset _keyCreated;

    public OnionRelay(DhtNode dht, TimeProvider time)
    {
        _dht = dht;
        _crypto = dht.Crypto;
        _sender = dht.Sender;
        _time = time;
        _keyCreated = time.GetUtcNow();
    }

    public void Attach(PacketDispatcher dispatcher)
    {
        dispatcher.Register(PacketKind.OnionSendInitial, HandleSendInitial);
        dispatcher.Register(PacketKind.OnionSend1, HandleSend1);
        dispatcher.Register(PacketKind.OnionSend2, HandleSend2);
        dispatcher.Register(PacketKind.OnionReceive3, HandleReceive3);
        dispatcher.Register(PacketKind.OnionReceive2, HandleReceive2);
        dispatcher.Register(PacketKind.OnionReceive1, HandleReceive1);
    }

    private const int NonceOffset = 1;
    private const int KeyOffset = NonceOffset + CryptoConstants.NonceSize;           // 25
    private const int CipherOffset = KeyOffset + CryptoConstants.PublicKeySize;      // 57

    /// <summary>We are node 1: [0x80][nonce][sender key][layer 1].</summary>
    private void HandleSendInitial(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.Length > OnionPacket.MaxPacketSize || packet.Length <= 1 + OnionPacket.Send1)
            return;

        var plain = OpenLayer(packet, packet.Length - CipherOffset);
        if (plain is null || plain.Length <= PackedIpPort.Size + OnionPacket.SendBase * 2)
            return;

        // Return block 1: the client's address.
        var ret = SealReturn(PackedIpPort.ToBytes(source));
        Forward(PacketKind.OnionSend1, packet.Slice(NonceOffset, CryptoConstants.NonceSize), plain, ret);
    }

    /// <summary>We are node 2: [0x81][nonce][temp key][layer 2][return 1].</summary>
    private void HandleSend1(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.Length > OnionPacket.MaxPacketSize || packet.Length <= 1 + OnionPacket.Send2)
            return;

        var plain = OpenLayer(packet, packet.Length - CipherOffset - OnionPacket.Return1);
        if (plain is null || plain.Length <= PackedIpPort.Size)
            return;

        var ret = SealReturn(Concat(PackedIpPort.ToBytes(source), packet[^OnionPacket.Return1..]));
        Forward(PacketKind.OnionSend2, packet.Slice(NonceOffset, CryptoConstants.NonceSize), plain, ret);
    }

    /// <summary>We are node 3: [0x82][nonce][temp key][layer 3][return 2]; deliver the request.</summary>
    private void HandleSend2(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.Length > OnionPacket.MaxPacketSize || packet.Length <= 1 + OnionPacket.Send3)
            return;

        var plain = OpenLayer(packet, packet.Length - CipherOffset - OnionPacket.Return2);
        if (plain is null || plain.Length <= PackedIpPort.Size)
            return;

        // Only announce and data requests may leave the onion: it must not be usable to send
        // arbitrary packets to arbitrary hosts.
        var kind = (PacketKind)plain[PackedIpPort.Size];
        if (kind is not (PacketKind.AnnounceRequest or PacketKind.AnnounceRequestNew or PacketKind.OnionDataRequest))
            return;
        if (!PackedIpPort.TryRead(plain, out var destination) || !_sender.CanReach(destination))
            return;

        var ret = SealReturn(Concat(PackedIpPort.ToBytes(source), packet[^OnionPacket.Return2..]));
        _sender.Send(destination, Concat(plain.AsSpan(PackedIpPort.Size), ret));
    }

    /// <summary>A response for a request we delivered as node 3: [0x8c][return 3][data].</summary>
    private void HandleReceive3(IpPort source, ReadOnlySpan<byte> packet) =>
        ForwardResponse(packet, OnionPacket.Return3, OnionPacket.Return2, PacketKind.OnionReceive2);

    private void HandleReceive2(IpPort source, ReadOnlySpan<byte> packet) =>
        ForwardResponse(packet, OnionPacket.Return2, OnionPacket.Return1, PacketKind.OnionReceive1);

    /// <summary>We were node 1: hand the bare response to the client.</summary>
    private void HandleReceive1(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.Length > OnionPacket.MaxPacketSize || packet.Length <= 1 + OnionPacket.Return1)
            return;
        if (!IsResponseKind(packet[1 + OnionPacket.Return1]))
            return;

        var plain = OpenReturn(packet.Slice(1, OnionPacket.Return1));
        if (plain is null || plain.Length != PackedIpPort.Size || !PackedIpPort.TryRead(plain, out var destination))
            return;

        _sender.Send(destination, packet[(1 + OnionPacket.Return1)..]);
    }

    /// <summary>Opens our return block and sends [kind][inner return][data] to the previous hop.</summary>
    private void ForwardResponse(ReadOnlySpan<byte> packet, int ourReturnSize, int innerReturnSize, PacketKind next)
    {
        if (packet.Length > OnionPacket.MaxPacketSize || packet.Length <= 1 + ourReturnSize)
            return;
        if (!IsResponseKind(packet[1 + ourReturnSize]))
            return;

        var plain = OpenReturn(packet.Slice(1, ourReturnSize));
        if (plain is null || plain.Length != PackedIpPort.Size + innerReturnSize || !PackedIpPort.TryRead(plain, out var destination))
            return;

        var data = packet[(1 + ourReturnSize)..];
        var forwarded = new byte[1 + innerReturnSize + data.Length];
        forwarded[0] = (byte)next;
        plain.AsSpan(PackedIpPort.Size).CopyTo(forwarded.AsSpan(1));
        data.CopyTo(forwarded.AsSpan(1 + innerReturnSize));
        _sender.Send(destination, forwarded);
    }

    private static bool IsResponseKind(byte kind) =>
        (PacketKind)kind is PacketKind.AnnounceResponse or PacketKind.AnnounceResponseNew or PacketKind.OnionDataResponse;

    /// <summary>Decrypts the layer encrypted for our DHT key: [nonce][their key][cipher of <paramref name="cipherLength"/>].</summary>
    private byte[]? OpenLayer(ReadOnlySpan<byte> packet, int cipherLength)
    {
        if (cipherLength <= CryptoConstants.MacSize)
            return null;

        var senderKey = packet.Slice(KeyOffset, CryptoConstants.PublicKeySize).ToArray();
        if (!_dht.TryGetSharedKey(senderKey, out var sharedKey))
            return null;

        return _crypto.Decrypt(sharedKey, packet.Slice(NonceOffset, CryptoConstants.NonceSize),
            packet.Slice(CipherOffset, cipherLength));
    }

    /// <summary>[kind][nonce][inner layer after the next-hop address][return block] sent to the next hop.</summary>
    private void Forward(PacketKind kind, ReadOnlySpan<byte> nonce, byte[] plain, byte[] ret)
    {
        if (!PackedIpPort.TryRead(plain, out var nextHop) || !_sender.CanReach(nextHop))
            return;

        var inner = plain.AsSpan(PackedIpPort.Size);
        var packet = new byte[1 + CryptoConstants.NonceSize + inner.Length + ret.Length];
        packet[0] = (byte)kind;
        nonce.CopyTo(packet.AsSpan(1));
        inner.CopyTo(packet.AsSpan(1 + CryptoConstants.NonceSize));
        ret.CopyTo(packet.AsSpan(1 + CryptoConstants.NonceSize + inner.Length));
        _sender.Send(nextHop, packet);
    }

    private byte[] SealReturn(ReadOnlySpan<byte> contents)
    {
        RotateKey();
        var nonce = Nonce.Random();
        return Concat(nonce, _crypto.Encrypt(_secretKey, nonce, contents));
    }

    private byte[]? OpenReturn(ReadOnlySpan<byte> block)
    {
        RotateKey();
        return _crypto.Decrypt(_secretKey, block[..CryptoConstants.NonceSize], block[CryptoConstants.NonceSize..]);
    }

    private void RotateKey()
    {
        var now = _time.GetUtcNow();
        if (now - _keyCreated < KeyRefreshInterval)
            return;
        _secretKey = CryptoExtensions.NewSymmetricKey();
        _keyCreated = now;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
