namespace Toxide.Network;

/// <summary>Handles a packet; <paramref name="packet"/> includes the kind byte at index 0, as in toxcore.</summary>
public delegate void PacketHandler(IpPort source, ReadOnlySpan<byte> packet);

/// <summary>
/// Routes each packet to the component registered for its first byte.
/// It does no I/O: the transport fills a queue, the node's main loop drains it and calls
/// <see cref="Dispatch"/>. Keeping all protocol logic on one loop (like toxcore's tox_iterate)
/// means DHT, onion and net_crypto state never needs locks.
/// </summary>
public sealed class PacketDispatcher
{
    private readonly PacketHandler?[] _handlers = new PacketHandler?[256];

    public void Register(PacketKind kind, PacketHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (_handlers[(byte)kind] is not null)
            throw new InvalidOperationException($"A handler for {kind} is already registered.");
        _handlers[(byte)kind] = handler;
    }

    public void Unregister(PacketKind kind) => _handlers[(byte)kind] = null;

    /// <summary>Returns false if the packet is empty or no handler is registered for its kind.</summary>
    public bool Dispatch(IpPort source, ReadOnlySpan<byte> packet)
    {
        if (packet.IsEmpty)
            return false;

        var handler = _handlers[packet[0]];
        if (handler is null)
            return false;

        handler(source, packet);
        return true;
    }
}