namespace Toxide.NetCrypto;

internal sealed class PacketData
{
    public PacketData(byte[] data) => Data = data;

    public byte[] Data { get; }

    /// <summary>Milliseconds timestamp of the last transmission; 0 = must be (re)sent.</summary>
    public long SentTime { get; set; }
}

/// <summary>
/// Ring buffer of lossless packets indexed by their 32-bit packet number (toxcore's Packets_Array).
/// Holds packet numbers in [<see cref="Start"/>, <see cref="End"/>); arithmetic wraps around like
/// the C unsigned integers it mirrors, so a connection may send more than 2^32 packets.
///  - Send side: packets wait here until the peer confirms it received everything before them.
///  - Receive side: out-of-order packets wait here until the gap before them is filled.
/// </summary>
internal sealed class PacketsArray
{
    public const int Capacity = 32768; // must be a power of 2

    private readonly PacketData?[] _buffer = new PacketData?[Capacity];

    /// <param name="start">First packet number (0 for every net_crypto session; other values only in tests).</param>
    public PacketsArray(uint start = 0)
    {
        Start = start;
        End = start;
    }

    public uint Start { get; private set; }
    public uint End { get; private set; }

    /// <summary>Number of slots in use, holes included.</summary>
    public uint Count => unchecked(End - Start);

    private static int Slot(uint number) => (int)(number % Capacity);

    /// <summary>Stores a received packet; false if out of window or already received.</summary>
    public bool TryAdd(uint number, PacketData data)
    {
        if (unchecked(number - Start) >= Capacity)
            return false;

        int slot = Slot(number);
        if (_buffer[slot] is not null)
            return false;

        _buffer[slot] = data;
        if (unchecked(number - Start) >= Count)
            End = unchecked(number + 1);
        return true;
    }

    /// <summary>-1 if <paramref name="number"/> is outside the array, 0 if that slot is empty, 1 if found.</summary>
    public int TryGet(uint number, out PacketData? data)
    {
        data = null;
        uint count = Count;
        if (unchecked(End - number) > count || unchecked(number - Start) >= count)
            return -1;

        data = _buffer[Slot(number)];
        return data is null ? 0 : 1;
    }

    /// <summary>Appends a packet to send; returns its number, or -1 if the buffer is full.</summary>
    public long Append(PacketData data)
    {
        if (Count >= Capacity)
            return -1;

        uint id = End;
        _buffer[Slot(id)] = data;
        End = unchecked(End + 1);
        return id;
    }

    /// <summary>Removes the first packet if it has arrived (in-order delivery).</summary>
    public bool TryTakeFirst(out PacketData? data)
    {
        data = null;
        if (End == Start)
            return false;

        int slot = Slot(Start);
        data = _buffer[slot];
        if (data is null)
            return false;

        _buffer[slot] = null;
        Start = unchecked(Start + 1);
        return true;
    }

    /// <summary>Drops every packet before <paramref name="number"/>: the peer has received them.</summary>
    public bool ClearUntil(uint number)
    {
        uint count = Count;
        if (unchecked(End - number) >= count || unchecked(number - Start) > count)
            return false;

        uint i;
        for (i = Start; i != number; i = unchecked(i + 1))
            _buffer[Slot(i)] = null;
        Start = i;
        return true;
    }

    public void Clear()
    {
        for (uint i = Start; i != End; i = unchecked(i + 1))
            _buffer[Slot(i)] = null;
        Start = End;
    }

    /// <summary>The peer told us the number of its next packet: extend the window so holes become visible.</summary>
    public bool SetEnd(uint number)
    {
        if (unchecked(number - Start) > Capacity || unchecked(number - End) > Capacity)
            return false;
        End = number;
        return true;
    }

    /// <summary>Removes the packet at <paramref name="number"/> (the peer confirmed it).</summary>
    public PacketData? Remove(uint number)
    {
        int slot = Slot(number);
        var data = _buffer[slot];
        _buffer[slot] = null;
        return data;
    }

    public PacketData? this[uint number] => _buffer[Slot(number)];
}
