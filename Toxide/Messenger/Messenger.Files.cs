using System.Buffers.Binary;

namespace Toxide.Messenger;

internal enum FileStatus
{
    None,
    NotAccepted,
    Transferring,

    /// <summary>All data queued; waiting for the friend to confirm the last packet.</summary>
    Finished,
}

[Flags]
internal enum FilePause
{
    None = 0,
    Us = 1,
    Other = 2,
}

internal sealed class FileTransfer
{
    public ulong Size { get; set; }
    public ulong Transferred { get; set; }

    /// <summary>Bytes already asked from the application through the chunk request callback.</summary>
    public ulong Requested { get; set; }

    public FileStatus Status { get; set; }
    public FilePause Paused { get; set; }
    public uint LastPacketNumber { get; set; }
    public byte[] Id { get; set; } = new byte[Messenger.FileIdLength];

    public static FileTransfer[] CreateSlots()
    {
        var slots = new FileTransfer[Messenger.MaxConcurrentFiles];
        for (int i = 0; i < slots.Length; i++)
            slots[i] = new FileTransfer();
        return slots;
    }
}

/// <summary>Result codes of the file functions, mirroring toxcore's negative return values.</summary>
internal enum FileResult
{
    Ok,
    FriendNotFound,
    FriendNotConnected,
    NotFound,
    BadControl,
    AlreadyPaused,
    Denied,
    NotPaused,
    SendFailed,
    NotReceiving,
    BadState,
    BadPosition,
    BadLength,
    NameTooLong,
    TooMany,
    SendQueue,
}

/// <summary>
/// File transfers (toxcore Messenger.c). Up to 256 files per direction and friend.
///   send request (80): [file number][kind u32 BE][size u64 BE][file id 32][file name]
///   control (81):      [1 = about a file we receive, 0 = a file we send][file number][control][data]
///   data (82):         [file number][up to 1371 bytes]
/// Data packets carry no offset: they are lossless and in order. A chunk shorter than the maximum
/// (or an empty one) marks the end of the file. Senders pull data from the application through
/// chunk requests, paced by congestion control.
/// File numbers seen by the application: n for files we send, (n + 1) &lt;&lt; 16 for files we receive.
/// </summary>
internal sealed partial class Messenger
{
    public const int MaxConcurrentFiles = 256;
    public const int FileIdLength = 32;
    public const int MaxFileNameLength = 255;
    public const int MaxFileDataSize = NetCrypto.NetCrypto.MaxDataSize - 2; // 1371

    public const byte PacketIdFileSendRequest = 80;
    public const byte PacketIdFileControl = 81;
    public const byte PacketIdFileData = 82;

    public const byte ControlAccept = 0;
    public const byte ControlPause = 1;
    public const byte ControlKill = 2;
    public const byte ControlSeek = 3;

    /// <summary>Slots kept free for messages: file data must not starve them.</summary>
    private const uint MinSlotsFree = NetCrypto.NetCrypto.MinQueueLength / 4;
    private const int MaxFileLoops = 128;

    public Action<uint, uint, uint, ulong, byte[]>? FileReceive { get; set; }
    public Action<uint, uint, byte>? FileControlReceived { get; set; }
    public Action<uint, uint, ulong, int>? FileChunkRequest { get; set; }
    public Action<uint, uint, ulong, byte[]>? FileChunkReceived { get; set; }

    private static bool TryDecodeFileNumber(uint fileNumber, out bool inbound, out int slot)
    {
        inbound = fileNumber >= 1 << 16;
        long temp = inbound ? (fileNumber >> 16) - 1 : fileNumber;
        slot = (int)temp;
        return temp is >= 0 and < MaxConcurrentFiles;
    }

    private FileResult GetTransfer(uint friendNumber, uint fileNumber, out Friend? friend, out FileTransfer? ft,
        out bool inbound, out int slot)
    {
        ft = null;
        slot = 0;
        inbound = false;
        friend = GetFriend(friendNumber);
        if (friend is null)
            return FileResult.FriendNotFound;
        if (friend.Status != FriendStatus.Online)
            return FileResult.FriendNotConnected;
        if (!TryDecodeFileNumber(fileNumber, out inbound, out slot))
            return FileResult.NotFound;

        ft = inbound ? friend.Receiving[slot] : friend.Sending[slot];
        return ft.Status == FileStatus.None ? FileResult.NotFound : FileResult.Ok;
    }

    public FileResult GetFileId(uint friendNumber, uint fileNumber, out byte[] id)
    {
        id = [];
        var result = GetTransfer(friendNumber, fileNumber, out _, out var ft, out _, out _);
        if (result == FileResult.Ok)
            id = (byte[])ft!.Id.Clone();
        return result;
    }

    /// <summary>Offers a file to a friend; returns the file number, or a negative <see cref="FileResult"/>.</summary>
    public FileResult NewFileSender(uint friendNumber, uint kind, ulong size, byte[] fileId, byte[] fileName, out uint fileNumber)
    {
        fileNumber = 0;
        if (GetFriend(friendNumber) is not { } friend)
            return FileResult.FriendNotFound;
        if (fileName.Length > MaxFileNameLength)
            return FileResult.NameTooLong;

        int slot = Array.FindIndex(friend.Sending, t => t.Status == FileStatus.None);
        if (slot < 0)
            return FileResult.TooMany;

        var packet = new byte[1 + sizeof(uint) + sizeof(ulong) + FileIdLength + fileName.Length];
        packet[0] = (byte)slot;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1), kind);
        BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(5), size);
        fileId.CopyTo(packet, 13);
        fileName.CopyTo(packet, 13 + FileIdLength);
        if (!Write(friend, PacketIdFileSendRequest, packet))
            return FileResult.FriendNotConnected;

        var ft = friend.Sending[slot];
        ft.Status = FileStatus.NotAccepted;
        ft.Size = size;
        ft.Transferred = 0;
        ft.Requested = 0;
        ft.Paused = FilePause.None;
        ft.Id = (byte[])fileId.Clone();
        fileNumber = (uint)slot;
        return FileResult.Ok;
    }

    private bool SendFileControlPacket(Friend friend, bool inbound, int slot, byte control, ReadOnlySpan<byte> data)
    {
        var packet = new byte[3 + data.Length];
        packet[0] = (byte)(inbound ? 1 : 0);
        packet[1] = (byte)slot;
        packet[2] = control;
        data.CopyTo(packet.AsSpan(3));
        return Write(friend, PacketIdFileControl, packet);
    }

    /// <summary>Accept/resume, pause or cancel a transfer (toxcore's file_control).</summary>
    public FileResult FileControl(uint friendNumber, uint fileNumber, byte control)
    {
        var result = GetTransfer(friendNumber, fileNumber, out var friend, out var ft, out bool inbound, out int slot);
        if (result != FileResult.Ok)
            return result;
        if (control > ControlKill)
            return FileResult.BadControl;
        if (control == ControlPause && ((ft!.Paused & FilePause.Us) != 0 || ft.Status != FileStatus.Transferring))
            return FileResult.AlreadyPaused;

        if (control == ControlAccept)
        {
            if (ft!.Status == FileStatus.Transferring)
            {
                if ((ft.Paused & FilePause.Us) == 0)
                    return (ft.Paused & FilePause.Other) != 0 ? FileResult.Denied : FileResult.NotPaused;
            }
            else
            {
                if (ft.Status != FileStatus.NotAccepted)
                    return FileResult.NotPaused;
                if (!inbound)
                    return FileResult.Denied; // only the receiver accepts
            }
        }

        if (!SendFileControlPacket(friend!, inbound, slot, control, default))
            return FileResult.SendFailed;

        switch (control)
        {
            case ControlKill:
                if (!inbound && ft!.Status is FileStatus.Transferring or FileStatus.Finished)
                    friend!.SendingFiles--;
                ft!.Status = FileStatus.None;
                break;
            case ControlPause:
                ft!.Paused |= FilePause.Us;
                break;
            case ControlAccept:
                ft!.Status = FileStatus.Transferring;
                ft.Paused &= ~FilePause.Us;
                break;
        }
        return FileResult.Ok;
    }

    /// <summary>Before accepting an incoming file: resume it from <paramref name="position"/>.</summary>
    public FileResult FileSeek(uint friendNumber, uint fileNumber, ulong position)
    {
        var result = GetTransfer(friendNumber, fileNumber, out var friend, out var ft, out bool inbound, out int slot);
        if (result != FileResult.Ok)
            return result;
        if (!inbound)
            return FileResult.NotReceiving;
        if (ft!.Status != FileStatus.NotAccepted)
            return FileResult.BadState;
        if (position >= ft.Size)
            return FileResult.BadPosition;

        Span<byte> data = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(data, position);
        if (!SendFileControlPacket(friend!, true, slot, ControlSeek, data))
            return FileResult.SendFailed;

        ft.Transferred = position;
        return FileResult.Ok;
    }

    /// <summary>Sends the chunk the application was asked for (toxcore's send_file_data).</summary>
    public FileResult SendFileData(uint friendNumber, uint fileNumber, ulong position, ReadOnlySpan<byte> data)
    {
        if (GetFriend(friendNumber) is not { } friend)
            return FileResult.FriendNotFound;
        if (friend.Status != FriendStatus.Online)
            return FileResult.FriendNotConnected;
        if (fileNumber >= MaxConcurrentFiles)
            return FileResult.NotFound;

        var ft = friend.Sending[fileNumber];
        if (ft.Status != FileStatus.Transferring)
            return FileResult.BadState;
        if (data.Length > MaxFileDataSize || ft.Size - ft.Transferred < (ulong)data.Length)
            return FileResult.BadLength;
        if (ft.Size != ulong.MaxValue && data.Length != MaxFileDataSize && ft.Transferred + (ulong)data.Length != ft.Size)
            return FileResult.BadLength;
        if (position != ft.Transferred || (ft.Requested <= position && ft.Size != 0))
            return FileResult.BadPosition;

        if (_friendConnections.FreeSendQueueSlots(friend.FriendConnectionId) < MinSlotsFree)
            return FileResult.SendQueue;

        var packet = new byte[2 + data.Length];
        packet[0] = PacketIdFileData;
        packet[1] = (byte)fileNumber;
        data.CopyTo(packet.AsSpan(2));
        long packetNumber = _friendConnections.WriteLossless(friend.FriendConnectionId, packet, true);
        if (packetNumber == -1)
            return FileResult.SendQueue;

        ft.Transferred += (ulong)data.Length;
        if (data.Length != MaxFileDataSize || ft.Size == ft.Transferred)
        {
            ft.Status = FileStatus.Finished;
            ft.LastPacketNumber = (uint)packetNumber;
        }
        return FileResult.Ok;
    }

    /// <summary>Asks the application for the next chunks of every active outgoing file.</summary>
    private void RequestFileChunks(uint number, Friend friend)
    {
        if (friend.SendingFiles == 0)
            return;

        uint free = _friendConnections.FreeSendQueueSlots(friend.FriendConnectionId);
        free = free > MinSlotsFree ? free - MinSlotsFree : 0;

        for (int loop = 0; loop < MaxFileLoops; loop++)
        {
            if (!RequestFileChunksOnce(number, friend, ref free) || free == 0)
                break;
        }
    }

    private bool RequestFileChunksOnce(uint number, Friend friend, ref uint free)
    {
        for (int i = 0; i < MaxConcurrentFiles; i++)
        {
            if (friend.SendingFiles == 0 || free == 0)
                return false;

            var ft = friend.Sending[i];
            if (ft.Status is FileStatus.None or FileStatus.NotAccepted)
                continue;
            if (_friendConnections.MaxSpeedReached(friend.FriendConnectionId))
                return false;

            if (ft.Status == FileStatus.Finished
                && _friendConnections.IsPacketReceived(friend.FriendConnectionId, ft.LastPacketNumber))
            {
                // The friend has everything: a zero-length request tells the application we are done.
                FileChunkRequest?.Invoke(number, (uint)i, ft.Transferred, 0);
                ft.Status = FileStatus.None;
                friend.SendingFiles--;
            }
            else if (ft.Status == FileStatus.Transferring && ft.Paused == FilePause.None)
            {
                if (ft.Size == 0)
                {
                    SendFileData(number, (uint)i, 0, default);
                    continue;
                }
                if (ft.Size == ft.Requested)
                    continue;

                int length = (int)Math.Min(ft.Size - ft.Requested, MaxFileDataSize);
                ulong position = ft.Requested;
                ft.Requested += (ulong)length;
                FileChunkRequest?.Invoke(number, (uint)i, position, length);
                free--;
            }
        }
        return true;
    }

    private static void BreakFiles(Friend friend)
    {
        foreach (var ft in friend.Sending)
            ft.Status = FileStatus.None;
        foreach (var ft in friend.Receiving)
            ft.Status = FileStatus.None;
        friend.SendingFiles = 0;
    }

    private void HandleFileSendRequest(uint number, Friend friend, byte[] data)
    {
        const int headLength = 1 + sizeof(uint) + sizeof(ulong) + FileIdLength;
        if (data.Length < headLength || data.Length - headLength > MaxFileNameLength)
            return;

        var ft = friend.Receiving[data[0]];
        if (ft.Status != FileStatus.None)
            return;

        uint kind = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(1));
        ft.Status = FileStatus.NotAccepted;
        ft.Size = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(5));
        ft.Transferred = 0;
        ft.Paused = FilePause.None;
        ft.Id = data[13..(13 + FileIdLength)];

        FileReceive?.Invoke(number, ((uint)data[0] + 1) << 16, kind, ft.Size, data[headLength..]);
    }

    private void HandleFileControl(uint number, Friend friend, byte[] data)
    {
        if (data.Length < 3)
            return;

        // The peer's "inbound" (a file it receives) is a file we send.
        bool outbound = data[0] == 1;
        byte slot = data[1];
        byte control = data[2];
        var ft = outbound ? friend.Sending[slot] : friend.Receiving[slot];
        uint fileNumber = outbound ? slot : ((uint)slot + 1) << 16;

        if (ft.Status == FileStatus.None)
        {
            // Unknown transfer: tell the peer to drop it.
            SendFileControlPacket(friend, !outbound, slot, ControlKill, default);
            return;
        }

        switch (control)
        {
            case ControlAccept:
                if (outbound && ft.Status == FileStatus.NotAccepted)
                {
                    ft.Status = FileStatus.Transferring;
                    friend.SendingFiles++;
                }
                else if ((ft.Paused & FilePause.Other) != 0)
                {
                    ft.Paused &= ~FilePause.Other;
                }
                else
                {
                    return;
                }
                FileControlReceived?.Invoke(number, fileNumber, control);
                break;

            case ControlPause:
                if ((ft.Paused & FilePause.Other) != 0 || ft.Status != FileStatus.Transferring)
                    return;
                ft.Paused |= FilePause.Other;
                FileControlReceived?.Invoke(number, fileNumber, control);
                break;

            case ControlKill:
                FileControlReceived?.Invoke(number, fileNumber, control);
                if (outbound && ft.Status is FileStatus.Transferring or FileStatus.Finished)
                    friend.SendingFiles--;
                ft.Status = FileStatus.None;
                break;

            case ControlSeek:
                // Only the receiver may seek, and only before accepting.
                if (data.Length != 3 + sizeof(ulong) || ft.Status != FileStatus.NotAccepted || !outbound)
                    return;
                ulong position = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(3));
                if (position >= ft.Size)
                    return;
                ft.Requested = position;
                ft.Transferred = position;
                break;
        }
    }

    private void HandleFileData(uint number, Friend friend, byte[] data)
    {
        if (data.Length < 1)
            return;

        var ft = friend.Receiving[data[0]];
        if (ft.Status != FileStatus.Transferring)
            return;

        uint fileNumber = ((uint)data[0] + 1) << 16;
        ulong position = ft.Transferred;
        int length = data.Length - 1;
        if (ft.Transferred + (ulong)length > ft.Size)
            length = (int)(ft.Size - ft.Transferred); // never pass more than the announced size

        FileChunkReceived?.Invoke(number, fileNumber, position, data.AsSpan(1, length).ToArray());
        ft.Transferred += (ulong)length;

        if (length > 0 && (ft.Transferred >= ft.Size || length != MaxFileDataSize))
        {
            // Full file received: an empty chunk tells the application.
            length = 0;
            FileChunkReceived?.Invoke(number, fileNumber, ft.Transferred, []);
        }

        if (length == 0)
            ft.Status = FileStatus.None;
    }
}
