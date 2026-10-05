namespace Toxide;

public sealed class ToxConnectionEventArgs(ToxConnection connection) : EventArgs
{
    public ToxConnection Connection { get; } = connection;
}

public sealed class FriendRequestEventArgs(byte[] publicKey, byte[] messageBytes) : EventArgs
{
    /// <summary>The sender's long-term public key: pass it to <see cref="Tox.AddFriendNoRequest"/> to accept.</summary>
    public byte[] PublicKey { get; } = publicKey;

    public byte[] MessageBytes { get; } = messageBytes;

    public string Message => Tox.DecodeText(MessageBytes);
}

/// <summary>Base for events about one friend.</summary>
public abstract class FriendEventArgs(uint friendNumber) : EventArgs
{
    public uint FriendNumber { get; } = friendNumber;
}

public sealed class FriendMessageEventArgs(uint friendNumber, ToxMessageType type, byte[] messageBytes)
    : FriendEventArgs(friendNumber)
{
    public ToxMessageType Type { get; } = type;
    public byte[] MessageBytes { get; } = messageBytes;
    public string Message => Tox.DecodeText(MessageBytes);
}

public sealed class FriendTextEventArgs(uint friendNumber, byte[] textBytes) : FriendEventArgs(friendNumber)
{
    public byte[] TextBytes { get; } = textBytes;
    public string Text => Tox.DecodeText(TextBytes);
}

public sealed class FriendStatusEventArgs(uint friendNumber, ToxUserStatus status) : FriendEventArgs(friendNumber)
{
    public ToxUserStatus Status { get; } = status;
}

public sealed class FriendTypingEventArgs(uint friendNumber, bool isTyping) : FriendEventArgs(friendNumber)
{
    public bool IsTyping { get; } = isTyping;
}

public sealed class FriendConnectionEventArgs(uint friendNumber, ToxConnection connection) : FriendEventArgs(friendNumber)
{
    public ToxConnection Connection { get; } = connection;
}

public sealed class FriendReadReceiptEventArgs(uint friendNumber, uint messageId) : FriendEventArgs(friendNumber)
{
    /// <summary>The id returned by <see cref="Tox.SendMessage"/>.</summary>
    public uint MessageId { get; } = messageId;
}

public sealed class FriendPacketEventArgs(uint friendNumber, byte[] data) : FriendEventArgs(friendNumber)
{
    /// <summary>The packet, starting with its id byte.</summary>
    public byte[] Data { get; } = data;
}

/// <summary>A friend offers a file; answer with <see cref="Tox.FileControl"/> (Resume to accept, Cancel to refuse).</summary>
public sealed class FileReceiveEventArgs(uint friendNumber, uint fileNumber, ToxFileKind kind, ulong size, byte[] fileNameBytes)
    : FriendEventArgs(friendNumber)
{
    public uint FileNumber { get; } = fileNumber;
    public ToxFileKind Kind { get; } = kind;

    /// <summary>Size in bytes; <see cref="ulong.MaxValue"/> for streams of unknown length.</summary>
    public ulong Size { get; } = size;

    public byte[] FileNameBytes { get; } = fileNameBytes;
    public string FileName => Tox.DecodeText(FileNameBytes);
}

/// <summary>The friend paused, resumed or cancelled a transfer.</summary>
public sealed class FileControlEventArgs(uint friendNumber, uint fileNumber, ToxFileControl control)
    : FriendEventArgs(friendNumber)
{
    public uint FileNumber { get; } = fileNumber;
    public ToxFileControl Control { get; } = control;
}

/// <summary>
/// Send <see cref="Length"/> bytes at <see cref="Position"/> with <see cref="Tox.FileSendChunk"/>.
/// A length of 0 means the transfer completed: the friend received everything.
/// </summary>
public sealed class FileChunkRequestEventArgs(uint friendNumber, uint fileNumber, ulong position, int length)
    : FriendEventArgs(friendNumber)
{
    public uint FileNumber { get; } = fileNumber;
    public ulong Position { get; } = position;
    public int Length { get; } = length;
}

/// <summary>Data of an incoming file; an empty chunk means the file is complete.</summary>
public sealed class FileChunkEventArgs(uint friendNumber, uint fileNumber, ulong position, byte[] data)
    : FriendEventArgs(friendNumber)
{
    public uint FileNumber { get; } = fileNumber;
    public ulong Position { get; } = position;
    public byte[] Data { get; } = data;
}
