namespace Toxide;

/// <summary>Why a <see cref="Tox"/> operation failed; mirrors toxcore's TOX_ERR_* values where they apply.</summary>
public enum ToxErrorCode
{
    /// <summary>No friend with that friend number.</summary>
    FriendNotFound,

    /// <summary>The friend is offline.</summary>
    FriendNotConnected,

    /// <summary>The friend is already in the friend list (or the request was already sent).</summary>
    FriendAlreadyAdded,

    /// <summary>The Tox ID is our own.</summary>
    OwnKey,

    /// <summary>A friend request needs a message.</summary>
    NoMessage,

    /// <summary>The text or packet is longer than the protocol allows.</summary>
    TooLong,

    /// <summary>The message is empty.</summary>
    Empty,

    /// <summary>The friend was already added with a different nospam; the new nospam will be used.</summary>
    SetNewNoSpam,

    /// <summary>The outgoing queue is full; try again later.</summary>
    SendQueue,

    /// <summary>The packet id is outside the custom ranges.</summary>
    InvalidPacket,

    /// <summary>The savedata could not be parsed, or the passphrase is wrong.</summary>
    BadSaveData,

    /// <summary>No UDP port could be bound in the requested range.</summary>
    PortAllocation,

    /// <summary>The bootstrap host could not be resolved or the key is malformed.</summary>
    BadBootstrapNode,

    /// <summary>No such file transfer.</summary>
    FileNotFound,

    /// <summary>The file transfer is not in a state that allows this (e.g. resuming a transfer paused by the friend).</summary>
    FileInvalidState,

    /// <summary>The chunk position does not match the one requested, or a seek is past the end.</summary>
    FileBadPosition,

    /// <summary>The chunk has the wrong length.</summary>
    FileBadLength,

    /// <summary>Too many concurrent file transfers with this friend (256).</summary>
    FileTooMany,
}

public sealed class ToxException : Exception
{
    public ToxException(ToxErrorCode code, string message, Exception? inner = null) : base(message, inner) => Code = code;

    public ToxErrorCode Code { get; }
}
