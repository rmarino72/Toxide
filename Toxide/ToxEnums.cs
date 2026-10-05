namespace Toxide;

/// <summary>How we (or a friend) are connected to the Tox network.</summary>
public enum ToxConnection
{
    /// <summary>Offline.</summary>
    None = 0,

    /// <summary>Through a TCP relay. Not produced by Toxide, which does not implement TCP relays yet.</summary>
    Tcp = 1,

    /// <summary>Directly over UDP.</summary>
    Udp = 2,
}

/// <summary>Presence set by the user; values match toxcore's TOX_USER_STATUS.</summary>
public enum ToxUserStatus : byte
{
    None = 0,
    Away = 1,
    Busy = 2,
}

public enum ToxMessageType
{
    /// <summary>A normal text message.</summary>
    Normal = 0,

    /// <summary>An action, like IRC's "/me waves".</summary>
    Action = 1,
}

/// <summary>What <see cref="ToxOptions.SaveData"/> contains.</summary>
public enum ToxSaveDataType
{
    None,

    /// <summary>A full profile as produced by <see cref="Tox.GetSaveData()"/> (or by toxcore/qTox, unencrypted).</summary>
    ToxSave,

    /// <summary>Only a 32-byte secret key: same identity, empty profile.</summary>
    SecretKey,
}

/// <summary>What a file transfer carries; values match toxcore's TOX_FILE_KIND.</summary>
public enum ToxFileKind : uint
{
    /// <summary>A regular file; the receiver should ask the user.</summary>
    Data = 0,

    /// <summary>
    /// The sender's avatar. Its file id is the SHA-256 (<see cref="Tox.Hash"/>) of the image, so a
    /// receiver that already has it can cancel; a size of 0 means "no avatar".
    /// </summary>
    Avatar = 1,
}

/// <summary>File transfer controls; values match toxcore's TOX_FILE_CONTROL.</summary>
public enum ToxFileControl : byte
{
    /// <summary>Accept an incoming file, or resume a paused transfer.</summary>
    Resume = 0,

    Pause = 1,
    Cancel = 2,
}
