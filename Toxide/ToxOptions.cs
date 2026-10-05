namespace Toxide;

/// <summary>Start-up options for <see cref="Tox"/>; the defaults match toxcore's.</summary>
public sealed class ToxOptions
{
    /// <summary>Use a dual-stack socket that also reaches IPv6 peers.</summary>
    public bool Ipv6Enabled { get; set; } = true;

    /// <summary>Broadcast our presence on the LAN and accept LAN peers announcing theirs.</summary>
    public bool LocalDiscoveryEnabled { get; set; } = true;

    /// <summary>Try to traverse NATs when a friend cannot be reached directly.</summary>
    public bool HolePunchingEnabled { get; set; } = true;

    /// <summary>First UDP port to try; with <see cref="EndPort"/>, 0 lets the OS choose.</summary>
    public ushort StartPort { get; set; } = 33445;

    /// <summary>Last UDP port to try.</summary>
    public ushort EndPort { get; set; } = 33545;

    public ToxSaveDataType SaveDataType { get; set; } = ToxSaveDataType.None;

    /// <summary>A profile from <see cref="Tox.GetSaveData()"/>, or a 32-byte secret key; see <see cref="SaveDataType"/>.</summary>
    public byte[]? SaveData { get; set; }

    /// <summary>Passphrase of an encrypted (toxEsave) profile in <see cref="SaveData"/>.</summary>
    public string? SaveDataPassphrase { get; set; }

    /// <summary>Clock used by every protocol timer; replace it only for tests or simulations.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}
