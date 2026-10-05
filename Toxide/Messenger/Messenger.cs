using Toxide.Crypto;
using Toxide.NetCrypto;
using Toxide.Onion;
using Toxide.State;

namespace Toxide.Messenger;

internal enum FriendStatus : byte
{
    None = 0,

    /// <summary>Added by us; the friend request has not been sent yet.</summary>
    Added = 1,

    /// <summary>Friend request sent; waiting for the friend to accept (i.e. to connect).</summary>
    Requested = 2,

    /// <summary>Accepted, currently offline.</summary>
    Confirmed = 3,

    Online = 4,
}

internal sealed class Friend
{
    public Friend(byte[] realPublicKey, int friendConnectionId, FriendStatus status)
    {
        RealPublicKey = realPublicKey;
        FriendConnectionId = friendConnectionId;
        Status = status;
    }

    public byte[] RealPublicKey { get; }
    public int FriendConnectionId { get; }
    public FriendStatus Status { get; set; }

    public byte[] RequestMessage { get; set; } = [];
    public byte[] RequestNoSpam { get; set; } = new byte[ToxId.NoSpamSize];
    public DateTimeOffset RequestLastSent { get; set; } = DateTimeOffset.UnixEpoch;
    public TimeSpan RequestTimeout { get; set; } = Messenger.FriendRequestTimeout;

    public byte[] Name { get; set; } = [];
    public byte[] StatusMessage { get; set; } = [];
    public ToxUserStatus UserStatus { get; set; }
    public bool IsTyping { get; set; }
    public ulong LastSeen { get; set; }

    // What we told this friend about ourselves (resent after every reconnection).
    public bool UserIsTyping { get; set; }
    public bool NameSent { get; set; }
    public bool StatusMessageSent { get; set; }
    public bool UserStatusSent { get; set; }
    public bool TypingSent { get; set; }

    public uint LastMessageId { get; set; }
    public Queue<(uint PacketNumber, uint MessageId)> Receipts { get; } = new();

    public ToxConnection ReportedConnection { get; set; }

    public FileTransfer[] Sending { get; } = FileTransfer.CreateSlots();
    public FileTransfer[] Receiving { get; } = FileTransfer.CreateSlots();
    public int SendingFiles { get; set; }
}

internal enum AddFriendResult
{
    Ok,
    TooLong,
    NoMessage,
    OwnKey,
    AlreadySent,
    BadChecksum,
    SetNewNoSpam,
}

internal enum SendMessageResult
{
    Ok,
    FriendNotFound,
    TooLong,
    FriendNotConnected,
    SendQueue,
    Empty,
}

/// <summary>
/// The instant messaging protocol on top of friend connections (toxcore Messenger.c):
/// friend list and requests, presence (name, status message, away/busy, typing), text messages
/// with read receipts. A message receipt is simply net_crypto confirming the lossless packet.
/// </summary>
internal sealed partial class Messenger
{
    public const int MaxNameLength = 128;
    public const int MaxStatusMessageLength = 1007;
    public const int MaxMessageLength = NetCrypto.NetCrypto.MaxDataSize - 1; // 1372
    public const int MaxFriendRequestDataSize = OnionClient.MaxDataSize - 100; // 921
    public static readonly TimeSpan FriendRequestTimeout = TimeSpan.FromSeconds(5);

    public const byte PacketIdOnline = 24;
    public const byte PacketIdOffline = 25;
    public const byte PacketIdNickname = 48;
    public const byte PacketIdStatusMessage = 49;
    public const byte PacketIdUserStatus = 50;
    public const byte PacketIdTyping = 51;
    public const byte PacketIdMessage = 64;
    public const byte PacketIdAction = 65;

    private const int MaxReceivedRequestsStored = 32;

    private readonly KeyPair _identity;
    private readonly FriendConnections _friendConnections;
    private readonly OnionClient _onion;
    private readonly TimeProvider _time;
    private readonly List<Friend?> _friends = [];
    private readonly List<byte[]> _receivedRequests = [];
    private OnionConnectionStatus _lastConnectionStatus;

    public Messenger(KeyPair identity, byte[] noSpam, FriendConnections friendConnections, OnionClient onion,
        TimeProvider time)
    {
        _identity = identity;
        NoSpam = noSpam;
        _friendConnections = friendConnections;
        _onion = onion;
        _time = time;
        friendConnections.FriendRequestReceived = HandleFriendRequest;
    }

    public byte[] NoSpam { get; set; }

    public byte[] Name { get; private set; } = [];
    public byte[] StatusMessage { get; private set; } = [];
    public ToxUserStatus UserStatus { get; private set; }

    public ToxId Address => new(_identity.PublicKey, NoSpam);

    // Callbacks (the public Tox facade turns them into events).
    public Action<byte[], byte[]>? FriendRequest { get; set; }
    public Action<uint, ToxMessageType, byte[]>? FriendMessage { get; set; }
    public Action<uint, byte[]>? FriendName { get; set; }
    public Action<uint, byte[]>? FriendStatusMessage { get; set; }
    public Action<uint, ToxUserStatus>? FriendUserStatus { get; set; }
    public Action<uint, bool>? FriendTyping { get; set; }
    public Action<uint, ToxConnection>? FriendConnectionStatus { get; set; }
    public Action<uint, uint>? FriendReadReceipt { get; set; }
    public Action<uint, byte[]>? FriendCustomPacket { get; set; }
    public Action<uint, byte[]>? FriendLossyPacket { get; set; }
    public Action<ToxConnection>? SelfConnectionStatus { get; set; }

    private DateTimeOffset Now => _time.GetUtcNow();

    public IEnumerable<uint> FriendNumbers =>
        Enumerable.Range(0, _friends.Count).Where(i => _friends[i] is not null).Select(i => (uint)i);

    public Friend? GetFriend(uint number) => number < _friends.Count ? _friends[(int)number] : null;

    public int FindFriend(ReadOnlySpan<byte> publicKey)
    {
        for (int i = 0; i < _friends.Count; i++)
            if (_friends[i] is { } f && f.RealPublicKey.AsSpan().SequenceEqual(publicKey))
                return i;
        return -1;
    }

    // ================================================================ self

    public void SetName(byte[] name)
    {
        if (name.Length > MaxNameLength)
            throw new ArgumentException($"Name longer than {MaxNameLength} bytes.", nameof(name));
        if (name.AsSpan().SequenceEqual(Name))
            return;
        Name = name;
        foreach (var f in _friends)
            if (f is not null)
                f.NameSent = false;
    }

    public void SetStatusMessage(byte[] message)
    {
        if (message.Length > MaxStatusMessageLength)
            throw new ArgumentException($"Status message longer than {MaxStatusMessageLength} bytes.", nameof(message));
        if (message.AsSpan().SequenceEqual(StatusMessage))
            return;
        StatusMessage = message;
        foreach (var f in _friends)
            if (f is not null)
                f.StatusMessageSent = false;
    }

    public void SetUserStatus(ToxUserStatus status)
    {
        if (status == UserStatus)
            return;
        UserStatus = status;
        foreach (var f in _friends)
            if (f is not null)
                f.UserStatusSent = false;
    }

    public void SetTyping(uint number, bool typing)
    {
        if (GetFriend(number) is not { } f || f.UserIsTyping == typing)
            return;
        f.UserIsTyping = typing;
        f.TypingSent = false;
    }

    // ================================================================ friend list

    private uint AddFriendSlot(byte[] realPublicKey, FriendStatus status)
    {
        int connectionId = _friendConnections.Add(realPublicKey);
        var friend = new Friend((byte[])realPublicKey.Clone(), connectionId, status);

        var fc = _friendConnections.Get(connectionId)!;
        int slot = _friends.IndexOf(null);
        if (slot < 0)
        {
            slot = _friends.Count;
            _friends.Add(null);
        }
        _friends[slot] = friend;

        uint number = (uint)slot;
        fc.StatusChanged = online => HandleConnectionStatus(number, online);
        fc.DataReceived = data => HandlePacket(number, data);
        fc.LossyReceived = data => FriendLossyPacket?.Invoke(number, data);

        if (_friendConnections.IsConnected(connectionId))
            SendOnlinePacket(friend);
        return number;
    }

    /// <summary>Adds a friend and queues a friend request to its Tox ID.</summary>
    public AddFriendResult AddFriend(ToxId address, byte[] message, out uint number)
    {
        number = uint.MaxValue;
        if (message.Length > MaxFriendRequestDataSize)
            return AddFriendResult.TooLong;
        if (message.Length == 0)
            return AddFriendResult.NoMessage;
        if (address.PublicKey.AsSpan().SequenceEqual(_identity.PublicKey))
            return AddFriendResult.OwnKey;

        int existing = FindFriend(address.PublicKey);
        if (existing >= 0)
        {
            var f = _friends[existing]!;
            number = (uint)existing;
            if (f.Status >= FriendStatus.Confirmed || f.RequestNoSpam.AsSpan().SequenceEqual(address.NoSpam))
                return AddFriendResult.AlreadySent;
            f.RequestNoSpam = (byte[])address.NoSpam.Clone();
            return AddFriendResult.SetNewNoSpam;
        }

        number = AddFriendSlot(address.PublicKey, FriendStatus.Added);
        var friend = _friends[(int)number]!;
        friend.RequestMessage = message;
        friend.RequestNoSpam = (byte[])address.NoSpam.Clone();
        return AddFriendResult.Ok;
    }

    /// <summary>Adds a friend without a request (accepting a request, or restoring a saved friend).</summary>
    public AddFriendResult AddFriendNoRequest(byte[] publicKey, out uint number)
    {
        number = uint.MaxValue;
        if (publicKey.AsSpan().SequenceEqual(_identity.PublicKey))
            return AddFriendResult.OwnKey;

        int existing = FindFriend(publicKey);
        if (existing >= 0)
        {
            number = (uint)existing;
            return AddFriendResult.AlreadySent;
        }

        number = AddFriendSlot(publicKey, FriendStatus.Confirmed);
        return AddFriendResult.Ok;
    }

    public bool DeleteFriend(uint number)
    {
        if (GetFriend(number) is not { } friend)
            return false;

        if (friend.Status == FriendStatus.Online)
            _friendConnections.WriteLossless(friend.FriendConnectionId, [PacketIdOffline], false);

        if (_friendConnections.Get(friend.FriendConnectionId) is { } fc)
        {
            fc.StatusChanged = null;
            fc.DataReceived = null;
            fc.LossyReceived = null;
        }
        _friendConnections.Kill(friend.FriendConnectionId);
        _friends[(int)number] = null;
        // A deleted friend may send a new request later: it must not look like a duplicate.
        _receivedRequests.RemoveAll(k => k.AsSpan().SequenceEqual(friend.RealPublicKey));
        return true;
    }

    /// <summary>Restores a friend from savedata, keeping its saved state.</summary>
    public void RestoreFriend(SavedFriend saved)
    {
        uint number;
        if (saved.Status >= FriendStatus.Confirmed)
        {
            if (AddFriendNoRequest(saved.PublicKey, out number) != AddFriendResult.Ok)
                return;
            var f = _friends[(int)number]!;
            f.Name = saved.Name;
            f.StatusMessage = saved.StatusMessage;
            f.UserStatus = saved.UserStatus;
            f.LastSeen = saved.LastSeen;
        }
        else if (saved.Status != FriendStatus.None)
        {
            AddFriend(new ToxId(saved.PublicKey, saved.RequestNoSpam), saved.RequestMessage, out _);
        }
    }

    private void SetFriendStatus(uint number, Friend friend, FriendStatus status)
    {
        bool wasOnline = friend.Status == FriendStatus.Online;
        bool isOnline = status == FriendStatus.Online;

        if (wasOnline != isOnline)
        {
            if (wasOnline)
            {
                friend.Receipts.Clear();
                BreakFiles(friend);
            }
            else
            {
                friend.NameSent = false;
                friend.UserStatusSent = false;
                friend.StatusMessageSent = false;
                friend.TypingSent = false;
            }
        }

        friend.Status = status;

        var connection = isOnline ? ToxConnection.Udp : ToxConnection.None;
        if (connection != friend.ReportedConnection)
        {
            friend.ReportedConnection = connection;
            FriendConnectionStatus?.Invoke(number, connection);
        }
    }

    // ================================================================ friend requests

    private void HandleFriendRequest(byte[] publicKey, byte[] data)
    {
        if (data.Length <= 1 + ToxId.NoSpamSize || data.Length > OnionClient.MaxDataSize)
            return;
        if (FindFriend(publicKey) >= 0)
            return; // already a friend
        if (_receivedRequests.Exists(k => k.AsSpan().SequenceEqual(publicKey)))
            return; // duplicate: requests are sent through several onion paths
        if (!data.AsSpan(1, ToxId.NoSpamSize).SequenceEqual(NoSpam))
            return; // wrong nospam: the sender has an old Tox ID of ours

        _receivedRequests.Add((byte[])publicKey.Clone());
        if (_receivedRequests.Count > MaxReceivedRequestsStored)
            _receivedRequests.RemoveAt(0);

        FriendRequest?.Invoke(publicKey, data[(1 + ToxId.NoSpamSize)..]);
    }

    // ================================================================ packets

    private bool Write(Friend friend, byte packetId, ReadOnlySpan<byte> payload, out long packetNumber)
    {
        packetNumber = -1;
        if (payload.Length >= NetCrypto.NetCrypto.MaxDataSize || friend.Status != FriendStatus.Online)
            return false;

        var packet = new byte[1 + payload.Length];
        packet[0] = packetId;
        payload.CopyTo(packet.AsSpan(1));
        packetNumber = _friendConnections.WriteLossless(friend.FriendConnectionId, packet, false);
        return packetNumber != -1;
    }

    private bool Write(Friend friend, byte packetId, ReadOnlySpan<byte> payload) => Write(friend, packetId, payload, out _);

    private void SendOnlinePacket(Friend friend) =>
        _friendConnections.WriteLossless(friend.FriendConnectionId, [PacketIdOnline], false);

    public SendMessageResult SendMessage(uint number, ToxMessageType type, byte[] message, out uint messageId)
    {
        messageId = 0;
        if (GetFriend(number) is not { } friend)
            return SendMessageResult.FriendNotFound;
        if (message.Length == 0)
            return SendMessageResult.Empty;
        if (message.Length > MaxMessageLength)
            return SendMessageResult.TooLong;
        if (friend.Status != FriendStatus.Online)
            return SendMessageResult.FriendNotConnected;

        byte id = type == ToxMessageType.Action ? PacketIdAction : PacketIdMessage;
        if (!Write(friend, id, message, out long packetNumber))
            return SendMessageResult.SendQueue;

        messageId = ++friend.LastMessageId;
        friend.Receipts.Enqueue(((uint)packetNumber, messageId));
        return SendMessageResult.Ok;
    }

    /// <summary>Custom lossless (160-191) or lossy (200-254) packets, for extensions.</summary>
    public bool SendCustomPacket(uint number, byte[] data, bool lossless)
    {
        if (GetFriend(number) is not { Status: FriendStatus.Online } friend || data.Length == 0)
            return false;
        return lossless
            ? data[0] is >= 160 and <= 191 && _friendConnections.WriteLossless(friend.FriendConnectionId, data, true) != -1
            : data[0] is >= 200 and <= 254 && _friendConnections.SendLossy(friend.FriendConnectionId, data);
    }

    private void HandleConnectionStatus(uint number, bool online)
    {
        if (GetFriend(number) is not { } friend)
            return;

        if (online)
            SendOnlinePacket(friend);
        else if (friend.Status == FriendStatus.Online)
            SetFriendStatus(number, friend, FriendStatus.Confirmed);
    }

    private void HandlePacket(uint number, byte[] data)
    {
        if (data.Length == 0 || GetFriend(number) is not { } friend)
            return;

        byte id = data[0];
        var payload = data[1..];

        if (friend.Status != FriendStatus.Online)
        {
            // The first packet of a session must be ONLINE; answering it brings both sides online.
            if (id != PacketIdOnline || data.Length != 1)
                return;
            SetFriendStatus(number, friend, FriendStatus.Online);
            SendOnlinePacket(friend);
            return;
        }

        switch (id)
        {
            case PacketIdOnline:
                break; // the peer's answer to our own ONLINE packet

            case PacketIdOffline:
                if (payload.Length == 0)
                    SetFriendStatus(number, friend, FriendStatus.Confirmed);
                break;

            case PacketIdNickname:
                if (payload.Length > MaxNameLength)
                    break;
                FriendName?.Invoke(number, payload);
                friend.Name = payload;
                break;

            case PacketIdStatusMessage:
                if (payload.Length > MaxStatusMessageLength)
                    break;
                FriendStatusMessage?.Invoke(number, payload);
                friend.StatusMessage = payload;
                break;

            case PacketIdUserStatus:
                if (payload.Length != 1 || payload[0] > (byte)ToxUserStatus.Busy)
                    break;
                FriendUserStatus?.Invoke(number, (ToxUserStatus)payload[0]);
                friend.UserStatus = (ToxUserStatus)payload[0];
                break;

            case PacketIdTyping:
                if (payload.Length != 1)
                    break;
                friend.IsTyping = payload[0] != 0;
                FriendTyping?.Invoke(number, friend.IsTyping);
                break;

            case PacketIdMessage:
            case PacketIdAction:
                if (payload.Length == 0)
                    break;
                FriendMessage?.Invoke(number, id == PacketIdAction ? ToxMessageType.Action : ToxMessageType.Normal, payload);
                break;

            case PacketIdFileSendRequest:
                HandleFileSendRequest(number, friend, payload);
                break;

            case PacketIdFileControl:
                HandleFileControl(number, friend, payload);
                break;

            case PacketIdFileData:
                HandleFileData(number, friend, payload);
                break;

            default:
                if (id is >= 160 and <= 191)
                    FriendCustomPacket?.Invoke(number, data);
                break;
        }
    }

    // ================================================================ main loop

    public void Tick()
    {
        var now = Now;
        for (int i = 0; i < _friends.Count; i++)
        {
            if (_friends[i] is not { } friend)
                continue;
            uint number = (uint)i;

            if (friend.Status == FriendStatus.Added)
            {
                if (_friendConnections.SendFriendRequest(friend.FriendConnectionId, friend.RequestNoSpam, friend.RequestMessage) >= 0)
                {
                    SetFriendStatus(number, friend, FriendStatus.Requested);
                    friend.RequestLastSent = now;
                }
            }

            if (friend.Status == FriendStatus.Requested && friend.RequestLastSent + friend.RequestTimeout < now)
            {
                // No connection after the request: assume it got lost and send it again, backing off.
                SetFriendStatus(number, friend, FriendStatus.Added);
                friend.RequestTimeout *= 2;
            }

            if (friend.Status != FriendStatus.Online)
                continue;

            if (!friend.NameSent && Write(friend, PacketIdNickname, Name))
                friend.NameSent = true;
            if (!friend.StatusMessageSent && Write(friend, PacketIdStatusMessage, StatusMessage))
                friend.StatusMessageSent = true;
            if (!friend.UserStatusSent && Write(friend, PacketIdUserStatus, [(byte)UserStatus]))
                friend.UserStatusSent = true;
            if (!friend.TypingSent && Write(friend, PacketIdTyping, [(byte)(friend.UserIsTyping ? 1 : 0)]))
                friend.TypingSent = true;

            RequestFileChunks(number, friend);

            while (friend.Receipts.TryPeek(out var receipt)
                   && _friendConnections.IsPacketReceived(friend.FriendConnectionId, receipt.PacketNumber))
            {
                friend.Receipts.Dequeue();
                FriendReadReceipt?.Invoke(number, receipt.MessageId);
            }

            friend.LastSeen = (ulong)now.ToUnixTimeSeconds();
        }

        var status = _onion.ConnectionStatus;
        if (status != _lastConnectionStatus)
        {
            _lastConnectionStatus = status;
            SelfConnectionStatus?.Invoke(status == OnionConnectionStatus.Udp ? ToxConnection.Udp : ToxConnection.None);
        }
    }

    internal IEnumerable<(uint Number, Friend Friend)> EnumerateFriends()
    {
        for (int i = 0; i < _friends.Count; i++)
            if (_friends[i] is { } f)
                yield return ((uint)i, f);
    }
}
