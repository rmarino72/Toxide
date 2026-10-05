using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Toxide.Crypto;
using Toxide.Dht;
using Toxide.Messenger;
using Toxide.Network;
using Toxide.Onion;
using Toxide.State;

namespace Toxide;

/// <summary>
/// A Tox instance: one identity on the Tox network, its friends and its conversations.
/// This is the managed counterpart of toxcore's <c>Tox</c> object (tox.h), wire-compatible with
/// toxcore clients such as qTox for one-to-one messaging.
///
/// <para>Driving it: call <see cref="Iterate"/> every <see cref="IterationInterval"/>, or let
/// <see cref="RunAsync"/> do it. All events are raised from inside <see cref="Iterate"/>, on the
/// thread that calls it.</para>
///
/// <para>Thread safety: every public member takes an internal lock, so the instance may be used
/// from several threads; event handlers may call back into the instance.</para>
///
/// <para>Not implemented yet: TCP relays (and therefore proxies), audio/video and group chats.
/// Peers must be reachable over UDP, possibly after NAT hole punching.</para>
/// </summary>
public sealed class Tox : IDisposable
{
    public const int PublicKeySize = CryptoConstants.PublicKeySize;
    public const int SecretKeySize = CryptoConstants.SecretKeySize;
    public const int AddressSize = ToxId.Size;
    public const int MaxNameLength = Messenger.Messenger.MaxNameLength;
    public const int MaxStatusMessageLength = Messenger.Messenger.MaxStatusMessageLength;
    public const int MaxFriendRequestLength = Messenger.Messenger.MaxFriendRequestDataSize;
    public const int MaxMessageLength = Messenger.Messenger.MaxMessageLength;
    public const int MaxCustomPacketSize = NetCrypto.NetCrypto.MaxDataSize;
    public const int MaxFileNameLength = Messenger.Messenger.MaxFileNameLength;
    public const int FileIdLength = Messenger.Messenger.FileIdLength;

    /// <summary>Chunk size used by file transfers: every chunk but the last has exactly this length.</summary>
    public const int MaxFileChunkSize = Messenger.Messenger.MaxFileDataSize;

    private const int MaxSavedDhtNodes = 512;
    private const int SavedPathNodes = 8;
    private static readonly TimeSpan MaxIterationInterval = TimeSpan.FromMilliseconds(50);

    private readonly object _sync = new();
    private readonly ToxOptions _options;
    private readonly UdpTransport? _ownedTransport;
    private readonly ChannelReader<ReceivedPacket> _incoming;
    private readonly PacketDispatcher _dispatcher = new();
    private readonly KeyPair _identity;
    private readonly DhtNode _dht;
    private readonly OnionClient _onion;
    private readonly NetCrypto.NetCrypto _netCrypto;
    private readonly FriendConnections _friendConnections;
    private readonly Messenger.Messenger _messenger;
    private readonly SaveData _loaded;
    private bool _disposed;

    /// <summary>Creates a Tox instance bound to a UDP port in the configured range.</summary>
    /// <exception cref="ToxException">Bad savedata, wrong passphrase, or no free port.</exception>
    public static Tox Create(ToxOptions? options = null)
    {
        options ??= new ToxOptions();
        var save = LoadSaveData(options);

        UdpTransport transport;
        try
        {
            transport = UdpTransport.Bind(options.StartPort, options.EndPort, ipv6: options.Ipv6Enabled);
        }
        catch (SocketException ex)
        {
            throw new ToxException(ToxErrorCode.PortAllocation,
                $"No free UDP port in {options.StartPort}-{options.EndPort}.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new ToxException(ToxErrorCode.PortAllocation, ex.Message, ex);
        }

        return new Tox(options, save, transport, transport.Incoming, transport.LocalPort, transport);
    }

    /// <summary>Wires all the layers on an arbitrary transport (used by tests with an in-memory network).</summary>
    internal Tox(ToxOptions options, SaveData save, IPacketSender sender, ChannelReader<ReceivedPacket> incoming, ushort port,
        UdpTransport? ownedTransport = null)
    {
        _options = options;
        _ownedTransport = ownedTransport;
        _incoming = incoming;
        _loaded = save;
        UdpPort = port;
        // Protocol timers need a clock that never jumps (NTP corrections, suspend): toxcore uses a
        // monotonic clock too. A custom provider (tests, simulations) is used as given.
        var time = options.TimeProvider == TimeProvider.System ? new MonotonicTimeProvider() : options.TimeProvider;
        var crypto = new ManagedCryptoCore();

        _identity = save.SecretKey is null ? crypto.GenerateKeyPair() : crypto.DeriveKeyPair(save.SecretKey);

        _dht = new DhtNode(crypto, sender, time)
        {
            HolePunchingEnabled = options.HolePunchingEnabled,
            LanDiscoveryEnabled = options.LocalDiscoveryEnabled,
        };
        var relay = new OnionRelay(_dht, time);
        var announceServer = new OnionAnnounceServer(_dht, time);
        _onion = new OnionClient(_dht, _identity, time);
        _netCrypto = new NetCrypto.NetCrypto(_dht, _identity, time);
        var lanDiscovery = options.LocalDiscoveryEnabled ? new LanDiscovery(sender, time) : null;
        _friendConnections = new FriendConnections(_dht, _onion, _netCrypto, time, lanDiscovery);
        _messenger = new Messenger.Messenger(_identity, save.NoSpam, _friendConnections, _onion, time);

        _dht.Attach(_dispatcher);
        relay.Attach(_dispatcher);
        announceServer.Attach(_dispatcher);
        _onion.Attach(_dispatcher);
        _netCrypto.Attach(_dispatcher);

        WireEvents();
        RestoreState(save);
    }

    private static SaveData LoadSaveData(ToxOptions options)
    {
        var data = options.SaveData;
        switch (options.SaveDataType)
        {
            case ToxSaveDataType.None:
                return new SaveData { NoSpam = RandomNumberGenerator.GetBytes(ToxId.NoSpamSize) };

            case ToxSaveDataType.SecretKey:
                if (data is not { Length: SecretKeySize })
                    throw new ToxException(ToxErrorCode.BadSaveData, $"A secret key must be {SecretKeySize} bytes.");
                return new SaveData { NoSpam = RandomNumberGenerator.GetBytes(ToxId.NoSpamSize), SecretKey = (byte[])data.Clone() };

            case ToxSaveDataType.ToxSave:
                if (data is null)
                    throw new ToxException(ToxErrorCode.BadSaveData, "SaveData is null.");
                try
                {
                    if (ToxEncryptSave.IsEncrypted(data))
                    {
                        if (options.SaveDataPassphrase is null)
                            throw new ToxException(ToxErrorCode.BadSaveData, "The profile is encrypted: set SaveDataPassphrase.");
                        data = ToxEncryptSave.Decrypt(data, options.SaveDataPassphrase);
                    }
                    return SaveData.Parse(data);
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException)
                {
                    throw new ToxException(ToxErrorCode.BadSaveData, ex.Message, ex);
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(options), options.SaveDataType, "Unknown savedata type.");
        }
    }

    private void RestoreState(SaveData save)
    {
        _messenger.SetName(save.Name);
        _messenger.SetStatusMessage(save.StatusMessage);
        _messenger.SetUserStatus(save.Status);
        foreach (var friend in save.Friends)
            _messenger.RestoreFriend(friend);
        _dht.AddSavedNodes(save.DhtNodes);
        foreach (var node in save.PathNodes)
            _onion.AddBootstrapPathNode(node);
    }

    // ================================================================ events

    /// <summary>Our own connection to the Tox network changed.</summary>
    public event EventHandler<ToxConnectionEventArgs>? ConnectionStatusChanged;

    /// <summary>Someone wants to be our friend; accept with <see cref="AddFriendNoRequest"/>.</summary>
    public event EventHandler<FriendRequestEventArgs>? FriendRequestReceived;

    public event EventHandler<FriendMessageEventArgs>? FriendMessageReceived;
    public event EventHandler<FriendTextEventArgs>? FriendNameChanged;
    public event EventHandler<FriendTextEventArgs>? FriendStatusMessageChanged;
    public event EventHandler<FriendStatusEventArgs>? FriendStatusChanged;
    public event EventHandler<FriendTypingEventArgs>? FriendTypingChanged;
    public event EventHandler<FriendConnectionEventArgs>? FriendConnectionStatusChanged;

    /// <summary>The friend received the message with this id (sent by <see cref="SendMessage"/>).</summary>
    public event EventHandler<FriendReadReceiptEventArgs>? FriendReadReceipt;

    /// <summary>A custom lossless packet (ids 160-191) from a friend.</summary>
    public event EventHandler<FriendPacketEventArgs>? FriendLosslessPacketReceived;

    /// <summary>A custom lossy packet (ids 200-254) from a friend.</summary>
    public event EventHandler<FriendPacketEventArgs>? FriendLossyPacketReceived;

    /// <summary>A friend offers a file.</summary>
    public event EventHandler<FileReceiveEventArgs>? FileReceiveRequested;

    /// <summary>A friend paused, resumed or cancelled a transfer.</summary>
    public event EventHandler<FileControlEventArgs>? FileControlReceived;

    /// <summary>A file we send needs its next chunk.</summary>
    public event EventHandler<FileChunkRequestEventArgs>? FileChunkRequested;

    /// <summary>A chunk of a file we receive.</summary>
    public event EventHandler<FileChunkEventArgs>? FileChunkReceived;

    private void WireEvents()
    {
        _messenger.SelfConnectionStatus = c => ConnectionStatusChanged?.Invoke(this, new ToxConnectionEventArgs(c));
        _messenger.FriendRequest = (pk, msg) => FriendRequestReceived?.Invoke(this, new FriendRequestEventArgs(pk, msg));
        _messenger.FriendMessage = (n, t, m) => FriendMessageReceived?.Invoke(this, new FriendMessageEventArgs(n, t, m));
        _messenger.FriendName = (n, v) => FriendNameChanged?.Invoke(this, new FriendTextEventArgs(n, v));
        _messenger.FriendStatusMessage = (n, v) => FriendStatusMessageChanged?.Invoke(this, new FriendTextEventArgs(n, v));
        _messenger.FriendUserStatus = (n, s) => FriendStatusChanged?.Invoke(this, new FriendStatusEventArgs(n, s));
        _messenger.FriendTyping = (n, t) => FriendTypingChanged?.Invoke(this, new FriendTypingEventArgs(n, t));
        _messenger.FriendConnectionStatus = (n, c) => FriendConnectionStatusChanged?.Invoke(this, new FriendConnectionEventArgs(n, c));
        _messenger.FriendReadReceipt = (n, id) => FriendReadReceipt?.Invoke(this, new FriendReadReceiptEventArgs(n, id));
        _messenger.FriendCustomPacket = (n, d) => FriendLosslessPacketReceived?.Invoke(this, new FriendPacketEventArgs(n, d));
        _messenger.FileReceive = (n, f, kind, size, name) =>
            FileReceiveRequested?.Invoke(this, new FileReceiveEventArgs(n, f, (ToxFileKind)kind, size, name));
        _messenger.FileControlReceived = (n, f, c) =>
            FileControlReceived?.Invoke(this, new FileControlEventArgs(n, f, (ToxFileControl)c));
        _messenger.FileChunkRequest = (n, f, pos, len) =>
            FileChunkRequested?.Invoke(this, new FileChunkRequestEventArgs(n, f, pos, len));
        _messenger.FileChunkReceived = (n, f, pos, data) =>
            FileChunkReceived?.Invoke(this, new FileChunkEventArgs(n, f, pos, data));
        _messenger.FriendLossyPacket = (n, d) =>
        {
            if (d.Length > 0 && d[0] is >= 200 and <= 254)
                FriendLossyPacketReceived?.Invoke(this, new FriendPacketEventArgs(n, d));
        };
    }

    // ================================================================ identity

    /// <summary>Our Tox ID, to give to people who want to add us.</summary>
    public ToxId Address
    {
        get { lock (_sync) return _messenger.Address; }
    }

    /// <summary>Our long-term public key (the first 32 bytes of the Tox ID).</summary>
    public byte[] PublicKey => (byte[])_identity.PublicKey.Clone();

    /// <summary>Our long-term secret key. Whoever has it can impersonate us.</summary>
    public byte[] SecretKey
    {
        get
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this); // the key is wiped on dispose
                return (byte[])_identity.SecretKey.Clone();
            }
        }
    }

    /// <summary>Our temporary DHT key: give it, with our address and port, to peers bootstrapping from us.</summary>
    public byte[] DhtId => (byte[])_dht.PublicKey.Clone();

    /// <summary>The UDP port we are bound to.</summary>
    public ushort UdpPort { get; }

    /// <summary>
    /// The nospam part of our Tox ID; changing it makes old Tox IDs useless for new friend requests.
    /// As in toxcore, the value reads big-endian from the Tox ID bytes (0x12345678 -> "12345678").
    /// </summary>
    public uint NoSpam
    {
        get { lock (_sync) return BinaryPrimitives.ReadUInt32BigEndian(_messenger.NoSpam); }
        set
        {
            var bytes = new byte[ToxId.NoSpamSize];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            lock (_sync) _messenger.NoSpam = bytes;
        }
    }

    public ToxConnection ConnectionStatus
    {
        get
        {
            lock (_sync)
                return _onion.ConnectionStatus == OnionConnectionStatus.Udp ? ToxConnection.Udp : ToxConnection.None;
        }
    }

    public string Name
    {
        get { lock (_sync) return DecodeText(_messenger.Name); }
        set { lock (_sync) _messenger.SetName(EncodeText(value, MaxNameLength, nameof(value))); }
    }

    public string StatusMessage
    {
        get { lock (_sync) return DecodeText(_messenger.StatusMessage); }
        set { lock (_sync) _messenger.SetStatusMessage(EncodeText(value, MaxStatusMessageLength, nameof(value))); }
    }

    public ToxUserStatus Status
    {
        get { lock (_sync) return _messenger.UserStatus; }
        set
        {
            if (!Enum.IsDefined(value))
                throw new ArgumentOutOfRangeException(nameof(value));
            lock (_sync) _messenger.SetUserStatus(value);
        }
    }

    // ================================================================ network

    /// <summary>
    /// Joins the network through a known node (see https://nodes.tox.chat). Several calls with
    /// different nodes make start-up faster and more reliable.
    /// </summary>
    /// <param name="host">IP address or host name.</param>
    /// <param name="publicKeyHex">The node's DHT public key, 64 hex characters.</param>
    public void Bootstrap(string host, ushort port, string publicKeyHex)
    {
        ArgumentNullException.ThrowIfNull(host);
        var key = ParseKey(publicKeyHex, nameof(publicKeyHex));

        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out var ip))
        {
            addresses = [ip];
        }
        else
        {
            try { addresses = Dns.GetHostAddresses(host); }
            catch (SocketException ex)
            {
                throw new ToxException(ToxErrorCode.BadBootstrapNode, $"Cannot resolve '{host}'.", ex);
            }
        }

        bool any = false;
        lock (_sync)
        {
            foreach (var address in addresses)
            {
                if (address.AddressFamily == AddressFamily.InterNetworkV6 && !_options.Ipv6Enabled)
                    continue;
                Bootstrap(new IpPort(address, port), key);
                any = true;
            }
        }

        if (!any)
            throw new ToxException(ToxErrorCode.BadBootstrapNode, $"No usable address for '{host}'.");
    }

    public void Bootstrap(IPEndPoint endPoint, byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        if (publicKey is not { Length: PublicKeySize })
            throw new ArgumentException($"A public key must be {PublicKeySize} bytes.", nameof(publicKey));
        lock (_sync)
            Bootstrap(IpPort.FromEndPoint(endPoint), (byte[])publicKey.Clone());
    }

    private void Bootstrap(IpPort endpoint, byte[] key)
    {
        _dht.Bootstrap(endpoint, key);
        _onion.AddBootstrapPathNode(new NodeInfo(TransportProtocol.Udp, endpoint, key));
    }

    /// <summary>How long to wait before the next <see cref="Iterate"/> call.</summary>
    public TimeSpan IterationInterval
    {
        get
        {
            lock (_sync)
            {
                var crypto = TimeSpan.FromMilliseconds(Math.Max(1, _netCrypto.RunInterval));
                return crypto < MaxIterationInterval ? crypto : MaxIterationInterval;
            }
        }
    }

    /// <summary>Processes received packets and runs all protocol timers. Raises the events.</summary>
    public void Iterate()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            while (_incoming.TryRead(out var packet))
            {
                var p = packet;
                Guard(() => _dispatcher.Dispatch(p.Source, p.Data)); // a malformed packet is simply dropped
            }

            Guard(_dht.Tick);
            Guard(_netCrypto.Tick);
            Guard(_onion.Tick);
            Guard(() => _friendConnections.Tick(_options.LocalDiscoveryEnabled));
            Guard(_messenger.Tick);
        }
    }

    /// <summary>
    /// Raised when processing a packet or a timer threw, including exceptions thrown by event
    /// handlers. The instance keeps running; this is for logging and diagnostics.
    /// </summary>
    public event EventHandler<Exception>? InternalError;

    private void Guard(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            InternalError?.Invoke(this, ex);
        }
    }

    /// <summary>Calls <see cref="Iterate"/> in a loop until cancelled, waking up early when packets arrive.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Iterate();

            using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            wait.CancelAfter(IterationInterval);
            try
            {
                if (!await _incoming.WaitToReadAsync(wait.Token).ConfigureAwait(false))
                    return; // transport closed
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // interval elapsed
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    // ================================================================ friends

    /// <summary>Adds a friend by Tox ID and sends a friend request; returns the friend number.</summary>
    /// <exception cref="ToxException">See <see cref="ToxErrorCode"/>.</exception>
    public uint AddFriend(ToxId address, string message)
    {
        ArgumentNullException.ThrowIfNull(address);
        var bytes = EncodeText(message, MaxFriendRequestLength, nameof(message));
        lock (_sync)
        {
            var result = _messenger.AddFriend(address, bytes, out uint number);
            return result switch
            {
                AddFriendResult.Ok => number,
                AddFriendResult.NoMessage => throw new ToxException(ToxErrorCode.NoMessage, "A friend request needs a message."),
                AddFriendResult.OwnKey => throw new ToxException(ToxErrorCode.OwnKey, "That is our own Tox ID."),
                AddFriendResult.AlreadySent => throw new ToxException(ToxErrorCode.FriendAlreadyAdded, "Friend already added."),
                AddFriendResult.SetNewNoSpam => throw new ToxException(ToxErrorCode.SetNewNoSpam,
                    "Friend already added; its new nospam will be used."),
                AddFriendResult.TooLong => throw new ToxException(ToxErrorCode.TooLong, "Friend request message too long."),
                _ => throw new ToxException(ToxErrorCode.BadSaveData, result.ToString()),
            };
        }
    }

    /// <summary>Adds a friend by Tox ID (76 hex characters) and sends a friend request.</summary>
    /// <exception cref="FormatException">The Tox ID is malformed or its checksum is wrong.</exception>
    public uint AddFriend(string address, string message) => AddFriend(ToxId.Parse(address), message);

    /// <summary>Adds a friend without a request, typically to accept a <see cref="FriendRequestReceived"/>.</summary>
    public uint AddFriendNoRequest(byte[] publicKey)
    {
        if (publicKey is not { Length: PublicKeySize })
            throw new ArgumentException($"A public key must be {PublicKeySize} bytes.", nameof(publicKey));
        lock (_sync)
        {
            return _messenger.AddFriendNoRequest((byte[])publicKey.Clone(), out uint number) switch
            {
                AddFriendResult.Ok => number,
                AddFriendResult.OwnKey => throw new ToxException(ToxErrorCode.OwnKey, "That is our own public key."),
                _ => throw new ToxException(ToxErrorCode.FriendAlreadyAdded, "Friend already added."),
            };
        }
    }

    /// <summary>Removes a friend; returns false if there was no such friend.</summary>
    public bool DeleteFriend(uint friendNumber)
    {
        lock (_sync)
            return _messenger.DeleteFriend(friendNumber);
    }

    public IReadOnlyList<uint> FriendList
    {
        get { lock (_sync) return _messenger.FriendNumbers.ToList(); }
    }

    public bool FriendExists(uint friendNumber)
    {
        lock (_sync)
            return _messenger.GetFriend(friendNumber) is not null;
    }

    /// <summary>The friend number for a public key, or null.</summary>
    public uint? FindFriend(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        lock (_sync)
        {
            int n = _messenger.FindFriend(publicKey);
            return n < 0 ? null : (uint)n;
        }
    }

    public byte[] GetFriendPublicKey(uint friendNumber)
    {
        lock (_sync)
            return (byte[])RequireFriend(friendNumber).RealPublicKey.Clone();
    }

    public string GetFriendName(uint friendNumber)
    {
        lock (_sync)
            return DecodeText(RequireFriend(friendNumber).Name);
    }

    public string GetFriendStatusMessage(uint friendNumber)
    {
        lock (_sync)
            return DecodeText(RequireFriend(friendNumber).StatusMessage);
    }

    public ToxUserStatus GetFriendStatus(uint friendNumber)
    {
        lock (_sync)
            return RequireFriend(friendNumber).UserStatus;
    }

    public ToxConnection GetFriendConnectionStatus(uint friendNumber)
    {
        lock (_sync)
            return RequireFriend(friendNumber).Status == FriendStatus.Online ? ToxConnection.Udp : ToxConnection.None;
    }

    public bool GetFriendTyping(uint friendNumber)
    {
        lock (_sync)
            return RequireFriend(friendNumber).IsTyping;
    }

    /// <summary>When the friend was last seen online, if ever.</summary>
    public DateTimeOffset? GetFriendLastOnline(uint friendNumber)
    {
        lock (_sync)
        {
            ulong seen = RequireFriend(friendNumber).LastSeen;
            return seen == 0 ? null : DateTimeOffset.FromUnixTimeSeconds((long)seen);
        }
    }

    /// <summary>Sends a message to an online friend; returns the id reported later by <see cref="FriendReadReceipt"/>.</summary>
    public uint SendMessage(uint friendNumber, string message, ToxMessageType type = ToxMessageType.Normal)
    {
        var bytes = EncodeText(message, MaxMessageLength, nameof(message));
        lock (_sync)
        {
            var result = _messenger.SendMessage(friendNumber, type, bytes, out uint id);
            return result switch
            {
                SendMessageResult.Ok => id,
                SendMessageResult.FriendNotFound => throw new ToxException(ToxErrorCode.FriendNotFound, "No such friend."),
                SendMessageResult.FriendNotConnected => throw new ToxException(ToxErrorCode.FriendNotConnected, "The friend is offline."),
                SendMessageResult.Empty => throw new ToxException(ToxErrorCode.Empty, "The message is empty."),
                SendMessageResult.TooLong => throw new ToxException(ToxErrorCode.TooLong, "The message is too long."),
                _ => throw new ToxException(ToxErrorCode.SendQueue, "The send queue is full."),
            };
        }
    }

    /// <summary>Tells the friend whether we are typing.</summary>
    public void SetTyping(uint friendNumber, bool typing)
    {
        lock (_sync)
        {
            RequireFriend(friendNumber);
            _messenger.SetTyping(friendNumber, typing);
        }
    }

    /// <summary>Sends a custom lossless packet; its first byte must be in 160-191.</summary>
    public void SendLosslessPacket(uint friendNumber, byte[] data) => SendCustomPacket(friendNumber, data, lossless: true);

    /// <summary>Sends a custom lossy packet; its first byte must be in 200-254.</summary>
    public void SendLossyPacket(uint friendNumber, byte[] data) => SendCustomPacket(friendNumber, data, lossless: false);

    private void SendCustomPacket(uint friendNumber, byte[] data, bool lossless)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0 || data.Length > MaxCustomPacketSize)
            throw new ToxException(ToxErrorCode.TooLong, $"A custom packet must be 1-{MaxCustomPacketSize} bytes.");
        bool validId = lossless ? data[0] is >= 160 and <= 191 : data[0] is >= 200 and <= 254;
        if (!validId)
            throw new ToxException(ToxErrorCode.InvalidPacket, "Packet id outside the custom range.");

        lock (_sync)
        {
            var friend = RequireFriend(friendNumber);
            if (friend.Status != FriendStatus.Online)
                throw new ToxException(ToxErrorCode.FriendNotConnected, "The friend is offline.");
            if (!_messenger.SendCustomPacket(friendNumber, (byte[])data.Clone(), lossless))
                throw new ToxException(ToxErrorCode.SendQueue, "The send queue is full.");
        }
    }

    // ================================================================ file transfers

    /// <summary>
    /// Offers a file to an online friend and returns its file number. Data is then pulled through
    /// <see cref="FileChunkRequested"/> once the friend accepts.
    /// </summary>
    /// <param name="size">Size in bytes, or <see cref="ulong.MaxValue"/> for a stream of unknown length.</param>
    /// <param name="fileId">32 bytes identifying the file (e.g. to resume it later); random when null.</param>
    public uint FileSend(uint friendNumber, ToxFileKind kind, ulong size, string fileName, byte[]? fileId = null)
    {
        var name = EncodeText(fileName, MaxFileNameLength, nameof(fileName));
        if (fileId is not null && fileId.Length != FileIdLength)
            throw new ArgumentException($"A file id must be {FileIdLength} bytes.", nameof(fileId));
        fileId ??= RandomNumberGenerator.GetBytes(FileIdLength);

        lock (_sync)
        {
            ThrowIfFileError(_messenger.NewFileSender(friendNumber, (uint)kind, size, (byte[])fileId.Clone(), name, out uint file));
            return file;
        }
    }

    public void FileControl(uint friendNumber, uint fileNumber, ToxFileControl control)
    {
        if (!Enum.IsDefined(control))
            throw new ArgumentOutOfRangeException(nameof(control));
        lock (_sync)
            ThrowIfFileError(_messenger.FileControl(friendNumber, fileNumber, (byte)control));
    }

    /// <summary>Before accepting an incoming file, asks the sender to start at <paramref name="position"/> (resume).</summary>
    public void FileSeek(uint friendNumber, uint fileNumber, ulong position)
    {
        lock (_sync)
            ThrowIfFileError(_messenger.FileSeek(friendNumber, fileNumber, position));
    }

    /// <summary>Answers a <see cref="FileChunkRequested"/> event.</summary>
    public void FileSendChunk(uint friendNumber, uint fileNumber, ulong position, ReadOnlySpan<byte> data)
    {
        lock (_sync)
            ThrowIfFileError(_messenger.SendFileData(friendNumber, fileNumber, position, data));
    }

    public byte[] GetFileId(uint friendNumber, uint fileNumber)
    {
        lock (_sync)
        {
            ThrowIfFileError(_messenger.GetFileId(friendNumber, fileNumber, out var id));
            return id;
        }
    }

    /// <summary>SHA-256, as toxcore's tox_hash (used for avatar file ids).</summary>
    public static byte[] Hash(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    private static void ThrowIfFileError(FileResult result)
    {
        switch (result)
        {
            case FileResult.Ok:
                return;
            case FileResult.FriendNotFound:
                throw new ToxException(ToxErrorCode.FriendNotFound, "No such friend.");
            case FileResult.FriendNotConnected:
                throw new ToxException(ToxErrorCode.FriendNotConnected, "The friend is offline.");
            case FileResult.NotFound:
                throw new ToxException(ToxErrorCode.FileNotFound, "No such file transfer.");
            case FileResult.BadPosition:
                throw new ToxException(ToxErrorCode.FileBadPosition, "Unexpected position.");
            case FileResult.BadLength:
                throw new ToxException(ToxErrorCode.FileBadLength, "Unexpected chunk length.");
            case FileResult.NameTooLong:
                throw new ToxException(ToxErrorCode.TooLong, "File name too long.");
            case FileResult.TooMany:
                throw new ToxException(ToxErrorCode.FileTooMany, "Too many concurrent transfers.");
            case FileResult.SendQueue:
            case FileResult.SendFailed:
                throw new ToxException(ToxErrorCode.SendQueue, "The send queue is full.");
            default:
                throw new ToxException(ToxErrorCode.FileInvalidState, $"Operation not allowed now ({result}).");
        }
    }

    private Friend RequireFriend(uint friendNumber) =>
        _messenger.GetFriend(friendNumber) ?? throw new ToxException(ToxErrorCode.FriendNotFound, $"No friend {friendNumber}.");

    // ================================================================ savedata

    /// <summary>The profile (keys, friends, name...), in toxcore's savedata format.</summary>
    public byte[] GetSaveData()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this); // the secret key is wiped on dispose
            var save = new SaveData
            {
                NoSpam = (byte[])_messenger.NoSpam.Clone(),
                SecretKey = _identity.SecretKey,
                DhtNodes = _dht.GetKnownNodes().Take(MaxSavedDhtNodes).ToList(),
                Name = _messenger.Name,
                StatusMessage = _messenger.StatusMessage,
                Status = _messenger.UserStatus,
                TcpRelays = _loaded.TcpRelays,
                PathNodes = _onion.GetBackupNodes(SavedPathNodes),
                OtherSections = _loaded.OtherSections,
            };

            foreach (var (_, f) in _messenger.EnumerateFriends())
            {
                save.Friends.Add(new SavedFriend(f.Status, f.RealPublicKey, f.RequestMessage, f.RequestNoSpam,
                    f.Name, f.StatusMessage, f.UserStatus, f.LastSeen));
            }

            return save.Serialize(_identity.PublicKey);
        }
    }

    /// <summary>The profile encrypted with a passphrase (toxEsave format, readable by qTox).</summary>
    public byte[] GetSaveData(string passphrase) => ToxEncryptSave.Encrypt(GetSaveData(), passphrase);

    // ================================================================ helpers

    internal static string DecodeText(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    private static byte[] EncodeText(string? text, int maxBytes, string paramName)
    {
        ArgumentNullException.ThrowIfNull(text, paramName);
        var bytes = Encoding.UTF8.GetBytes(text);
        if (bytes.Length > maxBytes)
            throw new ToxException(ToxErrorCode.TooLong, $"Text longer than {maxBytes} UTF-8 bytes.");
        return bytes;
    }

    private static byte[] ParseKey(string hex, string paramName)
    {
        ArgumentNullException.ThrowIfNull(hex, paramName);
        try
        {
            var key = Convert.FromHexString(hex);
            if (key.Length == PublicKeySize)
                return key;
        }
        catch (FormatException)
        {
        }
        throw new ToxException(ToxErrorCode.BadBootstrapNode, "A public key must be 64 hex characters.");
    }

    /// <summary>Internals, for tests.</summary>
    internal DhtNode DhtNode => _dht;
    internal OnionClient OnionClient => _onion;

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
                return;
            _disposed = true;

            // Tell online friends we are leaving, so they do not wait for the timeout.
            foreach (var (number, f) in _messenger.EnumerateFriends().ToList())
                if (f.Status == FriendStatus.Online)
                    _friendConnections.WriteLossless(f.FriendConnectionId, [Messenger.Messenger.PacketIdOffline], false);

            _netCrypto.Dispose();
            _onion.Dispose();
            _dht.Dispose();
            _identity.Dispose();
        }

        _ownedTransport?.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
