using System.Collections.Concurrent;
using Toxide.Crypto;
using Toxide.State;
using Xunit.Abstractions;

namespace Tests.Interop;

/// <summary>
/// Toxide against the reference implementation (c-toxcore, the library under qTox), over real UDP
/// sockets on localhost. The small network mixes toxcore and Toxide relays, so onion paths and DHT
/// lookups cross both implementations.
/// </summary>
[Collection("toxcore interop")]
public sealed class ToxcoreInteropTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(120);

    private readonly ITestOutputHelper _output;
    private readonly List<ToxPeer> _peers = [];
    private readonly List<Tox> _toxes = [];
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _loops = [];
    private static int _nextPort = 36000;

    public ToxcoreInteropTests(ITestOutputHelper output) => _output = output;

    private static ushort NextPort() => (ushort)Interlocked.Increment(ref _nextPort);

    private ToxPeer StartPeer(string? saveFile = null)
    {
        var peer = ToxPeer.Start(NextPort(), saveFile);
        _peers.Add(peer);
        return peer;
    }

    private Tox StartTox(byte[]? saveData = null)
    {
        ushort port = NextPort();
        var tox = Tox.Create(new ToxOptions
        {
            StartPort = port,
            EndPort = port,
            LocalDiscoveryEnabled = false,
            SaveDataType = saveData is null ? ToxSaveDataType.None : ToxSaveDataType.ToxSave,
            SaveData = saveData,
        });
        _toxes.Add(tox);
        _loops.Add(Task.Run(() => tox.RunAsync(_cts.Token)));
        return tox;
    }

    /// <summary>Three toxcore relays and two Toxide relays, all bootstrapped from each other.</summary>
    private (ToxPeer Peer, Tox Tox) StartNetwork()
    {
        var peers = Enumerable.Range(0, 3).Select(_ => StartPeer()).ToList();
        var toxes = Enumerable.Range(0, 2).Select(_ => StartTox()).ToList();

        foreach (var peer in peers.Skip(1))
            peer.Send($"BOOTSTRAP 127.0.0.1 {peers[0].Port} {peers[0].DhtId}");
        foreach (var tox in toxes)
            tox.Bootstrap("127.0.0.1", peers[0].Port, peers[0].DhtId);
        peers[0].Send($"BOOTSTRAP 127.0.0.1 {toxes[0].UdpPort} {Convert.ToHexString(toxes[0].DhtId)}");
        return (peers[0], toxes[0]);
    }

    private static void BootstrapBoth(Tox tox, ToxPeer peer, (ToxPeer Peer, Tox Tox) network)
    {
        tox.Bootstrap("127.0.0.1", network.Peer.Port, network.Peer.DhtId);
        tox.Bootstrap("127.0.0.1", network.Tox.UdpPort, Convert.ToHexString(network.Tox.DhtId));
        peer.Send($"BOOTSTRAP 127.0.0.1 {network.Peer.Port} {network.Peer.DhtId}");
        peer.Send($"BOOTSTRAP 127.0.0.1 {network.Tox.UdpPort} {Convert.ToHexString(network.Tox.DhtId)}");
    }

    private static void WaitUntil(Func<bool> condition, TimeSpan timeout, string what)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException(what);
            Thread.Sleep(100);
        }
    }

    [ToxcoreFact]
    public void Toxide_AddsToxcoreFriend_MessagesBothWays()
    {
        var network = StartNetwork();
        var peer = StartPeer();
        var tox = StartTox();
        tox.Name = "Toxide";
        peer.Send("NAME toxcore");
        BootstrapBoth(tox, peer, network);

        var messages = new ConcurrentQueue<string>();
        var receipts = new ConcurrentQueue<uint>();
        var names = new ConcurrentQueue<string>();
        tox.FriendMessageReceived += (_, e) => messages.Enqueue(e.Message);
        tox.FriendReadReceipt += (_, e) => receipts.Enqueue(e.MessageId);
        tox.FriendNameChanged += (_, e) => names.Enqueue(e.Text);

        WaitUntil(() => tox.ConnectionStatus == ToxConnection.Udp, Timeout, "Toxide did not come online");
        peer.WaitFor(l => l.StartsWith("SELF ") && l != "SELF 0", Timeout);
        _output.WriteLine("both online");

        uint friend = tox.AddFriend(ToxId.Parse(peer.Address), "hello from Toxide");
        var request = peer.WaitFor(l => l.StartsWith("REQUEST "), Timeout);
        Assert.Equal($"REQUEST {Convert.ToHexString(tox.PublicKey)} hello from Toxide", request);
        _output.WriteLine("toxcore received the friend request");

        peer.Send($"ACCEPT {Convert.ToHexString(tox.PublicKey)}");
        peer.WaitFor(l => l.StartsWith("CONN 0 ") && l != "CONN 0 0", Timeout);
        WaitUntil(() => tox.GetFriendConnectionStatus(friend) == ToxConnection.Udp, Timeout, "Toxide did not see the friend online");
        _output.WriteLine("friends connected");

        uint id = tox.SendMessage(friend, "ping from Toxide");
        Assert.Equal("MSG 0 0 ping from Toxide", peer.WaitFor(l => l.StartsWith("MSG "), Timeout));
        WaitUntil(() => receipts.Contains(id), Timeout, "no read receipt from toxcore");

        peer.Send("MSG 0 pong from toxcore");
        WaitUntil(() => messages.Contains("pong from toxcore"), Timeout, "Toxide did not receive the message");
        var sent = peer.WaitFor(l => l.StartsWith("SENT "), Timeout).Split(' ');
        peer.WaitFor(l => l == $"RECEIPT 0 {sent[1]}", Timeout);

        WaitUntil(() => names.Contains("toxcore"), Timeout, "toxcore's name did not arrive");
        peer.WaitFor(l => l == "NAME 0 Toxide", Timeout);
    }

    [ToxcoreFact]
    public void Toxcore_AddsToxideFriend()
    {
        var network = StartNetwork();
        var peer = StartPeer();
        var tox = StartTox();
        BootstrapBoth(tox, peer, network);

        var requests = new ConcurrentQueue<FriendRequestEventArgs>();
        tox.FriendRequestReceived += (_, e) => requests.Enqueue(e);
        var messages = new ConcurrentQueue<string>();
        tox.FriendMessageReceived += (_, e) => messages.Enqueue(e.Message);

        WaitUntil(() => tox.ConnectionStatus == ToxConnection.Udp, Timeout, "Toxide did not come online");
        peer.WaitFor(l => l.StartsWith("SELF ") && l != "SELF 0", Timeout);

        peer.Send($"ADD {tox.Address} hi Toxide, toxcore here");
        WaitUntil(() => !requests.IsEmpty, Timeout, "Toxide did not receive the friend request");
        Assert.True(requests.TryPeek(out var request));
        Assert.Equal("hi Toxide, toxcore here", request.Message);
        Assert.Equal(peer.PublicKey, Convert.ToHexString(request.PublicKey));

        uint friend = tox.AddFriendNoRequest(request.PublicKey);
        peer.WaitFor(l => l.StartsWith("CONN 0 ") && l != "CONN 0 0", Timeout);
        WaitUntil(() => tox.GetFriendConnectionStatus(friend) == ToxConnection.Udp, Timeout, "friend not online in Toxide");

        peer.Send("MSG 0 first message");
        WaitUntil(() => messages.Contains("first message"), Timeout, "message not received");
    }

    [ToxcoreFact]
    public void SaveData_RoundTripsBetweenImplementations()
    {
        var dir = Directory.CreateTempSubdirectory("toxide-interop");
        try
        {
            // toxcore -> Toxide
            var peer = StartPeer();
            peer.Send("NAME saved by toxcore");
            var file = Path.Combine(dir.FullName, "toxcore.tox");
            peer.Send($"SAVE {file}");
            peer.WaitFor(l => l.StartsWith("SAVED "), TimeSpan.FromSeconds(10));

            var tox = StartTox(File.ReadAllBytes(file));
            Assert.Equal(peer.Address, tox.Address.ToString());
            Assert.Equal("saved by toxcore", tox.Name);

            // Toxide -> toxcore
            var other = StartTox();
            other.Name = "saved by Toxide";
            other.AddFriendNoRequest(Convert.FromHexString(peer.PublicKey));
            var mine = Path.Combine(dir.FullName, "toxide.tox");
            File.WriteAllBytes(mine, other.GetSaveData());

            var restored = StartPeer(mine);
            Assert.Equal(other.Address.ToString(), restored.Address);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    /// <summary>A Toxide client and a toxcore client, friends and connected (toxcore friend 0).</summary>
    private (ToxPeer Peer, Tox Tox, uint Friend) ConnectFriends()
    {
        var network = StartNetwork();
        var peer = StartPeer();
        var tox = StartTox();
        BootstrapBoth(tox, peer, network);

        WaitUntil(() => tox.ConnectionStatus == ToxConnection.Udp, Timeout, "Toxide did not come online");
        peer.WaitFor(l => l.StartsWith("SELF ") && l != "SELF 0", Timeout);
        uint friend = tox.AddFriend(ToxId.Parse(peer.Address), "files?");
        peer.WaitFor(l => l.StartsWith("REQUEST "), Timeout);
        peer.Send($"ACCEPT {Convert.ToHexString(tox.PublicKey)}");
        WaitUntil(() => tox.GetFriendConnectionStatus(friend) == ToxConnection.Udp, Timeout, "friends did not connect");
        return (peer, tox, friend);
    }

    private static byte[] Pattern(int size) => Enumerable.Range(0, size).Select(i => (byte)((i * 31 + 7) & 0xff)).ToArray();

    [ToxcoreFact]
    public void FileTransfer_BothWays()
    {
        var (peer, tox, friend) = ConnectFriends();

        // Toxide -> toxcore
        var outgoing = System.Security.Cryptography.RandomNumberGenerator.GetBytes(250_000);
        tox.FileChunkRequested += (_, e) =>
        {
            if (e.Length > 0)
                tox.FileSendChunk(e.FriendNumber, e.FileNumber, e.Position, outgoing.AsSpan((int)e.Position, e.Length));
        };
        tox.FileSend(friend, ToxFileKind.Data, (ulong)outgoing.Length, "from-toxide.bin");
        Assert.StartsWith("FILERECV 0 65536 0 250000 from-toxide.bin", peer.WaitFor(l => l.StartsWith("FILERECV "), Timeout));
        var done = peer.WaitFor(l => l.StartsWith("FILEDONE "), Timeout).Split(' ');
        Assert.Equal("250000", done[3]);
        Assert.Equal(Convert.ToHexString(Tox.Hash(outgoing)), done[4]);

        // toxcore -> Toxide
        var incoming = new MemoryStream();
        bool complete = false;
        string? name = null;
        tox.FileReceiveRequested += (_, e) =>
        {
            name = e.FileName;
            tox.FileControl(e.FriendNumber, e.FileNumber, ToxFileControl.Resume);
        };
        tox.FileChunkReceived += (_, e) =>
        {
            if (e.Data.Length == 0)
                complete = true;
            else
                incoming.Write(e.Data);
        };
        peer.Send("FILESEND 0 123456 from-toxcore.bin");
        WaitUntil(() => complete, Timeout, "file from toxcore not received");
        Assert.Equal("from-toxcore.bin", name);
        Assert.Equal(Pattern(123456), incoming.ToArray());
        peer.WaitFor(l => l.StartsWith("FILESENT "), Timeout);
    }

    [ToxcoreFact]
    public void EncryptedSaveData_RoundTripsBetweenImplementations()
    {
        var dir = Directory.CreateTempSubdirectory("toxide-interop");
        try
        {
            // toxcore encrypts -> Toxide decrypts
            var peer = StartPeer();
            var file = Path.Combine(dir.FullName, "toxcore-encrypted.tox");
            peer.Send($"SAVEENC {file} correct horse");
            peer.WaitFor(l => l.StartsWith("SAVED "), TimeSpan.FromSeconds(30));

            var encrypted = File.ReadAllBytes(file);
            Assert.True(ToxEncryptSave.IsEncrypted(encrypted));
            Assert.Throws<ToxException>(() => Tox.Create(new ToxOptions
            {
                StartPort = 0, EndPort = 0, SaveDataType = ToxSaveDataType.ToxSave, SaveData = encrypted,
                SaveDataPassphrase = "wrong",
            }));
            using (var tox = Tox.Create(new ToxOptions
                   {
                       StartPort = 0, EndPort = 0, LocalDiscoveryEnabled = false, SaveDataType = ToxSaveDataType.ToxSave,
                       SaveData = encrypted, SaveDataPassphrase = "correct horse",
                   }))
            {
                Assert.Equal(peer.Address, tox.Address.ToString());
            }

            // Toxide encrypts -> toxcore decrypts
            var other = StartTox();
            var mine = Path.Combine(dir.FullName, "toxide-encrypted.tox");
            File.WriteAllBytes(mine, other.GetSaveData("battery staple"));
            var psi = ToxPeer.Start(NextPort(), mine, "battery staple");
            _peers.Add(psi);
            Assert.Equal(other.Address.ToString(), psi.Address);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { Task.WaitAll(_loops.ToArray(), TimeSpan.FromSeconds(5)); }
        catch (AggregateException) { }
        foreach (var tox in _toxes)
            tox.Dispose();
        foreach (var peer in _peers)
            peer.Dispose();
        _cts.Dispose();
    }
}
