using System.Security.Cryptography;
using Tests.Infrastructure;

namespace Tests.Integration;

public class FileTransferTests
{
    /// <summary>Serves chunk requests from <paramref name="content"/> and collects what the receiver gets.</summary>
    private static (MemoryStream Received, Func<bool> Done, Func<bool> SenderDone) Wire(Tox sender, Tox receiver, byte[] content)
    {
        var received = new MemoryStream();
        bool complete = false, senderDone = false;

        sender.FileChunkRequested += (_, e) =>
        {
            if (e.Length == 0)
            {
                senderDone = true;
                return;
            }
            sender.FileSendChunk(e.FriendNumber, e.FileNumber, e.Position, content.AsSpan((int)e.Position, e.Length));
        };
        receiver.FileReceiveRequested += (_, e) => receiver.FileControl(e.FriendNumber, e.FileNumber, ToxFileControl.Resume);
        receiver.FileChunkReceived += (_, e) =>
        {
            if (e.Data.Length == 0)
            {
                complete = true;
                return;
            }
            Assert.Equal(received.Length, (long)e.Position);
            received.Write(e.Data);
        };
        return (received, () => complete, () => senderDone);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(Tox.MaxFileChunkSize)]
    [InlineData(300_000)]
    public void File_IsTransferredIntact(int size)
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, _) = sim.CreateFriends();
        var content = RandomNumberGenerator.GetBytes(size);
        var (received, done, senderDone) = Wire(alice, bob, content);

        string? offeredName = null;
        ulong offeredSize = 0;
        bob.FileReceiveRequested += (_, e) => (offeredName, offeredSize) = (e.FileName, e.Size);

        uint file = alice.FileSend(bobOnAlice, ToxFileKind.Data, (ulong)size, "photo.jpg");
        Assert.True(sim.RunUntil(() => done() && senderDone(), TimeSpan.FromMinutes(2)));

        Assert.Equal("photo.jpg", offeredName);
        Assert.Equal((ulong)size, offeredSize);
        Assert.Equal(content, received.ToArray());
        Assert.Throws<ToxException>(() => alice.GetFileId(bobOnAlice, file)); // finished transfers are gone
    }

    [Fact]
    public void File_SurvivesPacketLoss()
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, _) = sim.CreateFriends();
        sim.Network.LossRate = 0.1;
        var content = RandomNumberGenerator.GetBytes(100_000);
        var (received, done, _) = Wire(alice, bob, content);

        alice.FileSend(bobOnAlice, ToxFileKind.Data, (ulong)content.Length, "lossy.bin");
        Assert.True(sim.RunUntil(done, TimeSpan.FromMinutes(5)));
        Assert.Equal(content, received.ToArray());
    }

    [Fact]
    public void File_CanBeRefused()
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, _) = sim.CreateFriends();
        var controls = new List<ToxFileControl>();
        alice.FileControlReceived += (_, e) => controls.Add(e.Control);
        bob.FileReceiveRequested += (_, e) => bob.FileControl(e.FriendNumber, e.FileNumber, ToxFileControl.Cancel);

        uint file = alice.FileSend(bobOnAlice, ToxFileKind.Avatar, 10, "avatar.png", Tox.Hash("png"u8));
        Assert.True(sim.RunUntil(() => controls.Contains(ToxFileControl.Cancel), TimeSpan.FromSeconds(10)));
        Assert.Throws<ToxException>(() => alice.GetFileId(bobOnAlice, file));
    }

    [Fact]
    public void File_PauseAndResume()
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, aliceOnBob) = sim.CreateFriends();
        var content = RandomNumberGenerator.GetBytes(200_000);
        var (received, done, _) = Wire(alice, bob, content);
        uint? incoming = null;
        bob.FileReceiveRequested += (_, e) => incoming = e.FileNumber;

        alice.FileSend(bobOnAlice, ToxFileKind.Data, (ulong)content.Length, "big.bin");
        Assert.True(sim.RunUntil(() => received.Length > 10_000, TimeSpan.FromSeconds(30)));

        bob.FileControl(aliceOnBob, incoming!.Value, ToxFileControl.Pause);
        sim.RunFor(TimeSpan.FromSeconds(2)); // let in-flight data land
        long paused = received.Length;
        sim.RunFor(TimeSpan.FromSeconds(5));
        Assert.Equal(paused, received.Length);
        Assert.False(done());

        bob.FileControl(aliceOnBob, incoming.Value, ToxFileControl.Resume);
        Assert.True(sim.RunUntil(done, TimeSpan.FromMinutes(2)));
        Assert.Equal(content, received.ToArray());
    }
}
