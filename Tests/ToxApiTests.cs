using Tests.Infrastructure;
using Toxide.Crypto;

namespace Tests;

public class ToxApiTests
{
    [Fact]
    public void Create_BindsUdpPort_AndHasValidAddress()
    {
        using var tox = Tox.Create(new ToxOptions { StartPort = 0, EndPort = 0, LocalDiscoveryEnabled = false });

        Assert.NotEqual(0, tox.UdpPort);
        Assert.True(ToxId.TryParse(tox.Address.ToString(), out var parsed));
        Assert.Equal(tox.PublicKey, parsed.PublicKey);
        Assert.Equal(ToxConnection.None, tox.ConnectionStatus);
        Assert.Empty(tox.FriendList);
    }

    [Fact]
    public void Profile_RoundTripsThroughSaveData()
    {
        using var sim = new Simulation();
        var tox = sim.AddNode();
        tox.Name = "Ålice 🙂";
        tox.StatusMessage = "on holiday";
        tox.Status = ToxUserStatus.Away;
        tox.NoSpam = 0xDEADBEEF;
        var friendKey = new ManagedCryptoCore().GenerateKeyPair().PublicKey;
        tox.AddFriendNoRequest(friendKey);

        var restored = sim.AddNode(tox.GetSaveData());

        Assert.Equal(tox.Address.ToString(), restored.Address.ToString());
        Assert.Equal(0xDEADBEEF, restored.NoSpam);
        Assert.Equal("Ålice 🙂", restored.Name);
        Assert.Equal("on holiday", restored.StatusMessage);
        Assert.Equal(ToxUserStatus.Away, restored.Status);
        Assert.Equal(friendKey, restored.GetFriendPublicKey(restored.FriendList.Single()));
    }

    [Fact]
    public void EncryptedProfile_NeedsThePassphrase()
    {
        using var sim = new Simulation();
        var tox = sim.AddNode();
        var encrypted = tox.GetSaveData("pa55");

        var restored = sim.AddNode(encrypted, "pa55");
        Assert.Equal(tox.Address.ToString(), restored.Address.ToString());

        var error = Assert.Throws<ToxException>(() => Tox.Create(new ToxOptions
        {
            StartPort = 0, EndPort = 0, SaveDataType = ToxSaveDataType.ToxSave, SaveData = encrypted,
        }));
        Assert.Equal(ToxErrorCode.BadSaveData, error.Code);
    }

    [Fact]
    public void SecretKeySaveData_KeepsTheIdentity()
    {
        using var first = Tox.Create(new ToxOptions { StartPort = 0, EndPort = 0, LocalDiscoveryEnabled = false });
        using var second = Tox.Create(new ToxOptions
        {
            StartPort = 0, EndPort = 0, LocalDiscoveryEnabled = false,
            SaveDataType = ToxSaveDataType.SecretKey, SaveData = first.SecretKey,
        });

        Assert.Equal(first.PublicKey, second.PublicKey);
    }

    [Fact]
    public void ChangingNoSpam_ChangesTheAddress()
    {
        using var sim = new Simulation();
        var tox = sim.AddNode();
        var before = tox.Address.ToString();

        tox.NoSpam = 42;

        Assert.NotEqual(before, tox.Address.ToString());
        Assert.Equal(before[..64], tox.Address.ToString()[..64]); // same public key
    }

    [Fact]
    public void InvalidArguments_AreReported()
    {
        using var sim = new Simulation();
        var tox = sim.AddNode();
        var other = sim.AddNode();

        Assert.Equal(ToxErrorCode.TooLong, Assert.Throws<ToxException>(() => tox.Name = new string('x', 129)).Code);
        Assert.Equal(ToxErrorCode.OwnKey, Assert.Throws<ToxException>(() => tox.AddFriend(tox.Address, "me")).Code);
        Assert.Equal(ToxErrorCode.NoMessage, Assert.Throws<ToxException>(() => tox.AddFriend(other.Address, "")).Code);

        uint friend = tox.AddFriend(other.Address, "hi");
        Assert.Equal(ToxErrorCode.FriendAlreadyAdded, Assert.Throws<ToxException>(() => tox.AddFriend(other.Address, "again")).Code);
        Assert.Equal(ToxErrorCode.FriendNotConnected, Assert.Throws<ToxException>(() => tox.SendMessage(friend, "x")).Code);
        Assert.Equal(ToxErrorCode.FriendNotFound, Assert.Throws<ToxException>(() => tox.SendMessage(99, "x")).Code);
        Assert.Equal(ToxErrorCode.InvalidPacket,
            Assert.Throws<ToxException>(() => tox.SendLosslessPacket(friend, [64, 1])).Code);
        Assert.Throws<ToxException>(() => tox.Bootstrap("127.0.0.1", 1, "not-a-key"));

        Assert.True(tox.DeleteFriend(friend));
        Assert.False(tox.FriendExists(friend));
        Assert.False(tox.DeleteFriend(friend));
    }

    [Fact]
    public async Task Tox_IsUsableFromSeveralThreads()
    {
        using var sim = new Simulation();
        var tox = sim.AddNode();
        var errors = 0;

        var workers = Enumerable.Range(0, 4).Select(i => Task.Run(() =>
        {
            try
            {
                for (int n = 0; n < 200; n++)
                {
                    tox.Name = $"name {i} {n}";
                    _ = tox.Address;
                    _ = tox.FriendList;
                    tox.Iterate();
                }
            }
            catch
            {
                Interlocked.Increment(ref errors);
            }
        })).ToArray();

        await Task.WhenAll(workers);
        Assert.Equal(0, errors);
    }

    [Fact]
    public void NoSpam_UsesToxcoreByteOrder()
    {
        using var sim = new Simulation();
        var tox = sim.AddNode();
        tox.NoSpam = 0x12345678;
        Assert.Equal("12345678", tox.Address.ToString()[64..72]);
        Assert.Equal(0x12345678u, tox.NoSpam);
    }

    [Fact]
    public void Dispose_PreventsSavingAWipedKey()
    {
        var tox = Tox.Create(new ToxOptions { StartPort = 0, EndPort = 0, LocalDiscoveryEnabled = false });
        tox.Dispose();
        Assert.Throws<ObjectDisposedException>(() => tox.GetSaveData());
        Assert.Throws<ObjectDisposedException>(() => tox.SecretKey);
    }

    [Fact]
    public void DeletedFriend_CanSendANewRequest()
    {
        using var sim = new Simulation();
        var (alice, bob, bobOnAlice, aliceOnBob) = sim.CreateFriends();
        var requests = 0;
        bob.FriendRequestReceived += (_, _) => requests++; // CreateFriends' handler accepts again

        Assert.True(bob.DeleteFriend(aliceOnBob));
        Assert.True(alice.DeleteFriend(bobOnAlice));
        sim.RunFor(TimeSpan.FromSeconds(5));
        alice.AddFriend(bob.Address, "me again");

        Assert.True(sim.RunUntil(() => requests == 1 && bob.FriendList.Count == 1, TimeSpan.FromMinutes(2)));
    }
}
