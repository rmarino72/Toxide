using System.Net;
using System.Security.Cryptography;
using Toxide;
using Toxide.Messenger;
using Toxide.Network;
using Toxide.State;

namespace Tests.State;

public class SaveDataTests
{
    private static byte[] Key(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    private static SaveData Sample() => new()
    {
        NoSpam = [1, 2, 3, 4],
        SecretKey = Key(7),
        Name = "Alice"u8.ToArray(),
        StatusMessage = "away for lunch"u8.ToArray(),
        Status = ToxUserStatus.Away,
        DhtNodes =
        [
            new NodeInfo(TransportProtocol.Udp, new IpPort(IPAddress.Parse("198.51.100.1"), 33445), Key(1)),
            new NodeInfo(TransportProtocol.Udp, new IpPort(IPAddress.Parse("2001:db8::1"), 33446), Key(2)),
        ],
        Friends =
        [
            new SavedFriend(FriendStatus.Confirmed, Key(3), [], [0, 0, 0, 0], "Bob"u8.ToArray(), "hi"u8.ToArray(),
                ToxUserStatus.Busy, 1_700_000_000),
            new SavedFriend(FriendStatus.Added, Key(4), "please add me"u8.ToArray(), [9, 9, 9, 9], [], [],
                ToxUserStatus.None, 0),
        ],
        PathNodes = [new NodeInfo(TransportProtocol.Udp, new IpPort(IPAddress.Parse("198.51.100.2"), 1), Key(5))],
        OtherSections = [(20, [0xC0, 0xFF, 0xEE])], // e.g. conferences, unknown to Toxide
    };

    [Fact]
    public void Serialize_ThenParse_RoundTrips()
    {
        var original = Sample();
        var parsed = SaveData.Parse(original.Serialize(Key(8)));

        Assert.Equal(original.NoSpam, parsed.NoSpam);
        Assert.Equal(original.SecretKey, parsed.SecretKey);
        Assert.Equal(original.Name, parsed.Name);
        Assert.Equal(original.StatusMessage, parsed.StatusMessage);
        Assert.Equal(ToxUserStatus.Away, parsed.Status);
        Assert.Equal(original.DhtNodes.Select(n => n.ToString()), parsed.DhtNodes.Select(n => n.ToString()));
        Assert.Equal(original.PathNodes.Select(n => n.ToString()), parsed.PathNodes.Select(n => n.ToString()));
        Assert.Equal(20, parsed.OtherSections.Single().Type);
        Assert.Equal(new byte[] { 0xC0, 0xFF, 0xEE }, parsed.OtherSections.Single().Data);

        var bob = parsed.Friends[0];
        Assert.Equal(FriendStatus.Confirmed, bob.Status);
        Assert.Equal(Key(3), bob.PublicKey);
        Assert.Equal("Bob"u8.ToArray(), bob.Name);
        Assert.Equal("hi"u8.ToArray(), bob.StatusMessage);
        Assert.Equal(ToxUserStatus.Busy, bob.UserStatus);
        Assert.Equal(1_700_000_000UL, bob.LastSeen);

        var pending = parsed.Friends[1];
        Assert.Equal(FriendStatus.Added, pending.Status);
        Assert.Equal("please add me"u8.ToArray(), pending.RequestMessage);
        Assert.Equal(new byte[] { 9, 9, 9, 9 }, pending.RequestNoSpam);
    }

    [Fact]
    public void Serialize_UsesToxcoreLayout()
    {
        var data = Sample().Serialize(Key(8));

        Assert.Equal(new byte[] { 0, 0, 0, 0, 0x1f, 0x1b, 0xed, 0x15 }, data[..8]); // cookie 0x15ed1b1f, LE
        // First section: keys, 68 bytes, type 1, inner cookie 0x01ce.
        Assert.Equal(new byte[] { 68, 0, 0, 0, 1, 0, 0xce, 0x01 }, data[8..16]);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, data[16..20]);
        Assert.Equal(Key(8), data[20..52]);
        Assert.Equal(Key(7), data[52..84]);
        // Last section: END, empty.
        Assert.Equal(new byte[] { 0, 0, 0, 0, 0xff, 0, 0xce, 0x01 }, data[^8..]);
    }

    [Fact]
    public void Friend_Record_Is2216Bytes()
    {
        var data = new SaveData { SecretKey = Key(1), Friends = [Sample().Friends[0]] }.Serialize(Key(2));
        int friendsHeader = FindSection(data, 3);
        Assert.Equal(2216, BitConverter.ToInt32(data, friendsHeader));
    }

    private static int FindSection(byte[] data, ushort type)
    {
        for (int offset = 8; offset < data.Length;)
        {
            int length = BitConverter.ToInt32(data, offset);
            if (BitConverter.ToUInt16(data, offset + 4) == type)
                return offset;
            offset += 8 + length;
        }
        throw new InvalidOperationException("section not found");
    }

    [Fact]
    public void Parse_RejectsGarbage()
    {
        Assert.Throws<FormatException>(() => SaveData.Parse(RandomNumberGenerator.GetBytes(100)));
        Assert.Throws<FormatException>(() => SaveData.Parse([]));

        var data = Sample().Serialize(Key(8));
        Assert.Throws<FormatException>(() => SaveData.Parse(data[..^20])); // truncated
    }

    [Fact]
    public void EncryptSave_RoundTrips_AndRejectsWrongPassphrase()
    {
        var plain = Sample().Serialize(Key(8));
        var encrypted = ToxEncryptSave.Encrypt(plain, "s3cret");

        Assert.True(ToxEncryptSave.IsEncrypted(encrypted));
        Assert.False(ToxEncryptSave.IsEncrypted(plain));
        Assert.Equal(plain.Length + ToxEncryptSave.ExtraLength, encrypted.Length);
        Assert.Equal(plain, ToxEncryptSave.Decrypt(encrypted, "s3cret"));
        Assert.Throws<CryptographicException>(() => ToxEncryptSave.Decrypt(encrypted, "wrong"));
    }
}
