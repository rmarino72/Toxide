using System.Buffers.Binary;
using Toxide.Crypto;
using Toxide.Messenger;
using Toxide.Network;

namespace Toxide.State;

internal sealed record SavedFriend(
    FriendStatus Status,
    byte[] PublicKey,
    byte[] RequestMessage,
    byte[] RequestNoSpam,
    byte[] Name,
    byte[] StatusMessage,
    ToxUserStatus UserStatus,
    ulong LastSeen);

/// <summary>
/// The toxcore savedata format, as used by qTox and every other toxcore client (unencrypted form).
///
///   [ u32 0 ][ u32 0x15ed1b1f ] then sections:  [ u32 length ][ u16 type ][ u16 0x01ce ][ data ]
/// All integers are little-endian, except where the original C structs used network byte order.
/// Sections we do not interpret (conferences, group chats) are kept verbatim and written back,
/// so loading and saving a profile through Toxide never loses data another client stored there.
/// </summary>
internal sealed class SaveData
{
    private const uint CookieGlobal = 0x15ed1b1f;
    private const ushort CookieType = 0x01ce;
    private const uint DhtCookieGlobal = 0x0159000d;
    private const ushort DhtCookieType = 0x11ce;
    private const ushort DhtTypeNodes = 4;

    private const ushort TypeNoSpamKeys = 1;
    private const ushort TypeDht = 2;
    private const ushort TypeFriends = 3;
    private const ushort TypeName = 4;
    private const ushort TypeStatusMessage = 5;
    private const ushort TypeStatus = 6;
    private const ushort TypeTcpRelay = 10;
    private const ushort TypePathNode = 11;
    private const ushort TypeEnd = 255;

    // struct Saved_Friend, with its C padding.
    private const int SavedRequestSize = 1024;
    private const int FriendSize = 1 + 32 + SavedRequestSize + 1 + 2 + Messenger.Messenger.MaxNameLength + 2
                                   + Messenger.Messenger.MaxStatusMessageLength + 1 + 2 + 1 + 3 + 4 + 8; // 2216

    public byte[] NoSpam { get; set; } = new byte[ToxId.NoSpamSize];
    public byte[]? SecretKey { get; set; }
    public List<NodeInfo> DhtNodes { get; set; } = [];
    public List<SavedFriend> Friends { get; set; } = [];
    public byte[] Name { get; set; } = [];
    public byte[] StatusMessage { get; set; } = [];
    public ToxUserStatus Status { get; set; }
    public List<NodeInfo> TcpRelays { get; set; } = [];
    public List<NodeInfo> PathNodes { get; set; } = [];

    /// <summary>Sections Toxide does not understand, preserved for round trips.</summary>
    public List<(ushort Type, byte[] Data)> OtherSections { get; set; } = [];

    public static SaveData Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8 || BinaryPrimitives.ReadUInt32LittleEndian(data) != 0
                            || BinaryPrimitives.ReadUInt32LittleEndian(data[4..]) != CookieGlobal)
            throw new FormatException("Not a Tox savedata file (bad header; encrypted profiles must be decrypted first).");

        var save = new SaveData();
        bool hasKeys = false;
        foreach (var (type, section) in ReadSections(data[8..], CookieType))
        {
            switch (type)
            {
                case TypeNoSpamKeys:
                    if (section.Length != 4 + 32 + 32)
                        throw new FormatException("Invalid keys section.");
                    save.NoSpam = section[..4];
                    save.SecretKey = section[36..68];
                    hasKeys = true;
                    break;
                case TypeDht:
                    save.DhtNodes = ParseDht(section);
                    break;
                case TypeFriends:
                    save.Friends = ParseFriends(section);
                    break;
                case TypeName:
                    if (section.Length <= Messenger.Messenger.MaxNameLength)
                        save.Name = section;
                    break;
                case TypeStatusMessage:
                    if (section.Length <= Messenger.Messenger.MaxStatusMessageLength)
                        save.StatusMessage = section;
                    break;
                case TypeStatus:
                    if (section.Length == 1 && section[0] <= (byte)ToxUserStatus.Busy)
                        save.Status = (ToxUserStatus)section[0];
                    break;
                case TypeTcpRelay:
                    save.TcpRelays = UnpackNodes(section);
                    break;
                case TypePathNode:
                    save.PathNodes = UnpackNodes(section);
                    break;
                case TypeEnd:
                    if (!hasKeys)
                        throw new FormatException("Savedata has no keys section.");
                    return save;
                default:
                    save.OtherSections.Add((type, section));
                    break;
            }
        }

        if (!hasKeys)
            throw new FormatException("Savedata has no keys section.");
        return save;
    }

    public byte[] Serialize(byte[] publicKey)
    {
        if (SecretKey is null)
            throw new InvalidOperationException("No secret key to save.");

        using var stream = new MemoryStream();
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], CookieGlobal);
        stream.Write(header);

        var keys = new byte[4 + 32 + 32];
        NoSpam.CopyTo(keys, 0);
        publicKey.CopyTo(keys, 4);
        SecretKey.CopyTo(keys, 36);
        WriteSection(stream, CookieType, TypeNoSpamKeys, keys);

        WriteSection(stream, CookieType, TypeDht, SerializeDht());
        WriteSection(stream, CookieType, TypeFriends, SerializeFriends());
        WriteSection(stream, CookieType, TypeName, Name);
        WriteSection(stream, CookieType, TypeStatusMessage, StatusMessage);
        WriteSection(stream, CookieType, TypeStatus, [(byte)Status]);
        WriteSection(stream, CookieType, TypeTcpRelay, PackNodes(TcpRelays));
        WriteSection(stream, CookieType, TypePathNode, PackNodes(PathNodes));
        foreach (var (type, data) in OtherSections)
            WriteSection(stream, CookieType, type, data);
        WriteSection(stream, CookieType, TypeEnd, []);
        return stream.ToArray();
    }

    // ---------------------------------------------------------------- sections

    private static List<(ushort Type, byte[] Data)> ReadSections(ReadOnlySpan<byte> data, ushort cookie)
    {
        var sections = new List<(ushort, byte[])>();
        while (data.Length >= 8)
        {
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(data);
            uint cookieType = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
            data = data[8..];

            if (data.Length < length)
                throw new FormatException("Savedata truncated.");
            if ((ushort)(cookieType >> 16) != cookie)
                throw new FormatException("Savedata section garbled.");

            var type = (ushort)(cookieType & 0xFFFF);
            sections.Add((type, data[..(int)length].ToArray()));
            data = data[(int)length..];
            if (type == TypeEnd)
                return sections;
        }

        if (!data.IsEmpty)
            throw new FormatException("Unparsed data at the end of the savedata.");
        return sections;
    }

    private static void WriteSection(Stream stream, ushort cookie, ushort type, ReadOnlySpan<byte> data)
    {
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(header[4..], ((uint)cookie << 16) | type);
        stream.Write(header);
        stream.Write(data);
    }

    private static List<NodeInfo> ParseDht(byte[] section)
    {
        if (section.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(section) != DhtCookieGlobal)
            return [];

        var nodes = new List<NodeInfo>();
        try
        {
            foreach (var (type, data) in ReadSections(section.AsSpan(4), DhtCookieType))
                if (type == DhtTypeNodes)
                    nodes.AddRange(UnpackNodes(data));
        }
        catch (FormatException)
        {
            // A damaged node list only costs a slower bootstrap.
        }
        return nodes;
    }

    private byte[] SerializeDht()
    {
        using var stream = new MemoryStream();
        Span<byte> cookie = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(cookie, DhtCookieGlobal);
        stream.Write(cookie);
        WriteSection(stream, DhtCookieType, DhtTypeNodes, PackNodes(DhtNodes));
        return stream.ToArray();
    }

    /// <summary>Packed nodes back to back; stops at the first malformed one.</summary>
    private static List<NodeInfo> UnpackNodes(ReadOnlySpan<byte> data)
    {
        var nodes = new List<NodeInfo>();
        while (!data.IsEmpty && NodeInfo.TryUnpack(data, out var node, out int read))
        {
            nodes.Add(node);
            data = data[read..];
        }
        return nodes;
    }

    private static byte[] PackNodes(List<NodeInfo> nodes)
    {
        var data = new byte[nodes.Sum(n => n.PackedSize)];
        NodeInfo.PackMany(nodes, data);
        return data;
    }

    private static List<SavedFriend> ParseFriends(byte[] section)
    {
        if (section.Length % FriendSize != 0)
            throw new FormatException("Invalid friends section.");

        var friends = new List<SavedFriend>();
        for (int offset = 0; offset < section.Length; offset += FriendSize)
        {
            var f = section.AsSpan(offset, FriendSize);
            byte status = f[0];
            if (status == 0)
                continue;
            if (status > (byte)FriendStatus.Confirmed)
                status = (byte)FriendStatus.Confirmed; // toxcore treats any status >= 3 as a confirmed friend

            int infoSize = Math.Min((int)BinaryPrimitives.ReadUInt16BigEndian(f[1058..]), SavedRequestSize);
            int nameLength = Math.Min((int)BinaryPrimitives.ReadUInt16BigEndian(f[1188..]), Messenger.Messenger.MaxNameLength);
            int statusLength = Math.Min((int)BinaryPrimitives.ReadUInt16BigEndian(f[2198..]), Messenger.Messenger.MaxStatusMessageLength);
            byte userStatus = f[2200];

            friends.Add(new SavedFriend(
                (FriendStatus)status,
                f.Slice(1, 32).ToArray(),
                f.Slice(33, infoSize).ToArray(),
                f.Slice(2204, 4).ToArray(),
                f.Slice(1060, nameLength).ToArray(),
                f.Slice(1190, statusLength).ToArray(),
                userStatus <= (byte)ToxUserStatus.Busy ? (ToxUserStatus)userStatus : ToxUserStatus.None,
                BinaryPrimitives.ReadUInt64BigEndian(f[2208..])));
        }
        return friends;
    }

    private byte[] SerializeFriends()
    {
        var data = new byte[Friends.Count * FriendSize];
        for (int i = 0; i < Friends.Count; i++)
        {
            var saved = Friends[i];
            var f = data.AsSpan(i * FriendSize, FriendSize);
            saved.PublicKey.CopyTo(f[1..]);

            if (saved.Status < FriendStatus.Confirmed)
            {
                f[0] = (byte)saved.Status;
                int infoSize = Math.Min(saved.RequestMessage.Length, SavedRequestSize);
                saved.RequestMessage.AsSpan(0, infoSize).CopyTo(f[33..]);
                BinaryPrimitives.WriteUInt16BigEndian(f[1058..], (ushort)saved.RequestMessage.Length);
                saved.RequestNoSpam.CopyTo(f[2204..]);
            }
            else
            {
                f[0] = (byte)FriendStatus.Confirmed; // "online" is never saved
                saved.Name.CopyTo(f[1060..]);
                BinaryPrimitives.WriteUInt16BigEndian(f[1188..], (ushort)saved.Name.Length);
                saved.StatusMessage.CopyTo(f[1190..]);
                BinaryPrimitives.WriteUInt16BigEndian(f[2198..], (ushort)saved.StatusMessage.Length);
                f[2200] = (byte)saved.UserStatus;
                BinaryPrimitives.WriteUInt64BigEndian(f[2208..], saved.LastSeen);
            }
        }
        return data;
    }
}
