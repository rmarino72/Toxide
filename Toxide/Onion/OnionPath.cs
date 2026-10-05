using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Onion;

/// <summary>
/// Three relay nodes and the keys used to talk to each of them.
/// Node 1 sees our DHT key (it sees our IP anyway); nodes 2 and 3 get fresh random keys, so
/// they cannot link the request to us. The path is chosen once and reused until it expires.
/// </summary>
internal sealed class OnionPath
{
    private OnionPath(NodeInfo[] nodes, byte[] publicKey1, byte[] sharedKey1, byte[] publicKey2, byte[] sharedKey2,
        byte[] publicKey3, byte[] sharedKey3)
    {
        Nodes = nodes;
        PublicKey1 = publicKey1;
        SharedKey1 = sharedKey1;
        PublicKey2 = publicKey2;
        SharedKey2 = sharedKey2;
        PublicKey3 = publicKey3;
        SharedKey3 = sharedKey3;
    }

    public NodeInfo[] Nodes { get; }

    public IpPort Endpoint1 => Nodes[0].Endpoint;
    public IpPort Endpoint2 => Nodes[1].Endpoint;
    public IpPort Endpoint3 => Nodes[2].Endpoint;

    public byte[] PublicKey1 { get; }
    public byte[] SharedKey1 { get; }
    public byte[] PublicKey2 { get; }
    public byte[] SharedKey2 { get; }
    public byte[] PublicKey3 { get; }
    public byte[] SharedKey3 { get; }

    /// <summary>Identifier echoed in sendback data: its low bits are the slot, the rest are random.</summary>
    public uint PathNumber { get; set; }

    public static OnionPath? Create(ICryptoCore crypto, byte[] dhtPublicKey, byte[] dhtSecretKey, IReadOnlyList<NodeInfo> nodes)
    {
        if (nodes.Count != OnionPacket.PathLength)
            return null;

        if (!crypto.TryShared(nodes[0].PublicKey, dhtSecretKey, out var shared1))
            return null;

        using var temp2 = crypto.GenerateKeyPair();
        using var temp3 = crypto.GenerateKeyPair();
        if (!crypto.TryShared(nodes[1].PublicKey, temp2.SecretKey, out var shared2)
            || !crypto.TryShared(nodes[2].PublicKey, temp3.SecretKey, out var shared3))
            return null;

        return new OnionPath(nodes.ToArray(), dhtPublicKey, shared1,
            (byte[])temp2.PublicKey.Clone(), shared2, (byte[])temp3.PublicKey.Clone(), shared3);
    }
}
