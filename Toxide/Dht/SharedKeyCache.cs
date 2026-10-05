using System.Security.Cryptography;
using Toxide.Crypto;

namespace Toxide.Dht;

/// <summary>
/// X25519 is the expensive part of crypto_box, and a DHT node talks to the same peers over and
/// over: computing each shared key once is a large saving (toxcore does the same).
/// The cache is bounded because sender keys come from the network: an attacker could otherwise
/// fill memory by sending packets with millions of random keys.
/// </summary>
internal sealed class SharedKeyCache
{
    private readonly ICryptoCore _crypto;
    private readonly byte[] _ownSecretKey;
    private readonly int _capacity;
    private readonly Dictionary<byte[], byte[]> _cache = new(PublicKeyComparer.Instance);

    public SharedKeyCache(ICryptoCore crypto, byte[] ownSecretKey, int capacity = 1024)
    {
        _crypto = crypto;
        _ownSecretKey = ownSecretKey;
        _capacity = capacity;
    }

    public bool TryGet(byte[] theirPublicKey, out byte[] sharedKey)
    {
        if (_cache.TryGetValue(theirPublicKey, out var cached))
        {
            sharedKey = cached;
            return true;
        }

        try
        {
            sharedKey = _crypto.ComputeSharedKey(theirPublicKey, _ownSecretKey);
        }
        catch (CryptographicException)
        {
            sharedKey = [];
            return false; // invalid (low-order) public key
        }

        if (_cache.Count >= _capacity)
            _cache.Clear(); // simple eviction; an LRU can come later

        _cache[(byte[])theirPublicKey.Clone()] = sharedKey;
        return true;
    }
}