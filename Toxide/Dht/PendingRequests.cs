using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Toxide.Network;

namespace Toxide.Dht;

internal enum RequestKind
{
    Ping,
    Nodes,
}

/// <param name="Target">For nodes requests: the key we asked about (our own key, or a friend's DHT key).</param>
internal sealed record PendingRequest(RequestKind Kind, IpPort Destination, byte[] PublicKey, DateTimeOffset SentAt,
    byte[]? Target = null);

/// <summary>
/// Requests waiting for an answer, indexed by their random 8-byte ID.
/// A response is accepted only if its ID matches a request we sent, to the same node, of the same
/// kind, within the timeout. This stops replayed or unsolicited responses from injecting nodes.
/// (toxcore implements the same idea with its "ping array".)
/// </summary>
internal sealed class PendingRequests
{
    private readonly Dictionary<ulong, PendingRequest> _requests = new();
    private readonly TimeSpan _timeout;
    private readonly int _capacity;

    public PendingRequests(TimeSpan timeout, int capacity)
    {
        _timeout = timeout;
        _capacity = capacity;
    }

    public int Count => _requests.Count;

    public bool TryAdd(PendingRequest request, DateTimeOffset now, out ulong id)
    {
        if (_requests.Count >= _capacity)
        {
            Prune(now);
            if (_requests.Count >= _capacity)
            {
                id = 0;
                return false;
            }
        }

        do id = RandomId();
        while (_requests.ContainsKey(id));

        _requests[id] = request;
        return true;
    }

    /// <summary>Consumes the request if the response matches it; a mismatch leaves it pending.</summary>
    public bool TryComplete(ulong id, RequestKind kind, IpPort source, ReadOnlySpan<byte> publicKey, DateTimeOffset now,
        [NotNullWhen(true)] out PendingRequest? completed)
    {
        completed = null;
        if (!_requests.TryGetValue(id, out var request))
            return false;

        if (request.Kind != kind || request.Destination != source || !publicKey.SequenceEqual(request.PublicKey))
            return false;

        _requests.Remove(id);
        if (now - request.SentAt > _timeout)
            return false;

        completed = request;
        return true;
    }

    public bool IsPending(ReadOnlySpan<byte> publicKey)
    {
        foreach (var request in _requests.Values)
            if (publicKey.SequenceEqual(request.PublicKey))
                return true;
        return false;
    }

    public void Prune(DateTimeOffset now)
    {
        foreach (var (id, request) in _requests.ToList())
            if (now - request.SentAt > _timeout)
                _requests.Remove(id);
    }

    private static ulong RandomId()
    {
        Span<byte> bytes = stackalloc byte[8];
        ulong value;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            value = BinaryPrimitives.ReadUInt64BigEndian(bytes);
        } while (value == 0);
        return value;
    }
}