using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Toxide.Onion;

/// <summary>
/// Stateless proof that a peer received a value from us recently (toxcore's timed_auth):
/// HMAC(key, time window || data). A value is accepted during its own window and the next one,
/// so it lives between one and two timeouts. Used as the announce "ping id": a node can only
/// store an announcement after proving it can receive our responses at the address it claims.
/// </summary>
internal sealed class TimedAuth
{
    public const int Size = 32;

    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly TimeSpan _timeout;

    public TimedAuth(TimeSpan timeout) => _timeout = timeout;

    public byte[] Generate(DateTimeOffset now, ReadOnlySpan<byte> data) => Compute(Window(now), data);

    public bool Check(DateTimeOffset now, ReadOnlySpan<byte> data, ReadOnlySpan<byte> auth)
    {
        if (auth.Length != Size)
            return false;

        long window = Window(now);
        return CryptographicOperations.FixedTimeEquals(Compute(window, data), auth)
               || CryptographicOperations.FixedTimeEquals(Compute(window - 1, data), auth);
    }

    private long Window(DateTimeOffset now) => now.ToUnixTimeSeconds() / (long)_timeout.TotalSeconds;

    private byte[] Compute(long window, ReadOnlySpan<byte> data)
    {
        var input = new byte[sizeof(long) + data.Length];
        BinaryPrimitives.WriteInt64BigEndian(input, window);
        data.CopyTo(input.AsSpan(sizeof(long)));
        return HMACSHA256.HashData(_key, input);
    }
}
