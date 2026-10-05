using System.Buffers.Binary;
using System.Numerics;

namespace Toxide.Crypto;

/// <summary>
/// Salsa20/20 family, implemented from the specification (https://cr.yp.to/snuffle/spec.pdf).
///
/// The core works on a 4x4 matrix of 32-bit words (64 bytes):
///   [ c0  k0  k1  k2 ]
///   [ k3  c1  i0  i1 ]
///   [ i2  i3  c2  k4 ]
///   [ k5  k6  k7  c3 ]
/// c = constants "expand 32-byte k", k = 256-bit key, i = 128-bit input (nonce + counter).
/// Only three operations are used: 32-bit addition, rotation and XOR (ARX), so the code
/// runs in constant time with no lookup tables.
/// </summary>
internal static class Salsa20
{
    public const int BlockSize = 64;
    public const int KeySize = 32;

    // "expand 32-byte k" as four little-endian words.
    private const uint C0 = 0x61707865, C1 = 0x3320646e, C2 = 0x79622d32, C3 = 0x6b206574;

    /// <summary>
    /// HSalsa20: runs the 20 rounds and returns 8 of the 16 words, WITHOUT the final addition.
    /// It is a key-derivation function: (32-byte key, 16-byte input) -> 32-byte subkey.
    /// Used twice: to turn the X25519 secret into the shared key, and inside XSalsa20.
    /// </summary>
    public static void HSalsa20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input16, Span<byte> output32)
    {
        Span<uint> x = stackalloc uint[16];
        InitState(x, key, input16);
        DoubleRounds(x);

        // Diagonal words (constants positions) + input positions.
        ReadOnlySpan<int> picks = [0, 5, 10, 15, 6, 7, 8, 9];
        for (int i = 0; i < picks.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output32[(i * 4)..], x[picks[i]]);

        x.Clear();
    }

    /// <summary>
    /// XSalsa20 keystream: extends Salsa20's 8-byte nonce to 24 bytes.
    ///   subkey = HSalsa20(key, nonce[0..16])
    ///   stream = Salsa20(subkey, nonce[16..24], counter = 0, 1, 2, ...)
    /// A 24-byte nonce can be chosen at random with negligible collision risk.
    /// </summary>
    public static void XSalsa20Stream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce24, Span<byte> output)
    {
        Span<byte> subKey = stackalloc byte[KeySize];
        HSalsa20(key, nonce24[..16], subKey);

        Span<byte> block = stackalloc byte[BlockSize];
        ulong counter = 0;
        for (int offset = 0; offset < output.Length; offset += BlockSize, counter++)
        {
            Block(subKey, nonce24[16..24], counter, block);
            int n = Math.Min(BlockSize, output.Length - offset);
            block[..n].CopyTo(output[offset..]);
        }

        subKey.Clear();
        block.Clear();
    }

    /// <summary>
    /// One Salsa20 block: 20 rounds, then each word is added to the initial state.
    /// The addition makes the function non-invertible (without it, one could run the rounds backwards).
    /// </summary>
    private static void Block(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce8, ulong counter, Span<byte> output64)
    {
        Span<byte> input16 = stackalloc byte[16];
        nonce8.CopyTo(input16);
        BinaryPrimitives.WriteUInt64LittleEndian(input16[8..], counter);

        Span<uint> state = stackalloc uint[16];
        Span<uint> x = stackalloc uint[16];
        InitState(state, key, input16);
        state.CopyTo(x);
        DoubleRounds(x);

        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output64[(i * 4)..], unchecked(x[i] + state[i]));

        state.Clear();
        x.Clear();
    }

    private static void InitState(Span<uint> s, ReadOnlySpan<byte> key, ReadOnlySpan<byte> input16)
    {
        s[0] = C0;
        for (int i = 0; i < 4; i++) s[1 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(i * 4)..]);
        s[5] = C1;
        for (int i = 0; i < 4; i++) s[6 + i] = BinaryPrimitives.ReadUInt32LittleEndian(input16[(i * 4)..]);
        s[10] = C2;
        for (int i = 0; i < 4; i++) s[11 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(16 + i * 4)..]);
        s[15] = C3;
    }

    /// <summary>
    /// 10 double rounds = 20 rounds.
    /// A column round mixes each column, a row round mixes each row:
    /// after two rounds every output word depends on every input word.
    /// </summary>
    private static void DoubleRounds(Span<uint> x)
    {
        for (int i = 0; i < 10; i++)
        {
            // Column round
            QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
            QuarterRound(ref x[5], ref x[9], ref x[13], ref x[1]);
            QuarterRound(ref x[10], ref x[14], ref x[2], ref x[6]);
            QuarterRound(ref x[15], ref x[3], ref x[7], ref x[11]);

            // Row round
            QuarterRound(ref x[0], ref x[1], ref x[2], ref x[3]);
            QuarterRound(ref x[5], ref x[6], ref x[7], ref x[4]);
            QuarterRound(ref x[10], ref x[11], ref x[8], ref x[9]);
            QuarterRound(ref x[15], ref x[12], ref x[13], ref x[14]);
        }
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        unchecked
        {
            b ^= BitOperations.RotateLeft(a + d, 7);
            c ^= BitOperations.RotateLeft(b + a, 9);
            d ^= BitOperations.RotateLeft(c + b, 13);
            a ^= BitOperations.RotateLeft(d + c, 18);
        }
    }
}