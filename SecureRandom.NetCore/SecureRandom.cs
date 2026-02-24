using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using PinnedMemory;

namespace SecureRandom.NetCore;

/*
 * This code was adapted from BouncyCastle 1.8.3 SecureRandom.cs, DigestRandomGenerator.cs, and CryptoApiRandomGenerator.cs
 * it has been modified to use Blake2b, and PinnedMemory.
 */
public sealed class SecureRandom : Random, IDisposable
{
    private readonly Blake2b.NetCore.Blake2b _digest;
    private readonly object _syncRoot = new();

    private readonly long _rounds;
    private long _stateCounter;
    private long _seedCounter;
    private readonly PinnedMemory<byte> _state;
    private PinnedMemory<byte> _seed;

    private long _counter = NanoTime(DateTime.UtcNow);
    private bool _disposed;

    /// <summary>
    /// Secure random number generator using Blake2b
    /// </summary>
    /// <param name="rounds">Number of rounds imposed on seeds (Default: 10)</param>
    /// <param name="seed">Seed using OS entropy provider by default</param>
    public SecureRandom(int rounds = 10, bool seed = true)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rounds);

        _rounds = rounds;
        _digest = new Blake2b.NetCore.Blake2b();

        _seed = new PinnedMemory<byte>(new byte[_digest.GetLength()]);
        _seedCounter = 0;

        _state = new PinnedMemory<byte>(new byte[_digest.GetLength()]);
        _stateCounter = 1;

        if (!seed)
            return;

        Span<byte> osSeed = stackalloc byte[_digest.GetLength()];
        RandomNumberGenerator.Fill(osSeed);

        _seedCounter++;
        AddSeedMaterial(osSeed.ToArray());

        _seedCounter++;
        AddSeedMaterial(NextCounterValue());
    }

    public int GetSeedSize() => _digest.GetLength();

    public void SetSeed(byte[] seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(seed);

        _seedCounter++;
        AddSeedMaterial(seed);
    }

    public void SetSeed(long seed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _seedCounter++;
        AddSeedMaterial(seed);
    }

    public override int Next()
    {
        EnsureSeeded();
        return NextInt() & int.MaxValue;
    }

    public override int Next(int maxValue)
    {
        EnsureSeeded();

        if (maxValue < 2)
        {
            if (maxValue < 0)
                throw new ArgumentOutOfRangeException(nameof(maxValue), "cannot be negative");

            return 0;
        }

        int bits;

        // Test whether maxValue is a power of 2
        if ((maxValue & (maxValue - 1)) == 0)
        {
            bits = NextInt() & int.MaxValue;
            return (int)(((long)bits * maxValue) >> 31);
        }

        int result;
        do
        {
            bits = NextInt() & int.MaxValue;
            result = bits % maxValue;
        }
        while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

        return result;
    }

    public override int Next(int minValue, int maxValue)
    {
        EnsureSeeded();

        if (maxValue <= minValue)
        {
            if (maxValue == minValue)
                return minValue;

            throw new ArgumentException("maxValue cannot be less than minValue");
        }

        var diff = maxValue - minValue;
        if (diff > 0)
            return minValue + Next(diff);

        while (true)
        {
            var i = NextInt();

            if (i >= minValue && i < maxValue)
                return i;
        }
    }

    public byte[] NextBytes(int length)
    {
        EnsureSeeded();
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        var result = new byte[length];
        NextBytes(result);
        return result;
    }

    public override void NextBytes(byte[] bytes)
    {
        EnsureSeeded();
        ArgumentNullException.ThrowIfNull(bytes);

        NextBytes(bytes, 0, bytes.Length);
    }

    public void NextBytes(byte[] bytes, int offset, int length)
    {
        EnsureSeeded();
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        if (offset > bytes.Length - length)
            throw new ArgumentException("Offset and length must specify a valid range in the destination buffer.");

        var stateOff = 0;
        GenerateState();

        var end = offset + length;
        for (var i = offset; i < end; ++i)
        {
            if (stateOff == _state.Length)
            {
                GenerateState();
                stateOff = 0;
            }

            bytes[i] = _state[stateOff++];
        }
    }

    private static readonly double DoubleScale = Math.Pow(2.0, 64.0);

    public override double NextDouble()
    {
        EnsureSeeded();
        return Convert.ToDouble((ulong)NextLong()) / DoubleScale;
    }

    public int NextInt()
    {
        EnsureSeeded();

        Span<byte> bytes = stackalloc byte[4];
        NextBytes(bytes.ToArray());
        return BinaryPrimitives.ReadInt32BigEndian(bytes);
    }

    public long NextLong()
    {
        EnsureSeeded();
        return ((long)(uint)NextInt() << 32) | (uint)NextInt();
    }

    private void EnsureSeeded()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_seedCounter == 0)
            throw new InvalidOperationException("Please add seed material, or allow auto seeding before using.");
    }

    private void AddSeedMaterial(byte[] inSeed)
    {
        lock (_syncRoot)
        {
            _digest.UpdateBlock(inSeed, 0, inSeed.Length);
            _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
            _digest.DoFinal(_seed, 0);
        }
    }

    private void AddSeedMaterial(long rSeed)
    {
        lock (_syncRoot)
        {
            AddCounter(rSeed);
            _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
            _digest.DoFinal(_seed, 0);
        }
    }

    private void CycleSeed()
    {
        lock (_syncRoot)
        {
            _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
            AddCounter(_seedCounter++);
            _digest.DoFinal(_seed, 0);
        }
    }

    private void GenerateState()
    {
        lock (_syncRoot)
        {
            AddCounter(_stateCounter++);
            _digest.UpdateBlock(_state.ToArray(), 0, _state.Length);
            _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
            _digest.DoFinal(_state, 0);

            if ((_stateCounter % _rounds) == 0)
            {
                CycleSeed();
            }
        }
    }

    private void AddCounter(long seedVal)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, (ulong)seedVal);
        _digest.UpdateBlock(bytes.ToArray(), 0, bytes.Length);
    }

    private long NextCounterValue() => Interlocked.Increment(ref _counter);

    private static long NanosecondsPerTick = 100L;
    private static long NanoTime(DateTime value) => value.Ticks * NanosecondsPerTick;

    public void Dispose()
    {
        if (_disposed)
            return;

        _digest.Dispose();
        _seed.Dispose();
        _state.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
