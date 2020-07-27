using System;
using System.Threading;
using PinnedMemory;

namespace SecureRandom.NetCore
{
    /*
     * This code was adapted from BouncyCastle 1.8.3 SecureRandom.cs, DigestRandomGenerator.cs, and CryptoApiRandomGenerator.cs
     * it has been modified to use Blake2b, and PinnedMemory.
     */
    public class SecureRandom : Random, IDisposable
    {
        private readonly Blake2b.NetCore.Blake2b _digest;

        private readonly long _rounds;
        private long _stateCounter;
        private long _seedCounter;
        private readonly PinnedMemory<byte> _state;
        private PinnedMemory<byte> _seed;

        private long _counter = NanoTime(DateTime.UtcNow);

        /// <summary>
        /// Secure random number generator using Blake2b
        /// </summary>
        /// <param name="rounds">Number of rounds imposed on seeds (Default: 10)</param>
        /// <param name="seed">Auto seed by nano time, and digest size</param>
        public SecureRandom(int rounds = 10, bool seed = true)
        {
            _rounds = rounds;
            _digest = new Blake2b.NetCore.Blake2b();

            _seed = new PinnedMemory<byte>(new byte[_digest.GetLength()]);
            _seedCounter = 0;

            _state = new PinnedMemory<byte>(new byte[_digest.GetLength()]);
            _stateCounter = 1;

            if (!seed) 
                return;

            _seedCounter = 2;
            AddSeedMaterial(NextCounterValue());
            AddSeedMaterial(NextBytes(_digest.GetLength()));
        }

        public int GetSeedSize()
        {
            return _digest.GetLength();
        }

        public virtual void SetSeed(byte[] seed)
        {
            _seedCounter++;
            AddSeedMaterial(seed);
        }

        public virtual void SetSeed(long seed)
        {
            _seedCounter++;
            AddSeedMaterial(seed);
        }

        public override int Next()
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            return NextInt() & int.MaxValue;
        }

        public override int Next(int maxValue)
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            if (maxValue < 2)
            {
                if (maxValue < 0)
                    throw new ArgumentOutOfRangeException("maxValue", "cannot be negative");

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
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            if (maxValue <= minValue)
            {
                if (maxValue == minValue)
                    return minValue;

                throw new ArgumentException("maxValue cannot be less than minValue");
            }

            var diff = maxValue - minValue;
            if (diff > 0)
                return minValue + Next(diff);

            for (;;)
            {
                var i = NextInt();

                if (i >= minValue && i < maxValue)
                    return i;
            }
        }

        public byte[] NextBytes(int length)
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            var result = new byte[length];
            NextBytes(result);
            return result;
        }

        public override void NextBytes(byte[] bytes)
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            NextBytes(bytes, 0, bytes.Length);
        }

        public virtual void NextBytes(byte[] bytes, int offset, int length)
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

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
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            return Convert.ToDouble((ulong) NextLong()) / DoubleScale;
        }

        public virtual int NextInt()
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            var bytes = new byte[4];
            NextBytes(bytes);

            uint result = bytes[0];
            result <<= 8;
            result |= bytes[1];
            result <<= 8;
            result |= bytes[2];
            result <<= 8;
            result |= bytes[3];
            return (int)result;
        }

        public virtual long NextLong()
        {
            if (_seedCounter == 0)
                throw new ArgumentNullException("_seed", "Please add seed material, or allow auto seeding before using.");

            return ((long)(uint) NextInt() << 32) | (long)(uint) NextInt();
        }

        private void AddSeedMaterial(byte[] inSeed)
        {
            lock (this)
            {
                _digest.UpdateBlock(inSeed, 0, inSeed.Length);
                _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
                _digest.DoFinal(_seed, 0);
            }
        }

        private void AddSeedMaterial(long rSeed)
        {
            lock (this)
            {
                AddCounter(rSeed);
                _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
                _digest.DoFinal(_seed, 0);
            }
        }

        private void CycleSeed()
        {
            lock (this)
            {
                _digest.UpdateBlock(_seed.ToArray(), 0, _seed.Length);
                AddCounter(_seedCounter++);
                _digest.DoFinal(_seed, 0);
            }
        }

        private void GenerateState()
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

        private void ClearSeed()
        {
            _seed?.Dispose();
            _seed = new PinnedMemory<byte>(new byte[_digest.GetLength()]);
            _seedCounter = 1;
        }

        private void AddCounter(long seedVal)
        {
            var bytes = new byte[8];
            UInt64_To_LE((ulong)seedVal, bytes);
            lock (this)
            {
                _digest.UpdateBlock(bytes, 0, bytes.Length);
            }
        }

        private long NextCounterValue()
        {
            return Interlocked.Increment(ref _counter);
        }

        private void UInt64_To_LE(ulong n, byte[] bs)
        {
            UInt32_To_LE((uint)(n), bs);
            UInt32_To_LE((uint)(n >> 32), bs, 4);
        }

        private void UInt32_To_LE(uint n, byte[] bs)
        {
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
            bs[2] = (byte)(n >> 16);
            bs[3] = (byte)(n >> 24);
        }

        private void UInt32_To_LE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        private static long NanosecondsPerTick = 100L;
        private static long NanoTime(DateTime value)
        {
            return value.Ticks * NanosecondsPerTick;
        }

        public void Dispose()
        {
            _digest?.Dispose();
            _seed?.Dispose();
            _state?.Dispose();
        }
    }
}
