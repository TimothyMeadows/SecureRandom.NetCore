using SecureRandom.NetCore;

namespace SecureRandom.NetCore.Tests;

public class SecureRandomTests
{
    [Fact]
    public void Constructor_WithInvalidRounds_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SecureRandom(rounds: 0));
    }

    [Fact]
    public void UnseededInstance_ThrowsOnGenerationCalls()
    {
        using var random = new SecureRandom(seed: false);

        Assert.Throws<InvalidOperationException>(() => random.Next());
        Assert.Throws<InvalidOperationException>(() => random.NextBytes(4));
    }

    [Fact]
    public void SetSeed_WithSameSeed_ProducesDeterministicOutput()
    {
        byte[] seed = [1, 2, 3, 4, 5, 6, 7, 8];

        using var first = new SecureRandom(seed: false);
        using var second = new SecureRandom(seed: false);

        first.SetSeed(seed);
        second.SetSeed(seed);

        var firstBytes = first.NextBytes(64);
        var secondBytes = second.NextBytes(64);

        Assert.Equal(firstBytes, secondBytes);
    }

    [Fact]
    public void Next_WithSingleOrZeroMaxValue_ReturnsZero()
    {
        using var random = new SecureRandom();

        Assert.Equal(0, random.Next(0));
        Assert.Equal(0, random.Next(1));
    }

    [Fact]
    public void Next_WithNegativeMaxValue_Throws()
    {
        using var random = new SecureRandom();

        Assert.Throws<ArgumentOutOfRangeException>(() => random.Next(-1));
    }

    [Fact]
    public void Next_WithRangeEqualBounds_ReturnsMinValue()
    {
        using var random = new SecureRandom();

        Assert.Equal(42, random.Next(42, 42));
    }

    [Fact]
    public void Next_WithRangeMaxLessThanMin_Throws()
    {
        using var random = new SecureRandom();

        Assert.Throws<ArgumentException>(() => random.Next(10, 5));
    }

    [Fact]
    public void NextBytes_WithOffsetAndLength_FillsExpectedSegment()
    {
        using var random = new SecureRandom();
        var buffer = new byte[16];

        random.NextBytes(buffer, offset: 4, length: 8);

        Assert.All(buffer.Take(4), b => Assert.Equal(0, b));
        Assert.All(buffer.Skip(12), b => Assert.Equal(0, b));
        Assert.Contains(buffer.Skip(4).Take(8), b => b != 0);
    }

    [Fact]
    public void NextBytes_WithInvalidRange_Throws()
    {
        using var random = new SecureRandom();

        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextBytes([], -1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => random.NextBytes([], 0, -1));
        Assert.Throws<ArgumentException>(() => random.NextBytes(new byte[4], 3, 2));
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes_AndPreventsFurtherUse()
    {
        var random = new SecureRandom();

        random.Dispose();
        random.Dispose();

        Assert.Throws<ObjectDisposedException>(() => random.SetSeed(1L));
        Assert.Throws<ObjectDisposedException>(() => random.Next());
    }

    [Fact]
    public void NextDouble_ReturnsValueInRange()
    {
        using var random = new SecureRandom();

        var value = random.NextDouble();

        Assert.InRange(value, 0d, 1d);
    }
}
