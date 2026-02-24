# SecureRandom.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet](https://img.shields.io/nuget/v/SecureRandom.NetCore.svg)](https://www.nuget.org/packages/SecureRandom.NetCore/)

`SecureRandom.NetCore` is a cryptographic pseudo-random number generator (CPRNG) for .NET, based on [Blake2b.NetCore](https://github.com/TimothyMeadows/Blake2b.NetCore) and optimized to reduce memory exposure through [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

## Table of contents

- [Runtime support](#runtime-support)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Security notes](#security-notes)
- [API reference](#api-reference)
- [Examples project](#examples-project)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Runtime support

- .NET 8 (`net8.0`)

## Installation

### .NET CLI

```bash
dotnet add package SecureRandom.NetCore
```

### Package Manager Console

```powershell
Install-Package SecureRandom.NetCore
```

### NuGet

https://www.nuget.org/packages/SecureRandom.NetCore/

## Quick start

```csharp
using SecureRandom.NetCore;

using var cprng = new SecureRandom();

// Generate a new byte array
byte[] token = cprng.NextBytes(32);

// Fill an existing buffer
byte[] nonce = new byte[12];
cprng.NextBytes(nonce);

// Random primitives
int count = cprng.Next(1, 100);
long id = cprng.NextLong();
double value = cprng.NextDouble();
```

## Security notes

- By default, the constructor auto-seeds from the OS entropy provider (`RandomNumberGenerator.Fill`).
- Avoid `seed: false` unless you explicitly provide secure seed material via `SetSeed(...)` before calling generation APIs.
- `SecureRandom` implements `IDisposable`; always dispose instances to clear and release internal state.

## API reference

### Constructor

```csharp
SecureRandom(int rounds = 10, bool seed = true)
```

- `rounds`: Number of state generations before cycling seed material.
- `seed`: When `true` (default), instance self-seeds with OS entropy.

> ⚠️ `seed: false` creates an unseeded generator. Calling random generation methods before `SetSeed(...)` will throw.

### Methods

| Method | Description |
| --- | --- |
| `int GetSeedSize()` | Gets digest output length used for internal state and seed buffers. |
| `void SetSeed(byte[] seed)` | Mixes user-provided byte seed material into internal seed state. |
| `void SetSeed(long seed)` | Mixes user-provided integral seed material into internal seed state. |
| `int Next()` | Returns a non-negative random `int`. |
| `int Next(int maxValue)` | Returns random `int` in `[0, maxValue)`. |
| `int Next(int minValue, int maxValue)` | Returns random `int` in `[minValue, maxValue)`. |
| `byte[] NextBytes(int length)` | Creates and returns a random byte array of `length`. |
| `void NextBytes(byte[] bytes)` | Fills provided byte array with random data. |
| `void NextBytes(byte[] bytes, int offset, int length)` | Fills a segment of a byte array with random data. |
| `double NextDouble()` | Returns random `double` in range `[0, 1]`. |
| `int NextInt()` | Returns random `int` over full signed 32-bit range. |
| `long NextLong()` | Returns random `long` over full signed 64-bit range. |
| `void Dispose()` | Disposes digest/state resources and suppresses finalization. |

## Examples project

Sample usage is available in:

- `SecureRandom.NetCore.Examples/Program.cs`

Run it with:

```bash
dotnet run --project SecureRandom.NetCore.Examples
```

## Testing

This repository includes unit tests in `SecureRandom.NetCore.Tests`.

Run all tests:

```bash
dotnet test SecureRandom.NetCore.sln
```

## Contributing

Issues and pull requests are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Add or update tests.
4. Run `dotnet test`.
5. Open a pull request with a clear summary.

## License

MIT. See [LICENSE](LICENSE).
