# SecureRandom.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/SecureRandom.NetCore.svg)](https://www.nuget.org/packages/SecureRandom.NetCore/)

Implementation of a cryptographic pseudorandom number generator (CPRNG) using [Blake2b](https://github.com/TimothyMeadows/Blake2b.NetCore). Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

# Install

From a command prompt
```bash
dotnet add package SecureRandom.NetCore
```

```bash
Install-Package SecureRandom.NetCore
```

You can also search for the package via your nuget ui / website:

https://www.nuget.org/packages/SecureRandom.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var cprng = new SecureRandom();

var randomBytes = cprng.NextBytes(16); // create by length

var nextRandomBytes = new byte[32];
cprng.NextBytes(nextRandomBytes); // popualte by size
```

# Constructor

WARNING: Never set seed to false unless you know what your doing. See example in github for more details.

```csharp
SecureRandom(int rounds = 10, bool seed = true)
```

# Methods

Get the hash output length used when seeding.
```csharp
int GetSeedLength()
```

Will add bytes to existing seed material, this will be hashed with blake2b.
```charp
void SetSeed(byte[] seed)
```

Will add number to existing seed material, this will be hashed with blake2b.
```charp
void SetSeed(long seed)
```

Will return a random number between 0, and int.MaxValue.
```charp
int Next()
```

Will return a random number between 0, and maxValue.
```charp
int Next(int maxValue)
```

Will return a random number between minValue, and maxValue.
```charp
int Next(int minValue, int maxValue)
```

Will return random bytes at length.
```csharp
byte[] NextBytes(int length)
```

Will populate random bytes by size.
```csharp
void NextBytes(byte[] bytes)
```

Will populate random bytes with offset at length.
```csharp
void NextBytes(byte[] bytes, int offset, int length)
```

Will return a random double between double.MinValue, and double.MaxValue.
```csharp
double NextDouble()
```

Will return a random int between int.MinValue, and int.MaxValue.
```csharp
int NextInt()
```

Will return a random long between long.MinValue, and long.MaxValue.
```csharp
int NextLong()
```

Will free state, and all seed material.
```csharp
void Dispose()
```
