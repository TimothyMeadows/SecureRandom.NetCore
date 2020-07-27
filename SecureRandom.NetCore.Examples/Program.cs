using System;

namespace SecureRandom.NetCore.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            // This is the ideal method for using SecureRandom, it will auto seed based on nano time, and digest length.
            // Further, additional seeding added only serves to strengthen the seed rather than a fix it.
            // Please use this method if you are not sure what to do!
            var cprng = new SecureRandom();
            cprng.SetSeed(1001); // this is added to the existing seed material but is not required to call.

            var randomBytes = cprng.NextBytes(16);
            Console.WriteLine(BitConverter.ToString(randomBytes));

            // I personally don't consider fixed seeds to be safe for secure applications as it puts your random number generator at risk.
            // However, it is required in some "secure" environment, so for the sake of completeness this ability exists.
            // WARNING: Please don't disable auto seeding unless you know what you are doing and have no choice!
            using var fixedCprng = new SecureRandom(10, false); // disable secure auto seed, this is not advised but can be done if you require it.
            fixedCprng.SetSeed(1001); // set static seed so the next 16 bytes will always be the same.

            var fixedBytes = fixedCprng.NextBytes(16); // 18-DF-51-AA-1D-7B-4F-01-02-8B-D1-5C-88-FE-DD-3F
            Console.WriteLine(BitConverter.ToString(fixedBytes));
        }
    }
}
